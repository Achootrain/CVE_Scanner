"""Retire.js rule importer + matcher.

Ingests RetireJS's `jsrepository.json` — a community-curated database of JS
library version fingerprints — and exposes a matcher that runs the loaded
rules against fetched script bodies and URLs.

Retire.js extractor kinds supported here:

- `filecontent` — regex matched against the script body. Version in group 1.
- `filename`    — regex matched against the URL's basename.   Version in group 1.
- `uri`         — regex matched against the full URL.         Version in group 1.
- `hashes`      — exact `{sha1: version}` lookup against the script body hash.

Unsupported (dropped at import time with a count in stats):
- `func` — requires a live JavaScript runtime.

This module is standalone; integrating retire.js into the main scan flow
alongside nuclei + Wappalyzer is a separate wiring step.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import aiohttp

from . import safe_regex as sre_mod

LOG = logging.getLogger("fp.retirejs")

RETIREJS_URL = (
    "https://raw.githubusercontent.com/RetireJS/retire.js/master/repository/"
    "jsrepository-v2.json"
)
# Older single-file location as a fallback in case upstream moves it.
RETIREJS_URL_FALLBACK = (
    "https://raw.githubusercontent.com/RetireJS/retire.js/master/repository/"
    "jsrepository.json"
)

SUPPORTED_KINDS = {"filecontent", "filename", "uri"}
UNSUPPORTED_KINDS = {"func"}

# retire.js v2 uses a template placeholder for version capture. The raw
# patterns in `jsrepository-v2.json` contain `§§version§§` (doubled section
# signs, U+00A7) which tools must substitute with a version-capturing
# group before use. retire.js's own JS implementation performs the same
# substitution. Using `[^\s'";]+` keeps trailing punctuation (quotes,
# semicolons, whitespace) from being swallowed by greedy matching.
VERSION_PLACEHOLDER = "§§version§§"
VERSION_CAPTURE_GROUP = r"([0-9][^\s'\";]*)"


def _expand_placeholders(pattern: str) -> str:
    return pattern.replace(VERSION_PLACEHOLDER, VERSION_CAPTURE_GROUP)

SCHEMA = """
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS retire_techs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT NOT NULL UNIQUE,
    bowername   TEXT,
    imported_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS retire_patterns (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    tech_id INTEGER NOT NULL REFERENCES retire_techs(id) ON DELETE CASCADE,
    kind    TEXT NOT NULL,
    regex   TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_retire_pat_tech ON retire_patterns(tech_id);
CREATE INDEX IF NOT EXISTS idx_retire_pat_kind ON retire_patterns(kind);

CREATE TABLE IF NOT EXISTS retire_hashes (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    tech_id INTEGER NOT NULL REFERENCES retire_techs(id) ON DELETE CASCADE,
    sha1    TEXT NOT NULL,
    version TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_retire_hash ON retire_hashes(sha1);
"""


# ---------------------------------------------------------------------------
# Download
# ---------------------------------------------------------------------------


async def fetch_repo() -> bytes:
    """Fetch the retire.js repository JSON. Tries v2 first, falls back to v1."""
    urls = (RETIREJS_URL, RETIREJS_URL_FALLBACK)
    async with aiohttp.ClientSession() as sess:
        for url in urls:
            try:
                async with sess.get(url, timeout=aiohttp.ClientTimeout(total=60)) as r:
                    if r.status == 200:
                        return await r.read()
                    LOG.warning("retire.js fetch %s → HTTP %d", url, r.status)
            except aiohttp.ClientError as e:
                LOG.warning("retire.js fetch %s failed: %s", url, e)
    raise RuntimeError("Could not download retire.js repository from any known URL")


# ---------------------------------------------------------------------------
# Parse
# ---------------------------------------------------------------------------


def parse_repo(blob: bytes) -> dict[str, dict]:
    """Parse retire.js JSON into a normalized dict.

    Accepts either the v1 (flat) or v2 format. Drops `func` extractors and
    any well-known top-level non-tech keys the upstream uses for metadata."""
    raw = json.loads(blob)
    if not isinstance(raw, dict):
        raise ValueError("retire.js repo must be a JSON object at the top level")
    out: dict[str, dict] = {}
    for name, entry in raw.items():
        # Upstream sometimes includes metadata keys — skip entries that
        # aren't shaped like a library record.
        if not isinstance(entry, dict):
            continue
        extractors = entry.get("extractors") or {}
        if not isinstance(extractors, dict):
            continue
        patterns: dict[str, list[str]] = {}
        for kind, pats in extractors.items():
            if kind not in SUPPORTED_KINDS:
                continue
            if isinstance(pats, list):
                patterns[kind] = [
                    _expand_placeholders(p) for p in pats if isinstance(p, str)
                ]
        hashes: dict[str, str] = {}
        raw_hashes = extractors.get("hashes")
        if isinstance(raw_hashes, dict):
            # hashes: {sha1: version}
            for k, v in raw_hashes.items():
                if isinstance(k, str) and isinstance(v, str):
                    hashes[k.lower()] = v
        if not patterns and not hashes:
            continue
        out[name] = {
            "bowername": entry.get("bowername"),
            "patterns": patterns,
            "hashes": hashes,
        }
    return out


# ---------------------------------------------------------------------------
# Import to SQLite
# ---------------------------------------------------------------------------


def import_to_db(data: dict[str, dict], db_path: str | Path) -> dict[str, int]:
    db_path = Path(db_path)
    conn = sqlite3.connect(db_path)
    conn.executescript(SCHEMA)
    # Clear before re-import so repeated calls are idempotent.
    conn.execute("DELETE FROM retire_hashes")
    conn.execute("DELETE FROM retire_patterns")
    conn.execute("DELETE FROM retire_techs")
    conn.commit()

    techs = patterns = hashes = 0
    for name, entry in data.items():
        cur = conn.execute(
            "INSERT INTO retire_techs(name, bowername) VALUES (?, ?)",
            (name, json.dumps(entry.get("bowername")) if entry.get("bowername") else None),
        )
        tech_id = cur.lastrowid
        techs += 1
        for kind, pats in entry["patterns"].items():
            for pat in pats:
                conn.execute(
                    "INSERT INTO retire_patterns(tech_id, kind, regex) VALUES (?, ?, ?)",
                    (tech_id, kind, pat),
                )
                patterns += 1
        for sha1, version in entry["hashes"].items():
            conn.execute(
                "INSERT INTO retire_hashes(tech_id, sha1, version) VALUES (?, ?, ?)",
                (tech_id, sha1, version),
            )
            hashes += 1
    conn.commit()
    conn.close()
    return {"techs": techs, "patterns": patterns, "hashes": hashes}


# ---------------------------------------------------------------------------
# Cache + scan
# ---------------------------------------------------------------------------


@dataclass
class CompiledPattern:
    tech_id: int
    tech_name: str
    kind: str           # 'filecontent' | 'filename' | 'uri'
    regex: re.Pattern


def build_cache(db_path: str | Path) -> dict[str, Any]:
    """Load retire.js rules from SQLite and compile regex patterns.

    Patterns that don't compile with Python's `re` module are skipped and
    counted in `stats.skipped_patterns` (retire.js uses some JS regex
    features Python doesn't support)."""
    db_path = Path(db_path)
    conn = sqlite3.connect(db_path)
    techs: dict[int, str] = {
        row[0]: row[1]
        for row in conn.execute("SELECT id, name FROM retire_techs")
    }
    compiled: list[CompiledPattern] = []
    skipped = 0
    for tech_id, kind, regex in conn.execute(
        "SELECT tech_id, kind, regex FROM retire_patterns"
    ):
        try:
            compiled.append(CompiledPattern(
                tech_id=tech_id,
                tech_name=techs[tech_id],
                kind=kind,
                regex=re.compile(regex),
            ))
        except re.error:
            skipped += 1
    # sha1 → (tech_id, version)
    hashes: dict[str, tuple[int, str]] = {}
    for tech_id, sha1, version in conn.execute(
        "SELECT tech_id, sha1, version FROM retire_hashes"
    ):
        hashes[sha1.lower()] = (tech_id, version)
    conn.close()
    return {
        "techs": techs,
        "compiled": compiled,
        "hashes": hashes,
        "stats": {
            "techs": len(techs),
            "patterns": len(compiled),
            "skipped_patterns": skipped,
            "hashes": len(hashes),
        },
    }


@dataclass
class Detection:
    tech: str
    version: str | None
    source: str       # 'filecontent' | 'filename' | 'uri' | 'hash'
    evidence: str     # short snippet explaining the match

    def to_dict(self) -> dict:
        return {"tech": self.tech, "version": self.version,
                "source": self.source, "evidence": self.evidence}


def scan_body(body: str, url: str, cache: dict[str, Any]) -> list[Detection]:
    """Run retire.js patterns against a fetched JS body + URL.

    Order of checks:
      1. Exact sha1 hash of body → deterministic version lookup (highest
         confidence — retire.js built this from known releases).
      2. filecontent regexes against body.
      3. filename / uri regexes against URL.

    A tech may produce multiple detections (e.g. both a hash hit and a
    content-regex hit) — callers should dedup as needed."""
    results: list[Detection] = []

    if body:
        sha1 = hashlib.sha1(body.encode("utf-8", errors="replace")).hexdigest()
        if sha1 in cache["hashes"]:
            tech_id, version = cache["hashes"][sha1]
            tech_name = cache["techs"].get(tech_id, f"id={tech_id}")
            results.append(Detection(
                tech=tech_name,
                version=version,
                source="hash",
                evidence=f"sha1={sha1[:12]}…",
            ))

    for cp in cache["compiled"]:
        target = body if cp.kind == "filecontent" else url
        if not target:
            continue
        # Wrap in safe_search: retire.js patterns compiled from upstream
        # jsrepository-v2.json have triggered catastrophic backtracking on
        # minified Vite/Webpack bundles. Without this wrapper a single
        # pathological pattern hangs the whole scan stage.
        m = sre_mod.safe_search(cp.regex, target)
        if not m:
            continue
        version = m.group(1) if m.groups() else None
        # uri/filename patterns match against the URL path; a slash in the
        # captured version group means the regex backtracked into directory
        # segments (e.g. "2game.vn/wp-includes/js" captured as Backbone
        # version). Reject any version that looks like a path.
        if version and cp.kind in ("uri", "filename") and ("/" in version or len(version) > 30):
            version = None
        snippet = m.group(0)
        if len(snippet) > 80:
            snippet = snippet[:77] + "..."
        results.append(Detection(
            tech=cp.tech_name,
            version=version,
            source=cp.kind,
            evidence=snippet,
        ))
    return results
