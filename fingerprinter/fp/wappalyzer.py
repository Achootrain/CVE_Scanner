"""Wappalyzer rule importer + matcher.

Pulls technology detection rules from the MIT-licensed `enthec/webappanalyzer`
fork of Wappalyzer, stores them in SQLite alongside the nuclei fingerprint data,
and exposes an evaluator that runs every rule against a single HTTP response.

Pattern format (per Wappalyzer):
    regex\\;version:\\N\\;confidence:M
Fields supported here: url, html, headers, meta, scriptSrc, scripts, cookies.
Fields requiring a browser / HTML parser (js, dom, css, text) are dropped at
import time with a log line.
"""

from __future__ import annotations

import io
import json
import logging
import re
import sqlite3
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import aiohttp

from . import safe_regex as sre_mod

LOG = logging.getLogger("fp.wappalyzer")

WAP_REPO = "enthec/webappanalyzer"
WAP_BRANCH = "main"
WAP_ZIP_URL = f"https://github.com/{WAP_REPO}/archive/refs/heads/{WAP_BRANCH}.zip"
_TECH_PREFIX = f"webappanalyzer-{WAP_BRANCH}/src/technologies/"
_CATS_PATH = f"webappanalyzer-{WAP_BRANCH}/src/categories.json"

SUPPORTED_FIELDS = {"url", "html", "headers", "meta", "scriptSrc", "scripts", "cookies"}
UNSUPPORTED_FIELDS = {"js", "dom", "css", "text", "dns", "robots", "xhr", "certIssuer"}

SCHEMA = """
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS wap_technologies (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT NOT NULL UNIQUE,
    description TEXT,
    website     TEXT,
    icon        TEXT,
    cpe         TEXT,
    categories  TEXT,
    implies     TEXT,
    requires    TEXT,
    excludes    TEXT,
    saas        INTEGER DEFAULT 0,
    oss         INTEGER DEFAULT 0,
    imported_at TEXT DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_wap_tech_name ON wap_technologies(name);

CREATE TABLE IF NOT EXISTS wap_patterns (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    technology_id INTEGER NOT NULL REFERENCES wap_technologies(id) ON DELETE CASCADE,
    field         TEXT NOT NULL,
    key           TEXT,
    regex         TEXT NOT NULL,
    version_tmpl  TEXT,
    confidence    INTEGER DEFAULT 100
);

CREATE INDEX IF NOT EXISTS idx_wap_pat_tech  ON wap_patterns(technology_id);
CREATE INDEX IF NOT EXISTS idx_wap_pat_field ON wap_patterns(field);

CREATE TABLE IF NOT EXISTS wap_categories (
    id       INTEGER PRIMARY KEY,
    name     TEXT NOT NULL,
    priority INTEGER DEFAULT 0
);
"""


# ---------------------------------------------------------------------------
# Pattern parsing
# ---------------------------------------------------------------------------


def parse_pattern(raw: str) -> tuple[str, str | None, int]:
    """Split ``regex\\;version:\\1\\;confidence:50`` into (regex, version, confidence)."""
    parts = raw.split("\\;")
    regex = parts[0]
    version: str | None = None
    confidence = 100
    for p in parts[1:]:
        if p.startswith("version:"):
            version = p[len("version:"):] or None
        elif p.startswith("confidence:"):
            try:
                confidence = int(p[len("confidence:"):])
            except ValueError:
                pass
    return regex, version, confidence


def _ensure_list(v: Any) -> list:
    if v is None:
        return []
    return v if isinstance(v, list) else [v]


def _normalise_field(field: str, value: Any) -> list[tuple[str, str | None, str, str | None, int]]:
    """Emit (field, key, regex, version_tmpl, confidence) tuples for one field."""
    out: list[tuple[str, str | None, str, str | None, int]] = []
    if value is None:
        return out
    if field in {"headers", "meta", "cookies"}:
        if not isinstance(value, dict):
            return out
        for k, v in value.items():
            for entry in _ensure_list(v):
                if not isinstance(entry, str):
                    continue
                rgx, ver, conf = parse_pattern(entry)
                out.append((field, k.lower(), rgx, ver, conf))
    else:
        for entry in _ensure_list(value):
            if not isinstance(entry, str):
                continue
            rgx, ver, conf = parse_pattern(entry)
            out.append((field, None, rgx, ver, conf))
    return out


# ---------------------------------------------------------------------------
# Fetch + import
# ---------------------------------------------------------------------------


async def fetch_zip(url: str = WAP_ZIP_URL) -> bytes:
    async with aiohttp.ClientSession() as s:
        async with s.get(url, timeout=aiohttp.ClientTimeout(total=120)) as r:
            r.raise_for_status()
            return await r.read()


def parse_zip(blob: bytes) -> dict[str, Any]:
    """Return {technologies: {name: record}, categories: {id: {name, priority}}}."""
    out: dict[str, Any] = {"technologies": {}, "categories": {}}
    with zipfile.ZipFile(io.BytesIO(blob)) as z:
        for info in z.infolist():
            if info.is_dir():
                continue
            if info.filename == _CATS_PATH:
                data = json.loads(z.read(info).decode("utf-8"))
                out["categories"] = {int(k): v for k, v in data.items()}
            elif info.filename.startswith(_TECH_PREFIX) and info.filename.endswith(".json"):
                try:
                    data = json.loads(z.read(info).decode("utf-8"))
                except json.JSONDecodeError as exc:
                    LOG.warning("skip %s: %s", info.filename, exc)
                    continue
                for name, tech in data.items():
                    if isinstance(tech, dict):
                        out["technologies"][name] = tech
    return out


def import_to_db(data: dict[str, Any], db_path: str | Path) -> dict[str, int]:
    conn = sqlite3.connect(str(db_path))
    try:
        conn.executescript(SCHEMA)
        conn.execute("DELETE FROM wap_patterns")
        conn.execute("DELETE FROM wap_technologies")
        conn.execute("DELETE FROM wap_categories")

        for cid, cat in data.get("categories", {}).items():
            conn.execute(
                "INSERT OR REPLACE INTO wap_categories (id, name, priority) VALUES (?, ?, ?)",
                (cid, cat.get("name"), cat.get("priority", 0)),
            )

        tech_count = 0
        pat_count = 0
        skipped: set[str] = set()
        for name, tech in data["technologies"].items():
            cats = [int(c) for c in (tech.get("cats") or [])]
            cur = conn.execute(
                "INSERT INTO wap_technologies "
                "(name, description, website, icon, cpe, categories, implies, requires, excludes, saas, oss) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    name,
                    tech.get("description"),
                    tech.get("website"),
                    tech.get("icon"),
                    tech.get("cpe"),
                    json.dumps(cats),
                    json.dumps(_ensure_list(tech.get("implies"))),
                    json.dumps(_ensure_list(tech.get("requires"))),
                    json.dumps(_ensure_list(tech.get("excludes"))),
                    int(bool(tech.get("saas"))),
                    int(bool(tech.get("oss"))),
                ),
            )
            tech_id = cur.lastrowid
            tech_count += 1

            for field, raw in tech.items():
                if field in SUPPORTED_FIELDS:
                    for row in _normalise_field(field, raw):
                        conn.execute(
                            "INSERT INTO wap_patterns "
                            "(technology_id, field, key, regex, version_tmpl, confidence) "
                            "VALUES (?, ?, ?, ?, ?, ?)",
                            (tech_id, *row),
                        )
                        pat_count += 1
                elif field in UNSUPPORTED_FIELDS:
                    skipped.add(field)

        conn.commit()
        if skipped:
            LOG.info("skipped unsupported fields: %s", ", ".join(sorted(skipped)))
        return {"technologies": tech_count, "patterns": pat_count}
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Cache
# ---------------------------------------------------------------------------


@dataclass
class WapPattern:
    field: str
    key: str | None
    regex: re.Pattern
    version_tmpl: str | None
    confidence: int


@dataclass
class WapTech:
    name: str
    categories: list[str]
    website: str | None
    cpe: str | None
    implies: list[str]
    patterns: list[WapPattern]


def build_cache(db_path: str | Path) -> dict[str, Any]:
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    try:
        categories = {r["id"]: r["name"] for r in conn.execute("SELECT id, name FROM wap_categories")}
        techs: list[WapTech] = []
        bad_regex = 0
        for t in conn.execute("SELECT * FROM wap_technologies"):
            cats = [categories.get(c, str(c)) for c in json.loads(t["categories"] or "[]")]
            pats: list[WapPattern] = []
            for p in conn.execute(
                "SELECT field, key, regex, version_tmpl, confidence FROM wap_patterns "
                "WHERE technology_id = ?",
                (t["id"],),
            ):
                try:
                    compiled = re.compile(p["regex"], re.IGNORECASE)
                except re.error:
                    bad_regex += 1
                    continue
                pats.append(WapPattern(
                    field=p["field"],
                    key=p["key"],
                    regex=compiled,
                    version_tmpl=p["version_tmpl"],
                    confidence=p["confidence"] or 100,
                ))
            techs.append(WapTech(
                name=t["name"],
                categories=cats,
                website=t["website"],
                cpe=t["cpe"],
                implies=json.loads(t["implies"] or "[]"),
                patterns=pats,
            ))
        if bad_regex:
            LOG.info("skipped %d patterns with unsupported regex syntax", bad_regex)
        return {
            "technologies": techs,
            "categories": categories,
            "stats": {
                "technologies": len(techs),
                "patterns": sum(len(t.patterns) for t in techs),
                "bad_regex": bad_regex,
            },
        }
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Evaluation
# ---------------------------------------------------------------------------


_SCRIPT_SRC_RE = re.compile(r'<script[^>]+src=["\']([^"\']+)["\']', re.IGNORECASE)
_META_RE = re.compile(
    r'<meta[^>]+name=["\']([^"\']+)["\'][^>]*content=["\']([^"\']*)["\']',
    re.IGNORECASE,
)
_META_RE_REV = re.compile(
    r'<meta[^>]+content=["\']([^"\']*)["\'][^>]*name=["\']([^"\']+)["\']',
    re.IGNORECASE,
)
_VER_BACKREF_RE = re.compile(r"\\(\d+)")
_VER_TERNARY_RE = re.compile(r"^\\(\d+)\?(.*?):(.*)$")


def _extract_meta(html: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for m in _META_RE.finditer(html):
        out.setdefault(m.group(1).lower(), m.group(2))
    for m in _META_RE_REV.finditer(html):
        out.setdefault(m.group(2).lower(), m.group(1))
    return out


def _extract_cookies(headers: dict[str, str]) -> dict[str, str]:
    out: dict[str, str] = {}
    for k, v in headers.items():
        if k.lower() != "set-cookie":
            continue
        # aiohttp collapses repeated Set-Cookie headers with comma; split only
        # at commas followed by a valid cookie-name=, not inside expires= dates.
        for item in re.split(r",\s+(?=[A-Za-z0-9_!#$%&'*+.^`|~-]+=)", v):
            first = item.split(";", 1)[0]
            if "=" in first:
                name, val = first.split("=", 1)
                out.setdefault(name.strip().lower(), val.strip())
    return out


def _apply_version(template: str | None, match: re.Match) -> str:
    if not template:
        return ""
    groups = match.groups() if match.re.groups else ()

    def _resolve_backrefs(s: str) -> str:
        def _sub(g: re.Match) -> str:
            idx = int(g.group(1))
            if 1 <= idx <= len(groups):
                return groups[idx - 1] or ""
            return ""
        return _VER_BACKREF_RE.sub(_sub, s)

    tern = _VER_TERNARY_RE.match(template)
    if tern:
        idx = int(tern.group(1))
        present = 1 <= idx <= len(groups) and bool(groups[idx - 1])
        branch = tern.group(2) if present else tern.group(3)
        return _resolve_backrefs(branch).strip()

    return _resolve_backrefs(template).strip()


def _match_pattern(
    pat: WapPattern,
    url: str,
    html: str,
    headers_lc: dict[str, str],
    meta: dict[str, str],
    cookies: dict[str, str],
    scripts: list[str],
) -> tuple[re.Match | None, str | None]:
    """Return ``(match, matched_script_src)``. The second element is non-None
    only for ``scriptSrc`` / ``scripts`` matchers, and carries the actual
    script URL that triggered the regex so callers can populate
    ``evidence_url``. Without it the funnel's BodyExtractStage has nothing
    to fetch for banner-rule version rescue (CLAUDE.md §8 cause B)."""
    # Every regex.search call below is wrapped in safe_search. Wappalyzer
    # rules come from upstream and some have caused catastrophic
    # backtracking on adversarial input -- a single bad rule could hang
    # the whole evaluator without this guard.
    if pat.field == "url":
        return sre_mod.safe_search(pat.regex, url), None
    if pat.field == "html":
        return sre_mod.safe_search(pat.regex, html), None
    if pat.field == "headers":
        val = headers_lc.get((pat.key or "").lower())
        return (sre_mod.safe_search(pat.regex, val) if val is not None else None), None
    if pat.field == "meta":
        val = meta.get((pat.key or "").lower())
        return (sre_mod.safe_search(pat.regex, val) if val is not None else None), None
    if pat.field == "cookies":
        key = (pat.key or "").lower()
        if key not in cookies:
            return None, None
        return sre_mod.safe_search(pat.regex, cookies[key]), None
    if pat.field in ("scriptSrc", "scripts"):
        for s in scripts:
            m = sre_mod.safe_search(pat.regex, s)
            if m:
                return m, s
    return None, None


def evaluate(
    cache: dict,
    url: str,
    headers: dict[str, str],
    body: bytes,
) -> list[dict]:
    """Run every Wappalyzer rule against a single HTTP response."""
    html = body.decode("utf-8", errors="replace")
    meta = _extract_meta(html)
    cookies = _extract_cookies(headers)
    scripts = _SCRIPT_SRC_RE.findall(html)
    headers_lc = {k.lower(): v for k, v in headers.items()}

    detections: list[dict] = []
    for tech in cache["technologies"]:
        versions: list[str] = []
        confidence = 0
        matched = False
        evidence_url: str | None = None
        for pat in tech.patterns:
            m, src_url = _match_pattern(pat, url, html, headers_lc, meta, cookies, scripts)
            if m is None:
                continue
            matched = True
            confidence += pat.confidence
            # First scriptSrc/scripts hit wins -- gives the funnel an asset
            # URL to fetch for banner-rule version rescue. Other fields
            # (html/url/headers/meta/cookies) have no per-match asset URL.
            if evidence_url is None and src_url:
                evidence_url = src_url
            if pat.version_tmpl:
                v = _apply_version(pat.version_tmpl, m)
                if v and v not in versions:
                    versions.append(v)
        if matched:
            detections.append({
                "source": "wappalyzer",
                "name": tech.name,
                "categories": tech.categories,
                "cpe": tech.cpe,
                "website": tech.website,
                "implies": tech.implies,
                "version": versions[0] if versions else None,
                "versions": versions,
                "confidence": min(100, confidence),
                "url": url,
                "evidence_url": evidence_url,
            })
    return detections
