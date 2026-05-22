"""WhatWeb plugin importer and version-pattern cache.

Downloads WhatWeb (https://github.com/urbanadventurer/WhatWeb) plugins,
extracts version-bearing patterns that work without a browser (body + header
matches only), and stores them in SQLite for use by the scanner.

Only patterns that have a version-capture group are imported -- detection-only
patterns are left to nuclei / Wappalyzer. Patterns that require an extra HTTP
request (aggressive :url probes), a browser (:dom, :js), or URI inspection
(uri.extension) are silently dropped at import time.

Pattern format stored in DB
---------------------------
  part:  'body' | 'header:<header-name>'
  regex: Python re-compatible pattern string (version in group 1)
"""

from __future__ import annotations

import io
import logging
import re
import sqlite3
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

import aiohttp

LOG = logging.getLogger("fp.whatweb")

GITHUB_ZIP = "https://github.com/urbanadventurer/WhatWeb/archive/refs/heads/master.zip"
_PLUGIN_PREFIX = "WhatWeb-master/plugins/"

SCHEMA = """
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS ww_technologies (
    id   INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE
);

CREATE INDEX IF NOT EXISTS idx_ww_name ON ww_technologies(name);

CREATE TABLE IF NOT EXISTS ww_patterns (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    tech_id INTEGER NOT NULL REFERENCES ww_technologies(id) ON DELETE CASCADE,
    part    TEXT NOT NULL,
    regex   TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_ww_pat_tech ON ww_patterns(tech_id);

CREATE TABLE IF NOT EXISTS ww_stats (
    key   TEXT PRIMARY KEY,
    value INTEGER DEFAULT 0
);
"""


# ---------------------------------------------------------------------------
# Ruby DSL parser (regex-based, not a full Ruby parser)
# ---------------------------------------------------------------------------

# Match a single Ruby hash entry value that is a regex literal: /pattern/flags
_RE_LIT = re.compile(r"/((?:[^/\\]|\\.)+)/([imx]*)")

# Match :search => "..." to determine what to search against
_SEARCH = re.compile(r":search\s*=>\s*\"([^\"]+)\"")

# Match :version => /pattern/ or :regexp => /pattern/ inside a hash block
_VER_KEY = re.compile(r":version\s*=>" + r"\s*" + r"/((?:[^/\\]|\\.)+)/([imx]*)")
_REG_KEY = re.compile(r":regexp\s*=>" + r"\s*" + r"/((?:[^/\\]|\\.)+)/([imx]*)")

# Match :offset => N
_OFFSET_KEY = re.compile(r":offset\s*=>\s*(\d+)")

# Ruby flag -> Python flag character
_FLAG_MAP = {"i": "(?i)", "m": "(?s)", "x": "(?x)"}


def _ruby_flags(flags: str) -> str:
    """Translate Ruby regex flags to Python inline flags prefix."""
    return "".join(_FLAG_MAP.get(f, "") for f in flags)


def _to_python_re(pattern: str, flags: str, offset: int = 0) -> str | None:
    """Convert a Ruby regex pattern+flags string to a Python re string.

    Returns None if the pattern doesn't compile under Python re.
    Skips patterns that have no capturing group (can't extract version).

    When *offset* > 0, the first *offset* capturing groups are converted to
    non-capturing so that the version always lands in group 1.
    """
    prefix = _ruby_flags(flags)
    py = prefix + pattern
    if "(" not in py:
        return None

    # Rewrite so the version group becomes group 1 when offset > 0.
    if offset > 0:
        converted = 0
        out: list[str] = []
        i = 0
        while i < len(py):
            if py[i] == "\\":
                # escaped character — pass through
                out.append(py[i:i + 2])
                i += 2
                continue
            if py[i] == "(" and converted < offset:
                # Is this already a non-capturing / special group?
                rest = py[i + 1:]
                if rest.startswith("?"):
                    # (?:...), (?i), (?=...) etc — already non-capturing
                    out.append("(")
                    i += 1
                    continue
                # Normal capturing group — convert to non-capturing
                out.append("(?:")
                converted += 1
                i += 1
                continue
            out.append(py[i])
            i += 1
        py = "".join(out)

    try:
        compiled = re.compile(py)
    except re.error:
        return None
    # Must still have at least one capturing group after rewriting.
    if compiled.groups < 1:
        return None
    return py


def _parse_plugin(ruby: str) -> Iterator[tuple[str, str, str]]:
    """Yield (tech_name, part, python_regex) tuples from a Ruby plugin file.

    Only yields entries that:
    - have a :version key (version-capture intent)
    - target body or a named response header (no aggressive/browser patterns)
    - compile cleanly under Python re
    """
    # Extract plugin name
    name_m = re.search(r'\bname\s+"([^"]+)"', ruby)
    if not name_m:
        return
    name = name_m.group(1)

    # Locate the matches [...] block using bracket-depth counting.
    # A regex like (.*?)] fails because ] appears inside character classes
    # in Ruby regex literals (e.g. [^>]).
    anchor = re.search(r"\bmatches\s*\[", ruby)
    if not anchor:
        return
    depth = 1
    pos = anchor.end()
    while pos < len(ruby) and depth > 0:
        ch = ruby[pos]
        if ch == "[":
            depth += 1
        elif ch == "]":
            depth -= 1
        elif ch == "/":
            # Skip over regex literal contents to avoid counting [] inside them
            pos += 1
            while pos < len(ruby) and ruby[pos] != "/":
                if ruby[pos] == "\\":
                    pos += 1  # skip escaped char
                pos += 1
        pos += 1
    if depth != 0:
        return
    block = ruby[anchor.end():pos - 1]

    # Split into individual hash entries { ... }
    depth = 0
    start = None
    for i, ch in enumerate(block):
        if ch == "{":
            if depth == 0:
                start = i
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0 and start is not None:
                entry = block[start + 1: i]
                yield from _parse_entry(name, entry)
                start = None


def _parse_entry(name: str, entry: str) -> Iterator[tuple[str, str, str]]:
    # Must have :version
    ver_m = _VER_KEY.search(entry)
    if not ver_m:
        return

    ver_pat, ver_flags = ver_m.group(1), ver_m.group(2)

    # Read :offset (0-based index of the capture group holding the version)
    off_m = _OFFSET_KEY.search(entry)
    offset = int(off_m.group(1)) if off_m else 0

    py_re = _to_python_re(ver_pat, ver_flags, offset=offset)
    if py_re is None:
        return

    # Determine search context
    search_m = _SEARCH.search(entry)
    search = search_m.group(1).lower() if search_m else "body"

    # Skip patterns we can't evaluate without a browser or extra request
    if any(search.startswith(p) for p in ("uri.", "scripts", "cookies", "meta")):
        return
    if ":url=>" in entry:
        return

    if search.startswith("headers["):
        hdr_m = re.search(r"headers\[([^\]]+)\]", search)
        if not hdr_m:
            return
        part = f"header:{hdr_m.group(1).lower()}"
    elif search == "headers":
        part = "header"
    else:
        part = "body"

    yield name, part, py_re


# ---------------------------------------------------------------------------
# Import
# ---------------------------------------------------------------------------


def _load_zip(data: bytes, db_path: str) -> dict[str, int]:
    """Parse a WhatWeb master ZIP and load patterns into SQLite.

    Returns stats dict: {imported_techs, imported_patterns, skipped_patterns}.
    """
    stats: dict[str, int] = {
        "imported_techs": 0,
        "imported_patterns": 0,
        "skipped_patterns": 0,
        "total_plugins": 0,
    }

    con = sqlite3.connect(db_path)
    con.executescript(SCHEMA)

    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        plugin_files = [
            n for n in zf.namelist()
            if n.startswith(_PLUGIN_PREFIX) and n.endswith(".rb")
        ]
        stats["total_plugins"] = len(plugin_files)

        for zpath in plugin_files:
            try:
                ruby = zf.read(zpath).decode("utf-8", errors="replace")
            except Exception:  # noqa: BLE001
                continue

            rows: list[tuple[str, str, str]] = list(_parse_plugin(ruby))
            if not rows:
                continue

            for name, part, py_re in rows:
                cur = con.execute(
                    "INSERT OR IGNORE INTO ww_technologies (name) VALUES (?)", (name,)
                )
                if cur.rowcount == 1:
                    tech_id = cur.lastrowid
                    stats["imported_techs"] += 1
                else:
                    tech_id = con.execute(
                        "SELECT id FROM ww_technologies WHERE name=?", (name,)
                    ).fetchone()[0]

                # Dedup: skip if identical (part, regex) already stored for this tech
                exists = con.execute(
                    "SELECT 1 FROM ww_patterns WHERE tech_id=? AND part=? AND regex=?",
                    (tech_id, part, py_re),
                ).fetchone()
                if exists:
                    continue

                con.execute(
                    "INSERT INTO ww_patterns (tech_id, part, regex) VALUES (?,?,?)",
                    (tech_id, part, py_re),
                )
                stats["imported_patterns"] += 1

    con.execute("DELETE FROM ww_stats")
    for k, v in stats.items():
        con.execute("INSERT INTO ww_stats (key,value) VALUES (?,?)", (k, v))
    con.commit()
    con.close()
    return stats


async def import_whatweb(db_path: str, *, zip_path: str | None = None) -> dict[str, int]:
    """Download (or load from disk) WhatWeb master ZIP and import into SQLite."""
    if zip_path:
        data = Path(zip_path).read_bytes()
    else:
        LOG.info("Downloading WhatWeb from %s ...", GITHUB_ZIP)
        connector = aiohttp.TCPConnector(ssl=False)
        async with aiohttp.ClientSession(connector=connector) as s:
            async with s.get(GITHUB_ZIP, timeout=aiohttp.ClientTimeout(total=120)) as r:
                r.raise_for_status()
                data = await r.read()
    return _load_zip(data, db_path)


# ---------------------------------------------------------------------------
# Cache (in-memory, built from DB)
# ---------------------------------------------------------------------------


@dataclass
class WwPattern:
    tech_name: str
    part: str        # 'body' | 'header:<name>'
    regex: re.Pattern


def build_cache(db_path: str) -> list[WwPattern]:
    """Load all patterns from SQLite into a compiled in-memory list."""
    if not Path(db_path).exists():
        return []
    con = sqlite3.connect(db_path)
    rows = con.execute(
        """SELECT t.name, p.part, p.regex
           FROM ww_patterns p
           JOIN ww_technologies t ON t.id = p.tech_id"""
    ).fetchall()
    con.close()

    patterns: list[WwPattern] = []
    skipped = 0
    for name, part, regex_str in rows:
        try:
            patterns.append(WwPattern(
                tech_name=name,
                part=part,
                regex=re.compile(regex_str, re.IGNORECASE),
            ))
        except re.error:
            skipped += 1
    if skipped:
        LOG.debug("build_cache: skipped %d patterns that failed to compile", skipped)
    return patterns


# ---------------------------------------------------------------------------
# Evaluate
# ---------------------------------------------------------------------------


@dataclass
class WwDetection:
    tech_name: str
    version: str
    part: str
    url: str

    def to_dict(self) -> dict:
        return {
            "source": "whatweb",
            "template_id": f"ww:{self.tech_name}",
            "name": self.tech_name,
            "version": self.version,
            "url": self.url,
        }


def scan_response(
    url: str,
    status: int,
    headers: dict[str, str],
    body: str,
    patterns: list[WwPattern],
) -> list[WwDetection]:
    """Run WhatWeb patterns against one HTTP response. Returns version hits."""
    hits: list[WwDetection] = []
    seen: set[str] = set()

    headers_lc = {k.lower(): v for k, v in headers.items()}
    all_headers_str = "\r\n".join(f"{k}: {v}" for k, v in headers_lc.items())

    for pat in patterns:
        if pat.part == "body":
            target = body
        elif pat.part == "header":
            target = all_headers_str
        elif pat.part.startswith("header:"):
            hdr_name = pat.part[7:]
            target = headers_lc.get(hdr_name, "")
            if not target:
                continue
        else:
            continue

        m = pat.regex.search(target)
        if not m:
            continue
        try:
            version = m.group(1).strip()
        except IndexError:
            continue
        if not version:
            continue

        key = (pat.tech_name, version)
        if key in seen:
            continue
        seen.add(key)
        hits.append(WwDetection(
            tech_name=pat.tech_name,
            version=version,
            part=pat.part,
            url=url,
        ))

    return hits
