"""Loader API for url_ver tables in lab.db.

Each load_*() returns the SAME Python type the in-code constant in fp/url_ver.py
exposes today. This is the drop-in shape; a scanner refactor would just swap

    from fp.url_ver import _JS_LIB_MAP
    -- ->
    from lab.url_ver_lab.loader import load_js_lib_map
    _JS_LIB_MAP = load_js_lib_map(LAB_DB_PATH)

The loader does NOT touch the scanner. Use is currently limited to the parity
test (test_parity.py) and any future lab consumer.

Cached in-process: each load_*() result is memoized on (db_path, table_state).
"""
from __future__ import annotations

import re
import sqlite3
from functools import lru_cache
from pathlib import Path


# ---------------------------------------------------------------------------
# Alias maps: returns dict[str, str]  (alias -> canonical tech)
# ---------------------------------------------------------------------------


def _load_alias_map(db_path: Path, context: str) -> dict[str, str]:
    conn = sqlite3.connect(str(db_path))
    try:
        rows = conn.execute(
            "SELECT alias, tech FROM lab_pkg_aliases WHERE context=? AND tech IS NOT NULL",
            (context,),
        ).fetchall()
    finally:
        conn.close()
    return {alias: tech for alias, tech in rows}


def load_js_lib_map(db_path: Path) -> dict[str, str]:
    return _load_alias_map(db_path, "js-lib")


def load_wp_plugin_map(db_path: Path) -> dict[str, str]:
    return _load_alias_map(db_path, "wp-plugin")


def load_cdn_pkg_map(db_path: Path) -> dict[str, str]:
    """CDN map = js-lib base + cdn-pkg-specific aliases (mirrors fp/url_ver.py _CDN_PKG_MAP construction)."""
    base = _load_alias_map(db_path, "js-lib")
    cdn_specific = _load_alias_map(db_path, "cdn-pkg")
    return {**base, **cdn_specific}


def load_skip_stems(db_path: Path) -> frozenset[str]:
    conn = sqlite3.connect(str(db_path))
    try:
        rows = conn.execute(
            "SELECT alias FROM lab_pkg_aliases WHERE context='skip-stem'"
        ).fetchall()
    finally:
        conn.close()
    return frozenset(r[0] for r in rows)


# ---------------------------------------------------------------------------
# URL patterns: returns list of tuples matching fp.url_ver shape
# ---------------------------------------------------------------------------


def load_cdn_patterns(db_path: Path) -> list[tuple]:
    """Return list[(compiled_re, pkg_group_or_None, version_group, fixed_name_or_None)].

    Matches the shape of fp.url_ver._CDN_PATTERNS exactly.
    """
    conn = sqlite3.connect(str(db_path))
    try:
        rows = conn.execute(
            """SELECT pattern, pkg_group, version_group, tech, family
               FROM lab_url_patterns WHERE kind='cdn' ORDER BY id"""
        ).fetchall()
    finally:
        conn.close()
    out: list[tuple] = []
    for pattern, pkg_group, version_group, tech, family in rows:
        out.append((re.compile(pattern), pkg_group, version_group, tech))
    return out


def load_framework_patterns(db_path: Path) -> list[tuple]:
    """Return list[(compiled_re, tech_name, slug)].

    Matches the shape of fp.url_ver._FRAMEWORK_PATTERNS. Slug recovered from
    the 'family' field (format 'framework: <slug>') or from the 'note' column.
    """
    conn = sqlite3.connect(str(db_path))
    try:
        rows = conn.execute(
            """SELECT pattern, tech, family, note
               FROM lab_url_patterns WHERE kind='framework' ORDER BY id"""
        ).fetchall()
    finally:
        conn.close()
    out: list[tuple] = []
    for pattern, tech, family, note in rows:
        slug = None
        if note and note.startswith("slug="):
            slug = note[len("slug="):]
        elif family and family.startswith("framework: "):
            slug = family[len("framework: "):]
        out.append((re.compile(pattern, re.IGNORECASE), tech, slug))
    return out


# ---------------------------------------------------------------------------
# Convenience: load everything in one call
# ---------------------------------------------------------------------------


def load_version_probes(db_path: Path) -> list:
    """Return list[Probe] from lab_version_probes.

    Imports fp.version_probes.Probe lazily so this module stays scanner-free
    on import. Matches the in-code CATALOG list shape exactly.
    """
    import json as _json
    import sys as _sys
    _sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent / "fingerprinter"))
    from fp.version_probes import Probe

    conn = sqlite3.connect(str(db_path))
    try:
        rows = conn.execute(
            """SELECT name, path, regex, method, version_group, ok_status,
                      part, content_hint, headers_json
               FROM lab_version_probes ORDER BY id"""
        ).fetchall()
    finally:
        conn.close()
    out: list = []
    for (name, path, regex, method, version_group, ok_status, part,
         content_hint, headers_json) in rows:
        ok_tuple = tuple(int(s) for s in ok_status.split(",") if s.strip())
        headers = _json.loads(headers_json) if headers_json else {}
        out.append(Probe(
            name=name, path=path, regex=regex, method=method,
            version_group=version_group, ok_status=ok_tuple, part=part,
            content_hint=content_hint, headers=headers,
        ))
    return out


def load_all(db_path: Path) -> dict:
    return {
        "JS_LIB_MAP": load_js_lib_map(db_path),
        "CDN_PKG_MAP": load_cdn_pkg_map(db_path),
        "WP_PLUGIN_MAP": load_wp_plugin_map(db_path),
        "SKIP_STEMS": load_skip_stems(db_path),
        "CDN_PATTERNS": load_cdn_patterns(db_path),
        "FRAMEWORK_PATTERNS": load_framework_patterns(db_path),
        "VERSION_PROBES": load_version_probes(db_path),
    }
