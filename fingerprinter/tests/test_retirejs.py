"""Tests for retire.js importer + matcher. No network; synthetic fixture."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from fp import retirejs


# A tiny retire.js-shaped fixture covering every supported extractor kind
# plus one unsupported kind (func) to confirm it's dropped.
FIXTURE = {
    "jquery": {
        "bowername": ["jquery"],
        "extractors": {
            "func": [
                # Should be dropped — we don't execute JS.
                "return typeof jQuery === 'function' && jQuery.prototype.jquery"
            ],
            "filecontent": [
                r"/\*![\n\s]*jQuery v(\d+\.\d+\.\d+[^\s]*)"
            ],
            "filename": [r"jquery-(\d+\.\d+\.\d+)(\.min)?\.js"],
            "uri": [r"/(\d+\.\d+\.\d+[^/]*)/jquery[.-]"],
            "hashes": {
                # sha1 of the string "jquery-v1.9.0-payload" — used below
                # to verify hash-based detection without downloading real JS.
                hashlib.sha1(b"jquery-v1.9.0-payload").hexdigest(): "1.9.0",
            },
        },
    },
    # A second tech with only patterns, no hashes.
    "angular": {
        "extractors": {
            "filecontent": [r"ng_version\s*=\s*['\"](\d+\.\d+\.\d+)"],
        },
    },
    # Malformed entry — importer should skip, not crash.
    "badlib": "not-a-dict",
    # Entry with no supported extractors — skipped silently.
    "empty-lib": {"extractors": {"func": ["foo"]}},
    # backbone-style uri pattern whose group can backtrack into path segments
    "backbone": {
        "extractors": {
            "uri": [r"/(([0-9][^\s'\";\s]*))/backbone(\.min)?\.js"],
        },
    },
}


# ---------------------------------------------------------------------------
# Parse
# ---------------------------------------------------------------------------


def test_parse_repo_keeps_supported_extractors_only():
    data = retirejs.parse_repo(json.dumps(FIXTURE).encode("utf-8"))
    assert "jquery" in data
    # func is the only unsupported extractor and MUST be absent.
    assert "func" not in data["jquery"]["patterns"]
    # All supported kinds preserved.
    assert set(data["jquery"]["patterns"]) == {"filecontent", "filename", "uri"}
    # Hashes carried through, lowercased.
    assert data["jquery"]["hashes"]
    assert all(k == k.lower() for k in data["jquery"]["hashes"])
    # angular kept (has at least one supported extractor).
    assert "angular" in data
    # Malformed + empty-lib dropped.
    assert "badlib" not in data
    assert "empty-lib" not in data


def test_parse_repo_rejects_non_dict_toplevel():
    with pytest.raises(ValueError):
        retirejs.parse_repo(b'["not", "an", "object"]')


def test_parse_repo_expands_v2_version_placeholder():
    """retire.js v2 uses `§§version§§` as a placeholder that must be
    substituted with a version-capturing group before patterns are usable.
    Without expansion, real retire.js rules (99% of upstream) never match."""
    v2 = {"jquery": {"extractors": {"filecontent": [
        r"/\*!? jQuery v§§version§§"
    ]}}}
    data = retirejs.parse_repo(json.dumps(v2).encode("utf-8"))
    expanded = data["jquery"]["patterns"]["filecontent"][0]
    assert "§§version§§" not in expanded
    assert retirejs.VERSION_CAPTURE_GROUP in expanded


# ---------------------------------------------------------------------------
# Import → SQLite → cache
# ---------------------------------------------------------------------------


def test_import_to_db_and_build_cache_roundtrip(tmp_path: Path):
    data = retirejs.parse_repo(json.dumps(FIXTURE).encode("utf-8"))
    db = tmp_path / "retirejs.db"
    stats = retirejs.import_to_db(data, db)
    assert stats["techs"] == 3            # jquery + angular + backbone
    assert stats["patterns"] == 5         # jquery: 3 + angular: 1 + backbone: 1
    assert stats["hashes"] == 1

    cache = retirejs.build_cache(db)
    assert cache["stats"]["techs"] == 3
    # All 5 patterns compile under Python re (no JS-specific syntax here).
    assert cache["stats"]["patterns"] == 5
    assert cache["stats"]["skipped_patterns"] == 0
    # Tech names round-tripped.
    names = {cp.tech_name for cp in cache["compiled"]}
    assert {"jquery", "angular", "backbone"} <= names


def test_import_is_idempotent(tmp_path: Path):
    """Re-importing must wipe and rewrite — not accumulate duplicates."""
    data = retirejs.parse_repo(json.dumps(FIXTURE).encode("utf-8"))
    db = tmp_path / "r.db"
    retirejs.import_to_db(data, db)
    stats = retirejs.import_to_db(data, db)   # second pass
    assert stats["techs"] == 3   # not doubled
    cache = retirejs.build_cache(db)
    assert cache["stats"]["techs"] == 3


def test_build_cache_skips_uncompilable_patterns(tmp_path: Path):
    """retire.js uses some JS regex features Python can't compile. The
    importer stores the raw string; build_cache silently drops any that
    don't compile and reports the count."""
    data = retirejs.parse_repo(json.dumps({
        "bad": {"extractors": {"filecontent": [
            r"valid-(\d+)",                  # compiles
            r"(?<!foo\w+)(?<!x)invalid(?!",  # malformed — unclosed
        ]}}
    }).encode("utf-8"))
    db = tmp_path / "r.db"
    retirejs.import_to_db(data, db)
    cache = retirejs.build_cache(db)
    assert cache["stats"]["patterns"] == 1
    assert cache["stats"]["skipped_patterns"] == 1


# ---------------------------------------------------------------------------
# Scan
# ---------------------------------------------------------------------------


@pytest.fixture
def cache(tmp_path: Path) -> dict:
    data = retirejs.parse_repo(json.dumps(FIXTURE).encode("utf-8"))
    db = tmp_path / "retirejs.db"
    retirejs.import_to_db(data, db)
    return retirejs.build_cache(db)


def test_scan_body_detects_via_filecontent(cache):
    # Synthetic regex in the fixture is `/\*![\n\s]*jQuery v(...)` — it
    # expects only whitespace/newline between the comment open and the
    # library name. Real retire.js regexes are more forgiving.
    body = "/*!\n\njQuery v3.6.0 | (c) OpenJS Foundation\n"
    dets = retirejs.scan_body(body, "http://t/app.js", cache)
    jquery_content = [d for d in dets if d.source == "filecontent" and d.tech == "jquery"]
    assert jquery_content
    assert jquery_content[0].version == "3.6.0"


def test_scan_body_detects_via_filename(cache):
    dets = retirejs.scan_body("", "http://t/assets/jquery-1.12.4.min.js", cache)
    via_filename = [d for d in dets if d.source == "filename" and d.tech == "jquery"]
    assert via_filename
    assert via_filename[0].version == "1.12.4"


def test_scan_body_detects_via_uri(cache):
    dets = retirejs.scan_body(
        "", "http://t/ajax/libs/jquery/3.5.1/jquery.min.js", cache,
    )
    via_uri = [d for d in dets if d.source == "uri" and d.tech == "jquery"]
    assert via_uri
    assert via_uri[0].version == "3.5.1"


def test_scan_body_detects_via_sha1_hash(cache):
    body = "jquery-v1.9.0-payload"
    dets = retirejs.scan_body(body, "http://t/obscure.js", cache)
    hash_hits = [d for d in dets if d.source == "hash"]
    assert hash_hits
    assert hash_hits[0].tech == "jquery"
    assert hash_hits[0].version == "1.9.0"


def test_scan_body_no_match_returns_empty(cache):
    dets = retirejs.scan_body("plain text, no versioned library here", "http://t/x", cache)
    assert dets == []


def test_uri_version_rejects_path_segments(cache):
    # backbone uri pattern can backtrack and capture "hostname/path" as version.
    # The fix: version containing "/" is suppressed for uri/filename matchers.
    dets = retirejs.scan_body(
        "", "https://2game.vn/wp-includes/js/backbone.min.js?ver=1.6.0", cache,
    )
    bb = [d for d in dets if d.tech == "backbone"]
    # Match is expected (backbone.min.js present in URL)
    assert bb, "backbone should be detected by uri pattern"
    assert bb[0].version is None or "/" not in bb[0].version, (
        f"version should not contain a slash, got {bb[0].version!r}"
    )


def test_uri_version_accepts_real_semver(cache):
    dets = retirejs.scan_body(
        "", "https://cdn.example.com/1.6.0/backbone.min.js", cache,
    )
    bb = [d for d in dets if d.tech == "backbone"]
    assert bb and bb[0].version == "1.6.0"


def test_scan_body_handles_multiple_techs(cache):
    body = "const ng_version = '15.2.9';"
    dets = retirejs.scan_body(body, "http://t/app.js", cache)
    angular = [d for d in dets if d.tech == "angular"]
    assert angular and angular[0].version == "15.2.9"
