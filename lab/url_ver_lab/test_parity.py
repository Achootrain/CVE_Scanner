"""Parity test: lab.db rows == fp.url_ver constants.

Run with: python -m lab.url_ver_lab.test_parity
Or: pytest lab/url_ver_lab/test_parity.py
"""
from __future__ import annotations

import sys
from pathlib import Path


HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
DEFAULT_DB = REPO / "fingerprinter" / "lab.db"

sys.path.insert(0, str(REPO / "fingerprinter"))
from fp import url_ver  # noqa: E402
from lab.url_ver_lab import loader  # noqa: E402


def test_js_lib_map_parity() -> None:
    code = {k.lower(): v for k, v in url_ver._JS_LIB_MAP.items()}
    db = loader.load_js_lib_map(DEFAULT_DB)
    assert code == db, (
        f"_JS_LIB_MAP parity broken.\n"
        f"  only-in-code: {set(code) - set(db)}\n"
        f"  only-in-db:   {set(db) - set(code)}\n"
        f"  value-mismatch: {[(k, code[k], db[k]) for k in code if k in db and code[k] != db[k]]}"
    )


def test_wp_plugin_map_parity() -> None:
    code = {k.lower(): v for k, v in url_ver.WP_PLUGIN_MAP.items()}
    db = loader.load_wp_plugin_map(DEFAULT_DB)
    assert code == db, (
        f"WP_PLUGIN_MAP parity broken.\n"
        f"  only-in-code: {set(code) - set(db)}\n"
        f"  only-in-db:   {set(db) - set(code)}"
    )


def test_cdn_pkg_map_parity() -> None:
    code = {k.lower(): v for k, v in url_ver._CDN_PKG_MAP.items()}
    db = loader.load_cdn_pkg_map(DEFAULT_DB)
    assert code == db, (
        f"_CDN_PKG_MAP parity broken.\n"
        f"  only-in-code: {set(code) - set(db)}\n"
        f"  only-in-db:   {set(db) - set(code)}"
    )


def test_skip_stems_parity() -> None:
    code = frozenset(s.lower() for s in url_ver._SKIP_STEMS)
    db = loader.load_skip_stems(DEFAULT_DB)
    assert code == db, (
        f"_SKIP_STEMS parity broken.\n"
        f"  only-in-code: {code - db}\n"
        f"  only-in-db:   {db - code}"
    )


def test_cdn_patterns_parity() -> None:
    """Compare (pattern_str, pkg_group, version_group, fixed_name) tuples."""
    code = [(r[0].pattern, r[1], r[2], r[3]) for r in url_ver._CDN_PATTERNS]
    db = [(r[0].pattern, r[1], r[2], r[3]) for r in loader.load_cdn_patterns(DEFAULT_DB)]
    assert code == db, (
        f"_CDN_PATTERNS parity broken.\n"
        f"  only-in-code: {[r for r in code if r not in db]}\n"
        f"  only-in-db:   {[r for r in db if r not in code]}"
    )


def test_framework_patterns_parity() -> None:
    """Compare (pattern_str, tech, slug) tuples. Flags must match too."""
    code = [(r[0].pattern, r[1], r[2]) for r in url_ver._FRAMEWORK_PATTERNS]
    db = [(r[0].pattern, r[1], r[2]) for r in loader.load_framework_patterns(DEFAULT_DB)]
    assert code == db, (
        f"_FRAMEWORK_PATTERNS parity broken.\n"
        f"  only-in-code: {[r for r in code if r not in db]}\n"
        f"  only-in-db:   {[r for r in db if r not in code]}"
    )


def test_version_probes_parity() -> None:
    """Probe dataclass field-by-field equality."""
    from fp import version_probes  # noqa: WPS433
    code = version_probes.CATALOG
    db = loader.load_version_probes(DEFAULT_DB)
    assert len(code) == len(db), f"probe count mismatch: code={len(code)} db={len(db)}"
    for i, (a, b) in enumerate(zip(code, db)):
        for attr in ("name", "path", "regex", "method", "version_group",
                     "ok_status", "part", "content_hint", "headers"):
            assert getattr(a, attr) == getattr(b, attr), (
                f"probe[{i}].{attr} mismatch: code={getattr(a, attr)!r} db={getattr(b, attr)!r}"
            )


def main() -> int:
    tests = [
        test_js_lib_map_parity,
        test_wp_plugin_map_parity,
        test_cdn_pkg_map_parity,
        test_skip_stems_parity,
        test_cdn_patterns_parity,
        test_framework_patterns_parity,
        test_version_probes_parity,
    ]
    failed = 0
    for t in tests:
        try:
            t()
            print(f"  ok    {t.__name__}")
        except AssertionError as e:
            print(f"  FAIL  {t.__name__}")
            print(f"    {e}")
            failed += 1
    print(f"\n{len(tests) - failed}/{len(tests)} passed")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
