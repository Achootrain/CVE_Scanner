"""Offline tests for Wappalyzer pattern parsing, version substitution, and evaluation."""

from __future__ import annotations

import re

from fp.wappalyzer import (
    SUPPORTED_FIELDS,
    WapPattern,
    WapTech,
    _apply_version,
    _extract_cookies,
    _extract_meta,
    _normalise_field,
    evaluate,
    parse_pattern,
)


# ---------------------------------------------------------------------------
# parse_pattern
# ---------------------------------------------------------------------------


def test_parse_pattern_plain():
    assert parse_pattern("foo") == ("foo", None, 100)


def test_parse_pattern_with_version():
    assert parse_pattern(r"WordPress ([\d.]+)\;version:\1") == (
        r"WordPress ([\d.]+)",
        r"\1",
        100,
    )


def test_parse_pattern_with_confidence():
    assert parse_pattern(r"foo\;confidence:50") == ("foo", None, 50)


def test_parse_pattern_with_both():
    assert parse_pattern(r"foo\;version:\1\;confidence:25") == ("foo", r"\1", 25)


def test_parse_pattern_bad_confidence_falls_back():
    assert parse_pattern(r"foo\;confidence:nope") == ("foo", None, 100)


# ---------------------------------------------------------------------------
# _normalise_field
# ---------------------------------------------------------------------------


def test_normalise_keyed_field_lowers_key():
    rows = _normalise_field("headers", {"X-Pingback": r"/xmlrpc\.php"})
    assert rows == [("headers", "x-pingback", r"/xmlrpc\.php", None, 100)]


def test_normalise_list_field_yields_multiple_rows():
    rows = _normalise_field("scriptSrc", [r"/wp-content/", r"wordpress"])
    assert len(rows) == 2
    assert {r[2] for r in rows} == {r"/wp-content/", r"wordpress"}


def test_supported_fields_set_is_sensible():
    # Guards against accidental removal during refactor.
    assert {"html", "headers", "meta", "scriptSrc", "cookies", "url"} <= SUPPORTED_FIELDS


# ---------------------------------------------------------------------------
# _apply_version
# ---------------------------------------------------------------------------


def test_apply_version_simple_backref():
    m = re.search(r"WordPress ([\d.]+)", "WordPress 6.4.2")
    assert _apply_version(r"\1", m) == "6.4.2"


def test_apply_version_ternary_present():
    m = re.search(r"WordPress( \d+)?", "WordPress 6")
    assert _apply_version(r"\1?yes:no", m) == "yes"


def test_apply_version_ternary_absent():
    m = re.search(r"WordPress( \d+)?", "WordPress")
    assert _apply_version(r"\1?yes:no", m) == "no"


def test_apply_version_missing_group_returns_empty():
    m = re.search(r"Foo", "Foo")
    assert _apply_version(r"\1", m) == ""


# ---------------------------------------------------------------------------
# HTML introspection helpers
# ---------------------------------------------------------------------------


def test_extract_meta_name_then_content():
    html = '<meta name="generator" content="WordPress 6.4">'
    assert _extract_meta(html) == {"generator": "WordPress 6.4"}


def test_extract_meta_content_then_name():
    html = '<meta content="Django 4.2" name="framework">'
    assert _extract_meta(html) == {"framework": "Django 4.2"}


def test_extract_cookies_parses_multiple():
    headers = {"Set-Cookie": "wp_lang=en; Path=/, PHPSESSID=abcd; HttpOnly"}
    cookies = _extract_cookies(headers)
    assert cookies["wp_lang"] == "en"
    assert cookies["phpsessid"] == "abcd"


def test_extract_cookies_survives_expires_dates():
    # Expires dates contain commas that must not fragment cookies.
    headers = {
        "Set-Cookie": (
            "sid=xyz; expires=Wed, 21 Oct 2026 07:28:00 GMT, "
            "other=ok"
        )
    }
    cookies = _extract_cookies(headers)
    assert cookies["sid"] == "xyz"
    assert cookies["other"] == "ok"


# ---------------------------------------------------------------------------
# evaluate — end to end
# ---------------------------------------------------------------------------


def _tech_wordpress() -> WapTech:
    return WapTech(
        name="WordPress",
        categories=["CMS"],
        website="https://wordpress.org",
        cpe="cpe:2.3:a:wordpress:wordpress:*:*:*:*:*:*:*:*",
        implies=["PHP"],
        patterns=[
            WapPattern(
                field="meta",
                key="generator",
                regex=re.compile(r"WordPress ?([\d.]+)?", re.IGNORECASE),
                version_tmpl=r"\1",
                confidence=100,
            ),
            WapPattern(
                field="html",
                key=None,
                regex=re.compile(r"/wp-content/", re.IGNORECASE),
                version_tmpl=None,
                confidence=100,
            ),
        ],
    )


def test_evaluate_detects_wordpress_with_version():
    cache = {"technologies": [_tech_wordpress()], "categories": {}}
    body = b'<html><meta name="generator" content="WordPress 6.4.2">' \
           b'<link href="/wp-content/themes/x/style.css"></html>'
    dets = evaluate(cache, "https://example.com/", {}, body)
    assert len(dets) == 1
    d = dets[0]
    assert d["name"] == "WordPress"
    assert d["version"] == "6.4.2"
    assert d["confidence"] == 100
    assert d["source"] == "wappalyzer"


def test_evaluate_no_match_returns_empty():
    cache = {"technologies": [_tech_wordpress()], "categories": {}}
    dets = evaluate(cache, "https://example.com/", {}, b"<html>plain</html>")
    assert dets == []


def test_evaluate_header_pattern():
    tech = WapTech(
        name="nginx",
        categories=["Web server"],
        website=None,
        cpe=None,
        implies=[],
        patterns=[
            WapPattern(
                field="headers",
                key="server",
                regex=re.compile(r"nginx(?:/([\d.]+))?", re.IGNORECASE),
                version_tmpl=r"\1",
                confidence=100,
            ),
        ],
    )
    cache = {"technologies": [tech], "categories": {}}
    dets = evaluate(cache, "https://x/", {"Server": "nginx/1.25.3"}, b"")
    assert len(dets) == 1
    assert dets[0]["version"] == "1.25.3"


def test_evaluate_script_src_pattern():
    tech = WapTech(
        name="jQuery",
        categories=["JavaScript libraries"],
        website=None,
        cpe=None,
        implies=[],
        patterns=[
            WapPattern(
                field="scriptSrc",
                key=None,
                regex=re.compile(r"jquery[.-]?([\d.]+)?\.js", re.IGNORECASE),
                version_tmpl=r"\1",
                confidence=100,
            ),
        ],
    )
    cache = {"technologies": [tech], "categories": {}}
    body = b'<html><script src="/assets/jquery-3.7.1.js"></script></html>'
    dets = evaluate(cache, "https://x/", {}, body)
    assert len(dets) == 1
    assert dets[0]["version"] == "3.7.1"
