"""Offline tests for matcher/extractor primitives — no network, no DB."""

from __future__ import annotations

from fp.scanner import (
    Detection,
    FetchedResponse,
    _evaluate_request,
    _run_extractors,
)


def _resp(status=200, headers=None, body=b"") -> FetchedResponse:
    return FetchedResponse(url="http://t/", status=status, headers=headers or {}, body=body)


def _tpl(**kw):
    base = {
        "id": "t-demo",
        "name": "Demo",
        "vendor": None,
        "product": None,
        "category": None,
        "cpe": None,
        "severity": "info",
        "tags": [],
    }
    base.update(kw)
    return base


def test_word_matcher_or_any_hit():
    req = {
        "matchers_condition": "or",
        "stop_at_first_match": False,
        "extractors": [],
        "matchers": [
            {"type": "word", "name": "wp", "part": "body",
             "condition": "or", "negative": False, "values": ["wp-login.php"]}
        ],
    }
    resp = _resp(body=b"<a href='/wp-login.php'>login</a>")
    dets = _evaluate_request(req, _tpl(), "http://t/", "/", resp)
    assert len(dets) == 1 and dets[0].matcher_name == "wp"


def test_word_matcher_case_sensitive_by_default():
    """Nuclei word matchers are case-sensitive unless the template sets
    `case-insensitive: true`. Without this, templates like jeecg-boot-detect
    (word: `Jeecg-Boot`) fire on 404 pages that reflect the lowercase path
    back into the body. Regression test for that FP class."""
    req = {
        "matchers_condition": "or",
        "stop_at_first_match": False,
        "extractors": [],
        "matchers": [
            {"type": "word", "name": None, "part": "body",
             "condition": "or", "negative": False,
             "case_insensitive": False,
             "values": ["Jeecg-Boot"]},
        ],
    }
    # Lowercase path reflection (Drupal 404 / body class) must NOT match.
    assert len(_evaluate_request(req, _tpl(), "http://t/", "/", _resp(
        body=b'<body class="page-jeecg-boot">not found /jeecg-boot/</body>'))) == 0
    # Exact-case occurrence still matches.
    assert len(_evaluate_request(req, _tpl(), "http://t/", "/", _resp(
        body=b'Jeecg-Boot admin panel'))) == 1


def test_word_matcher_case_insensitive_opt_in():
    """When `case-insensitive: true`, cache.py lowers values and scanner
    lowers body — so mixed-case text still matches."""
    req = {
        "matchers_condition": "or",
        "stop_at_first_match": False,
        "extractors": [],
        "matchers": [
            {"type": "word", "name": None, "part": "body",
             "condition": "or", "negative": False,
             "case_insensitive": True,
             "values": ["jeecg-boot"]},   # pre-lowered by cache
        ],
    }
    assert len(_evaluate_request(req, _tpl(), "http://t/", "/", _resp(
        body=b'<body class="page-Jeecg-Boot">'))) == 1


def test_regex_matcher_case_insensitive_opt_in():
    req = {
        "matchers_condition": "or",
        "stop_at_first_match": False,
        "extractors": [],
        "matchers": [
            {"type": "regex", "name": None, "part": "body", "condition": "or",
             "negative": False, "case_insensitive": True,
             "values": [r"jeecg-boot"]},
        ],
    }
    assert len(_evaluate_request(req, _tpl(), "http://t/", "/", _resp(
        body=b'Jeecg-Boot'))) == 1
    # Default (case-sensitive) regex wouldn't match without the flag.
    req["matchers"][0]["case_insensitive"] = False
    assert len(_evaluate_request(req, _tpl(), "http://t/", "/", _resp(
        body=b'Jeecg-Boot'))) == 0


def test_word_matcher_and_all_required():
    req = {
        "matchers_condition": "and",
        "stop_at_first_match": False,
        "extractors": [],
        "matchers": [
            {"type": "word", "name": None, "part": "body",
             "condition": "and", "negative": False, "values": ["foo", "bar"]},
        ],
    }
    assert len(_evaluate_request(req, _tpl(), "http://t/", "/", _resp(body=b"has foo only"))) == 0
    assert len(_evaluate_request(req, _tpl(), "http://t/", "/", _resp(body=b"has foo and bar"))) == 1


def test_status_and_kval_and_mode():
    req = {
        "matchers_condition": "and",
        "stop_at_first_match": False,
        "extractors": [],
        "matchers": [
            {"type": "status", "name": None, "part": "", "condition": "or",
             "negative": False, "values": [200]},
            {"type": "kval", "name": None, "part": "header", "condition": "or",
             "negative": False, "values": ["server"]},
        ],
    }
    resp = _resp(status=200, headers={"Server": "Apache/2.4"})
    assert len(_evaluate_request(req, _tpl(), "http://t/", "/", resp)) == 1
    resp2 = _resp(status=404, headers={"Server": "Apache/2.4"})
    assert len(_evaluate_request(req, _tpl(), "http://t/", "/", resp2)) == 0


def test_regex_matcher_case_and_multiline():
    req = {
        "matchers_condition": "or",
        "stop_at_first_match": False,
        "extractors": [],
        "matchers": [
            {"type": "regex", "name": "gen", "part": "body", "condition": "or",
             "negative": False,
             "values": [r"<generator>https?:\/\/wordpress\.org.*</generator>"]}
        ],
    }
    body = b"<rss><channel><generator>https://wordpress.org/?v=6.4</generator></channel></rss>"
    dets = _evaluate_request(req, _tpl(), "http://t/", "/", _resp(body=body))
    assert len(dets) == 1


def test_negative_matcher_inverts():
    req = {
        "matchers_condition": "or",
        "stop_at_first_match": False,
        "extractors": [],
        "matchers": [
            {"type": "word", "name": "no-wp", "part": "body",
             "condition": "or", "negative": True, "values": ["wp-login.php"]}
        ],
    }
    dets = _evaluate_request(req, _tpl(), "http://t/", "/", _resp(body=b"plain html"))
    assert len(dets) == 1


def test_regex_extractor_group_capture():
    extractors = [{
        "type": "regex", "name": "version", "part": "body",
        "group": 1,
        "values": [r"wordpress.org\/\?v=([0-9.]+)"],
    }]
    resp = _resp(body=b"<link href='https://wordpress.org/?v=6.4.3'/>")
    out = _run_extractors(extractors, resp)
    assert out == {"version": ["6.4.3"]}


def test_dsl_status_code():
    req = {
        "matchers_condition": "or",
        "stop_at_first_match": False,
        "extractors": [],
        "matchers": [
            {"type": "dsl", "name": "s", "part": "body",
             "condition": "or", "negative": False,
             "values": ["status_code == 418"]},
        ],
    }
    assert len(_evaluate_request(req, _tpl(), "http://t/", "/", _resp(status=418))) == 1
    assert len(_evaluate_request(req, _tpl(), "http://t/", "/", _resp(status=200))) == 0
