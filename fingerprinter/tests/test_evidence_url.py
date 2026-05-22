"""Regression tests: scanner records the matched asset URL, not just the page URL.

CLAUDE.md "problem exist": sites detected as font-awesome were logging
`url=https://<site>/` — i.e. the root page that nuclei probed, not the
`<link href>` URL whose value triggered the matcher. The pipeline then has
no asset URL to mine a version from, so version always shows as `-`.

Fix: when a body-text word matcher fires, scan the body for <link>/<script>
URLs containing the matched word and record one as `evidence_url` on the
Detection. Downstream consumers prefer it over the page URL.
"""
from __future__ import annotations

import asyncio

import fp.scanner as scanner_mod
from fp.scanner import (
    Detection,
    FetchedResponse,
    _evaluate_request,
    _find_matcher_evidence_url,
)


# ---------------------------------------------------------------------------
# _find_matcher_evidence_url — unit
# ---------------------------------------------------------------------------


def _resp(body: bytes) -> FetchedResponse:
    return FetchedResponse(
        url="https://site.test/", status=200,
        headers={"Content-Type": "text/html"}, body=body,
    )


class TestFindMatcherEvidenceUrl:
    def test_word_matcher_finds_link_href(self):
        body = (
            b'<html><head>'
            b'<link rel="stylesheet" href="https://cdn/x/font-awesome.min.css">'
            b'</head></html>'
        )
        matcher = {
            "type": "word", "part": "body",
            "condition": "or", "negative": False,
            "case_insensitive": False,
            "values": ["font-awesome"],
        }
        assert _find_matcher_evidence_url(_resp(body), matcher) == \
            "https://cdn/x/font-awesome.min.css"

    def test_word_matcher_finds_script_src(self):
        body = b'<script src="/assets/slick.min.js?ver=1.8.1"></script>'
        matcher = {
            "type": "word", "part": "body",
            "condition": "or", "negative": False,
            "case_insensitive": False,
            "values": ["slick"],
        }
        # Raw href value -- stages resolve against page URL when fetching.
        assert _find_matcher_evidence_url(_resp(body), matcher) == \
            "/assets/slick.min.js?ver=1.8.1"

    def test_case_insensitive_word(self):
        body = b'<link href="/Font-Awesome.css">'
        matcher = {
            "type": "word", "part": "body",
            "condition": "or", "negative": False,
            "case_insensitive": True,
            "values": ["font-awesome"],
        }
        assert _find_matcher_evidence_url(_resp(body), matcher) == "/Font-Awesome.css"

    def test_no_matching_url_returns_none(self):
        body = b'<p>font-awesome is mentioned in text only</p>'
        matcher = {
            "type": "word", "part": "body",
            "condition": "or", "negative": False,
            "case_insensitive": False,
            "values": ["font-awesome"],
        }
        assert _find_matcher_evidence_url(_resp(body), matcher) is None

    def test_non_body_part_returns_none(self):
        body = b'<link href="/x/font-awesome.css">'
        matcher = {
            "type": "word", "part": "header",
            "condition": "or", "negative": False,
            "case_insensitive": False,
            "values": ["font-awesome"],
        }
        assert _find_matcher_evidence_url(_resp(body), matcher) is None

    def test_non_word_matcher_returns_none(self):
        body = b'<link href="/x/font-awesome.css">'
        matcher = {
            "type": "status", "part": "body",
            "condition": "or", "negative": False,
            "values": [200],
        }
        assert _find_matcher_evidence_url(_resp(body), matcher) is None

    def test_regex_matcher_link_tag_match(self):
        """Regression: cache.json's Wappalyzer 'font-awesome' rule is a regex
        matcher that consumes the whole <link ... font-awesome.css> tag. We
        must still recover the href URL from inside the match."""
        body = (
            b'<html><head>'
            b'<link rel="stylesheet" href="https://site/x/font-awesome.min.css">'
            b'</head></html>'
        )
        matcher = {
            "type": "regex", "part": "body",
            "condition": "or", "negative": False,
            "case_insensitive": False,
            "values": [r"<link[^>]* href=[^>]+(?:css/)?font-awesome(?:\.min)?\.css"],
        }
        assert _find_matcher_evidence_url(_resp(body), matcher) == \
            "https://site/x/font-awesome.min.css"

    def test_regex_matcher_no_url_in_match_falls_back_to_nearby(self):
        """Regex matches an inline string with no <link>/<script> nearby."""
        body = b'<style>.fa{font-family:"FontAwesome";}</style>'
        matcher = {
            "type": "regex", "part": "body",
            "condition": "or", "negative": False,
            "case_insensitive": False,
            "values": [r"font-?family:\s*[\"']FontAwesome"],
        }
        # No URL anywhere in body
        assert _find_matcher_evidence_url(_resp(body), matcher) is None

    def test_returns_first_match_when_multiple(self):
        body = (
            b'<link href="/a/font-awesome.css">'
            b'<link href="/b/font-awesome.min.css">'
        )
        matcher = {
            "type": "word", "part": "body",
            "condition": "or", "negative": False,
            "case_insensitive": False,
            "values": ["font-awesome"],
        }
        # First in document order
        assert _find_matcher_evidence_url(_resp(body), matcher) == "/a/font-awesome.css"


# ---------------------------------------------------------------------------
# _evaluate_request integration — Detection.evidence_url is populated
# ---------------------------------------------------------------------------


class TestEvaluateRequestPopulatesEvidenceUrl:
    def _make_template_and_req(self):
        template = {
            "id": "tech-detect", "name": "Tech Detect",
            "vendor": None, "product": None, "category": None,
            "cpe": None, "severity": "info", "tags": [],
        }
        request = {
            "template_pk": 1,
            "matchers_condition": "or",
            "stop_at_first_match": False,
            "extractors": [],
            "matchers": [
                {"type": "word", "name": "font-awesome", "part": "body",
                 "condition": "or", "negative": False,
                 "case_insensitive": False,
                 "values": ["font-awesome"]},
            ],
        }
        return template, request

    def test_word_match_records_link_href_as_evidence_url(self):
        template, request = self._make_template_and_req()
        body = (
            b'<html><body>'
            b'<link rel="stylesheet" href="https://cdn/x/font-awesome.min.css?ver=4.7.0">'
            b'</body></html>'
        )
        resp = FetchedResponse(
            url="https://site.test/", status=200,
            headers={"Content-Type": "text/html"}, body=body,
        )
        detections = _evaluate_request(
            request, template, "https://site.test/", "/", resp,
        )
        assert len(detections) == 1
        det = detections[0]
        assert det.matcher_name == "font-awesome"
        assert det.url == "https://site.test/"          # page URL preserved
        assert det.evidence_url == "https://cdn/x/font-awesome.min.css?ver=4.7.0"

    def test_matcher_fires_but_no_url_in_body_evidence_url_is_none(self):
        template, request = self._make_template_and_req()
        body = b'<html><body><p>font-awesome rocks</p></body></html>'
        resp = FetchedResponse(
            url="https://site.test/", status=200,
            headers={"Content-Type": "text/html"}, body=body,
        )
        detections = _evaluate_request(
            request, template, "https://site.test/", "/", resp,
        )
        assert len(detections) == 1
        assert detections[0].evidence_url is None
