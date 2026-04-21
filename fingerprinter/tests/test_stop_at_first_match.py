"""Regression test for stop-at-first-match scoping.

Historically the scanner would break out of request evaluation on later paths
once *any* prior detection existed, because it checked a global `detections`
list. This test ensures stop-at-first-match only triggers when the current
request block produced a match.
"""

from __future__ import annotations

import asyncio

import pytest

import fp.scanner as scanner_mod
from fp.scanner import FetchedResponse


class _DummySession:
    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False


def test_stop_at_first_match_does_not_skip_later_paths(monkeypatch):
    # Ensure no real HTTP happens.
    monkeypatch.setattr(scanner_mod.aiohttp, "ClientSession", lambda **_kw: _DummySession())

    async def fake_fetch(self, session, url: str) -> FetchedResponse:  # noqa: ARG001
        # Return different bodies per path.
        if url.endswith("/a"):
            body = b"hit-a"
        elif url.endswith("/b"):
            body = b"hit-b"
        else:
            body = b""
        return FetchedResponse(url=url, status=200, headers={"Server": "dummy"}, body=body)

    monkeypatch.setattr(scanner_mod.Scanner, "_fetch", fake_fetch)

    template = {
        "pk": 1,
        "id": "t1",
        "name": "Template1",
        "vendor": None,
        "product": None,
        "category": None,
        "cpe": None,
        "severity": "info",
        "tags": [],
    }

    # Path /a: first request matches and has stop-at-first-match.
    req1 = {
        "pk": 101,
        "template_pk": 1,
        "method": "GET",
        "headers": {},
        "body": None,
        "redirects": True,
        "max_redirects": 0,
        "stop_at_first_match": True,
        "matchers_condition": "or",
        "paths": ["/a"],
        "extractors": [],
        "matchers": [
            {
                "type": "word",
                "name": "a",
                "part": "body",
                "condition": "or",
                "negative": False,
                "values": ["hit-a"],
            }
        ],
    }

    # Path /b: first request does NOT match but has stop-at-first-match;
    # second request DOES match. The scanner must still evaluate it.
    req3 = {
        "pk": 103,
        "template_pk": 1,
        "method": "GET",
        "headers": {},
        "body": None,
        "redirects": True,
        "max_redirects": 0,
        "stop_at_first_match": True,
        "matchers_condition": "or",
        "paths": ["/b"],
        "extractors": [],
        "matchers": [
            {
                "type": "word",
                "name": "nope",
                "part": "body",
                "condition": "or",
                "negative": False,
                "values": ["does-not-exist"],
            }
        ],
    }
    req4 = {
        "pk": 104,
        "template_pk": 1,
        "method": "GET",
        "headers": {},
        "body": None,
        "redirects": True,
        "max_redirects": 0,
        "stop_at_first_match": False,
        "matchers_condition": "or",
        "paths": ["/b"],
        "extractors": [],
        "matchers": [
            {
                "type": "word",
                "name": "b",
                "part": "body",
                "condition": "or",
                "negative": False,
                "values": ["hit-b"],
            }
        ],
    }

    cache = {
        "templates": {1: template},
        "requests": {101: req1, 103: req3, 104: req4},
        "by_path": {"/a": [101], "/b": [103, 104]},
        "stats": {},
    }

    async def _run() -> list[scanner_mod.Detection]:
        s = scanner_mod.Scanner(cache, concurrency=5, timeout=5, verify_ssl=False)
        return await s.scan("http://example.test")

    dets = asyncio.run(_run())

    matcher_names = {d.matcher_name for d in dets}
    assert "a" in matcher_names
    assert "b" in matcher_names
