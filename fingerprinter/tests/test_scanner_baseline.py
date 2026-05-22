"""Negative-baseline 404 fingerprint: SPA / catch-all-rewrite hosts (Vercel,
Netlify, Cloudflare Pages) return 200 + index.html for every unknown path.
Without this fix, any nuclei matcher that triggers on the index body fires
on every nonexistent probed path. The scanner now probes a guaranteed-absent
path first, captures (status, body sha256), and skips matcher evaluation on
non-root responses that match that signature."""

from __future__ import annotations

import asyncio

import pytest

import fp.scanner as scanner_mod
from fp.scanner import FetchedResponse


SPA_SHELL = (
    b'<!doctype html><html><head><title>App</title></head>'
    b'<body><div id="root"></div>'
    b'<script src="/assets/index.js"></script></body></html>'
)


class _DummySession:
    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False


def _spa_cache_with_phantom_matcher() -> dict:
    """A nuclei cache with one template whose word matcher fires on any HTML
    containing `<div id="root">` — i.e. on the SPA shell. Without the
    baseline guard this would match every probed path on a SPA host."""
    template = {
        "id": "phantom-detect",
        "name": "Phantom Detect",
        "vendor": None, "product": None, "category": None,
        "cpe": None, "severity": "info", "tags": [],
    }
    request = {
        "template_pk": 1,
        "matchers_condition": "or",
        "stop_at_first_match": False,
        "extractors": [],
        "matchers": [
            {"type": "word", "name": "root-div", "part": "body",
             "condition": "or", "negative": False,
             "values": ['<div id="root">']},
        ],
    }
    return {
        "templates": {1: template},
        "requests": {1: request},
        # Probe set hits both / and a path that DOES NOT exist on the host;
        # without the baseline fix, both responses match and produce dets.
        "by_path": {"/": [1], "/wp-login.php": [1]},
        "stats": {},
    }


def test_baseline_suppresses_phantom_200_on_spa_rewrite(monkeypatch):
    """Vercel-style behaviour: every URL returns the same SPA shell. The
    matcher must fire only against `/` (the legitimate homepage) and be
    suppressed against `/wp-login.php` (a phantom 200)."""
    monkeypatch.setattr(scanner_mod, "_CurlSession", lambda **_kw: _DummySession())

    seen_paths: list[str] = []

    async def fake_fetch(self, session, url: str) -> FetchedResponse:  # noqa: ARG001
        seen_paths.append(url)
        # Every path returns the same SPA shell — including the baseline
        # probe path with a UUID in it.
        return FetchedResponse(
            url=url, status=200,
            headers={"Content-Type": "text/html"},
            body=SPA_SHELL,
        )

    monkeypatch.setattr(scanner_mod.Scanner, "_fetch", fake_fetch)

    cache = _spa_cache_with_phantom_matcher()

    async def _run():
        s = scanner_mod.Scanner(cache, concurrency=5, timeout=5)
        return await s.scan("http://spa.test")

    detections = asyncio.run(_run())

    # Baseline probe path must have been requested.
    assert any("__fp_baseline_" in u for u in seen_paths), seen_paths

    # Exactly one detection: the homepage match. The /wp-login.php probe
    # returned the same body as baseline, so its match is suppressed.
    phantom_dets = [d for d in detections if d.template_id == "phantom-detect"]
    assert len(phantom_dets) == 1, [d.path for d in phantom_dets]
    assert phantom_dets[0].path == "/"


def test_baseline_does_not_suppress_when_responses_differ(monkeypatch):
    """When `/wp-login.php` actually returns a different body from the
    baseline probe, the matcher must still fire — suppression is keyed on
    body equality, not on path."""
    monkeypatch.setattr(scanner_mod, "_CurlSession", lambda **_kw: _DummySession())

    real_login = (
        b'<!doctype html><html><body><div id="root"></div>'
        b'<form id="loginform">distinct body for the real login page</form>'
        b'</body></html>'
    )

    async def fake_fetch(self, session, url: str) -> FetchedResponse:  # noqa: ARG001
        # Baseline probe path is unique per scan (UUID); return a 404 body
        # so the baseline signature differs from /wp-login.php's body.
        if "__fp_baseline_" in url:
            return FetchedResponse(
                url=url, status=404,
                headers={"Content-Type": "text/html"},
                body=b"<html><body>not found</body></html>",
            )
        if url.endswith("/wp-login.php"):
            return FetchedResponse(
                url=url, status=200,
                headers={"Content-Type": "text/html"},
                body=real_login,
            )
        # `/` returns the SPA shell.
        return FetchedResponse(
            url=url, status=200,
            headers={"Content-Type": "text/html"},
            body=SPA_SHELL,
        )

    monkeypatch.setattr(scanner_mod.Scanner, "_fetch", fake_fetch)

    cache = _spa_cache_with_phantom_matcher()

    async def _run():
        s = scanner_mod.Scanner(cache, concurrency=5, timeout=5)
        return await s.scan("http://t.test")

    detections = asyncio.run(_run())
    phantom_paths = sorted(d.path for d in detections if d.template_id == "phantom-detect")
    # Both `/` and `/wp-login.php` legitimately match — neither matches the baseline.
    assert phantom_paths == ["/", "/wp-login.php"]


def test_baseline_skips_when_probe_fails(monkeypatch):
    """If the baseline probe itself errors out, the scanner must fall back
    to its old behaviour (no suppression) — silently failing closed would
    silently disable detection on hosts that drop UUIDs paths but answer
    real probes."""
    monkeypatch.setattr(scanner_mod, "_CurlSession", lambda **_kw: _DummySession())

    async def fake_fetch(self, session, url: str) -> FetchedResponse:  # noqa: ARG001
        if "__fp_baseline_" in url:
            return FetchedResponse(
                url=url, status=0, headers={}, body=b"", error="boom",
            )
        return FetchedResponse(
            url=url, status=200,
            headers={"Content-Type": "text/html"},
            body=SPA_SHELL,
        )

    monkeypatch.setattr(scanner_mod.Scanner, "_fetch", fake_fetch)

    cache = _spa_cache_with_phantom_matcher()

    async def _run():
        s = scanner_mod.Scanner(cache, concurrency=5, timeout=5)
        return await s.scan("http://t.test")

    detections = asyncio.run(_run())
    phantom_paths = sorted(d.path for d in detections if d.template_id == "phantom-detect")
    # Baseline failed → pre-fix behaviour: matcher fires on both paths.
    assert phantom_paths == ["/", "/wp-login.php"]
