"""End-to-end test: Scanner pulls `<script src>` from the root HTML,
fetches each same-host script, runs retire.js, and emits Detection objects
with source='retirejs'.

No network — `_fetch` is monkeypatched to return synthetic responses so
the test runs deterministically in CI without Docker or aiohttp mocks."""

from __future__ import annotations

import asyncio
import hashlib
import json
from pathlib import Path

import pytest

import fp.retirejs as retirejs
import fp.scanner as scanner_mod
from fp.scanner import FetchedResponse


# ---------------------------------------------------------------------------
# Unit tests for _extract_script_refs
# ---------------------------------------------------------------------------


def test_extract_script_refs_resolves_relative_urls():
    html = """
    <html><body>
      <script src="/js/app.js"></script>
      <script src="./vendor.js"></script>
      <script src="lib.js"></script>
    </body></html>
    """
    refs = scanner_mod.extract_script_refs(html, "http://example.test/page")
    assert refs == [
        "http://example.test/js/app.js",
        "http://example.test/vendor.js",
        "http://example.test/lib.js",
    ]


def test_extract_script_refs_drops_cross_host_and_special_schemes():
    html = """
    <script src="https://cdn.example.com/lib.js"></script>
    <script src="//othercdn.com/x.js"></script>
    <script src="data:text/javascript,alert(1)"></script>
    <script src="javascript:void(0)"></script>
    <script src="/local.js"></script>
    """
    refs = scanner_mod.extract_script_refs(html, "http://target.local/")
    assert refs == ["http://target.local/local.js"]


def test_extract_script_refs_dedupes_and_caps():
    # Duplicates collapse.
    html = '<script src="/a.js"></script><script src="/a.js"></script>'
    assert scanner_mod.extract_script_refs(html, "http://t/") == ["http://t/a.js"]

    # Cap enforcement.
    many = "".join(f'<script src="/s{i}.js"></script>' for i in range(50))
    refs = scanner_mod.extract_script_refs(many, "http://t/")
    assert len(refs) == scanner_mod.MAX_RETIRE_SCRIPTS


def test_extract_script_refs_preserves_query_string():
    html = '<script src="/lib.js?ver=1.2.3"></script>'
    refs = scanner_mod.extract_script_refs(html, "http://t/")
    assert refs == ["http://t/lib.js?ver=1.2.3"]


# ---------------------------------------------------------------------------
# End-to-end: Scanner + retire_cache → retirejs Detections
# ---------------------------------------------------------------------------


@pytest.fixture
def retire_cache(tmp_path: Path) -> dict:
    """Build a small retire.js cache with jQuery + Bootstrap patterns."""
    repo = {
        "jquery": {"extractors": {
            "filecontent": [r"/\*!? jQuery v§§version§§"],
            "filename": [r"jquery-§§version§§(\.min)?\.js"],
        }},
        "bootstrap": {"extractors": {
            "filecontent": [r"/\*!\s*Bootstrap v§§version§§"],
        }},
    }
    data = retirejs.parse_repo(json.dumps(repo).encode("utf-8"))
    db = tmp_path / "retirejs.db"
    retirejs.import_to_db(data, db)
    return retirejs.build_cache(db)


class _DummySession:
    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False


def test_scanner_runs_retirejs_against_crawled_scripts(monkeypatch, retire_cache):
    """Happy path: root HTML references two scripts, both hit retire.js
    rules; Scanner returns Detection(source='retirejs') for each."""
    monkeypatch.setattr(scanner_mod, "_CurlSession", lambda **_kw: _DummySession())

    # Canned responses keyed by URL.
    responses = {
        # Root HTML
        "http://t.test": (
            b'<html><head>'
            b'<script src="/assets/jquery-3.6.0.min.js"></script>'
            b'<script src="/assets/bootstrap.js"></script>'
            b'<script src="https://cdn.external.com/other.js"></script>'  # dropped
            b'</head></html>'
        ),
        # Script bodies
        "http://t.test/assets/jquery-3.6.0.min.js": (
            b"/*! jQuery v3.6.0 | (c) OpenJS */"
        ),
        "http://t.test/assets/bootstrap.js": (
            b"/*! Bootstrap v5.3.2 (https://getbootstrap.com/) */"
        ),
    }

    async def fake_fetch(self, session, url: str) -> FetchedResponse:  # noqa: ARG001
        # Normalize: Scanner appends paths to the base; strip trailing slash.
        key = url.rstrip("/") if url.endswith("/") and url.count("/") == 3 else url
        if key == "http://t.test":
            return FetchedResponse(
                url=key, status=200,
                headers={"Content-Type": "text/html"},
                body=responses[key],
            )
        body = responses.get(url, b"")
        return FetchedResponse(
            url=url, status=200 if body else 404,
            headers={"Content-Type": "application/javascript"},
            body=body,
        )

    monkeypatch.setattr(scanner_mod.Scanner, "_fetch", fake_fetch)

    # Minimal nuclei cache — probes just "/".
    cache = {
        "templates": {},
        "requests": {},
        "by_path": {"/": []},
        "stats": {},
    }

    async def _run() -> list[scanner_mod.Detection]:
        s = scanner_mod.Scanner(cache, retire_cache=retire_cache, concurrency=5, timeout=5)
        return await s.scan("http://t.test")

    detections = asyncio.run(_run())

    retire_dets = [d for d in detections if d.source == "retirejs"]
    techs_found = {d.name for d in retire_dets}
    assert "jquery" in techs_found
    assert "bootstrap" in techs_found

    jquery = next(d for d in retire_dets if d.name == "jquery")
    assert jquery.version == "3.6.0"
    assert jquery.source == "retirejs"
    assert jquery.template_id == "retire:jquery"
    assert jquery.category == "javascript-library"
    assert "retirejs" in jquery.tags
    # Path was preserved from the fetched URL.
    assert jquery.path == "/assets/jquery-3.6.0.min.js"

    bootstrap = next(d for d in retire_dets if d.name == "bootstrap")
    assert bootstrap.version == "5.3.2"

    # Cross-host script must NOT contribute detections.
    assert all("external.com" not in d.url for d in retire_dets)


def test_scanner_skips_retirejs_when_cache_is_none(monkeypatch):
    """If no retire_cache, the script crawl must not even run — the scan
    returns whatever nuclei/wappalyzer produced without touching scripts."""
    monkeypatch.setattr(scanner_mod, "_CurlSession", lambda **_kw: _DummySession())

    called_urls: list[str] = []

    async def fake_fetch(self, session, url: str) -> FetchedResponse:  # noqa: ARG001
        called_urls.append(url)
        return FetchedResponse(
            url=url, status=200, headers={},
            body=b'<script src="/jquery.js"></script>',
        )

    monkeypatch.setattr(scanner_mod.Scanner, "_fetch", fake_fetch)

    cache = {"templates": {}, "requests": {}, "by_path": {"/": []}, "stats": {}}

    async def _run() -> list[scanner_mod.Detection]:
        s = scanner_mod.Scanner(cache, retire_cache=None, concurrency=5, timeout=5)
        return await s.scan("http://t.test")

    asyncio.run(_run())
    # Scanner must have fetched only the root path, not chased the script.
    assert all("/jquery.js" not in u for u in called_urls)


def test_scanner_skips_oversized_script_bodies(monkeypatch, retire_cache):
    """Scripts exceeding MAX_RETIRE_BODY_BYTES must be dropped before
    retire.js evaluation — scanning multi-MB bundles is expensive and
    very rarely produces a hit."""
    monkeypatch.setattr(scanner_mod, "_CurlSession", lambda **_kw: _DummySession())

    big_body = b"X" * (scanner_mod.MAX_RETIRE_BODY_BYTES + 1024)

    async def fake_fetch(self, session, url: str) -> FetchedResponse:  # noqa: ARG001
        if url.rstrip("/") == "http://t.test":
            return FetchedResponse(
                url="http://t.test", status=200, headers={},
                body=b'<script src="/huge.js"></script>',
            )
        # /huge.js returns a giant body that happens to contain a jQuery tag
        # retire.js would match — but the size gate must drop it first.
        return FetchedResponse(
            url=url, status=200, headers={},
            body=big_body + b"/*! jQuery v9.9.9",
        )

    monkeypatch.setattr(scanner_mod.Scanner, "_fetch", fake_fetch)

    cache = {"templates": {}, "requests": {}, "by_path": {"/": []}, "stats": {}}

    async def _run() -> list[scanner_mod.Detection]:
        s = scanner_mod.Scanner(cache, retire_cache=retire_cache, concurrency=5, timeout=5)
        return await s.scan("http://t.test")

    dets = asyncio.run(_run())
    # No retirejs detection: size gate fired.
    assert not [d for d in dets if d.source == "retirejs"]


def test_scanner_crawls_scripts_from_non_root_html_responses(monkeypatch, retire_cache):
    """CMS scripts often live on /wp-login.php or /admin rather than /.
    The scanner must pull refs from every HTML response it fetches, not
    just the homepage."""
    monkeypatch.setattr(scanner_mod, "_CurlSession", lambda **_kw: _DummySession())

    responses = {
        "http://t.test": (
            b"<!doctype html><html><body>no scripts here</body></html>"
        ),
        "http://t.test/login": (
            b'<!doctype html><html><body>'
            b'<script src="/js/jquery-3.6.0.min.js"></script>'
            b'</body></html>'
        ),
        "http://t.test/js/jquery-3.6.0.min.js": (
            b"/*! jQuery v3.6.0 | (c) OpenJS */"
        ),
    }

    async def fake_fetch(self, session, url: str) -> FetchedResponse:  # noqa: ARG001
        key = url.rstrip("/") if url.count("/") == 3 and url.endswith("/") else url
        body = responses.get(key, responses.get(url, b""))
        headers = {"Content-Type": "text/html"} if body.startswith((b"<!doctype", b"<html")) \
                  else {"Content-Type": "application/javascript"}
        return FetchedResponse(
            url=url, status=200 if body else 404,
            headers=headers, body=body,
        )

    monkeypatch.setattr(scanner_mod.Scanner, "_fetch", fake_fetch)

    # Nuclei cache probes `/` AND `/login` — scanner must walk the login
    # response for script refs too.
    cache = {
        "templates": {},
        "requests": {},
        "by_path": {"/": [], "/login": []},
        "stats": {},
    }

    async def _run() -> list[scanner_mod.Detection]:
        s = scanner_mod.Scanner(cache, retire_cache=retire_cache, concurrency=5, timeout=5)
        return await s.scan("http://t.test")

    dets = asyncio.run(_run())
    jquery = [d for d in dets if d.source == "retirejs" and d.name == "jquery"]
    assert jquery, "expected jQuery detection from /login's script ref"
    assert jquery[0].version == "3.6.0"


def test_looks_like_html_catches_common_shapes():
    # Content-Type header is the primary signal.
    assert scanner_mod._looks_like_html(FetchedResponse(
        url="", status=200, headers={"Content-Type": "text/html; charset=utf-8"}, body=b""
    ))
    # Missing Content-Type — sniff the body.
    assert scanner_mod._looks_like_html(FetchedResponse(
        url="", status=200, headers={}, body=b"<!DOCTYPE html>\n<html>"
    ))
    assert scanner_mod._looks_like_html(FetchedResponse(
        url="", status=200, headers={}, body=b"  <html><body>"
    ))
    # Non-HTML.
    assert not scanner_mod._looks_like_html(FetchedResponse(
        url="", status=200, headers={"Content-Type": "application/json"}, body=b"{}"
    ))


def test_retire_to_detection_shape():
    rd = retirejs.Detection(tech="jquery", version="3.6.0",
                            source="filecontent", evidence="jQuery v3.6.0")
    det = scanner_mod._retire_to_detection(rd, "http://t/j.js", "/j.js")
    assert det.source == "retirejs"
    assert det.template_id == "retire:jquery"
    assert det.name == "jquery"
    assert det.version == "3.6.0"
    assert det.matcher_name == "filecontent"
    assert det.category == "javascript-library"
    assert det.extracted == {"version": ["3.6.0"]}

    # No-version detection (matcher fired but didn't capture a group).
    rd_noversion = retirejs.Detection(tech="jquery", version=None,
                                      source="filecontent", evidence="blob")
    det = scanner_mod._retire_to_detection(rd_noversion, "http://t/j.js", "/j.js")
    assert det.version is None
    assert det.extracted == {}
