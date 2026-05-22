"""Tests for fp.version_probes (catalog matching + content_hint + run_catalog)."""

from __future__ import annotations

import asyncio

import pytest

from fp import version_probes as vp


# ---------------------------------------------------------------------------
# _match
# ---------------------------------------------------------------------------


class TestMatch:
    def test_wordpress_readme_extracts_version(self):
        body = "<html><body>...<br /> Version 6.4.3 ... WordPress ...</body></html>"
        probe = next(p for p in vp.CATALOG if p.name == "WordPress")
        assert vp._match(probe, 200, {}, body) == "6.4.3"

    def test_drupal_changelog(self):
        body = "Drupal 10.1.5, 2024-01-15\n----\nFix...\n"
        probe = next(p for p in vp.CATALOG if p.name == "Drupal")
        assert vp._match(probe, 200, {}, body) == "10.1.5"

    def test_grafana_buildinfo_json(self):
        body = '{"buildInfo":{"version":"10.2.3","commit":"abc"}}'
        probe = next(p for p in vp.CATALOG if p.name == "Grafana")
        assert vp._match(probe, 200, {}, body) == "10.2.3"

    def test_jenkins_header_part(self):
        # Header-part probe; body irrelevant.
        probe = next(p for p in vp.CATALOG if p.name == "Jenkins")
        headers = {"x-jenkins": "2.426.3"}
        assert vp._match(probe, 200, headers, "irrelevant body") == "2.426.3"

    def test_supabase_storage_bare_semver(self):
        probe = next(p for p in vp.CATALOG if p.name == "Supabase Storage")
        assert vp._match(probe, 200, {}, "1.54.0") == "1.54.0"
        assert vp._match(probe, 200, {}, "1.54.0\n") == "1.54.0"

    def test_status_gate_drops_non_200(self):
        probe = next(p for p in vp.CATALOG if p.name == "Drupal")
        body = "Drupal 10.1.5, 2024-01-15"
        assert vp._match(probe, 404, {}, body) is None

    def test_content_hint_required(self):
        # Joomla probe requires "<version>" in the body. Without it: None.
        probe = next(p for p in vp.CATALOG if p.name == "Joomla")
        assert vp._match(probe, 200, {}, "5.0.2") is None  # no <version> wrapper

    def test_no_match_returns_none(self):
        probe = next(p for p in vp.CATALOG if p.name == "WordPress")
        assert vp._match(probe, 200, {}, "no version here") is None

    def test_generic_api_info(self):
        probe = next(p for p in vp.CATALOG if p.name == "generic-api-info")
        body = '{"name":"my-app","version":"1.2.3"}'
        assert vp._match(probe, 200, {}, body) == "1.2.3"

    def test_generic_with_prerelease(self):
        probe = next(p for p in vp.CATALOG if p.name == "generic-api-info")
        body = '{"version":"4.0.0-rc.1"}'
        assert vp._match(probe, 200, {}, body) == "4.0.0-rc.1"


# ---------------------------------------------------------------------------
# _origin
# ---------------------------------------------------------------------------


class TestOrigin:
    def test_strips_path(self):
        assert vp._origin("https://x.test/foo/bar") == "https://x.test"

    def test_adds_https_for_bare_host(self):
        assert vp._origin("x.test") == "https://x.test"

    def test_preserves_port(self):
        assert vp._origin("http://x.test:8080/api") == "http://x.test:8080"


# ---------------------------------------------------------------------------
# run_catalog with mocked aiohttp
# ---------------------------------------------------------------------------


def _install_fake_aiohttp(monkeypatch, route_to_response: dict):
    """Patch aiohttp.ClientSession to return canned responses keyed by path."""
    import aiohttp

    class _FakeContent:
        def __init__(self, body: bytes):
            self._body = body
        async def read(self, n: int = -1) -> bytes:
            return self._body if n == -1 else self._body[:n]

    class _FakeResp:
        def __init__(self, status: int, body: bytes, headers: dict):
            self.status = status
            self.content = _FakeContent(body)
            self.headers = headers
        async def __aenter__(self): return self
        async def __aexit__(self, *a): return None

    class _FakeSession:
        def __init__(self, *a, **kw): pass
        async def __aenter__(self): return self
        async def __aexit__(self, *a): return None
        def request(self, method, url, **kw):
            from urllib.parse import urlsplit
            path = urlsplit(url).path or "/"
            if urlsplit(url).query:
                path = f"{path}?{urlsplit(url).query}"
            r = route_to_response.get(path)
            if r is None:
                return _FakeResp(404, b"", {})
            return _FakeResp(*r)

    monkeypatch.setattr(aiohttp, "ClientSession", _FakeSession)


class TestRunCatalog:
    def test_wordpress_target_pins_version(self, monkeypatch):
        _install_fake_aiohttp(monkeypatch, {
            "/readme.html": (200, b"<br /> Version 6.4.3 ... WordPress ...", {}),
        })
        hits = asyncio.run(vp.run_catalog("https://wp.test"))
        names = {h.probe.name: h.version for h in hits}
        assert names.get("WordPress") == "6.4.3"

    def test_no_hits_when_all_404(self, monkeypatch):
        _install_fake_aiohttp(monkeypatch, {})  # everything 404s
        hits = asyncio.run(vp.run_catalog("https://nothing.test"))
        assert hits == []

    def test_multiple_techs_one_target(self, monkeypatch):
        _install_fake_aiohttp(monkeypatch, {
            "/readme.html": (200, b"<br /> Version 6.4.3 ... WordPress ...", {}),
            "/storage/v1/version": (200, b"1.54.0\n", {}),
            "/api/v4/version": (200, b'{"version":"16.5.1"}', {}),
        })
        hits = asyncio.run(vp.run_catalog("https://stack.test"))
        by_name = {h.probe.name: h.version for h in hits}
        assert by_name["WordPress"] == "6.4.3"
        assert by_name["Supabase Storage"] == "1.54.0"
        assert by_name["GitLab"] == "16.5.1"

    def test_uses_custom_catalog(self, monkeypatch):
        custom = [
            vp.Probe(
                name="MyApp", path="/v",
                regex=r"MyApp v(\d+\.\d+\.\d+)",
            ),
        ]
        _install_fake_aiohttp(monkeypatch, {
            "/v": (200, b"MyApp v7.7.7", {}),
        })
        hits = asyncio.run(vp.run_catalog("https://mine.test", catalog=custom))
        assert len(hits) == 1
        assert hits[0].version == "7.7.7"

    def test_hit_to_dict_shape(self, monkeypatch):
        _install_fake_aiohttp(monkeypatch, {
            "/storage/v1/version": (200, b"1.54.0", {}),
        })
        hits = asyncio.run(vp.run_catalog("https://x.test"))
        d = hits[0].to_dict()
        assert d == {
            "name": "Supabase Storage",
            "version": "1.54.0",
            "path": "/storage/v1/version",
            "url": "https://x.test/storage/v1/version",
            "status": 200,
        }
