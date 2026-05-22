"""Tests for fp.cross_page (cross-route Wappalyzer + retire.js rescan)."""

from __future__ import annotations

import asyncio

from fp import cross_page as cp


# ---------------------------------------------------------------------------
# curl_cffi fake -- routes URL -> (status, body bytes, headers dict)
# ---------------------------------------------------------------------------


def _install_fake_session(monkeypatch, url_to_response: dict, request_log: list[str] | None = None):
    """Patch ``cp._CurlSession`` to return canned responses by URL.

    Unmatched URLs return 404. Headers default to ``{"Content-Type": "text/html"}``
    so ``_looks_like_html`` returns True for the common HTML case.
    """
    class _FakeResp:
        def __init__(self, status: int, body: bytes, headers: dict, url: str):
            self.status_code = status
            self.content = body       # bytes, no await (curl_cffi API)
            self.headers = headers
            self.url = url            # plain string (curl_cffi API)

    class _FakeSession:
        def __init__(self, *a, **kw): pass
        async def __aenter__(self): return self
        async def __aexit__(self, *a): return None
        async def get(self, url, **kw):
            if request_log is not None:
                request_log.append(url)
            r = url_to_response.get(url)
            if r is None:
                return _FakeResp(404, b"", {"Content-Type": "text/html"}, url)
            status, body, headers = r
            return _FakeResp(status, body, headers, url)

    monkeypatch.setattr(cp, "_CurlSession", _FakeSession)


# ---------------------------------------------------------------------------
# Fixture caches
# ---------------------------------------------------------------------------


def _wap_cache_with_xpowered_by_php():
    """Tiny in-memory wappalyzer cache: detects PHP via the X-Powered-By header.

    Mirrors what ``wappalyzer.build_cache`` returns: ``{"technologies": [WapTech, ...]}``
    consumed by ``wap_mod.evaluate``.
    """
    import re
    from fp import wappalyzer as wap

    pat = wap.WapPattern(
        field="headers",
        key="x-powered-by",  # evaluate() lowercases header keys
        regex=re.compile(r"PHP/?([\d.]+)?"),
        version_tmpl=r"\1",
        confidence=100,
    )
    php = wap.WapTech(
        name="PHP",
        categories=["Programming languages"],
        website=None,
        cpe=None,
        implies=[],
        patterns=[pat],
    )
    return {"technologies": [php]}


# ---------------------------------------------------------------------------
# rescan() -- empty / degenerate cases
# ---------------------------------------------------------------------------


class TestRescanEmptyCases:
    def test_no_urls_returns_empty(self):
        dets, stats = asyncio.run(cp.rescan(
            [], wap_cache={"x": 1}, retire_cache={"y": 1},
        ))
        assert dets == []
        assert stats["urls_input"] == 0

    def test_no_caches_returns_empty(self):
        dets, stats = asyncio.run(cp.rescan(
            ["https://t.test/a"], wap_cache=None, retire_cache=None,
        ))
        assert dets == []
        # Skipped before any HTTP work, so nothing fetched
        assert stats["urls_fetched"] == 0


# ---------------------------------------------------------------------------
# rescan() -- Wappalyzer pass
# ---------------------------------------------------------------------------


class TestRescanWappalyzer:
    def test_php_version_detected_on_admin_route(self, monkeypatch):
        """Regression for the cross-route gap: the seed homepage doesn't
        emit X-Powered-By, but /admin does. Cross-page rescan must catch it."""
        _install_fake_session(monkeypatch, {
            "https://t.test/admin": (
                200,
                b"<html><body>admin panel</body></html>",
                {"Content-Type": "text/html", "X-Powered-By": "PHP/8.2.10"},
            ),
            "https://t.test/login": (
                200,
                b"<html>login</html>",
                {"Content-Type": "text/html"},  # no X-Powered-By here
            ),
        })
        wap = _wap_cache_with_xpowered_by_php()
        dets, stats = asyncio.run(cp.rescan(
            ["https://t.test/admin", "https://t.test/login"],
            wap_cache=wap,
            retire_cache=None,
        ))
        php = [d for d in dets if d.get("name") == "PHP"]
        assert len(php) == 1
        assert php[0]["version"] == "8.2.10"
        # Evidence URL points at the route that fired, not the seed
        assert php[0]["url"] == "https://t.test/admin"
        assert php[0]["source"] == "wappalyzer"
        assert stats["urls_html"] == 2
        assert stats["wap_detections"] == 1

    def test_dedup_first_seen_wins(self, monkeypatch):
        _install_fake_session(monkeypatch, {
            "https://t.test/a": (
                200, b"<html>a</html>",
                {"Content-Type": "text/html", "X-Powered-By": "PHP/8.2.10"},
            ),
        })
        wap = _wap_cache_with_xpowered_by_php()
        # Pass /a twice; rescan must dedup before fetching.
        dets, stats = asyncio.run(cp.rescan(
            ["https://t.test/a", "https://t.test/a"],
            wap_cache=wap, retire_cache=None,
        ))
        assert stats["urls_after_dedup"] == 1
        assert stats["urls_fetched"] == 1

    def test_max_urls_caps_fetches(self, monkeypatch):
        # 100 URLs; cap at 5; only 5 should be fetched.
        urls = [f"https://t.test/p{i}" for i in range(100)]
        routes = {
            u: (200, b"<html></html>", {"Content-Type": "text/html"})
            for u in urls
        }
        _install_fake_session(monkeypatch, routes)
        wap = _wap_cache_with_xpowered_by_php()
        _, stats = asyncio.run(cp.rescan(
            urls, wap_cache=wap, retire_cache=None, max_urls=5,
        ))
        assert stats["urls_after_dedup"] == 5
        assert stats["urls_fetched"] == 5

    def test_ranking_prefers_rare_new_and_diverse_routes(self, monkeypatch):
        request_log: list[str] = []
        urls = [
            "https://t.test/threads/1",
            "https://t.test/threads/2",
            "https://t.test/admin",
            "https://t.test/threads/3",
        ]
        routes = {
            u: (200, b"<html></html>", {"Content-Type": "text/html"})
            for u in urls
        }
        _install_fake_session(monkeypatch, routes, request_log=request_log)
        wap = _wap_cache_with_xpowered_by_php()

        _, stats = asyncio.run(cp.rescan(
            urls, wap_cache=wap, retire_cache=None, max_urls=2,
        ))

        assert stats["urls_after_dedup"] == 2
        assert set(request_log) == {
            "https://t.test/admin",
            "https://t.test/threads/3",
        }

    def test_failed_fetch_increments_counter_does_not_crash(self, monkeypatch):
        # 404 routes are reported as urls_fetched (status != 0). Truly
        # failing fetches (network errors) hit urls_failed. Force a
        # network error by routing to a status-0 / error response.
        import aiohttp

        class _BoomSession:
            def __init__(self, *a, **kw): pass
            async def __aenter__(self): return self
            async def __aexit__(self, *a): return None
            def get(self, url, **kw):
                class _Ctx:
                    async def __aenter__(self):
                        raise aiohttp.ClientError("boom")
                    async def __aexit__(self, *a): return None
                return _Ctx()

        monkeypatch.setattr(aiohttp, "ClientSession", _BoomSession)
        wap = _wap_cache_with_xpowered_by_php()
        dets, stats = asyncio.run(cp.rescan(
            ["https://t.test/x"], wap_cache=wap, retire_cache=None,
        ))
        assert stats["urls_failed"] == 1
        assert stats["urls_fetched"] == 0
        assert dets == []


# ---------------------------------------------------------------------------
# Pipeline integration: cross-page detections feed reconcile()
# ---------------------------------------------------------------------------


class TestPipelineMergesCrossPageDetections:
    """The pipeline glue must concatenate cross_page_detections into the
    seed-scan detections list before reconcile() runs, so the merged tech
    list pulls evidence from both the seed scan and any cross-route hits."""

    def test_reconcile_merges_seed_and_cross_page_evidence(self):
        from fp import pipeline as pl
        # Simulate: seed-scan saw "WordPress" but no version; cross-page
        # rescan saw the same tech with a version on a different route.
        seed = {
            "source": "wappalyzer", "template_id": "wap:WordPress",
            "name": "WordPress", "matcher_name": None,
            "vendor": None, "product": "WordPress",
            "category": None, "cpe": None, "severity": None,
            "tags": [], "url": "https://t.test/", "path": "/",
            "extracted": {}, "version": None, "confidence": None,
        }
        cross = dict(seed)
        cross["url"] = "https://t.test/wp-login.php"
        cross["version"] = "6.4.3"
        recs = pl.reconcile([seed, cross], [])
        assert len(recs) == 1
        assert recs[0].name == "WordPress"
        assert recs[0].version == "6.4.3"
        # Both pieces of evidence are tracked
        urls = sorted(e["url"] for e in recs[0].evidence)
        assert urls == ["https://t.test/", "https://t.test/wp-login.php"]


# ---------------------------------------------------------------------------
# Body-hash dedup (PR-A: cuts wappalyzer cost on CDNs that serve identical
# HTML on many routes, e.g. WP themes, Shopify storefronts).
# ---------------------------------------------------------------------------


class TestWappalyzerBodyDedup:
    def test_identical_bodies_dedup_to_one_evaluation(self, monkeypatch):
        """Two URLs serving the SAME body+headers should run wap_evaluate once.

        Both routes still appear in the detections (each tagged with its own
        URL), but the second is satisfied from the body-hash cache. Stats
        report cache_hits=1 and cache_size=1."""
        identical = (
            200,
            b"<html><body>same html</body></html>",
            {"Content-Type": "text/html", "X-Powered-By": "PHP/8.2.10"},
        )
        _install_fake_session(monkeypatch, {
            "https://t.test/page-a": identical,
            "https://t.test/page-b": identical,
        })
        wap = _wap_cache_with_xpowered_by_php()

        # Count actual wap_mod.evaluate invocations to prove dedup is real.
        from fp import wappalyzer as wap_mod_real
        original = wap_mod_real.evaluate
        call_count = {"n": 0}
        def counting_evaluate(*a, **kw):
            call_count["n"] += 1
            return original(*a, **kw)
        monkeypatch.setattr(cp.wap_mod, "evaluate", counting_evaluate)

        dets, stats = asyncio.run(cp.rescan(
            ["https://t.test/page-a", "https://t.test/page-b"],
            wap_cache=wap,
            retire_cache=None,
        ))

        # Both routes produce a PHP detection (per-URL stamping after cache hit)
        php = [d for d in dets if d.get("name") == "PHP"]
        assert len(php) == 2
        urls = sorted(d["url"] for d in php)
        assert urls == ["https://t.test/page-a", "https://t.test/page-b"]

        # The actual expensive call ran ONCE.
        assert call_count["n"] == 1, (
            f"expected wap_mod.evaluate to dedup to 1 call, got {call_count['n']}")
        assert stats["wap_body_cache_hits"] == 1
        assert stats["wap_body_cache_size"] == 1

    def test_different_bodies_do_not_dedup(self, monkeypatch):
        """Sanity check the other direction: distinct bodies bypass the cache."""
        _install_fake_session(monkeypatch, {
            "https://t.test/a": (
                200, b"<html>a</html>",
                {"Content-Type": "text/html", "X-Powered-By": "PHP/8.2.10"},
            ),
            "https://t.test/b": (
                200, b"<html>b</html>",   # different body
                {"Content-Type": "text/html", "X-Powered-By": "PHP/8.2.10"},
            ),
        })
        wap = _wap_cache_with_xpowered_by_php()
        dets, stats = asyncio.run(cp.rescan(
            ["https://t.test/a", "https://t.test/b"],
            wap_cache=wap,
            retire_cache=None,
        ))
        assert stats["wap_body_cache_hits"] == 0
        assert stats["wap_body_cache_size"] == 2

    def test_body_dedup_key_ignores_irrelevant_headers(self):
        """Date/server-instance headers shouldn't bust the cache; the key
        only hashes the body head + headers that wap actually reads."""
        body = b"<html>x</html>"
        h1 = {"content-type": "text/html", "x-trace-id": "abc-1",
              "date": "Wed, 21 May 2026 10:00:00 GMT"}
        h2 = {"content-type": "text/html", "x-trace-id": "abc-2",
              "date": "Wed, 21 May 2026 11:00:00 GMT"}
        assert cp._body_dedup_key(body, h1) == cp._body_dedup_key(body, h2)

    def test_body_dedup_key_separates_on_xpowered_by(self):
        """Different X-Powered-By header -> different cache entry, because
        wap_evaluate's detection depends on it."""
        body = b"<html>x</html>"
        k1 = cp._body_dedup_key(body, {"x-powered-by": "PHP/8.2.10"})
        k2 = cp._body_dedup_key(body, {"x-powered-by": "PHP/7.4.0"})
        assert k1 != k2
