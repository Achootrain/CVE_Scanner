"""Tests for fp.katana (Phase 7 — static endpoint extraction)."""

from __future__ import annotations

import asyncio
import json
from unittest.mock import AsyncMock, patch

import pytest

from fp import katana


# ---------------------------------------------------------------------------
# Sample Katana JSONL records
#
# Schema confirmed from upstream docs:
#   {timestamp, request:{method,endpoint,raw}, response:{status_code,headers,body}}
# ---------------------------------------------------------------------------


def _rec(url: str, *, ct: str = "text/html", status: int = 200, method: str = "GET") -> dict:
    return {
        "timestamp": "2026-04-30T00:00:00Z",
        "request": {"method": method, "endpoint": url, "raw": ""},
        "response": {
            "status_code": status,
            "headers": {"content-type": ct},
            "body": "",
        },
    }


# ---------------------------------------------------------------------------
# parse_katana_jsonl
# ---------------------------------------------------------------------------


class TestParseJsonl:
    def test_parses_lines(self):
        blob = "\n".join([
            json.dumps(_rec("https://a.test/1")),
            json.dumps(_rec("https://a.test/2")),
        ])
        recs = katana.parse_katana_jsonl(blob)
        assert len(recs) == 2

    def test_skips_blank_lines(self):
        blob = "\n\n" + json.dumps(_rec("https://a.test/1")) + "\n\n"
        recs = katana.parse_katana_jsonl(blob)
        assert len(recs) == 1

    def test_skips_malformed_lines(self):
        blob = "{not json\n" + json.dumps(_rec("https://a.test/1"))
        recs = katana.parse_katana_jsonl(blob)
        assert len(recs) == 1

    def test_handles_bytes(self):
        blob = json.dumps(_rec("https://a.test/x")).encode("utf-8")
        recs = katana.parse_katana_jsonl(blob)
        assert len(recs) == 1


# ---------------------------------------------------------------------------
# classify_records: pages vs JS
# ---------------------------------------------------------------------------


class TestClassify:
    def test_js_by_content_type(self):
        recs = [_rec("https://a.test/x", ct="application/javascript")]
        out = katana.classify_records(recs)
        assert out[0].is_js is True

    def test_js_by_extension(self):
        recs = [_rec("https://a.test/static/app.js", ct="text/plain")]
        out = katana.classify_records(recs)
        assert out[0].is_js is True

    def test_js_with_query_string(self):
        recs = [_rec("https://a.test/static/app.js?v=12345", ct="text/plain")]
        out = katana.classify_records(recs)
        assert out[0].is_js is True

    def test_html_not_js(self):
        recs = [_rec("https://a.test/page", ct="text/html")]
        out = katana.classify_records(recs)
        assert out[0].is_js is False

    def test_mjs_extension(self):
        recs = [_rec("https://a.test/m.mjs", ct="text/plain")]
        out = katana.classify_records(recs)
        assert out[0].is_js is True

    def test_ecmascript_ct(self):
        recs = [_rec("https://a.test/x", ct="text/ecmascript")]
        out = katana.classify_records(recs)
        assert out[0].is_js is True

    def test_skips_record_with_no_endpoint(self):
        out = katana.classify_records([{"request": {}, "response": {}}])
        assert out == []

    def test_status_extracted(self):
        recs = [_rec("https://a.test/x", status=404)]
        out = katana.classify_records(recs)
        assert out[0].status == 404

    def test_handles_missing_response_block(self):
        recs = [{"request": {"method": "GET", "endpoint": "https://a.test/x"}}]
        out = katana.classify_records(recs)
        assert out[0].url == "https://a.test/x"
        assert out[0].is_js is False


# ---------------------------------------------------------------------------
# Layer 1: dedup_pages -- the forum scenario
# ---------------------------------------------------------------------------


class TestDedupPages:
    def test_collapses_numeric_threads(self):
        urls = [f"https://forum.test/threads/{i}" for i in range(1, 21)]
        out = katana.dedup_pages(urls, "forum.test", max_per_template=5)
        assert len(out) == 5

    def test_uuid_template_collapse(self):
        urls = [
            f"https://a.test/users/{u}/profile"
            for u in (
                "11111111-1111-1111-1111-111111111111",
                "22222222-2222-2222-2222-222222222222",
                "33333333-3333-3333-3333-333333333333",
            )
        ]
        out = katana.dedup_pages(urls, "a.test", max_per_template=1)
        assert len(out) == 1

    def test_distinct_templates_kept(self):
        urls = [
            "https://forum.test/threads/1",
            "https://forum.test/threads/2",
            "https://forum.test/profile",
            "https://forum.test/about",
        ]
        out = katana.dedup_pages(urls, "forum.test", max_per_template=1)
        # threads/1 (template /threads/{n}), profile, about -> 3 templates
        assert len(out) == 3
        assert "https://forum.test/threads/1" in out
        assert "https://forum.test/profile" in out
        assert "https://forum.test/about" in out

    def test_drops_cross_registrable(self):
        urls = [
            "https://forum.test/x",
            "https://other.test/y",
        ]
        out = katana.dedup_pages(urls, "forum.test", max_per_template=10)
        assert "https://other.test/y" not in out
        assert "https://forum.test/x" in out

    def test_keeps_cross_registrable_when_disabled(self):
        urls = ["https://other.test/y"]
        out = katana.dedup_pages(
            urls, "forum.test",
            max_per_template=10, same_registrable_only=False,
        )
        assert "https://other.test/y" in out

    def test_huge_forum_scenario(self):
        # 100k posts, three real templates
        urls = [f"https://forum.test/threads/{i}" for i in range(100_000)]
        urls += [f"https://forum.test/posts/{i}" for i in range(100_000)]
        urls += ["https://forum.test/login", "https://forum.test/register"]
        out = katana.dedup_pages(urls, "forum.test", max_per_template=3)
        # 3 reps of threads, 3 reps of posts, login, register
        assert len(out) == 3 + 3 + 2


# ---------------------------------------------------------------------------
# Layer 2: dedup_js -- canonical URL collapse + cap
# ---------------------------------------------------------------------------


class TestDedupJs:
    def test_strips_query_string(self):
        urls = [
            "https://cdn.test/app.js?v=1",
            "https://cdn.test/app.js?v=2",
            "https://cdn.test/app.js",
        ]
        out = katana.dedup_js(urls, cap=10)
        assert len(out) == 1

    def test_distinct_paths_kept(self):
        urls = [
            "https://cdn.test/app.js",
            "https://cdn.test/vendor.js",
            "https://cdn.test/runtime.js",
        ]
        out = katana.dedup_js(urls, cap=10)
        assert len(out) == 3

    def test_cap_enforced(self):
        urls = [f"https://cdn.test/chunk-{i}.js" for i in range(100)]
        out = katana.dedup_js(urls, cap=10)
        assert len(out) == 10

    def test_host_case_insensitive(self):
        urls = [
            "https://CDN.test/app.js",
            "https://cdn.test/app.js",
        ]
        out = katana.dedup_js(urls, cap=10)
        assert len(out) == 1

    def test_first_seen_wins(self):
        urls = [
            "https://cdn.test/app.js?v=first",
            "https://cdn.test/app.js?v=second",
        ]
        out = katana.dedup_js(urls, cap=10)
        assert out == ["https://cdn.test/app.js?v=first"]


# ---------------------------------------------------------------------------
# Binary discovery
# ---------------------------------------------------------------------------


class TestFindBinary:
    def test_returns_none_when_missing(self, monkeypatch):
        monkeypatch.delenv("KATANA_BIN", raising=False)
        # Force shutil.which to find nothing
        monkeypatch.setattr(katana.shutil, "which", lambda _: None)
        assert katana.find_katana_binary() is None

    def test_explicit_env_path_to_file(self, monkeypatch, tmp_path):
        bin_path = tmp_path / "katana"
        bin_path.write_text("")
        monkeypatch.setenv("KATANA_BIN", str(bin_path))
        assert katana.find_katana_binary() == str(bin_path)

    def test_explicit_env_dir(self, monkeypatch, tmp_path):
        (tmp_path / "katana").write_text("")
        monkeypatch.setenv("KATANA_BIN", str(tmp_path))
        out = katana.find_katana_binary()
        assert out is not None
        assert out.endswith("katana") or out.endswith("katana.exe")

    def test_falls_back_to_path(self, monkeypatch):
        monkeypatch.delenv("KATANA_BIN", raising=False)
        monkeypatch.setattr(
            katana.shutil, "which",
            lambda name: "/fake/" + name if name == "katana" else None,
        )
        assert katana.find_katana_binary() == "/fake/katana"


# ---------------------------------------------------------------------------
# Argument construction
# ---------------------------------------------------------------------------


class TestBuildArgs:
    def test_minimum(self):
        args = katana.build_katana_args(
            "/bin/katana", "https://a.test",
            depth=2, headless=False, jsluice=False,
        )
        assert args[0] == "/bin/katana"
        assert "-u" in args and "https://a.test" in args
        assert "-d" in args and "2" in args
        assert "-jc" in args
        assert "-jsonl" in args
        assert "-headless" not in args
        assert "-jsl" not in args

    def test_concurrency_default_present(self):
        args = katana.build_katana_args(
            "/bin/katana", "https://a.test",
            depth=1, headless=False, jsluice=False,
        )
        # -c <n> should always be passed so katana doesn't default to its
        # own (10) which is too aggressive for the container's RAM budget.
        assert "-c" in args
        i = args.index("-c")
        assert args[i + 1] == str(katana.DEFAULT_KATANA_CONCURRENCY)

    def test_concurrency_override(self):
        args = katana.build_katana_args(
            "/bin/katana", "https://a.test",
            depth=1, headless=False, jsluice=False,
            concurrency=2,
        )
        i = args.index("-c")
        assert args[i + 1] == "2"

    def test_headless_flag(self):
        args = katana.build_katana_args(
            "/bin/katana", "https://a.test",
            depth=1, headless=True, jsluice=False,
        )
        assert "-headless" in args

    def test_jsluice_flag(self):
        args = katana.build_katana_args(
            "/bin/katana", "https://a.test",
            depth=1, headless=False, jsluice=True,
        )
        assert "-jsl" in args

    def test_extra_args_appended(self):
        args = katana.build_katana_args(
            "/bin/katana", "https://a.test",
            depth=1, headless=False, jsluice=False,
            extra_args=["-rl", "10"],
        )
        assert args[-2:] == ["-rl", "10"]


class TestDefaults:
    def test_default_timeout_at_least_300s(self):
        # 120s was too tight for medium sites; bumped to 300.
        assert katana.DEFAULT_KATANA_TIMEOUT >= 300

    def test_default_concurrency_capped(self):
        # Katana's own default is 10. We cap at <= 10 (currently 5).
        assert 1 <= katana.DEFAULT_KATANA_CONCURRENCY <= 10


# ---------------------------------------------------------------------------
# run_katana raises when binary missing
# ---------------------------------------------------------------------------


class TestRunKatanaMissing:
    def test_raises_runtime_error_with_install_hint(self, monkeypatch):
        monkeypatch.delenv("KATANA_BIN", raising=False)
        monkeypatch.setattr(katana.shutil, "which", lambda _: None)

        async def _run():
            await katana.run_katana("https://a.test")

        with pytest.raises(RuntimeError) as exc_info:
            asyncio.run(_run())
        assert "katana binary not found" in str(exc_info.value)


# ---------------------------------------------------------------------------
# crawl() end-to-end with a mocked subprocess
# ---------------------------------------------------------------------------


def _mock_subprocess_output(records: list[dict]) -> bytes:
    return ("\n".join(json.dumps(r) for r in records)).encode("utf-8")


def _install_fake_katana_subprocess(monkeypatch, records: list[dict]):
    """Replace asyncio.create_subprocess_exec with a stub that exposes a
    line-iterating proc.stdout (run_katana streams JSONL line-by-line).

    The stub surfaces records as separate ``readline()`` returns so the
    URL-budget cap can fire mid-crawl in tests. Returns the proc object
    so tests can assert on terminate()/kill() if needed.
    """
    monkeypatch.setattr(katana, "find_katana_binary", lambda: "/fake/katana")

    lines = [json.dumps(r).encode("utf-8") + b"\n" for r in records]
    # run_katana now uses chunked read() instead of readline() (asyncio's
    # readline has a 64 KiB separator-search limit that Katana JSONL with
    # full response bodies routinely trips). The mock needs to mirror that.
    blob = b"".join(lines)

    class _FakeStdout:
        def __init__(self):
            self._buf = bytearray(blob)
        async def read(self, n: int = -1) -> bytes:
            if not self._buf:
                return b""
            if n < 0 or n >= len(self._buf):
                out, self._buf = bytes(self._buf), bytearray()
            else:
                out = bytes(self._buf[:n])
                del self._buf[:n]
            return out
        async def readline(self) -> bytes:
            # Kept for any legacy code path; not used by run_katana anymore.
            nl = self._buf.find(b"\n")
            if nl == -1:
                if not self._buf:
                    return b""
                out, self._buf = bytes(self._buf), bytearray()
                return out
            out = bytes(self._buf[: nl + 1])
            del self._buf[: nl + 1]
            return out

    class _FakeStderr:
        async def read(self) -> bytes:
            return b""

    class _FakeProc:
        def __init__(self):
            self.stdout = _FakeStdout()
            self.stderr = _FakeStderr()
            self.returncode = None
            self.terminated = False
            self.killed = False
        async def wait(self):
            self.returncode = 0
            return 0
        def terminate(self):
            self.terminated = True
            self.returncode = -15
        def kill(self):
            self.killed = True
            self.returncode = -9

    proc_holder: dict = {}

    async def _fake_exec(*a, **kw):
        proc_holder["proc"] = _FakeProc()
        return proc_holder["proc"]

    monkeypatch.setattr(katana.asyncio, "create_subprocess_exec", _fake_exec)
    return proc_holder


class TestCrawl:
    def test_end_to_end_mock(self, monkeypatch, tmp_path):
        # Forum scenario: 50 thread URLs + 1 page + 1 unique JS shared by all
        records = (
            [_rec(f"https://forum.test/threads/{i}", ct="text/html") for i in range(50)]
            + [_rec("https://forum.test/about", ct="text/html")]
            + [_rec("https://cdn.forum.test/app.js?v=1", ct="application/javascript")]
            + [_rec("https://cdn.forum.test/app.js?v=2", ct="application/javascript")]
        )
        _install_fake_katana_subprocess(monkeypatch, records)

        result = asyncio.run(katana.crawl(
            "https://forum.test",
            depth=2,
            max_templates_per_host=3,
            extract_bodies=False,
            max_katana_urls=0,  # disable cap so all 53 records flow through
        ))

        # 50 thread pages collapse to 3, /about kept -> 4 page URLs
        assert result.stats["page_urls_total"] == 51
        assert result.stats["page_urls_deduped"] == 4
        # Two JS variants of app.js collapse to 1
        assert result.stats["js_urls_total"] == 2
        assert result.stats["js_urls_deduped"] == 1
        assert len(result.js_urls) == 1
        assert result.paths == []


# ---------------------------------------------------------------------------
# fetch_html_and_extract -- backlogs.md item #1 fix
# ---------------------------------------------------------------------------


class TestFetchHtmlAndExtract:
    def test_extracts_form_action(self, monkeypatch):
        """XenForo / classic-PHP scenario: API surface is in HTML form actions."""
        html = b"""<html><body>
            <form method="post" action="/login.php">
                <input name="user">
            </form>
            <a data-href="/api/threads/list" hx-get="/threads/recent">x</a>
        </body></html>"""
        _install_fake_aiohttp(monkeypatch, [(200, html, "text/html")])

        async def run():
            return await katana.fetch_html_and_extract(["https://forum.test/"])
        paths, stats = asyncio.run(run())

        found = {p.path for p in paths}
        assert "/login.php" in found
        assert "/api/threads/list" in found
        assert "/threads/recent" in found
        assert stats["fetch_ok"] == 1
        assert stats["unique_bodies"] == 1
        # All extracted paths are attributed to the source URL
        assert all(p.source_url == "https://forum.test/" for p in paths)

    def test_sha1_dedup_across_pages(self, monkeypatch):
        """Two URLs that return the same body get only the first counted."""
        html = b"<html><form action='/login'></form></html>"
        _install_fake_aiohttp(monkeypatch, [
            (200, html, "text/html"),
            (200, html, "text/html"),  # identical body
        ])

        async def run():
            return await katana.fetch_html_and_extract([
                "https://a.test/page1",
                "https://a.test/page2",
            ])
        paths, stats = asyncio.run(run())

        assert stats["fetch_ok"] == 2
        assert stats["unique_bodies"] == 1
        assert stats["sha1_dedup_drops"] == 1

    def test_4xx_skipped(self, monkeypatch):
        _install_fake_aiohttp(monkeypatch, [(403, b"", "text/html")])

        async def run():
            return await katana.fetch_html_and_extract(["https://a.test/"])
        paths, stats = asyncio.run(run())

        assert paths == []
        assert stats["fetch_4xx_5xx"] == 1
        assert stats["unique_bodies"] == 0

    def test_seen_paths_shared_across_passes(self, monkeypatch):
        """JS pass and HTML pass share a seen-paths set so the same path
        doesn't appear twice."""
        html = b"<form action='/api/x'></form>"
        _install_fake_aiohttp(monkeypatch, [(200, html, "text/html")])

        shared: set[str] = {"/api/x"}  # pretend JS pass already saw this

        async def run():
            return await katana.fetch_html_and_extract(
                ["https://a.test/"], seen_paths=shared,
            )
        paths, _ = asyncio.run(run())
        assert paths == []  # /api/x already in seen


def _install_fake_aiohttp(monkeypatch, responses: list[tuple[int, bytes, str]]):
    """Patch aiohttp.ClientSession with a stub that replays canned responses.

    The cursor lives on the response list itself (via a closure) so the
    index keeps advancing across multiple ClientSession instances -- crawl()
    opens one session per fetch pass (JS, then HTML).
    """
    import aiohttp

    cursor = {"i": 0}

    class _FakeResp:
        def __init__(self, status, body, ct):
            self.status = status
            self._body = body
            self._ct = ct
        async def __aenter__(self): return self
        async def __aexit__(self, *a): return None
        async def read(self): return self._body
        @property
        def headers(self): return {"content-type": self._ct}

    class _FakeSession:
        def __init__(self, *a, **kw): pass
        async def __aenter__(self): return self
        async def __aexit__(self, *a): return None
        def get(self, url, **kw):
            r = responses[cursor["i"]]
            cursor["i"] += 1
            return _FakeResp(*r)

    monkeypatch.setattr(aiohttp, "ClientSession", _FakeSession)


# ---------------------------------------------------------------------------
# crawl() with extract_html: end-to-end stats namespacing
# ---------------------------------------------------------------------------


class TestCrawlWithHtmlExtraction:
    def test_html_stats_namespaced(self, monkeypatch):
        """When both --extract-bodies and --extract-html run, JS stats stay
        unprefixed (backwards compat) and HTML stats live under html_*."""
        records = [
            _rec("https://hybrid.test/", ct="text/html"),
            _rec("https://hybrid.test/login", ct="text/html"),
            _rec("https://hybrid.test/static/app.js", ct="application/javascript"),
        ]
        _install_fake_katana_subprocess(monkeypatch, records)

        # 3 fetches: app.js (JS pass), then / and /login (HTML pass).
        _install_fake_aiohttp(monkeypatch, [
            (200, b"fetch('/api/users')", "application/javascript"),
            (200, b"<form action='/api/login'></form>", "text/html"),
            (200, b"<a data-href='/api/logout'>x</a>", "text/html"),
        ])

        result = asyncio.run(katana.crawl(
            "https://hybrid.test",
            extract_bodies=True,
            extract_html=True,
        ))

        # JS pass stats are top-level (backwards compat)
        assert "fetch_ok" in result.stats
        assert "paths_extracted_js" in result.stats
        # HTML pass stats are namespaced
        assert "html_fetch_ok" in result.stats
        assert "paths_extracted_html" in result.stats
        # Combined total
        assert result.stats["paths_extracted"] == (
            result.stats["paths_extracted_js"] + result.stats["paths_extracted_html"]
        )
        # Both JS and HTML endpoints surfaced
        found = {p.path for p in result.paths}
        assert "/api/users" in found
        assert "/api/login" in found
        assert "/api/logout" in found

    def test_extract_html_off_by_default(self, monkeypatch):
        """Plain --extract-bodies (no --extract-html) does not fetch HTML."""
        records = [
            _rec("https://x.test/", ct="text/html"),
            _rec("https://x.test/static/a.js", ct="application/javascript"),
        ]
        _install_fake_katana_subprocess(monkeypatch, records)

        # Only 1 fetch expected (the JS file).
        _install_fake_aiohttp(monkeypatch, [
            (200, b"fetch('/api/x')", "application/javascript"),
        ])

        result = asyncio.run(katana.crawl(
            "https://x.test",
            extract_bodies=True,
            extract_html=False,
        ))
        assert "html_fetch_ok" not in result.stats
        assert "paths_extracted_html" not in result.stats

    def test_config_leaks_extracted_during_html_sweep(self, monkeypatch):
        """backlogs.md item #3: __NUXT__ / __NEXT_DATA__ / window.ENV blobs
        in fetched HTML should populate result.config_leaks with classified
        ConfigLeak records, namespaced stats, and survive the HTML sweep."""
        records = [
            _rec("https://spa.test/", ct="text/html"),
        ]
        _install_fake_katana_subprocess(monkeypatch, records)

        nuxt_html = (
            b"<html><body><script>"
            b"window.__NUXT__={config:{"
            b'BASE_URL:"https://api.spa.test/v2/",'
            b'COGNITO_CLIENT_ID:"abc123def456",'
            b'STRIPE_PUBLIC_KEY:"pk_live_51HabcdEFGHijklmnop1234567890QRST"'
            b"}};"
            b"</script></body></html>"
        )
        _install_fake_aiohttp(monkeypatch, [(200, nuxt_html, "text/html")])

        result = asyncio.run(katana.crawl(
            "https://spa.test",
            extract_bodies=False,
            extract_html=True,
        ))

        assert result.stats["config_leaks_total"] == 3
        klasses = {l.leak_class for l in result.config_leaks}
        assert klasses == {"backend_url", "auth_id", "api_key"}
        assert all(l.framework == "nuxt" for l in result.config_leaks)
        # Per-class tally surfaced in stats
        assert result.stats["config_leaks_by_class"]["backend_url"] == 1
        assert result.stats["config_leaks_by_class"]["api_key"] == 1

    def test_no_config_leaks_when_extract_html_off(self, monkeypatch):
        """Without --extract-html, config_leaks list and stat stay empty."""
        records = [
            _rec("https://x.test/static/a.js", ct="application/javascript"),
        ]
        _install_fake_katana_subprocess(monkeypatch, records)
        _install_fake_aiohttp(monkeypatch, [
            (200, b"fetch('/api/x')", "application/javascript"),
        ])

        result = asyncio.run(katana.crawl(
            "https://x.test",
            extract_bodies=True,
            extract_html=False,
        ))
        assert result.config_leaks == []
        assert result.stats["config_leaks_total"] == 0

    def test_max_html_caps_fetches(self, monkeypatch):
        """--max-html truncates the HTML fetch list."""
        records = [
            _rec(f"https://x.test/page{i}", ct="text/html") for i in range(20)
        ]
        _install_fake_katana_subprocess(monkeypatch, records)

        _install_fake_aiohttp(monkeypatch, [(200, b"<html></html>", "text/html")] * 5)

        result = asyncio.run(katana.crawl(
            "https://x.test",
            extract_bodies=False,
            extract_html=True,
            max_html_files=5,
            max_katana_urls=0,  # disable URL cap so all 20 pages flow through
        ))
        # 20 unique pages classified, but only 5 fetched
        assert result.stats["page_urls_deduped"] == 20
        assert result.stats["html_fetch_attempted"] == 5


# ---------------------------------------------------------------------------
# URL-budget cap (backlogs.md item #2 fix)
# ---------------------------------------------------------------------------


class TestUrlBudgetCap:
    def test_budget_hit_terminates_subprocess(self, monkeypatch):
        """Forum-style scenario: 1000 thread URLs, budget=10. Subprocess
        terminates as soon as 10 unique URLs are seen."""
        records = [
            _rec(f"https://forum.test/threads/{i}", ct="text/html")
            for i in range(1000)
        ]
        proc_holder = _install_fake_katana_subprocess(monkeypatch, records)

        async def run():
            return await katana.run_katana(
                "https://forum.test", max_urls=10,
            )
        records_out, budget_hit = asyncio.run(run())

        assert budget_hit is True
        assert len(records_out) == 10
        # The subprocess was terminated after the budget fired.
        assert proc_holder["proc"].terminated is True

    def test_budget_not_hit_finishes_naturally(self, monkeypatch):
        """Small site under the cap returns budget_hit=False."""
        records = [_rec(f"https://small.test/page{i}", ct="text/html") for i in range(5)]
        proc_holder = _install_fake_katana_subprocess(monkeypatch, records)

        async def run():
            return await katana.run_katana(
                "https://small.test", max_urls=100,
            )
        records_out, budget_hit = asyncio.run(run())

        assert budget_hit is False
        assert len(records_out) == 5
        assert proc_holder["proc"].terminated is False

    def test_budget_zero_disables_cap(self, monkeypatch):
        """max_urls=0 lets katana run to completion regardless of count."""
        records = [_rec(f"https://big.test/p{i}", ct="text/html") for i in range(200)]
        proc_holder = _install_fake_katana_subprocess(monkeypatch, records)

        async def run():
            return await katana.run_katana(
                "https://big.test", max_urls=0,
            )
        records_out, budget_hit = asyncio.run(run())

        assert budget_hit is False
        assert len(records_out) == 200
        assert proc_holder["proc"].terminated is False

    def test_budget_counts_unique_urls_not_records(self, monkeypatch):
        """Duplicate URLs in katana output don't double-count against budget."""
        # Same URL repeated 20 times -> only 1 unique URL.
        records = [_rec("https://x.test/dup") for _ in range(20)]
        _install_fake_katana_subprocess(monkeypatch, records)

        async def run():
            return await katana.run_katana("https://x.test", max_urls=5)
        records_out, budget_hit = asyncio.run(run())

        # Only 1 unique URL across 20 records: budget never fires.
        assert budget_hit is False

    def test_crawl_surfaces_budget_hit_in_stats(self, monkeypatch):
        """The crawl() wrapper exposes budget_hit + the budget value via stats."""
        records = [_rec(f"https://forum.test/threads/{i}") for i in range(50)]
        _install_fake_katana_subprocess(monkeypatch, records)

        result = asyncio.run(katana.crawl(
            "https://forum.test",
            max_katana_urls=10,
            extract_bodies=False,
        ))
        assert result.stats["katana_budget_hit"] is True
        assert result.stats["katana_url_budget"] == 10


class TestDefaultsAfterFix:
    def test_default_depth_restored_to_two(self):
        """Backlog item #2 fix: default depth back to 2 since the URL budget
        cap now provides the safety net for forum-style fan-out."""
        assert katana.DEFAULT_DEPTH == 2

    def test_default_url_budget_present(self):
        """A non-zero default budget must exist so users don't accidentally
        hit the unbounded-crawl pathology."""
        assert katana.DEFAULT_MAX_KATANA_URLS > 0
