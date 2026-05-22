"""Static endpoint extraction via Katana (ProjectDiscovery).

Phase 7 of the build order: shells out to the ``katana`` binary, parses the
``-jsonl`` output, and applies three layers of dedup so the JS-fetch volume
stays bounded even on high-cardinality sites (e.g. forums with 100k+ thread
URLs all linking the same handful of bundles).

Layers
------
1. **Page-URL template dedup.** Reuses ``browser_capture.path_template`` so
   ``/threads/12345``, ``/threads/12346``, ... collapse to the same key. We
   keep at most ``max_templates_per_host`` representatives per template.
2. **JS-URL exact dedup.** Each unique JS asset URL (canonical form: query
   string stripped) is recorded at most once.
3. **Body SHA1 dedup.** Optional, only fires when re-fetching JS bodies for
   downstream regex extraction. Catches CDN-served same-content bundles
   served behind cache-busting query strings.

Katana already dedupes URLs at output. The forum scenario hurts at *crawl*
time, not output time, so this wrapper also exposes ``--depth`` as the
primary bandwidth control. Default depth is 2 (Katana's own default is 3).

Binary discovery order
----------------------
1. ``KATANA_BIN`` env var (absolute path)
2. ``katana`` / ``katana.exe`` on PATH

Missing binary -> RuntimeError with install hint.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import shutil
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from .url_utils import is_same_registrable, path_template
from .config_leaks import ConfigLeak, extract_config_leaks
from .jsextract import ExtractedPath, extract_paths, extract_paths_from_html


# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------

# Default depth was briefly lowered to 1 (commit before this) to fix the
# voz.vn forum-fanout timeout, but that regressed SPA coverage by ~40% on
# leetcode.com (lost the entire _buildManifest.js Next.js route haul -- see
# backlogs.md item #2 / D:\DATN2\comparision.json). Depth 2 is now restored
# as the default and the URL-budget cap below provides the safety net for
# high-cardinality fan-out instead.
DEFAULT_DEPTH = 2

# URL-budget cap: stream Katana's JSONL output and terminate the subprocess
# once N unique URLs have been observed. This bounds work regardless of
# site shape -- forums hit the cap fast and stop, SPAs typically finish
# under the cap with their full chunk graph captured. 500 is enough for
# leetcode-class SPAs (the depth-2 reference run hit 609 records but the
# valuable signals -- _buildManifest.js, top-level chunks -- come early).
DEFAULT_MAX_KATANA_URLS = 500

DEFAULT_MAX_JS_FILES = 50
# HTML fetches cost real network and the per-page extraction yield is much
# lower than JS bundles (most pages have at most a handful of form/data-href
# endpoints). Cap tighter than JS by default. Raise on hybrid sites
# (XenForo, ASP.NET, server-rendered Rails) where the API surface lives in
# HTML markup -- see backlogs.md item #1.
DEFAULT_MAX_HTML_FILES = 30
DEFAULT_MAX_TEMPLATES_PER_HOST = 5

# 300s wall-clock safety net. With the URL-budget cap above this rarely
# fires, but it still guards against pathological cases (network stalls,
# katana stuck in jsluice).
DEFAULT_KATANA_TIMEOUT = 300

# Katana's own default concurrency is 10. Capping at 5 trades crawl speed
# for RAM headroom -- relevant in containers where the parent process has
# to share memory with the OS image. Raise via --katana-concurrency.
DEFAULT_KATANA_CONCURRENCY = 5

DEFAULT_FETCH_TIMEOUT = 30
DEFAULT_MAX_BODY_BYTES = 1 * 1024 * 1024  # 1 MiB; mirrors retire.js cap
DEFAULT_USER_AGENT = "Mozilla/5.0 (compatible; fp-katana/0.1)"
_REDIRECT_RESOLVE_TIMEOUT = 10

INSTALL_HINT = (
    "katana binary not found.\n"
    "  Windows: download from https://github.com/projectdiscovery/katana/releases\n"
    "    extract katana.exe to a directory on PATH (or set KATANA_BIN env var)\n"
    "  Go users: go install github.com/projectdiscovery/katana/cmd/katana@latest\n"
)

_JS_CT_TOKENS = ("javascript", "ecmascript")
_JS_EXTS = (".js", ".mjs", ".cjs")


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------


@dataclass
class KatanaUrl:
    """One URL surfaced by katana, after content-type classification."""

    url: str
    method: str = "GET"
    status: int = 0
    content_type: str = ""
    is_js: bool = False


@dataclass
class KatanaResult:
    seed: str
    page_urls: list[str] = field(default_factory=list)
    js_urls: list[str] = field(default_factory=list)
    paths: list[ExtractedPath] = field(default_factory=list)
    config_leaks: list[ConfigLeak] = field(default_factory=list)
    stats: dict = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Binary discovery
# ---------------------------------------------------------------------------


def find_katana_binary() -> str | None:
    """Return absolute path to the katana binary, or None if not found."""
    explicit = os.environ.get("KATANA_BIN")
    if explicit:
        if os.path.isfile(explicit):
            return explicit
        # Allow KATANA_BIN to point at a directory containing the binary.
        for name in ("katana", "katana.exe"):
            cand = os.path.join(explicit, name)
            if os.path.isfile(cand):
                return cand
    return shutil.which("katana") or shutil.which("katana.exe")


# ---------------------------------------------------------------------------
# Subprocess invocation
# ---------------------------------------------------------------------------


def build_katana_args(
    binary: str,
    url: str,
    *,
    depth: int,
    headless: bool,
    jsluice: bool,
    concurrency: int = DEFAULT_KATANA_CONCURRENCY,
    user_agent: str | None = None,
    extra_args: list[str] | None = None,
) -> list[str]:
    args = [
        binary,
        "-u", url,
        "-d", str(depth),
        "-c", str(concurrency),
        "-jc",          # extract endpoints from JS via the built-in parser
        "-jsonl",
        "-silent",
        "-nc",          # no color
    ]
    if user_agent:
        args += ["-H", f"User-Agent: {user_agent}"]
    if jsluice:
        # -jsl runs jsluice; per upstream docs it is memory intensive.
        args.append("-jsl")
    if headless:
        args.append("-headless")
    if extra_args:
        args.extend(extra_args)
    return args


async def _run_katana_proc(
    args: list[str],
    *,
    timeout: int,
    max_urls: int,
) -> tuple[list[dict], bool]:
    """Core subprocess driver. Requires a loop that supports subprocesses
    (ProactorEventLoop on Windows, any loop on Unix)."""
    proc = await asyncio.create_subprocess_exec(
        *args,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )

    records: list[dict] = []
    seen_urls: set[str] = set()
    budget_hit = False

    def _process_line(line: bytes) -> bool:
        """Parse one JSONL line; return True iff budget just fired."""
        nonlocal budget_hit
        stripped = line.strip()
        if not stripped:
            return False
        try:
            rec = json.loads(stripped)
        except json.JSONDecodeError:
            return False
        records.append(rec)
        if max_urls > 0:
            ep = _endpoint_of(rec)
            if ep and ep not in seen_urls:
                seen_urls.add(ep)
                if len(seen_urls) >= max_urls:
                    budget_hit = True
                    return True
        return False

    async def _consume_stdout() -> None:
        """Read JSONL via chunked read + manual newline split.

        We avoid ``proc.stdout.readline()`` because asyncio's StreamReader
        enforces a 64 KiB separator-search limit (LimitOverrunError) and
        Katana JSONL records routinely embed full response bodies that
        push individual lines past that. Chunked ``read()`` has no such
        limit -- the buffer grows as needed.
        """
        nonlocal budget_hit
        assert proc.stdout is not None
        CHUNK = 64 * 1024
        buf = bytearray()
        while True:
            try:
                chunk = await proc.stdout.read(CHUNK)
            except asyncio.LimitOverrunError:
                # Defensive: even read() can hit limits on some platforms.
                # Drain what's currently buffered and continue.
                chunk = b""
            if not chunk:
                # EOF: flush any trailing partial line then return.
                if buf:
                    _process_line(bytes(buf))
                return
            buf.extend(chunk)
            while True:
                nl = buf.find(b"\n")
                if nl == -1:
                    break
                line = bytes(buf[:nl])
                del buf[: nl + 1]
                if _process_line(line):
                    return  # budget hit; caller will terminate

    try:
        await asyncio.wait_for(_consume_stdout(), timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill()
        try:
            await asyncio.wait_for(proc.wait(), timeout=3)
        except asyncio.TimeoutError:
            pass
        raise
    except asyncio.CancelledError:
        # External cancellation (e.g. pipeline katana_timeout). Kill the
        # subprocess before propagating so pipe transports get released.
        proc.kill()
        try:
            await asyncio.shield(asyncio.wait_for(proc.wait(), timeout=3))
        except (asyncio.TimeoutError, asyncio.CancelledError):
            pass
        raise
    finally:
        # Do NOT call feed_eof() here — it races with the OS delivering a
        # final pipe chunk after _consume_stdout returns, causing asyncio's
        # SubprocessStreamProtocol to raise AssertionError in its internal
        # pipe_data_received callback. The proc.wait() calls below are the
        # authoritative cleanup path; they release the transport naturally.
        pass

    # Budget hit: katana is still running. Terminate cleanly.
    if budget_hit and proc.returncode is None:
        proc.terminate()
        try:
            await asyncio.wait_for(proc.wait(), timeout=5)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
    elif proc.returncode is None:
        # Stdout EOF reached but proc may still be flushing -- let it exit.
        try:
            await asyncio.wait_for(proc.wait(), timeout=3)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()

    return records, budget_hit


async def run_katana(
    url: str,
    *,
    depth: int = DEFAULT_DEPTH,
    headless: bool = False,
    jsluice: bool = False,
    concurrency: int = DEFAULT_KATANA_CONCURRENCY,
    timeout: int = DEFAULT_KATANA_TIMEOUT,
    max_urls: int = DEFAULT_MAX_KATANA_URLS,
    user_agent: str | None = None,
    extra_args: list[str] | None = None,
    binary: str | None = None,
) -> tuple[list[dict], bool]:
    """Run katana against ``url`` with streaming JSONL parse + URL-budget cap.

    Returns ``(records, budget_hit)``:
      * ``records`` - list of parsed JSON dicts; malformed lines skipped.
      * ``budget_hit`` - True iff ``max_urls`` was reached and katana was
        terminated early. False if katana finished naturally.

    Streams stdout line-by-line; counts unique ``request.endpoint`` values
    and SIGTERMs the subprocess when the count crosses ``max_urls``. Pass
    ``max_urls=0`` to disable the cap (let katana run to completion).

    Raises:
      RuntimeError - katana binary not found.
      asyncio.TimeoutError - wall-clock ``timeout`` exceeded before the
        natural end of crawl OR the budget cap.
    """
    import sys

    bin_path = binary or find_katana_binary()
    if not bin_path:
        raise RuntimeError(INSTALL_HINT)

    args = build_katana_args(
        bin_path, url,
        depth=depth, headless=headless, jsluice=jsluice,
        concurrency=concurrency,
        user_agent=user_agent,
        extra_args=extra_args,
    )

    # Windows: cli.py sets WindowsSelectorEventLoopPolicy so curl_cffi's
    # add_reader works, but SelectorEventLoop cannot create subprocesses
    # (raises NotImplementedError). Run the subprocess in a thread that
    # spins up its own ProactorEventLoop to work around the conflict.
    if sys.platform == "win32":
        lp = asyncio.get_running_loop()
        if not isinstance(lp, asyncio.ProactorEventLoop):
            _args, _timeout, _max_urls = args, timeout, max_urls

            def _thread_fn() -> tuple[list[dict], bool]:
                new_loop = asyncio.ProactorEventLoop()
                try:
                    return new_loop.run_until_complete(
                        _run_katana_proc(_args, timeout=_timeout, max_urls=_max_urls)
                    )
                finally:
                    new_loop.close()

            return await lp.run_in_executor(None, _thread_fn)

    return await _run_katana_proc(args, timeout=timeout, max_urls=max_urls)


def parse_katana_jsonl(blob: bytes | str) -> list[dict]:
    """Parse Katana's -jsonl output. Skips malformed lines."""
    if isinstance(blob, bytes):
        blob = blob.decode("utf-8", errors="replace")
    out: list[dict] = []
    for line in blob.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return out


# ---------------------------------------------------------------------------
# Record classification + dedup
# ---------------------------------------------------------------------------


def _content_type_of(record: dict) -> str:
    resp = record.get("response") or {}
    headers = resp.get("headers") or {}
    if not isinstance(headers, dict):
        return ""
    for k, v in headers.items():
        if k.lower() == "content-type":
            return (v or "").lower()
    return ""


def _endpoint_of(record: dict) -> str:
    req = record.get("request") or {}
    return req.get("endpoint") or record.get("endpoint") or ""


def classify_records(records: list[dict]) -> list[KatanaUrl]:
    """Turn raw katana records into ``KatanaUrl`` entries with is_js set."""
    out: list[KatanaUrl] = []
    for rec in records:
        url = _endpoint_of(rec)
        if not url:
            continue
        ct = _content_type_of(rec)
        url_path = url.split("?", 1)[0].lower()
        is_js = (
            any(tok in ct for tok in _JS_CT_TOKENS)
            or url_path.endswith(_JS_EXTS)
        )
        req = rec.get("request") or {}
        resp = rec.get("response") or {}
        out.append(KatanaUrl(
            url=url,
            method=req.get("method") or "GET",
            status=int(resp.get("status_code") or 0),
            content_type=ct,
            is_js=is_js,
        ))
    return out


def dedup_pages(
    urls: list[str],
    target_host: str,
    *,
    max_per_template: int = DEFAULT_MAX_TEMPLATES_PER_HOST,
    same_registrable_only: bool = True,
) -> list[str]:
    """Layer 1: collapse identifier-bearing URLs by ``path_template``.

    ``/threads/12345``, ``/threads/12346``, ``/threads/12347`` ... -> one entry
    per unique ``(host, path_template)`` up to ``max_per_template`` reps.
    """
    counts: dict[tuple[str, str], int] = {}
    out: list[str] = []
    for u in urls:
        if same_registrable_only and not is_same_registrable(u, target_host):
            continue
        host = (urlsplit(u).hostname or "").lower()
        key = (host, path_template(u))
        if counts.get(key, 0) >= max_per_template:
            continue
        counts[key] = counts.get(key, 0) + 1
        out.append(u)
    return out


def _canonical_js_url(url: str) -> str:
    """Strip query+fragment so cache-bust params don't fragment the dedup key."""
    parts = urlsplit(url)
    return f"{parts.scheme}://{parts.netloc.lower()}{parts.path}"


def dedup_js(urls: list[str], cap: int = DEFAULT_MAX_JS_FILES) -> list[str]:
    """Layer 2: exact-URL dedup on JS files (canonical form), capped."""
    seen: set[str] = set()
    out: list[str] = []
    for u in urls:
        canonical = _canonical_js_url(u)
        if canonical in seen:
            continue
        seen.add(canonical)
        out.append(u)
        if len(out) >= cap:
            break
    return out


# ---------------------------------------------------------------------------
# Optional: fetch JS bodies + run regex extraction (Layer 3 dedup applies)
# ---------------------------------------------------------------------------


async def _fetch_bodies_and_extract(
    urls: list[str],
    extractor,
    *,
    timeout: int,
    user_agent: str,
    max_body_bytes: int,
    accept: str,
    seen_paths: set[str] | None = None,
    secondary=None,
    secondary_sink: list | None = None,
    secondary_seen: set | None = None,
) -> tuple[list[ExtractedPath], dict]:
    """Shared fetch loop used by both the JS and HTML extraction paths.

    ``extractor`` is ``extract_paths`` (for JS) or ``extract_paths_from_html``
    (for HTML). ``seen_paths`` lets the caller pass a shared set across both
    fetch passes so the same path doesn't show up twice in the merged result.

    Optional ``secondary`` runs an extra extractor on the same body and
    appends results to ``secondary_sink``, deduped via ``secondary_seen``.
    Used by the HTML pass to drive ``extract_config_leaks`` alongside the
    primary path-extraction pass without doubling the fetch traffic.
    """
    import aiohttp

    if seen_paths is None:
        seen_paths = set()
    seen_sha1: set[str] = set()
    paths: list[ExtractedPath] = []
    stats = {
        "fetch_attempted": len(urls),
        "fetch_ok": 0,
        "fetch_errors": 0,
        "fetch_4xx_5xx": 0,
        "sha1_dedup_drops": 0,
        "unique_bodies": 0,
    }

    headers = {"User-Agent": user_agent, "Accept": accept}
    timeout_cfg = aiohttp.ClientTimeout(total=timeout)
    async with aiohttp.ClientSession(headers=headers, timeout=timeout_cfg) as sess:
        for url in urls:
            try:
                async with sess.get(url, ssl=False, allow_redirects=True) as r:
                    if r.status >= 400:
                        stats["fetch_4xx_5xx"] += 1
                        continue
                    raw = await r.read()
            except Exception:
                stats["fetch_errors"] += 1
                continue

            stats["fetch_ok"] += 1
            if len(raw) > max_body_bytes:
                raw = raw[:max_body_bytes]
            sha1 = hashlib.sha1(raw).hexdigest()
            if sha1 in seen_sha1:
                stats["sha1_dedup_drops"] += 1
                continue
            seen_sha1.add(sha1)
            stats["unique_bodies"] += 1

            body = raw.decode("utf-8", errors="replace")
            for ep in extractor(body, source_url=url):
                if ep.path in seen_paths:
                    continue
                seen_paths.add(ep.path)
                paths.append(ep)

            if secondary is not None and secondary_sink is not None:
                for item in secondary(body):
                    sig = (item.framework, item.key_path, item.value)
                    if secondary_seen is not None:
                        if sig in secondary_seen:
                            continue
                        secondary_seen.add(sig)
                    secondary_sink.append(item)

    return paths, stats


async def fetch_and_extract(
    js_urls: list[str],
    *,
    timeout: int = DEFAULT_FETCH_TIMEOUT,
    user_agent: str = DEFAULT_USER_AGENT,
    max_body_bytes: int = DEFAULT_MAX_BODY_BYTES,
    seen_paths: set[str] | None = None,
) -> tuple[list[ExtractedPath], dict]:
    """Re-fetch each unique JS URL, dedup by body SHA1, run extract_paths."""
    return await _fetch_bodies_and_extract(
        js_urls, extract_paths,
        timeout=timeout, user_agent=user_agent,
        max_body_bytes=max_body_bytes, accept="*/*",
        seen_paths=seen_paths,
    )


async def fetch_html_and_extract(
    page_urls: list[str],
    *,
    timeout: int = DEFAULT_FETCH_TIMEOUT,
    user_agent: str = DEFAULT_USER_AGENT,
    max_body_bytes: int = DEFAULT_MAX_BODY_BYTES,
    seen_paths: set[str] | None = None,
    config_leaks_sink: list[ConfigLeak] | None = None,
    config_leaks_seen: set | None = None,
) -> tuple[list[ExtractedPath], dict]:
    """Re-fetch each unique page URL, dedup by body SHA1, run
    ``extract_paths_from_html`` so form actions, data-href attributes, htmx
    directives, and inline <script> blocks are all swept.

    This is the fix for backlogs.md item #1 -- hybrid / server-rendered
    sites (XenForo, ASP.NET, traditional PHP) carry their endpoint surface
    in HTML markup, not in shippable JS bundles.

    When ``config_leaks_sink`` is supplied, ``extract_config_leaks`` also
    runs against each fetched body (Nuxt ``__NUXT__``, Next ``__NEXT_DATA__``,
    Remix ``__remixContext``, generic ``window.ENV``) and the deduped
    ``ConfigLeak`` records are appended to the sink. This is the fix for
    backlogs.md item #3 -- config-blob value leaks the line-regex tiers miss.
    """
    return await _fetch_bodies_and_extract(
        page_urls, extract_paths_from_html,
        timeout=timeout, user_agent=user_agent,
        max_body_bytes=max_body_bytes,
        accept="text/html,application/xhtml+xml;q=0.9,*/*;q=0.8",
        seen_paths=seen_paths,
        secondary=extract_config_leaks if config_leaks_sink is not None else None,
        secondary_sink=config_leaks_sink,
        secondary_seen=config_leaks_seen,
    )


# ---------------------------------------------------------------------------
# Top-level orchestration
# ---------------------------------------------------------------------------


async def _resolve_redirect(url: str, *, user_agent: str, timeout: int = _REDIRECT_RESOLVE_TIMEOUT) -> str:
    """Follow HTTP redirects and return the final URL.

    Katana enforces crawl scope by registrable domain.  When the seed URL
    redirects to a *different* domain (e.g. baodongkhoi.vn -> dongkhoi.baovinhlong.vn)
    katana sees the landing page as out-of-scope and stops after 1 record.
    Resolving the redirect first and seeding katana with the final URL fixes this.

    Falls back to the original URL on any network or parse error so callers
    can always proceed.
    """
    import aiohttp
    try:
        headers = {"User-Agent": user_agent}
        timeout_cfg = aiohttp.ClientTimeout(total=timeout)
        async with aiohttp.ClientSession(headers=headers, timeout=timeout_cfg) as sess:
            async with sess.get(url, ssl=False, allow_redirects=True) as r:
                final = str(r.url)
                return final if final else url
    except Exception:
        return url


async def crawl(
    seed: str,
    *,
    depth: int = DEFAULT_DEPTH,
    headless: bool = False,
    jsluice: bool = False,
    katana_concurrency: int = DEFAULT_KATANA_CONCURRENCY,
    max_katana_urls: int = DEFAULT_MAX_KATANA_URLS,
    max_js_files: int = DEFAULT_MAX_JS_FILES,
    max_html_files: int = DEFAULT_MAX_HTML_FILES,
    max_templates_per_host: int = DEFAULT_MAX_TEMPLATES_PER_HOST,
    katana_timeout: int = DEFAULT_KATANA_TIMEOUT,
    extract_bodies: bool = False,
    extract_html: bool = False,
    fetch_timeout: int = DEFAULT_FETCH_TIMEOUT,
    user_agent: str = DEFAULT_USER_AGENT,
    max_body_bytes: int = DEFAULT_MAX_BODY_BYTES,
    binary: str | None = None,
    extra_katana_args: list[str] | None = None,
) -> KatanaResult:
    """End-to-end Phase 7 entry point.

    1. Run katana against ``seed``.
    2. Classify records into pages vs JS.
    3. Apply Layer 1 (page template) and Layer 2 (JS canonical) dedup.
    4. If ``extract_bodies``, fetch each unique JS body and run
       ``extract_paths`` with Layer 3 (body SHA1) dedup.
    5. If ``extract_html``, also fetch each unique deduped page URL and
       run ``extract_paths_from_html`` (form actions, data-href, htmx,
       inline <script>). This is the hybrid / server-rendered fix for
       backlogs.md item #1.
    """
    # Resolve redirect so katana is seeded with the final domain.
    # Without this, a seed like baodongkhoi.vn that redirects to
    # dongkhoi.baovinhlong.vn produces only 1 record because katana's
    # default scope restricts crawling to the original registrable domain.
    effective_seed = await _resolve_redirect(seed, user_agent=user_agent)
    target_host = urlsplit(effective_seed).hostname or ""
    records, budget_hit = await run_katana(
        effective_seed,
        depth=depth, headless=headless, jsluice=jsluice,
        concurrency=katana_concurrency,
        timeout=katana_timeout,
        max_urls=max_katana_urls,
        user_agent=user_agent,
        extra_args=extra_katana_args,
        binary=binary,
    )

    classified = classify_records(records)
    raw_pages = [u.url for u in classified if not u.is_js]
    raw_js = [u.url for u in classified if u.is_js]

    pages_dedup = dedup_pages(
        raw_pages, target_host,
        max_per_template=max_templates_per_host,
    )
    js_dedup = dedup_js(raw_js, cap=max_js_files)
    # HTML fetch list: take the deduped pages and apply the same canonical+cap
    # treatment as JS, then trim to max_html_files. dedup_pages already
    # collapsed forum-style /threads/{n} fanout; this second cap protects
    # against medium-sized sites still surfacing dozens of unique pages.
    html_fetch = dedup_js(pages_dedup, cap=max_html_files)

    stats = {
        "katana_records": len(records),
        "katana_budget_hit": budget_hit,
        "katana_url_budget": max_katana_urls,
        "page_urls_total": len(raw_pages),
        "page_urls_deduped": len(pages_dedup),
        "js_urls_total": len(raw_js),
        "js_urls_deduped": len(js_dedup),
    }

    paths: list[ExtractedPath] = []
    seen_paths: set[str] = set()
    config_leaks: list[ConfigLeak] = []
    config_leaks_seen: set[tuple[str, str, str]] = set()

    if extract_bodies and js_dedup:
        # JS fetch stats keep the top-level unprefixed names
        # (fetch_attempted, fetch_ok, ...) for backwards compat with
        # callers parsing the JSON output of `fp katana --json`.
        js_paths, js_fetch_stats = await fetch_and_extract(
            js_dedup,
            timeout=fetch_timeout,
            user_agent=user_agent,
            max_body_bytes=max_body_bytes,
            seen_paths=seen_paths,
        )
        paths.extend(js_paths)
        stats.update(js_fetch_stats)
        stats["paths_extracted_js"] = len(js_paths)

    if extract_html and html_fetch:
        # HTML fetch stats are namespaced under `html_*` so they don't
        # clobber the JS stats when both passes run.
        html_paths, html_fetch_stats = await fetch_html_and_extract(
            html_fetch,
            timeout=fetch_timeout,
            user_agent=user_agent,
            max_body_bytes=max_body_bytes,
            seen_paths=seen_paths,
            config_leaks_sink=config_leaks,
            config_leaks_seen=config_leaks_seen,
        )
        paths.extend(html_paths)
        for k, v in html_fetch_stats.items():
            stats[f"html_{k}"] = v
        stats["paths_extracted_html"] = len(html_paths)

    stats["paths_extracted"] = len(paths)
    stats["config_leaks_total"] = len(config_leaks)
    if config_leaks:
        # Per-class tally so users can see at a glance whether the leak set
        # is dominated by URL hosts, auth IDs, or live API keys.
        by_class: dict[str, int] = {}
        for leak in config_leaks:
            by_class[leak.leak_class] = by_class.get(leak.leak_class, 0) + 1
        stats["config_leaks_by_class"] = by_class

    return KatanaResult(
        seed=seed,
        page_urls=pages_dedup,
        js_urls=js_dedup,
        paths=paths,
        config_leaks=config_leaks,
        stats=stats,
    )
