"""Async CloakBrowser fetcher for the fp scanner.

Drop-in replacement for the curl_cffi `AsyncSession` the scanner uses by
default. Exposes `.get(url, allow_redirects=True)` and `.request(method, url, ...)`
returning a duck-typed response object with `.url`, `.status_code`,
`.headers`, `.content` -- matching what `scanner._fetch` reads.

CloakBrowser is a stealth Chromium with source-level fingerprint patches.
The hand-rolled stealth init script that used to live here is gone --
CloakBrowser patches webdriver / plugins / languages and the rest of the
navigator-fingerprint surface at the C++ layer, where it can't be undone
by site-side overrides.

Use as an async context manager::

    async with AsyncCloakFetcher(headers=H, timeout=15) as session:
        r = await session.get("https://example.com/")
"""

from __future__ import annotations

import asyncio
from typing import Any


# Substrings that match the headless-browser internal-task errors we want
# to silence at the loop level. They originate in background tasks the
# browser engine creates for resource loaders / frame event handlers;
# when one navigation is aborted by another, those tasks raise and asyncio
# logs them at GC time even though our own `get()` already returned a
# soft-zero response. None of these indicate a real bug -- they are
# routine collateral of running many concurrent goto()s through one
# BrowserContext.
_BROWSER_SILENCED_SUBSTRINGS: tuple[str, ...] = (
    "net::ERR_ABORTED",
    "frame was detached",
    "Target page, context or browser has been closed",
    "Target closed",
    "Page closed",
    "Browser closed",
    "Execution context was destroyed",
)


def _is_silenceable_browser_error(context: dict) -> bool:
    """True iff this loop-exception context is a known-noisy browser task."""
    exc = context.get("exception")
    if exc is not None:
        msg = repr(exc) + " " + str(exc)
    else:
        msg = context.get("message", "")
    return any(s in msg for s in _BROWSER_SILENCED_SUBSTRINGS)


# Loops where we've already installed the silencer. Keyed by id(loop) so we
# don't accidentally hold the loop alive across runs.
_SILENCER_INSTALLED_LOOPS: set[int] = set()


def install_silencer_on_running_loop() -> None:
    """Idempotent. Install a chained exception handler that filters out
    headless-browser internal-task errors (ERR_ABORTED, frame detached,
    target closed) for the lifetime of the current event loop.

    Call this once per pipeline run before any cloak fetcher is used.
    Surviving the entire run -- not just one fetcher's lifetime -- is
    necessary: aborted Futures get GC'd in unpredictable windows, often
    between targets, and a per-fetcher install-then-restore leaves those
    windows unprotected.
    """
    loop = asyncio.get_running_loop()
    if id(loop) in _SILENCER_INSTALLED_LOOPS:
        return
    _SILENCER_INSTALLED_LOOPS.add(id(loop))
    prev = loop.get_exception_handler()

    def _filter(_loop, context):
        if _is_silenceable_browser_error(context):
            return
        if prev is not None:
            prev(_loop, context)
        else:
            _loop.default_exception_handler(context)

    loop.set_exception_handler(_filter)


try:
    from cloakbrowser import launch_async   # type: ignore

    _HAS_CLOAKBROWSER = True
except ImportError:
    launch_async = None  # type: ignore
    _HAS_CLOAKBROWSER = False


# CloakBrowser's `stealth_args=True` default supplies all fingerprint /
# automation-flag patches at the binary layer. Everything below is
# orthogonal resource / perf trim for APIRequestContext use (we never
# paint).
# JS init script injected before every page load -- only matters in
# ``mode="page"`` since APIRequestContext never creates a Page object.
# Defense-in-depth on top of CloakBrowser's binary-level patches, and
# strictly required when the binary is overridden to a vanilla Chromium
# (CLOAKBROWSER_BINARY_PATH=<playwright chromium>). Hides the three
# most-fingerprinted automation signals plus the empty `window.chrome`.
_STEALTH_INIT_SCRIPT = """
Object.defineProperty(navigator, 'webdriver', { get: () => undefined });
Object.defineProperty(navigator, 'plugins', {
    get: () => [1, 2, 3, 4, 5].map(i => ({ name: 'Plugin' + i }))
});
Object.defineProperty(navigator, 'languages', { get: () => ['en-US', 'en'] });
window.chrome = window.chrome || { runtime: {} };
"""


_CHROMIUM_LAUNCH_ARGS = [
    "--no-sandbox",
    "--disable-dev-shm-usage",
    # Footprint trims -- we use APIRequestContext (no page rendering), so
    # everything below is dead weight for our use case.
    "--disable-extensions",
    "--disable-component-extensions-with-background-pages",
    "--disable-background-networking",
    "--disable-background-timer-throttling",
    "--disable-backgrounding-occluded-windows",
    "--disable-breakpad",
    "--disable-default-apps",
    "--disable-features=Translate,TranslateUI,BackForwardCache,AcceptCHFrame,MediaRouter",
    "--disable-ipc-flooding-protection",
    "--disable-renderer-backgrounding",
    "--disable-sync",
    "--metrics-recording-only",
    "--mute-audio",
    "--no-first-run",
    "--no-default-browser-check",
    "--no-pings",
    # Half the renderer/GPU subsystem can be off because we never paint.
    "--disable-gpu",
    "--disable-software-rasterizer",
    "--disable-accelerated-2d-canvas",
    "--blink-settings=imagesEnabled=false",
]


async def _announce_binary_download() -> None:
    """If the stealth Chromium binary isn't on disk yet, log a stderr
    notice before launch_async() goes off and downloads ~200 MB silently.
    Runs the actual download in a worker thread so the event loop stays
    responsive. Idempotent: subsequent calls find the binary present and
    return immediately. When the user has set ``CLOAKBROWSER_BINARY_PATH``
    to a local Chromium, the download is skipped entirely."""
    if not _HAS_CLOAKBROWSER:
        return
    import os as _os
    import sys as _sys
    import time as _time
    # The env override (CLOAKBROWSER_BINARY_PATH) makes ensure_binary() a
    # no-op, so bail out before printing the misleading "downloading..." line.
    if _os.environ.get("CLOAKBROWSER_BINARY_PATH"):
        return
    try:
        from cloakbrowser import binary_info, ensure_binary
    except ImportError:
        return
    try:
        info = binary_info()
        # binary_info() returns a dict; ``installed`` is the truthy flag.
        if isinstance(info, dict) and info.get("installed"):
            return
    except Exception:  # noqa: BLE001
        pass
    _sys.stderr.write(
        "[cloak] downloading stealth Chromium binary (~200 MB, first run only) "
        "-- run `python -m fp.cli setup-cloak` next time to pre-cache...\n"
    )
    _sys.stderr.flush()
    t0 = _time.monotonic()
    try:
        await asyncio.to_thread(ensure_binary)
    except Exception as exc:  # noqa: BLE001
        _sys.stderr.write(f"[cloak] download failed: {exc}\n")
        raise
    _sys.stderr.write(
        f"[cloak] binary ready in {_time.monotonic() - t0:.1f}s\n"
    )
    _sys.stderr.flush()


class _Response:
    """Minimum surface the scanner reads from a fetcher response.

    Scanner code path: ``r.url``, ``r.status_code``, ``r.headers``, ``r.content``.
    Keep this dumb -- no methods, no validation.
    """

    def __init__(self, url: str, status_code: int, headers: dict, content: bytes):
        self.url = url
        self.status_code = status_code
        self.headers = headers
        self.content = content


class AsyncCloakFetcher:
    """Async stealth-Chrome fetcher with two fetch modes.

    ``mode="api"`` (default): every ``get()`` uses BrowserContext's
    APIRequestContext. Fast (~10x lighter than Page), shares Chrome TLS +
    cookies + headers, but is **HTTP/1.1** to the target and never runs
    JS. Use for cheap stealth where you only need network-layer Chrome
    impersonation; ``fp.scanner._fetch`` calls this when ``--use-cloak``
    is on.

    ``mode="page"``: every ``get()`` spawns a Page, calls ``goto()`` with
    ``wait_until="domcontentloaded"`` + a brief ``networkidle`` wait,
    then captures the raw response body. Slow (~3-5s/fetch) but uses
    **HTTP/2**, executes JS, and gives Cloudflare interstitials /
    Turnstile / Akamai sensor-based gates time to resolve. Stage 5
    escalation in the pipeline switches to this mode automatically when
    curl_cffi appears blocked.
    """

    def __init__(
        self,
        *,
        mode: str = "api",
        headers: dict[str, str] | None = None,
        timeout: float = 15.0,
        verify: bool = False,
        headless: bool = True,
    ):
        if not _HAS_CLOAKBROWSER:
            raise RuntimeError(
                "cloakbrowser not installed -- pip install cloakbrowser "
                "(downloads the stealth Chromium binary on first run)"
            )
        if mode not in ("api", "page"):
            raise ValueError(f"AsyncCloakFetcher mode must be 'api' or 'page', got {mode!r}")
        self._mode = mode
        self._headers = headers or {}
        self._timeout_ms = int(timeout * 1000)
        self._verify = verify
        self._headless = headless
        self._browser = None
        self._context = None

    async def __aenter__(self) -> "AsyncCloakFetcher":
        # Belt-and-braces: pipeline.run_pipeline installs the loop silencer
        # once before any target. If a caller skips the pipeline and drives
        # the fetcher directly, install it lazily here too. Idempotent.
        install_silencer_on_running_loop()

        # First-run download visibility. launch_async() will call
        # ensure_binary() internally if the stealth Chromium isn't on disk,
        # but that download stalls inside ssl.read() with no log line --
        # which looks like a scan hang. Surface it explicitly so users see
        # what's happening, then hand off to the normal launch path.
        await _announce_binary_download()

        # launch_async returns a standard Browser object whose new_context /
        # request.get methods follow the same async contract the rest of
        # this class targets.
        self._browser = await launch_async(
            headless=self._headless,
            args=_CHROMIUM_LAUNCH_ARGS,
            stealth_args=True,
        )
        ua = self._headers.get("User-Agent")
        ctx_kwargs: dict[str, Any] = {
            "ignore_https_errors": not self._verify,
            # No viewport / locale / timezone -- we never render pages, and
            # APIRequestContext doesn't care about those. Locale-derived
            # Accept-Language still gets set via set_extra_http_headers below
            # from fetchlib.BROWSER_HEADERS, so WAFs see a coherent fingerprint.
        }
        if ua:
            ctx_kwargs["user_agent"] = ua
        self._context = await self._browser.new_context(**ctx_kwargs)
        extra = {k: v for k, v in self._headers.items() if k.lower() != "user-agent"}
        if extra:
            await self._context.set_extra_http_headers(extra)
        # add_init_script is no-op for APIRequestContext (no Page is ever
        # created), so this only fires in page mode. Defense-in-depth on
        # top of CloakBrowser's binary patches; required when the binary
        # is overridden to a vanilla Chromium.
        if self._mode == "page":
            await self._context.add_init_script(_STEALTH_INIT_SCRIPT)
        return self

    async def __aexit__(self, *exc) -> None:
        try:
            if self._context:
                await self._context.close()
        except Exception:
            pass
        try:
            if self._browser:
                await self._browser.close()
        except Exception:
            pass
        # launch_async manages its own runtime and tears it down when the
        # browser closes.
        # Deliberately do NOT restore the loop exception handler -- aborted
        # Futures from this fetcher's run are GC'd in unpredictable windows,
        # sometimes well after __aexit__ returns. Keeping the silencer in
        # place for the rest of the loop's lifetime is the only way to keep
        # those late GC events out of the log.

    async def get(self, url: str, *, allow_redirects: bool = True) -> _Response:
        if self._mode == "page":
            return await self._page_get(url)
        return await self._api_get(url, allow_redirects=allow_redirects)

    async def _api_get(self, url: str, *, allow_redirects: bool = True) -> _Response:
        # APIRequestContext -- shares Chrome's TLS fingerprint, cookies, and
        # extra HTTP headers, but does NOT spawn a page, render the DOM,
        # execute JS, or fetch images/fonts/CSS. ~10x faster + ~10x lighter
        # per call than page.goto(). Negotiates HTTP/1.1 (Playwright
        # limitation) -- for full Chrome network-layer impersonation use
        # mode="page" or stay on curl_cffi.
        try:
            api_resp = await self._context.request.get(
                url,
                max_redirects=20 if allow_redirects else 0,
                timeout=self._timeout_ms,
            )
            try:
                body = await api_resp.body()
            except Exception:
                body = b""
            try:
                hdrs = dict(api_resp.headers)
            except Exception:
                hdrs = {}
            return _Response(
                url=api_resp.url,
                status_code=api_resp.status,
                headers=hdrs,
                content=body or b"",
            )
        except Exception:
            # Soft-zero on any nav / network error so scanner._fetch treats
            # it as "unreachable" and the exception is consumed in-band
            # (asyncio never logs "Future exception was never retrieved").
            return _Response(url=url, status_code=0, headers={}, content=b"")

    async def _page_get(self, url: str) -> _Response:
        # Real navigation: HTTP/2 to target, full DOM build, JS executed.
        # Slow (~3-5s/fetch) but the only way to make Cloudflare interstitial
        # / Turnstile / Akamai sensor-based gates actually resolve. The
        # init script (added in __aenter__) masks navigator.webdriver et al
        # before any site JS runs.
        try:
            page = await self._context.new_page()
        except Exception:
            return _Response(url=url, status_code=0, headers={}, content=b"")
        try:
            try:
                response = await page.goto(
                    url,
                    timeout=self._timeout_ms,
                    wait_until="domcontentloaded",
                )
            except Exception:
                return _Response(url=url, status_code=0, headers={}, content=b"")
            if response is None:
                return _Response(url=url, status_code=0, headers={}, content=b"")
            # Give Cloudflare interstitials a beat to either redirect on
            # success or settle on the block page. ~2s is the canonical CF
            # challenge resolution window.
            try:
                await page.wait_for_load_state("networkidle", timeout=2000)
            except Exception:
                pass
            # Prefer raw response bytes; fall back to rendered DOM. The raw
            # path matters for asset URLs (.css / .js / .json) -- Chromium
            # wraps non-HTML responses in a synthetic text viewer if we read
            # via page.content(), which would corrupt any line-anchored regex
            # the lab applies later.
            body: bytes = b""
            try:
                body = await response.body()
            except Exception:
                try:
                    body = (await page.content() or "").encode("utf-8", errors="replace")
                except Exception:
                    body = b""
            try:
                hdrs = dict(response.headers)
            except Exception:
                hdrs = {}
            return _Response(
                url=page.url,
                status_code=response.status,
                headers=hdrs,
                content=body or b"",
            )
        finally:
            try:
                await page.close()
            except Exception:
                pass

    async def request(self, method: str, url: str, **kwargs) -> _Response:
        """Non-GET via APIRequestContext (backend_leaks uses POST/etc)."""
        if method.upper() == "GET":
            return await self.get(url)
        ctx_req = self._context.request
        kw: dict[str, Any] = {"timeout": self._timeout_ms, "method": method.upper()}
        data = kwargs.get("data")
        if data is not None:
            kw["data"] = data
        hdrs = kwargs.get("headers")
        if hdrs:
            kw["headers"] = hdrs
        try:
            api_resp = await ctx_req.fetch(url, **kw)
            body = await api_resp.body()
            try:
                resp_hdrs = dict(api_resp.headers)
            except Exception:
                resp_hdrs = {}
            return _Response(
                url=api_resp.url,
                status_code=api_resp.status,
                headers=resp_hdrs,
                content=body or b"",
            )
        except Exception:
            return _Response(url=url, status_code=0, headers={}, content=b"")
