"""Two fetcher implementations + a factory.

Both share `BaseFetcher.fetch(url, *, timeout, ua, verify_ssl, extra_headers) -> FetchResult`.
Differences:

- RequestsFetcher: vanilla `requests.Session`. Cheapest, no special TLS.
  Defeats only UA-string filters. Use as a sanity baseline.

- CurlCffiFetcher: `curl_cffi.requests.Session(impersonate="chrome120")`.
  Replays Chrome 120's TLS handshake + HTTP/2 SETTINGS frame so the
  JA3/JA4 fingerprint matches a real browser. Bypasses Cloudflare's
  basic Bot Score without booting a browser. Recommended default.

A real-browser tier (CloakBrowser stealth Chromium) lives in
``fp.cloak_fetcher`` for the scanner's async pipeline. There is no sync
fetchlib equivalent -- callers that need stealth go through the async
scanner's ``--use-cloak`` flag or Stage 5 escalation.
"""

from __future__ import annotations

from typing import Literal

from .headers import build_request_headers
from .block import detect_block
from .result import FetchResult, MAX_BODY_BYTES


Strategy = Literal["requests", "curl_cffi"]


# ---------------------------------------------------------------------------
# Base + soft-optional imports
# ---------------------------------------------------------------------------

class BaseFetcher:
    """Minimum surface every fetcher implements."""

    def fetch(
        self,
        url: str,
        *,
        timeout: float = 10.0,
        ua: str | None = None,
        verify_ssl: bool = False,
        extra_headers: dict[str, str] | None = None,
    ) -> FetchResult:
        raise NotImplementedError

    def close(self) -> None:
        pass


# ---------------------------------------------------------------------------
# Requests
# ---------------------------------------------------------------------------

import requests as _requests   # always present
import urllib3 as _urllib3
_urllib3.disable_warnings(_urllib3.exceptions.InsecureRequestWarning)


class RequestsFetcher(BaseFetcher):
    def __init__(self, verify_ssl: bool = False):
        self._sess = _requests.Session()
        self._sess.verify = verify_ssl

    def fetch(self, url, *, timeout=10.0, ua=None, verify_ssl=False, extra_headers=None):
        try:
            r = self._sess.get(
                url, timeout=timeout,
                headers=build_request_headers(ua, extra_headers),
                allow_redirects=True, verify=verify_ssl,
            )
        except Exception as e:
            return FetchResult(status_tag="error", error=type(e).__name__ + ": " + str(e)[:200])
        return _classify_http(r.status_code, r.text or "", dict(r.headers), str(r.url))

    def close(self):
        try: self._sess.close()
        except Exception: pass


# ---------------------------------------------------------------------------
# curl_cffi (TLS impersonation)
# ---------------------------------------------------------------------------

try:
    from curl_cffi import requests as _cffi_requests  # type: ignore
    _HAS_CURL_CFFI = True
except ImportError:
    _cffi_requests = None
    _HAS_CURL_CFFI = False


class CurlCffiFetcher(BaseFetcher):
    IMPERSONATE = "chrome120"

    def __init__(self, verify_ssl: bool = False):
        if not _HAS_CURL_CFFI:
            raise RuntimeError("curl_cffi not installed - `pip install curl_cffi`")
        self._sess = _cffi_requests.Session(impersonate=self.IMPERSONATE)

    def fetch(self, url, *, timeout=10.0, ua=None, verify_ssl=False, extra_headers=None):
        try:
            r = self._sess.get(
                url, timeout=timeout,
                headers=build_request_headers(ua, extra_headers),
                allow_redirects=True, verify=verify_ssl,
            )
        except Exception as e:
            return FetchResult(status_tag="error", error=type(e).__name__ + ": " + str(e)[:200])
        return _classify_http(r.status_code, r.text or "", dict(r.headers), str(r.url))

    def close(self):
        try: self._sess.close()
        except Exception: pass


# ---------------------------------------------------------------------------
# Shared status classifier (block detection runs first)
# ---------------------------------------------------------------------------

def _classify_http(status: int, body: str, headers: dict, final_url: str) -> FetchResult:
    body = body[:MAX_BODY_BYTES] if body else ""
    headers_lc = {k.lower(): v for k, v in headers.items()}
    cf_ray = "cf-ray" in headers_lc
    block_label = detect_block(status, body, cf_ray=cf_ray)
    if block_label:
        return FetchResult(status_tag="blocked", http_status=status,
                           body=body, headers=headers_lc,
                           final_url=final_url, error=block_label)
    if status and status >= 500:
        return FetchResult(status_tag="http_5xx", http_status=status, headers=headers_lc)
    if status and status >= 400:
        return FetchResult(status_tag="http_4xx", http_status=status, headers=headers_lc)
    if not body:
        return FetchResult(status_tag="empty", http_status=status, headers=headers_lc,
                           error="empty body")
    return FetchResult(status_tag="ok_body", http_status=status, body=body,
                       headers=headers_lc, final_url=final_url)


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------

def available_strategies() -> dict[str, bool]:
    """Map each strategy name -> True if its backing lib is importable."""
    return {
        "requests": True,
        "curl_cffi": _HAS_CURL_CFFI,
    }


def make_fetcher(strategy: Strategy = "curl_cffi", *, verify_ssl: bool = False) -> BaseFetcher:
    """Pick a fetcher. Falls back to `requests` if the asked strategy's
    backing library isn't installed, with a stderr note.
    """
    avail = available_strategies()
    if not avail.get(strategy, False):
        import sys
        sys.stderr.write(
            f"[fetchlib] strategy {strategy!r} not available; falling back to requests\n"
        )
        strategy = "requests"
    if strategy == "curl_cffi":
        return CurlCffiFetcher(verify_ssl=verify_ssl)
    return RequestsFetcher(verify_ssl=verify_ssl)
