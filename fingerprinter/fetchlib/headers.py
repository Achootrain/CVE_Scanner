"""User-Agent + default-header constants shared by every fetcher.

Single source of truth: fp's pipeline UA preset `chrome` and the lab's
back-test default both source CHROME_UA from this module.
"""

from __future__ import annotations


# Match a real Chrome 121 desktop UA. Used by fp `--ua chrome` preset,
# fp's backend_leaks PROBE_USER_AGENT, and the lab back-test default.
CHROME_UA = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36"
)


# Headers a real Chrome 121 sends on a top-level navigation. UA filters
# at the WAF layer (cheap, common) sniff these in combination - sending
# UA-alone with no Accept-Language, no sec-ch-ua, etc. is itself a tell.
BROWSER_HEADERS: dict[str, str] = {
    "Accept": (
        "text/html,application/xhtml+xml,application/xml;q=0.9,"
        "image/avif,image/webp,image/apng,*/*;q=0.8"
    ),
    "Accept-Language": "en-US,en;q=0.9",
    "Accept-Encoding": "gzip, deflate, br",
    "sec-ch-ua": '"Not A(Brand";v="99", "Google Chrome";v="121", "Chromium";v="121"',
    "sec-ch-ua-mobile": "?0",
    "sec-ch-ua-platform": '"macOS"',
    "Sec-Fetch-Dest": "document",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-Site": "none",
    "Sec-Fetch-User": "?1",
    "Upgrade-Insecure-Requests": "1",
}


def build_request_headers(ua: str | None = None, extra: dict[str, str] | None = None) -> dict[str, str]:
    """Compose the per-request header set: BROWSER_HEADERS + UA + caller extras.

    `extra` wins ties (so a per-request Referer or Cookie overrides anything).
    UA falls back to CHROME_UA if not provided.
    """
    headers: dict[str, str] = {**BROWSER_HEADERS, "User-Agent": ua or CHROME_UA}
    if extra:
        headers.update(extra)
    return headers
