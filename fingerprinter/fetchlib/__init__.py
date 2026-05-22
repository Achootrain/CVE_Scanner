"""Shared HTTP-fetch primitives used by the fp scanner and the lab back-test.

What's in here:
- Constants: CHROME_UA, BROWSER_HEADERS (single source of truth)
- detect_block: vendor-signature classifier for bot-block / challenge pages
- HostThrottle: per-host min-gap scheduler with jitter
- FetchResult: uniform result type across both fetchers
- Fetchers (uniform interface): RequestsFetcher, CurlCffiFetcher
- make_fetcher(strategy=...) factory

The fetcher interface is sync. fp's scanner is async and keeps its own
HTTP layer; it consumes only the constants + detect_block from this
package. The lab back-test consumes the full fetcher layer. The async
real-browser tier lives in ``fp.cloak_fetcher`` (CloakBrowser).
"""

from .headers import CHROME_UA, BROWSER_HEADERS, build_request_headers
from .block import BLOCK_SIGNATURES, detect_block
from .throttle import HostThrottle
from .result import FetchResult, MAX_BODY_BYTES
from .client import (
    BaseFetcher,
    RequestsFetcher,
    CurlCffiFetcher,
    make_fetcher,
    available_strategies,
    Strategy,
)

__all__ = [
    "CHROME_UA",
    "BROWSER_HEADERS",
    "build_request_headers",
    "BLOCK_SIGNATURES",
    "detect_block",
    "HostThrottle",
    "FetchResult",
    "MAX_BODY_BYTES",
    "BaseFetcher",
    "RequestsFetcher",
    "CurlCffiFetcher",
    "make_fetcher",
    "available_strategies",
    "Strategy",
]
