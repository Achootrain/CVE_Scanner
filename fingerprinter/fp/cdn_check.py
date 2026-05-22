"""Lightweight CDN/WAF block detector.

Runs a single GET to the target root before the main scan. Checks response
headers, status, and body for provider-specific block signatures.

Detecting a block early lets the pipeline:
- Record it in stats so the user knows why detections are sparse.
- Optionally skip expensive stages (katana, cross-page) that will just
  hammer a challenge page and return nothing useful.

Providers detected: Cloudflare, Akamai, Imperva/Incapsula, generic WAF.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from curl_cffi.requests import AsyncSession as _CurlSession

from fetchlib import build_request_headers as _build_request_headers

TIMEOUT = 8

_CF_HEADERS = {"cf-ray", "cf-cache-status", "cf-mitigated"}
_CF_BODY = re.compile(
    r"(just a moment|checking your browser|cloudflare ray id|"
    r"ddos protection by cloudflare|enable javascript and cookies)",
    re.IGNORECASE,
)
_AKAMAI_BODY = re.compile(r"reference\s+#\d+[\.\d]*", re.IGNORECASE)
_IMPERVA_BODY = re.compile(r"incapsula incident id", re.IGNORECASE)
_GENERIC_BLOCK = re.compile(
    r"(access denied|blocked|security check|bot detection|captcha|"
    r"i am under attack|please verify you are human)",
    re.IGNORECASE,
)


@dataclass
class CdnBlock:
    provider: str
    reason: str
    status: int

    def to_dict(self) -> dict:
        return {"provider": self.provider, "reason": self.reason, "status": self.status}


def _detect(status: int, headers: dict[str, str], body: str) -> CdnBlock | None:
    server = headers.get("server", "").lower()
    h = {k.lower() for k in headers}

    # Cloudflare
    if h & _CF_HEADERS or "cloudflare" in server:
        if status in (403, 503) or _CF_BODY.search(body):
            return CdnBlock("cloudflare", "challenge/block page", status)
        # Cloudflare present but not blocking -- note it without flagging as blocked
        return None

    # Akamai
    if "akamai" in server or "akamaighost" in server:
        if status == 403 or _AKAMAI_BODY.search(body):
            return CdnBlock("akamai", "access denied", status)
        return None

    # Imperva / Incapsula
    if any(k.startswith("x-iinfo") for k in h) or "incap_ses_" in headers.get("set-cookie", ""):
        if _IMPERVA_BODY.search(body):
            return CdnBlock("imperva", "incapsula block", status)
        return None

    # Generic WAF: 403/429 with a small body full of block keywords
    if status in (403, 429) and len(body) < 8000 and _GENERIC_BLOCK.search(body):
        return CdnBlock("unknown-waf", f"HTTP {status} with block page", status)

    return None


async def check(target: str, *, user_agent: str = "", timeout: int = TIMEOUT) -> CdnBlock | None:
    """GET target root and return CdnBlock if a block is detected, else None.

    Uses curl_cffi with ``impersonate="chrome120"`` so the TLS ClientHello
    (JA3/JA4) matches a real Chrome and matches what ``scanner._fetch``
    will send on the actual scan. With stock aiohttp here, Cloudflare bot-
    management on TLS-fingerprint-strict sites (voz.vn, many .vn forums)
    challenged the pre-flight even though the scanner's real fetcher
    passed cleanly -- producing a false-positive ``cdn_blocked`` stat and
    a misleading "results may be incomplete" message on a target that
    actually scanned fine. Aligning the pre-flight fingerprint with the
    scanner makes the block verdict reflect what the scan will see.
    """
    headers = _build_request_headers(ua=user_agent or None)
    try:
        async with _CurlSession(
            impersonate="chrome120",
            headers=headers,
            timeout=timeout,
            verify=False,
        ) as session:
            resp = await session.get(target, allow_redirects=True)
        status = resp.status_code
        resp_headers = {k.lower(): v for k, v in resp.headers.items()}
        body = resp.text or ""
        return _detect(status, resp_headers, body)
    except Exception:
        return None
