"""Unified FA detector: extract version from a target's root HTML.

Two-stage detection (all rules sourced from Phase 1-3 corpus analysis):

  Stage 1 — URL extraction:
    Parse <link href>, <script src>, @import url(...) from root HTML.
    Filter to FA-related URLs. Extract version from URL path or query.
    Trust if version looks like a real FA release (1.0 <= v < 10.0).

  Stage 2 — Body fingerprinting (fallback):
    For FA URLs without a version, fetch the CSS/JS file and apply
    body regexes (FA banner comment, version variable). Used only when
    Stage 1 yields nothing.

Returns FaDetection(version, source, url, evidence). source is one of:
  "url" | "body" | None
"""
from __future__ import annotations

import re
import sys
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse


# Lab imports for fetcher / throttle
HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent.parent
sys.path.insert(0, str(REPO / "fingerprinter"))
import fetchlib  # noqa: E402


# --- Phase 2: URL extractors (from corpus analysis) -------------------------

RE_LINK_HREF = re.compile(r'<link[^>]*\bhref=["\'](.*?)["\']', re.I)
RE_SCRIPT_SRC = re.compile(r'<script[^>]*\bsrc=["\'](.*?)["\']', re.I)
RE_CSS_IMPORT = re.compile(r'@import\s+(?:url\()?["\']?(.*?)["\']?\)?[;\s]', re.I)
RE_STYLE_SRC = re.compile(r'url\(["\']?(.*?)["\']?\)', re.I)

FA_URL = re.compile(r'font-?awesome|@fortawesome|fontawesome', re.I)
KIT_ONLY = re.compile(r'kit\.fontawesome\.com|use\.fontawesome\.com/[0-9a-f]{8,}\.js', re.I)

# Version-shaped token. Constrained to plausible FA semver: each component < 100,
# major < 10. Refuses timestamps and kit IDs.
VERSION_TOKEN = re.compile(r'(\d{1,2}\.\d{1,2}(?:\.\d{1,2})?)')


def _looks_like_version(v: str) -> bool:
    parts = v.split(".")
    if len(parts) < 2:
        return False
    try:
        ints = [int(p) for p in parts[:3]]
    except ValueError:
        return False
    return ints[0] < 10 and all(i < 100 for i in ints)


def _normalize(url: str, page_origin: str) -> str:
    if url.startswith("//"):
        return "https:" + url
    if url.startswith("/"):
        u = urlparse(page_origin)
        return f"{u.scheme}://{u.netloc}{url}"
    if not url.startswith(("http://", "https://")):
        return f"{page_origin.rstrip('/')}/{url}"
    return url


def extract_fa_urls(html: str, page_origin: str) -> list[str]:
    """Return ordered, deduped FA-related URLs from one HTML document."""
    out: list[str] = []
    seen: set[str] = set()
    for rx in (RE_LINK_HREF, RE_SCRIPT_SRC, RE_CSS_IMPORT, RE_STYLE_SRC):
        for m in rx.findall(html):
            if not FA_URL.search(m):
                continue
            full = _normalize(m.strip(), page_origin)
            if full in seen:
                continue
            seen.add(full)
            out.append(full)
    return out


def extract_version_from_url(url: str) -> str | None:
    for m in VERSION_TOKEN.finditer(url):
        v = m.group(1)
        if _looks_like_version(v):
            return v
    return None


# --- Phase 3: body fingerprint regexes (from corpus analysis) ---------------

BODY_RX = [
    ("fa_banner", re.compile(r"Font Awesome (?:Free|Pro)?\s*(\d+\.\d+(?:\.\d+)?)", re.I)),
    ("js_version_var", re.compile(r"version\s*[:=]\s*[\"'](\d+\.\d+(?:\.\d+)?)[\"']", re.I)),
    ("fa_comment_version", re.compile(r"fontawesome[\s\S]{0,200}?(\d+\.\d+\.\d+)", re.I)),
]


def extract_version_from_body(body: str) -> tuple[str, str] | None:
    """Return (version, regex_id) on first plausible match, else None."""
    snippet = body[: 1024 * 1024]
    for rx_id, rx in BODY_RX:
        m = rx.search(snippet)
        if m:
            v = m.group(1)
            if _looks_like_version(v):
                return v, rx_id
    return None


# --- Unified API ------------------------------------------------------------

@dataclass
class FaDetection:
    version: str | None
    source: str | None        # "url" | "body" | None
    url: str | None
    evidence: str | None      # regex id for body, or "url" for URL extraction
    fa_urls: list[str]        # all FA URLs found, for debugging
    kit_only: bool            # true if every FA URL is a kit (unrecoverable)


def detect_from_html(target: str, html: str, *, fetcher=None, throttle=None) -> FaDetection:
    """Detect FA version from a target's root HTML.

    Stage 1 (URL): scan FA URLs; return first plausible version.
    Stage 2 (body): for each unversioned URL, fetch and apply body regexes.
                    Only used when `fetcher` is provided.
    """
    page_origin = target if target.startswith(("http://", "https://")) else f"https://{target}"
    fa_urls = extract_fa_urls(html, page_origin)

    if not fa_urls:
        return FaDetection(None, None, None, None, [], False)

    # Stage 1: URL
    for u in fa_urls:
        v = extract_version_from_url(u)
        if v:
            return FaDetection(v, "url", u, "url", fa_urls, False)

    # All URLs are kit-only -> unrecoverable
    if all(KIT_ONLY.search(u) for u in fa_urls):
        return FaDetection(None, None, None, None, fa_urls, True)

    # Stage 2: body
    if fetcher is None:
        return FaDetection(None, None, None, None, fa_urls, False)

    for u in fa_urls:
        if KIT_ONLY.search(u):
            continue
        if not re.search(r"\.(css|js)(?:\?|$)", u, re.I):
            continue
        u_host = urlparse(u).netloc
        if throttle is not None:
            throttle.acquire(u_host)
        try:
            res = fetcher.fetch(u, timeout=10.0, verify_ssl=False, extra_headers={})
        except Exception:
            continue
        if not res.is_ok or not res.body:
            continue
        hit = extract_version_from_body(res.body)
        if hit:
            v, rx_id = hit
            return FaDetection(v, "body", u, rx_id, fa_urls, False)

    return FaDetection(None, None, None, None, fa_urls, False)


def make_default_fetcher_throttle(*, strategy: str = "curl_cffi", min_host_gap: float = 0.3):
    return fetchlib.make_fetcher(strategy), fetchlib.HostThrottle(min_delay_s=min_host_gap)
