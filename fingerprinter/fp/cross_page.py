"""Cross-page rescan: run Wappalyzer + retire.js over katana-discovered URLs.

The katana wrapper surfaces (default) up to 500 unique page URLs and 30 JS
bundles per target. The Phase-7 pipeline previously consumed only the
*body-extracted paths* from those crawls -- the URLs themselves were
discarded after dedup. With the page URLs surfaced (Phase 7 v2), the
natural follow-up is to *use* them: re-fetch each page and re-run the
cheap, regex-based detectors (Wappalyzer, retire.js) against the
response.

Why not full ``scanner.scan_targets``?
--------------------------------------
``scan_targets`` runs the nuclei probe-path loop against every input URL
(``cache["by_path"]`` is on the order of 200 paths). Feeding 491
discovered URLs into that would issue ~98k probes -- unacceptable for a
follow-up pass.

This module is the lean alternative:
  * One ``GET`` per page URL (capped at ``max_urls``).
  * ``wappalyzer.evaluate`` against each response -- regex over headers,
    HTML body, cookies, scriptSrc, meta. No extra network.
  * ``<script src>`` aggregation across all responses, deduped to the
    same ``MAX_RETIRE_SCRIPTS`` cap as the main scan, then a single
    retire.js sweep over the script bodies.

Why this is the right pass-through
----------------------------------
Different routes expose different tech. A WordPress homepage rendered by
Gutenberg may not load jQuery; ``/wp-login.php`` always does. A SPA
homepage may not include the framework banner cookie; an ``/api/...``
404 page does. Running Wappalyzer on the seed only is a real coverage
gap, and these regex-based detectors are exactly the ones that benefit
from more samples.

Output shape
------------
A list of ``Detection.to_dict()`` dicts, each tagged with the discovered
URL via the ``url`` field. Pipeline.reconcile() consumes these
unchanged.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import os
import sys
import time
from collections import defaultdict
from typing import Any
from urllib.parse import urlsplit

from curl_cffi.requests import AsyncSession as _CurlSession

from fetchlib import build_request_headers as _build_request_headers

from .url_utils import path_template
from . import retirejs as retire_mod
from . import scanner as scanner_mod
from . import url_ver as uv_mod
from . import wappalyzer as wap_mod
from urlcrawl import extract_html_link_urls

LOG = logging.getLogger("fp.cross_page")


DEFAULT_MAX_URLS = 30
DEFAULT_TIMEOUT = 15
DEFAULT_CONCURRENCY = 5
DEFAULT_MAX_BODY_BYTES = scanner_mod.MAX_RETIRE_BODY_BYTES

# Substage timing prints match the main scanner's `[scan +Xs]` format so
# the per-target log reads coherently. Set FP_CROSS_PAGE_TIMING=0 to
# silence (e.g. in batch runs that already strip stderr).
_TIMING_ENABLED = os.environ.get("FP_CROSS_PAGE_TIMING", "1") != "0"


def _body_dedup_key(body: bytes, headers: dict) -> str:
    """Cache key for wap_evaluate dedup.

    Hashes body head + the headers that wappalyzer actually reads
    (content-type, set-cookie, x-powered-by, server). URL is NOT in the
    key: two URLs serving identical content produce identical wap
    detections (the per-detection `url` tag is stamped after lookup).
    Body is truncated to 64KB -- wap rules read the head; minified
    bundle tails would only hash-busy the cache.
    """
    h = hashlib.sha256()
    h.update(body[:65536])
    for k in ("content-type", "set-cookie", "x-powered-by", "server"):
        v = headers.get(k) or headers.get(k.title()) or ""
        h.update(f"{k}={v}\n".encode("utf-8", errors="replace"))
    return h.hexdigest()


async def _fetch(
    session: _CurlSession,
    url: str,
    sem: asyncio.Semaphore,
) -> scanner_mod.FetchedResponse:
    """One GET, error-swallowing, identical to ``Scanner._fetch`` so the
    existing helpers (``extract_script_refs``, ``_looks_like_html``,
    ``_retire_to_detection``) work without adapters."""
    async with sem:
        try:
            r = await session.get(url, allow_redirects=True)
            return scanner_mod.FetchedResponse(
                url=str(r.url),
                status=r.status_code,
                headers=dict(r.headers),
                body=r.content,
            )
        except Exception as exc:  # noqa: BLE001
            return scanner_mod.FetchedResponse(
                url=url, status=0, headers={}, body=b"", error=str(exc),
            )


def _wap_evaluate_safe(
    cache: dict, url: str, headers: dict, body: bytes,
) -> list[dict]:
    """Wrap wap_mod.evaluate so a single bad response doesn't crash the rescan."""
    try:
        return wap_mod.evaluate(cache, url, headers, body)
    except Exception as exc:  # noqa: BLE001
        LOG.debug("wappalyzer.evaluate raised on %s: %s", url, exc)
        return []


def _scan_wappalyzer_over_html(
    html_responses: list[scanner_mod.FetchedResponse],
    wap_cache: dict,
    *,
    body_cache: dict[str, list[dict]] | None = None,
    stats: dict | None = None,
) -> list[dict]:
    """Run Wappalyzer over HTML responses in a worker thread.

    Keeping this synchronous helper allows the async caller to offload it via
    ``asyncio.to_thread`` so event-loop-level timeouts remain responsive.

    ``body_cache`` (optional) memoises wap_evaluate by body+header hash so
    duplicate pages (CDNs returning identical HTML on many routes, common
    on WP installs / Shopify themes) skip re-evaluation. The per-detection
    `url` field is re-stamped after a cache hit; the rule dicts otherwise
    only depend on body+headers.
    """
    bc = body_cache if body_cache is not None else {}
    cache_hits = 0
    out: list[dict] = []
    for r in html_responses:
        key = _body_dedup_key(r.body, r.headers)
        cached = bc.get(key)
        if cached is not None:
            cache_hits += 1
            for d in cached:
                d2 = dict(d)
                d2["url"] = r.url
                out.append(d2)
            continue
        page_dets: list[dict] = []
        for wd in _wap_evaluate_safe(wap_cache, r.url, r.headers, r.body):
            det = scanner_mod._wap_to_detection(wd)
            # Tag evidence with the discovered route that fired the rule.
            det.url = r.url
            page_dets.append(det.to_dict())
        bc[key] = page_dets
        out.extend(page_dets)
    if stats is not None:
        stats["wap_body_cache_hits"] = cache_hits
        stats["wap_body_cache_size"] = len(bc)
    return out


def _scan_retire_over_scripts(
    refs: list[str],
    script_responses: list[scanner_mod.FetchedResponse],
    retire_cache: dict,
    max_body_bytes: int,
) -> list[dict]:
    """Run retire.js body matching in a worker thread.

    retire.js patterns are regex-based and can be CPU-heavy on large bundles;
    offloading keeps cross-page timeout enforcement responsive.
    """
    out: list[dict] = []
    for url, r in zip(refs, script_responses):
        if r.error or r.status >= 400 or not r.body:
            continue
        if len(r.body) > max_body_bytes:
            continue
        parts = urlsplit(url)
        path = parts.path or "/"
        if parts.query:
            path += "?" + parts.query
        for rd in retire_mod.scan_body(r.body_text, url, retire_cache):
            det = scanner_mod._retire_to_detection(rd, url, path)
            out.append(det.to_dict())
    return out


def _rank_urls_for_rescan(urls: list[str], max_urls: int) -> list[str]:
    """Rank URLs by route rarity, then by discovery recency, then diversity.

    The selector keeps one URL per route template before taking second-round
    picks, so a broad set of distinct routes is favored over early repeated
    templates.
    """
    seen: set[str] = set()
    buckets: dict[tuple[str, str], list[tuple[int, str]]] = defaultdict(list)

    for idx, url in enumerate(urls):
        if url in seen:
            continue
        seen.add(url)
        host = (urlsplit(url).hostname or "").lower()
        key = (host, path_template(url))
        buckets[key].append((idx, url))

    if not buckets:
        return []

    def _route_score(url: str) -> tuple[int, int]:
        parts = [part for part in (urlsplit(url).path or "/").split("/") if part]
        # Favor shallow, non-article routes first. News/blog post URLs are
        # often unique slugs but still share the same HTML shell, so depth is
        # a better signal than raw uniqueness for the first few rescan slots.
        return (len(parts), 1 if len(parts) >= 3 else 0)

    ordered_keys = sorted(
        buckets,
        key=lambda key: (
            len(buckets[key]),
            _route_score(buckets[key][-1][1])[0],
            _route_score(buckets[key][-1][1])[1],
            -buckets[key][-1][0],
            key[0],
            key[1],
        ),
    )

    ordered_buckets = [
        [url for _, url in sorted(buckets[key], key=lambda item: -item[0])]
        for key in ordered_keys
    ]

    pruned: list[str] = []
    round_idx = 0
    while len(pruned) < max_urls:
        progress = False
        for bucket in ordered_buckets:
            if round_idx >= len(bucket):
                continue
            pruned.append(bucket[round_idx])
            progress = True
            if len(pruned) >= max_urls:
                return pruned
        if not progress:
            break
        round_idx += 1
    return pruned


async def rescan(
    urls: list[str],
    *,
    wap_cache: dict | None,
    retire_cache: dict | None,
    user_agent: str = scanner_mod.DEFAULT_UA,
    max_urls: int = DEFAULT_MAX_URLS,
    timeout: int = DEFAULT_TIMEOUT,
    concurrency: int = DEFAULT_CONCURRENCY,
    max_body_bytes: int = DEFAULT_MAX_BODY_BYTES,
) -> tuple[list[dict], dict[str, Any]]:
    """Re-fetch each URL once and run Wappalyzer + retire.js over the responses.

    Returns ``(detections, stats)`` where ``detections`` is a list of
    ``Detection.to_dict()`` records ready to feed into
    ``pipeline.reconcile()`` and ``stats`` carries fetch counters.

    Both ``wap_cache`` and ``retire_cache`` are optional -- the rescan
    silently skips the corresponding pass when its cache is None. This
    matches the pipeline's "degrade gracefully" contract.

    The URL list is deduplicated and capped at ``max_urls`` before
    fetching. The default cap (30) matches the HTML-sweep budget so two
    independent passes don't explode the per-target request count.
    """
    stats: dict[str, Any] = {
        "urls_input": len(urls),
        "urls_fetched": 0,
        "urls_html": 0,
        "urls_failed": 0,
        "wap_detections": 0,
        "retire_scripts_fetched": 0,
        "retire_detections": 0,
        "asset_urls_harvested": 0,
        "url_ver_detections": 0,
        "wap_body_cache_hits": 0,
        "wap_body_cache_size": 0,
    }

    # Per-substage timing so future-us can see WHERE the 55s on dongviet.vn
    # actually went. The main scanner uses the same `[scan +Xs]` shape;
    # we mirror it as `[cross-page +Xs]`. Toggle via FP_CROSS_PAGE_TIMING=0.
    _t0 = time.monotonic()
    def _ts(msg: str) -> None:
        if _TIMING_ENABLED:
            print(f"  [cross-page +{time.monotonic() - _t0:5.1f}s] {msg}",
                  file=sys.stderr, flush=True)

    if not urls:
        return [], stats
    # Note: even when both wap_cache and retire_cache are None we still run
    # the asset-URL harvest below -- url_ver works off the fetched HTML
    # without needing either cache.

    # Dedup exact URLs, then rank routes so the cap prefers newer, rarer,
    # and more route-diverse pages rather than the earliest repeated family.
    pruned = _rank_urls_for_rescan(urls, max_urls)
    stats["urls_after_dedup"] = len(pruned)

    headers = _build_request_headers(ua=user_agent)
    sem = asyncio.Semaphore(concurrency)

    detections: list[dict] = []

    async with _CurlSession(
        impersonate="chrome120",
        headers=headers,
        timeout=timeout,
        verify=False,
    ) as session:
        _ts(f"begin fetch n={len(pruned)} concurrency={concurrency} timeout={timeout}s")
        responses = await asyncio.gather(
            *[_fetch(session, u, sem) for u in pruned]
        )
        ok_responses: list[scanner_mod.FetchedResponse] = []
        html_responses: list[scanner_mod.FetchedResponse] = []
        for r in responses:
            if r.error or r.status == 0:
                stats["urls_failed"] += 1
                continue
            stats["urls_fetched"] += 1
            ok_responses.append(r)
            if scanner_mod._looks_like_html(r):
                html_responses.append(r)
        stats["urls_html"] = len(html_responses)
        _ts(f"fetch done html={len(html_responses)} fail={stats['urls_failed']}")

        # --- Asset URL harvest -> url_ver CDN extraction (zero extra network) ---
        # Every fetched HTML is already in memory. Walk it for <link href> /
        # <script src> / <img src> etc and feed the discovered URLs through
        # url_ver.extract_ver_params. This closes the cross-host CDN gap the
        # lab back-test exploits (REPORT.md: 0/69 -> 22/69 versioned on the
        # FA corpus came almost entirely from these CDN paths).
        if html_responses:
            harvested: list[str] = []
            seen_urls: set[str] = set()
            for resp in html_responses:
                for u in extract_html_link_urls(resp.body_text):
                    if u and u not in seen_urls:
                        seen_urls.add(u)
                        harvested.append(u)
            stats["asset_urls_harvested"] = len(harvested)
            if harvested:
                hits = uv_mod.extract_ver_params(harvested)
                for h in hits:
                    detections.append(h.to_detection_dict())
                stats["url_ver_detections"] = len(hits)
            _ts(f"asset-harvest done harvested={len(harvested)} "
                f"url_ver_hits={stats['url_ver_detections']}")

        # --- Wappalyzer pass over each HTML response ---
        # Wap rules accept any HTTP response; html_responses gives the
        # best signal-to-noise (skip pure JSON/binary 404 pages where
        # nothing useful matches anyway).
        if wap_cache is not None:
            _ts(f"wap begin n_html={len(html_responses)}")
            wap_body_cache: dict[str, list[dict]] = {}
            wap_detections = await asyncio.to_thread(
                _scan_wappalyzer_over_html,
                html_responses,
                wap_cache,
                body_cache=wap_body_cache,
                stats=stats,
            )
            detections.extend(wap_detections)
            stats["wap_detections"] = sum(
                1 for d in detections if d.get("source") == "wappalyzer"
            )
            _ts(f"wap done hits={stats['wap_detections']} "
                f"cache_hits={stats['wap_body_cache_hits']}/"
                f"{len(html_responses)} "
                f"unique_bodies={stats['wap_body_cache_size']}")

        # --- retire.js: aggregate <script src> across pages, frequency-ranked ---
        if retire_cache is not None and html_responses:
            _ts("retire begin")
            # Scan ALL pages before trimming so that scripts referenced on
            # many pages (core bundles) win slots over long-tail assets
            # discovered on the first few BFS pages. This prevents the
            # "more crawl budget = fewer retire.js detections" inversion
            # that occurred when --max-katana-urls was raised from 60 to 200.
            script_freq: dict[str, int] = {}
            script_first: dict[str, int] = {}
            for page_idx, resp in enumerate(html_responses):
                for url in scanner_mod.extract_script_refs(resp.body_text, resp.url):
                    script_freq[url] = script_freq.get(url, 0) + 1
                    if url not in script_first:
                        script_first[url] = page_idx
            refs = sorted(
                script_freq,
                key=lambda u: (-script_freq[u], script_first[u]),
            )[:scanner_mod.MAX_RETIRE_SCRIPTS]

            if refs:
                _ts(f"retire fetch begin n_scripts={len(refs)}")
                script_responses: list[scanner_mod.FetchedResponse] = await asyncio.gather(
                    *[_fetch(session, u, sem) for u in refs]
                )
                # One-shot retry for transient CDN/WAF blocks.
                needs_retry = [i for i, r in enumerate(script_responses) if r.error or r.status == 0]
                if needs_retry:
                    retried = await asyncio.gather(
                        *[_fetch(session, refs[i], sem) for i in needs_retry]
                    )
                    for i, r in zip(needs_retry, retried):
                        if not r.error and r.status:
                            script_responses[i] = r
                stats["retire_scripts_fetched"] = sum(
                    1 for r in script_responses if not r.error and r.status
                )
                _ts(f"retire fetch done ok={stats['retire_scripts_fetched']}/"
                    f"{len(refs)}")
                detections.extend(
                    await asyncio.to_thread(
                        _scan_retire_over_scripts,
                        refs,
                        script_responses,
                        retire_cache,
                        max_body_bytes,
                    )
                )
                stats["retire_detections"] = sum(
                    1 for d in detections if d.get("source") == "retirejs"
                )
                _ts(f"retire scan done hits={stats['retire_detections']}")

    _ts(f"complete total_dets={len(detections)}")
    return detections, stats
