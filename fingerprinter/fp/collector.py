"""Crawl4AI-based web data collector for the detect-version pipeline.

Crawls target URLs using Crawl4AI, extracts linked JavaScript files,
and writes JSONL output that ``fp detect-version`` consumes directly.

Each output record is one HTTP response:
    {
      "url":         "https://example.com",
      "html":        "...",               # body text
      "headers":     {"server": "nginx"}, # response headers
      "status_code": 200,
      "record_type": "html" | "js"        # informational
    }

Usage (programmatic):
    results = asyncio.run(collect(["https://example.com"], follow_js=True))
    # writes JSONL to stdout or a file

Usage (via CLI):
    python -m fp.cli collect https://example.com --json > target.txt
    python -m fp.cli collect --file targets.txt --out target.txt
"""

from __future__ import annotations

import asyncio
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urljoin, urlsplit

# Maximum JS files to fetch per HTML page (same cap as the main scanner).
MAX_JS_PER_PAGE = 20
# Hard cap on body size for JS files (bytes).
MAX_JS_BODY_BYTES = 512 * 1024

_SCRIPT_SRC_RE = re.compile(
    r'<script\b[^>]*\bsrc=["\']([^"\']+)["\']', re.IGNORECASE
)


@dataclass
class CollectedRecord:
    url: str
    body: str
    headers: dict[str, str]
    status: int
    record_type: str  # "html" | "js"

    def to_dict(self) -> dict:
        return {
            "url": self.url,
            "html": self.body,
            "headers": self.headers,
            "status_code": self.status,
            "record_type": self.record_type,
        }


# ---------------------------------------------------------------------------
# JS file fetcher (aiohttp -- already in requirements)
# ---------------------------------------------------------------------------


async def _fetch_js(session, url: str) -> CollectedRecord | None:
    try:
        import aiohttp
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
            if resp.status >= 400:
                return None
            ct = resp.headers.get("content-type", "")
            if "html" in ct.lower() and "javascript" not in ct.lower():
                return None  # redirect to login page or similar
            body_bytes = await resp.read()
            if len(body_bytes) > MAX_JS_BODY_BYTES:
                body_bytes = body_bytes[:MAX_JS_BODY_BYTES]
            body = body_bytes.decode("utf-8", errors="replace")
            headers = dict(resp.headers)
            return CollectedRecord(
                url=str(resp.url),
                body=body,
                headers=headers,
                status=resp.status,
                record_type="js",
            )
    except Exception as exc:
        sys.stderr.write(f"[collect] JS fetch failed {url}: {exc}\n")
        return None


def _extract_js_urls(html: str, base_url: str) -> list[str]:
    urls = []
    seen: set[str] = set()
    for m in _SCRIPT_SRC_RE.finditer(html):
        src = m.group(1).strip()
        if not src or src.startswith("data:"):
            continue
        full = urljoin(base_url, src)
        # Only same-host or CDN JS (keep all for version detection purposes)
        if full not in seen:
            seen.add(full)
            urls.append(full)
    return urls


# ---------------------------------------------------------------------------
# Core crawl logic
# ---------------------------------------------------------------------------


async def _crawl_one(url: str, follow_js: bool, user_agent: str | None) -> list[CollectedRecord]:
    """Crawl a single URL with Crawl4AI and optionally fetch linked JS files."""
    try:
        from crawl4ai import AsyncWebCrawler, BrowserConfig, CrawlerRunConfig, CacheMode
    except ImportError:
        raise RuntimeError(
            "crawl4ai is not installed. Run: pip install crawl4ai\n"
            "Then run: crawl4ai-setup  (installs its bundled browser)"
        )

    records: list[CollectedRecord] = []

    browser_cfg = BrowserConfig(headless=True, verbose=False)
    if user_agent:
        browser_cfg = BrowserConfig(headless=True, verbose=False, user_agent=user_agent)

    run_cfg = CrawlerRunConfig(
        cache_mode=CacheMode.BYPASS,
        word_count_threshold=0,   # keep all HTML, don't filter short pages
        exclude_external_links=False,
        process_iframes=False,
        remove_overlay_elements=False,
    )

    async with AsyncWebCrawler(config=browser_cfg) as crawler:
        result = await crawler.arun(url=url, config=run_cfg)

    if not result.success:
        sys.stderr.write(
            f"[collect] {url}: crawl failed: {getattr(result, 'error_message', 'unknown')}\n"
        )
        return records

    # Normalise headers -- Crawl4AI stores them as a dict (may be CIDict)
    headers = {}
    raw_headers = getattr(result, "response_headers", None) or {}
    for k, v in raw_headers.items():
        headers[str(k)] = str(v)

    html_body = getattr(result, "html", "") or ""
    final_url = getattr(result, "url", url) or url
    status = int(getattr(result, "status_code", 200) or 200)

    records.append(CollectedRecord(
        url=final_url,
        body=html_body,
        headers=headers,
        status=status,
        record_type="html",
    ))

    if follow_js and html_body:
        js_urls = _extract_js_urls(html_body, final_url)[:MAX_JS_PER_PAGE]
        if js_urls:
            import aiohttp
            async with aiohttp.ClientSession(headers={
                "User-Agent": user_agent or "Mozilla/5.0 (compatible; FpCollector/1.0)",
            }) as session:
                tasks = [_fetch_js(session, u) for u in js_urls]
                js_results = await asyncio.gather(*tasks)
            for rec in js_results:
                if rec:
                    records.append(rec)

    return records


async def collect(
    urls: list[str],
    *,
    follow_js: bool = True,
    concurrency: int = 3,
    user_agent: str | None = None,
) -> list[CollectedRecord]:
    """Crawl a list of URLs and return CollectedRecord objects.

    Each URL produces one HTML record plus up to MAX_JS_PER_PAGE JS records
    when follow_js=True.
    """
    sem = asyncio.Semaphore(concurrency)

    async def _bounded(url: str) -> list[CollectedRecord]:
        async with sem:
            sys.stderr.write(f"[collect] crawling {url} ...\n")
            try:
                recs = await _crawl_one(url, follow_js=follow_js, user_agent=user_agent)
                sys.stderr.write(
                    f"[collect] {url}: {len(recs)} record(s) "
                    f"(html={sum(1 for r in recs if r.record_type=='html')} "
                    f"js={sum(1 for r in recs if r.record_type=='js')})\n"
                )
                return recs
            except RuntimeError:
                raise  # propagate install errors immediately
            except Exception as exc:
                sys.stderr.write(f"[collect] {url}: error: {exc}\n")
                return []

    all_results: list[CollectedRecord] = []
    tasks = [_bounded(u) for u in urls]
    for batch in await asyncio.gather(*tasks, return_exceptions=False):
        all_results.extend(batch)
    return all_results


def load_targets(path: str | Path) -> list[str]:
    """Read URLs from a text file (one per line, # comments ignored)."""
    lines = Path(path).read_text(encoding="utf-8").splitlines()
    return [l.strip() for l in lines if l.strip() and not l.strip().startswith("#")]
