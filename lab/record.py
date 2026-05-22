"""Lab phase 3 — response recorder.

Probes a curated path list against a running fixture and dumps every
response body and header set to disk. Those recordings become the input
for `lab/diff.py`, which mines candidate version-extractor patterns by
diffing adjacent versions of the same technology.

Record format (`<outdir>/<fixture_id>/responses.json`):

    {
      "fixture": "nginx-1-25-3",
      "url":     "http://localhost:18101",
      "tech":    "nginx",
      "version": "1.25.3",
      "responses": [
        {
          "path": "/",
          "status": 200,
          "headers": {"server": "nginx/1.25.3", ...},
          "body": "<!DOCTYPE html>...",
          "body_len": 612,
          "truncated": false
        },
        ...
      ]
    }
"""

from __future__ import annotations

import argparse
import asyncio
import json
import re
import sys
from pathlib import Path
from urllib.parse import urljoin, urlparse

import aiohttp

# Curated probe list. Broad enough to catch the common version leaks across
# webservers, CMSs, and app frameworks; small enough that pounding it against
# every fixture is cheap.
DEFAULT_PROBE_PATHS: list[str] = [
    "/",
    "/index.html",
    "/index.php",
    # Random path → default 404. Nginx/apache/etc. routinely put version in
    # the error page footer, which is one of the most reliable diff signals.
    "/__fp_lab_notfound_nrqc9s8__",
    # Webserver status/info
    "/server-status",
    "/server-info",
    # Changelogs / docs
    "/README",
    "/README.md",
    "/readme.html",
    "/CHANGELOG",
    "/CHANGELOG.txt",
    "/CHANGELOG.md",
    "/LICENSE",
    "/LICENSE.txt",
    # WordPress
    "/wp-login.php",
    "/wp-admin/",
    "/wp-admin/install.php",
    "/wp-json/",
    "/wp-links-opml.php",
    "/feed/",
    # Grafana / generic app
    "/login",
    "/api/",
    "/api/health",
    "/api/frontend/settings",
    # Java/Spring
    "/actuator/info",
    "/actuator/health",
    # PHP
    "/phpinfo.php",
    # Source-control / config leaks
    "/.git/HEAD",
    "/package.json",
    "/composer.json",
    # Proxies / management UIs
    "/manager/html",
    "/host-manager/html",
    # robots/sitemap sometimes contain version in generator comments
    "/robots.txt",
    "/sitemap.xml",
]

# Cap body capture to keep recordings bounded. 256 KiB is enough to include
# bundled JS/CSS fragments but avoids recording 5 MB binary downloads.
BODY_CAP_BYTES = 256 * 1024
# Upper bound on URLs the root-page crawler will fetch per fixture. Keeps
# recording time and disk usage predictable when a page references dozens of
# assets.
MAX_CRAWL_REFS = 30
# Very loose regexes — no HTML parsing, no DOM. Good enough for `<script src>`
# and `<link href>` on server-rendered pages, which is the signal we want. A
# full parser would catch more but carries a dependency that isn't warranted
# yet. Matches even if other attributes precede src/href.
SCRIPT_SRC_RE = re.compile(r'''<script\b[^>]*\bsrc=["']([^"']+)["']''', re.I)
LINK_HREF_RE = re.compile(r'''<link\b[^>]*\bhref=["']([^"']+)["']''', re.I)
# Text content types we'll decode as UTF-8. Everything else is treated as
# binary and recorded as a hex prefix + length only.
TEXT_CT_PREFIXES = ("text/", "application/json", "application/xml",
                    "application/javascript", "application/xhtml+xml",
                    "application/rss+xml", "application/atom+xml")

# Fuzzed / abnormal probes. These deliberately exercise server error paths —
# many servers route method-not-allowed, oversized-URI, bad-range, and
# unauthenticated-auth requests to distinct templates that leak different
# build info than the happy path does. Each probe has a stable `id` that
# becomes the "path" key in the recording, so both fixtures in a diff pair
# agree on which responses to compare.
FUZZ_PROBES: list[dict] = [
    {"id": "PROPFIND /",            "method": "PROPFIND", "path": "/"},
    {"id": "TRACE /",               "method": "TRACE",    "path": "/"},
    {"id": "OPTIONS /",             "method": "OPTIONS",  "path": "/"},
    {"id": "DELETE /",              "method": "DELETE",   "path": "/"},
    {"id": "PATCH /",               "method": "PATCH",    "path": "/"},
    {"id": "LOCK /",                "method": "LOCK",     "path": "/"},
    {"id": "GET /%00",              "method": "GET",      "path": "/%00"},
    {"id": "GET /longurl",          "method": "GET",      "path": "/" + "A" * 4000},
    {"id": "GET / Range=bad",       "method": "GET",      "path": "/",
     "headers": {"Range": "bytes=a-z"}},
    {"id": "GET / Range=overflow",  "method": "GET",      "path": "/",
     "headers": {"Range": "bytes=999999999-"}},
    {"id": "GET / Auth=garbage",    "method": "GET",      "path": "/",
     "headers": {"Authorization": "Basic Og=="}},
    {"id": "GET / Accept=none",     "method": "GET",      "path": "/",
     "headers": {"Accept": "application/vnd.made.up.doesnotexist"}},
    {"id": "POST / empty",          "method": "POST",     "path": "/",
     "body": b""},
]


def _is_text(content_type: str | None) -> bool:
    if not content_type:
        return True  # default to text; decoder handles errors
    ct = content_type.split(";", 1)[0].strip().lower()
    return any(ct.startswith(p) for p in TEXT_CT_PREFIXES)


async def probe_url(
    session: aiohttp.ClientSession,
    base_url: str,
    path: str,
    *,
    timeout: float,
) -> dict:
    url = base_url.rstrip("/") + path
    try:
        async with session.get(
            url,
            allow_redirects=False,
            timeout=aiohttp.ClientTimeout(total=timeout),
        ) as r:
            raw = await r.content.read(BODY_CAP_BYTES + 1)
            truncated = len(raw) > BODY_CAP_BYTES
            raw = raw[:BODY_CAP_BYTES]
            ct = r.headers.get("Content-Type")
            headers = {k.lower(): v for k, v in r.headers.items()}
            if _is_text(ct):
                body = raw.decode("utf-8", errors="replace")
            else:
                # Binary — record a hex prefix only. Plenty to disambiguate
                # magic numbers; version leaks almost never live in binaries.
                body = "<binary:" + raw[:64].hex() + ">"
            return {
                "path": path,
                "status": r.status,
                "headers": headers,
                "body": body,
                "body_len": len(raw),
                "truncated": truncated,
            }
    except asyncio.TimeoutError:
        return {"path": path, "error": "timeout"}
    except aiohttp.ClientError as e:
        return {"path": path, "error": f"{type(e).__name__}: {e}"}


async def probe_fuzz(
    session: aiohttp.ClientSession,
    base_url: str,
    probe: dict,
    *,
    timeout: float,
) -> dict:
    """Issue a single fuzzed/abnormal request.

    The recorded `path` key is the probe's stable id (e.g. "PROPFIND /"),
    not a URL path — downstream diffing pairs responses by this key so both
    fixtures in a pair must agree. Uses the generic `session.request` so the
    same error/timeout handling as `probe_url` applies."""
    url = base_url.rstrip("/") + probe["path"]
    method = probe["method"]
    hdrs = probe.get("headers") or {}
    body = probe.get("body")
    try:
        async with session.request(
            method, url,
            headers=hdrs,
            data=body,
            allow_redirects=False,
            timeout=aiohttp.ClientTimeout(total=timeout),
        ) as r:
            raw = await r.content.read(BODY_CAP_BYTES + 1)
            truncated = len(raw) > BODY_CAP_BYTES
            raw = raw[:BODY_CAP_BYTES]
            ct = r.headers.get("Content-Type")
            resp_headers = {k.lower(): v for k, v in r.headers.items()}
            if _is_text(ct):
                out_body = raw.decode("utf-8", errors="replace")
            else:
                out_body = "<binary:" + raw[:64].hex() + ">"
            return {
                "path": probe["id"],
                "status": r.status,
                "headers": resp_headers,
                "body": out_body,
                "body_len": len(raw),
                "truncated": truncated,
            }
    except asyncio.TimeoutError:
        return {"path": probe["id"], "error": "timeout"}
    except (aiohttp.ClientError, ValueError) as e:
        # ValueError covers aiohttp rejecting the method/URL client-side,
        # e.g. overlong URLs on some aiohttp versions. Record the rejection
        # so diffs don't silently miss paired absences.
        return {"path": probe["id"], "error": f"{type(e).__name__}: {e}"}


def extract_refs(body: str, base_url: str, max_refs: int = MAX_CRAWL_REFS) -> list[str]:
    """Extract same-host script/stylesheet URLs from an HTML body.

    Returns a list of request paths (including any query string). Relative
    URLs are resolved against `base_url`; absolute URLs pointing at another
    host are dropped (we only probe the target under test). Order preserves
    document order; duplicates are removed."""
    if not body or body.startswith("<binary:"):
        return []
    base_host = urlparse(base_url).netloc
    seen: set[str] = set()
    out: list[str] = []
    for regex in (SCRIPT_SRC_RE, LINK_HREF_RE):
        for m in regex.finditer(body):
            raw = m.group(1).strip()
            if not raw or raw.startswith(("data:", "#", "javascript:")):
                continue
            abs_url = urljoin(base_url, raw)
            parsed = urlparse(abs_url)
            if parsed.scheme not in ("http", "https"):
                continue
            if parsed.netloc and parsed.netloc != base_host:
                continue
            path = parsed.path or "/"
            if parsed.query:
                path += "?" + parsed.query
            if path in seen:
                continue
            seen.add(path)
            out.append(path)
            if len(out) >= max_refs:
                return out
    return out


async def record_target(
    base_url: str,
    paths: list[str],
    *,
    timeout: float = 5.0,
    concurrency: int = 10,
    crawl: bool = True,
) -> list[dict]:
    connector = aiohttp.TCPConnector(limit=concurrency, ssl=False)
    headers = {"User-Agent": "fp-lab/1 (record)"}
    async with aiohttp.ClientSession(connector=connector, headers=headers) as sess:
        sem = asyncio.Semaphore(concurrency)

        async def bounded_path(p: str) -> dict:
            async with sem:
                return await probe_url(sess, base_url, p, timeout=timeout)

        async def bounded_fuzz(pf: dict) -> dict:
            async with sem:
                return await probe_fuzz(sess, base_url, pf, timeout=timeout)

        path_results = await asyncio.gather(*[bounded_path(p) for p in paths])
        fuzz_results = await asyncio.gather(*[bounded_fuzz(pf) for pf in FUZZ_PROBES])
        results = path_results + fuzz_results

        if crawl:
            # Mine the root response for referenced assets (<script src>,
            # <link href>) and probe same-host ones. This is where CMSes
            # and SPAs bury version strings — the root HTML is often thin
            # and delegates to bundled JS/CSS.
            already = set(paths) | {pf["id"] for pf in FUZZ_PROBES}
            root = next(
                (r for r in path_results
                 if r.get("path") == "/" and "error" not in r),
                None,
            )
            if root and isinstance(root.get("body"), str):
                refs = extract_refs(root["body"], base_url)
                new_refs = [r for r in refs if r not in already]
                if new_refs:
                    crawl_results = await asyncio.gather(
                        *[bounded_path(r) for r in new_refs]
                    )
                    results.extend(crawl_results)

        return results


def write_recording(
    outdir: Path,
    fixture_id: str,
    url: str,
    tech: str,
    version: str,
    responses: list[dict],
) -> Path:
    fx_dir = outdir / fixture_id
    fx_dir.mkdir(parents=True, exist_ok=True)
    rec_path = fx_dir / "responses.json"
    rec_path.write_text(
        json.dumps(
            {
                "fixture": fixture_id,
                "url": url,
                "tech": tech,
                "version": version,
                "responses": responses,
            },
            indent=2,
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )
    return rec_path


def main() -> int:
    ap = argparse.ArgumentParser(description="Record responses from a fixture for diff mining.")
    ap.add_argument("--url", required=True, help="Target base URL (e.g. http://localhost:18101)")
    ap.add_argument("--id", required=True, help="Fixture id (directory name under outdir)")
    ap.add_argument("--tech", required=True, help="Ground-truth tech name")
    ap.add_argument("--version", required=True, help="Ground-truth version string")
    ap.add_argument("--outdir", required=True, help="Output directory root")
    ap.add_argument("--timeout", type=float, default=5.0)
    ap.add_argument("--concurrency", type=int, default=10)
    args = ap.parse_args()

    responses = asyncio.run(
        record_target(
            args.url,
            DEFAULT_PROBE_PATHS,
            timeout=args.timeout,
            concurrency=args.concurrency,
        )
    )
    out = write_recording(
        Path(args.outdir),
        args.id,
        args.url,
        args.tech,
        args.version,
        responses,
    )
    hits = sum(1 for r in responses if "error" not in r)
    errs = len(responses) - hits
    print(f"Recorded {hits} responses ({errs} errors) to {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
