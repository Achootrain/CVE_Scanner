"""Collect .vn domain targets from crt.sh and Tranco top-1M.

Outputs one https:// URL per line to stdout (or --out file).

Sources (run in order, deduplicated):
  1. Tranco top-1M CSV -- filter rows whose domain ends in .vn
     Download: https://tranco-list.eu/download/latest/full
     Pass with --tranco tranco-full.csv

  2. crt.sh wildcard query -- %.vn certificate transparency logs
     Live HTTP GET; response can be 20-50 MB, uses aiohttp + 180s timeout.
     Skipped when --no-crtsh is set.

  3. crt.sh per-apex subdomain expansion (--expand) -- for each apex
     domain found in step 1/2, query crt.sh for its subdomains.
     Adds api.*, www.*, forum.* etc.

Usage:
    python lab/collect_vn_targets.py --out targets.txt
    python lab/collect_vn_targets.py --tranco tranco-full.csv --out targets.txt
    python lab/collect_vn_targets.py --no-crtsh --tranco tranco-full.csv
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

import aiohttp

CRTSH_URL = "https://crt.sh/?q=%25.vn&output=json"
CRTSH_SUB_URL = "https://crt.sh/?q=%25.{domain}&output=json"

# crt.sh wildcard %.vn returns 20-50 MB of JSON; give it 3 minutes.
# Per-domain subdomain queries are much smaller; 60s is plenty.
WILDCARD_TIMEOUT = 180
SUB_TIMEOUT = 60

_HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; fp-target-collector/1.0)"}


async def _fetch_crtsh(session: aiohttp.ClientSession, url: str, timeout: int) -> list:
    """Fetch a crt.sh JSON endpoint, return parsed list or [] on failure.

    crt.sh can return HTML under load. The fp/subdomains.py note says to
    fall back to NDJSON when the top-level JSON parse fails -- crt.sh
    sometimes sends newline-delimited records instead of a JSON array.
    """
    to = aiohttp.ClientTimeout(total=timeout)
    for attempt in range(3):
        try:
            async with session.get(url, timeout=to, ssl=False) as resp:
                raw = await resp.read()
            try:
                data = json.loads(raw)
                if isinstance(data, list):
                    return data
            except json.JSONDecodeError:
                pass
            # Fallback: try NDJSON line-by-line
            out = []
            for line in raw.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                    if isinstance(obj, dict):
                        out.append(obj)
                except json.JSONDecodeError:
                    continue
            return out
        except (aiohttp.ClientError, asyncio.TimeoutError) as exc:
            if attempt == 2:
                print(f"warn: {url} failed after 3 attempts: {exc}", file=sys.stderr)
                return []
            wait = 2 ** attempt
            print(f"  retry {attempt + 1}/3 in {wait}s ({exc})", file=sys.stderr)
            await asyncio.sleep(wait)
    return []


def _names_from_crtsh(data: list) -> set[str]:
    out: set[str] = set()
    for entry in data:
        for field in ("name_value", "common_name"):
            val = entry.get(field) or ""
            for name in val.split("\n"):
                name = name.strip().lower().lstrip("*.")
                if name and not name.startswith("*") and name.endswith(".vn"):
                    out.add(name)
    return out


def load_tranco(path: Path) -> set[str]:
    out: set[str] = set()
    with path.open(encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            parts = line.split(",", 1)
            domain = parts[-1].strip().lower()
            if domain.endswith(".vn"):
                out.add(domain)
    print(f"Tranco: {len(out)} .vn domains", file=sys.stderr)
    return out


async def _filter_live(urls: list[str], *, timeout: int = 5, concurrency: int = 50) -> list[str]:
    """Probe each URL; keep only those that return any HTTP response.

    Strategy: HEAD first; if server returns 405 retry with GET (some hosts
    reject HEAD entirely). Drops DNS failures, TCP timeouts, SSL errors.
    Keeps any HTTP status -- 403/404 still means a server is alive.
    """
    sem = asyncio.Semaphore(concurrency)
    total = len(urls)
    counters = {"live": 0, "dead": 0, "dns": 0, "timeout": 0, "other": 0}
    import time
    t0 = time.monotonic()

    async def _probe(session: aiohttp.ClientSession, url: str) -> bool:
        async with sem:
            to = aiohttp.ClientTimeout(total=timeout)
            for method in ("HEAD", "GET"):
                try:
                    async with session.request(
                        method, url, timeout=to, allow_redirects=True, ssl=False,
                    ) as r:
                        if method == "HEAD" and r.status == 405:
                            continue  # retry with GET
                        return True
                except aiohttp.ClientConnectorDNSError:
                    counters["dns"] += 1
                    return False
                except asyncio.TimeoutError:
                    counters["timeout"] += 1
                    return False
                except Exception:
                    counters["other"] += 1
                    return False
            return False  # both HEAD and GET failed

    async def _probe_tagged(session: aiohttp.ClientSession, url: str) -> tuple[str, bool]:
        return url, await _probe(session, url)

    live: list[str] = []
    connector = aiohttp.TCPConnector(ssl=False, limit=concurrency)
    async with aiohttp.ClientSession(headers=_HEADERS, connector=connector) as session:
        tasks = [asyncio.create_task(_probe_tagged(session, u)) for u in urls]
        done_count = 0
        for fut in asyncio.as_completed(tasks):
            url, ok = await fut
            done_count += 1
            if ok:
                counters["live"] += 1
                live.append(url)
            else:
                counters["dead"] += 1
            if done_count % 50 == 0 or done_count == total:
                elapsed = time.monotonic() - t0
                rate = done_count / elapsed if elapsed else 0
                eta = int((total - done_count) / rate) if rate else 0
                print(
                    f"  [{done_count:>4}/{total}] "
                    f"live={counters['live']} "
                    f"timeout={counters['timeout']} "
                    f"dns={counters['dns']} "
                    f"other={counters['other']} "
                    f"| {rate:.0f}/s  ETA {eta}s",
                    file=sys.stderr,
                )

    print(
        f"Filter done: {counters['live']} live / {total} total "
        f"({counters['timeout']} timeout, {counters['dns']} dns, "
        f"{counters['other']} other)",
        file=sys.stderr,
    )
    return live


async def _collect(args: argparse.Namespace) -> set[str]:
    hostnames: set[str] = set()

    if args.tranco:
        hostnames |= load_tranco(Path(args.tranco))

    connector = aiohttp.TCPConnector(ssl=False)
    async with aiohttp.ClientSession(headers=_HEADERS, connector=connector) as session:

        if not args.no_crtsh:
            print(
                f"Querying crt.sh for %%.vn (timeout {WILDCARD_TIMEOUT}s, "
                "response may be 20-50 MB) ...",
                file=sys.stderr,
            )
            data = await _fetch_crtsh(session, CRTSH_URL, WILDCARD_TIMEOUT)
            names = _names_from_crtsh(data)
            print(f"crt.sh wildcard: {len(names)} .vn hostnames", file=sys.stderr)
            hostnames |= names

        if args.expand:
            apexes = sorted({
                ".".join(h.split(".")[-2:])
                for h in hostnames
                if h.count(".") >= 1
            })
            print(
                f"Expanding {len(apexes)} apex domains via crt.sh ...",
                file=sys.stderr,
            )
            sem = asyncio.Semaphore(5)

            async def _expand(apex: str) -> set[str]:
                async with sem:
                    await asyncio.sleep(0.2)
                    url = CRTSH_SUB_URL.format(domain=apex)
                    d = await _fetch_crtsh(session, url, SUB_TIMEOUT)
                    return _names_from_crtsh(d)

            results = await asyncio.gather(*[_expand(a) for a in apexes])
            for s in results:
                hostnames |= s
            print(f"After expansion: {len(hostnames)} hostnames", file=sys.stderr)

    return hostnames


def main() -> None:
    ap = argparse.ArgumentParser(description="Collect .vn scan targets")
    ap.add_argument("--tranco", metavar="CSV", help="Tranco top-1M CSV path")
    ap.add_argument("--no-crtsh", action="store_true", help="Skip crt.sh wildcard query")
    ap.add_argument("--expand", action="store_true",
                    help="Expand each apex domain into subdomains via crt.sh")
    ap.add_argument("--out", help="Output file (default: stdout)")
    ap.add_argument("--limit", type=int, default=0,
                    help="Cap total targets (0 = no cap)")
    ap.add_argument("--filter-live", action="store_true",
                    help="HEAD-probe every collected URL and drop unreachable hosts "
                         "(timeout, DNS failure, connection refused). Adds ~1-3 min "
                         "for 2000 targets at concurrency=50.")
    ap.add_argument("--probe-timeout", type=int, default=5,
                    help="Per-host timeout in seconds for --filter-live (default: 5)")
    ap.add_argument("--probe-concurrency", type=int, default=50,
                    help="Concurrent probes for --filter-live (default: 50)")
    args = ap.parse_args()

    hostnames = asyncio.run(_collect(args))

    targets = sorted(f"https://{h}" for h in hostnames)
    if args.limit:
        targets = targets[:args.limit]

    if args.filter_live:
        print(f"Probing {len(targets)} targets for liveness "
              f"(timeout={args.probe_timeout}s, concurrency={args.probe_concurrency}) ...",
              file=sys.stderr)
        targets = asyncio.run(_filter_live(
            targets,
            timeout=args.probe_timeout,
            concurrency=args.probe_concurrency,
        ))
        print(f"Live targets after filter: {len(targets)}", file=sys.stderr)

    print(f"Total targets: {len(targets)}", file=sys.stderr)

    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            for t in targets:
                fh.write(t + "\n")
    else:
        for t in targets:
            print(t)


if __name__ == "__main__":
    main()
