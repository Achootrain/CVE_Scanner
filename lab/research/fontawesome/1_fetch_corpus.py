"""Phase 1: fetch root HTML for FA-positive sites and save to corpus/.

Reads:
    data/scan_results_dev.jsonl   (default; --scan-jsonl to override)

Writes:
    lab/research/fontawesome/corpus/<host>.html       (decoded body)
    lab/research/fontawesome/corpus/_manifest.jsonl   (per-site status row)

Politeness: curl_cffi fetcher, per-host serial via HostThrottle, single retry,
10s timeout, 1 MiB body cap. Idempotent -- skips hosts whose .html exists.

Why: scan_results.jsonl records WHICH FA-positive sites we have but discards
the actual <link>/<script> URLs that triggered detection. To mine real URL
patterns and link href versions, we need the raw HTML.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path
from urllib.parse import urlparse


HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent.parent
SCAN_JSONL_DEFAULT = REPO / "data" / "scan_results_dev.jsonl"
CORPUS_DIR = HERE / "corpus"

# Lab + fingerprinter on sys.path
sys.path.insert(0, str(REPO / "fingerprinter"))
sys.path.insert(0, str(REPO / "lab" / "research" / "dashboard"))
import backtest  # noqa: E402  -- reuse read_jsonl + test-set guard
import fetchlib  # noqa: E402


def load_fa_targets(scan_path: Path) -> list[str]:
    """Return ordered, deduped target URLs where the scan flagged Font Awesome."""
    seen: set[str] = set()
    out: list[str] = []
    for rec in backtest.read_jsonl(scan_path):
        techs = rec.get("techs") or []
        fa = any(
            "font" in (t.get("name") or "").lower() and "awesome" in (t.get("name") or "").lower()
            for t in techs
        )
        if not fa:
            continue
        target = rec.get("target") or rec.get("url")
        if not target:
            continue
        # normalize to scheme://host
        u = urlparse(target)
        if not u.scheme:
            target = f"https://{target}"
            u = urlparse(target)
        key = f"{u.scheme}://{u.netloc}"
        if key in seen:
            continue
        seen.add(key)
        out.append(key)
    return out


def host_of(url: str) -> str:
    return urlparse(url).netloc or url.replace("https://", "").replace("http://", "")


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--scan-jsonl", default=str(SCAN_JSONL_DEFAULT))
    ap.add_argument("--out-dir", default=str(CORPUS_DIR))
    ap.add_argument("--strategy", default="curl_cffi", choices=["requests", "curl_cffi"])
    ap.add_argument("--timeout", type=float, default=10.0)
    ap.add_argument("--min-host-gap", type=float, default=0.3)
    ap.add_argument("--force", action="store_true", help="Refetch even if file exists")
    args = ap.parse_args(argv)

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    manifest_path = out_dir / "_manifest.jsonl"

    targets = load_fa_targets(Path(args.scan_jsonl))
    print(f"FA-positive targets: {len(targets)}", file=sys.stderr)

    fetcher = fetchlib.make_fetcher(args.strategy)
    throttle = fetchlib.HostThrottle(min_delay_s=args.min_host_gap)

    n_ok = n_skip = n_blocked = n_err = 0
    started = time.time()
    with manifest_path.open("a", encoding="utf-8") as mf:
        for i, url in enumerate(targets, 1):
            host = host_of(url)
            html_path = out_dir / f"{host}.html"
            if html_path.exists() and not args.force:
                n_skip += 1
                continue
            throttle.acquire(host)
            try:
                res = fetcher.fetch(
                    url,
                    timeout=args.timeout,
                    verify_ssl=False,
                    extra_headers={},
                )
            except Exception as e:
                n_err += 1
                mf.write(json.dumps({"host": host, "url": url, "status_tag": "exception", "error": str(e)}) + "\n")
                print(f"  [{i:3d}/{len(targets)}] {host:40s} EXC: {e}", file=sys.stderr)
                continue
            row = {
                "host": host,
                "url": url,
                "status_tag": res.status_tag,
                "http_status": res.http_status,
                "final_url": res.final_url,
                "body_bytes": len(res.body.encode("utf-8", errors="replace")) if res.body else 0,
                "error": res.error,
                "fetched_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
            }
            mf.write(json.dumps(row) + "\n")
            if res.is_ok:
                html_path.write_text(res.body, encoding="utf-8", errors="replace")
                n_ok += 1
                print(f"  [{i:3d}/{len(targets)}] {host:40s} OK   {res.http_status} {row['body_bytes']}b", file=sys.stderr)
            elif res.is_blocked:
                n_blocked += 1
                print(f"  [{i:3d}/{len(targets)}] {host:40s} BLOCK {res.error}", file=sys.stderr)
            else:
                n_err += 1
                print(f"  [{i:3d}/{len(targets)}] {host:40s} {res.status_tag} {res.error}", file=sys.stderr)
    elapsed = time.time() - started
    print(f"done in {elapsed:.1f}s: ok={n_ok} skip={n_skip} blocked={n_blocked} err={n_err}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
