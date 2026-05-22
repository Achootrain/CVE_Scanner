"""Phase 6: final-eval FA detection rate on the BLIND TEST SET.

This is the SINGLE end-to-end run against scan_results_test.jsonl.
Requires LAB_ALLOW_TEST=1 in env (enforced by backtest.read_jsonl guard).

For each FA-positive site in the test JSONL:
  1. Fetch root HTML (live, polite throttle).
  2. Run detect_fa.detect_from_html with fetcher enabled (URL + body fallback).
  3. Record version + source.

Reports detection rate vs dev baseline (92.9%).
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from urllib.parse import urlparse


HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent.parent
OUT_JSON = HERE / "test_eval.json"
OUT_MD = HERE / "test_eval.md"

sys.path.insert(0, str(REPO / "fingerprinter"))
sys.path.insert(0, str(REPO / "lab" / "research" / "dashboard"))
sys.path.insert(0, str(HERE))
import backtest  # noqa: E402  -- includes LAB_ALLOW_TEST guard
import detect_fa  # noqa: E402


def load_fa_targets(scan_path: Path) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for rec in backtest.read_jsonl(scan_path):
        techs = rec.get("techs") or []
        if not any(
            "font" in (t.get("name") or "").lower() and "awesome" in (t.get("name") or "").lower()
            for t in techs
        ):
            continue
        target = rec.get("target") or rec.get("url")
        if not target:
            continue
        u = urlparse(target if "://" in target else f"https://{target}")
        key = f"{u.scheme}://{u.netloc}"
        if key in seen:
            continue
        seen.add(key)
        out.append(key)
    return out


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--scan-jsonl", required=True)
    ap.add_argument("--out-json", default=str(OUT_JSON))
    ap.add_argument("--out-md", default=str(OUT_MD))
    ap.add_argument("--strategy", default="curl_cffi")
    ap.add_argument("--timeout", type=float, default=10.0)
    ap.add_argument("--min-host-gap", type=float, default=0.3)
    args = ap.parse_args(argv)

    targets = load_fa_targets(Path(args.scan_jsonl))
    print(f"FA-positive test targets: {len(targets)}", file=sys.stderr)

    fetcher, throttle = detect_fa.make_default_fetcher_throttle(
        strategy=args.strategy, min_host_gap=args.min_host_gap,
    )

    per_site: list[dict] = []
    n_url = n_body = n_kit = n_none = n_fetch_err = 0
    started = time.time()
    for i, target in enumerate(targets, 1):
        host = urlparse(target).netloc
        throttle.acquire(host)
        try:
            res = fetcher.fetch(target, timeout=args.timeout, verify_ssl=False, extra_headers={})
        except Exception as e:
            n_fetch_err += 1
            per_site.append({"host": host, "version": None, "source": "fetch_exc", "error": str(e)[:200]})
            print(f"  [{i:3d}/{len(targets)}] EXC  {host}: {e}", file=sys.stderr)
            continue
        if not res.is_ok or not res.body:
            n_fetch_err += 1
            per_site.append({"host": host, "version": None, "source": res.status_tag, "error": res.error})
            print(f"  [{i:3d}/{len(targets)}] {res.status_tag} {host} {res.error or ''}", file=sys.stderr)
            continue
        det = detect_fa.detect_from_html(target, res.body, fetcher=fetcher, throttle=throttle)
        if det.version:
            per_site.append({
                "host": host, "version": det.version, "source": det.source,
                "url": det.url, "evidence": det.evidence,
            })
            if det.source == "url":
                n_url += 1
            else:
                n_body += 1
            print(f"  [{i:3d}/{len(targets)}] HIT  {host:35s} -> {det.version}  ({det.source})", file=sys.stderr)
        elif det.kit_only:
            per_site.append({"host": host, "version": None, "source": "kit_only", "urls": det.fa_urls})
            n_kit += 1
            print(f"  [{i:3d}/{len(targets)}] kit  {host}", file=sys.stderr)
        else:
            per_site.append({"host": host, "version": None, "source": "no_match", "urls": det.fa_urls})
            n_none += 1
            print(f"  [{i:3d}/{len(targets)}] miss {host}  fa_urls={len(det.fa_urls)}", file=sys.stderr)

    elapsed = time.time() - started
    n_total = len(targets)
    n_ver = n_url + n_body
    rate = 100 * n_ver / max(n_total, 1)
    summary = {
        "test_targets": n_total,
        "versioned": n_ver,
        "from_url": n_url,
        "from_body": n_body,
        "kit_only": n_kit,
        "no_match": n_none,
        "fetch_err": n_fetch_err,
        "detection_rate_pct": round(rate, 1),
        "elapsed_s": round(elapsed, 1),
    }
    print(file=sys.stderr)
    print(json.dumps(summary, indent=2), file=sys.stderr)

    Path(args.out_json).write_text(
        json.dumps({"summary": summary, "per_site": per_site}, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    lines = [
        "# Phase 6: FA detection on BLIND TEST SET",
        "",
        f"- Test FA-positive targets: **{n_total}**",
        f"- Versioned: **{n_ver}** = **{rate:.1f}%**",
        f"  - From URL: {n_url}",
        f"  - From body: {n_body}",
        f"- Kit-only: {n_kit}",
        f"- No match (FA URLs found, no version): {n_none}",
        f"- Fetch errors: {n_fetch_err}",
        f"- Elapsed: {elapsed:.1f}s",
        "",
        "## Per-site detections",
        "",
        "| Host | Version | Source | URL |",
        "|------|---------|--------|-----|",
    ]
    for row in per_site:
        url = (row.get("url") or "")[:80]
        v = row.get("version") or ""
        src = row.get("source") or ""
        lines.append(f"| {row['host']} | {v} | {src} | `{url}` |")
    Path(args.out_md).write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"wrote {args.out_json}", file=sys.stderr)
    print(f"wrote {args.out_md}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
