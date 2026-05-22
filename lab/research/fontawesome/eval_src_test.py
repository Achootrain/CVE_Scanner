"""Final-eval source-grounded FA rules against BLIND test set.

Single LAB_ALLOW_TEST=1 run. Fetches root HTML for each FA-positive test
target, applies source-grounded rules (URL + class + banner-fetch).
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
OUT_JSON = HERE / "src_test_eval.json"
OUT_MD = HERE / "src_test_eval.md"

sys.path.insert(0, str(REPO / "fingerprinter"))
sys.path.insert(0, str(REPO / "lab" / "research" / "dashboard"))
sys.path.insert(0, str(HERE))
import backtest  # noqa: E402 -- LAB_ALLOW_TEST guard
import detect_src  # noqa: E402


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
    args = ap.parse_args(argv)

    targets = load_fa_targets(Path(args.scan_jsonl))
    print(f"FA-positive test targets: {len(targets)}", file=sys.stderr)

    fetcher, throttle = detect_src.make_default_fetcher_throttle()

    per_site: list[dict] = []
    started = time.time()
    for i, target in enumerate(targets, 1):
        host = urlparse(target).netloc
        throttle.acquire(host)
        try:
            res = fetcher.fetch(target, timeout=10.0, verify_ssl=False, extra_headers={})
        except Exception as e:
            per_site.append({"host": host, "version": None, "fetch_error": str(e)[:200]})
            print(f"  [{i:3d}/{len(targets)}] EXC {host}: {e}", file=sys.stderr)
            continue
        if not res.is_ok or not res.body:
            per_site.append({"host": host, "version": None, "fetch_error": res.error or res.status_tag})
            print(f"  [{i:3d}/{len(targets)}] {res.status_tag} {host}: {res.error}", file=sys.stderr)
            continue
        det = detect_src.detect(target, res.body, fetcher=fetcher, throttle=throttle)
        row = det.to_dict()
        row["host"] = host
        per_site.append(row)
        tag = (
            f"v={det.version}" if det.version
            else f"gen>={det.generation_at_least}" if det.generation_at_least
            else f"gen={det.generation}" if det.generation
            else "kit_only" if det.kit_only
            else "no_signal"
        )
        print(f"  [{i:3d}/{len(targets)}] {host:30s} {tag}", file=sys.stderr)

    n_total = len(targets)
    n_ver = sum(1 for r in per_site if r.get("version"))
    n_gen = sum(1 for r in per_site if not r.get("version") and (r.get("generation") or r.get("generation_at_least")))
    n_kit = sum(1 for r in per_site if r.get("kit_only"))
    n_fetch_err = sum(1 for r in per_site if r.get("fetch_error"))
    n_none = n_total - n_ver - n_gen - n_kit - n_fetch_err
    summary = {
        "test_targets": n_total,
        "version_extracted": n_ver,
        "generation_only": n_gen,
        "kit_only": n_kit,
        "fetch_error": n_fetch_err,
        "no_signal": n_none,
        "any_signal_pct_raw": round(100 * (n_ver + n_gen + n_kit) / max(n_total, 1), 1),
        "any_signal_pct_of_fetched": round(100 * (n_ver + n_gen + n_kit) / max(n_total - n_fetch_err, 1), 1),
        "version_pct_raw": round(100 * n_ver / max(n_total, 1), 1),
        "version_pct_of_fetched": round(100 * n_ver / max(n_total - n_fetch_err, 1), 1),
        "elapsed_s": round(time.time() - started, 1),
    }
    print(file=sys.stderr)
    print(json.dumps(summary, indent=2), file=sys.stderr)

    Path(args.out_json).write_text(
        json.dumps({"summary": summary, "per_site": per_site}, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    lines = [
        "# Final eval: source-grounded FA rules on BLIND TEST SET",
        "",
        f"- Test FA-positive targets: **{n_total}**",
        f"- Version extracted: **{n_ver}** ({summary['version_pct_raw']}% raw / {summary['version_pct_of_fetched']}% of fetched)",
        f"- Generation only: **{n_gen}**",
        f"- Kit only: **{n_kit}**",
        f"- Fetch error: **{n_fetch_err}**",
        f"- No signal: **{n_none}**",
        f"- **Any signal: {summary['any_signal_pct_raw']}% raw / {summary['any_signal_pct_of_fetched']}% of fetched**",
        f"- Elapsed: {summary['elapsed_s']}s",
        "",
        "## Per-site",
        "",
        "| Host | Version | Gen | Edition | Kit | Error | Rules |",
        "|------|---------|-----|---------|-----|-------|-------|",
    ]
    for row in per_site:
        gen = row.get("generation") or (f">={row.get('generation_at_least')}" if row.get("generation_at_least") else "")
        rules = ",".join(s["rule"] for s in (row.get("sources") or [])[:3]) or ""
        lines.append(
            f"| {row['host']} | {row.get('version','') or ''} | {gen} | {row.get('edition','') or ''} | "
            f"{'kit' if row.get('kit_only') else ''} | {row.get('fetch_error','') or ''} | {rules} |"
        )
    Path(args.out_md).write_text("\n".join(lines) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
