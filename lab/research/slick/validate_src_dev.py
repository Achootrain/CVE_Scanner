"""Validate source-grounded slick rules against dev corpus.

Two passes:
1. Offline: URL-only rules (version-in-path, filename, webfont). No HTTP.
2. With body fetch (--with-fetch): also fetch slick.js bodies for banner
   extraction on sites where stage 1 found no version.

Reads:  lab/research/slick/dataset_dev.jsonl
Writes: lab/research/slick/src_dev_validation.json
        lab/research/slick/src_dev_validation.md
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent.parent
DEV_JSONL = HERE / "dataset_dev.jsonl"
OUT_JSON = HERE / "src_dev_validation.json"
OUT_MD = HERE / "src_dev_validation.md"

sys.path.insert(0, str(REPO / "lab" / "research" / "dashboard"))
import backtest  # noqa: E402

sys.path.insert(0, str(HERE))
import detect_src  # noqa: E402


def summarise(per_site: list[dict], n_total: int) -> dict:
    n_ver = sum(1 for r in per_site if r["version"])
    n_detected = sum(1 for r in per_site if r["slick_urls"] or r["sources"])
    n_no_signal = sum(1 for r in per_site if not r["version"] and not r["slick_urls"] and not r["sources"])
    return {
        "corpus_sites": n_total,
        "version_extracted": n_ver,
        "detected_no_version": n_detected - n_ver,
        "no_signal": n_no_signal,
        "version_pct": round(100 * n_ver / max(n_total, 1), 1),
        "any_signal_pct": round(100 * n_detected / max(n_total, 1), 1),
    }


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description="Validate slick rules against dev corpus")
    ap.add_argument("--with-fetch", action="store_true",
                    help="Enable body fetch for banner extraction")
    ap.add_argument("--dataset", default=str(DEV_JSONL),
                    help="Path to dataset JSONL")
    ap.add_argument("--out-json", default=str(OUT_JSON))
    ap.add_argument("--out-md", default=str(OUT_MD))
    args = ap.parse_args(argv)

    rules = detect_src.load_rules()
    fetcher = throttle = None
    if args.with_fetch:
        fetcher, throttle = detect_src.make_default_fetcher_throttle()

    records = list(backtest.read_jsonl(Path(args.dataset)))
    per_site: list[dict] = []
    started = time.time()

    for i, rec in enumerate(records, 1):
        target = rec.get("target") or rec.get("url") or ""
        det = detect_src.detect_from_record(
            rec, rules=rules, fetcher=fetcher, throttle=throttle
        )
        row = det.to_dict()
        row["target"] = target
        per_site.append(row)

        tag = f"v={det.version}" if det.version else "no_ver"
        n_urls = len(det.slick_urls)
        n_rules = len(det.sources)
        print(f"  [{i:3d}/{len(records)}] {target:45s} {tag:15s} "
              f"urls={n_urls} rules_hit={n_rules}", file=sys.stderr)

    summary = summarise(per_site, len(records))
    summary["elapsed_s"] = round(time.time() - started, 1)
    summary["with_fetch"] = bool(args.with_fetch)

    Path(args.out_json).write_text(
        json.dumps({"summary": summary, "per_site": per_site}, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    lines = [
        f"# Slick source-grounded rules validation ({'live-fetch' if args.with_fetch else 'offline'})",
        "",
        f"- Sites in dev corpus: **{summary['corpus_sites']}**",
        f"- Version extracted: **{summary['version_extracted']}** ({summary['version_pct']}%)",
        f"- Detected but no version: **{summary['detected_no_version']}**",
        f"- No signal: **{summary['no_signal']}**",
        f"- **Any signal: {summary['any_signal_pct']}%**",
        f"- Elapsed: {summary['elapsed_s']}s",
        "",
        "## Per-site",
        "",
        "| Target | Version | slick URLs | Rules hit |",
        "|--------|---------|------------|-----------|",
    ]
    for row in per_site:
        ver = row["version"] or ""
        n_urls = len(row["slick_urls"])
        rules_hit = ", ".join(s["rule"] for s in row["sources"][:5]) or "-"
        lines.append(f"| {row['target']} | {ver} | {n_urls} | {rules_hit} |")

    Path(args.out_md).write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
