"""Validate source-grounded rules against dev corpus.

Two passes:
1. Offline: URL + class rules only, no HTTP. Measures structural-rule coverage.
2. With body fetch: same plus banner extraction for sites where stage 1 found
   no version. Measures total coverage.

Writes:
    lab/research/fontawesome/src_dev_validation.md
    lab/research/fontawesome/src_dev_validation.json
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path


HERE = Path(__file__).resolve().parent
CORPUS = HERE / "corpus"
OUT_JSON = HERE / "src_dev_validation.json"
OUT_MD = HERE / "src_dev_validation.md"

sys.path.insert(0, str(HERE))
import detect_src  # noqa: E402


def summarise(per_site: list[dict], n_total: int) -> dict:
    n_ver = sum(1 for r in per_site if r["version"])
    n_gen_only = sum(1 for r in per_site if not r["version"] and (r["generation"] or r["generation_at_least"]))
    n_kit = sum(1 for r in per_site if r["kit_only"])
    n_none = sum(1 for r in per_site if not r["version"] and not r["generation"] and not r["generation_at_least"] and not r["kit_only"])
    return {
        "corpus_sites": n_total,
        "version_extracted": n_ver,
        "generation_only": n_gen_only,
        "kit_only": n_kit,
        "no_signal": n_none,
        "any_signal_pct": round(100 * (n_ver + n_gen_only + n_kit) / max(n_total, 1), 1),
        "version_pct": round(100 * n_ver / max(n_total, 1), 1),
    }


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--with-fetch", action="store_true", help="Enable stage-3 body fetch for banner extraction")
    ap.add_argument("--corpus-dir", default=str(CORPUS))
    ap.add_argument("--out-json", default=str(OUT_JSON))
    ap.add_argument("--out-md", default=str(OUT_MD))
    args = ap.parse_args(argv)

    corpus = Path(args.corpus_dir)
    html_files = sorted(corpus.glob("*.html"))

    fetcher = throttle = None
    if args.with_fetch:
        fetcher, throttle = detect_src.make_default_fetcher_throttle()

    per_site: list[dict] = []
    started = time.time()
    for i, hp in enumerate(html_files, 1):
        host = hp.stem
        html = hp.read_text(encoding="utf-8", errors="replace")
        det = detect_src.detect(host, html, fetcher=fetcher, throttle=throttle)
        row = det.to_dict()
        row["host"] = host
        per_site.append(row)
        if args.with_fetch:
            tag = (
                f"v={det.version}" if det.version
                else f"gen>={det.generation_at_least}" if det.generation_at_least
                else f"gen={det.generation}" if det.generation
                else "kit_only" if det.kit_only
                else "none"
            )
            print(f"  [{i:3d}/{len(html_files)}] {host:35s} {tag}", file=sys.stderr)

    summary = summarise(per_site, len(html_files))
    summary["elapsed_s"] = round(time.time() - started, 1)
    summary["with_fetch"] = bool(args.with_fetch)

    Path(args.out_json).write_text(json.dumps({"summary": summary, "per_site": per_site}, indent=2, ensure_ascii=False), encoding="utf-8")

    lines = [
        f"# Source-grounded rules validation on dev corpus ({'live-fetch' if args.with_fetch else 'offline'})",
        "",
        f"- Sites: **{summary['corpus_sites']}**",
        f"- Version extracted: **{summary['version_extracted']}** ({summary['version_pct']}%)",
        f"- Generation-only (no exact version): **{summary['generation_only']}**",
        f"- Kit-only (unrecoverable by design): **{summary['kit_only']}**",
        f"- No signal: **{summary['no_signal']}**",
        f"- **Any signal: {summary['any_signal_pct']}%**",
        f"- Elapsed: {summary['elapsed_s']}s",
        "",
        "## Per-site",
        "",
        "| Host | Version | Gen | Edition | Kit | Top rule sources |",
        "|------|---------|-----|---------|-----|------------------|",
    ]
    for row in per_site:
        gen = row["generation"] or (f">={row['generation_at_least']}" if row["generation_at_least"] else "")
        rules = ",".join(s["rule"] for s in row["sources"][:3]) or "-"
        lines.append(f"| {row['host']} | {row['version'] or ''} | {gen} | {row['edition'] or ''} | {'kit' if row['kit_only'] else ''} | {rules} |")
    Path(args.out_md).write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
