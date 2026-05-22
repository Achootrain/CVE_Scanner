"""Build tech-labeled URL dataset from BuiltWith Pro exports.

Inputs:
    lab/research/<dir-slug>/test.txt   -- tab-separated BuiltWith rows,
                                         hostname in column 2.

Output:
    data/url_by_tech.jsonl             -- one record per (tech, host):
        {"tech": "...", "host": "...", "url": "https://...",
         "source": "builtwith", "source_file": "lab/research/.../test.txt"}

Slug -> canonical tech mapping is fixed inline. Adjust SLUG_MAP if new
research dirs land. The tailwind/tailwindcss split is merged into
"tailwindcss" by dedup over hostname.

Usage:
    python lab/build_url_dataset.py
    python lab/build_url_dataset.py --out data/url_by_tech.jsonl --stats
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# dir-slug under lab/research/ -> canonical tech name used downstream
SLUG_MAP = {
    "owl-carousel":   "owl-carousel",
    "next.js":        "next.js",
    "wp-rocket":      "wp-rocket",
    "shopify":        "shopify",
    "jquerytooltip":  "jquery-ui-tooltip",
    "xenforo":        "xenforo",
    "nuxtjs":         "nuxt.js",
    "require.js":     "requirejs",
    "tailwind":       "tailwindcss",
    "tailwindcss":    "tailwindcss",
}

ROOT = Path(__file__).resolve().parent.parent  # repo root (D:\DATN2)
RESEARCH = ROOT / "lab" / "research"


def _parse_test_txt(path: Path) -> list[str]:
    """Yield hostnames from a BuiltWith export. Column 2 is the hostname.

    Skips blank lines and rows whose column 2 doesn't look like a hostname
    (no dot, contains whitespace, etc.).
    """
    hosts: list[str] = []
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        cols = raw.split("\t")
        if len(cols) < 2:
            continue
        host = cols[1].strip().lower().rstrip(".")
        if not host or "." not in host or " " in host:
            continue
        hosts.append(host)
    return hosts


def build(out_path: Path, *, stats: bool = False) -> dict:
    """Walk SLUG_MAP, ingest each test.txt, emit JSONL.

    Returns per-tech counts (canonical_tech -> unique host count).
    """
    by_tech: dict[str, set[str]] = {}
    by_tech_files: dict[str, list[str]] = {}

    for slug, tech in SLUG_MAP.items():
        src = RESEARCH / slug / "test.txt"
        if not src.exists():
            print(f"missing: {src.relative_to(ROOT)}", file=sys.stderr)
            continue
        hosts = _parse_test_txt(src)
        by_tech.setdefault(tech, set()).update(hosts)
        by_tech_files.setdefault(tech, []).append(
            str(src.relative_to(ROOT)).replace("\\", "/")
        )

    out_path.parent.mkdir(parents=True, exist_ok=True)
    n_records = 0
    with out_path.open("w", encoding="utf-8") as fh:
        for tech in sorted(by_tech):
            for host in sorted(by_tech[tech]):
                fh.write(json.dumps({
                    "tech": tech,
                    "host": host,
                    "url": f"https://{host}",
                    "source": "builtwith",
                    "source_files": by_tech_files[tech],
                }) + "\n")
                n_records += 1

    counts = {t: len(hs) for t, hs in by_tech.items()}
    print(f"wrote {n_records} records to {out_path.relative_to(ROOT)}",
          file=sys.stderr)
    if stats:
        print("\nper-tech unique hosts:", file=sys.stderr)
        for tech in sorted(counts):
            print(f"  {tech:<22} {counts[tech]:>4}", file=sys.stderr)
    return counts


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--out", default="data/url_by_tech.jsonl",
                    help="Output JSONL path (default: data/url_by_tech.jsonl)")
    ap.add_argument("--stats", action="store_true",
                    help="Print per-tech unique host counts to stderr")
    args = ap.parse_args()
    build(ROOT / args.out, stats=args.stats)


if __name__ == "__main__":
    main()
