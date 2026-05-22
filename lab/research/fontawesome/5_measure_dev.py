"""Phase 5: end-to-end FA detection rate on the dev corpus (offline).

Applies detect_fa.extract_fa_urls + extract_version_from_url to every
corpus HTML (Phase 2 path). For sites with no URL-extractable version,
fall back to the Phase 3 body-mining JSON.

This measures the rule pack as a whole, with no double-counting and no
fresh HTTP. Writes a per-site detection report.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


HERE = Path(__file__).resolve().parent
CORPUS_DIR = HERE / "corpus"
BODY_JSON = HERE / "mined_body_fingerprints.json"
OUT_MD = HERE / "dev_detection.md"
OUT_JSON = HERE / "dev_detection.json"

sys.path.insert(0, str(HERE))
import detect_fa  # noqa: E402


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--corpus-dir", default=str(CORPUS_DIR))
    ap.add_argument("--body-json", default=str(BODY_JSON))
    ap.add_argument("--out-md", default=str(OUT_MD))
    ap.add_argument("--out-json", default=str(OUT_JSON))
    args = ap.parse_args(argv)

    corpus = Path(args.corpus_dir)
    body = json.loads(Path(args.body_json).read_text(encoding="utf-8")) if Path(args.body_json).exists() else {"findings": []}
    body_index: dict[str, dict] = {}
    for row in body.get("findings", []):
        if row["host"] not in body_index:
            body_index[row["host"]] = row

    html_files = sorted(corpus.glob("*.html"))
    per_site: list[dict] = []
    n_url = n_body = n_kit_only = n_none = 0

    for hp in html_files:
        host = hp.stem
        html = hp.read_text(encoding="utf-8", errors="replace")
        det = detect_fa.detect_from_html(host, html, fetcher=None)
        if det.version:
            # Should be source="url" since fetcher=None
            per_site.append({"host": host, "version": det.version, "source": det.source, "url": det.url})
            n_url += 1
        elif det.kit_only:
            per_site.append({"host": host, "version": None, "source": "kit_only", "url": None})
            n_kit_only += 1
        else:
            # Stage 2 fallback via saved Phase 3 data
            row = body_index.get(host)
            if row:
                m0 = row["matches"][0]
                per_site.append({"host": host, "version": m0["version"], "source": "body", "url": row["url"]})
                n_body += 1
            else:
                per_site.append({"host": host, "version": None, "source": None, "url": None})
                n_none += 1

    n_total = len(html_files)
    n_versioned = n_url + n_body
    rate = 100 * n_versioned / max(n_total, 1)
    summary = {
        "corpus_sites": n_total,
        "versioned": n_versioned,
        "from_url": n_url,
        "from_body": n_body,
        "kit_only": n_kit_only,
        "no_version": n_none,
        "detection_rate_pct": round(rate, 1),
    }

    Path(args.out_json).write_text(json.dumps({"summary": summary, "per_site": per_site}, indent=2, ensure_ascii=False), encoding="utf-8")

    lines = [
        "# Phase 5: End-to-end FA detection rate (dev corpus, offline)",
        "",
        f"- Corpus sites: **{n_total}**",
        f"- Versioned: **{n_versioned}** = **{rate:.1f}%**",
        f"  - From URL: {n_url}",
        f"  - From body: {n_body}",
        f"- Kit-only (unrecoverable): {n_kit_only}",
        f"- No version: {n_none}",
        "",
        "## Per-site detections (versioned)",
        "",
        "| Host | Version | Source | URL |",
        "|------|---------|--------|-----|",
    ]
    for row in per_site:
        if row["version"]:
            url = (row["url"] or "")[:80]
            lines.append(f"| {row['host']} | {row['version']} | {row['source']} | `{url}` |")
    lines += ["", "## Sites with NO version detected", ""]
    for row in per_site:
        if not row["version"]:
            lines.append(f"- `{row['host']}` ({row['source'] or 'no_version'})")
    Path(args.out_md).write_text("\n".join(lines) + "\n", encoding="utf-8")

    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
