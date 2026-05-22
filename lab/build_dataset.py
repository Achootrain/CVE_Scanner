"""Assemble AI training dataset from pipeline --save-responses output.

Usage:
    python lab/build_dataset.py ./responses/ ./dataset.jsonl
    python lab/build_dataset.py ./responses/ ./dataset.jsonl --min-confidence 80
    python lab/build_dataset.py ./responses/ ./dataset.jsonl --versioned-only

Input:
    Directory of <host>.responses.jsonl + <host>.labels.jsonl pairs written
    by `fp pipeline --save-responses <dir>`.

Output:
    JSONL where each record is one HTTP response with tech/version labels:

    {
      "id": "<sha1>",
      "url": "https://example.vn/wp-login.php",
      "content_type": "text/html; charset=UTF-8",
      "status": 200,
      "response_headers": {...},
      "body": "<decoded body or null if binary>",
      "body_b64": "<base64 raw bytes>",
      "body_size": 14520,
      "labels": [
        {"tech": "WordPress", "version": "6.4.3", "source": "wappalyzer"},
        ...
      ],
      "target": "https://example.vn",
      "timestamp": "..."
    }

Filters applied:
    - Drop records with no version in any label (unless --all-labels)
    - Drop bodies > --max-body-bytes (default 2 MiB)
    - Drop bodies < --min-body-bytes (default 200 bytes -- login walls)
    - Drop responses with non-200 status (unless --all-status)
    - SHA1 dedup across the full input (already done at write time, but
      guard against merged dirs from multiple runs)

Train/val split:
    Split is on apex domain, not URL, to prevent leakage. Sites using the
    same CMS across subdomains all land in the same split.
    Written to <output>.train.jsonl and <output>.val.jsonl when --split is set.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import sys
from pathlib import Path
from urllib.parse import urlsplit


def _apex(host: str) -> str:
    parts = host.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def load_records(responses_dir: Path, args: argparse.Namespace):
    seen_ids: set[str] = set()
    label_map: dict[str, list[dict]] = {}

    # Load all label files first (small)
    for lf in sorted(responses_dir.glob("*.labels.jsonl")):
        with lf.open(encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    continue
                rid = rec.get("id")
                if rid:
                    label_map.setdefault(rid, []).extend(rec.get("labels") or [])

    # Stream response files, join with labels
    for rf in sorted(responses_dir.glob("*.responses.jsonl")):
        with rf.open(encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    continue

                rid = rec.get("id")
                if not rid or rid in seen_ids:
                    continue

                labels = label_map.get(rid) or []
                if not labels:
                    continue

                # Filter: versioned-only
                has_version = any(lb.get("version") for lb in labels)
                if args.versioned_only and not has_version:
                    continue

                # Filter: min confidence
                if args.min_confidence > 0:
                    labels = [
                        lb for lb in labels
                        if (lb.get("confidence") or 0) >= args.min_confidence
                        or lb.get("confidence") is None
                    ]
                    if not labels:
                        continue

                # Filter: body size
                body_size = rec.get("body_size", 0)
                if body_size > args.max_body_bytes:
                    continue
                if body_size < args.min_body_bytes:
                    continue

                # Filter: status
                status = rec.get("status", 0)
                if not args.all_status and status != 200:
                    continue

                seen_ids.add(rid)

                # Decode body to text when possible; keep b64 for binary
                body_b64 = rec.get("body_b64", "")
                raw = base64.b64decode(body_b64) if body_b64 else b""
                try:
                    body_text = raw.decode("utf-8")
                    body_b64_out = None
                except UnicodeDecodeError:
                    body_text = None
                    body_b64_out = body_b64

                out = {
                    "id": rid,
                    "url": rec.get("url", ""),
                    "content_type": rec.get("content_type", ""),
                    "status": status,
                    "response_headers": rec.get("response_headers") or {},
                    "body": body_text,
                    "body_size": body_size,
                    "labels": labels,
                    "target": rec.get("target", ""),
                    "timestamp": rec.get("timestamp", ""),
                }
                if body_b64_out is not None:
                    out["body_b64"] = body_b64_out

                yield out


def main() -> None:
    ap = argparse.ArgumentParser(description="Build AI training dataset from fp pipeline responses")
    ap.add_argument("responses_dir", help="Directory with *.responses.jsonl + *.labels.jsonl")
    ap.add_argument("output", help="Output JSONL path (or stem when --split)")
    ap.add_argument("--versioned-only", action="store_true",
                    help="Only include records where at least one label has a version")
    ap.add_argument("--all-status", action="store_true",
                    help="Include non-200 responses (default: 200 only)")
    ap.add_argument("--all-labels", action="store_true",
                    help="Include records with no versioned label")
    ap.add_argument("--min-confidence", type=int, default=0,
                    help="Drop labels below this confidence (0 = keep all)")
    ap.add_argument("--max-body-bytes", type=int, default=2 * 1024 * 1024,
                    help="Skip responses with body > N bytes (default: 2 MiB)")
    ap.add_argument("--min-body-bytes", type=int, default=200,
                    help="Skip responses with body < N bytes (default: 200)")
    ap.add_argument("--split", type=float, default=0.0,
                    help="Train fraction for train/val split on apex domain (e.g. 0.9)")
    args = ap.parse_args()

    if args.all_labels:
        args.versioned_only = False

    responses_dir = Path(args.responses_dir)
    if not responses_dir.is_dir():
        print(f"error: {responses_dir} is not a directory", file=sys.stderr)
        sys.exit(1)

    records = list(load_records(responses_dir, args))
    print(f"Loaded {len(records)} records after filters", file=sys.stderr)

    if not args.split:
        out_path = Path(args.output)
        with out_path.open("w", encoding="utf-8") as fh:
            for rec in records:
                fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
        print(f"Written {len(records)} records to {out_path}", file=sys.stderr)
        return

    # Train/val split on apex domain
    from collections import defaultdict
    by_apex: dict[str, list[dict]] = defaultdict(list)
    for rec in records:
        host = urlsplit(rec["url"]).hostname or ""
        by_apex[_apex(host)].append(rec)

    apexes = sorted(by_apex)
    n_train = int(len(apexes) * args.split)
    train_apexes = set(apexes[:n_train])

    stem = Path(args.output).with_suffix("")
    train_path = Path(str(stem) + ".train.jsonl")
    val_path = Path(str(stem) + ".val.jsonl")

    n_train_recs = n_val_recs = 0
    with train_path.open("w", encoding="utf-8") as tf, val_path.open("w", encoding="utf-8") as vf:
        for apex, recs in by_apex.items():
            fh = tf if apex in train_apexes else vf
            for rec in recs:
                fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
                if apex in train_apexes:
                    n_train_recs += 1
                else:
                    n_val_recs += 1

    print(
        f"Train: {n_train_recs} records ({len(train_apexes)} domains) -> {train_path}",
        file=sys.stderr,
    )
    print(
        f"Val:   {n_val_recs} records ({len(apexes) - len(train_apexes)} domains) -> {val_path}",
        file=sys.stderr,
    )


if __name__ == "__main__":
    main()
