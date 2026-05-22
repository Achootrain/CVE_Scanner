"""JSONL corpus reading with blind-test guard.

The scanner writes ``scan_results.jsonl`` which the lab splits into
``data/scan_results_dev.jsonl`` (development) and
``data/scan_results_test.jsonl`` (blind final eval). Loading the test split
requires ``LAB_ALLOW_TEST=1`` so accidental usage during development is
rejected loudly.

This module is the single canonical implementation. ``backtest.read_jsonl``
and other historical entry points re-export from here.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Iterable


def _detect_encoding(path: Path) -> str:
    with open(path, "rb") as f:
        head = f.read(4)
    if head.startswith(b"\xff\xfe") or head.startswith(b"\xfe\xff"):
        return "utf-16"
    if head.startswith(b"\xef\xbb\xbf"):
        return "utf-8-sig"
    return "utf-8"


def guard_test_dataset(path: Path) -> None:
    """Refuse to load the blind-test JSONL during development.

    The test split is reserved for final evaluation: set ``LAB_ALLOW_TEST=1``
    to override (use sparingly; one shot per tech research cycle).
    """
    if path.name.endswith("scan_results_test.jsonl") and not os.environ.get("LAB_ALLOW_TEST"):
        raise SystemExit(
            f"refusing to load test dataset: {path}\n"
            "use data/scan_results_dev.jsonl for development, "
            "or set LAB_ALLOW_TEST=1 to override."
        )


def read_jsonl(path: Path) -> Iterable[dict]:
    """Yield each record from a scanner JSONL, tolerating BOMs and bad lines."""
    guard_test_dataset(path)
    enc = _detect_encoding(path)
    with open(path, "r", encoding=enc, errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue
