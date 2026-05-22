"""Port of data/analyze.py: returns structured data instead of printing.

Reads a JSONL scan_results file (one pipeline record per line) and computes
aggregates: tech counts, version coverage, version-leak URLs, tech -> URLs map.
"""

from __future__ import annotations

import json
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable


def detect_encoding(path: str | Path) -> str:
    with open(path, "rb") as f:
        start = f.read(4)
    if start.startswith(b"\xff\xfe") or start.startswith(b"\xfe\xff"):
        return "utf-16"
    if start.startswith(b"\xef\xbb\xbf"):
        return "utf-8-sig"
    return "utf-8"


def open_safe(path: str | Path):
    encodings = [detect_encoding(path), "utf-8", "utf-8-sig", "latin-1"]
    last_err: Exception | None = None
    for enc in encodings:
        try:
            return open(path, "r", encoding=enc)
        except Exception as e:
            last_err = e
    raise RuntimeError(f"Cannot open file: {last_err}")


def iter_records(path: str | Path) -> Iterable[dict]:
    """Yield one parsed record per JSONL line, skipping blanks/bad lines."""
    with open_safe(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue


@dataclass
class AnalysisResult:
    total_targets: int = 0
    total_techs: int = 0
    bad_lines: int = 0

    tech_counter: Counter = field(default_factory=Counter)
    tech_with_version_counter: Counter = field(default_factory=Counter)
    version_counter: Counter = field(default_factory=Counter)  # key: (tech, version)
    tech_versions: dict = field(default_factory=lambda: defaultdict(list))

    url_version_counter: Counter = field(default_factory=Counter)
    tech_url_map: dict = field(default_factory=lambda: defaultdict(set))

    targets: list = field(default_factory=list)

    @property
    def unique_techs(self) -> int:
        return len(self.tech_counter)

    def coverage_rows(self) -> list[dict]:
        rows = []
        for tech, total in self.tech_counter.most_common():
            with_ver = self.tech_with_version_counter.get(tech, 0)
            without_ver = total - with_ver
            ratio = (with_ver / total * 100.0) if total else 0.0
            rows.append({
                "tech": tech,
                "total": total,
                "with_version": with_ver,
                "without_version": without_ver,
                "coverage_pct": round(ratio, 1),
            })
        return rows

    def top_techs(self, n: int = 10) -> list[tuple[str, int]]:
        return self.tech_counter.most_common(n)

    def top_techs_with_version(self, n: int = 10) -> list[tuple[str, int]]:
        return self.tech_with_version_counter.most_common(n)

    def top_techs_without_version(self, n: int = 20) -> list[tuple[str, int]]:
        rows = []
        for tech, total in self.tech_counter.items():
            with_ver = self.tech_with_version_counter.get(tech, 0)
            without_ver = total - with_ver
            if without_ver > 0:
                rows.append((tech, without_ver))
        rows.sort(key=lambda x: x[1], reverse=True)
        return rows[:n]

    def top_tech_version_pairs(self, n: int = 10) -> list[tuple[tuple[str, str], int]]:
        return self.version_counter.most_common(n)

    def top_url_leaks(self, n: int = 50) -> list[tuple[str, int]]:
        return self.url_version_counter.most_common(n)

    def techs_never_versioned(self) -> list[tuple[str, int]]:
        out = []
        for tech, total in self.tech_counter.most_common():
            if self.tech_with_version_counter.get(tech, 0) == 0:
                out.append((tech, total))
        return out

    def techs_with_multiple_versions(self) -> list[tuple[str, list[str]]]:
        out = []
        for tech, versions in self.tech_versions.items():
            uniq = sorted(set(versions))
            if len(uniq) > 1:
                out.append((tech, uniq))
        out.sort(key=lambda x: x[0])
        return out

    def tech_url_samples(self, sample: int = 3) -> list[tuple[str, list[str]]]:
        out = []
        for tech, urls in self.tech_url_map.items():
            out.append((tech, list(urls)[:sample]))
        return out


def analyze_file(path: str | Path) -> AnalysisResult:
    result = AnalysisResult()
    # iter_records skips bad lines silently, so count them in a separate pass-equivalent
    # by re-reading; cheaper: track inline.
    with open_safe(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                result.bad_lines += 1
                continue
            _ingest(result, data)
    return result


def analyze_records(records: Iterable[dict]) -> AnalysisResult:
    """Analyze an in-memory iterable of records (e.g. fresh scan output)."""
    result = AnalysisResult()
    for data in records:
        _ingest(result, data)
    return result


def _ingest(result: AnalysisResult, data: dict) -> None:
    result.total_targets += 1
    target = data.get("target")
    if target:
        result.targets.append(target)
    techs: list[dict[str, Any]] = data.get("techs", []) or []
    result.total_techs += len(techs)
    for tech in techs:
        name = tech.get("name")
        if not name:
            continue
        name = name.lower()
        version = tech.get("version")
        evidence = tech.get("evidence", []) or []

        result.tech_counter[name] += 1
        if version:
            result.tech_with_version_counter[name] += 1
            result.version_counter[(name, version)] += 1
            result.tech_versions[name].append(version)
            for ev in evidence:
                url = ev.get("url")
                if url:
                    result.url_version_counter[url] += 1
                    result.tech_url_map[name].add(url)
