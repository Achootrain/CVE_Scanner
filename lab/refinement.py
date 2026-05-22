"""Closed-loop refinement (CLAUDE.md §12 extension, 2026-05-21).

End-to-end pipeline:

  PRESCAN       run fp.cli scan (current lab.db rules) over target list,
                write UTF-8 prescan.jsonl
  EXPOSURE      parse prescan -> per-target asset URLs where the tech was
                flagged (by any source); fetch body bytes; save as
                content-hashed snapshots
  SPLIT         per-target deterministic 30/70 split -> exposure_dev.jsonl
                + exposure_test.jsonl (test gated by LAB_ALLOW_TEST=1)
  REFINE LOOP   for each dev exposure body the current rule misses:
                  - bundle as CounterExample, hand to refiner agent
                  - structural guardrails enforce monotonic coverage
                  - judge PASS required
                  - auto-import (UPDATE rules_src.json row) + git commit
                  - iteration budget = 5 per rule
  TEST EVAL     one-shot eval on exposure_test (LAB_ALLOW_TEST=1 set
                only here; loop never reads test)

Each auto-import is a git commit so a regression is `git revert <sha>`.
The architecture replaces §12's human gate with structural gates:
judge PASS, monotonic coverage, pattern history, iteration budget.

Bodies are saved as snapshots BEFORE the refiner sees them (§10 earned
citations: content_hash is computable from disk).
"""
from __future__ import annotations

import hashlib
import json
import os
import random
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, asdict, field
from pathlib import Path
from urllib.parse import urlsplit


REPO = Path(__file__).resolve().parent.parent
RESEARCH = REPO / "lab" / "research"

# Per-target split ratio (CLAUDE.md project convention, 30% dev / 70% test).
DEV_RATIO = 0.30
MAX_REFINE_ITERATIONS = 5
FETCH_TIMEOUT = 30
FETCH_USER_AGENT = "Mozilla/5.0 (compatible; fp-lab-refiner/0.1; +https://github.com/Achootrain/fp)"


# ---------------------------------------------------------------------------
# Exposure types
# ---------------------------------------------------------------------------

@dataclass
class Exposure:
    """One (target, asset_url) pair where a tech was detected."""
    target: str
    asset_url: str
    tech_name: str       # canonical name as scanner emits it
    tech_slug: str       # slug used for lab.db (e.g. 'owl-carousel')
    detected_by: list[str]   # ['wappalyzer', 'banner', ...]
    prescan_version: str | None    # what the rule yielded BEFORE refinement

    # Filled in after fetch_and_snapshot_bodies()
    body_path: str | None = None        # path to local snapshot (rel to REPO)
    body_content_hash: str | None = None
    body_status: int | None = None      # HTTP status code, or None if not fetched

    def to_dict(self) -> dict:
        return asdict(self)


def _parse_scan_results(path: Path) -> list[dict]:
    """Read either UTF-8 or UTF-16-LE-BOM JSONL transparently."""
    raw = path.read_bytes()
    if raw[:2] == b"\xff\xfe":
        text = raw.decode("utf-16")
    else:
        text = raw.decode("utf-8", errors="replace")
    out: list[dict] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return out


def extract_exposures(scan_results_path: Path, tech_slug: str,
                      tech_name_filter: str | None = None) -> list[Exposure]:
    """Parse prescan output and yield (target, asset_url) exposures for
    one tech.

    Match a record's `techs[]` entry to the requested tech_slug. tech_name
    matching is fuzzy (substring after lowercase/dehyphen) -- scanner
    emits 'OWL Carousel' vs 'Owl Carousel' depending on the source.
    Pulls every evidence URL (including wappalyzer-only) so refinement
    sees the URLs the existing rule may have missed.
    """
    needle = (tech_name_filter or tech_slug).lower().replace("-", "").replace("_", "")
    out: list[Exposure] = []
    seen: set[tuple[str, str]] = set()
    for rec in _parse_scan_results(scan_results_path):
        target = rec.get("target") or rec.get("url") or ""
        for t in (rec.get("techs") or []):
            tname = t.get("name") or ""
            if needle not in tname.lower().replace(" ", "").replace("-", ""):
                continue
            version = t.get("version")
            sources_top = list(t.get("sources") or [])
            for ev in (t.get("evidence") or []):
                url = ev.get("url")
                if not url or not url.startswith("http"):
                    continue
                key = (target, url)
                if key in seen:
                    continue
                seen.add(key)
                out.append(Exposure(
                    target=target,
                    asset_url=url,
                    tech_name=tname,
                    tech_slug=tech_slug,
                    detected_by=sources_top or [ev.get("source") or "?"],
                    prescan_version=version,
                ))
    return out


# ---------------------------------------------------------------------------
# Fetch + snapshot
# ---------------------------------------------------------------------------

def _snapshot_dir_for(tech_slug: str) -> Path:
    return RESEARCH / tech_slug / "out" / "exposure_snapshots"


def fetch_and_snapshot_bodies(exposures: list[Exposure],
                              *, max_bytes: int = 512_000,
                              verbose: bool = False) -> list[Exposure]:
    """For each Exposure, fetch the asset_url and save body to disk.

    Bodies are written under
    ``lab/research/<tech>/out/exposure_snapshots/<sha8>.bin`` and the
    Exposure dataclass is mutated in place with body_path + content_hash.
    Fetches that 404/timeout are kept with body_status set so the
    refinement loop can classify them as Cause B (plumbing) rather than
    as a regex-failure.
    """
    out: list[Exposure] = []
    for ex in exposures:
        snap_dir = _snapshot_dir_for(ex.tech_slug)
        snap_dir.mkdir(parents=True, exist_ok=True)
        req = urllib.request.Request(
            ex.asset_url, headers={"User-Agent": FETCH_USER_AGENT})
        try:
            with urllib.request.urlopen(req, timeout=FETCH_TIMEOUT) as resp:
                ex.body_status = resp.status
                body = resp.read(max_bytes)
            sha = hashlib.sha256(body).hexdigest()
            fname = snap_dir / f"{sha[:16]}.bin"
            if not fname.exists():
                fname.write_bytes(body)
            ex.body_path = str(fname.relative_to(REPO)).replace("\\", "/")
            ex.body_content_hash = sha
        except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError,
                ConnectionError) as e:
            ex.body_status = getattr(e, "code", None) if hasattr(e, "code") else None
            if verbose:
                print(f"  fetch failed {ex.asset_url}: {e}", file=sys.stderr)
        out.append(ex)
    return out


# ---------------------------------------------------------------------------
# Persistent split
# ---------------------------------------------------------------------------

def _deterministic_target_bucket(target: str, seed: str) -> float:
    """Stable [0,1) value per target. Deterministic across runs so the
    test set never bleeds into dev as the corpus grows."""
    h = hashlib.sha256(f"{seed}::{target}".encode("utf-8")).hexdigest()
    # Take first 8 hex chars -> int -> normalise to [0,1)
    return int(h[:8], 16) / 0xFFFF_FFFF


def split_per_target(exposures: list[Exposure], *,
                     dev_ratio: float = DEV_RATIO,
                     seed: str = "lab-refinement-v1") -> tuple[list[Exposure], list[Exposure]]:
    """Per-target 30/70 split. All exposures for a given target go to
    the same side -- this matches the project's existing dev/test
    convention and prevents leakage."""
    dev: list[Exposure] = []
    test: list[Exposure] = []
    for ex in exposures:
        bucket = _deterministic_target_bucket(ex.target, seed)
        (dev if bucket < dev_ratio else test).append(ex)
    return dev, test


def write_exposure_files(tech_slug: str, dev: list[Exposure],
                         test: list[Exposure]) -> dict:
    """Write exposure_dev.jsonl + exposure_test.jsonl (UTF-8)."""
    base = RESEARCH / tech_slug
    base.mkdir(parents=True, exist_ok=True)
    dev_path = base / "exposure_dev.jsonl"
    test_path = base / "exposure_test.jsonl"
    with dev_path.open("w", encoding="utf-8") as f:
        for ex in dev:
            f.write(json.dumps(ex.to_dict(), ensure_ascii=False) + "\n")
    with test_path.open("w", encoding="utf-8") as f:
        for ex in test:
            f.write(json.dumps(ex.to_dict(), ensure_ascii=False) + "\n")
    return {
        "dev_path": str(dev_path),
        "test_path": str(test_path),
        "dev_count": len(dev),
        "test_count": len(test),
        "dev_targets": len({e.target for e in dev}),
        "test_targets": len({e.target for e in test}),
    }


# ---------------------------------------------------------------------------
# Coverage check
# ---------------------------------------------------------------------------

@dataclass
class Coverage:
    """Pattern-vs-bodies report."""
    pattern: str
    total: int                # how many exposures had a body we could fetch
    hits: list[Exposure]      # regex matched
    misses: list[Exposure]    # regex did not match
    skipped: list[Exposure]   # no body (fetch failure -- Cause B / plumbing)

    @property
    def pct(self) -> float:
        return 0.0 if self.total == 0 else 100.0 * len(self.hits) / self.total


def apply_rule(pattern: str, exposures: list[Exposure]) -> Coverage:
    """Compile pattern, run against each Exposure's cached body."""
    try:
        cre = re.compile(pattern)
    except re.error as e:
        raise ValueError(f"pattern does not compile: {e}") from e
    hits: list[Exposure] = []
    misses: list[Exposure] = []
    skipped: list[Exposure] = []
    for ex in exposures:
        if not ex.body_path:
            skipped.append(ex)
            continue
        body_path = REPO / ex.body_path
        try:
            body = body_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            skipped.append(ex)
            continue
        if cre.search(body):
            hits.append(ex)
        else:
            misses.append(ex)
    return Coverage(
        pattern=pattern,
        total=len(hits) + len(misses),
        hits=hits, misses=misses, skipped=skipped,
    )


# ---------------------------------------------------------------------------
# Refine loop
# ---------------------------------------------------------------------------

def _load_body_span(exposure: Exposure, *, head_chars: int = 1500) -> tuple[str, str]:
    """Load body head + return (text, content_hash_of_text)."""
    body = (REPO / exposure.body_path).read_text(
        encoding="utf-8", errors="replace")[:head_chars]
    return body, hashlib.sha256(body.encode("utf-8")).hexdigest()


def _rule_original_texts(rule: dict) -> list[str]:
    """Re-load the text of each citation referenced by rule.source.
    Needed for the refiner's G1 monotonic-coverage check."""
    out: list[str] = []
    for c in (rule.get("source") or {}).get("citations") or []:
        fp = (c.get("file_path") or "").replace("\\", "/")
        if not fp:
            continue
        ls, le = int(c.get("line_start", 1)), int(c.get("line_end", 1))
        path = REPO / fp
        if not path.exists():
            continue
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        if ls < 1 or le > len(lines) or ls > le:
            continue
        out.append("\n".join(lines[ls - 1:le]))
    return out


def _git_commit(message: str, *, files: list[str]) -> str | None:
    """Stage + commit. Returns the new SHA, or None on failure."""
    try:
        subprocess.run(["git", "add"] + files, cwd=REPO, check=True,
                       capture_output=True)
        # If nothing actually changed, git commit will return 1 -- swallow.
        r = subprocess.run(
            ["git", "commit", "-m", message],
            cwd=REPO, capture_output=True, text=True)
        if r.returncode != 0:
            return None
        sha = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=REPO, check=True, capture_output=True, text=True).stdout.strip()
        return sha
    except (subprocess.CalledProcessError, FileNotFoundError):
        return None


def _save_rules_src(tech_slug: str, rule: dict) -> Path:
    """Write the updated rule back to rules_src.json (single-rule shape
    used by import-rules)."""
    section = rule.get("section") or "banner_rules"
    # Strip drafter/judge meta but keep pattern_history for audit
    clean = {k: v for k, v in rule.items() if not k.startswith("_")}
    clean.pop("section", None)
    pattern_history = (rule.get("_drafter_meta") or {}).get("pattern_history")
    if pattern_history:
        clean["_history"] = {"pattern_history": pattern_history}
    out = {section: [clean]}
    path = RESEARCH / tech_slug / "rules_src.json"
    path.write_text(json.dumps(out, indent=2, ensure_ascii=False), encoding="utf-8")
    return path


def _import_to_lab_db(tech_slug: str, rules_src_path: Path) -> None:
    """Idempotent import via the existing CLI."""
    subprocess.run(
        [sys.executable, "-m", "lab.research_cycle",
         "import-rules", tech_slug, "--rules-json", str(rules_src_path)],
        cwd=REPO, check=True, capture_output=True, text=True)


@dataclass
class RefineReport:
    iterations: list[dict] = field(default_factory=list)
    final_pattern: str = ""
    initial_coverage: float = 0.0
    final_coverage: float = 0.0
    aborts: list[str] = field(default_factory=list)
    commits: list[str] = field(default_factory=list)


def refinement_loop(tech_slug: str, rule: dict,
                    dev_exposures: list[Exposure],
                    *,
                    client,
                    max_iterations: int = MAX_REFINE_ITERATIONS,
                    verbose: bool = False,
                    log=print) -> tuple[dict, RefineReport]:
    """Run the closed loop: apply rule -> collect misses -> refine ->
    structural-validate (monotonic + counter-match) -> auto-import +
    git commit -> repeat.

    Returns (final_rule, report).
    """
    from lab.rag.refiner import refine_rule, CounterExample

    report = RefineReport(final_pattern=rule.get("pattern", ""))
    original_texts = _rule_original_texts(rule)
    if not original_texts:
        log("  refinement_loop: no original cited spans loadable; "
            "monotonic guardrail will be vacuous.")

    pattern_history: list[dict] = list(
        (rule.get("_drafter_meta") or {}).get("pattern_history") or [])

    current = dict(rule)
    cov0 = apply_rule(current["pattern"], dev_exposures)
    report.initial_coverage = cov0.pct
    log(f"  [iter 0] coverage={cov0.pct:.1f}% "
        f"(hits={len(cov0.hits)}, misses={len(cov0.misses)}, "
        f"unfetched={len(cov0.skipped)})")

    for it in range(1, max_iterations + 1):
        cov = apply_rule(current["pattern"], dev_exposures)
        if not cov.misses:
            log(f"  [iter {it}] no misses; stopping (coverage={cov.pct:.1f}%)")
            break

        # Bundle every miss head as a CounterExample (head only, to keep
        # the LLM prompt sane).
        counters: list[CounterExample] = []
        for ex in cov.misses[:8]:   # cap counters per iteration
            text, sha = _load_body_span(ex)
            counters.append(CounterExample(
                file_path=ex.body_path,
                line_start=1, line_end=text.count("\n") + 1,
                content_hash=sha, text=text,
            ))

        log(f"  [iter {it}] {len(cov.misses)} misses; refining with "
            f"{len(counters)} counter-examples ...")

        refined = refine_rule(
            client, current, original_texts, counters,
            pattern_history=pattern_history, verbose=verbose,
        )
        if "_aborted" in refined:
            log(f"  [iter {it}] refiner aborted: {refined['_aborted']}")
            report.aborts.append(refined["_aborted"])
            break

        new_pattern = refined["pattern"]
        # Pattern history accumulates across the whole loop, not just this
        # turn. Anything the refiner saw + anything it tried.
        pattern_history.append({"pattern": new_pattern,
                                "iteration": it, "accepted": True})
        refined["_drafter_meta"]["pattern_history"] = pattern_history

        # Hard structural check on the FINAL widening across the FULL dev
        # set (refiner only saw a head-slice of each counter). This is
        # the monotonic-coverage floor that backs the auto-import.
        cov_new = apply_rule(new_pattern, dev_exposures)
        if len(cov_new.hits) < len(cov.hits):
            log(f"  [iter {it}] REGRESSION: new pattern hits "
                f"{len(cov_new.hits)} < {len(cov.hits)}; rejecting")
            report.aborts.append(
                f"iter {it} regression "
                f"(hits {len(cov.hits)} -> {len(cov_new.hits)})")
            break

        # Persist + import + git commit
        current = refined
        report.final_pattern = new_pattern
        rules_path = _save_rules_src(tech_slug, current)
        try:
            _import_to_lab_db(tech_slug, rules_path)
        except subprocess.CalledProcessError as e:
            log(f"  [iter {it}] import failed: "
                f"{(e.stderr or '')[:200]}")
            report.aborts.append(f"iter {it} import error")
            break

        sha = _git_commit(
            f"refine({tech_slug}): widen pattern iter {it} "
            f"(coverage {cov.pct:.1f}% -> {cov_new.pct:.1f}%)",
            files=[str(rules_path.relative_to(REPO)).replace("\\", "/")],
        )
        if sha:
            report.commits.append(sha)
            log(f"  [iter {it}] coverage {cov.pct:.1f}% -> "
                f"{cov_new.pct:.1f}%, committed {sha[:8]}")
        else:
            log(f"  [iter {it}] coverage {cov.pct:.1f}% -> "
                f"{cov_new.pct:.1f}%, (no git commit)")

        report.iterations.append({
            "iter": it,
            "pattern": new_pattern,
            "coverage_before": cov.pct,
            "coverage_after": cov_new.pct,
            "hits_before": len(cov.hits),
            "hits_after": len(cov_new.hits),
            "miss_count_before": len(cov.misses),
        })

    final_cov = apply_rule(current["pattern"], dev_exposures)
    report.final_coverage = final_cov.pct
    return current, report


# ---------------------------------------------------------------------------
# Test-set eval (one shot, gated)
# ---------------------------------------------------------------------------

def evaluate_on_test(rule_pattern: str, test_exposures: list[Exposure]) -> Coverage:
    """One-shot eval on held-out test set. LAB_ALLOW_TEST=1 must be set
    in the env before this is called (the caller is responsible)."""
    if os.environ.get("LAB_ALLOW_TEST") != "1":
        raise RuntimeError(
            "test-set eval requires LAB_ALLOW_TEST=1 in env (caller did "
            "not set it). The refinement loop never reads test data; "
            "only the final evaluator does, exactly once.")
    return apply_rule(rule_pattern, test_exposures)
