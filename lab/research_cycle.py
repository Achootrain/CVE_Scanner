"""Full lab research cycle for a single tech.

Subcommands:
  start <tech-slug> [--match-pattern REGEX]
      Filter data/scan_results_{dev,test}.jsonl to records that detected the
      tech. Write tech-specific dev/test JSONLs into lab/research/<slug>/.
      Scaffold a research directory with a template README.

  import-rules <tech-slug> --rules-json <path>
      Import a rules_src.json into lab.db's lab_src_rules table for this
      tech_slug. Idempotent.

  status <tech-slug>
      Show dataset sizes, rules count in DB, last import date.

Dev/test boundary:
  The global split lives in data/scan_results_{dev,test}.jsonl. Per-tech
  datasets are SUBSETS of each side; sites in test stay in test. This
  preserves blind-test discipline across tech research.

Why a single tool:
  Every new tech research follows the same loop -- filter corpus, research,
  author rules from source, import. Codifying it in one CLI keeps the
  pattern consistent and prevents accidental re-splits that would leak the
  test set.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sqlite3
import subprocess
import sys
from pathlib import Path
from urllib.parse import urlparse


REPO = Path(__file__).resolve().parent.parent
DATA = REPO / "data"
RESEARCH = REPO / "lab" / "research"
DEFAULT_DB = REPO / "fingerprinter" / "lab.db"

DEV_JSONL = DATA / "scan_results_dev.jsonl"
TEST_JSONL = DATA / "scan_results_test.jsonl"

# Make the lab package importable when invoked via ``python lab/research_cycle.py``
# (the repo root needs to be on sys.path; pytest / -m invocations already have it).
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from lab.core import read_jsonl, import_rules as _import_rules  # noqa: E402


# ---------------------------------------------------------------------------
# Filter
# ---------------------------------------------------------------------------


def _tech_matcher(slug: str, pattern: str | None) -> "re.Pattern[str]":
    """Build the regex used to test tech names against. Default = slug as substring."""
    if pattern:
        return re.compile(pattern, re.I)
    # Default: slug parts must all appear (e.g. 'font-awesome' -> needs 'font' AND 'awesome')
    parts = [re.escape(p) for p in re.split(r"[-_/]", slug) if p]
    if len(parts) > 1:
        return re.compile(r".*".join(parts), re.I)
    return re.compile(re.escape(slug), re.I)


def filter_jsonl(src: Path, dst: Path, matcher: "re.Pattern[str]") -> dict:
    """Write to dst every record from src whose techs[].name matches the regex."""
    n_in = n_kept = 0
    seen_targets: set[str] = set()
    dst.parent.mkdir(parents=True, exist_ok=True)
    with dst.open("w", encoding="utf-8") as out:
        for rec in read_jsonl(src):
            n_in += 1
            techs = rec.get("techs") or []
            if not any(matcher.search(t.get("name") or "") for t in techs):
                continue
            target = rec.get("target") or rec.get("url") or ""
            # Dedup by apex host so multiple scans of the same site don't double-count
            host = urlparse(target if "://" in target else f"https://{target}").netloc
            if host in seen_targets:
                continue
            seen_targets.add(host)
            out.write(json.dumps(rec, ensure_ascii=False) + "\n")
            n_kept += 1
    return {"input_records": n_in, "kept": n_kept, "unique_hosts": len(seen_targets)}


def cmd_start(args: argparse.Namespace) -> int:
    slug = args.tech_slug
    target_dir = RESEARCH / slug
    target_dir.mkdir(parents=True, exist_ok=True)

    matcher = _tech_matcher(slug, args.match_pattern)
    print(f"matcher regex: {matcher.pattern}", file=sys.stderr)

    dev_out = target_dir / "dataset_dev.jsonl"
    test_out = target_dir / "dataset_test.jsonl"

    if not args.force and (dev_out.exists() or test_out.exists()):
        print(f"refusing to overwrite existing datasets at {target_dir} (use --force)", file=sys.stderr)
        return 1

    dev_stats = filter_jsonl(DEV_JSONL, dev_out, matcher)

    # Filter test set: requires LAB_ALLOW_TEST=1 (enforced by backtest.read_jsonl)
    # Set it transiently here so the user doesn't have to set it manually;
    # the env var elsewhere still gates blind eval scripts that need stronger
    # discipline. This is the explicit "I am setting up a research dataset" flow.
    os.environ["LAB_ALLOW_TEST"] = "1"
    try:
        test_stats = filter_jsonl(TEST_JSONL, test_out, matcher)
    finally:
        os.environ.pop("LAB_ALLOW_TEST", None)

    # Write a README scaffold
    readme = target_dir / "README.md"
    if not readme.exists():
        readme.write_text(
            f"# {slug} — lab research\n\n"
            f"Datasets filtered from the global dev/test corpus:\n\n"
            f"- `dataset_dev.jsonl`: {dev_stats['kept']} records, {dev_stats['unique_hosts']} unique hosts (from {dev_stats['input_records']} dev records)\n"
            f"- `dataset_test.jsonl`: {test_stats['kept']} records, {test_stats['unique_hosts']} unique hosts (from {test_stats['input_records']} test records)\n\n"
            f"Test-set discipline: dataset_test.jsonl is held out for FINAL eval only. Do not\n"
            f"mine rules from it. Set `LAB_ALLOW_TEST=1` when reading it.\n\n"
            f"## Workflow\n\n"
            f"1. Acquire the tech's release artifacts (multiple major versions if breaking changes exist).\n"
            f"2. Catalog version-bearing signals: banner format, canonical filenames, webfonts, class\n"
            f"   prefixes, package metadata. Cite each signal back to a specific release file.\n"
            f"3. Author `rules_src.json` -- every rule carries a `source` field pointing at the\n"
            f"   release file or documented downstream convention it was derived from.\n"
            f"4. Validate against `dataset_dev.jsonl`. The corpus is for VALIDATION, never for\n"
            f"   rule discovery (per CLAUDE.md section 6).\n"
            f"5. Import rules to lab.db:\n"
            f"   ```bash\n"
            f"   python -m lab.research_cycle import-rules {slug} --rules-json lab/research/{slug}/rules_src.json\n"
            f"   ```\n"
            f"6. Final eval on `dataset_test.jsonl` (single run, `LAB_ALLOW_TEST=1`).\n",
            encoding="utf-8",
        )

    print(f"\nstarted research for tech_slug='{slug}'")
    print(f"  dir: {target_dir}")
    print(f"  dev:  {dev_stats}")
    print(f"  test: {test_stats}")
    return 0


# ---------------------------------------------------------------------------
# Import rules
# ---------------------------------------------------------------------------


def cmd_import_rules(args: argparse.Namespace) -> int:
    res = _import_rules(Path(args.db), Path(args.rules_json), args.tech_slug)
    print(
        f"imported {res['inserted']} rules for tech_slug='{res['tech_slug']}' "
        f"into {res['db']}  (+{res['propagated_to_scanner']} url_version rows -> lab_url_patterns)"
    )
    return 0


# ---------------------------------------------------------------------------
# Source acquisition
# ---------------------------------------------------------------------------


def cmd_acquire_source(args: argparse.Namespace) -> int:
    from lab.core.source import acquire
    dst = acquire(args.tech_slug, args.repo, args.ref, force=args.force)
    print(f"cloned {args.repo}@{args.ref} -> {dst}")
    return 0


# ---------------------------------------------------------------------------
# Index build
# ---------------------------------------------------------------------------


def cmd_build_index(args: argparse.Namespace) -> int:
    from lab.rag.index_builder import build_index
    stats = build_index(Path(args.index_db) if args.index_db else None, lab_db=Path(args.db))
    print(
        f"index built: {stats['chunks']} chunks "
        f"(source={stats['source']}, research={stats['research']}, "
        f"policy={stats['policy']}, rules={stats['rules']}) -> {stats['index_db']}"
    )
    return 0


# ---------------------------------------------------------------------------
# Draft rule via Gemini + RAG
# ---------------------------------------------------------------------------


def cmd_draft_rule(args: argparse.Namespace) -> int:
    from lab.rag.rule_drafter import (
        draft_rule as _draft_rule,
        build_task_from_candidate,
    )
    from lab.rag.llm import GeminiClient

    if args.from_candidates:
        cand_path = Path(args.from_candidates)
        if not cand_path.exists():
            print(f"candidates file not found: {cand_path}", file=sys.stderr)
            return 2
        data = json.loads(cand_path.read_text(encoding="utf-8"))
        candidates = data.get("candidates") or []
    elif args.task:
        candidates = [{"_inline_task": args.task}]
    else:
        print("supply --task or --from-candidates", file=sys.stderr)
        return 2

    out_path = (Path(args.out) if args.out
                else (RESEARCH / args.tech_slug / "rules_src_drafted.json"))
    out_path.parent.mkdir(parents=True, exist_ok=True)

    client = GeminiClient(model=args.model) if args.model else GeminiClient()
    existing = {"rules": []}
    if out_path.exists():
        try:
            existing = json.loads(out_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            pass
    existing.setdefault("rules", [])

    ok = aborted = 0
    for cand in candidates:
        task = cand.get("_inline_task") or build_task_from_candidate(cand)
        if args.verbose:
            print(f"\n=== drafting {cand.get('candidate_id', '(inline)')} ===",
                  file=sys.stderr)
        rule = _draft_rule(client, args.tech_slug, task, verbose=args.verbose)
        if "_aborted" in rule:
            aborted += 1
        else:
            ok += 1
        if "candidate_id" in cand:
            rule.setdefault("_drafter_meta", {})["candidate_id"] = cand["candidate_id"]
        existing["rules"].append(rule)

    out_path.write_text(
        json.dumps(existing, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"\ndrafted: {ok} ok, {aborted} aborted -> {out_path}")
    return 0 if aborted == 0 else 1


# ---------------------------------------------------------------------------
# Discover (deterministic candidate-signal pre-pass)
# ---------------------------------------------------------------------------


def cmd_discover(args: argparse.Namespace) -> int:
    from lab.core.discover import discover as _discover
    tech_dir = RESEARCH / args.tech_slug
    result = _discover(args.tech_slug)
    out_path = Path(args.out) if args.out else (tech_dir / "candidates.json")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(
        json.dumps(result, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    by_kind: dict[str, int] = {}
    for c in result["candidates"]:
        by_kind[c["kind"]] = by_kind.get(c["kind"], 0) + 1
    print(f"tech_slug: {args.tech_slug}")
    print(f"  refs scanned: {len(result['refs'])} ({', '.join(result['refs']) or '-'})")
    print(f"  candidates:   {len(result['candidates'])}")
    for kind in sorted(by_kind):
        print(f"    {kind}: {by_kind[kind]}")
    print(f"  written to {out_path}")
    return 0


# ---------------------------------------------------------------------------
# Judge drafted rules via Claude Sonnet
# ---------------------------------------------------------------------------


def cmd_judge_rule(args: argparse.Namespace) -> int:
    from lab.rag.judge import main as judge_main
    judge_argv = [args.tech_slug]
    if args.in_path:
        judge_argv += ["--in", args.in_path]
    if args.out:
        judge_argv += ["--out", args.out]
    if args.model:
        judge_argv += ["--model", args.model]
    return judge_main(judge_argv)


# ---------------------------------------------------------------------------
# run-all: chain acquire -> index -> discover -> draft -> judge
# ---------------------------------------------------------------------------


def _hms() -> str:
    import time as _t
    return _t.strftime("%H:%M:%S")


def _select_smoke_candidate(candidates: list[dict], tech: str) -> dict | None:
    """Pick the most canonical banner candidate for a smoke run.

    Heuristic (CLAUDE.md §7 spirit: signal over samples): prefer banner
    candidates in /dist/ or /src/ paths whose file name contains the
    tech slug. Falls back to the first banner candidate if no canonical
    one is found, then to first candidate of any kind.
    """
    slug_compact = tech.replace("-", "").replace("_", "").replace(".", "")
    junk_dirs = ("/docs/", "/test/", "/tests/", "/spec/", "/vendor/",
                 "/node_modules/", "/examples/", "/example/")

    def _is_canonical(c: dict) -> bool:
        fp = (c.get("evidence") or {}).get("file_path") or ""
        if c.get("kind") != "banner":
            return False
        if any(d in fp for d in junk_dirs):
            return False
        fn_low = fp.lower()
        return tech.lower() in fn_low or slug_compact in fn_low

    for c in candidates:
        if _is_canonical(c):
            return c
    for c in candidates:
        if c.get("kind") == "banner":
            return c
    return candidates[0] if candidates else None


def cmd_run_all(args: argparse.Namespace) -> int:
    """Chain the full §12 sandwich in one command.

    Stages (each is idempotent; existing outputs are reused unless --force):
      1. acquire-source     git clone (skipped if out/source/<ref>/ exists)
      2. build-index        always; cheap and ensures the RAG sees the new src
      3. discover           emits candidates.json
      4. draft-rule         Gemini Flash (drafter loop); writes rules_src_drafted.json
      5. judge-rule         Claude Sonnet review; writes rules_src_judged.json

    Stops BEFORE import-rules -- that step is the human-review gate per §12.
    """
    import time as _time

    tech = args.tech_slug
    tech_dir = RESEARCH / tech
    tech_dir.mkdir(parents=True, exist_ok=True)
    pipeline_start = _time.time()

    def _log(step: str, name: str, msg: str) -> None:
        print(f"[{_hms()}] [{step}] {name}: {msg}", flush=True)

    # ----- 1. acquire-source ----------------------------------------------
    src_dir = tech_dir / "out" / "source" / args.ref
    step_start = _time.time()
    if src_dir.exists() and not args.force:
        _log("1/5", "acquire-source", f"reusing {src_dir} (skipped)")
    else:
        if not args.repo:
            _log("1/5", "acquire-source",
                 "FAIL: --repo required when source not yet cloned")
            return 2
        from lab.core.source import acquire
        dst = acquire(tech, args.repo, args.ref, force=args.force)
        _log("1/5", "acquire-source",
             f"{args.repo}@{args.ref} -> {dst} ({_time.time()-step_start:.1f}s)")

    # ----- 2. build-index -------------------------------------------------
    step_start = _time.time()
    from lab.rag.index_builder import build_index
    stats = build_index(None, lab_db=Path(args.db))
    _log("2/5", "build-index",
         f"{stats['chunks']} chunks (source={stats['source']}, "
         f"research={stats['research']}, rules={stats['rules']}) "
         f"({_time.time()-step_start:.1f}s)")

    # ----- 3. discover ----------------------------------------------------
    step_start = _time.time()
    candidates_path = tech_dir / "candidates.json"
    if candidates_path.exists() and not args.force:
        data = json.loads(candidates_path.read_text(encoding="utf-8"))
        _log("3/5", "discover",
             f"reusing {candidates_path.name} "
             f"({len(data['candidates'])} candidates, skipped)")
    else:
        from lab.core.discover import discover as _discover
        data = _discover(tech)
        candidates_path.write_text(
            json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
        by_kind: dict[str, int] = {}
        for c in data["candidates"]:
            by_kind[c["kind"]] = by_kind.get(c["kind"], 0) + 1
        kinds_str = ", ".join(f"{k}={v}" for k, v in sorted(by_kind.items()))
        _log("3/5", "discover",
             f"{len(data['candidates'])} candidates ({kinds_str}) "
             f"({_time.time()-step_start:.1f}s)")

    # Select candidates to feed the drafter
    if args.candidates == "all":
        chosen_candidates = data["candidates"]
        _log("->", "candidate selection",
             f"drafting ALL {len(chosen_candidates)} candidates")
    elif args.candidates == "smoke":
        c = _select_smoke_candidate(data["candidates"], tech)
        if c is None:
            _log("!", "candidate selection", "no candidates found; abort")
            return 1
        chosen_candidates = [c]
        _log("->", "candidate selection",
             f"smoke ({c['kind']}): {c['candidate_id'][:80]}")
    else:
        cand_path = Path(args.candidates)
        if not cand_path.exists():
            _log("!", "candidate selection",
                 f"file not found: {cand_path}")
            return 2
        chosen_candidates = json.loads(
            cand_path.read_text(encoding="utf-8")).get("candidates") or []
        _log("->", "candidate selection",
             f"from {cand_path.name}: {len(chosen_candidates)} candidate(s)")

    # ----- 4. draft-rule --------------------------------------------------
    step_start = _time.time()
    drafted_path = tech_dir / "rules_src_drafted.json"
    if drafted_path.exists() and not args.force:
        existing = json.loads(drafted_path.read_text(encoding="utf-8"))
        n = len(existing.get("rules") or [])
        _log("4/5", "draft-rule",
             f"reusing {drafted_path.name} ({n} rules, skipped)")
    else:
        from lab.rag.rule_drafter import (
            draft_rule as _draft_rule,
            build_task_from_candidate,
        )
        from lab.rag.llm import GeminiClient
        client = (GeminiClient(model=args.gemini_model)
                  if args.gemini_model else GeminiClient())
        drafts: list[dict] = []
        ok_n = abort_n = 0
        for i, cand in enumerate(chosen_candidates, 1):
            print(f"  [{i}/{len(chosen_candidates)}] "
                  f"drafting {cand.get('candidate_id', '(inline)')[:80]}",
                  flush=True)
            task = build_task_from_candidate(cand)
            rule = _draft_rule(client, tech, task, verbose=args.verbose)
            if "candidate_id" in cand:
                rule.setdefault("_drafter_meta", {})["candidate_id"] = cand["candidate_id"]
            if "_aborted" in rule:
                abort_n += 1
                print(f"    ABORTED: {rule.get('_aborted')}", flush=True)
            else:
                ok_n += 1
                print(f"    ok: id={rule.get('id','?')} "
                      f"turns={(rule.get('_drafter_meta') or {}).get('turns_used','?')}",
                      flush=True)
            drafts.append(rule)
        drafted_path.write_text(
            json.dumps({"rules": drafts}, indent=2, ensure_ascii=False),
            encoding="utf-8")
        _log("4/5", "draft-rule",
             f"{ok_n} ok, {abort_n} aborted via {client.model} "
             f"({_time.time()-step_start:.1f}s)")
        if ok_n == 0:
            _log("!", "draft-rule", "no successful drafts; stopping before judge")
            return 1

    # ----- 5. judge-rule --------------------------------------------------
    step_start = _time.time()
    judged_path = tech_dir / "rules_src_judged.json"
    if judged_path.exists() and not args.force:
        _log("5/5", "judge-rule",
             f"reusing {judged_path.name} (skipped)")
    else:
        from lab.rag.judge import judge_rule, _build_judge_client
        # Provider per lab/rag/config.json. --anthropic-model overrides
        # the model name but does NOT force the provider; switch
        # 'judge.provider' in config.json to flip providers.
        client_j = _build_judge_client(model_override=args.anthropic_model)
        rules = json.loads(drafted_path.read_text(encoding="utf-8")).get("rules") or []
        judged: list[dict] = []
        pass_n = flag_n = skip_n = 0
        for i, rule in enumerate(rules, 1):
            if "_aborted" in rule or not rule.get("pattern"):
                skip_n += 1
                judged.append(rule)
                continue
            print(f"  [{i}/{len(rules)}] judging {rule.get('id','?')[:60]}",
                  flush=True)
            verdict = judge_rule(rule, tech, client=client_j)
            r = dict(rule)
            r["_judge"] = verdict
            judged.append(r)
            if verdict["verdict"] == "PASS":
                pass_n += 1
            else:
                flag_n += 1
            checks = verdict.get("checks") or {}
            check_str = " ".join(f"{k.split('_')[0]}={v}"
                                 for k, v in checks.items())
            print(f"    {verdict['verdict']}  {check_str}", flush=True)
            for r_ in (verdict.get("reasons") or [])[:3]:
                print(f"      - {r_}", flush=True)
        judged_path.write_text(
            json.dumps({"rules": judged}, indent=2, ensure_ascii=False),
            encoding="utf-8")
        _log("5/5", "judge-rule",
             f"{pass_n} PASS, {flag_n} FLAG, {skip_n} skipped via "
             f"{client_j.model} ({_time.time()-step_start:.1f}s)")

    elapsed = _time.time() - pipeline_start
    print(f"\n[{_hms()}] pipeline complete in {elapsed:.1f}s")
    print(f"  candidates: {candidates_path}")
    print(f"  drafted:    {drafted_path}")
    print(f"  judged:     {judged_path}")
    print(f"\nnext: review rules_src_judged.json; copy approved rules into "
          f"rules_src.json; then:\n"
          f"  python -m lab.research_cycle import-rules {tech} "
          f"--rules-json lab/research/{tech}/rules_src.json")
    return 0


# ---------------------------------------------------------------------------
# run-auto: closed-loop pipeline (prescan -> exposure -> draft -> refine -> test)
# ---------------------------------------------------------------------------


def cmd_run_auto(args: argparse.Namespace) -> int:
    """Fully-automatic closed-loop pipeline.

    Stages:
      1. PRESCAN     fp.cli scan over <targets-file> -> prescan.jsonl (UTF-8)
      2. EXPOSURE    parse + per-target asset URLs + body snapshots
      3. SPLIT       persistent 30/70 dev/test
      4. DRAFT       run-all (acquire/index/discover/draft/judge/auto-import)
      5. REFINE      regex-only refinement loop on dev exposures
                     (judge + monotonic guardrail; up to N iters; git commit
                     per accepted widening)
      6. TEST        one-shot eval on held-out test exposures
                     (LAB_ALLOW_TEST=1 auto-set only here)

    All structural guardrails replace the §12 human gate; see
    lab/refinement.py docstring.
    """
    import time as _time
    from lab.refinement import (
        DEV_RATIO, MAX_REFINE_ITERATIONS,
        extract_exposures, fetch_and_snapshot_bodies,
        split_per_target, write_exposure_files,
        apply_rule, refinement_loop, evaluate_on_test,
    )
    from lab.rag.llm import GeminiClient

    tech = args.tech_slug
    tech_dir = RESEARCH / tech
    tech_dir.mkdir(parents=True, exist_ok=True)
    pipeline_start = _time.time()

    def _log(step: str, msg: str) -> None:
        print(f"[{_hms()}] [{step}] {msg}", flush=True)

    # ------ 1. PRESCAN ---------------------------------------------------
    targets = Path(args.targets)
    if not targets.exists():
        _log("1/6", f"FAIL: targets file not found: {targets}")
        return 2
    prescan_path = tech_dir / "prescan.jsonl"
    if prescan_path.exists() and not args.force_prescan:
        from lab.refinement import _parse_scan_results as _read_scan
        n_prescan = len(_read_scan(prescan_path))
        _log("1/6", f"prescan: reusing {prescan_path.name} "
                    f"({n_prescan} records)")
    else:
        _log("1/6", f"prescan: scanning {targets.name} ...")
        scan_start = _time.time()
        scan_cmd = [
            sys.executable, "-m", "fp.cli", "scan",
            "-i", str(targets),
            "-o", str(prescan_path),
        ]
        if args.scan_concurrency:
            scan_cmd += ["--concurrency", str(args.scan_concurrency)]
        try:
            subprocess.run(scan_cmd, cwd=REPO / "fingerprinter", check=True)
        except subprocess.CalledProcessError as e:
            _log("1/6", f"FAIL: scan returned {e.returncode}")
            return 3
        from lab.refinement import _parse_scan_results as _read_scan
        n_prescan = len(_read_scan(prescan_path))
        _log("1/6", f"prescan: wrote {n_prescan} records "
                    f"({_time.time()-scan_start:.1f}s)")

    # ------ 2. EXPOSURE EXTRACT ------------------------------------------
    exp_start = _time.time()
    raw_exposures = extract_exposures(prescan_path, tech)
    if not raw_exposures:
        _log("2/6", f"FAIL: no {tech} exposures found in prescan")
        return 4
    _log("2/6", f"extracted {len(raw_exposures)} exposures across "
                f"{len({e.target for e in raw_exposures})} targets; "
                f"fetching bodies ...")
    exposures = fetch_and_snapshot_bodies(raw_exposures, verbose=args.verbose)
    fetched = sum(1 for e in exposures if e.body_path)
    _log("2/6", f"fetched {fetched}/{len(exposures)} bodies "
                f"({_time.time()-exp_start:.1f}s); "
                f"{len(exposures)-fetched} unfetchable (cause-B plumbing)")

    # ------ 3. SPLIT -----------------------------------------------------
    dev, test = split_per_target(exposures, dev_ratio=DEV_RATIO,
                                 seed=f"refinement::{tech}")
    info = write_exposure_files(tech, dev, test)
    _log("3/6", f"split: dev={info['dev_count']} exposures "
                f"({info['dev_targets']} targets), test={info['test_count']} "
                f"exposures ({info['test_targets']} targets)")

    # ------ 4. DRAFT (delegate to run-all) -------------------------------
    rules_src = tech_dir / "rules_src.json"
    if rules_src.exists() and not args.force_draft:
        _log("4/6", f"draft: reusing {rules_src.name} (skipped)")
    else:
        _log("4/6", f"draft: chaining run-all ...")
        # We can't easily call cmd_run_all directly here (argparse coupling);
        # spawn it as a subprocess so failures surface cleanly.
        run_all_cmd = [
            sys.executable, "-m", "lab.research_cycle", "run-all", tech,
            "--ref", args.ref,
        ]
        if args.repo:
            run_all_cmd += ["--repo", args.repo]
        if args.verbose:
            run_all_cmd.append("--verbose")
        try:
            subprocess.run(run_all_cmd, cwd=REPO, check=True)
        except subprocess.CalledProcessError as e:
            _log("4/6", f"FAIL: run-all returned {e.returncode}")
            return 5
        # run-all writes rules_src_judged.json -- convert to rules_src.json
        # (single-rule shape) for refinement.
        judged_path = tech_dir / "rules_src_judged.json"
        if not judged_path.exists():
            _log("4/6", "FAIL: rules_src_judged.json not produced")
            return 6
        from lab.refinement import _save_rules_src
        judged = json.loads(judged_path.read_text(encoding="utf-8"))
        for r in judged.get("rules") or []:
            if r.get("_aborted") or not r.get("pattern"):
                continue
            verdict = (r.get("_judge") or {}).get("verdict")
            if verdict != "PASS":
                _log("4/6", f"judge FLAG; not auto-importing "
                            f"id={r.get('id')}: {(r.get('_judge') or {}).get('reasons')}")
                continue
            _save_rules_src(tech, r)
            from lab.refinement import _import_to_lab_db
            _import_to_lab_db(tech, rules_src)
            _log("4/6", f"auto-imported id={r.get('id')} to lab.db")
            break

    # Load the imported rule from rules_src.json so refinement can edit it.
    if not rules_src.exists():
        _log("4/6", "FAIL: no rules_src.json after draft stage")
        return 7
    rs = json.loads(rules_src.read_text(encoding="utf-8"))
    # find the first rule across sections
    rule = None
    section_name = None
    for sec, items in rs.items():
        if sec.startswith("_") or not isinstance(items, list) or not items:
            continue
        rule = dict(items[0])
        rule["section"] = sec
        section_name = sec
        break
    if rule is None:
        _log("4/6", "FAIL: no rules in rules_src.json")
        return 8
    _log("4/6", f"loaded rule id={rule.get('id')} "
                f"pattern={rule.get('pattern')[:80]}")

    # ------ 5. REFINE ----------------------------------------------------
    if args.skip_refine:
        _log("5/6", "refine: skipped (--skip-refine)")
    else:
        client = (GeminiClient(model=args.gemini_model)
                  if args.gemini_model else GeminiClient())
        _log("5/6", f"refining (budget={args.max_iterations} iters, "
                    f"dev={len(dev)} exposures)")
        rule, report = refinement_loop(
            tech, rule, dev,
            client=client,
            max_iterations=args.max_iterations,
            verbose=args.verbose, log=lambda m: _log("5/6", m.lstrip()),
        )
        _log("5/6", f"refine done: coverage "
                    f"{report.initial_coverage:.1f}% -> {report.final_coverage:.1f}% "
                    f"after {len(report.iterations)} iter(s); "
                    f"{len(report.commits)} commits")
        if report.aborts:
            _log("5/6", f"  aborts: {report.aborts}")

    # ------ 6. TEST EVAL -------------------------------------------------
    if args.skip_test:
        _log("6/6", "test eval: skipped (--skip-test)")
    else:
        os.environ["LAB_ALLOW_TEST"] = "1"
        try:
            cov = evaluate_on_test(rule["pattern"], test)
        finally:
            os.environ.pop("LAB_ALLOW_TEST", None)
        _log("6/6", f"TEST coverage = {cov.pct:.1f}% "
                    f"(hits={len(cov.hits)}, misses={len(cov.misses)}, "
                    f"unfetched={len(cov.skipped)})")

    elapsed = _time.time() - pipeline_start
    print(f"\n[{_hms()}] AUTO PIPELINE complete in {elapsed:.1f}s "
          f"for tech_slug='{tech}'")
    return 0


# ---------------------------------------------------------------------------
# Status
# ---------------------------------------------------------------------------


def cmd_status(args: argparse.Namespace) -> int:
    target_dir = RESEARCH / args.tech_slug
    dev = target_dir / "dataset_dev.jsonl"
    test = target_dir / "dataset_test.jsonl"

    def _count(p: Path) -> int:
        if not p.exists():
            return -1
        return sum(1 for _ in p.open(encoding="utf-8"))

    n_dev = _count(dev)
    n_test = _count(test)

    n_rules = 0
    if Path(args.db).exists():
        conn = sqlite3.connect(args.db)
        try:
            row = conn.execute(
                "SELECT COUNT(*) FROM lab_src_rules WHERE tech_slug=?",
                (args.tech_slug,),
            ).fetchone()
            n_rules = row[0] if row else 0
        except sqlite3.OperationalError:
            n_rules = 0
        finally:
            conn.close()

    print(f"tech_slug: {args.tech_slug}")
    print(f"  dir: {target_dir} ({'exists' if target_dir.exists() else 'missing'})")
    print(f"  dataset_dev.jsonl:  {n_dev if n_dev >= 0 else 'missing'} records")
    print(f"  dataset_test.jsonl: {n_test if n_test >= 0 else 'missing'} records")
    print(f"  rules in lab.db:    {n_rules}")
    return 0


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description="Lab research cycle for a single tech")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p_start = sub.add_parser("start", help="Filter dev/test JSONLs for a tech and scaffold a research dir")
    p_start.add_argument("tech_slug")
    p_start.add_argument("--match-pattern", help="Override the default name-regex (regex on tech.name; case-insensitive)")
    p_start.add_argument("--force", action="store_true", help="Overwrite existing datasets")
    p_start.set_defaults(func=cmd_start)

    p_import = sub.add_parser("import-rules", help="Import rules_src.json into lab_src_rules")
    p_import.add_argument("tech_slug")
    p_import.add_argument("--rules-json", required=True)
    p_import.add_argument("--db", default=str(DEFAULT_DB))
    p_import.set_defaults(func=cmd_import_rules)

    p_status = sub.add_parser("status", help="Show research progress for a tech")
    p_status.add_argument("tech_slug")
    p_status.add_argument("--db", default=str(DEFAULT_DB))
    p_status.set_defaults(func=cmd_status)

    p_acq = sub.add_parser(
        "acquire-source",
        help="Clone a tech release into lab/research/<tech>/out/source/<ref>/",
    )
    p_acq.add_argument("tech_slug")
    p_acq.add_argument("--repo", required=True, help="git repository URL")
    p_acq.add_argument("--ref", required=True, help="git ref (tag/branch/sha)")
    p_acq.add_argument("--force", action="store_true", help="re-clone if dir exists")
    p_acq.set_defaults(func=cmd_acquire_source)

    p_idx = sub.add_parser(
        "build-index",
        help="(Re)build the RAG retrieval index at lab/rag/.index/rag.db",
    )
    p_idx.add_argument("--index-db", default=None, help="override index path")
    p_idx.add_argument("--db", default=str(DEFAULT_DB), help="lab.db to mine rules from")
    p_idx.set_defaults(func=cmd_build_index)

    p_disc = sub.add_parser(
        "discover",
        help="Deterministic scan of lab/research/<tech>/out/source/ for candidate signals",
    )
    p_disc.add_argument("tech_slug")
    p_disc.add_argument("--out", default=None,
                        help="output JSON (default: lab/research/<tech>/candidates.json)")
    p_disc.set_defaults(func=cmd_discover)

    p_draft = sub.add_parser(
        "draft-rule",
        help="Draft a candidate rule via Gemini + RAG (requires GEMINI_API_KEY)",
    )
    p_draft.add_argument("tech_slug")
    p_draft.add_argument("--task", help="natural-language description of what to draft")
    p_draft.add_argument(
        "--from-candidates",
        help="path to candidates.json (drafts one rule per candidate; supersedes --task)",
    )
    p_draft.add_argument("--out", default=None,
                         help="output path (default: lab/research/<tech>/rules_src_drafted.json)")
    p_draft.add_argument("--model", default=None, help="override Gemini model")
    p_draft.add_argument("--verbose", action="store_true")
    p_draft.set_defaults(func=cmd_draft_rule)

    p_judge = sub.add_parser(
        "judge-rule",
        help="Run Claude Sonnet judge over rules_src_drafted.json (requires ANTHROPIC_API_KEY)",
    )
    p_judge.add_argument("tech_slug")
    p_judge.add_argument("--in", dest="in_path", default=None,
                         help="input rules_src_drafted.json (default per-tech)")
    p_judge.add_argument("--out", default=None,
                         help="output path (default: rules_src_judged.json)")
    p_judge.add_argument("--model", default=None, help="override Anthropic model")
    p_judge.set_defaults(func=cmd_judge_rule)

    p_run = sub.add_parser(
        "run-all",
        help="Chain acquire-source -> build-index -> discover -> draft-rule -> "
             "judge-rule in one command. Idempotent per step (reuses existing "
             "outputs unless --force).",
    )
    p_run.add_argument("tech_slug")
    p_run.add_argument("--repo", default=None,
                       help="git repo URL (required if source not yet cloned)")
    p_run.add_argument("--ref", required=True, help="git ref (tag/branch/sha)")
    p_run.add_argument(
        "--candidates", default="smoke",
        help="'smoke' = 1 canonical banner candidate (default); "
             "'all' = draft every candidate; "
             "<path> = drafts the candidates listed in that JSON file")
    p_run.add_argument("--gemini-model", default=None,
                       help="override Gemini model (default: gemini-2.5-flash)")
    p_run.add_argument("--anthropic-model", default=None,
                       help="override Anthropic model (default: claude-sonnet-4-5)")
    p_run.add_argument("--db", default=str(DEFAULT_DB))
    p_run.add_argument("--force", action="store_true",
                       help="re-run every step (re-clone, rebuild index, "
                            "re-discover, re-draft, re-judge)")
    p_run.add_argument("--verbose", action="store_true")
    p_run.set_defaults(func=cmd_run_all)

    p_auto = sub.add_parser(
        "run-auto",
        help="Fully-automatic closed-loop pipeline: prescan -> exposure -> "
             "split -> draft -> refine -> test eval. Auto-imports each PASS "
             "draft and each accepted refinement; one git commit per import.",
    )
    p_auto.add_argument("tech_slug")
    p_auto.add_argument("--ref", required=True, help="git ref for source (e.g. 2.3.4)")
    p_auto.add_argument("--repo", default=None,
                        help="git repo URL (required if source not yet cloned)")
    p_auto.add_argument("--targets", default=None,
                        help="targets file for prescan "
                             "(default: lab/research/<tech>/test.txt)")
    p_auto.add_argument("--max-iterations", type=int, default=5,
                        help="max refinement iterations per rule (default 5)")
    p_auto.add_argument("--scan-concurrency", type=int, default=None,
                        help="passed to fp.cli scan --concurrency")
    p_auto.add_argument("--gemini-model", default=None,
                        help="override drafter/refiner model")
    p_auto.add_argument("--force-prescan", action="store_true",
                        help="re-run prescan even if prescan.jsonl exists")
    p_auto.add_argument("--force-draft", action="store_true",
                        help="re-run discover/draft even if rules_src.json exists")
    p_auto.add_argument("--skip-refine", action="store_true",
                        help="stop after draft; skip refinement loop")
    p_auto.add_argument("--skip-test", action="store_true",
                        help="skip final test-set eval (LAB_ALLOW_TEST stays unset)")
    p_auto.add_argument("--verbose", action="store_true")
    p_auto.set_defaults(func=cmd_run_auto)

    args = ap.parse_args(argv)
    # Default targets to per-tech test.txt
    if getattr(args, "cmd", None) == "run-auto" and not args.targets:
        args.targets = str(RESEARCH / args.tech_slug / "test.txt")
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
