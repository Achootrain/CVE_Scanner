# CLAUDE.md

Guidance for Claude Code. Biased toward caution over speed; use judgment on trivial tasks.

## 1. Think Before Coding
- State assumptions explicitly. If uncertain, ask.
- If multiple interpretations exist, present them.
- Push back when a simpler approach exists.

## 2. Simplicity First
No features beyond what was asked. No speculative abstractions, "flexibility," or error handling for impossible scenarios. If 200 lines could be 50, rewrite.

## 3. Surgical Changes
Touch only what you must. Match existing style. Remove imports/variables YOUR changes orphaned; don't remove pre-existing dead code (mention it instead). Every changed line should trace to the user's request.

## 4. Goal-Driven Execution
Transform tasks into verifiable goals. For multi-step tasks, state a brief plan with verification checks per step. Strong success criteria let you loop independently.

## 5. Lab Authors Rules; `lab.db` Is The Single Source Of Truth

- Lab outputs rows in `lab.db` (`lab_url_patterns`, `lab_pkg_aliases`, `lab_version_probes`, `lab_src_rules`). The scanner is a consumer.
- New patterns/aliases land as SQL `INSERT`s, not Python edits. No hardcoded rules in scanner code.
- Scanner's read-side (`fp/url_ver.py`, `fp/version_probes.py`) loads from `lab.db` at module init. Adding a tech = one `INSERT` + `reload()`.
- **`lab.db` is the override layer for upstream DBs** (`wappalyzer.db`, `fingerprints.db`, `whatweb.db`). Never edit upstream DBs directly — next refresh wipes edits. Override patterns:
  - Upstream misses version → author `lab_src_rules` row (BodyExtract/SlugReadme stages emit versioned detection; reconcile merges).
  - Upstream emits wrong name → normalize via `lab_pkg_aliases` + `_canonical_name_from_url` at `_from_scanner` boundary.
  - Upstream misses tech entirely → author fresh in `lab.db` per §6.
- `lab.db` = accumulated research record. External DBs stay clean mirrors; overrides in one auditable place.

## 6. The Lab Research Loop: Source → Pattern → Backtest → Improve → Loop

### Evidence hierarchy (weakest → strongest)
1. **Corpus pattern-matching** — write regex from observed URLs. Anti-pattern.
2. **Documentation** — better, but lags code. Not sufficient alone.
3. **Source code / release artifacts** — the contract. Derive rule from code; cite file + line.

### Five-phase loop
1. **Source acquire** — `git clone --depth 1` the actual server/build/release source. Not docs.
2. **Pattern extract** — Grep source for disclosure structure (URL parser, banner emitter, header writer). Mirror the producer regex on consumer side. Cite file + line.
3. **Filtered backtest** — Filter to tech slice (dashboard's tech_counter = denominator, see §11). For body/CDN rules, live re-fetch HTML. Classify every miss: rule-side / data-side / plumbing / out-of-scope / intentionally-rejected.
4. **Improve** — Each miss category → different action (widen rule / INSERT alias / fix plumbing / queue new iteration / cite as by-design).
4b. **Persist** — Every `lab.db` INSERT must be mirrored to its L1/L2 source file in the same turn:
  - `lab_src_rules` → `lab/research/<tech>/rules_src.json`
  - `lab_pkg_aliases` / `lab_url_patterns` / `lab_version_probes` → `lab/url_ver_lab/snapshot.json`
  - A row in lab.db alone is LOST on next seed/import. If only one write happens, it must be L1/L2.
5. **Loop or close** — Re-run phase 3. Stop only when remaining misses are cited intentionally-rejected or structural ceilings.

### Citation rule
**Never write `Source: X` unless X was fetched this turn.** `source_json.principle` must quote/paraphrase specific file + line. If fetch impossible, label explicitly: `Source: corpus-derived from N samples; not verified — needs upgrading`.

### Tech-specific guidance
- **Library-version rules:** Download releases across majors → grep banners, `package.json`, filenames, class prefixes.
- **URL-scheme / CDN rules:** Clone producer's router → grep route grammar + version classifier.
- **Protocol / framework rules:** Fetch reference implementation → read wire-format code.

## 7. Think About The Signal, Not The Samples

The signal is: a TOKEN naming the tech, in PROXIMITY to a VERSION, separated by URL-conventional characters (`/`, `-`, `.`, `_`, `@`, `?ver=`).

Rules describe that signal regardless of host (cdnjs, jsdelivr, unpkg, self-hosted), token order, or separator character.

**Anti-patterns:** Rule per CDN host. Pinning separator to one character. Hard-coding token position. These enumerate samples, not signals.

**Absorb:** casing, separators, intermediate path noise (`/releases/v`, `/ajax/libs/`), query forms (`?ver=`, `?v=`).
**Reject:** non-version digits (timestamps, kit hashes, cache-busters), wrapper versions belonging to a different tech.

Rule count per tech is a consequence of signal shapes, not a quota.

## 7a. Build From A Principle, Not From Patches

Detection is a uniform funnel. Each stage extracts `(tech, version, evidence)` from progressively more expensive sources:

```
Stage 0: Discovery     — collect URLs (root, katana, evidence_url)
Stage 1: URL extract   — proximity + query rules from lab_url_patterns
Stage 2: Body extract  — banner regexes from lab_src_rules over .css/.js bodies
Stage 3: Inline extract — banner regexes over <style>/<script> in HTML
Stage 4: Bundle scan   — glyph/class signatures in app bundles
Stage 5: Browser tier  — escalate fetcher when blocked
```

When a failure surfaces, ask: **which funnel stage failed?** Answer is always:
- **Rule data wrong/missing** → author rule row, no code change.
- **Content didn't reach the rule** → fix data plumbing between stages (1-2 lines at boundary).
- **No stage covers this source** → add uniform stage (applies to all techs via `lab.db`, not tech-specific).

**Sinkhole signals:** tech-specific branches, near-duplicate code paths, `if tech == "X"` conditionals, "workaround for X" comments in scanner code.

## 8. Diagnose Before You Fix: Tech-Without-Version Exceptions

When tech detected but no version despite existing rules, exactly three root causes:

**A — Rule wrong/incomplete.** Run regex manually against URL/body. Doesn't match → fix the `lab.db` row. No code change.

**B — Right content never reached the rule.** Rule is correct but pipeline stage never received the URL/body. Trace data flow, find where content drops. Fix plumbing at the CONSUMER, not producer. (Worked example: relative `evidence_url` → resolve in `BodyExtractStage._candidate_asset_urls`.)

**C — No stage covers this source.** Content source genuinely new. Add uniform stage with `lab.db` rules, not tech-specific code.

## 9. Before Inserting A Rule, Survey Existing Rules

New rule = last resort. Each extra rule is another regex on the hot path and future maintenance surface.

**Procedure:**
1. Query all existing rows for this tech across `lab_*` tables. Read each.
2. Run failing sample against each. Note which almost matched.
3. Decide and document WHY:
   - **Generalise** when same signal shape + one absorbable variation (separator, casing, host, path noise). Edit one row.
   - **New rule** when genuinely different signal shape (different content source, anchoring token, or structure).
4. If generalising, re-run dev corpus to confirm no regression.

**Test:** "If I widen rule R, does it still describe one coherent signal shape, or two things glued with `|`?" Coherent → generalise. Glued → new rule.

## 10. Earned Citations — see §6
Never cite what wasn't fetched this turn. Anti-patterns: unfetched URL in `note`; `validated_against` = derivation set (tautology); "from the docs" without URL + fetch.

## 11. Backtest Against The Right Slice (Denominator Discipline)

```
slice  = {targets where rule's signal could appear} (defined BEFORE measuring)
hits   = rule.apply(slice)
misses = slice - hits, each labelled by failure reason
Report: |slice|, |hits|/|slice|, misses bucketed, net-new (target,version) pairs
```

**Three failure modes:**
1. No filter (full corpus) — drowns misses in noise.
2. Filter by archived evidence only — misses URLs not in scan summaries.
3. **Correct:** Filter by dashboard count, live re-fetch those pages — honest miss surface.

For body/CDN rules: scan archives ≠ reference graph. Live-fetch the slice (N = dashboard count, not full corpus).

**Always classify misses:** rule-side / data-side / plumbing / out-of-scope / intentionally-rejected. Each → different follow-up.

## 12. RAG Is For Rule Authoring, Not Scanning

RAG aids the §6 research loop at authoring time. Not part of scanner. Never runs at scan time. Never writes `lab.db` directly.

### In scope
- Drafting candidate rules (§6 phase 2) when agent does source-read
- §9 duplicate check before insert
- Cross-tech analogy / policy lookup

### Out of scope
- Scan-time detection (matching, not generating)
- Version-string extraction (use grep + build-script reader)
- Replacing deterministic preprocessing (git diff, sha256, presence matrices)

### The sandwich: deterministic outside, agent inside
```
[DETERMINISTIC] 1-3: git clone, inspect_build, inspect_versions → candidate signals
[AGENT + RAG]   4: retrieve → draft rule + citation (compile_regex must pass; self-match required)
[DETERMINISTIC] 5-8: backtest → rules_src.json → human review → import-rules → lab.db
```

Agent never touches `lab.db` directly. Always: `rules_src_drafted.json` → human review → `rules_src.json` → `import-rules`.

### Three structural guardrails
1. **Bounded-citation:** `source_json.principle` must reference a span returned this turn. Post-validator re-hashes; mismatch → reject.
2. **Self-match:** Every regex must compile AND match ≥1 retrieved span verbatim.
3. **§9 gate:** Must call `retrieve_rules(signal_shape)` and justify novelty or cite no near-match.

### Model choice
- Drafter: cheap model (DeepSeek-V3 / Qwen2.5-Coder-32B). Guardrails catch failure modes.
- Judge: Claude Sonnet reviews for signal-shape coherence, inventory-matching, channel-choice sanity. PASS/FLAG.

### Indexed corpora
| Corpus | Path |
|---|---|
| Source code (per-tech) | `lab/research/<tech>/out/source/<release>/` |
| Research artifacts | `lab/research/<tech>/*.md`, `rules_src.json` |
| Policy | `CLAUDE.md` |
| Live rules | `lab.db` rows |

NOT indexed: `scan_results.jsonl`, upstream mirror DBs, `node_modules/`, `vendor/`.

### Implementation status (2026-05-21)
**Shipped:** `lab/core/` (corpus, rules, source, discover), `lab/rag/` (index_builder, retrieval, llm via Gemini + Anthropic, rule_drafter with 4 guardrails, judge), `lab/research_cycle.py` (start, status, import-rules, acquire-source, build-index, discover, draft-rule, judge-rule). 52 lab tests pass.

### Next steps (in leverage order)
1. ✅ Deterministic pre-pass (`lab.core.discover`) — ran on FA: 251 candidates across 4 refs. Surfaces expected-noisy candidates (e.g. SemVer pulled from license string); §12 sandwich design — the drafter + judge triage. Live `draft-rule` smoke deferred (Gemini Flash-Lite at 18/20 RPD).
2. ✅ Multi-phrased §9 gate + post-draft duplicate check — `rule_drafter._verify_guardrails` now (a) requires ≥2 textually-distinct retrieve_rules queries (symmetric-difference test, stopword-aware) and (b) re-runs retrieve_rules with the drafted regex's literal anchors; flags when anchors overlap an existing rule AND drafter claimed `no_near_match`. 14 unit tests.
3. ✅ Judge step (Claude Sonnet review) — `lab/rag/judge.py` runs the three §12 checks (signal coherence, inventory matching, channel choice). PASS/FLAG verdict with structured reasons. 7 unit tests (mocked client; live smoke deferred — needs ANTHROPIC_API_KEY in shell env).
4. ✅ Backtest integration (sandwich step 5)
5. ⏸ Bootstrap re-derivation experiment — deferred; requires live Gemini + Anthropic calls. Tomorrow's quota window.
6. 🔒 Embeddings (BM25 → hybrid) — GATED on concrete BM25 miss class. No such miss class observed yet; defer until one surfaces during real-tech rule authoring.

Status: 3/5 done today (2/3/CLAUDE.md update); 1 partially done (discover ran, draft deferred); 1 deferred (bootstrap); 1 gated (embeddings).

---

## Project Overview

Security vulnerability / technology fingerprinting scanner. Three rule sources: Nuclei templates (883 YAML), Wappalyzer rules (~2.8k techs), crt.sh CT logs. Everything under `fingerprinter/`.

## Architecture

Two pipelines meet at `lab.db`. Lab authors rules; scanner reads them.

### Scanner pipeline
```
Target URL → fp.cli scan/pipeline
  Rule sources: fingerprints.db (Nuclei), wappalyzer.db, retirejs.db, lab.db
  → katana crawl → version_probes → cross_page rescan → Detection aggregator → scan_results.jsonl
```
Key invariant: no detection-rule literal in `fp/*.py`. `url_ver.py`/`version_probes.py` load from `lab.db` at module init.

### Lab pipeline
```
scan_results.jsonl → research_cycle.py start (filter by tech) → dataset_dev/test.jsonl
Release tarballs → src_catalog.py → src_artifact_inventory.json → Author rules_src.json
  → import-rules → lab.db → validate against dev → (gate passes) → final eval on test set
```

### Canonical artifact paths
| Artifact | Path |
|---|---|
| Scanner rule store (SSOT) | `fingerprinter/lab.db` |
| Re-seed snapshot | `lab/url_ver_lab/snapshot.json` |
| Per-tech research | `lab/research/<tech>/` |
| Per-tech rules (pre-import) | `lab/research/<tech>/rules_src.json` |
| Parity test | `lab/url_ver_lab/test_parity.py` |
| Global scan corpus | `fingerprinter/scan_results.jsonl` |
| Per-tech dev/test datasets | `lab/research/<tech>/dataset_{dev,test}.jsonl` |

Corpus split happens per-tech after filtering (blind-test boundary maintained per-tech).

### Plan
**Scanner/dataset:** fix URL evidence in results, refine pipeline as labeling tool, research owl-carousel/nextjs/wp-rocket/shopify/jquery-ui-tooltip/xenforo/nuxt.js/requirejs/tailwind, scan + label versions, refine data for ML.

**Lab RAG:** see §12 Next Steps.

### problems
Target	Config	Time	Techs	Versioned	Notes
hanoi.edu.vn	api + no-katana	5.9s	3	0	Header-only: cloudflare, HSTS, ASP.NET
api + katana	62.2s	3	0	+60s for nothing (katana timeout, same 3 techs)
page + no-katana	93.6s	10	5	✅ bootstrap, FA, jQuery, Slick, OGP, google-font-api
page + katana	95.1s	10	5	Katana timeout adds nothing over page-only
gosu.vn	all configs	4-64s	0	0	Site down/unreachable
cafebiz.vn	api + no-katana	39.1s	6	1	Not CF-blocked, api works
api + katana	62.3s	6	1	+23s katana timeout, same 6 techs
page + no-katana	67.7s	6	1	Slower, same result (no CF block here)
page + katana	71.0s	6	1	Slowest, same result

- katana is useless. check why
- maybe add a smart detection ( cloudflare detection to enable/disable page mode)