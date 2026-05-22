# lab/rag/ -- RAG for rule authoring (CLAUDE.md §12)

Authoring-time tooling. Not part of the scanner. Never runs at scan time.

## Why it exists

The §6 research loop (Source -> Pattern -> Backtest -> Improve) is small for
a human who already knows where to look in a repo (`package.json` ->
`scripts.build` -> banner plugin -> emitted literal). For an AI agent
authoring rules across many techs, the missing piece is "where do I look?"
RAG indexes the lab's research artifacts and per-tech source trees so the
agent can ground each drafted rule in cited spans.

## The §12 sandwich

```
   [DETERMINISTIC] (lab.research_cycle, lab.core)
     1. git clone --depth 1 into lab/research/<tech>/out/source/<release>/
     2. inspect_build(...)     -> declared_version, banner template
     3. inspect_versions(...)  -> presence matrix, banner-format diff
   ----------------------------------------------------------------------
   [AGENT + RAG]  (this package)
     4. For each candidate signal:
          retrieve_source(query, tech)    -- AST-chunked spans
          retrieve_rules(signal_shape)    -- §9 duplicate check
          retrieve_research(analog)       -- prior-tech template
          read_file / grep_source         -- open what retrieval points at
        draft rule + citation
          compile_regex(pattern)          -- self-match contract
          on failure: loop to retrieval
   ----------------------------------------------------------------------
   [DETERMINISTIC] (lab.core, lab.research_cycle)
     5. backtest(rule, dev_slice)         -- §6 phase 3 gate
     6. emit rules_src.json (NOT lab.db)
     7. human reviews citations + signal-shape coherence
     8. research_cycle import-rules       -- only then does lab.db change
```

Step 4 is the only LLM step.

## Three structural guardrails

1. **Bounded-citation contract.** Retrieval tools return spans as
   `(file_path, line_start, line_end, content_hash, text)`. The drafter's
   `source_json.principle` must cite a tuple from THIS turn. Post-validator
   re-hashes the cited span and rejects on mismatch. Prevents the §10
   "Source: X" fabrication failure structurally.

2. **Self-match contract.** Every drafted regex must (a) compile in
   Python's `re`, (b) match at least one retrieved span verbatim. Catches
   the cheap-model "looks-right regex that matches nothing" failure mode
   before the row reaches a human.

3. **§9 gate.** Drafter MUST call `retrieve_rules(signal_shape)` and either
   cite no near-match or articulate why this is a genuinely different
   signal shape. Prevents rule sprawl per host / separator / release era.

## What this package indexes -- and what it doesn't

Indexed:

| Corpus                                | Path                                                    |
|---------------------------------------|---------------------------------------------------------|
| Per-tech multi-version source         | `lab/research/<tech>/out/source/<release>/`             |
| Per-tech research artifacts           | `lab/research/<tech>/*.md`, `rules_src.json`, etc.      |
| Policy                                | `CLAUDE.md`                                             |
| Live rules                            | `lab.db` rows (`lab_src_rules`, `lab_url_patterns`, ...) |

Explicitly NOT indexed:

- `scan_results.jsonl` -- routes the agent into §6 level-1 corpus pattern
  matching (the §6 anti-pattern).
- `wappalyzer.db` / `fingerprints.db` / `whatweb.db` -- upstream mirrors
  (CLAUDE.md §5). Indexing them corrupts the §9 duplicate-check answer.
- `node_modules/`, `vendor/`, test fixtures inside cloned source trees.

## Files in this package

| File             | Role                                                 |
|------------------|------------------------------------------------------|
| `index_builder.py` | Walks the indexed corpora, emits the hybrid index. |
| `retrieval.py`   | `retrieve_source / _rules / _research / _policy`.    |
| `ask.py`         | Human CLI for ad-hoc queries (debugging).            |
| `rule_drafter.py` | Agent loop that emits candidate `rules_src.json`.   |

All modules are stubbed -- they raise `NotImplementedError` and document
the intended shape. Implementation lands once `lab/core/` is stable and the
Bootstrap re-derivation experiment is set up.

## Model choice

- Drafter: cheap model (e.g. DeepSeek-V3, Qwen2.5-Coder-32B). Guardrails do
  the heavy lifting; model quality matters less when `compile_regex` +
  citation-hash structurally intercept failure modes.
- Judge: Claude Sonnet reviews drafts that pass the guardrails. Its job is
  what guardrails can't enforce structurally -- §7 inventory-matching, §9
  signal-shape coherence, channel-choice sanity.

## Where lab.db sits relative to this

`lab.db` is downstream of this package. The agent writes JSON; humans
review; only then does `lab.research_cycle import-rules` write to lab.db.
Scanner reads lab.db unchanged.
