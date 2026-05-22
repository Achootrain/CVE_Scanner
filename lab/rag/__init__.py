"""RAG-assisted rule authoring (CLAUDE.md §12).

This package is the LLM-side tooling for the lab research loop. It is:

  - Authoring-time only. Never imported by the scanner; never runs at scan
    time. The scanner stays a pure rule applier (CLAUDE.md §12, first
    paragraph).

  - The MIDDLE of the §12 sandwich. Deterministic steps live in
    ``lab.research_cycle`` / ``lab.core`` (clone source, compute presence
    matrices, backtest, import). The agent + retrieval lives here.

  - Bounded by three structural guardrails:
      1. Bounded-citation contract: retrieval returns
         ``(file_path, line_start, line_end, content_hash, text)`` tuples;
         drafted rules' ``source_json.principle`` MUST cite a tuple from
         the current turn. ``rule_drafter`` re-hashes and rejects on
         mismatch -- prevents the §10 "Source: X" fabrication failure.
      2. Self-match contract: every drafted regex MUST compile AND match
         at least one retrieved span verbatim. Intercepts the cheap-model
         failure mode of "looks-right regex that fires on nothing".
      3. §9 gate: drafter MUST call ``retrieve_rules(signal_shape)`` and
         either cite no near-match or articulate WHY this is a genuinely
         different signal shape. Prevents rule sprawl per host /
         separator / release era.

Build order (none of these are implemented yet; this package is a
skeleton):

  1. ``index_builder``: walks ``lab/research/<tech>/out/source/`` and
     ``lab/research/<tech>/*.md|*.json``, CLAUDE.md, and ``lab.db`` rows;
     produces a vector + BM25 hybrid index. EXCLUDES
     ``scan_results.jsonl`` and upstream mirrors (``wappalyzer.db``,
     ``fingerprints.db``, ``whatweb.db``) per §12 to avoid corpus-driven
     and upstream-driven contamination.
  2. ``retrieval``: ``retrieve_source / _rules / _research / _policy``
     return bounded spans. Each span carries content_hash so the post-
     validator can verify citations.
  3. ``ask``: CLI for ad-hoc human queries against the index (debugging,
     exploration).
  4. ``rule_drafter``: agent loop that produces candidate
     ``rules_src.json`` rows. NEVER writes to ``lab.db`` directly --
     output is JSON for human review, then
     ``research_cycle.py import-rules`` to land it.

Bootstrap target: re-derive ``lab/research/bootstrap/rules_src.json``
without seeing it. If drafted output ~ existing rules with valid
citations, the approach holds and a fresh tech becomes the first real
test.
"""

__all__: list[str] = []
