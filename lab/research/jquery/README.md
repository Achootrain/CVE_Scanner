# jquery — lab research

Datasets filtered from the global dev/test corpus:

- `dataset_dev.jsonl`: 156 records, 156 unique hosts (from 258 dev records)
- `dataset_test.jsonl`: 53 records, 53 unique hosts (from 82 test records)

Test-set discipline: dataset_test.jsonl is held out for FINAL eval only. Do not
mine rules from it. Set `LAB_ALLOW_TEST=1` when reading it.

## Workflow

1. Acquire the tech's release artifacts (multiple major versions if breaking changes exist).
2. Catalog version-bearing signals: banner format, canonical filenames, webfonts, class
   prefixes, package metadata. Cite each signal back to a specific release file.
3. Author `rules_src.json` -- every rule carries a `source` field pointing at the
   release file or documented downstream convention it was derived from.
4. Validate against `dataset_dev.jsonl`. The corpus is for VALIDATION, never for
   rule discovery (per CLAUDE.md section 6).
5. Import rules to lab.db:
   ```bash
   python -m lab.research_cycle import-rules jquery --rules-json lab/research/jquery/rules_src.json
   ```
6. Final eval on `dataset_test.jsonl` (single run, `LAB_ALLOW_TEST=1`).
