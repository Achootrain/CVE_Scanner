# jQuery UI — lab research

Status: loop closed 2026-05-18 (single iteration).

## Summary

jQuery UI versioning is well-served by retire.js's existing filecontent banner
rules. The malformed entries in `data/malformed_data.json` are
**evidence-level pollution from two upstream rules that lab cannot edit
directly** (per CLAUDE.md §5):

1. retire.js's URI fallback `/(([0-9][^\s'";]*))/jquery-ui(\.min)?\.js`
   captures multi-segment paths and underscore-encoded cache filenames as
   "versions" — same defect shape as the bootstrap URI rule.
2. Wappalyzer's html/scriptSrc patterns return major-only digits like
   `'01'`.

Both **fire alongside** retire.js's correct filecontent banner rule, so the
rolled-up `tech.version` ends up correct in reconcile, but the bogus
captures persist in the evidence list and surface in any downstream
review that walks `evidence[].version`.

## §6 loop record

### Phase 1 — Source acquire

WebFetched on 2026-05-18:

- `https://code.jquery.com/ui/1.12.1/jquery-ui.min.js`
- `https://code.jquery.com/ui/1.13.3/jquery-ui.min.js`
- `https://code.jquery.com/ui/1.14.1/jquery-ui.min.js`

All three open with the identical banner shape (date suffix and copyright
holder vary; the banner shape itself does not):

```
/*! jQuery UI - v X.Y.Z - YYYY-MM-DD
* https://jqueryui.com
* Includes: widget.js, position.js, ...
* Copyright <Foundation> and other contributors; Licensed MIT */
```

Copyright holder changed `jQuery Foundation` → `OpenJS Foundation` between
1.12.x (2016) and 1.13.x (2023+). Banner shape did not change.

### Phase 2 — Pattern extract

The producer signal is the literal `- v` separator between `jQuery UI`
and the dotted version. The date suffix and includes line are
intentionally outside the capture (per CLAUDE.md §7: model the signal,
not the surrounding sample).

Rule:

```
/\*!\s*jQuery\s+UI\s+-\s+v(\d+\.\d+(?:\.\d+)?)
```

Stored as `lab_src_rules` row id=161, tech_slug=`jquery-ui`,
rule_id=`banner_jquery_ui`, applies_to=`js body`, confidence=`high`.

### Phase 3 — Filtered backtest

Slice: 6 jquery-ui asset URLs across 5 targets that have malformed
jquery-ui entries in `data/malformed_data.json`
(6giay.vn, 769audio.vn, baothuathienhue.vn, baovephapluat.vn,
capstone.edu.vn).

Live re-fetch + apply the rule:

| outcome              | count |
|----------------------|-------|
| `banner_dash_v` hit  | 5     |
| `fetch_fail`         | 1 (6giay.vn — URL error on relative re-resolution) |

Per-target versions recovered:

| target                  | recovered |
|-------------------------|-----------|
| 769audio.vn             | 1.12.0    |
| baothuathienhue.vn      | 1.14.1    |
| baovephapluat.vn        | 1.12.1    |
| capstone.edu.vn         | 1.13.1, 1.13.3 |

Cross-check with rolled-up `tech.version` in `scan_results.jsonl` for
each target: **identical to the recovered values**. No new
`(target, version)` pairs were rescued by this rule because the
upstream retire.js filecontent rule was already producing the same
answer in reconcile.

### Phase 4 — Improve

Miss classification of the remaining gaps:

- **`fetch_fail` (1 case, 6giay.vn):** structural ceiling. The URL
  references the asset via a relative path that gets resolved
  differently depending on the requesting context. Not a rule defect.
- **Bogus retire.js URI captures (`01_14_01`, `01_12_01`, `01_13_03`,
  `6giay.vn/webmail/plugins/jqueryui/js`):** out-of-scope for lab. These
  come from retire.js's URI rule whose regex character class
  `[^\s'";]*` greedily spans `/`. We cannot edit retire.js's database
  per §5. The override rule lands the correct version which wins
  reconcile; the bogus URI captures persist as evidence-level
  pollution.
- **Wappalyzer `version='01'`:** out-of-scope for lab. Same shape as
  the bootstrap wappalyzer major-only false positive — upstream
  pattern matches `bootstrap`/`jquery-ui` against any digit-prefixed
  path segment.

### Phase 4b — Persist (atomic)

Both writes in one turn:

- L1/L2: `lab/research/jquery-ui/rules_src.json`
- L3:    `lab.db` `lab_src_rules` row id=161

### Phase 5 — Loop or close

**Close.** Coverage on the malformed slice is at the ceiling that the
banner rule can achieve (5/5 banner-bearing assets fire cleanly). No
banner-stripped jquery-ui build was observed in the corpus, so the
bootstrap-style `version_getter_inline` fallback was not added (per
CLAUDE.md §2 + §9: do not add speculative rules without corpus
evidence of need).

Next-iteration triggers:

- A corpus target reporting jquery-ui with no version AND no banner in
  the body would justify a phase-1 iteration on the per-widget
  `version:"X.Y.Z"` assignment pattern (verified present in upstream
  source but not used as the primary signal here).
- An upstream retire.js refresh that removes the filecontent banner
  rule would make this lab rule the primary signal source rather than
  override-layer backup. No action required from us in that case
  except revalidation.

## Why this loop did not add a new `(target, version)` rescue

Distinct from the bootstrap loop (which rescued aeon.com.vn and
cofer.edu.vn). For jquery-ui, every malformed corpus body still
contained the canonical banner — retire.js's existing filecontent rule
was already extracting the correct version. The lab's contribution is
**defensive** (override-layer per §5) rather than rescuing previously-lost
data. This is a legitimate outcome of the §6 loop: a phase-5 close on a
correctly-functioning canonical signal, recorded so that future
iterations can pick up from a known baseline rather than re-deriving it.
