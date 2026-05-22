# Open Graph Protocol — lab research

Status: loop closed 2026-05-18 (single iteration, no-rule outcome).

## Summary

Open Graph Protocol has **no version concept**. The 30 malformed entries in
`data/malformed_data.json` with `version='website'`/`'product'`/`'article'`
are all WhatWeb misextractions of the `og:type` meta property — an
**enumeration field**, not a version. There is no producer-emitted version
signal to author a rule against. **No `lab.db` row added.** This is a
phase-5 close where every remaining miss is a cited intentionally-rejected
form (CLAUDE.md §6).

## §6 loop record

### Phase 1 — Source acquire

WebFetched `https://ogp.me/` on 2026-05-18. Direct quote from the response:

> The specification does not define a semver-style version number. The only
> version-related mention is: "The specification described on this page is
> available under the Open Web Foundation Agreement, Version 0.9" — but
> this refers to the license agreement, not the protocol itself.

`og:type` is an enumeration:
- Global: `article`, `book`, `payment.link`, `profile`, `website`
- `music.*`: `music.song`, `music.album`, `music.playlist`, `music.radio_station`
- `video.*`: `video.movie`, `video.episode`, `video.tv_show`, `video.other`
- Extension types in the wild include `product` (not in the official ogp.me
  list — used by Shopify, WooCommerce, and other e-commerce vocabularies).

### Phase 2 — Pattern extract

**N/A — no signal exists.**

A meaningful version would require a producer to emit a numbered protocol
release. OGP is a vocabulary, not a numbered protocol. There is no banner,
no `Version:` header, no `data-ogp-version` attribute, no minor-revision
identifier anywhere on ogp.me or in linked specifications.

### Phase 3 — Filtered backtest

Slice: 30 records in `data/malformed_data.json` where
`tech == 'Open-Graph-Protocol'`. All 30 had `category == 'non_numeric'`
with values from the `og:type` enumeration:

| version value | count |
|---------------|-------|
| `website`     | majority |
| `product`     | smaller subset (e-commerce sites) |
| `article`     | smaller subset (news sites) |

All 30 records had `source == 'whatweb'` and `template_id == None`.
Zero records came from Wappalyzer, retire.js, nuclei, or lab. The bogus
extraction is confined to a single upstream rule.

### Phase 4 — Improve / classify

The single upstream rule responsible is in `whatweb.db`:

```sql
-- whatweb.db ww_patterns row, tech_id=540 (Open-Graph-Protocol)
SELECT part, regex FROM ww_patterns WHERE tech_id = 540;
-- ('body', '<meta[^>]+property="og:type"[^>]+content="([^"^>]+)"')
```

The regex correctly identifies that OGP is in use on the page (every page
with `<meta property="og:type">` is using OGP), but capture group 1 is
the `og:type` value — which the scanner's WhatWeb adapter then treats as
a version field. Two structural problems:

1. **The captured field is semantically wrong.** `og:type` is the page's
   declared OGP category, not a protocol revision.
2. **OGP has nothing else to capture.** Even with a corrected regex,
   there is no producer-emitted version literal to extract.

Wappalyzer also tracks OGP as `Open Graph` (id present in
`wap_technologies`) but has **zero patterns** for it
(`wap_patterns` returns no rows for that tech). Wappalyzer correctly
declines to claim a version it cannot derive — WhatWeb's behaviour is
the outlier.

Miss classification per CLAUDE.md §11:

- **Cited intentionally-rejected (30 / 30):** the OGP spec defines no
  version; any "version" field for this tech is structurally wrong. The
  rejection is justified by the upstream spec (ogp.me) fetched in
  phase 1.

### Phase 4b — Persist (atomic)

- L1/L2 (research record): `lab/research/open-graph-protocol/README.md`
  (this file).
- L3 (`lab.db`): **no row added**. This is deliberate. Authoring a
  `lab_src_rules` row with no version extractor (`extracts_json` empty
  or omitting `version`) would create a tech-presence echo of what
  WhatWeb already produces, with no value added — and would be
  exactly the kind of speculative addition CLAUDE.md §2 and §9 warn
  against.

### Phase 5 — Loop or close

**Close.** Coverage is at the structural ceiling: there is no producer
version signal to extract. Future iterations should not revisit this
unless one of these triggers fires:

1. A future revision of the OGP specification introduces an explicit
   version identifier (would re-open phase 1 to capture that signal).
2. Scanner-side reconcile gains a "no-version-allowed" tech set (out
   of lab scope per memory `Lab scope: rules only` — flagged as a
   scanner work item below).

## Scanner-side follow-up (out of lab scope)

The 30 bogus `version` values flow through the scanner unfiltered because
reconcile has no per-tech version-shape validator. A principled
scanner-side change would be:

- A small allow-list of techs that **have no version concept** (OGP,
  RSS, JSON-LD, Schema.org, robots-meta, etc.) and a reconcile-time
  rule that drops any `version` claim for them.
- Or, a uniform post-extraction validator (CLAUDE.md §7a "missing
  uniform stage" form) that rejects any version not matching
  `^[=v]?\d+(\.\d+)+[a-z]?(...)?$` regardless of source.

Both changes belong in `fingerprinter/fp/pipeline.py` (reconcile) and
are tracked here only as research context, not as deliverables of
this loop.

## What this loop teaches

A legitimate §6 outcome is **no rule**. When the producer has no
version signal, the right deliverable is the research note explaining
the absence — not a misleading rule that pretends to extract
something. Future readers can audit this record and understand:

- Why OGP has no `lab_src_rules` row,
- That the malformed corpus values are a single-source upstream
  defect, not a gap in our research,
- The exact scanner-side fix that would silence the bogus
  versions — without committing to that fix as a lab deliverable.
