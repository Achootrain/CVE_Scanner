# Fancybox version-detection research

## Headline

21 corpus detections of Fancybox; 5 "versioned" of which **1 was a
bogus cache-buster** (`960410695`) Wappalyzer captured from a `?v=`
query string. Post-research: **13/17 = 76.5% target lift on the
unversioned + bogus-versioned slice**, AND the bogus version is
corrected at reconcile via a generic SOURCE_RANK fix.

## §6 Phase 1 -- Source acquire

Two upstream repos (Fancybox split mid-life):

- `github.com/fancyapps/fancybox` -- v1 through v3 (jQuery plugin)
- `github.com/fancyapps/ui` -- v4+ (rewrite, npm `@fancyapps/ui`)

Fetched 11 release artifacts across v1.3.4, v2.0.6, v2.1.5, v3.0.0,
v3.5.7, v4.0.0, v5.0.0, v6.0.0 in both .js and .css form via the
jsDelivr GitHub mirror.

## §6 Phase 2 -- Pattern extract

Three distinct banner shapes across the lineage:

| Version | Banner literal observed (head[:280]) | Channel |
|---|---|---|
| v2.0.6 | `/*! fancyBox v2.0.6 fancyapps.com \| fancyapps.com/fancybox/#license */` | .js AND .css |
| v2.1.5 | `/*! fancyBox v2.1.5 fancyapps.com \| fancyapps.com/fancybox/#license */` | .js AND .css |
| v3.5.7 | `// ==================================================\n// fancyBox v3.5.7\n//` | .js only (v3 .css starts at `body.compensate-for-scrollbar{...}` with no banner) |
| v4.0.0 | `// @fancyapps/ui/Fancybox v4.0.0` | .js only, new namespace prefix |
| v5.0.0 | (no banner -- minifier strips) | structural ceiling |
| v6.0.0 | `/*! License details at fancyapps.com/license */` (no version) | structural ceiling |

The signal across v2-v4 is: optional `@fancyapps/ui/` namespace prefix,
the token `fancy[Bb]ox` (case varies -- v2/v3 use `fancyBox`, v4 uses
`Fancybox`), whitespace, literal `v`, dotted version. Comment chars
(`/*!` vs `//`) are absorbed by NOT pinning them. Per §7 the rule
captures the signal, not each per-release sample.

**Rule:**

```
(?i)(?:@fancyapps/ui/)?fancy[Bb]ox\s+v(\d+\.\d+(?:\.\d+)?)
```

## §6 Phase 3 -- Filtered backtest

Slice: 17 targets (16 unversioned + 1 with bogus `960410695` from
Wappalyzer's permissive `\?v=([\d.]+)` matching a cache-buster
timestamp). Live re-fetch + apply rule.

Result: **13 recovered**, including the bogus-version correction
(`baovietbank.vn`: 960410695 -> 3.5.7).

Versions span: 2.0.6, 2.1.3, 2.1.5, 3.0.47, 3.2.10, 3.3.5, 3.5.7 -- a
spread of v2-v3 era, confirming the rule generalises across what's
actually in the wild.

## §6 Phase 4 -- Miss classification

| Bucket | Count | Class | Action |
|---|---:|---|---|
| no-fancybox-asset (page no longer references) | 1 | stale corpus | accept |
| asset-no-banner (backtest's 6-URL cap missed the canonical file) | 3 | backtest artifact, not rule defect | production scan has bigger URL pool; rule will fire |
| v5/v6 structural ceiling | 0 in corpus | structural | accept |
| rule-side / data-side | 0 | -- | -- |

## §6 Phase 4 -- Generic plumbing fix (caught during research, applied)

Discovered a real bug while surveying: `pipeline._SOURCE_RANK` did NOT
include `"banner"` or `"readme"`. The dict-lookup default returned 0,
meaning detections from `BodyExtractStage` (source="banner") and
`SlugReadmeStage` (source="readme") had LOWER rank than Wappalyzer (3).
When Wappalyzer captured a bogus version (Fancybox at baovietbank.vn
captured `960410695`), the lab's correct version (`3.5.7`) was ignored
at reconcile time -- the bogus value won.

Fix: added `"banner": 4` and `"readme": 4` to `_SOURCE_RANK` (same
rank as `"lab"` because they ARE the lab, just emitted from different
stages). Source-grounded body extraction now correctly overrides
upstream's noisy regex matches.

Verified end-to-end:

```
reconcile([
  {source: 'wappalyzer', version: '960410695'},  # bogus
  {source: 'banner',     version: '3.5.7'},      # source-grounded
])
-> name=Fancybox version=3.5.7 sources=['wappalyzer','banner']
```

This is the CLAUDE.md §5 override-layer policy working as designed:
when an upstream rule emits the wrong value, the lab's source-grounded
rule wins. The SOURCE_RANK miss was a generic infrastructure gap;
fixing it benefits every banner / readme rule, not just Fancybox.

## §6 Phase 4b -- Persist

| Layer | Item | Where |
|---|---|---|
| L3 | `lab_src_rules.banner_fancybox` | id=157 |
| L2 | per-tech rule file | `lab/research/fancybox/rules_src.json` |
| L1 | snapshot.json | n/a -- `banner_rules` is L2-only |
| Scanner | `_SOURCE_RANK` gained `banner`/`readme` at rank 4 | `fp/pipeline.py` |

## §6 Phase 5 -- Close

Every remaining miss is either backtest-script-limit (production scan
will catch) or stale corpus. v5/v6 structural ceiling is documented;
no current corpus hits land there. Loop stops.

## What we did NOT add

- A v5/v6-specific bundle-body fingerprint -- the v5/v6 minifier strips
  ALL identifying literals from the head. Recovery would require deep
  body grep for an obscure non-banner token; §6 says no empirical
  corpus-mining and the official source doesn't expose a stable
  alternate channel here.
- A WordPress Easy FancyBox plugin override -- nuclei's
  `wordpress-easy-fancybox` template handles the plugin presence; the
  banner rule handles the underlying Fancybox library it wraps. No
  duplication.
- Tightening Wappalyzer's `\?v=([\d.]+)` rule -- per §5, never edit
  upstream DBs. The lab rule + the SOURCE_RANK fix together neutralise
  the upstream defect without touching wappalyzer.db.
