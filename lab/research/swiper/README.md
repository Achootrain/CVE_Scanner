# Swiper version-detection research

## Headline

24 unversioned Swiper detections in dev corpus. **21/24 = 87.5% recovered**
with one source-grounded banner rule, in one loop iteration. Versions
span 3.3.1 → 11.2.10 (16 distinct).

## §6 phase 1 -- Source acquire

Source: github.com/nolimits4web/swiper, npm-mirrored at jsdelivr.
Fetched release artifacts across 9 majors:

| Release | File | HTTP | Banner version |
|---|---|---|---|
| 4.5.1  | dist/js/swiper.min.js   | 200 | 4.5.1 |
| 5.4.5  | js/swiper.min.js        | 200 | 5.4.5 |
| 6.8.4  | swiper-bundle.min.js    | 200 | 6.8.4 |
| 6.8.4  | swiper-bundle.min.css   | 200 | 6.8.4 |
| 7.4.1  | swiper-bundle.min.js    | 200 | 7.4.1 |
| 8.4.7  | swiper-bundle.min.js    | 200 | 8.4.7 |
| 9.4.1  | swiper-bundle.min.js    | 200 | 9.4.1 |
| 10.3.1 | swiper-bundle.min.js    | 200 | 10.3.1 |
| 11.0.0 | swiper-bundle.min.js    | 200 | 11.0.0 |
| 11.2.6 | swiper-bundle.min.js    | 200 | 11.2.6 |
| 11.2.6 | swiper-bundle.min.css   | 200 | 11.2.6 |

## §6 phase 2 -- Pattern extract

Every release artifact's body starts with:

```
/**
 * Swiper <version>
 * Most modern mobile touch slider and framework with hardware accelerated transitions
 * https://swiperjs.com
 * Copyright 2014-<year> Vladimir Kharlampidi
 */
```

Note: the banner uses `/**` (not `/*!`). Some minifier configurations
strip `/**` comments. The artifacts shipped via npm/jsdelivr use rollup
with `output.banner` which is preserved unconditionally -- so the
signal survives in the canonical release. Secondary minification by
white-label CDN bundlers (bizweb.dktcdn.net, hstatic.net) DOES strip
this, creating a structural ceiling.

**Rule:** the `Most modern mobile touch slider` tail is required as
disambiguator -- prevents matching prose mentions of `Swiper N.N` in
unrelated content.

```
Swiper\s+(\d+\.\d+(?:\.\d+)?)\s*\n\s*\*\s*Most\s+modern\s+mobile\s+touch\s+slider
```

## §6 phase 3 -- Filtered backtest

Slice: 24 targets with tech='swiper' and version=null in
scan_results.jsonl (dashboard's tech_counter denominator). Each target
was live re-fetched, Swiper-bearing `.css`/`.js` asset URLs extracted
from the HTML, asset body fetched, banner rule applied.

Result: 21 recovered / 2 banner-stripped / 1 page-no-longer-references.

## §6 phase 4 -- Miss classification

| Bucket | Count | Action |
|---|---:|---|
| banner-not-in-asset (bizweb.dktcdn, hstatic.net) | 2 | structural ceiling -- secondary minifier strips `/**`; same shape as Bootstrap's Magento/Portals misses |
| no-swiper-asset (page no longer references Swiper) | 1 | scan staleness; re-scan would correct |
| rule-side / data-side misses | 0 | none |
| intentionally-rejected | 0 | none |

## §6 phase 5 -- Close

Every remaining miss is structurally unrecoverable. Loop stops here.

## Artifacts

- `lab_src_rules` banner_swiper (this iteration)
- `lab_pkg_aliases`: `swiper -> Swiper` (canonical from swiperjs.com)
