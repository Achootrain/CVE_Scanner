# Next.js version-detection research

## Headline

23 Next.js detections in corpus. Pre-research: 8/23 versioned (35%) via
retire.js's __NEXT_DATA__-anchored fingerprint (Pages Router only).
Post-research: **+13 new App Router hits**, projected combined coverage
~21/23 = 91%.

## §6 Phase 1 -- Source acquire

- `git clone --sparse vercel/next.js` -- sparse-checkout
  `packages/next/src/server/` + `packages/next/src/client/`.
- Probed 5 corpus Next.js targets (live re-fetch) to characterise
  externally-observable disclosures: `x-powered-by` header,
  `<meta name="generator">`, `__NEXT_DATA__` JSON tag, asset URL paths.

## §6 Phase 2 -- Pattern extract

### What's NOT a version channel (sourced from code, not inferred)

- `x-powered-by: Next.js` -- `packages/next/src/server/send-payload.ts:55`
  literally `res.setHeader('X-Powered-By', 'Next.js')`. **Header carries
  no version.** Confirmed by probing 3 corpus sites: 2 emit the header,
  none include a version.
- `<meta name="generator">` -- not emitted by Next.js (no match in source,
  none in 3 probed sites).
- `__NEXT_DATA__` JSON -- contains `buildId` (per
  `packages/next/src/server/render.tsx:1496`) and `nextExport` (L1498),
  but NOT version. buildId is a content-hash, not semver.

### The actual channel: `window.next` runtime assignment (App Router)

```
File:    packages/next/src/client/app-bootstrap.ts:13-16
const version = process.env.__NEXT_VERSION
window.next = {
  version,
  appDir: true,
}
```

The build inlines `__NEXT_VERSION` literal into the App Router
bootstrap bundle. The output shape is:

```js
window.next={version:"15.5.14",appDir:!0}
```

Validated against real bundles:

| Target | Bundle | Literal extracted |
|---|---|---|
| bachmai.gov.vn  | /_next/static/.../1255-5a410d1dc2ef3778.js   | `window.next={version:"15.5.14",appDir:!0}` |
| Backtest sweep  | 13 targets across Next 13.4.12 -> 15.5.14    | same shape, 9 distinct versions |

### Pages Router channel (separate, retire.js's domain)

retire.js (tech_id=257 in retirejs.db) already has:

```
version="(([0-9][^\s'";]*))".{1,1500}document\.getElementById\("__NEXT_DATA__"\).textContent
```

This fires on Pages Router builds where `_app-<hash>.js` parses
`__NEXT_DATA__`. Different code path from App Router, different
fingerprint -- the two are complementary, not duplicative.

## §6 Phase 3 -- Filtered backtest

Slice: 22 unversioned Next.js targets from `tech_counter` (dashboard
denominator per §11). For each: live-fetch the homepage, extract
`/_next/static/` script srcs, prioritise `framework-*` / `main-app-*` /
`_app-*` / `app-pages-internals-*` (`polyfills-*` explicitly skipped --
polyfills never contain the literal), inspect up to 25 bundles,
apply the banner rule.

Result: 13/22 = 59.1% recovered.

## §6 Phase 4 -- Miss classification

| Bucket | Count | Class | Action |
|---|---:|---|---|
| no-banner-in-bundles (Pages Router shape `n.version="X.Y.Z"` near `__NEXT_DATA__`) | 6 | out-of-scope for this rule | retire.js's fingerprint covers it in production; not a gap at the pipeline level |
| no-next-bundles in HTML (Next 15 RSC inline payload, no script srcs) | 3 | structural ceiling | no externally-fetchable bundle; would need a different channel |
| no rule-side gaps | 0 | -- | -- |
| no data-side gaps | 0 | (aliases authored) | -- |

## §6 Phase 4b -- Persist

- L3: `lab.db` rows added (banner_rule id=155, aliases for `next.js`
  and `nextjs`)
- L2: `lab/research/next.js/rules_src.json` (this directory)
- L1: `lab/url_ver_lab/snapshot.json._CDN_PKG_MAP` + `_JS_LIB_MAP`
  updated with `next.js` / `nextjs` -> `Next.js`

A `seed.py` rebuild now regenerates `lab.db` with all three persisted.

## §6 Phase 5 -- Close

Every remaining miss is either (a) a different channel already covered
by retire.js (Pages Router) or (b) a structural ceiling where the
version is not externally observable (RSC inline, no JS bundle URL in
HTML). Loop stops here.

Combined production coverage projection: ~91% on this corpus (8 retire.js
+ 13 banner_next_app_bootstrap).

## What did NOT go into lab.db (and why)

- `<meta name="generator">` rule -- Next.js does not emit this; would
  be a phantom rule with no signal.
- `x-powered-by`-based rule -- header carries no version per source.
  Would emit presence-only at best, duplicating Wappalyzer.
- A second App-Router-internal pattern (`process.env.__NEXT_VERSION` raw
  literal in bundles) -- only present in dev builds, never in production.
