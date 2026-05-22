# Vue.js version-detection research

## Headline

Two source-grounded banner rules added, one for Vue 2 and one for Vue 3,
each complementing retire.js's existing fingerprints where they fail.
Iteration 1: Vue 2 minified-bundle gap closed (4/8 unversioned slice
recovered). Iteration 2: Vue 3 forward-coverage gap proven empirically
against retire.js's own DB (retire.js misses Vue 3.2.37 entirely),
closed.

## §6 Phase 0/9 -- Survey

| Source | Vue coverage |
|---|---|
| retire.js | **14 fingerprints** for Vue: URI shapes (`/vue@<v>/`, `/npm/vue@<v>/`), filename `vue-<v>.min.js`, banner `/*! Vue.js v<v>`, runtime `Vue.version='<v>'`, plus 9 Vue 3-specific filecontent patterns |
| Wappalyzer | 3 patterns: `data-v-<hash>` HTML attribute (presence only -- false positives on non-Vue templates), `vue[.-]<ver>.js` scriptSrc (version only when URL has version), and `(?:/<ver>)?/vue.min.js` |
| nuclei | 1 unrelated template (CARESTREAM Vue Motion -- different product) |
| lab.db | 1 seeded alias `vue -> Vue.js` |

Corpus: 15 detections, 7 versioned (all via retire.js, 47%), 8
unversioned.

## §6 Phase 1+2+3 -- Iteration 1: Vue 2 minified gap

### Probe finding

Of the 8 unversioned sites, the deep probe found that 9pay.vn's
`a916bea.js` bundle contained:

```
Object.defineProperty(ir,"FunctionalRenderContext",{value:jn}),ir.version="2.7.13"
```

This is Vue 2.7.13 -- but **retire.js's `Vue\.version = '...'` fingerprint
requires the literal prefix `Vue.version`**, and the minified bundle
renamed the Vue constructor to `ir`. Missed by retire.js.

### Source-grounded anchor

`vuejs/vue@v2.7.16 src/core/index.ts:21-25` emits two consecutive
assignments:

```typescript
Object.defineProperty(Vue, 'FunctionalRenderContext', {
  value: FunctionalRenderContext
})
Vue.version = version
```

The minifier preserves the string literal `"FunctionalRenderContext"`
(it is a `defineProperty` key) regardless of constructor renaming. The
`.version=` assignment is within ~200 chars of that literal in every
build. Anchor on the preserved string, not the variable name.

### Rule and result

```
"FunctionalRenderContext"[\s\S]{0,400}?\.version\s*=\s*["'](\d+\.\d+\.\d+)["']
| \.version\s*=\s*["'](\d+\.\d+\.\d+)["'][\s\S]{0,400}?"FunctionalRenderContext"
```

Backtest on the 8 unversioned slice: **4 recovered** -- Vue 2.6.11 (×2),
2.6.14, 2.7.13. The remaining 4 were probed deeply (iteration 2 below).

## §6 Phase 4 -- Iteration 2: the remaining 4 misses + Vue 3 forward-coverage

### Probe finding: 4 of 8 "unversioned Vue" are Wappalyzer false positives

| Site | What it actually is |
|---|---|
| bitget.com.vn | React 18.3.0 (the `data-v-` match was on React `Fragment`/`Suspense` chunks) |
| baocamau.vn | jQuery + slick + video.js (matched on "Fragment" string in non-Vue libraries) |
| baodongthap.vn | 1 KiB chunk; random text match |
| bocongan.gov.vn | 0 vue strings anywhere; pure HTML site with a `data-v-` attribute from some custom CMS |

Wappalyzer's `<(?!svg)[^>]+\sdata-v(?:ue)?-` matcher is too permissive:
modern frameworks, CSS scoped components, and custom Vietnamese
government CMSes all use `data-v-` style attributes. Per §5 the upstream
DB stays untouched; the lab override layer corrects by emitting
higher-rank source-grounded detections on real Vue sites only -- false
positives just lack any Vue evidence at reconcile time.

**No Vue rule can fix false-positive upstream detection on non-Vue
sites.** Those 4 are accepted as upstream-detection misclassification.

### Source analysis pushed: Vue 3 source

Pushed iteration 2 to source-ground retire.js's Vue 3 fingerprints
properly (this was the user's call-out -- "did you analyze source
code?").

- Cloned `vuejs/core@v3.5.0` (`packages/runtime-core/src/index.ts:3`):
  `export const version: string = __VERSION__`
- Tested retire.js's 6 Vue 3 filecontent fingerprints against 5
  downloaded Vue 3 release artifacts (3.2.37 / 3.4.0 / 3.5.0 global
  + runtime-only / 3.5.0 esm-bundler):

| Build | retire.js hits |
|---|---|
| 3.4.0 global | 1/6 (only v3-compiler) |
| 3.5.0 global | 1/6 (only v3-policy) |
| 3.5.0 runtime-only | 1/6 (only v3-policy) |
| 3.5.0 esm-bundler (2.4 KiB re-export shim) | 0/6 (correctly -- no version literal in shim) |
| **3.2.37 global** | **0/6 -- ENTIRELY MISSED** |

retire.js's Vue 3 fingerprints anchor on too-narrow surrounding context
(SSR utils comment, devtoolsFormatters proximity, etc.) and the context
varies by Vue 3 version. The 3.2.37 global build (128 KiB) ships the
version literal but in a form none of the 6 patterns match.

### Source-grounded Vue 3 pattern

Probed three Vue 3 builds for any literal version with 80 chars of
context. All three show the version constant interleaved with Vue 3's
DOM-safety init code:

```
3.2.37:  const ds="3.2.37",hs="undefined"!=typeof document?document:null,ms=hs&&hs.createElement("template
3.4.0:   const Ar="3.4.0",Er=o,Ir=o,Rr="undefined"!=typeof document?document:null,Or=Rr&&Rr.createElement
3.5.0:   let i3="3.5.0",i4="undefined"!=typeof window&&window.trustedTypes;if(i4)try{
```

Two stable Vue 3 internals appear within ~200 chars of the version
literal in every build:

- `"undefined"!=typeof document?document:null` -- Vue 3 runtime-dom env
  detection (3.2-3.4 era), in `packages/runtime-dom/src/nodeOps.ts`
- `"undefined"!=typeof window&&window.trustedTypes` -- Vue 3 CSP-trusted-
  types policy creation (3.4+), `packages/runtime-dom/src/nodeOps.ts`

Both are Vue 3-distinctive. Generic JS libraries that check
`typeof window` don't follow it with `window.trustedTypes`. The
`document?document:null` ternary is specifically Vue 3's pattern.

### Rule and result

```
["'](\d+\.\d+\.\d+(?:-[\w.]+)?)["'][\s\S]{0,200}
(?:["']undefined["']!=typeof\s+document\?document:null
   |["']undefined["']!=typeof\s+window&&window\.trustedTypes)
```

Validation:

| Test | Result |
|---|---|
| vue@3.2.37 global | HIT 3.2.37 (retire.js misses) |
| vue@3.4.0 global | HIT 3.4.0 |
| vue@3.5.0 global | HIT 3.5.0 |
| vue@3.5.0 runtime-only | HIT 3.5.0 |
| vue@3.5.13 global | HIT 3.5.13 |
| jquery@3.7.1 (negative control) | miss |
| react@18.3.0 (negative control) | miss |

5/5 Vue 3 hits, 2/2 negative tests reject.

## §6 Phase 4b -- Persist

| Item | Layer | Where |
|---|---|---|
| `banner_vue2_functional_render_ctx` | L3 | lab.db id=158 |
| `banner_vue3_dom_safety` | L3 | lab.db id=159 |
| Both rules | L2 | `lab/research/vue/rules_src.json` |
| `vue -> Vue.js` alias | L1 | snapshot.json (pre-existing seeded row) |
| banner_rules section in L1 | n/a | banner_rules is L2-only |

## §6 Phase 5 -- Close

Real Vue coverage on the current corpus is now effectively 100%:

- 7 already-versioned sites via retire.js URL/filename/runtime patterns.
- 4 newly-recovered Vue 2.x sites via the FunctionalRenderContext anchor
  (banner_vue2 rule).
- 0 actual unversioned Vue sites remain -- the 4 "missing" were
  Wappalyzer false-positive Vue detections on non-Vue sites.

Forward-coverage:

- `banner_vue3_dom_safety` catches Vue 3 builds where retire.js's 6
  v3 fingerprints fail. Empirically demonstrated on 3.2.37 global which
  retire.js misses entirely.

## What we did NOT add

- A "loose match any X.Y.Z in a Vue context" rule -- the probe on
  9pay.vn showed THREE distinct version literals in one bundle
  (Vue 2.7.13, vue-i18n 8.28.2, core-js 3.6.4). A loose rule would
  false-positive on neighbouring libraries in the same bundle. Both
  authored rules use Vue-distinctive anchor literals to scope the
  proximity window.
- Override of Wappalyzer's `data-v-` matcher -- per §5, never edit
  upstream DBs. The 4 false positives just have no real version
  evidence and lose at reconcile against no override -- they appear
  as "presence-only" Vue records which is the honest outcome.
- A Vue 1.x rule -- v1.x is unmaintained and absent from our corpus.
- A Nuxt.js-specific rule -- Nuxt's version is separate from Vue's; a
  future iteration would research Nuxt independently.

## Side note: bundle archaeology on 9pay.vn

The deep probe found three concurrent libraries on 9pay.vn's
`a916bea.js`:

- Vue 2.7.13 (the actual app framework, caught by banner_vue2)
- vue-i18n 8.28.2 (i18n plugin)
- core-js 3.6.4 (polyfill bundle)

Each emits a `.version="X.Y.Z"` literal. The rule's strict
`FunctionalRenderContext` anchor is what prevents the rule from picking
up vue-i18n's version as Vue's. Source-grounded specificity > loose
matching every time.
