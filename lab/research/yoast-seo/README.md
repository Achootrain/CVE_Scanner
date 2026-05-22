# Yoast SEO version-detection research

## Headline

20 corpus detections of Yoast SEO; 15 versioned (75%) via existing
upstream stack (Wappalyzer HTML comment, nuclei, retire.js), 5
unversioned. **All 5 unversioned cases are already coverable by existing
lab infrastructure** -- no new Yoast-specific rule needed. Two generic
plumbing fixes landed alongside, both source-grounded improvements
discovered during the §9 survey.

## §6 Phase 0/9 -- Survey first

| Source | Coverage | Channel |
|---|---|---|
| Wappalyzer | 14/20 versioned | `<!-- This site is optimized with the Yoast (?:WordPress )?SEO plugin v(...) -->` |
| nuclei | 1/20 versioned (plus 5 presence-only via `wordpress-wordpress-seo` template emitting long marketing copy as name) | `wordpress-detect` template's extractor + `wordpress-wordpress-seo` template's matcher |
| retire.js | 0 | (no Yoast fingerprint in retirejs.db) |
| lab.db | Two seeded aliases (`wordpress-seo -> Yoast SEO`, `yoast-seo -> Yoast SEO`); SlugReadmeStage's `wp_plugin_readme` rule applies | readme.txt Stable tag |

## §6 Phase 1+2 -- Source acquire and pattern characterisation

Live-probed all 5 unversioned slice targets for what version-disclosure
channels exist:

| Target | Yoast HTML comment | `/wp-content/plugins/wordpress-seo/readme.txt` Stable tag |
|---|---|---|
| 2game.vn        | stripped | **24.2** (premium also installed at 22.5) |
| avia.vn         | stripped | **18.6** |
| bazaarvietnam.vn| stripped | **21.1** |
| bkns.com.vn     | stripped | **24.9** |
| buv.edu.vn      | present (21.5) | **21.5** (channels agree) |

All 5 unversioned sites expose `Stable tag:` via the standard
`/wp-content/plugins/wordpress-seo/readme.txt` path. The existing
`wp_plugin_readme` rule + `SlugReadmeStage` recover all 5 on a fresh
scan; the corpus shows them as unversioned because it predates that
work.

## §6 Phase 4 -- Improvements landed during survey

### Fix 1: SlugReadmeStage now alias-resolves the canonical name

Before: SlugReadmeStage emitted `name='{slug}'` literally
(`wordpress-seo`). Wappalyzer emits `name='Yoast SEO'`. These have
different `_norm_name` keys -> reconcile creates two TechRecords for
the same plugin.

Fix: when `name_template == '{slug}'`, SlugReadmeStage now calls
`lookup_canonical_name(lab_db, slug)` and uses the alias-resolved name
when an actual row exists (not the title-cased-slug fallback). Templates
with explicit prefixes like `'wp-theme:{slug}'` skip alias lookup --
the prefix is the explicit disambiguator (theme slugs collide with
plugin slugs).

### Fix 2: pipeline._canonical_name_from_url now consults lab_pkg_aliases

Before: when nuclei emitted `name='Yoast SEO – Advanced SEO with
real-time guidance and built-in AI Detection'`,
`_canonical_name_from_url` rewrote it via the readme URL pattern to
`'wordpress-seo'` (the slug). Fix 1 above made SlugReadmeStage emit
`'Yoast SEO'`, but `_from_scanner` runs the URL normalizer on EVERY
detection -- so the readme-stage's `'Yoast SEO'` got immediately
overwritten back to `'wordpress-seo'`.

Fix: `_canonical_name_from_url` now does URL -> slug -> canonical
(alias-aware). Cached at module level for performance. Both layers
now agree: the URL `/wp-content/plugins/wordpress-seo/readme.txt`
resolves to canonical name `Yoast SEO` for both Wappalyzer's nuclei-
detected entries AND the readme-stage's emission. They reconcile into
one TechRecord.

Verified per-target reconcile on 2game.vn synthesis:

```
  name=Yoast SEO          version=24.2    sources=['nuclei', 'readme']
  name=wordpress-seo-premium  version=22.5  sources=['readme']
```

The premium variant has no alias row -- correctly stays as the bare
slug (don't fabricate canonical names for unknown slugs).

## §6 Phase 4b -- Persist

All work in this iteration is generic infrastructure or already-
persisted data:

| Item | Where | Persists across re-seed? |
|---|---|---|
| `wordpress-seo` and `yoast-seo` aliases | `lab_pkg_aliases` (L3) -- already seeded; mirrored in snapshot.json L1 | yes |
| SlugReadmeStage alias-aware tech_name | `fp/stages.py` (scanner code, git) | yes |
| `_canonical_name_from_url` alias-aware | `fp/pipeline.py` (scanner code, git) | yes |
| New Yoast-specific rule | NONE -- existing infra covers it | n/a |

## §6 Phase 5 -- Close

No Yoast-specific rule was added because none was needed: the existing
`wp_plugin_readme` rule + `SlugReadmeStage` + `lab_pkg_aliases`
together cover every observable channel for Yoast SEO. The two
plumbing fixes that landed alongside (alias-aware SlugReadmeStage
emission + alias-aware URL normalizer) are GENERIC -- they benefit
every WordPress plugin that has a `lab_pkg_aliases` row, not just
Yoast.

The Yoast research was a §9-only iteration of the loop: survey
found existing coverage adequate, the work that landed was fixing
two latent reconcile bugs that the survey EXPOSED.

## What we did NOT add

- Yoast-specific banner rule for the HTML comment -- Wappalyzer already
  has it; §5 says don't duplicate upstream.
- Yoast-specific JSON-LD parser -- probed 5 unversioned sites, no
  Yoast-mentioning JSON-LD that exposes the version anywhere we don't
  already get it.
- Override of nuclei's `wordpress-wordpress-seo` template name -- the
  URL-shape normalizer handles this generically for ALL WordPress
  plugin "X Detection" templates, not Yoast specifically.

## Side note: 2game.vn has two Yoast installs

Free `wordpress-seo` 24.2 AND premium `wordpress-seo-premium` 22.5 both
present and serving readme.txt. The premium is likely an older
abandoned install left behind during plugin migration; the active
plugin is the free 24.2. Worth flagging as an interesting case but
not actionable for the lab.
