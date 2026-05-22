# Owl Carousel — `?ver=` attribution scoping

**Status:** known, reconciler-mitigated. No lab rule INSERT required.
**Discovered:** 2026-05-21 during initial owl-carousel scan (envirotech.vn).

## The signal

WordPress vendors third-party libraries under
`/wp-content/plugins/<wp-plugin>/.../libs/owl-carousel/...` (or under themes).
WordPress's `wp_enqueue_script()` appends a `?ver=<X>` query param whose
value is the **enqueuing site's** version (often WordPress core), NOT the
vendored library's.

Worked example from `envirotech.vn` scan (2026-05-21):

```
URL    : /wp-content/plugins/ova-framework/assets/libs/owl-carousel/.../owl.carousel.min.js?ver=6.7.5
banner : 2.3.4   (extracted from file body — Owl Carousel comment header)
url-ver: 6.7.5   (extracted from ?ver= — actually WP 6.7.5 cache-buster)
```

The reconciler picks `banner` (`version_confidence: exact`) over `url-ver`, so
the user-visible answer (`version: 2.3.4`) is correct. The bug is purely in
the evidence trail, where `url-ver:owl.carousel -> 6.7.5` looks like
disagreement.

## Why no lab.db rule

Per CLAUDE.md §9 (survey first) and [[feedback_cve_no_redundant_lab_rule]]:
the version is already detected correctly by the banner rule
(`owl_carousel_banner`). Adding a URL pattern that REJECTS `?ver=` for
owl-carousel would not improve detection — it would only declutter the
evidence list. Not worth a rule on the hot path.

## Principled fix (deferred)

The general pattern is broader than owl-carousel: any time a stem matches a
known js-lib AND the URL is under a wrapper path (WP plugin / theme /
`vendor/` / `node_modules/`), the `?ver=` should be attributed to the
wrapper, not the vendored library.

If we ever address this, the right shape is a scanner-side data-driven
predicate (not a tech-specific branch), keyed off the URL path structure:

```
if url.path matches /wp-content/(plugins|themes)/<W>/.../<L>/...
   and <L> is a known js-lib stem:
   attribute `?ver=` to <W>, not <L>
```

This is §7a "uniform stage" thinking — would apply across all vendored
js-libs in WP installs (and analogously across Drupal/Joomla module dirs).
Until we see this misattribution cause a USER-VISIBLE wrong version (it
doesn't today, thanks to reconciler precedence), keep it as a backlog item.

## Backtest tail

Verified the banner rule wins consistently:

```
envirotech.vn   banner=2.3.4   url-ver=6.7.5   final=2.3.4  ✓
vatlieuhome.com banner=2.3.4   nuclei=2.3.4    final=2.3.4  ✓
```

No false-final-version cases observed in the partial scan (17/100 records).

## Related

- CLAUDE.md §7 "Reject ... wrapper versions belonging to a different tech"
- CLAUDE.md §9 survey-before-INSERT
- Slick (`lab_url_patterns` id=51, kind='cdn') uses a path-segment version
  pattern that already structurally avoids this issue — it requires the
  digits to follow `slick-carousel|slick` with no `?`/`#` in between.
