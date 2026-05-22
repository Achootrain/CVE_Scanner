# Bootstrap version-detection coverage on the dev corpus

## Headline

112 Bootstrap detections; 94 versioned (83.9%) before this work.
**24 unversioned cases triaged; 14 recovered by one banner rule.
New coverage: 108/112 = 96.4% (+12.5 pp).**

## Diagnosis (CLAUDE.md sec 8)

All 24 unversioned cases share the same pattern: self-hosted Bootstrap
where the URL carries no version (`bootstrap.min.css`,
`bootstrap.bundle.min.js`, sometimes renamed `sl-bootstrap.css`). The
existing lab rules covered only `bootstrapcdn.com/bootstrap/<ver>/` --
inventory-matching at the CDN-host level (sec 7 anti-pattern). The
underlying signal is independent of host.

Cause B (data plumbing): the right content (Bootstrap's minified
`.css` / `.js` body, with banner) was reachable for almost all cases,
but the only rule channel for Bootstrap was URL-pattern matching --
which is empty when the URL has no version. The funnel's
`BodyExtractStage` had no `banner_rules` row for Bootstrap to apply.

## Source-grounded signal (CLAUDE.md sec 6)

Bootstrap's release pipeline emits a `/*!` banner at the top of every
minified artifact:

```
/*!
 * Bootstrap v5.3.3 (https://getbootstrap.com/)
 * Copyright 2011-2024 The Bootstrap Authors
 * ...
 */
```

The `/*!` prefix is the standard "preserve through minification"
comment marker honored by uglify/terser/cssnano. Verified across:

- 3.4.1 (official jsdelivr mirror)
- 4.3.1, 4.4.1, 4.6.2 (official + 3 real corpus targets)
- 5.0.2, 5.3.3, 5.3.8 (official + 4 real corpus targets)

5.3.x CSS introduces an extra space (`Bootstrap  v5.3.3`), absorbed by
`\s+`. The signal -- token `Bootstrap` then optional `v` then dotted
version -- is stable across all three majors and is independent of
whether the file lives on cdnjs / jsdelivr / unpkg / self-hosted.

## Rule added

```sql
INSERT INTO lab_src_rules (
    tech_slug, rule_id, section, kind, pattern, extracts_json,
    applies_to, confidence, source_json
) VALUES (
    'bootstrap',
    'banner_bootstrap',
    'banner_rules',
    'banner',
    'Bootstrap\s+v?(\d+\.\d+(?:\.\d+)?)',
    '{"version": {"g": 1}}',
    'css/js body (first 8 KiB)',
    'high',
    '{...source citations...}'
);
```

Picked up by `stages.load_rules(..., section="banner_rules")` and applied
by `BodyExtractStage` against the first 8 KiB of every fetched
`bootstrap*.{css,js}` body. No code change; lab-scope preserved.

## Validation against the 24 unversioned corpus targets

Pulled each target's homepage, found Bootstrap-bearing `<link>` /
`<script src>`, fetched the asset, applied the rule:

| Outcome | Count | Notes |
|---|---:|---|
| Recovered (rule fires, valid version) | 14 | versions 3.4.1, 4.3.1-4.6.2, 5.0.2-5.3.8 |
| Banner stripped from asset             | 10 | Magento, NVCMS, bizweb.dktcdn, Portals/Skins white-labels |

## Why the remaining 10 are the structural ceiling

The 10 unrecovered cases all use **secondary minification pipelines**
that strip ALL comments including `/*!` (Magento's CSS minifier,
NVCMS's templating, bizweb.dktcdn.net's white-label bundler). Once
`/*!` is stripped, the version is no longer in the body. Recovery
would require either:

1. Behavioural fingerprinting (cipher set, CSS class shape diffs) -- sec 6
   violation (corpus-mined, not source-grounded).
2. Probing for a vendored marker file (e.g. `package.json` in a
   `vendor/twbs/bootstrap/` path) -- works for a slice of self-hosted
   PHP/Composer setups but is host-shape-specific and inventories
   server layouts. Not pursued.

Accept the 96.4% ceiling.

## sec 9 survey -- what existed, what we added, what we did not

Existed:
- `lab_url_patterns id=20`: `bootstrapcdn\.com/bootstrap/(...)` (host-pinned)
- `lab_pkg_aliases id=154`: `bootstrap -> Bootstrap`

Added:
- `lab_src_rules` banner_rule (this work)

Did not generalize the existing url_pattern rule -- the CDN-host
inventory rule is a different signal shape (URL token + version) from
the body banner. Both should exist; the body banner is the higher-value
channel.

Did not add additional `url_version_in_path_rules` for self-hosted
Bootstrap layouts (e.g. `/bootstrap-5.3.3/` or `/vendor/twbs/bootstrap/`).
These show up in the wild but the body banner already recovers them,
and they're URL-shape inventories which sec 7 explicitly warns against.
