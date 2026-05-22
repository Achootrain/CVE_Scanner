# WordPress theme version-detection research

## Headline

Externally-observable WordPress theme detection had ZERO version coverage
before this work (4 nuclei theme templates exist but none extract version).
Result: **20 distinct theme slug + version pairs recovered** across the
WordPress corpus slice, applying a single source-grounded rule reusing the
existing SlugReadmeStage (extended once, generically).

## §6 Phase 1 -- Source acquire

- `git clone --sparse WordPress/wordpress-develop` -- sparse-checkout
  `src/wp-includes/`.
- Fetched the official Theme Handbook page for the style.css header
  spec verbatim (WP Theme Repository requires `Version` field).

## §6 Phase 2 -- Pattern extract

### The contract

Two source-of-truth artifacts in WP core:

1. **Field declaration** (`src/wp-includes/class-wp-theme.php:30-45`):

   ```php
   private static $file_headers = array(
     'Name'        => 'Theme Name',
     ...
     'Version'     => 'Version',
     ...
   );
   ```

2. **Header parser** (`src/wp-includes/functions.php:6979`):

   ```php
   preg_match(
     '/^(?:[ \t]*<\?php)?[ \t\/*#@]*' . preg_quote($regex, '/') . ':(.*)$/mi',
     $file_data,
     $match
   )
   ```

   Where `$regex = 'Version'`, the literal pattern WP core uses is:

   ```
   /^(?:[ \t]*<\?php)?[ \t\/*#@]*Version:(.*)$/mi
   ```

   Reads only the first 8 KiB of the file (`functions.php:6951`) -- exactly
   matches our `BodyExtractStage` window.

### The URL grammar (also source-grounded)

`/wp-content/themes/<slug>/style.css` -- canonical theme stylesheet path
per WP's theme loader. Slug is a filesystem directory name; WP performs
no validation on the format (`class-wp-theme.php` reads whatever
directory exists), so slug charset must allow dots, uppercase, and
underscores. The first iteration of this rule used
`[a-z0-9][a-z0-9_\-]*` and missed real corpus slugs like
`Newspaper12.7.3-child` and `vidi_v1.0`. Phase 4 widened to `[^/?#]+`.

## §6 Phase 3 -- Filtered backtest

Slice: every corpus target with `WordPress` detected (denominator from
`tech_counter`, per §11). For each: live re-fetch the homepage, extract
every `<link href>` / `<script src>` containing `wp-content/themes/.../style.css`,
apply the URL pattern to find the canonical theme stylesheet, fetch its
body (first 8 KiB), apply the source-grounded header regex.

## §6 Phase 4 -- Improve

Two iterations:

1. Iteration 1: 17 distinct slugs recovered. Misses included
   `Newspaper12.7.3-child` (root `style.css` but slug regex too narrow).
2. Iteration 2: slug widened to `[^/?#]+` per WP's no-validation behavior.
   20 distinct slugs recovered.

Remaining "misses" in the backtest output (4-5 URLs) are all nested
component CSS files like `/themes/flatsome/library/css/style.css` -- the
canonical theme stylesheet at the THEME ROOT is the only file with a
header block per WP's spec, so the rule correctly rejects these nested
URLs. The backtest's URL-extraction regex was deliberately loose
(includes nested) to surface these as a sanity check; the rule itself
is tight.

## §6 Phase 4b -- Persist

| Layer | What | Where |
|---|---|---|
| L3 | `lab_src_rules` row | id=156, section=`slug_url_rules` |
| L2 | per-tech rule file | `lab/research/wp-theme/rules_src.json` |
| L1 | snapshot.json | n/a -- `slug_url_rules` section is L2-only |
| Scanner | SlugReadmeStage extended to scan `ctx.url_pool` (small generic change, benefits ALL slug_url_rules including the existing wp-plugin one) | `fp/stages.py` |

## §6 Phase 5 -- Close

The 20 distinct slugs recovered span popular themes (flatsome, sahifa,
betheme, vantage, monatheme, Newspaper12.7.3-child, …) and many
custom Vietnamese-market themes. Combined with the existing plugin
readme rule and WordPress-core detection from Wappalyzer + nuclei, the
WordPress ecosystem coverage is now:

| Component | Channel |
|---|---|
| Core WordPress version | Wappalyzer `meta.generator` + nuclei `wordpress-detect` extractors (3 channels) |
| Plugin slug + version | lab `wp_plugin_readme` -> Stable tag in readme.txt |
| **Theme slug + version** | **lab `wp_theme_style` -> Version in style.css header (this work)** |
| Sub-techs (Block Editor, Multisite, etc) | Wappalyzer |

## What we did NOT add (and why)

- Per-theme rule rows (one per popular theme) -- §7 anti-pattern, the
  one slug_url_rule covers the whole class.
- Theme version probe at a known path -- the home page already
  references the canonical style.css; no additional probe needed.
- `nuclei`-style "theme-X-detect" overrides for the 4 themes with
  existing nuclei templates -- §9 says don't duplicate. nuclei's
  templates fire on file presence; our rule adds the version on top
  without conflict.

## Slugs to note

Some recovered slugs are clearly identifiers WP wouldn't validate
("Newspaper12.7.3-child", "vidi_v1.0", "Zephyr-child", "shop-ruou",
"cang-vu-hang-hai"). Filesystem reality > WP.org style guide: the rule
absorbs both.
