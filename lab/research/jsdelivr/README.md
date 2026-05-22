# jsDelivr URL-scheme research

## Source of truth

- Docs page: https://www.jsdelivr.com/?docs=gh (npm + GitHub schemes)
- Verified by downloading real URLs (see "Download evidence" below)

## Documented URL forms

### `/npm/<pkg>@<version>/<path>`

- `<pkg>`: npm package name. Scoped form `@<scope>/<name>` allowed.
- `<version>`: one of
  - **Exact**: `1.2.3` -- pins to that release.
  - **Range (2-part)**: `1.2` -- jsDelivr resolves to latest matching `1.2.x`.
  - **Range (1-part)**: `1` -- resolves to latest matching `1.x.x`.
  - **Alias**: `latest` -- resolves to latest published version.

### `/gh/<user>/<repo>@<version>/<file>`

- `<version>`: a git tag, branch, or commit. Only tags shaped as dotted-numeric
  carry semantic version information; branches (`main`, `master`) do not.

## Download evidence (verification, not rule discovery)

| URL form | HTTP | Body banner version |
|---|---|---|
| `/npm/bootstrap@5.3.3/...`  | 200 | **5.3.3** |
| `/npm/bootstrap@5.3/...`    | 200 | 5.3.8 (range alias) |
| `/npm/bootstrap@5/...`      | 200 | 5.3.8 (range alias) |
| `/npm/bootstrap@latest/...` | 200 | 5.3.8 (alias) |
| `/npm/@popperjs/core@2.11.8/...` | 200 | n/a (no banner ver in popper bundle for that range) |
| `/gh/jquery/jquery@3.6.4/...`    | 200 | 3.6.4 |
| `/gh/jquery/jquery@main/...`     | **404** | n/a (branch not snapshot) |

## Rule authored

Single row in `lab_url_patterns` (id=53):

```
pattern:        jsdelivr\.net/npm/((?:@[a-z0-9][a-z0-9._\-]*/)?[a-z0-9][a-z0-9._\-]*)@(\d+\.\d+(?:\.\d+)?)
tech:           NULL   -- captured from pkg_group, looked up in lab_pkg_aliases
pkg_group:      1
version_group:  2
kind:           cdn
origin:         research:jsdelivr-npm
```

### Why MAJOR.MINOR(.PATCH) is required by design (CLAUDE.md sec 7)

The download evidence above is decisive: `@5` and `@5.3` are **range aliases**,
not version disclosures. The URL `cdn.jsdelivr.net/npm/bootstrap@5/...` serves
Bootstrap 5.3.8's body -- treating the URL `@5` as "version 5" would emit a
precision the URL did not actually carry. The regex's mandatory `\.\d+`
component rejects range-alias forms while still capturing every legitimate
pinned-version URL. This is what sec 7 calls "thinking about the signal" --
the signal is "the URL pinned a specific version" not "there was a digit
after @".

A future researcher tempted to widen the regex to also capture `@5` should
re-read this paragraph.

## Scope-creep skipped (sec 3 surgical, sec 9 generalize-first)

- `/gh/<user>/<repo>@<tag>/` -- different URL shape, would need a separate
  pattern with branch/commit rejection. No corpus hits in current dataset.
  Defer; add only when a real hit accumulates.
- `/wp/plugins/<slug>/tags/<ver>/` -- different shape, wp slug lookup needs
  WP_PLUGIN_MAP not _CDN_PKG_MAP. Defer.
- `cdnjs.cloudflare.com/ajax/libs/<pkg>/<ver>/` -- same conceptual signal
  shape but different host. Existing seeded rules cover cdnjs; revisit if
  coverage gaps surface.

## Loop closure (2026-05-17)

After three loop iterations (CLAUDE.md §6 phases), closing here. **jsDelivr
is a CDN, not a versioned tech in its own right.** The jsDelivr URL rule's
purpose is a fast-path extraction of `(library, version)` from URL shape
BEFORE any body fetch. It is a SHORTCUT for the body-channel banner rules
that BodyExtractStage already runs on every fetched `.min.js`/`.min.css`.

Final coverage on the 37-target dashboard slice (live re-fetch, ~40 URLs):

- **18 hits** via /npm/ + /gh/ rules: Bootstrap, jQuery, Popper.js, Slick,
  Day.js, GSAP, Splide Auto Scroll, Splide Intersection, Select2.
- **8 intentionally-rejected** range aliases (`@MAJOR`, `@MAJOR.MINOR`) --
  cited from `is-semver-static` regex; the body-banner channel
  catches these libs from the served file content.
- **5 legacy form** (`/bootstrap/3.3.7/`, `/bxslider/4.2.12/`, `/html5shiv/3.7.3/`) --
  no public project allowlist available in jsDelivr source; all three
  libs ARE covered by independent body-banner / Wappalyzer / retire.js
  rules, so the URL fast-path miss does not translate to a coverage miss
  at the pipeline level.
- **~5 alias gaps** (lenis, intersection-observer-polyfill,
  ie11CustomProperties, etc.) -- niche libs whose body channels (banner,
  retire.js fingerprint) already provide detection. Adding alias rows is
  cheap but redundant on this corpus.

**Stop condition met (§6 phase 5):** every remaining miss is either
cited-as-intentionally-rejected (range alias, no precise version possible)
or covered by an independent funnel channel. The URL fast-path's job is
done; remaining work is in body-channel rules per individual library,
not in jsdelivr-the-CDN.

## Corpus validation

7 jsDelivr URLs in the dev corpus, all `/npm/` form, all exact versions:

| URL                                                          | Captured pkg          | Version |
|--------------------------------------------------------------|-----------------------|---------|
| `/npm/@popperjs/core@2.9.2/dist/umd/popper.min.js`           | `@popperjs/core`      | 2.9.2   |
| `/npm/bootstrap@4.5.3/dist/js/bootstrap.bundle.min.js`       | `bootstrap`           | 4.5.3   |
| `/npm/bootstrap@4.6.0/dist/css/bootstrap.min.css`            | `bootstrap`           | 4.6.0   |
| `/npm/bootstrap@5.0.1/dist/js/bootstrap.min.js`              | `bootstrap`           | 5.0.1   |
| `/npm/dayjs@1.8.36/dayjs.min.js`                             | `dayjs`               | 1.8.36  |
| `/npm/jquery-validation@1.17.0/dist/jquery.validate.min.js`  | `jquery-validation`   | 1.17.0  |
| `/npm/jquery@3.6.0/dist/jquery.min.js`                       | `jquery`              | 3.6.0   |

7/7 URLs captured; pkg lookup in `lab_pkg_aliases` resolves the canonicals
(Bootstrap, jQuery, Popper.js, Swiper, ...). `dayjs` and `jquery-validation`
have no alias row yet -- they would emit no detection until aliases land.
That is the right failure mode: an unknown pkg should not be wishful-
named, it should be flagged for a follow-up alias addition.
