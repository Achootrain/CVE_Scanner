# How CDNs and modern build pipelines hide library versions

Research notes on the signal: when, why, and how does a library version
disappear from URLs between the developer's source code and the rendered HTML
a scanner sees? Organised by mechanism, with attribution and recovery channels.

## The general signal

Every detection scanner exploits the same chain:

```
source release  ->  developer/build pipeline  ->  CDN/server  ->  HTML in browser
                          |                         |
                          v                         v
                    (may alter URL)          (may rewrite URL)
                          |                         |
                          v                         v
                   what reaches the scanner is the END of this chain
```

A version is "hidden" when somewhere in that chain the chain step drops,
rewrites, or replaces the version marker. The hiding is sometimes
**intentional** (anti-scanning, anti-fingerprinting), but the overwhelmingly
common cause is **incidental** -- a build-tool default that was chosen for
cache-busting, immutability, or aesthetics, and that happens to drop the
version as a side effect.

Distinguishing the two matters for response strategy. Incidental hiding
yields to body-fetching the asset (the banner survives even when the URL
forgets); intentional hiding plus active bot management does not.

## Mechanism catalog

Eleven categories observed in real corpus + documented in upstream tools.
Each entry has: **WHAT** (the signal observed), **WHO** (tools/CDNs that
produce it), **WHY** (the engineering reason), **EXAMPLE** (concrete URL),
**RECOVERY** (which channel can still extract a version).

### 1. Version embedded in URL

  **WHAT** Library token and dotted-semver coexist in URL, separated by
  URL-conventional characters.

  **WHO** Canonical CDNs that mirror npm/GitHub releases: cdnjs, jsDelivr
  (`/npm/<pkg>@<ver>/`, `/gh/<owner>/<repo>@<tag>/`), unpkg, BootstrapCDN,
  FA's own `use.fontawesome.com/releases/v<ver>/`. Also self-hosted sites
  preserving release-tarball directory naming
  (`Font-Awesome-7.2.0/`, `slick-1.8.1/`).

  **WHY** Mirror is built to be cache-immutable per-version. URL IS the
  version pin.

  **EXAMPLE** `https://cdnjs.cloudflare.com/ajax/libs/font-awesome/4.7.0/css/font-awesome.min.css`

  **RECOVERY** URL pattern: proximity match between token and dotted-semver.

### 2. Query-param cache-buster

  **WHAT** Asset URL has no version in path; the `?ver=`/`?version=`/`?v=`
  query param carries a version-shaped value.

  **WHO** WordPress is the dominant source (`wp_enqueue_style` /
  `wp_enqueue_script` default behaviour appends `?ver=$version`). Many
  PHP-template ecosystems copy the convention.

  **WHY** Cache busting at the CDN/browser layer without per-version
  directory structure on disk. Developer ergonomics: one path, version
  bumps automatically.

  **EXAMPLE** `https://example.com/wp-content/plugins/contact-form-7/includes/css/styles.css?ver=5.8.4`

  **RECOVERY** URL pattern: token + `[?&](?:ver|version|v)=<semver>`.
  **Caveat that matters:** when the asset is BUNDLED inside a wrapper
  (an Elementor template ships its own copy of FA at
  `wp-content/plugins/elementor/.../font-awesome/?ver=3.4.3`), the `?ver=`
  reflects the WRAPPER'S version, not the bundled lib's. This is an
  irreducible ambiguity at the URL level. Resolved by body-fetching the
  asset and reading the banner.

### 3. Content-hash filename (webpack/vite/parcel/rollup)

  **WHAT** Library shipped under a content-hash filename. The version is
  intentionally REMOVED in favour of a per-build hash. Webpack default
  output template is `[name].[contenthash].js` producing names like
  `main.7e2c49a622975ebd9b7e.js` (confirmed: 20-char hex hash, source:
  webpack.js.org/guides/caching/). Vite, Parcel, Rollup use similar
  schemes (8-12 char default in vite).

  **WHO** Any project using webpack/vite/parcel/rollup with the default
  asset-naming. Common in Next.js (`/_next/static/chunks/...`), Nuxt
  (`/_nuxt/`), SvelteKit (`/_app/immutable/`), modern React/Vue SPAs.

  **WHY** HTTP-cache immutability. The bundler guarantees: same content
  -> same hash -> infinite cache TTL. Version-as-filename is incompatible
  with this guarantee because content can change without a release.

  **EXAMPLE** `https://example.com/_next/static/chunks/vendors-c4f2a91b.js`

  **RECOVERY** URL pattern: useless. Body fetch CAN work if the bundle
  preserved the library's banner comment (most minifiers strip comments
  but banners with `/*!` are preserved by default in terser/uglify).
  Otherwise, scan the bundle for tech-specific signatures: FA glyph
  unicode codepoints, jQuery's `var jQuery=` source-level marker, etc.

### 4. Kit / loader scripts (opaque ID)

  **WHAT** A small JS shim at an opaque-ID URL that bootstraps the real
  library. The URL contains no version; version is a server-side config
  for that ID.

  **WHO**
  - **FA Cloud (legacy)** at `use.fontawesome.com/<10-hex-chars>.js`,
    pre-2018. JS body is `window.FontAwesomeCdnConfig = { code: "<id>", ... }`
    and asset-loading logic. **NO version anywhere in the body** --
    confirmed empirically on two corpus kits (`f455f83be3.js`, `b6de74fbb9.js`,
    ~9.5 KB each).
  - **FA modern Kit** at `kit.fontawesome.com/<id>.js`. Documented at
    docs.fontawesome.com: the kit's FA version is a USER-CHOSEN setting on
    the FA dashboard, defaults to "Latest (auto-updates to whatever the
    latest release is)". The version IS stored server-side; whether it
    leaks into the kit JS body is undocumented and varies.
  - Auth0, Stripe.js, Intercom, Segment Analyse: same architecture -- a
    bootstrap shim at a customer-account-scoped URL.

  **WHY** Vendor wants flexibility to change library version without
  customer redeploy. Vendor also wants to attribute usage per customer
  account.

  **RECOVERY** URL pattern: nothing (the ID is not a version, will never
  be a version). Body fetch: works for some kits (modern FA may emit
  version metadata in the kit JS source), fails for others (legacy FA
  Cloud kits are truly opaque). Beyond static analysis: vendor APIs
  may resolve <id> -> version, but typically require authentication.

### 5. Hashed asset paths via CDN transform

  **WHAT** CDN/edge service rewrites asset URLs to opaque hashes. The
  origin still serves versioned paths; the public-facing URL is rewritten.

  **WHO** Cloudflare Polish / Mirage / Pages, Fastly Image Optimizer,
  Vercel's automatic image optimisation (less so for JS/CSS but
  conceptually similar), some Squarespace/Webflow asset pipelines.

  **WHY** Performance optimisation (CDN can serve a transformed variant
  -- compressed image, autoprefixed CSS) while pinning the URL to its
  cache identity rather than the source identity.

  **EXAMPLE** `https://example.com/__cf__/asset/1a2b3c4d-fontawesome.min.css`

  **RECOVERY** Body fetch -> banner regex (the body is usually still the
  unmodified asset content for non-image types).

### 6. Vendor-front CDN subdomain (reverse proxy)

  **WHAT** Site fronts a generic CDN behind its own subdomain. URL
  reveals nothing about origin or version.

  **WHO** Custom asset domains: `cdn.example.com`, `static.example.com`,
  `assets.example.com`. Common for sites using Cloudflare Worker or
  NGINX as an asset reverse-proxy.

  **WHY** Branding, performance (single-origin cookies/CORS savings),
  security (origin server hidden).

  **EXAMPLE** `https://cdn.example.com/lib/font-awesome.min.css`

  **RECOVERY** Body fetch -> banner.

### 7. Stripped path (clean URLs)

  **WHAT** Site serves the unversioned filename verbatim with no
  cache-buster, no hash, no embedded version.

  **WHO** Rails sprockets in legacy config, Django collectstatic without
  the versioning addon, hand-built nginx configs, themes that hand-roll
  asset loading.

  **WHY** "Pretty URLs" aesthetic, or developer didn't configure
  versioning.

  **EXAMPLE** `https://example.com/static/css/font-awesome.min.css`

  **RECOVERY** Body fetch -> banner. Same channel as #5/#6; this is the
  category that lab body-fingerprint rules exist for.

### 8. Inlined CSS / JS

  **WHAT** No URL at all -- the library's CSS or JS is included verbatim
  in `<style>` / `<script>` tags in the HTML.

  **WHO** Critical-CSS pipelines (Next.js inlines critical, Astro
  inlines stylesheet content under threshold, Eleventy with bundler
  plugins, lots of homegrown PHP themes). FOUC-prevention SPAs.

  **WHY** Render-blocking-resource performance score.

  **RECOVERY** Run banner / class-signature regex against the HTML body
  directly, scoped to `<style>` and `<script>` contents.

### 9. JS-injected loaders

  **WHAT** Library URL is constructed and inserted at runtime by JS.
  Static HTML has no `<link>` / `<script>` for the library.

  **WHO** Single-page apps with code-splitting, async module loaders
  (RequireJS in legacy projects, dynamic `import()` in modern), remote
  config-driven asset loading (`fetch('/manifest.json').then(loadIt)`).

  **WHY** Code-splitting, lazy loading, A/B testing infra.

  **RECOVERY** Browser rendering (Playwright) to observe the final DOM
  or the network log. Static analysis can grep the page JS for the
  library token but version extraction usually needs runtime to construct
  the URL.

### 10. Bundle inlining (library vendored into app bundle)

  **WHAT** Library compiled into a single application JS bundle along
  with everything else. No separate URL.

  **WHO** Common in Webpack/Vite/Rollup builds with `optimization.splitChunks`
  not configured. Also common in Browserify-era code, and in modern
  bun.build outputs.

  **WHY** Reduce request count.

  **RECOVERY** Body fetch the bundle; banner regex (if banner survived
  minification); or library-specific signature regex (FA glyph unicode,
  jQuery `var jQuery=function`, etc.). Versionless library presence may
  still be detectable even when version is not.

### 11. Active bot management (intentional blocking)

  **WHAT** The legitimate asset URLs never reach the scanner. The CDN
  returns a challenge page, 403, 429, or a cloaked variant.

  **WHO** Cloudflare Bot Management ("I am under attack" + Turnstile),
  Akamai Bot Manager, Imperva/Incapsula, DataDome, PerimeterX/HUMAN.

  **WHY** Anti-scraping, anti-vulnerability-scanning, account-takeover
  prevention.

  **EXAMPLE** Response: `HTTP 403`, body contains "ddos protection by
  cloudflare" + `<title>Just a moment...</title>`.

  **RECOVERY** TLS-fingerprint impersonation (curl_cffi with chrome120)
  defeats basic JA3-fingerprint detection. Cloudflare Pro "I am under
  attack" + Turnstile challenge requires a real browser solving JS work.
  `fp/cdn_check.py` detects these blocks so the pipeline can record
  "blocked" instead of silently returning no detections.

## Intent: who's hiding, and why?

| Category | Intent | Frequency in corpus |
|---|---|---|
| 1 Direct | n/a (canonical) | Common |
| 2 ?ver= cache-buster | Incidental (cache-busting) | Very common (WP-heavy) |
| 3 contenthash | Incidental (immutability) | Growing fast (modern SPAs) |
| 4 Kit/opaque ID | Incidental (vendor flexibility) | Rare in corpus, growing |
| 5 CDN transform | Incidental (perf) | Rare |
| 6 Vendor-front CDN | Incidental (branding/security) | Common |
| 7 Stripped | Incidental (aesthetic/laziness) | Common |
| 8 Inlined | Incidental (perf) | Moderate |
| 9 JS-injected | Incidental (code-split) | Moderate |
| 10 Bundle-inlined | Incidental (perf) | Growing (modern SPAs) |
| 11 Bot management | **Intentional** | Rare in corpus, devastating where present |

The takeaway: **almost all version-hiding is incidental.** The build-tool or
deployment choice was made for caching/performance/aesthetics, with no anti-
scanner intent. This is good news for the scanner -- the body of the asset
usually still carries the canonical banner; the URL just stopped advertising
it. Body-fetch banner extraction recovers most of #2 (wrapper case), #5, #6,
#7, #8 (inline-scoped), #10 (if banner-preserved).

Category 4 (kit / opaque ID) and category 11 (active bot management) are
where the URL-pattern channel and body-fetch channel both fail.

## Implications for the lab/scanner architecture

| Recovery channel | Covers | Where in codebase |
|---|---|---|
| URL-pattern proximity matching | 1, 2 (URL-side) | `fp/url_ver.py` reading rules from `lab_url_patterns` (DB-driven; rules authored in `lab/research/<tech>/rules_src.json`) |
| Body fetch + banner regex | 2 (resolve wrapper ambiguity), 3 (when banner preserved), 5, 6, 7, 8, 10 (when banner preserved) | `lab/research/<tech>/detect_src.py` body-fetch stage + `banner_rules` in `lab_src_rules` |
| Inline HTML scan | 8 | Same body regex applied to `<style>`/`<script>` block contents in the HTML response itself |
| Library-specific signatures (class names, glyph codepoints) | 3, 10 (when banner stripped) | Not yet implemented; per-tech `css_class_rules` in `lab_src_rules` is a start |
| Browser rendering | 9, 10 (deep), 11 (Turnstile) | Playwright fetcher in `fetchlib/`, invoked on demand |
| TLS impersonation | 11 (basic) | `fetchlib.CurlCffiFetcher` is the default |

## Why "research about how CDNs hide version" matters more than rule consolidation

Per the methodology in CLAUDE.md sections 6+7, rule authoring should start
from understanding the signal's variations across all the obfuscation
mechanisms above, NOT from the URL shapes a particular corpus happens to
contain. The categories above are the catalog of variations; the rules need
to reach as far down the catalog as URL-pattern matching can stretch and
then hand off cleanly to body-fetch.

The temptation when researching a new tech is to:
1. Mine its dev corpus for URL shapes.
2. Author one rule per observed shape.
3. Decide the rule set is "complete" when corpus recall plateaus.

Steps 1-3 catch categories 1+2 only. The plateau is the corpus's exposure
to those categories, not the rule pack's coverage of the signal. A rule pack
that ignores #3 #5-#10 will silently fail every time the corpus rotates
toward modern build-pipeline-heavy sites (more SPAs, more contenthash, more
inlining).

The correct authoring path:
1. Author 1-2 URL-proximity rules (cover #1+#2).
2. Author 1 banner rule that the lab detector applies to body fetches (covers
   #2-wrapper, #5, #6, #7, #8-inline, #10-banner-preserved).
3. Optionally add class-prefix / glyph-codepoint signature rules for the
   tech (covers #3 / #10 with banner stripped).
4. Mark #4 (opaque kit) and #11 (bot management) as out-of-scope-for-static
   and rely on browser rendering + dedicated tooling.

For FA + Slick the existing rules already implement (1)-(2). Step (3) is
where future deepening yields the most marginal coverage.
