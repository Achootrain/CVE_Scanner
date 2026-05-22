# Lab Research Report — Rule Mining & Back-Test

A short summary of the tooling shipped under `lab/research/` and what it produced when run against the existing fingerprinter scan corpus (`fingerprinter/scan_results.jsonl`, 253 targets, 71 Font Awesome-related tech detections across 69 distinct targets).

---

## Case study: Font Awesome — 0% → 31% version coverage

The end-to-end narrative the rest of this report describes in pieces.

### Step 1 — scan first, observe the gap
`fp pipeline` ran against 253 Vietnamese websites. Font Awesome was detected on **69 distinct targets** (71 detections across 3 name variants: `font-awesome`, `Font Awesome`, `Font Awesome Detection`), but the scanner could not pin a version on a single one: **0/71 = 0.0% version coverage**. Most detections came from nuclei's HTML pattern matching (seeing `fa-*` class names or `<i class="fa fa-...">` markup); the scanner recorded the HTML page as evidence but never walked to the actual FA file the page linked.

### Step 2 — download FA source and mine
Ran `mine_paths.py` against `lab/research/fontawesome/config.yaml`:
- **Downloaded** `FortAwesome/Font-Awesome` tag `7.2.0` zip from GitHub (codeload)
- **Scanned** every file under `css/*.css`, `js/*.js`, `package.json`, `**/_variables.scss`, `**/variables.less` for the literal byte string `7.2.0`
- **Cross-validated** each candidate path by re-fetching it for versions `4.7.0`, `5.15.4`, `6.7.2` and confirming each version's string appears in similar context
- **Distilled** the surrounding ±60 char context into a regex from the `regex_bank` (first match wins)

Output: **28 body rules + 4 URL patterns**.

#### The body rules (28x same family, different paths)
All 28 rules share one regex (the banner family won every candidate context); each pins a different path FA serves the banner at:
```
regex: Font Awesome (?:Free|Pro)\s+([0-9][\w.\-]*)
paths: /css/all.css, /css/all.min.css, /css/brands.css, /css/brands.min.css,
       /css/fontawesome.css, /css/fontawesome.min.css, /css/regular.css,
       /css/solid.css, /css/v4-shims.css, /css/v5-font-face.css, ...
       (28 CSS/JS bundle paths total)
validated_versions: ['7.2.0', '5.15.4', '6.7.2']
```

#### The URL patterns (4x, hand-curated post-mining)
Patterns the source tarball can't surface (CDN deployment URLs don't live in repo source):
```
1) use.fontawesome.com/releases/v?([0-9]+\.[0-9]+\.[0-9]+)
2) cdnjs.cloudflare.com/ajax/libs/font-awesome/([0-9]+\.[0-9]+\.[0-9]+)
3) maxcdn.bootstrapcdn.com/font-awesome/([0-9]+\.[0-9]+\.[0-9]+)
4) font[-_]?awesome[^?]*\?ver=([0-9]+\.[0-9]+(?:\.[0-9]+)?(?:[\w.\-]*)?)
```

Plus a parallel sweep across **10 WordPress plugins wrapping FA** produced:
- 17 primary rules pinning each plugin's own version (e.g. `Stable tag:` regex against the plugin's `readme.txt`)
- 55 bundled-tech rules pinning the FA library version *bundled inside* 4 of those plugins:
  - `better-font-awesome 2.0.4` ⇒ FA `4.7.0`
  - `eds-font-awesome 3.0.1` ⇒ FA `5.15.2` or `6.7.2`
  - `perfect-font-awesome-integration 2.3.1` ⇒ FA `6.7.1`
  - `wp-font-awesome 1.8.0` ⇒ FA `6.0.0`

### Step 3 — back-test against the same corpus
Ran the lab's `cross_host_walk_pass` + standard back-test against the original 69 FA-flagged targets:
- **Pass 1** (evidence-URL body fetches + URL-pool pattern matches): **4 / 69 targets** versioned (5.8%)
- **Pass 2** (cross-host HTML link walk — fetch each target's homepage, regex out `<link>` / `<script>` URLs, apply lab URL patterns): **+18 targets** versioned
- **Combined: 22 / 69 = 31.9% version coverage**

The single Cloudflare-Turnstile target (`anhemphim.com.vn`) blocked every strategy including Playwright.

### Step 4 — what the recovered versions look like

```
admon.com.vn        →  font-awesome plugin 5.1.5   AND  FA 6.6.0 (via use.fontawesome.com)
beetechno.com.vn    →  font-awesome plugin 5.1.4   AND  FA 6.4.2 (CDN)
accesstrade.vn      →  FA 4.7.0 (via maxcdn.bootstrapcdn.com/font-awesome/4.7.0/)
568play.vn          →  FA 6.6.0 (via cdnjs.cloudflare.com/ajax/libs/font-awesome/6.6.0/)
apec.com.vn         →  FA 3.4.3 + 5.13.0 + 6.9.4 (site serves multiple variants)
aznet.vn            →  FA 6.1.1 (use.fontawesome.com/releases/v6.1.1/)
ankhang.vn          →  FA 5.15.4 (cdnjs)
amcdn.vn / asin.com.vn / bejob.vn → FA 4.7.0 (cdnjs)
banhangvnpt.vn      →  FA 4.3.0 (maxcdn)
... 13 more
```

| Metric | Before lab | After lab back-test | Delta |
|---|---:|---:|---:|
| FA-flagged targets versioned | 0 / 69 | 22 / 69 | **+22 targets** |
| Version coverage | **0.0%** | **31.9%** | **+31.9 pp** |
| Distinct FA versions surfaced | 0 | 11 distinct (3.4.3, 4.1.0, 4.3.0, 4.6.2, 4.7.0, 4.11.53, 5.1.x, 5.13.0, 5.15.x, 6.x, 12.7.x) | — |

The remaining 47/69 are mostly targets whose HTML doesn't reference an absolute versioned URL: they either bundle FA into a webpack/Vite build artifact (no version in the asset path), use a privately-hosted unversioned `font-awesome.css`, or sit behind aggressive Cloudflare configurations.

---

## 1. Tools

### Rule miner — `lab/research/mine_paths.py`
Library/plugin-agnostic miner driven by a YAML config. Stages:
1. **Download** primary version's source tarball (`archive_url`)
2. **Scan** every text file matching `include_paths` for the literal primary-version byte string (`grep -F` equivalent), recording ±60 chars of context per hit
3. **Cross-validate** each candidate path against older versions via `raw_url` (per-tag raw fetch)
4. **Distill** a regex by matching the surrounding context against the config's `regex_bank` — first matching pattern wins
5. **Mine bundled techs** (new): for any `secondary_techs:` entry, apply that other tech's regex_bank to the plugin source tree to find versions of *bundled* libraries (e.g. FA shipped inside a WP plugin); records URL templates anchored to `/wp-content/plugins/<slug>/`

### Back-test engine — `lab/research/dashboard/backtest.py`
Applies lab rules against real-world targets recorded in the scanner's `scan_results.jsonl`. Four candidate kinds:
- **body** — fetch scanner's evidence URL, apply body regex
- **url** — apply URL-pattern regex to URL strings in the target's existing URL pool (no fetch)
- **bundled** — fetch a path constructed from `target_host + url_template` of a bundled-tech rule
- **html-walk** (cross-host pass) — fetch the target's homepage, regex-extract `<link href>` / `<script src>` references, apply URL patterns to the discovered cross-host URLs

### Shared HTTP layer — `fingerprinter/fetchlib/`
Single source of truth for both fp scanner and lab back-test. Owns:
- `CHROME_UA`, `BROWSER_HEADERS` (11 Chrome-121 headers)
- `BLOCK_SIGNATURES` + `detect_block()` — 13 vendor signatures (Cloudflare/Akamai/Sucuri/DataDome/Imperva/PerimeterX)
- `HostThrottle` — per-host min-gap + jitter scheduler
- Three fetcher strategies sharing one interface:
  - `RequestsFetcher` — vanilla `requests`, UA spoofing only
  - `CurlCffiFetcher` — `curl_cffi` with `impersonate="chrome120"` (TLS JA3/JA4 match — bypasses CF Bot Score)
  - `PlaywrightFetcher` — real headless Chromium with stealth init script (channel="auto" prefers system Chrome to avoid Windows Firewall prompts)

### Streamlit dashboards
- `fingerprinter/dashboard/` — scan launcher + scan-result analyzer + report exporter
- `lab/research/dashboard/` — catalog / inspect / new-tech / mine / back-test / stats tabs

---

## 2. Mining results

### Lab inventory
- **1 library**: `fontawesome` (FA core)
- **10 WordPress plugins** wrapping/bundling FA

### Per-plugin rule counts (after `secondary_techs: fontawesome` sweep)

| Plugin slug | Plugin v | Primary rules | Bundled rules | Bundled FA versions |
|---|---|---:|---:|---|
| `better-font-awesome` | 2.0.4 | 2 | 6 | **4.7.0** (+ noise from sibling iconpicker) |
| `eds-font-awesome` | 3.0.1 | 2 | 29 | **5.15.2** and **6.7.2** (plugin offers both) |
| `perfect-font-awesome-integration` | 2.3.1 | 1 | 18 | **6.7.1** |
| `wp-font-awesome` | 1.8.0 | 2 | 2 | **6.0.0** |
| `font-awesome` | 5.1.5 | 2 | 0 | (CDN-only, no bundled assets) |
| `advanced-custom-fields-font-awesome` | 6.0.2 | 2 | 0 | CDN-only |
| `block-for-font-awesome` | 1.7.7 | 2 | 0 | CDN-only |
| `shortcode-for-font-awesome` | 1.4.6 | 1 | 0 | CDN-only |
| `ss-font-awesome-icon` | 4.1.3 | 1 | 0 | CDN-only |
| `surbma-font-awesome` | 3.1 | 2 | 0 | CDN-only |

**Cross-mapping discovered**: 4 of 10 plugins ship FA assets in their tree (the others use a CDN); the bundled rules pin which FA version each plugin's release carries.

### Hand-curated URL patterns (lab/research/fontawesome/version_rules.json)
Added 4 `url_patterns` entries for FA's CDN distribution shapes:
- `use.fontawesome.com/releases/vX.Y.Z` (FA's official CDN)
- `cdnjs.cloudflare.com/ajax/libs/font-awesome/X.Y.Z`
- `maxcdn.bootstrapcdn.com/font-awesome/X.Y.Z`
- `font-awesome[^?]*?ver=X.Y.Z` (WP `?ver=` query-string convention, requires `X.Y` minimum to filter cache-bust timestamps)

Plus an auto-derived `?ver=` pattern from each lib's slug, so any new lab entry auto-gets WP asset-URL version extraction.

### Mining gotcha encountered
The `font-awesome` plugin's SVN tag `5.2.0-1` ships a `readme.txt` whose `Stable tag:` line still says `5.1.3` (release-day sloppiness). The miner's literal-string scan for `5.2.0-1` finds nothing in the readme and drops the readme rule. **Fix**: pin `primary: 5.1.5` in the config and let the miner work with a version that's actually present in `readme.txt`. Documented in the config's comments so future re-mines don't regress.

---

## 3. Back-test against the scan corpus

Corpus: `fingerprinter/scan_results.jsonl` — 253 scanned targets, 71 Font Awesome-related tech detections across 69 distinct targets (name variants: `font-awesome`, `Font Awesome`, `Font Awesome Detection`). Run: `curl_cffi` strategy, 0.3s min per-host delay, retry-on-block on.

### Coverage

| Phase | Targets versioned | Time |
|---|---:|---|
| Pass 1 — standard back-test (evidence URLs only) | 4 / 69 | 8s |
| Pass 2 — cross-host HTML link walk | +18 targets (additional beyond Pass 1) | 52s |
| **Combined** | **22 distinct targets** | **~60s** |

22/69 = **31.9% coverage** of FA-flagged targets. 1 target blocked by Cloudflare Turnstile (`anhemphim.com.vn`) even with Playwright — would need a CAPTCHA-solver service to crack.

### Versions extracted (sample)

Dual-extraction shape (plugin version *and* served FA version):

| Target | Plugin | Served FA |
|---|---|---|
| `admon.com.vn` | font-awesome plugin `5.1.5` | FA `6.6.0` (via `use.fontawesome.com/releases/v6.6.0/`) |
| `beetechno.com.vn` | font-awesome plugin `5.1.4` | FA `6.4.2` (CDN) |
| `apec.com.vn` | — | FA `3.4.3` + `5.13.0` + `6.9.4` (site serves multiple variants) |

Cross-host CDN extractions (where scanner alone couldn't see the FA URL):
- `accesstrade.vn` → FA `4.7.0` from `maxcdn.bootstrapcdn.com/font-awesome/4.7.0/`
- `568play.vn` → FA `6.6.0` from `cdnjs.cloudflare.com/ajax/libs/font-awesome/6.6.0/`
- `aznet.vn` → FA `6.1.1` from `use.fontawesome.com/releases/v6.1.1/`
- 18 more

### Why the other 47 targets didn't yield
- Most FA detections by the original scanner used HTML-pattern matching (nuclei seeing `fa-*` class names). In the corpus, 73/76 FA evidence entries have `path: "/"` (homepage HTML), and 3/76 point at `/wp-content/plugins/font-awesome/readme.txt` — none point at a FA bundle URL
- For those targets the homepage HTML may not link to a CDN URL containing the FA version directly (some use `font-awesome.css` with no version segment, or load FA via a build-step bundle)
- A handful behind Cloudflare Turnstile or 4xx-aggressive rate-limit

---

## 4. Key findings

1. **Scanner's evidence-URL shape is the bottleneck**, not the lab's rules. In the corpus, 73/76 FA evidence entries have `path: "/"` (homepage HTML) and 3/76 point at `/wp-content/plugins/font-awesome/readme.txt` — none point at a FA bundle URL. Recovering versions requires walking the HTML for cross-host references — done now in the lab side via `cross_host_walk_pass`, so no scanner changes needed.
2. **Generic regex patterns work across the whole lab.** The same `Stable tag:` regex extracts every WP plugin's version; the same `Font Awesome (?:Free|Pro) X.Y.Z` regex matches every FA5+ CSS banner. Per-plugin mining only matters for *where* a pattern was first discovered — at runtime the universal pattern pool re-applies them across all detections.
3. **Plugin → bundled-tech mapping is mineable.** Adding `secondary_techs:` to a plugin config produces explicit cross-mapping rules (e.g. BFA 2.0.4 ⇒ FA 4.7.0) without separate tooling. Four plugins in this lab now carry that mapping; six don't because they CDN-load.
4. **TLS impersonation is often necessary for bot-fronted targets**. Vanilla `requests` gets soft-blocked on Cloudflare-fronted real-world targets; `curl_cffi` with `impersonate="chrome120"` passes JA3/JA4 fingerprint checks. Playwright unlocks JS-challenge gates but doesn't help against Turnstile.

---

## 5. Next steps (deferred)

- Extend `secondary_techs:` to other lab entries (jQuery, Bootstrap, etc.) when added via the New-tech dashboard tab
- Tighten BFA's `path_filter` from `font[-_]?awesome[-_/]` to `font[-_]?awesome/` (require trailing slash) to drop the iconpicker noise (4 false-positive bundled rules)
- Wire the cross-host walk into the fingerprinter scanner itself (`fp/scanner.py`) so the scan record carries the cross-host URLs as evidence, removing the need for the back-test second pass
- For Cloudflare Turnstile targets: integrate a CAPTCHA solver or skip them as "browser-required, manual review only"
