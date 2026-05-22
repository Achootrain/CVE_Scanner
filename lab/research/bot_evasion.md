# How bot management fingerprints clients, and how to look like a browser

Companion to `cdn_obfuscation.md`. That document covered ten obfuscation
mechanisms where the version disappears from URLs and bodies; nine of them
yield to body-fetch + banner regex. The tenth was **active bot management**
(category #11) -- the case where the legitimate asset URLs never reach the
scanner because the CDN flagged the client as a bot and served a challenge
page, a 403, or a cloaked variant.

This document is about that case. What does bot management actually
measure, and what does it take to pass for a browser?

## The stack of fingerprintable signals

Each layer of the network stack and each browser-level API surface emits
identifying signals. Bot management scores a session by combining signals
from many layers; failing any one of them may not block, but failing
several pushes the score over the threshold.

```
+------------------------------------------------+
|  Layer 7 -- behavioural                        |   mouse, scroll, dwell,
|             event-loop timing, focus changes   |   keystroke cadence
+------------------------------------------------+
|  Layer 6 -- JS runtime / Web APIs              |   navigator, screen,
|             canvas, WebGL, audio, fonts, perf  |   plugins, languages,
|                                                |   timezone, codecs
+------------------------------------------------+
|  Layer 5 -- HTTP/2 (or HTTP/3 QUIC)            |   SETTINGS frame,
|             stream multiplexing                |   pseudo-header order,
|                                                |   HPACK dynamic table
+------------------------------------------------+
|  Layer 4 -- HTTP/1.1 request shape             |   header order,
|                                                |   capitalisation,
|                                                |   Accept-* values,
|                                                |   Sec-CH-* hints
+------------------------------------------------+
|  Layer 3 -- TLS ClientHello                    |   JA3 / JA4 / JA4+
|             ciphers, extensions, curves,       |   GREASE
|             signature algorithms, ALPN         |
+------------------------------------------------+
|  Layer 2 -- TCP                                |   JA4T -- options,
|             window size, MSS, options order    |   timestamp, ECN
+------------------------------------------------+
|  Layer 1 -- IP / ASN reputation                |   IP rep DBs,
|             geo coherence with UA, hosting     |   datacenter ASN
+------------------------------------------------+
```

The lower the layer, the harder it is to forge: a Python `requests` client
can swap any HTTP header (layer 4), but it cannot rewrite its TCP options
without OS support (layer 2). The higher layers (6+) require either a real
browser or extensive emulation.

## Per-layer detail

### Layer 1 -- IP / ASN reputation

  **WHAT** Source IP belongs to a known datacenter ASN (AWS, GCP, Azure,
  Hetzner, Vultr, OVH, DigitalOcean). Residential IPs from Vietnamese ISPs
  score very differently from a Hetzner box.

  **DETECT** Cloudflare, Akamai, Imperva all consult IP reputation lists
  (Spamhaus, AbuseIPDB, internal blocklists from previous blocked traffic).
  Datacenter-origin requests are automatically suspicious; the bot score
  starts elevated even before headers are inspected.

  **EVASION COST** Residential proxies cost $5-15/GB. Mobile proxies more.
  Free tier: none.

  **OUR POSITION** Out of scope for the scanner. We accept being seen as a
  datacenter origin.

### Layer 2 -- TCP fingerprint (JA4T)

  **WHAT** Initial TCP options ordering, window size, MSS, presence/order
  of timestamp, ECN, SACK-permitted, window-scale. Linux/Windows/macOS
  defaults are distinct enough to fingerprint the OS reliably.

  **DETECT** JA4T (from FoxIO-LLC/ja4 family) extracts a structured
  fingerprint from the SYN packet. Mismatch between TCP-claimed OS and
  TLS-claimed OS (Layer 3 cipher set) flags as forged.

  **EVASION COST** Requires raw-socket or eBPF-level patching of the OS
  TCP stack to mimic a target OS. Practically: spin up the matching VM
  type, or use a TCP-rewriting proxy like p0f-based middleboxes.

  **OUR POSITION** We run as a regular process; our TCP stack is whatever
  the Windows/Linux kernel provides. We do not currently mimic TCP layer.

### Layer 3 -- TLS ClientHello fingerprint (JA3 / JA4)

  **WHAT**
  - **JA3** (Salesforce, 2017): MD5 of `version,ciphers,extensions,curves,formats`
    extracted from ClientHello. Order matters; 32-char hex output.
  - **JA4** (FoxIO, 2023+): sorts ciphers and extensions to defeat the
    "cipher stunting" evasion, adds signature algorithms, ALPN, SNI.
    Structured `a_b_c` output (`t13d1516h2_8daaf6152771_02713d6af862`)
    allowing partial / locality-preserving matching.
  - **GREASE values** (RFC 8701): Chrome injects random "GREASE" code
    points into the cipher list / extension list. JA3 filters them; not
    filtering is itself a flag.

  **DETECT** Cloudflare/Akamai/Imperva all match the observed JA3/JA4
  against a database of known browser fingerprints. A Python `requests`
  client emits a recognisable Python-OpenSSL fingerprint that doesn't
  match any browser entry; this alone scores 90+ bot.

  **EVASION COST** TLS-impersonation libraries solve this: `curl_cffi`
  uses a patched BoringSSL with browser cipher orderings and GREASE;
  `python-tls-client`, `httpx` with `httpx-impersonate`, Go's `utls`.
  Profile must match the claimed User-Agent (chrome120 UA + chrome120
  TLS fingerprint).

  **OUR POSITION** `fetchlib.CurlCffiFetcher` uses curl_cffi with
  `impersonate="chrome120"`. Cipher list, extensions, GREASE all match
  Chrome 120 desktop. This is the single biggest unlock for getting
  past basic bot management.

### Layer 5 -- HTTP/2 fingerprint

  **WHAT**
  - **SETTINGS frame values**: `HEADER_TABLE_SIZE`, `INITIAL_WINDOW_SIZE`,
    `MAX_CONCURRENT_STREAMS`, `MAX_HEADER_LIST_SIZE`. Each browser has
    distinct default values.
  - **Pseudo-header order**: `:method`, `:authority`, `:scheme`, `:path`
    -- Chrome sends in `m,a,s,p` order, Firefox uses `m,p,a,s`. Many
    HTTP/2 libraries default to alphabetical, which matches no browser.
  - **HPACK dynamic table behaviour**: which headers go into the table,
    in what order.
  - **WINDOW_UPDATE timing** and other early control-frame patterns.

  **DETECT** Akamai and Cloudflare specifically extract H2 fingerprints.
  Many JS-runtime-perfect scrapers still get blocked here because their
  HTTP/2 layer (typically `httpx` defaults) doesn't match their claimed UA.

  **EVASION COST** Most HTTP libraries don't expose this layer. curl_cffi
  + `hyper` (Rust) tuned via specific knobs can match. `python-tls-client`
  handles SETTINGS but not pseudo-header order. The Akamai engineering
  blogs document this as one of their highest-precision signals.

  **OUR POSITION** curl_cffi chrome120 also handles H2 -- the impersonation
  profile covers TLS + H2 together. This is one of the reasons curl_cffi
  is the right default for unauthenticated scanning.

### Layer 4 -- HTTP/1.1 headers shape

  **WHAT**
  - **Header order**: real browsers send headers in a stable order
    (Chrome: Host, Connection, sec-ch-ua, sec-ch-ua-mobile, ...).
    Python `requests` sorts alphabetically by default.
  - **Header capitalisation**: HTTP is case-insensitive but browsers
    send canonical capitalisation (`User-Agent`, `Accept-Encoding`).
    Curl in default mode emits `Accept-Encoding`; raw Python sends
    whatever you wrote.
  - **Accept-Language**: missing or lowercase signals bot. Chrome sends
    `en-US,en;q=0.9` (or matching locale).
  - **Sec-CH-UA hints**: `Sec-CH-UA: "Not_A Brand";v="8", "Chromium";v="120"`,
    `Sec-CH-UA-Mobile`, `Sec-CH-UA-Platform`. Chrome 90+ ships them; absence
    in a UA claiming Chrome 120 is a tell.
  - **Sec-Fetch-***: `Sec-Fetch-Dest: document`, `Sec-Fetch-Mode: navigate`,
    `Sec-Fetch-Site`, `Sec-Fetch-User`. Modern Chrome always sends these
    on navigation requests; absence + Chrome UA = bot.

  **DETECT** Cheap, high-precision. Header ordering and missing Sec-* hints
  are server-checkable on the first request, no JS challenge needed.

  **EVASION COST** Cheap. Build the header set + order to match the
  impersonated browser. `fetchlib/headers.py` already does this.

  **OUR POSITION** `fetchlib.build_request_headers()` emits a Chrome 121
  desktop header set with the canonical order and Sec-* hints. Combined
  with curl_cffi for TLS+H2, the request looks like a Chrome request all
  the way through.

### Layer 6 -- JavaScript runtime / Web APIs

  **WHAT** The big surface area. Each of the following is a separate
  signal that can betray automation:

  - **`navigator.webdriver`**: `true` in headless Chrome/Puppeteer by
    default. Real browsers return `undefined`.
  - **`navigator.plugins`**: empty in headless; non-empty in real Chrome
    even with no extensions.
  - **`navigator.languages`**: present and stable in real browser; can be
    empty array in misconfigured headless.
  - **`navigator.permissions.query(...)`**: returns realistic states;
    headless Chrome misbehaves on `Notification.permission`.
  - **`navigator.hardwareConcurrency` + `deviceMemory`**: should be in
    realistic ranges (4/8/16 cores; 4/8 GB).
  - **`window.chrome`**: present in real Chrome with `runtime`, `loadTimes`,
    `csi`; missing or partial in headless.
  - **`window.outerWidth`/`outerHeight`**: present in real browser; some
    headless modes return 0 or undefined.
  - **`screen.colorDepth`, `screen.pixelDepth`**: usually 24; values like
    32 or 0 are suspicious.
  - **Iframe contentWindow tricks**: re-reading navigator from a same-
    origin iframe sometimes reveals the unpatched defaults.

  **DETECT** Cloudflare's "JavaScript Detections" runs a lightweight JS
  challenge that probes these. The result POSTs back to Cloudflare and
  becomes part of the bot score. Akamai's Bot Manager Sensor.js does the
  same with a larger script (~50-100 KB obfuscated).

  **EVASION COST** Significant. `puppeteer-extra-plugin-stealth` and
  `playwright-stealth` ship a stack of patches:
  - `navigator.webdriver` -> proxy that returns `undefined`
  - `chrome.runtime` mock
  - `navigator.plugins` emulated (real-looking PluginArray with PDF Viewer)
  - WebGL `getParameter(VENDOR/RENDERER)` overrides to realistic values
  - Accept-Language header injection
  - Media codec presence flags
  - iframe.contentWindow proxy
  - User-Agent platform consistency with `navigator.platform`

  **OUR POSITION** `fetchlib.PlaywrightFetcher` includes most of the
  crawl4ai-derived stealth patches. Gaps: we do NOT currently spoof
  hardwareConcurrency or deviceMemory; do NOT randomize per-session;
  do NOT mimic timezone+geolocation coherence.

### Canvas / WebGL / Audio / Font fingerprints

  **WHAT** All Layer-6, but worth calling out: these signals are stable
  across visits from the same machine but unique per device.

  - **Canvas**: render a known text/image to an offscreen canvas, read
    pixels back, hash. Subtle differences in font rendering, anti-
    aliasing, GPU produce per-machine output.
  - **WebGL**: extracted vendor + renderer strings ("Google Inc.",
    "ANGLE (NVIDIA, ...)"), plus a similar pixel-readback hash on a
    rendered triangle.
  - **AudioContext**: process an OscillatorNode + DynamicsCompressorNode,
    read frequency-domain output, hash. Stable per audio stack.
  - **Font enumeration**: measure widths of known characters in
    candidate fonts; presence/absence and exact width signals which
    fonts are installed.

  **DETECT** Cloudflare/Akamai/Imperva run all four in their JS
  challenges. The results feed into the score.

  **EVASION COST** Real Chromium produces these naturally and they look
  identical to real Chrome on the same hardware. Headless Chrome's
  Canvas/WebGL/Audio outputs can differ subtly (different swiftshader
  vs hardware GPU); stealth plugins try to override the values to match
  common configurations.

  **OUR POSITION** With Playwright over real Chromium (not headless
  shell), Canvas/WebGL/Audio look like a real Chrome on the host
  hardware. Fonts depend on what's installed on the scanner machine.

### Layer 7 -- Behavioural

  **WHAT** Mouse movement curves, scroll cadence, dwell on form fields,
  keystroke inter-arrival times, touch gestures on mobile. Real humans
  generate noisy, biologically-plausible event streams. Bots that
  "skip" event generation (no mouse events between page load and form
  submit) are clearly bots.

  **DETECT** Cloudflare Turnstile, Akamai Bot Manager, hCaptcha all
  score behaviour over a several-second window after the JS challenge
  loads. PerimeterX/HUMAN sells dedicated behavioural scoring.

  **EVASION COST** High. Open-source `puppeteer-humanize` does Bezier-
  curve mouse movement but a determined classifier still distinguishes.
  Commercial scrapers either solve CAPTCHA-style challenges via CAPTCHA-
  solving services (2captcha, anticaptcha) or use residential-proxy
  + real-browser-driven sessions.

  **OUR POSITION** None. We do not generate behavioural events. Any
  target gated by Turnstile-style interactive challenge will block us.

## Vendor capability matrix (rough, public information only)

| Vendor | TLS (L3) | H2 (L5) | Headers (L4) | JS runtime (L6) | Behaviour (L7) | Active challenge |
|---|---|---|---|---|---|---|
| Cloudflare basic (free) | Yes | Yes | Yes | Light | -- | "I am under attack" |
| Cloudflare Pro/Business | Yes+ | Yes | Yes | Heavy | Light | Turnstile |
| Cloudflare Enterprise (Bot Mgmt) | Yes+ | Yes+ | Yes+ | Heavy+ | ML-scored | Turnstile + custom |
| Akamai Bot Manager | Yes+ | Yes+ | Yes | Heavy (Sensor.js) | ML-scored | CAPTCHA |
| Imperva (Incapsula) | Yes | Yes | Yes | Heavy | Light | CAPTCHA |
| DataDome | Yes+ | Yes+ | Yes+ | Heavy | ML-scored | CAPTCHA |
| PerimeterX (HUMAN) | Yes | Yes | Yes | Heavy | ML-scored, **primary signal** | CAPTCHA |

(Plus signs indicate the vendor publicly mentions tuning that layer with
their own proprietary fingerprint variants.)

## Mapping to fetchlib's three tiers

`fetchlib` (in this repo) provides three fetcher implementations, ordered
by capability and cost:

| Tier | L3 TLS | L5 H2 | L4 headers | L6 JS | L7 behav | Defeats |
|---|---|---|---|---|---|---|
| `RequestsFetcher` | Python OpenSSL (recognisable as Python) | h11 defaults | Roughly correct | -- | -- | Sites that only filter by User-Agent string. Useful only as a baseline. |
| `CurlCffiFetcher` (default) | chrome120 impersonation via BoringSSL | chrome120 H2 SETTINGS + pseudo-headers | Chrome 121 header set + order, Sec-CH-UA hints | -- | -- | Cloudflare basic Bot Score, Imperva-light, Akamai-light. Empirically defeats most VN forum/news/gov bot management. |
| `PlaywrightFetcher` (escalation) | Real BoringSSL (Chromium build) | Real | Real | crawl4ai-derived stealth patches | -- | Cloudflare Pro JS challenges (no Turnstile), Akamai Sensor.js scored as human-likely, Imperva (without active CAPTCHA). Cost: 1-3 s per fetch, single-process serialised. |

The fetchers are independent of one another; the pipeline can fall back
from curl_cffi to Playwright on detected block (`cdn_check.py` signals
that, and the pipeline can re-fetch via Playwright on demand).

## Gaps in fetchlib (where to invest next)

1. **TLS profile freshness.** chrome120 is a year old; some sites detect
   it as outdated. Periodic refresh of curl_cffi to whatever the current
   profile is (chrome131 / chrome133 etc) closes this for free.
2. **Per-session randomization.** Real users have varying viewport sizes,
   languages, timezones. Stealth currently emits a fixed profile per
   process. A pool of plausible profiles drawn at fetch time would help
   against ML-scoring vendors that learn "this scanner = single fixed
   profile."
3. **TCP-layer (JA4T).** Out of reach without OS-level hacks. Accept
   datacenter detection; route through residential proxies when targets
   demand it.
4. **Behavioural emulation (L7).** Out of reach for static scanning.
   For Turnstile-gated targets, integrate a CAPTCHA-solving service OR
   accept that those targets are blocked.
5. **Detection feedback loop.** `cdn_check.py` detects when we got
   blocked; the pipeline could record which fingerprint tier was used
   and which targets escalated successfully. That history becomes
   training data for "which tier to start at, per target."

## What this means for the scanner

The scanner is currently in a good spot for cases where bot management
is configured at the Cloudflare-basic or Imperva-light level: curl_cffi
chrome120 + the Chrome header set defeats the JA3/JA4 + L4 + L5 + UA-
string filters, which is most production WAF deployments by volume.

Where it loses: Cloudflare Pro with Turnstile, Akamai Bot Manager on
high-risk endpoints, anything PerimeterX or DataDome. These require
either residential proxies + a real browser + CAPTCHA-solving (the
"commercial scraper" stack) or accepting the target as unreachable.

The methodology consequence is the same as for `cdn_obfuscation.md`:
identify which layer is blocking us, hand off to the right tier (or to a
documented "out of scope" bucket), and don't try to defeat L7 behavioural
challenges with L3-L5 tweaks.

## Sources

- EFF Cover Your Tracks (educational primer): https://coveryourtracks.eff.org/learn
- JA3: https://github.com/salesforce/ja3
- JA4 / JA4+: https://github.com/FoxIO-LLC/ja4
- AmIUnique fingerprint catalog: https://amiunique.org/fingerprint
- puppeteer-extra-plugin-stealth evasions: https://github.com/berstend/puppeteer-extra/tree/master/packages/puppeteer-extra-plugin-stealth
- Cloudflare bot scoring (intentionally vague): https://developers.cloudflare.com/bots/concepts/bot-score/
- Akamai engineering blog on H2 fingerprinting (general knowledge; vendor docs gated)
- curl_cffi (TLS+H2 impersonation): https://github.com/lexiforest/curl_cffi
