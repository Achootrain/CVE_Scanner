# fp CLI Cheatsheet

All commands run from `fingerprinter/` unless noted. Activate venv first:
```powershell
.\.venv\Scripts\Activate.ps1
$env:KATANA_BIN = "D:\DATN2\fingerprinter\katana.exe"   # set automatically on activate
```

---

## Setup / DB build

```powershell
pip install aiohttp PyYAML mmh3 pytest

# Build nuclei cache from YAML templates (only needed when templates change)
python -m fp.cli parse ../nuclei-templates/http/technologies fingerprints.db
python -m fp.cli build-cache fingerprints.db --out cache.json

# Import Wappalyzer rules
python -m fp.cli wap-import --db wappalyzer.db                          # download from GitHub
python -m fp.cli wap-import --db wappalyzer.db --zip webappanalyzer.zip # offline

# Import Retire.js rules
python -m fp.cli retire-import --db retirejs.db                         # download from GitHub
python -m fp.cli retire-import --db retirejs.db --json jsrepository-v2.json  # offline

# Import WhatWeb rules (1000+ plugins with version patterns)
python -m fp.cli whatweb-import --db whatweb.db                         # download from GitHub
python -m fp.cli whatweb-import --db whatweb.db --zip WhatWeb-master.zip  # offline
python -m fp.cli whatweb-cache --db whatweb.db                          # stats check
```

---

## Target collection (run from repo root D:\DATN2)

```powershell
# Collect .vn targets from crt.sh Certificate Transparency logs
python lab/collect_vn_targets.py --out fingerprinter/targets.txt

# Add Tranco top-1M filter (download CSV from https://tranco-list.eu/download/latest/full)
python lab/collect_vn_targets.py --tranco tranco-full.csv --out fingerprinter/targets.txt

# Expand apex domains into subdomains (slow -- queries crt.sh per apex)
python lab/collect_vn_targets.py --expand --out fingerprinter/targets.txt

# Filter out dead/unreachable hosts before scanning
python lab/collect_vn_targets.py --no-crtsh --filter-live --out fingerprinter/targets_live.txt

# Filter with custom probe settings (faster)
python lab/collect_vn_targets.py --no-crtsh --filter-live --probe-timeout 3 --probe-concurrency 100 --out fingerprinter/targets_live.txt
```

---

## Subdomain enumeration

```powershell
python -m fp.cli subdomains example.com
python -m fp.cli subdomains example.com acme.com --json
```

---

## Scan (nuclei + Wappalyzer + retire.js)

```powershell
# Basic scan
python -m fp.cli scan https://example.com --cache cache.json

# With Wappalyzer version detection
python -m fp.cli scan https://example.com --cache cache.json --wap-db wappalyzer.db

# With retire.js JS library detection
python -m fp.cli scan https://example.com --cache cache.json --wap-db wappalyzer.db --retire-db retirejs.db

# Auto-expand to subdomains then scan
python -m fp.cli scan example.com --wap-db wappalyzer.db --expand-subdomains --json

# Tuning
python -m fp.cli scan https://example.com --cache cache.json --concurrency 50 --timeout 8 --json
```

---

## Katana (static JS endpoint extraction)

```powershell
# Basic crawl
python -m fp.cli katana https://target.com

# Deeper crawl with body extraction
python -m fp.cli katana https://target.com --depth 3 --extract-bodies --json

# SPA / server-rendered targets (XenForo, ASP.NET, PHP, Rails)
python -m fp.cli katana https://forum.target.com --extract-bodies --extract-html --json

# Headless (Chromium hybrid for JS-heavy SPAs)
python -m fp.cli katana https://target.com --headless --extract-bodies --json

# Limit URL budget and JS files
python -m fp.cli katana https://target.com --max-katana-urls 100 --max-js 20
```

---

## Pipeline (full automated scan -- recommended)

```powershell
# Single target
python -m fp.cli pipeline https://example.com --json

# Multiple targets inline
python -m fp.cli pipeline https://target1.com https://target2.com --json

# From file (one target per line)
python -m fp.cli pipeline --file targets.txt --json
python -m fp.cli pipeline --file targets_live.txt --json

# Mass scan
python -m fp.cli pipeline --file targets.txt --parallel 10 --json --quiet > scan_results.jsonl

# Honest scanner UA instead of Chrome (may get blocked by Cloudflare)
python -m fp.cli pipeline https://target.com --ua scanner

# Skip optional sources (when binary/DB not available)
python -m fp.cli pipeline https://target.com --no-katana --no-version-probes

# Reduce katana crawl depth/budget for faster mass scan
python -m fp.cli pipeline --file targets.txt --depth 1 --max-katana-urls 50 --parallel 10 --json --quiet

# Save HTTP responses + labels for AI training data
python -m fp.cli pipeline https://target.com --save-responses ./responses/
```

### Pipeline key flags

| Flag | Default | Notes |
|---|---|---|
| `--file / -f` | — | Read targets from file, repeatable |
| `--parallel` | 3 | Targets processed concurrently |
| `--concurrency` | 20 | Per-target HTTP request concurrency |
| `--timeout` | 10 | Per-request timeout (seconds) |
| `--scan-timeout` | 90 | Hard cap on nuclei scan stage |
| `--depth` | 2 | Katana crawl depth |
| `--max-katana-urls` | 500 | Katana URL budget per target |
| `--max-cross-page-urls` | 30 | Cross-page Wappalyzer rescan cap |
| `--ua` | `chrome` | `chrome` / `scanner` / custom string |
| `--no-katana` | — | Skip katana |
| `--no-cross-page` | — | Skip cross-page rescan |
| `--no-version-probes` | — | Skip hand-curated version probes |
| `--ww-db` | `whatweb.db` | WhatWeb patterns DB (auto-skipped if missing) |
| `--no-extract-bodies` | — | Skip JS body re-fetch |
| `--no-extract-html` | — | Skip HTML body sweep |
| `--json` | — | Machine-readable output |
| `--quiet` | — | Suppress stderr progress |

---

## JS path extraction

```powershell
# Extract paths from an existing browser-capture JSONL
python -m fp.cli js-extract --from-capture capture.jsonl --json
```

---

## Browser / session capture (requires camoufox)

```powershell
# Record a login session
python -m fp.cli session-capture https://target.com --out session.json --window-size 1280x800

# Capture authenticated XHR traffic (feed session from above)
python -m fp.cli browser-capture https://target.com --session session.json --out capture.jsonl --max-pages 50
```

---

## Docker

```powershell
# Build image
docker build -t fp .

# Single scan
docker run --rm fp pipeline https://example.com --json

# Mass scan from file (use --entrypoint sh to read file inside container)
docker run --rm -v "$PWD/fingerprinter:/data" -w /app/fingerprinter --entrypoint sh fp `
  -c 'xargs python -m fp.cli pipeline --parallel 10 --json --quiet < /data/targets.txt > /data/results.json'

# Interactive shell
docker run --rm -it fp
```

---

## Lab (ground-truth test harness)

```powershell
# Run all fixtures (from D:\DATN2)
python lab/run.py

# Single fixture
python lab/run.py --only nginx-1-25-3

# JSON output
python lab/run.py --json out.json
```

---

## Tests

```powershell
python -m pytest tests/ -q          # all tests
python -m pytest tests/ -q --tb=short  # with short tracebacks
```

python -m fp.cli pipeline --file targets.txt --parallel 1 --use-cloak --depth 2 --max-katana-urls 500 --katana-timeout 90 --no-backend-probe --concurrency 40 --scan-timeout 180 --max-cross-page-urls 30 --cross-page-timeout 60 --json >> scan_results.jsonl 2>> scan_results.stderr

# Start research on a new tech
  python lab/research_cycle.py start jquery
  #   filters data/scan_results_{dev,test}.jsonl to jquery-tagged sites
  #   -> lab/research/jquery/dataset_{dev,test}.jsonl + scaffolded README
  #   dev=156, test=53 (~75/25, preserves global split)

  # (do the source-grounded research per CLAUDE.md section 6,
  #  author lab/research/jquery/rules_src.json)

  # Import the new rules
  python lab/research_cycle.py import-rules jquery --rules-json lab/research/jquery/rules_src.json

  # Check progress
  python lab/research_cycle.py status jquery
