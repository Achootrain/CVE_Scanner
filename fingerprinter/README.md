# Nuclei Technology Fingerprint Parser & Scanner

Parse every YAML template in [nuclei-templates](https://github.com/projectdiscovery/nuclei-templates)`/http/technologies`, load the fingerprint rules into SQLite, compile an in-memory JSON cache, and drive a concurrent HTTP scan engine.

## Architecture

```
┌─────────────────────┐   ┌────────────────────┐   ┌────────────────────┐   ┌──────────────────┐
│ http/technologies/  │ → │ fp.parser          │ → │ fingerprints.db    │ → │ fp.cache         │
│  *.yaml (883 files) │   │ (yaml → SQL)       │   │ (SQLite, indexed)  │   │ (JSON in-memory) │
└─────────────────────┘   └────────────────────┘   └────────────────────┘   └────────┬─────────┘
                                                                                     │
                                                                    ┌────────────────▼─────────┐
                                                                    │ fp.scanner               │
                                                                    │ (aiohttp, path-dedup)    │
                                                                    └────────────────┬─────────┘
                                                                                     ▼
                                                                             Detection[] / JSON
```

## Database schema (`fp/schema.sql`)

| Table         | Purpose                                                                                 |
|---------------|-----------------------------------------------------------------------------------------|
| `templates`   | One row per YAML file: id, name, vendor/product/category, CPE, tags, raw YAML.          |
| `requests`    | Per-`http:`-block: method, headers, redirect flags, `matchers-condition`.               |
| `paths`       | Every probe path the request block will hit (`{{BaseURL}}` templating preserved).       |
| `matchers`    | Every matcher with its type/part/condition; `payload` holds raw arrays as JSON.         |
| `extractors`  | Every extractor with type/part/group; `payload` holds regex/kval/xpath/json arrays.     |
| `parse_errors`| Files the loader rejected — preserved for audit rather than silently dropped.           |

Foreign keys cascade, so re-loading (`DELETE FROM templates`) wipes dependents atomically.

## Usage

```bash
pip install -r requirements.txt

# 1. Parse all YAMLs into SQLite
python -m fp.cli parse path/to/nuclei-templates/http/technologies fingerprints.db

# 2. (Optional) dump the in-memory cache to disk for fast reloads
python -m fp.cli build-cache fingerprints.db --out cache.json

# 3. Scan targets
python -m fp.cli scan https://example.com --cache cache.json
python -m fp.cli scan example.com nginx.org --concurrency 50 --timeout 8 --json
```

## Matcher support

| Type     | Implemented | Notes                                                                   |
|----------|-------------|-------------------------------------------------------------------------|
| `word`   | full        | Case-insensitive (Nuclei default), AND/OR across the values list.       |
| `regex`  | full        | Case-sensitive (Nuclei default); `re.MULTILINE | re.DOTALL` flags.      |
| `status` | full        | HTTP status equality.                                                    |
| `kval`   | full        | Header presence (case-insensitive, `_` ↔ `-` normalised).                |
| `dsl`    | best-effort | Supports `status_code == N` and `mmh3(base64_py(body))` favicon hashing. |
| `binary` | stored only | Parsed into DB; scanner skips (vanishingly rare in /http/technologies).  |

All matchers honour `part` (`body`/`header`/`response`/`all`), `condition` (`and`/`or`), `negative`, and the request-level `matchers-condition`.

## Scanner performance

- **Path deduplication**: the 883 templates reference 1,231 paths, which collapse to **647 unique paths** per target. Every target hits each path exactly once regardless of how many templates reference it.
- **Concurrency**: `aiohttp` with a configurable semaphore (default 20). SSL verification is off by default for broad coverage — enable with `--verify-ssl`.
- **Stop-at-first-match**: honoured per request block, matching Nuclei's semantics.

## Tests

```bash
python -m pytest tests/ -q


python -m fp.cli session-capture https://masterji.co --out .\capture_data\masterji.session.json --window-size 1280x800 

python -m fp.cli browser-capture https://masterji.co --session .\capture_data\masterji.session.json --out .\capture_data\masterji.capture.jsonl --max-pages 50 --window-size 1280x800;

```

Seven offline tests cover word/regex/status/kval/dsl matchers, negative inversion, AND/OR modes, and regex extractor group capture.

## Files

```
fp/
  __init__.py
  schema.sql      # SQLite DDL
  parser.py       # YAML → SQL loader
  cache.py        # SQL → JSON in-memory cache
  scanner.py      # aiohttp scan engine + matcher evaluator
  cli.py          # `python -m fp.cli {parse|build-cache|scan}`
tests/
  test_matchers.py
requirements.txt
README.md
```
