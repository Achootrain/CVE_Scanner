# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

A security vulnerability scanning system with two components:
- **`fingerprinter/`** — Python async HTTP scanner that detects web technologies and vulnerabilities
- **`nuclei-templates/`** — Cloned ProjectDiscovery template repository (883 YAML files for HTTP technology detection)

## Commands

All commands run from the `fingerprinter/` directory.

```bash
# Install dependencies
pip install -r requirements.txt

# Three-stage pipeline:

# 1. Parse YAML templates into SQLite database
python -m fp.cli parse ../nuclei-templates/http/technologies fingerprints.db

# 2. Build in-memory JSON cache (optional, for faster scanning)
python -m fp.cli build-cache fingerprints.db --out cache.json

# 3. Scan targets
python -m fp.cli scan https://example.com --cache cache.json
python -m fp.cli scan example.com nginx.org --concurrency 50 --timeout 8 --json

# Run tests
python -m pytest tests/ -q
```

## Architecture

Data flows through three sequential stages:

```
YAML Templates → [parser.py] → SQLite DB → [cache.py] → JSON cache → [scanner.py] → Results
```

**`fp/parser.py`** — Reads YAML template files, extracts requests/matchers/extractors, stores into 7-table SQLite schema defined in `fp/schema.sql`. Foreign keys cascade so deleting a template wipes all dependent rows.

**`fp/cache.py`** — Loads SQLite into memory, deduplicates paths (883 templates → 647 unique probe paths), pre-compiles regex patterns.

**`fp/scanner.py`** — Issues async HTTP requests via `aiohttp` with a configurable semaphore (default: 20 concurrent). Evaluates matchers per response, runs extractors, outputs detections.

**`fp/cli.py`** — Entry point wiring the three stages to CLI subcommands.

## Matcher/Extractor Support

Matchers: `word` (AND/OR substring), `regex` (MULTILINE|DOTALL), `status` (HTTP code), `kval` (header presence, `-`↔`_` normalized), `dsl` (partial: `status_code == N` and favicon hash via `mmh3`), `binary` (stored but skipped).

Extractors: `regex` (with capture groups), `kval`, `json` (JSON path), `xpath`.

## SQLite Schema

Seven tables: `templates`, `requests`, `paths`, `matchers`, `extractors`, `parse_errors`. The `parse_errors` table captures failed YAML files as an audit trail.

## Key Artifacts

Large pre-built artifacts already committed — do not regenerate unless templates change:
- `fingerprinter/fingerprints.db` — SQLite database (~24MB)
- `fingerprinter/cache.json` — Pre-built in-memory cache (~22MB)
