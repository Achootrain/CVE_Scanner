# Font Awesome — source-grounded rules

## Where the rules live

| File | Role |
|------|------|
| `rules_src.json` | **Source of truth.** Human-editable. 20 rules across 6 sections (banner / url_version / url_filename / webfont / css_class / kit). Every rule carries a `source` field citing the FA release file or documented downstream convention it was derived from. |
| `src_artifact_inventory.json` | Per-release inventory (v4.7.0, v5.15.4, v6.5.2, v7.2.0) — CSS filenames, webfont filenames, banner strings, class indicators. The catalog the rules cite back to. |
| `out/source/FA-<ver>/...` | Acquired FA release tarballs. Excluded from git via `.gitignore` line 18 (`lab`). |
| `lab.db` table `lab_src_rules` | Mirror of `rules_src.json` for SQL access. Created by `import_rules.py`. |

## How rules were derived (NOT corpus-mined)

The full inventory step is `src_catalog.py` which reads every release tarball and emits `src_artifact_inventory.json`. Each rule in `rules_src.json` cites one of:

1. **A specific file in a specific release** (e.g., `release: 4.7.0, file: css/font-awesome.css, line_range: 1-4`). The banner regex captures the literal string FA itself ships in that file.
2. **A documented downstream convention** (e.g., `WordPress wp_enqueue_style ?ver=`, `cdnjs canonical path layout`, `FA official CDN docs`). Not a regex pulled from observed corpus URLs.

Corpus (`corpus/*.html`) is used **only for validation** — never for rule discovery. If a rule produces a hit on the corpus but cannot be traced to a release artifact or documented convention, it is wrong.

## How to import / consume

### Option A — read JSON directly

```python
import detect_src
rules = detect_src.load_rules()  # default: rules_src.json
det = detect_src.detect("example.com", html, fetcher=None)
```

### Option B — import into lab.db, read from SQL

```bash
# One-time import (idempotent; re-running picks up edits to rules_src.json)
python lab/research/fontawesome/import_rules.py --print
```

```python
import detect_src
from pathlib import Path
rules = detect_src.load_rules_from_db(Path("fingerprinter/lab.db"))
# Then monkey-patch detect_src.load_rules to return this dict, or
# refactor detect() to accept rules as a parameter.
```

```sql
-- Query examples
SELECT rule_id, kind, pattern FROM lab_src_rules WHERE tech_slug='font-awesome';
SELECT rule_id, json_extract(source_json, '$.file') AS src_file
  FROM lab_src_rules WHERE tech_slug='font-awesome' AND kind='banner';
```

### Editing rules

1. Edit `rules_src.json` (add or modify entries). Every new rule MUST have a `source` block citing a release file or documented convention.
2. `python import_rules.py` to push to `lab.db`.
3. `python validate_src_dev.py --with-fetch` to re-validate on dev corpus.
4. Do NOT re-run on the test set unless this is a final evaluation; use `LAB_ALLOW_TEST=1` gate.

## Adding a new tech (template for next research target)

The schema in `lab_src_rules` is generic across tech. To add e.g. jQuery:

1. Create `lab/research/jquery/` with the same layout: `src_catalog.py`, `rules_src.json`, `import_rules.py` (mostly reusable).
2. Acquire jQuery releases (multiple majors).
3. Catalog version-bearing artifacts.
4. Author rules citing release files.
5. `python import_rules.py --tech-slug=jquery` to push them.

Result: one DB, multiple `tech_slug` rows, same shape for every tech.

## Rule extracts semantics

```json
{ "version": {"g": 1} }                       // value comes from regex group 1
{ "generation": {"l": 4} }                    // literal value 4
{ "edition": {"from_host": {"use.fontawesome.com": "free", "pro.fontawesome.com": "pro"}} }
```

A rule may emit any of: `version`, `generation`, `generation_at_least`, `edition`. The detector merges across firing rules and reports the most specific available signal.
