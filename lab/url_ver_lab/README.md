# url_ver_lab — Phase A (lab side)

Migrates the four catalogs currently hard-coded in `fingerprinter/fp/url_ver.py`
into `lab.db` so each detection gap becomes a one-row `INSERT` instead of a
code commit + redeploy. Lab-side only; the scanner is not touched.

## Tables (in `fingerprinter/lab.db`)

### `lab_url_patterns`
| column | meaning |
|---|---|
| `pattern` | regex string (uncompiled) |
| `tech` | canonical tech name when fixed (e.g. "Font Awesome"); NULL when `pkg_group` resolves the name |
| `pkg_group` | regex group # holding the pkg name to look up via `lab_pkg_aliases`; NULL if `tech` is fixed |
| `version_group` | regex group # holding the version; NULL = pattern-only |
| `family` | e.g. `cdn: jsdelivr`, `framework: next.js` |
| `kind` | `cdn` or `framework` |
| `origin` | `seeded:_CDN_PATTERNS` / `hand-curated` / `mined:<process>` |

### `lab_pkg_aliases`
| column | meaning |
|---|---|
| `alias` | lookup key, lowercase (e.g. `jquery`, `fullpage.js`, `acf`) |
| `tech` | canonical name (`jQuery`); NULL for skip-stem rows |
| `context` | `js-lib` / `cdn-pkg` / `wp-plugin` / `skip-stem` |
| `origin` | source tag (same convention as `lab_url_patterns`) |

UNIQUE on `(alias, context)` so the same alias can mean different things in different lookup contexts.

## Workflow

### One-time seed (and re-seed after url_ver.py changes upstream)

```bash
python -m lab.url_ver_lab.seed --print
```

Idempotent: deletes only rows whose `origin` starts with `seeded:` then re-inserts. Hand-curated rows are preserved.

### Adding a new tech — no code commit needed

```sql
-- Map a new JS lib filename stem to a canonical name
INSERT INTO lab_pkg_aliases (alias, tech, context, origin)
VALUES ('fullpage.js', 'fullPage.js', 'js-lib', 'hand-curated'),
       ('fullpage',    'fullPage.js', 'js-lib', 'hand-curated');

-- Add a new CDN pattern
INSERT INTO lab_url_patterns (pattern, tech, pkg_group, version_group, family, origin, kind)
VALUES ('cdn\.bytedance\.net/[^/]+/(\d+\.\d+(?:\.\d+)*)', 'ByteCDN', NULL, 1,
        'cdn: bytedance', 'hand-curated', 'cdn');

-- Block a new noise stem from ?ver= probing
INSERT INTO lab_pkg_aliases (alias, tech, context, origin)
VALUES ('analytics', NULL, 'skip-stem', 'hand-curated');
```

### Parity test (gate before any future scanner refactor)

```bash
python -m lab.url_ver_lab.test_parity
```

Confirms `lab.db` rows are byte-equivalent to `fp.url_ver` constants. Must pass before considering a scanner-side swap.

## Consumer API

```python
from lab.url_ver_lab.loader import load_all
from pathlib import Path

cats = load_all(Path("fingerprinter/lab.db"))
cats["JS_LIB_MAP"]          # dict[alias, tech]    -- same shape as _JS_LIB_MAP
cats["CDN_PKG_MAP"]         # dict[alias, tech]    -- same shape as _CDN_PKG_MAP
cats["WP_PLUGIN_MAP"]       # dict[alias, tech]    -- same shape as WP_PLUGIN_MAP
cats["SKIP_STEMS"]          # frozenset[str]       -- same shape as _SKIP_STEMS
cats["CDN_PATTERNS"]        # list[(compiled_re, pkg_group, version_group, fixed_name)]
cats["FRAMEWORK_PATTERNS"]  # list[(compiled_re, tech, slug)]
```

The shapes match `fp.url_ver` exactly — a future scanner-side refactor would only need to swap the import.

## What's NOT in this phase

- **Scanner refactor**: `fp/url_ver.py` still defines the constants in code. The loader is exercised only by tests, not by the live scan path. Per directive #1 (lab does rules, not scanner code), refactoring the scanner to read from `lab.db` is tracked as a separate concern.
- **Phase B (`lab_version_probes`)** and **Phase C (`lab_framework_patterns` move)** from CLAUDE.md — Phase A is the high-value shippable; B and C are deferred per CLAUDE.md's own recommendation.

## Files

- `schema.py` — DDL
- `seed.py` — reads `fp.url_ver` constants, inserts rows (idempotent)
- `loader.py` — read API matching `fp.url_ver` shapes
- `test_parity.py` — equivalence test (6 cases)
