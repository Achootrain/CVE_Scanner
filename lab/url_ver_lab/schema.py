"""Schema for Phase A tables: lab_url_patterns + lab_pkg_aliases.

Both tables follow the source-grounded convention from lab_src_rules:
each row carries an `origin` field documenting where it came from
(seeded:<constant>, mined:<process>, hand-curated, etc.) so a re-seed can
safely wipe only seeded rows.
"""

SCHEMA = """
CREATE TABLE IF NOT EXISTS lab_url_patterns (
  id              INTEGER PRIMARY KEY AUTOINCREMENT,
  pattern         TEXT NOT NULL,        -- regex string (uncompiled)
  tech            TEXT,                 -- canonical tech name when fixed; NULL when pkg_group resolves it
  pkg_group       INTEGER,              -- regex group # holding pkg name to look up via lab_pkg_aliases
  version_group   INTEGER,              -- regex group # holding version (NULL = pattern-only, no version)
  family          TEXT NOT NULL,        -- 'cdn: jsdelivr' / 'cdn: cdnjs' / 'cdn: fontawesome' / 'framework: next.js' / ...
  origin          TEXT NOT NULL,        -- 'seeded:_CDN_PATTERNS' / 'hand-curated' / 'mined:cdn-miner'
  kind            TEXT NOT NULL,        -- 'cdn' | 'framework'
  note            TEXT
);

CREATE INDEX IF NOT EXISTS idx_lab_url_patterns_kind ON lab_url_patterns(kind);
CREATE INDEX IF NOT EXISTS idx_lab_url_patterns_origin ON lab_url_patterns(origin);

CREATE TABLE IF NOT EXISTS lab_pkg_aliases (
  id              INTEGER PRIMARY KEY AUTOINCREMENT,
  alias           TEXT NOT NULL,        -- lookup key (lowercase): 'jquery', 'fullpage.js', 'acf', 'app'
  tech            TEXT,                 -- canonical name; NULL for skip-stem rows
  context         TEXT NOT NULL,        -- 'js-lib' | 'cdn-pkg' | 'wp-plugin' | 'skip-stem'
  origin          TEXT NOT NULL,        -- 'seeded:_JS_LIB_MAP' / 'hand-curated' / ...
  note            TEXT,
  UNIQUE(alias, context)
);

CREATE INDEX IF NOT EXISTS idx_lab_pkg_aliases_context ON lab_pkg_aliases(context);
CREATE INDEX IF NOT EXISTS idx_lab_pkg_aliases_alias ON lab_pkg_aliases(alias);

CREATE TABLE IF NOT EXISTS lab_version_probes (
  id              INTEGER PRIMARY KEY AUTOINCREMENT,
  name            TEXT NOT NULL,        -- canonical tech name; becomes vp:<name> template id
  path            TEXT NOT NULL,        -- HTTP path to probe
  regex           TEXT NOT NULL,        -- version-extraction regex
  method          TEXT NOT NULL DEFAULT 'GET',
  version_group   INTEGER NOT NULL DEFAULT 1,
  ok_status       TEXT NOT NULL DEFAULT '200',  -- comma-separated ints, e.g. '200,201'
  part            TEXT NOT NULL DEFAULT 'body', -- 'body' | 'header' | 'status'
  content_hint    TEXT,                 -- optional substring guard
  headers_json    TEXT,                 -- JSON object of extra request headers
  origin          TEXT NOT NULL,        -- 'seeded:CATALOG' / 'hand-curated' / 'mined:<process>'
  note            TEXT
);

CREATE INDEX IF NOT EXISTS idx_lab_version_probes_name ON lab_version_probes(name);
CREATE INDEX IF NOT EXISTS idx_lab_version_probes_origin ON lab_version_probes(origin);
"""
