-- Nuclei Technology Fingerprint Schema
-- SQLite 3. Foreign keys enforced; cascading deletes from templates.

PRAGMA foreign_keys = ON;
PRAGMA journal_mode = WAL;

CREATE TABLE IF NOT EXISTS templates (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    template_id     TEXT    NOT NULL UNIQUE,          -- e.g. "wordpress-detect"
    name            TEXT    NOT NULL,
    author          TEXT,
    severity        TEXT,
    description     TEXT,
    vendor          TEXT,
    product         TEXT,
    category        TEXT,
    cpe             TEXT,
    tags            TEXT,                             -- csv
    max_request     INTEGER DEFAULT 0,
    verified        INTEGER DEFAULT 0,                -- 0/1
    file_path       TEXT    NOT NULL,
    raw_yaml        TEXT    NOT NULL,
    created_at      TEXT    DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_templates_vendor   ON templates(vendor);
CREATE INDEX IF NOT EXISTS idx_templates_product  ON templates(product);
CREATE INDEX IF NOT EXISTS idx_templates_category ON templates(category);

-- A template has one or more HTTP request groups (almost always one in /technologies).
CREATE TABLE IF NOT EXISTS requests (
    id                   INTEGER PRIMARY KEY AUTOINCREMENT,
    template_id          INTEGER NOT NULL REFERENCES templates(id) ON DELETE CASCADE,
    block_idx            INTEGER NOT NULL,            -- position of this http block in the template
    method               TEXT    NOT NULL DEFAULT 'GET',
    headers_json         TEXT,                         -- serialized dict
    body                 TEXT,
    redirects            INTEGER DEFAULT 0,
    host_redirects       INTEGER DEFAULT 0,
    max_redirects        INTEGER DEFAULT 0,
    stop_at_first_match  INTEGER DEFAULT 0,
    matchers_condition   TEXT    DEFAULT 'or'         -- 'and' | 'or'
);

CREATE INDEX IF NOT EXISTS idx_requests_template ON requests(template_id);

-- Paths the request should probe (may contain {{BaseURL}} templating).
CREATE TABLE IF NOT EXISTS paths (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    request_id  INTEGER NOT NULL REFERENCES requests(id) ON DELETE CASCADE,
    idx         INTEGER NOT NULL,
    path        TEXT    NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_paths_request ON paths(request_id);
CREATE INDEX IF NOT EXISTS idx_paths_path    ON paths(path);

-- One row per matcher. Payload fields stored as JSON strings.
CREATE TABLE IF NOT EXISTS matchers (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    request_id  INTEGER NOT NULL REFERENCES requests(id) ON DELETE CASCADE,
    idx         INTEGER NOT NULL,
    type        TEXT    NOT NULL,    -- word | regex | status | kval | dsl | binary
    name        TEXT,
    part        TEXT    DEFAULT 'body',  -- body | header | response | all | raw
    condition   TEXT    DEFAULT 'or',    -- 'and' | 'or' (for multi-value matchers)
    negative    INTEGER DEFAULT 0,
    group_val   INTEGER DEFAULT 0,       -- some matchers carry 'group' (regex extractor-style)
    payload     TEXT    NOT NULL         -- JSON: {"words":[...]}, {"regex":[...]}, etc.
);

CREATE INDEX IF NOT EXISTS idx_matchers_request ON matchers(request_id);
CREATE INDEX IF NOT EXISTS idx_matchers_type    ON matchers(type);

-- Extractors pull values (versions, etc.) out of responses.
CREATE TABLE IF NOT EXISTS extractors (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    request_id   INTEGER NOT NULL REFERENCES requests(id) ON DELETE CASCADE,
    idx          INTEGER NOT NULL,
    type         TEXT    NOT NULL,  -- regex | kval | xpath | json
    name         TEXT,
    part         TEXT    DEFAULT 'body',
    group_val    INTEGER DEFAULT 0,
    internal     INTEGER DEFAULT 0,
    payload      TEXT    NOT NULL   -- JSON containing regex/kval/xpath/json arrays
);

CREATE INDEX IF NOT EXISTS idx_extractors_request ON extractors(request_id);

-- Loader bookkeeping: rows that could not be parsed or were skipped.
CREATE TABLE IF NOT EXISTS parse_errors (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    file_path  TEXT NOT NULL,
    error      TEXT NOT NULL,
    created_at TEXT DEFAULT (datetime('now'))
);
