# lab/ -- rule authoring, fixtures, and (soon) RAG

Three pipelines, one store. The store is `fingerprinter/lab.db` (CLAUDE.md
§5). Every pipeline either writes to it (lab does) or reads from it (the
scanner does). No detection literals in `fp/*.py`.

```
                +--------------------------+
                |  fingerprinter/lab.db    |
                |  lab_src_rules           |   <-- scanner reads via fp/stages.py
                |  lab_url_patterns        |   <-- scanner reads via fp/url_ver.py
                |  lab_pkg_aliases         |
                |  lab_version_probes      |
                +--------------------------+
                  ^             ^             ^
                  |             |             |
       writes from this side    |    reads/audits from this side
                  |             |             |
        +---------+---+   +-----+-------+   +-+-----------+
        | research_   |   | docker      |   | rag (§12,   |
        | cycle.py +  |   | fixtures    |   | scaffolded) |
        | lab/core    |   | (run.py +)  |   |             |
        +-------------+   +-------------+   +-------------+
        Pipeline A         Pipeline B         Pipeline C
```

## Pipeline A -- research-cycle (the main loop)

Authors source-grounded detection rules for one technology at a time and
imports them into `lab.db`. Every new tech goes through this loop.

Entry point: `python -m lab.research_cycle ...`

```bash
# 1. Filter the global dev/test corpus to this tech and scaffold a dir
python -m lab.research_cycle start owl-carousel

# 2. (manual) Acquire the tech's source -- multi-version git clone or
#    release tarballs into lab/research/owl-carousel/out/source/<rel>/.
#    Catalog version-bearing signals (banner format, filenames, webfonts,
#    class prefixes). Author lab/research/owl-carousel/rules_src.json --
#    every rule cites a release file or documented downstream convention.

# 3. Import rules into lab.db
python -m lab.research_cycle import-rules owl-carousel \
    --rules-json lab/research/owl-carousel/rules_src.json

# 4. (manual) Validate against dataset_dev.jsonl; loop §6.
# 5. Final eval on dataset_test.jsonl: one shot, LAB_ALLOW_TEST=1.

python -m lab.research_cycle status owl-carousel    # progress check
```

Shared primitives live in `lab/core/`:

| Module             | Role                                                   |
|--------------------|--------------------------------------------------------|
| `lab/core/corpus`  | `read_jsonl` with the LAB_ALLOW_TEST blind-test guard. |
| `lab/core/rules`   | `lab_src_rules` schema, idempotent JSON->DB import, load-back-as-JSON, and the propagator that bridges `url_version_in_path_rules` into `lab_url_patterns` so the scanner picks them up. |
| `lab/core/tech_aliases.json` | `tech_slug -> canonical scanner name` lookup. Add a row when registering a new tech. |

Per-tech research directories `lab/research/<tech>/` hold DATA: `README.md`,
`rules_src.json`, `dataset_dev.jsonl`, `dataset_test.jsonl`, and any
per-tech mining notebooks/scripts that don't generalise. The earliest
techs (fontawesome, slick) accumulated numbered scripts (`1_fetch_corpus.py`,
`2_mine_urls.py`, etc.) -- those are historical and will collapse into
shared modules under `lab/core/` as the patterns crystalise.

### Dev/test split

Lives in `data/scan_results_{dev,test}.jsonl`. Per-tech datasets are
SUBSETS of each side; sites in test stay in test. `research_cycle start`
preserves that boundary automatically (CLAUDE.md §6 phase 3).

## Pipeline B -- docker fixtures (phase 1-3)

Boots known-version tech containers, records responses across a curated
probe set, and diffs across versions to surface candidate version
extractors. Independent of pipeline A; uses its own manifest.

Entry point: `python lab/run.py ...`

See the section "Phase 1-3 fixture-lab details" below.

## Pipeline C -- RAG for rule authoring (CLAUDE.md §12)

Scaffolded under `lab/rag/`. Authoring-time only; never runs at scan time.
Indexes `lab/research/<tech>/out/source/`, research artifacts, CLAUDE.md
and `lab.db` rows so an agent can draft `rules_src.json` rows grounded in
cited spans. Three structural guardrails (bounded-citation, self-match,
§9 gate) intercept the failure modes §7/§9/§10 were written to catch.

Modules are stubbed (`NotImplementedError`) and document the intended
shape -- see `lab/rag/README.md`. Implementation lands once the Bootstrap
re-derivation experiment is set up.

---

## Phase 1-3 fixture-lab details

Pre-existing pipeline for boot-record-diff over Docker containers. Below
is the original documentation; the workflow hasn't changed.

### Prerequisites

- Docker Desktop (or `docker` CLI pointing at a reachable daemon)
- Python dependency: `pip install pyyaml`  (on top of `fingerprinter/requirements.txt`)
- At least one of: `fingerprinter/cache.json` or `fingerprinter/fingerprints.db`

### Run

```bash
cd D:/DATN2
python lab/run.py                          # all fixtures
python lab/run.py --only nginx-1-25-3      # single
python lab/run.py --keep                   # leave containers up after
python lab/run.py --json lab/results.json  # dump full detections
```

Host ports 18101-18104 (Phase 1 banner servers -- nginx 1.24/1.25, httpd
2.4.57/2.4.58) and 18201-18202 (Phase 2 CMS/app) are used; change in
`manifest.yaml` if they collide.

### Phase 2 additions

- **`wordpress-6-4-3`** -- docker-compose (WordPress + MariaDB). After the
  containers become ready, `setup.py` POSTs the install form so WordPress
  transitions from the setup wizard to a live site whose root page exposes
  `<meta name="generator" content="WordPress 6.4.3">`. A second readiness
  probe confirms `/` returns 200 before scanning.
- **`grafana-10-2-3`** -- single container on port 3000 (mapped to host 18202).
  Version is exposed at `/api/health` JSON and in the login footer.

Compose fixtures live in `lab/fixtures/<id>/` and accept a `HOST_PORT` env
var (injected by `run.py`) so the manifest remains the single source of
truth for port assignments.

### Phase 3 -- diff mode (candidate extractor mining)

Given >=2 fixtures of the same technology, diff mode records every
response across a curated path list and surfaces contexts where the
version string appears at the same position in both recordings. Those
contexts are high-signal candidates for new version extractors.

```bash
# All-in-one: record + diff on the 4 paired banner fixtures
python lab/run.py --only nginx-1-25-3 nginx-1-24-0 httpd-2-4-58 httpd-2-4-57 \
    --diff lab/out/phase3-demo

# Or run the steps independently
python lab/run.py --only nginx-1-25-3 nginx-1-24-0 --record lab/out/rec
python lab/diff.py --indir lab/out/rec
```

Output:

- `<outdir>/<fixture_id>/responses.json` -- one recording per fixture.
- `<outdir>/candidates/<tech>.md` -- human-readable report per technology,
  split into **Headers** and **Bodies** buckets with confidence scores.
- `<outdir>/candidates.json` -- machine-readable roll-up (same data).

A candidate is emitted when:

- **Header**: the same header appears in both recordings, each containing
  its fixture's version, AND the header value is byte-identical after
  masking the version out.
- **Body**: a version occurrence has the same +/- 48-char surrounding
  context (whitespace-normalised) in both fixtures, and both responses
  are in the same status class (2xx/3xx/4xx/5xx).

### Signal sources (what `record.py` probes)

Three phases per fixture:

1. **Curated path list** -- 34 well-known paths (`/`, `/readme.html`,
   error-triggering random path, `/wp-login.php`, `/api/health`,
   `/actuator/info`, ...). Stable across fixtures so diff can pair them
   directly.
2. **Fuzzed / abnormal requests** -- `PROPFIND`, `TRACE`, `OPTIONS`,
   `DELETE`, `PATCH`, `LOCK`, null-byte URL, 4 KB URL, malformed/overflow
   `Range`, garbage `Authorization`, exotic `Accept`, empty `POST`.
   Exercises error paths whose templates often leak build info that
   happy-path responses suppress (e.g. nginx surfaces version in 405/416/400
   error pages).
3. **Reference crawl** -- parses `<script src>` and `<link href>` from the
   root HTML, fetches up to 30 same-host URLs. Captures the JS/CSS bundles
   where CMSes and SPAs bury their version strings.

Probe count varies per fixture depending on how many assets the root page
references (nginx/httpd default pages reference none -> 47 probes;
WordPress root references ~20 -> 55 probes).

### Multi-version sweep + cross-distro validation

When three or more fixtures share the same `expected.tech`, the miner runs
`compare_responses` on every **adjacent pair** (sorted by version tuple)
and merges results. A candidate that appears in every pair is reported
with `confidence: high`; one that only appears in a subset of pairs is
downgraded to `medium`. In the candidate report, each entry's `pairs (N)`
line shows exactly which pairs contributed -- e.g.:

    server (high) -- pairs (4): 1.24.0<->1.24.0, 1.24.0<->1.25.3,
                                1.25.3<->1.25.3, 1.25.3<->1.26.0

Same-version pairs (e.g. `nginx:1.25.3` vs `nginx:1.25.3-alpine`) are a
byproduct of adding distro variants under the same tech: they validate
that a pattern is distro-independent. Different-version pairs validate
that the capture group is actually version-discriminating. A regex that
survives both kinds is maximally trustworthy.

Current built-in sweep: 5 nginx (1.24/1.25/1.26 debian + 1.24/1.25 alpine)
and 3 httpd (2.4.57/.58/.59) fixtures. `python lab/run.py --diff lab/out/xxx`
(no `--only`) runs the whole matrix.

### Known limitation

Diff pairs responses by exact path string. URLs with the version *in the
query* (e.g. `/wp-includes/foo.js?ver=6.4.3` vs `/wp-includes/foo.js?ver=6.4.2`)
get different keys and are never paired, so their bodies aren't diffed
against each other. Fix is a "match-by-path-sans-query" fallback in
`diff.py::compare_responses` -- not yet implemented.
