"""Lab-mined rule store + applier.

Consolidates every ``(path, regex)`` pair the lab miner produced under
``lab/research/`` into a single SQLite database (``lab.db``) and gives the
fp scanner a runtime hook to apply those rules during a live scan.

Three rule kinds live in the DB:

- **body**: ``(path, regex)``. Fetch ``target_host + path``, apply regex
  to the response body. Mined output of ``lab/research/mine_paths.py``.
- **bundled**: like ``body`` but the parent ``lab_libs.slug`` must be
  detected first (the path lives inside the plugin's own tree). The
  rule's ``bundled_tech`` column records which other tech the version
  pin actually identifies (e.g. ``eds-font-awesome`` bundles
  ``fontawesome`` at ``/font-awesome/js/all.min.js``).
- **url**: regex over URL strings. No fetch needed. Used to mine
  CDN-deployment URLs that already appear in a target's endpoint pool
  (``use.fontawesome.com/releases/vX.Y.Z`` etc.). Hand-curated in the
  lab; stored here for reuse.

CVE metadata also lands in the DB so a downstream module can later map
detected ``(slug, version)`` pairs to vulnerability records without
re-parsing the lab JSON.

CLI::

    python -m fp.cli lab-import --lab-dir lab/research --db lab.db
    python -m fp.cli pipeline <target> --lab-db lab.db

Scanner integration::

    cache = build_cache("lab.db")
    detections = await apply(
        target_host, current_detections, session, prog=prog,
    )
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import sqlite3
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

LOG = logging.getLogger("fp.lab_rules")


_SCHEMA = """
CREATE TABLE IF NOT EXISTS lab_libs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  slug TEXT UNIQUE NOT NULL,
  product TEXT,
  kind TEXT NOT NULL,             -- "library" | "plugin"
  source_dir TEXT,
  primary_version TEXT,
  cross_versions TEXT             -- JSON array
);

CREATE TABLE IF NOT EXISTS lab_rules (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  lib_id INTEGER NOT NULL REFERENCES lab_libs(id) ON DELETE CASCADE,
  kind TEXT NOT NULL,             -- "body" | "url" | "bundled"
  path TEXT,                      -- relative path (body / bundled)
  url_pattern TEXT,               -- raw regex string (url)
  regex TEXT NOT NULL,
  regex_family TEXT,
  bundled_tech TEXT,              -- bundled: which tech the rule actually pins
  validated_versions TEXT         -- JSON array
);

CREATE INDEX IF NOT EXISTS idx_lab_rules_lib ON lab_rules(lib_id);
CREATE INDEX IF NOT EXISTS idx_lab_rules_kind ON lab_rules(kind);

CREATE TABLE IF NOT EXISTS lab_cves (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  lib_id INTEGER NOT NULL REFERENCES lab_libs(id) ON DELETE CASCADE,
  cve TEXT NOT NULL,
  cvss REAL,
  vuln_type TEXT,
  affected TEXT,
  range_op TEXT,
  range_version TEXT,
  summary TEXT
);

CREATE INDEX IF NOT EXISTS idx_lab_cves_lib ON lab_cves(lib_id);
"""


# ---------------------------------------------------------------------------
# Importer: walk lab/research/ and seed lab.db
# ---------------------------------------------------------------------------


def _read_json(p: Path) -> dict | None:
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def _iter_lab_libs(lab_dir: Path) -> Iterable[tuple[str, str, Path, dict | None, dict | None]]:
    """Walk ``lab_dir`` and yield ``(slug, kind, source_dir, version_rules, cves_rules)``
    tuples for every lab entry that has at least one rule file.

    Layout:
      ``lab/research/<lib>/version_rules.json``     -> kind="library"
      ``lab/research/<lib>/rules.json``             -> CVE rules for that lib
      ``lab/research/plugins/<slug>/version_rules.json`` -> kind="plugin"
    """
    if not lab_dir.is_dir():
        return
    for child in sorted(lab_dir.iterdir()):
        if not child.is_dir() or child.name == "dashboard":
            continue
        if child.name == "plugins":
            for plug in sorted(child.iterdir()):
                if not plug.is_dir():
                    continue
                vr = _read_json(plug / "version_rules.json")
                if vr is None:
                    continue
                yield plug.name, "plugin", plug, vr, None
        else:
            vr = _read_json(child / "version_rules.json")
            cves = _read_json(child / "rules.json")
            if vr is None and cves is None:
                continue
            yield child.name, "library", child, vr, cves


def _insert_lib(
    cur: sqlite3.Cursor,
    slug: str,
    kind: str,
    source_dir: Path,
    primary_version: str | None,
    cross_versions: list | None,
    product: str | None = None,
) -> int:
    cur.execute(
        """INSERT INTO lab_libs(slug, product, kind, source_dir, primary_version, cross_versions)
           VALUES (?, ?, ?, ?, ?, ?)
           ON CONFLICT(slug) DO UPDATE SET
             product=excluded.product, kind=excluded.kind,
             source_dir=excluded.source_dir,
             primary_version=excluded.primary_version,
             cross_versions=excluded.cross_versions""",
        (
            slug, product, kind, str(source_dir),
            primary_version,
            json.dumps(cross_versions) if cross_versions else None,
        ),
    )
    cur.execute("SELECT id FROM lab_libs WHERE slug=?", (slug,))
    return cur.fetchone()[0]


def _insert_rules_for(cur: sqlite3.Cursor, lib_id: int, vr: dict) -> dict[str, int]:
    counts = {"body": 0, "url": 0, "bundled": 0}

    for rule in vr.get("rules", []) or []:
        regex = (rule.get("regex") or "").strip()
        path = (rule.get("path") or "").strip()
        if not regex or not path:
            continue
        cur.execute(
            """INSERT INTO lab_rules(lib_id, kind, path, regex, regex_family, validated_versions)
               VALUES (?, 'body', ?, ?, ?, ?)""",
            (
                lib_id, path, regex, rule.get("regex_family", ""),
                json.dumps(rule.get("validated_versions", []) or []),
            ),
        )
        counts["body"] += 1

    for rule in vr.get("bundled_tech_rules", []) or []:
        tmpl = (rule.get("url_path_template") or "").strip()
        regex = (rule.get("regex") or "").strip()
        if not tmpl or not regex:
            continue
        cur.execute(
            """INSERT INTO lab_rules(lib_id, kind, path, regex, regex_family, bundled_tech, validated_versions)
               VALUES (?, 'bundled', ?, ?, ?, ?, ?)""",
            (
                lib_id, tmpl, regex, rule.get("regex_family", ""),
                rule.get("bundled_tech", ""),
                json.dumps(rule.get("validated_versions", []) or []),
            ),
        )
        counts["bundled"] += 1

    for up in vr.get("url_patterns", []) or []:
        pat = (up.get("pattern") or "").strip()
        if not pat:
            continue
        cur.execute(
            """INSERT INTO lab_rules(lib_id, kind, url_pattern, regex, regex_family)
               VALUES (?, 'url', ?, ?, ?)""",
            (lib_id, pat, pat, up.get("regex_family", "")),
        )
        counts["url"] += 1
    return counts


def _insert_cves_for(cur: sqlite3.Cursor, slug: str, cves_rules: dict) -> int:
    """Process a CVE-rules.json. The file shape uses one "rules" entry per slug
    with embedded CVEs and an embedded `version_regex` -- record both.
    """
    n = 0
    for r in cves_rules.get("rules", []) or []:
        if r.get("slug") != slug:
            continue
        # The CVE-rules.json also ships a version_regex applied to its
        # `paths`. Store it as a body rule alongside any mined entries.
        regex = (r.get("version_regex") or "").strip()
        for path in r.get("paths", []) or []:
            if regex and path:
                cur.execute(
                    """INSERT INTO lab_rules(lib_id, kind, path, regex, regex_family, validated_versions)
                       VALUES ((SELECT id FROM lab_libs WHERE slug=?), 'body', ?, ?, 'cve: Stable tag', '[]')""",
                    (slug, path, regex),
                )
        cur.execute(
            "UPDATE lab_libs SET product=? WHERE slug=?",
            (r.get("product"), slug),
        )
        for cve in r.get("cves", []) or []:
            rng = cve.get("range") or {}
            cur.execute(
                """INSERT INTO lab_cves(lib_id, cve, cvss, vuln_type, affected, range_op, range_version, summary)
                   VALUES ((SELECT id FROM lab_libs WHERE slug=?), ?, ?, ?, ?, ?, ?, ?)""",
                (
                    slug, cve.get("cve"), cve.get("cvss"),
                    cve.get("vuln_type"), cve.get("affected"),
                    rng.get("op"), rng.get("version"),
                    cve.get("summary"),
                ),
            )
            n += 1
    return n


def build_db(lab_dir: str | Path, db_path: str | Path) -> dict[str, int]:
    """Walk ``lab_dir``, write rule + CVE rows into ``db_path``.

    Existing DB is wiped first so re-running is idempotent. Returns a
    summary of insertion counts.
    """
    lab_dir = Path(lab_dir)
    db_path = Path(db_path)
    if db_path.exists():
        db_path.unlink()
    conn = sqlite3.connect(db_path)
    try:
        conn.executescript(_SCHEMA)
        cur = conn.cursor()
        totals = {"libs": 0, "body": 0, "url": 0, "bundled": 0, "cves": 0}
        # First pass: insert libs + their version_rules.json rules.
        for slug, kind, source_dir, vr, cves_rules in _iter_lab_libs(lab_dir):
            if vr is not None:
                lib_id = _insert_lib(
                    cur, slug, kind, source_dir,
                    vr.get("primary_version"),
                    vr.get("cross_versions"),
                )
                counts = _insert_rules_for(cur, lib_id, vr)
                for k, v in counts.items():
                    totals[k] += v
                totals["libs"] += 1
            elif cves_rules is not None:
                # CVE-only library (no mined version_rules.json). Insert
                # the parent row so the CVE rules can attach.
                _insert_lib(cur, slug, kind, source_dir, None, None)
                totals["libs"] += 1
        # Second pass: CVE rules and their embedded version_regex bodies.
        for slug, _kind, _src, _vr, cves_rules in _iter_lab_libs(lab_dir):
            if cves_rules is None:
                continue
            # CVE-rules.json declares slugs for *every* covered plugin,
            # not just the parent library. Ensure each referenced slug has
            # a lib row before attaching CVEs to it.
            for r in cves_rules.get("rules", []) or []:
                child_slug = (r.get("slug") or "").strip()
                if not child_slug:
                    continue
                cur.execute("SELECT 1 FROM lab_libs WHERE slug=?", (child_slug,))
                if cur.fetchone() is None:
                    _insert_lib(
                        cur, child_slug, "plugin",
                        Path(str(_src) + "/" + child_slug),
                        None, None, product=r.get("product"),
                    )
                    totals["libs"] += 1
                n = _insert_cves_for(cur, child_slug, {"rules": [r]})
                # Don't double-count the body rule; it was inserted above
                # by _insert_cves_for via its `paths` traversal.
                cur.execute(
                    "SELECT COUNT(*) FROM lab_rules WHERE lib_id=(SELECT id FROM lab_libs WHERE slug=?) AND regex_family='cve: Stable tag'",
                    (child_slug,),
                )
                totals["cves"] += n
        conn.commit()
        # Recount totals from the DB to surface anything _insert_cves_for added.
        cur.execute("SELECT kind, COUNT(*) FROM lab_rules GROUP BY kind")
        recount = dict(cur.fetchall())
        totals["body"] = recount.get("body", 0)
        totals["url"] = recount.get("url", 0)
        totals["bundled"] = recount.get("bundled", 0)
        cur.execute("SELECT COUNT(*) FROM lab_libs")
        totals["libs"] = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM lab_cves")
        totals["cves"] = cur.fetchone()[0]
        return totals
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Cache loader -- DB rows -> in-memory index
# ---------------------------------------------------------------------------


@dataclass
class LabRule:
    lib_slug: str
    kind: str                 # "body" | "url" | "bundled"
    path: str | None
    url_pattern: str | None
    regex: str
    regex_family: str
    bundled_tech: str | None
    compiled: re.Pattern


@dataclass
class LabCache:
    libs_by_slug: dict[str, dict] = field(default_factory=dict)
    body_rules_by_slug: dict[str, list[LabRule]] = field(default_factory=dict)
    bundled_rules_by_parent: dict[str, list[LabRule]] = field(default_factory=dict)
    url_rules: list[LabRule] = field(default_factory=list)


def _norm_name(s: str) -> str:
    return re.sub(r"[^a-z0-9]", "", (s or "").lower())


def build_cache(db_path: str | Path) -> LabCache:
    """Load lab.db into an in-memory ``LabCache`` ready for ``apply``."""
    conn = sqlite3.connect(db_path)
    cache = LabCache()
    try:
        cur = conn.cursor()
        cur.execute("SELECT id, slug, product, kind FROM lab_libs")
        id_to_slug = {}
        for lib_id, slug, product, kind in cur.fetchall():
            id_to_slug[lib_id] = slug
            cache.libs_by_slug[slug] = {"product": product, "kind": kind}
        cur.execute(
            "SELECT lib_id, kind, path, url_pattern, regex, regex_family, bundled_tech FROM lab_rules"
        )
        for lib_id, kind, path, url_pat, regex, family, bundled in cur.fetchall():
            slug = id_to_slug.get(lib_id, "?")
            try:
                compiled = re.compile(regex)
            except re.error:
                continue
            rule = LabRule(
                lib_slug=slug, kind=kind,
                path=path, url_pattern=url_pat,
                regex=regex, regex_family=family or "",
                bundled_tech=bundled or None,
                compiled=compiled,
            )
            if kind == "body":
                cache.body_rules_by_slug.setdefault(slug, []).append(rule)
            elif kind == "bundled":
                # Bundled rules attach to the *parent* plugin (the one whose
                # tree the bundled tech lives inside). Index by parent slug.
                cache.bundled_rules_by_parent.setdefault(slug, []).append(rule)
            elif kind == "url":
                cache.url_rules.append(rule)
        return cache
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Runtime apply
# ---------------------------------------------------------------------------


def _detection_slugs(detections: list[dict]) -> set[str]:
    """Collect normalized tech names + Wappalyzer ``wap:<Name>`` template IDs
    from the scanner's detection list. Lab keys use the dashed/lower-cased
    form, so we normalise everything to that representation.
    """
    out: set[str] = set()
    for d in detections or []:
        name = d.get("name") or d.get("product") or ""
        tmpl = d.get("template_id") or ""
        for raw in (name, tmpl):
            if not raw:
                continue
            cleaned = raw
            for prefix in ("wap:", "retire:", "vp:", "url-ver:"):
                if cleaned.lower().startswith(prefix):
                    cleaned = cleaned[len(prefix):]
                    break
            out.add(_norm_name(cleaned))
    return out


def _match_lab_lib(detection_slugs: set[str], lib_slug: str) -> bool:
    """A lab lib matches if any detection slug equals or contains the lab slug
    (with the same length guard the back-test uses: ``len(slug) >= 4``)."""
    norm = _norm_name(lib_slug)
    if not norm or len(norm) < 4:
        return False
    if norm in detection_slugs:
        return True
    for ds in detection_slugs:
        if norm in ds:
            return True
    return False


@dataclass
class LabHit:
    """One ``apply()`` output before being merged into the pipeline reconcile."""
    lib_slug: str
    tech: str           # canonical name to feed reconcile
    version: str
    url: str
    regex_family: str

    def to_detection_dict(self) -> dict:
        return {
            "source": "lab",
            "name": self.tech,
            "version": self.version,
            "url": self.url,
            "template_id": f"lab:{self.lib_slug}",
            "matcher_name": self.regex_family,
            "extracted": {},
        }


async def _fetch_body(session, base: str, path: str, timeout: float) -> tuple[int, bytes]:
    """One HTTP GET. Returns ``(status, body)`` or ``(0, b"")`` on error."""
    url = base.rstrip("/") + ("" if path.startswith("/") else "/") + path
    try:
        # curl_cffi AsyncSession.get and our AsyncCloakFetcher.get
        # both accept this signature, so we can call apply() with either.
        r = await session.get(url, allow_redirects=True)
        body = r.content if isinstance(r.content, (bytes, bytearray)) else b""
        return r.status_code or 0, body
    except Exception:
        return 0, b""


async def apply(
    target_host: str,
    detections: list[dict],
    session,
    cache: LabCache,
    *,
    timeout: float = 10.0,
    max_probes: int = 50,
) -> list[LabHit]:
    """Run matching lab rules over ``target_host`` using ``session``.

    For each detection-side tech matched against a lab slug:
      1. Probe every ``body`` rule (fetch + regex).
      2. Probe every ``bundled`` rule (same flow; emits the *bundled* tech).

    URL rules are intentionally skipped here -- they're best applied
    against the pipeline's existing endpoint pool by the caller. See
    ``apply_url_rules()``.

    ``max_probes`` caps the total number of HTTP fetches issued. Each lab
    rule = one fetch; 18 plugins * 2 rules each ~ 36 probes worst case.
    """
    if not cache.libs_by_slug or not detections:
        return []
    slugs = _detection_slugs(detections)
    hits: list[LabHit] = []
    probes_left = max_probes

    matched_libs = [
        slug for slug in cache.libs_by_slug
        if _match_lab_lib(slugs, slug)
    ]
    if not matched_libs:
        return []

    # ---- body rules (the plugin / library's own version) -------------------
    fetch_tasks = []
    rule_refs: list[tuple[str, LabRule]] = []
    for slug in matched_libs:
        for rule in cache.body_rules_by_slug.get(slug, []):
            if probes_left <= 0:
                break
            probes_left -= 1
            fetch_tasks.append(_fetch_body(session, target_host, rule.path, timeout))
            rule_refs.append((slug, rule))

    # ---- bundled rules (only fire when the parent plugin is in matched_libs) -
    for slug in matched_libs:
        for rule in cache.bundled_rules_by_parent.get(slug, []):
            if probes_left <= 0:
                break
            probes_left -= 1
            fetch_tasks.append(_fetch_body(session, target_host, rule.path, timeout))
            rule_refs.append((slug, rule))

    if not fetch_tasks:
        return []

    results = await asyncio.gather(*fetch_tasks, return_exceptions=True)
    for (slug, rule), res in zip(rule_refs, results):
        if isinstance(res, Exception):
            continue
        status, body = res
        if not body or status >= 400:
            continue
        try:
            text = body.decode("utf-8", errors="replace")
        except Exception:
            continue
        m = rule.compiled.search(text)
        if not m or not m.groups():
            continue
        version = m.group(1)
        if not version:
            continue
        url = target_host.rstrip("/") + rule.path
        # For bundled rules, the canonical tech is the bundled inner tech;
        # for body rules, it's the lab lib slug itself.
        if rule.kind == "bundled" and rule.bundled_tech:
            tech_name = rule.bundled_tech
        else:
            product = cache.libs_by_slug.get(slug, {}).get("product")
            tech_name = product or slug
        hits.append(LabHit(
            lib_slug=slug,
            tech=tech_name,
            version=version,
            url=url,
            regex_family=rule.regex_family,
        ))
    return hits


def apply_url_rules(urls: Iterable[str], cache: LabCache) -> list[LabHit]:
    """Apply lab URL-pattern rules over a discovered URL pool. No fetch."""
    if not cache.url_rules:
        return []
    out: list[LabHit] = []
    seen: set[tuple[str, str]] = set()
    for u in urls:
        if not u:
            continue
        for rule in cache.url_rules:
            m = rule.compiled.search(u)
            if not m or not m.groups():
                continue
            version = m.group(1)
            key = (rule.lib_slug, version)
            if key in seen:
                continue
            seen.add(key)
            product = cache.libs_by_slug.get(rule.lib_slug, {}).get("product")
            out.append(LabHit(
                lib_slug=rule.lib_slug,
                tech=product or rule.lib_slug,
                version=version,
                url=u,
                regex_family=rule.regex_family,
            ))
    return out
