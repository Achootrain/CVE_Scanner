"""Funnel-stage unit tests.

Covers the §7a uniform-funnel contract for ``fp.stages``:

  * load_rules / lookup_canonical_name read from lab.db rows -- no
    hardcoded slug -> name dict anywhere in scanner code.
  * _apply_banner_rules emits dotted-numeric versions only.
  * extract_inline_blocks pulls inline <style>/<script> contents.
  * InlineExtractStage / BundleScanStage are pure transforms over
    StageContext -- given the same context, deterministic output.
"""

from __future__ import annotations

import asyncio
import sqlite3
from pathlib import Path

import pytest

from fp import stages


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def lab_db(tmp_path: Path) -> str:
    """Minimal lab.db with two techs + one banner rule + one bundle rule."""
    db = tmp_path / "lab.db"
    conn = sqlite3.connect(str(db))
    conn.executescript("""
        CREATE TABLE lab_pkg_aliases (
            id INTEGER PRIMARY KEY,
            alias TEXT NOT NULL,
            tech TEXT,
            context TEXT NOT NULL,
            origin TEXT NOT NULL,
            note TEXT
        );
        CREATE TABLE lab_src_rules (
            id INTEGER PRIMARY KEY,
            tech_slug TEXT NOT NULL,
            rule_id TEXT NOT NULL,
            section TEXT NOT NULL,
            kind TEXT NOT NULL,
            pattern TEXT NOT NULL,
            extracts_json TEXT NOT NULL,
            generation_map TEXT,
            applies_to TEXT,
            confidence TEXT,
            source_json TEXT NOT NULL,
            note TEXT
        );
    """)
    conn.executemany(
        "INSERT INTO lab_pkg_aliases (alias, tech, context, origin) VALUES (?,?,?,?)",
        [
            ("font-awesome", "Font Awesome", "js-lib", "test"),
            ("slick", "Slick", "js-lib", "test"),
        ],
    )
    conn.executemany(
        "INSERT INTO lab_src_rules "
        "(tech_slug, rule_id, section, kind, pattern, extracts_json, source_json) "
        "VALUES (?,?,?,?,?,?,?)",
        [
            ("font-awesome", "fa-banner",
             "banner_rules", "regex",
             r"Font Awesome (\d+\.\d+(?:\.\d+)?) by @davegandy",
             '{"version": {"g": 1}}', "{}"),
            ("slick", "slick-class",
             "css_class_rules", "regex",
             r"slick-slider", '{}', "{}"),
        ],
    )
    conn.commit()
    conn.close()
    return str(db)


def _run(coro):
    return asyncio.run(coro)


# ---------------------------------------------------------------------------
# Helper-level tests
# ---------------------------------------------------------------------------


class TestLabHelpers:
    def test_load_rules_compiles_patterns(self, lab_db):
        rules = stages.load_rules(lab_db, "banner_rules")
        assert len(rules) == 1
        rule = rules[0]
        assert rule["tech_slug"] == "font-awesome"
        assert rule["version_group"] == 1
        assert rule["pattern"].search("Font Awesome 4.7.0 by @davegandy")

    def test_load_rules_filters_by_tech(self, lab_db):
        assert stages.load_rules(lab_db, "banner_rules", tech_slug="slick") == []

    def test_lookup_canonical_name_hits_db(self, lab_db):
        assert stages.lookup_canonical_name(lab_db, "font-awesome") == "Font Awesome"
        assert stages.lookup_canonical_name(lab_db, "slick") == "Slick"

    def test_lookup_canonical_name_falls_back_for_unknown_slug(self, lab_db):
        # No row -> title-cased slug. The fallback exists so a stage never
        # explodes when the lab hasn't seeded an alias yet.
        assert stages.lookup_canonical_name(lab_db, "new-tech") == "New Tech"

    def test_is_dotted_version(self):
        assert stages.is_dotted_version("4.7.0")
        assert stages.is_dotted_version("1.2")
        assert not stages.is_dotted_version("4")
        assert not stages.is_dotted_version("abc123")
        assert not stages.is_dotted_version(None)


class TestCandidateAssetUrls:
    """The careforvietnam.vn bug -- regression test.

    Scanner emits evidence_url verbatim from HTML, which is often relative
    (``catalog/view/.../font-awesome.min.css``). BodyExtractStage must
    resolve those against the detection's page URL before fetching, or
    Stage 2's banner_rules never get a chance to fire."""

    def test_resolves_relative_evidence_url_against_page_url(self):
        ctx = stages.StageContext(
            target="https://careforvietnam.vn/",
            lab_db=None, ua="t",
            detections=[{
                "name": "font-awesome",
                "url": "https://careforvietnam.vn/",
                "evidence_url": (
                    "catalog/view/javascript/font-awesome/css/font-awesome.min.css"
                ),
                "version": None,
            }],
        )
        candidates = stages._candidate_asset_urls(ctx)
        assert candidates == [
            "https://careforvietnam.vn/"
            "catalog/view/javascript/font-awesome/css/font-awesome.min.css"
        ]

    def test_root_relative_url_resolved(self):
        ctx = stages.StageContext(
            target="https://x/", lab_db=None, ua="t",
            detections=[{
                "name": "slick",
                "url": "https://x/some/page",
                "evidence_url": "/assets/slick.min.js",
                "version": None,
            }],
        )
        assert stages._candidate_asset_urls(ctx) == \
            ["https://x/assets/slick.min.js"]

    def test_protocol_relative_url_gets_page_scheme(self):
        ctx = stages.StageContext(
            target="https://x/", lab_db=None, ua="t",
            detections=[{
                "name": "fa", "url": "https://x/",
                "evidence_url": "//cdn.test/font-awesome.css",
                "version": None,
            }],
        )
        assert stages._candidate_asset_urls(ctx) == \
            ["https://cdn.test/font-awesome.css"]

    def test_absolute_url_passes_through_unchanged(self):
        ctx = stages.StageContext(
            target="https://x/", lab_db=None, ua="t",
            detections=[{
                "name": "fa", "url": "https://x/",
                "evidence_url": "https://cdn.test/x/font-awesome.min.css",
                "version": None,
            }],
        )
        assert stages._candidate_asset_urls(ctx) == \
            ["https://cdn.test/x/font-awesome.min.css"]

    def test_versioned_techs_are_skipped(self):
        ctx = stages.StageContext(
            target="https://x/", lab_db=None, ua="t",
            detections=[{
                "name": "font-awesome", "product": "font-awesome",
                "url": "https://x/", "evidence_url": "/fa.css",
                "version": "4.7.0",
            }],
        )
        assert stages._candidate_asset_urls(ctx) == []

    def test_url_pool_entries_resolve_against_ctx_target(self):
        ctx = stages.StageContext(
            target="https://example.com/", lab_db=None, ua="t",
            url_pool=["/static/foo.css", "https://cdn/abs.js"],
        )
        # Both end up absolute; ctx.target is the fallback base.
        candidates = stages._candidate_asset_urls(ctx)
        assert "https://example.com/static/foo.css" in candidates
        assert "https://cdn/abs.js" in candidates


class TestInlineBlocks:
    def test_extracts_style_and_script(self):
        html = (
            "<html><head>"
            "<style>.foo { color: red; }</style>"
            "<script src=\"app.js\"></script>"  # NOT inline, has src
            "<script>window.__X={a:1};</script>"
            "</head></html>"
        )
        blocks = stages.extract_inline_blocks(html)
        assert ".foo { color: red; }" in blocks
        assert "window.__X={a:1};" in blocks
        # src-loaded script is Stage 4's job, not Stage 3
        assert not any("app.js" in b for b in blocks)


# ---------------------------------------------------------------------------
# Stage tests
# ---------------------------------------------------------------------------


class TestBodyAndInlineStages:
    def test_apply_banner_rules_emits_dotted_version_only(self, lab_db):
        rules = stages.load_rules(lab_db, "banner_rules")
        # Real dotted version -> emits detection
        out = stages._apply_banner_rules(
            rules, "Font Awesome 4.7.0 by @davegandy",
            lab_db, "https://x/y.css",
        )
        assert len(out) == 1
        assert out[0]["name"] == "Font Awesome"
        assert out[0]["version"] == "4.7.0"
        assert out[0]["source"] == "banner"
        assert out[0]["url"] == "https://x/y.css"
        assert out[0]["matcher_name"] == "fa-banner"

    def test_apply_banner_rules_rejects_non_dotted(self, lab_db):
        # If somebody writes a bad rule whose group captures an integer
        # only, _apply_banner_rules must drop it -- that contract lives in
        # is_dotted_version, not in the rule itself.
        with sqlite3.connect(lab_db) as c:
            c.execute(
                "INSERT INTO lab_src_rules "
                "(tech_slug, rule_id, section, kind, pattern, extracts_json, source_json) "
                "VALUES (?,?,?,?,?,?,?)",
                ("font-awesome", "fa-bad", "banner_rules", "regex",
                 r"Font Awesome (\d+) by", '{"version": {"g": 1}}', "{}"),
            )
        rules = stages.load_rules(lab_db, "banner_rules")
        out = stages._apply_banner_rules(
            rules, "Font Awesome 4 by @davegandy",
            lab_db, "https://x/y.css",
        )
        assert out == []

    def test_inline_extract_stage_is_pure(self, lab_db):
        ctx = stages.StageContext(
            target="https://x/", lab_db=lab_db, ua="t",
            html_bodies={
                "https://x/": (
                    "<html><script>/* Font Awesome 5.15.4 by @davegandy */"
                    "window.X=1;</script></html>"
                ),
            },
        )
        out = _run(stages.InlineExtractStage().apply(ctx))
        assert len(out) == 1
        assert out[0]["name"] == "Font Awesome"
        assert out[0]["version"] == "5.15.4"

    def test_inline_extract_noop_without_lab_db(self):
        ctx = stages.StageContext(
            target="https://x/", lab_db=None, ua="t",
            html_bodies={"https://x/": "<style>.x{}</style>"},
        )
        assert _run(stages.InlineExtractStage().apply(ctx)) == []


class TestBundleScan:
    def test_bundle_scan_emits_presence_only(self, lab_db):
        ctx = stages.StageContext(
            target="https://x/", lab_db=lab_db, ua="t",
            js_bodies={"https://x/app.js": "var foo='slick-slider';"},
        )
        out = _run(stages.BundleScanStage().apply(ctx))
        assert len(out) == 1
        assert out[0]["name"] == "Slick"
        assert out[0]["version"] is None
        assert out[0]["source"] == "bundle"

    def test_bundle_scan_skips_already_present(self, lab_db):
        # If Slick was already detected (with or without a version), we
        # don't want a duplicate presence-only hit cluttering the output.
        ctx = stages.StageContext(
            target="https://x/", lab_db=lab_db, ua="t",
            detections=[{"name": "Slick", "version": "1.8.1"}],
            js_bodies={"https://x/app.js": "var foo='slick-slider';"},
        )
        out = _run(stages.BundleScanStage().apply(ctx))
        assert out == []


# ---------------------------------------------------------------------------
# §7a anti-pattern guard
# ---------------------------------------------------------------------------


class TestNoTechSpecificBranches:
    """Pin the §7a invariant: no slug -> canonical-name dict lives in
    Python. The mapping comes from lab_pkg_aliases. If somebody adds
    another aliases dict back to the codebase, this test fails."""

    def test_no_hardcoded_alias_dict_in_pipeline(self):
        from pathlib import Path as _P
        pipeline_src = (_P(__file__).resolve().parent.parent / "fp" / "pipeline.py").read_text(encoding="utf-8")
        # The previous offender: {"font-awesome": "Font Awesome", "slick": "Slick"}
        assert "\"font-awesome\": \"Font Awesome\"" not in pipeline_src
        assert "'font-awesome': 'Font Awesome'" not in pipeline_src

    def test_no_hardcoded_alias_dict_in_stages(self):
        from pathlib import Path as _P
        stages_src = (_P(__file__).resolve().parent.parent / "fp" / "stages.py").read_text(encoding="utf-8")
        assert "\"font-awesome\": \"Font Awesome\"" not in stages_src
        assert "'font-awesome': 'Font Awesome'" not in stages_src
