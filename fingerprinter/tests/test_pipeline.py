"""Tests for fp.pipeline (reconcile + end-to-end orchestration)."""

from __future__ import annotations

from fp import pipeline as pl
from fp import version_probes as vp


# ---------------------------------------------------------------------------
# reconcile()
# ---------------------------------------------------------------------------


def _det(source: str, name: str, version: str | None = None, **kw) -> dict:
    """Helper: build a Detection-like dict matching scanner.Detection.to_dict."""
    return {
        "source": source,
        "template_id": kw.get("template_id", f"{source}:{name}"),
        "name": name,
        "matcher_name": kw.get("matcher_name"),
        "vendor": kw.get("vendor"),
        "product": kw.get("product") or name,
        "category": kw.get("category"),
        "cpe": kw.get("cpe"),
        "severity": kw.get("severity"),
        "tags": kw.get("tags", []),
        "url": kw.get("url", "https://t.test/"),
        "path": kw.get("path", "/"),
        "extracted": kw.get("extracted", {}),
        "version": version,
        "confidence": kw.get("confidence"),
    }


def _hit(name: str, version: str, path: str = "/x") -> vp.ProbeHit:
    return vp.ProbeHit(
        probe=vp.Probe(name=name, path=path, regex="."),
        version=version, status=200, url=f"https://t.test{path}",
    )


class TestReconcileSourceMerging:
    def test_single_detection_creates_record(self):
        recs = pl.reconcile([_det("nuclei", "WordPress", "6.4.3")], [])
        assert len(recs) == 1
        assert recs[0].name == "WordPress"
        assert recs[0].version == "6.4.3"
        assert recs[0].sources == ["nuclei"]

    def test_two_sources_same_tech_merge(self):
        dets = [
            _det("wappalyzer", "WordPress", "6.4"),
            _det("nuclei", "WordPress", None),
        ]
        recs = pl.reconcile(dets, [])
        assert len(recs) == 1
        assert sorted(recs[0].sources) == ["nuclei", "wappalyzer"]

    def test_version_probe_outranks_wappalyzer(self):
        """version-probe is hand-curated and should win on version conflicts."""
        dets = [_det("wappalyzer", "WordPress", "6.4")]
        hits = [_hit("WordPress", "6.4.3")]
        recs = pl.reconcile(dets, hits)
        assert len(recs) == 1
        assert recs[0].version == "6.4.3"
        assert "version-probe" in recs[0].sources
        assert "wappalyzer" in recs[0].sources

    def test_more_specific_version_wins_within_same_rank(self):
        # Two wappalyzer hits, second is more specific.
        dets = [
            _det("wappalyzer", "nginx", "1.25"),
            _det("wappalyzer", "nginx", "1.25.3"),
        ]
        recs = pl.reconcile(dets, [])
        assert recs[0].version == "1.25.3"

    def test_first_version_kept_when_no_better_evidence(self):
        dets = [
            _det("wappalyzer", "nginx", "1.25.3"),
            _det("wappalyzer", "nginx", "1.25"),  # less specific, ignored
        ]
        recs = pl.reconcile(dets, [])
        assert recs[0].version == "1.25.3"

    def test_canonicalised_name_dedup_strips_prefixes(self):
        # Wappalyzer prefixes its template_id with wap:, retire.js with retire:.
        # The reconcile name-key should normalise so wp:WordPress and bare
        # WordPress collapse to the same record.
        dets = [
            _det("wappalyzer", "WordPress", "6.4.3", template_id="wap:WordPress"),
            _det("nuclei", "WordPress", None, template_id="wp-detect"),
        ]
        recs = pl.reconcile(dets, [])
        assert len(recs) == 1
        assert recs[0].version == "6.4.3"

    def test_space_and_hyphen_name_variants_merge(self):
        # Wappalyzer names "jQuery Migrate" (spaces); retire.js names it
        # "jquery-migrate" (hyphens). They must collapse to one record.
        dets = [
            _det("wappalyzer", "jQuery Migrate", "3.4.1"),
            _det("retirejs", "jquery-migrate", "3.4.1"),
        ]
        recs = pl.reconcile(dets, [])
        assert len(recs) == 1, f"expected 1 record, got {[r.name for r in recs]}"
        assert recs[0].version == "3.4.1"
        assert sorted(recs[0].sources) == ["retirejs", "wappalyzer"]

    def test_no_version_anywhere_record_still_emitted(self):
        recs = pl.reconcile([_det("nuclei", "Cloudflare")], [])
        assert len(recs) == 1
        assert recs[0].version is None
        assert recs[0].version_confidence is None

    def test_evidence_has_one_entry_per_source(self):
        dets = [_det("wappalyzer", "WordPress", "6.4")]
        hits = [_hit("WordPress", "6.4.3")]
        recs = pl.reconcile(dets, hits)
        assert len(recs[0].evidence) == 2

    def test_versioned_record_marked_exact(self):
        recs = pl.reconcile([_det("nuclei", "X", "1.0")], [])
        assert recs[0].version_confidence == "exact"

    def test_multiple_techs_sorted_versioned_first(self):
        dets = [
            _det("nuclei", "Apple"),       # no version
            _det("nuclei", "Banana", "1"),  # has version
            _det("nuclei", "Cherry"),       # no version
        ]
        recs = pl.reconcile(dets, [])
        assert [r.name for r in recs] == ["Banana", "Apple", "Cherry"]


class TestReconcileWappalyzerExtractedFallback:
    def test_pulls_version_from_extracted_dict(self):
        # Wappalyzer scanner-side puts version in extracted["version"][0]
        # when the rule has a version_tmpl. Top-level `version` may be None
        # in older artefacts -- reconcile() must still find it.
        det = _det(
            "wappalyzer", "PHP", version=None,
            extracted={"version": ["8.2.10"]},
        )
        recs = pl.reconcile([det], [])
        assert recs[0].version == "8.2.10"


class TestJsextractIsNotATech:
    """Regression: scanner --jsextract emits Detection(source='jsextract',
    name=path) records that previously polluted the tech list with URL
    paths like '/api/login'. They belong in endpoints, not techs."""

    def test_jsextract_detection_dropped_from_techs(self):
        dets = [
            _det("nuclei", "Cloudflare"),
            _det("jsextract", "/accounts/login", path="/accounts/login"),
            _det("jsextract", "/graphql", path="/graphql"),
            _det("retirejs", "jquery", "3.7.1"),
        ]
        recs = pl.reconcile(dets, [])
        names = {r.name for r in recs}
        # URL paths must not appear as techs
        assert "/accounts/login" not in names
        assert "/graphql" not in names
        # Real techs survive
        assert "Cloudflare" in names
        assert "jquery" in names

    def test_jsextract_does_not_create_record_even_solo(self):
        # A scan that only produced jsextract paths should yield zero techs.
        dets = [
            _det("jsextract", "/api/x", path="/api/x"),
            _det("jsextract", "/api/y", path="/api/y"),
        ]
        recs = pl.reconcile(dets, [])
        assert recs == []


class TestUserAgentResolver:
    def test_scanner_preset_returns_scanner_ua(self):
        from fp import scanner as sc
        assert pl.resolve_ua("scanner") == sc.DEFAULT_UA

    def test_chrome_preset_returns_browser_ua(self):
        ua = pl.resolve_ua("chrome")
        assert "Chrome/" in ua and "Mozilla/5.0" in ua

    def test_arbitrary_string_passes_through(self):
        custom = "MyCustomScanner/2.0"
        assert pl.resolve_ua(custom) == custom

    def test_default_pipeline_config_uses_chrome(self):
        cfg = pl.PipelineConfig()
        assert cfg.user_agent == "chrome"
        # Chrome preset must resolve to a browser-shaped UA, not the
        # honest scanner UA -- this is the whole point of the default.
        from fp import scanner as sc
        assert pl.resolve_ua(cfg.user_agent) != sc.DEFAULT_UA


class TestComposeEndpoints:
    """Endpoints must surface katana's discovered URLs (page_urls + js_urls),
    not just the body-extracted paths. The user reported that on a 492-page
    crawl the pipeline reported endpoints=3 because page_urls/js_urls were
    only counted in stats and then thrown away."""

    def _make_katana(
        self,
        page_urls=None, js_urls=None, paths=None,
        seed="https://t.test",
    ):
        from fp import katana as kat
        from fp.jsextract import ExtractedPath
        return kat.KatanaResult(
            seed=seed,
            page_urls=list(page_urls or []),
            js_urls=list(js_urls or []),
            paths=[
                ExtractedPath(path=p, confidence="api", source_url=seed)
                for p in (paths or [])
            ],
        )

    def test_page_urls_appear_as_endpoints(self):
        kr = self._make_katana(
            page_urls=["https://t.test/a", "https://t.test/b"],
        )
        eps, _, _ = pl._compose_endpoints([], kr)
        bys = {e["discovered_by"] for e in eps}
        assert "katana-page" in bys
        paths = {e["path"] for e in eps}
        assert "https://t.test/a" in paths
        assert "https://t.test/b" in paths

    def test_js_urls_appear_as_endpoints_with_separate_tag(self):
        kr = self._make_katana(
            js_urls=["https://t.test/app.js", "https://t.test/vendor.js"],
        )
        eps, _, _ = pl._compose_endpoints([], kr)
        js_eps = [e for e in eps if e["discovered_by"] == "katana-js"]
        assert len(js_eps) == 2

    def test_extracted_paths_keep_their_own_tag(self):
        kr = self._make_katana(paths=["/api/x"])
        eps, _, _ = pl._compose_endpoints([], kr)
        assert any(
            e["discovered_by"] == "katana-extracted" and e["path"] == "/api/x"
            for e in eps
        )

    def test_dedup_first_seen_wins_when_same_path(self):
        # scanner-jsextract reports /api/x AND katana also crawled
        # https://t.test/api/x as a page. They have distinct path strings
        # so both survive -- this test guards against accidental over-dedup.
        det = _det("jsextract", "/api/x", path="/api/x")
        kr = self._make_katana(
            page_urls=["https://t.test/api/x"],
            paths=["/api/x"],
        )
        eps, _, _ = pl._compose_endpoints([det], kr)
        # /api/x deduped between jsextract and katana-extracted (same path)
        # but the full URL https://t.test/api/x stays separately.
        paths = [e["path"] for e in eps]
        assert paths.count("/api/x") == 1
        assert "https://t.test/api/x" in paths

    def test_no_katana_result_still_returns_jsextract_endpoints(self):
        det = _det("jsextract", "/login", path="/login")
        eps, leaks, hosts = pl._compose_endpoints([det], None)
        assert eps == [{
            "path": "/login",
            "confidence": None,
            "source_url": "https://t.test/",
            "discovered_by": "scanner-jsextract",
        }]
        assert leaks == []
        assert hosts == []

    def test_realistic_volume_492_pages_7_js_all_surface(self):
        """Regression for the metruyenchu.com.vn report: 492 pages + 7 JS
        bundles must all appear, not be silently dropped."""
        kr = self._make_katana(
            page_urls=[f"https://t.test/p{i}" for i in range(492)],
            js_urls=[f"https://t.test/j{i}.js" for i in range(7)],
            paths=["/api/login", "/api/users", "/admin"],
        )
        eps, _, _ = pl._compose_endpoints([], kr)
        page_count = sum(1 for e in eps if e["discovered_by"] == "katana-page")
        js_count = sum(1 for e in eps if e["discovered_by"] == "katana-js")
        ext_count = sum(1 for e in eps if e["discovered_by"] == "katana-extracted")
        assert page_count == 492
        assert js_count == 7
        assert ext_count == 3
        assert len(eps) == 502


class TestTechRecordToDict:
    def test_categories_deduped_and_sorted(self):
        rec = pl.TechRecord(
            name="X", version="1.0",
            categories=["CMS", "Analytics", "CMS"],
            sources=["nuclei", "wappalyzer", "nuclei"],
        )
        d = rec.to_dict()
        assert d["categories"] == ["Analytics", "CMS"]
        assert d["sources"] == ["nuclei", "wappalyzer"]
