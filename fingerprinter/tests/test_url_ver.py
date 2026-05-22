"""Tests for fp.url_ver -- multi-method URL version/tech extraction."""

from __future__ import annotations

from fp.url_ver import (
    UrlVerHit,
    WP_PLUGIN_MAP,
    _classify_path,
    _extract_from_filename,
    _js_stem,
    _try_cdn_url,
    _try_filename_version,
    _try_framework_pattern,
    _try_query_param,
    _wp_segment,
    extract_ver_params,
)


# ---------------------------------------------------------------------------
# _js_stem
# ---------------------------------------------------------------------------


class TestJsStem:
    def test_strips_min_js(self):
        assert _js_stem("jquery.min.js") == "jquery"

    def test_strips_plain_js(self):
        assert _js_stem("lodash.js") == "lodash"

    def test_strips_min_css(self):
        assert _js_stem("font-awesome.min.css") == "font-awesome"

    def test_strips_plain_css(self):
        assert _js_stem("font-awesome.css") == "font-awesome"

    def test_strips_bundle_min_js(self):
        assert _js_stem("bootstrap.bundle.min.js") == "bootstrap"

    def test_strips_bundle_js(self):
        assert _js_stem("app.bundle.js") == "app"

    def test_strips_mjs(self):
        assert _js_stem("vue.mjs") == "vue"

    def test_strips_bundle_min_before_min(self):
        # .bundle.min.js must be stripped as one unit, not .min.js first
        assert _js_stem("bootstrap.bundle.min.js") == "bootstrap"

    def test_strips_prod_js(self):
        # .production.min.js: strips .min.js leaving .production suffix
        assert _js_stem("react.production.min.js") == "react.production"

    def test_lowercase(self):
        assert _js_stem("Bootstrap.min.js") == "bootstrap"

    def test_no_extension(self):
        assert _js_stem("jquery") == "jquery"


# ---------------------------------------------------------------------------
# _wp_segment
# ---------------------------------------------------------------------------


class TestWpSegment:
    def test_plugin_slug(self):
        assert _wp_segment(
            "/wp-content/plugins/woocommerce/assets/js/woo.min.js", "plugins"
        ) == "woocommerce"

    def test_theme_slug(self):
        assert _wp_segment(
            "/wp-content/themes/twentytwentyfour/style.css", "themes"
        ) == "twentytwentyfour"

    def test_not_found(self):
        assert _wp_segment("/assets/js/app.js", "plugins") is None

    def test_case_insensitive_path(self):
        assert _wp_segment(
            "/WP-Content/Plugins/elementor/assets/js/elementor.js", "plugins"
        ) == "elementor"


# ---------------------------------------------------------------------------
# _classify_path (replaces old _classify_url)
# ---------------------------------------------------------------------------


class TestClassifyPath:
    def test_wp_plugin_curated(self):
        url = "https://example.com/wp-content/plugins/woocommerce/assets/js/woocommerce.min.js?ver=8.0.0"
        name, slug = _classify_path(url)
        assert name == "WooCommerce"
        assert slug == "woocommerce"

    def test_wp_plugin_fallback_title_case(self):
        url = "https://example.com/wp-content/plugins/my-cool-plugin/js/script.js?ver=1.0.0"
        name, slug = _classify_path(url)
        assert name == "My Cool Plugin"
        assert slug == "my-cool-plugin"

    def test_wp_theme(self):
        url = "https://example.com/wp-content/themes/divi/js/custom.min.js?ver=4.24.0"
        name, slug = _classify_path(url)
        assert name == "WP Theme: Divi"
        assert slug == "divi"

    def test_known_js_lib(self):
        url = "https://example.com/assets/js/jquery.min.js?v=3.7.1"
        name, slug = _classify_path(url)
        assert name == "jQuery"
        assert slug == "jquery"

    def test_unknown_stem_skipped(self):
        url = "https://example.com/assets/js/myapp.min.js?v=2.0.0"
        assert _classify_path(url) is None

    def test_skip_stem_app(self):
        url = "https://example.com/static/app.js?v=1.2.3"
        assert _classify_path(url) is None

    def test_no_filename(self):
        url = "https://example.com/?v=1.0.0"
        assert _classify_path(url) is None

    # --- Regression: known JS/CSS lib filename should win over WP plugin slug ---
    # See CLAUDE.md "problem exist": casio-vietnam.vn was being mis-attributed
    # as "Contact Widgets" when the URL was actually loading font-awesome
    # bundled inside that plugin. Tail (filename) > head (path slug).

    def test_known_css_lib_wins_over_wp_plugin(self):
        url = (
            "https://www.casio-vietnam.vn/wp-content/plugins/contact-widgets/"
            "assets/css/font-awesome.min.css?ver=4.7.0"
        )
        name, slug = _classify_path(url)
        assert name == "Font Awesome"
        assert slug == "font-awesome"

    def test_known_js_lib_wins_over_wp_plugin(self):
        url = (
            "https://example.com/wp-content/plugins/some-plugin/"
            "vendor/jquery.min.js?ver=3.7.1"
        )
        name, slug = _classify_path(url)
        assert name == "jQuery"
        assert slug == "jquery"

    def test_unknown_filename_falls_back_to_wp_plugin(self):
        # Preserve old behavior: unknown stem inside known plugin path -> plugin wins.
        url = "https://example.com/wp-content/plugins/elementor/assets/js/custom.js?ver=3.4.3"
        name, slug = _classify_path(url)
        assert name == "Elementor"
        assert slug == "elementor"

    def test_skip_stem_filename_falls_back_to_wp_plugin(self):
        # Skip-stem filename inside known plugin -> plugin wins (no useful lib signal).
        url = "https://example.com/wp-content/plugins/elementor/assets/js/app.js?ver=3.4.3"
        name, slug = _classify_path(url)
        assert name == "Elementor"
        assert slug == "elementor"


# ---------------------------------------------------------------------------
# _extract_from_filename
# ---------------------------------------------------------------------------


class TestExtractFromFilename:
    def test_hyphen_separator(self):
        name, version, stem = _extract_from_filename("jquery-3.7.1.min.js")
        assert name == "jQuery"
        assert version == "3.7.1"
        assert stem == "jquery"

    def test_dot_separator(self):
        name, version, stem = _extract_from_filename("vue.3.4.15.esm.js")
        assert name == "Vue.js"
        assert version == "3.4.15"

    def test_bundle_min_stripped(self):
        result = _extract_from_filename("bootstrap-5.3.0.bundle.min.js")
        assert result is not None
        name, version, stem = result
        assert name == "Bootstrap"
        assert version == "5.3.0"

    def test_longer_stem_wins_react_dom(self):
        # react-dom-18.2.0.min.js should match "react-dom", not "react"
        result = _extract_from_filename("react-dom-18.2.0.min.js")
        assert result is not None
        name, version, _ = result
        assert name == "React"
        assert version == "18.2.0"

    def test_four_part_version(self):
        result = _extract_from_filename("jquery-1.11.0.min.js")
        assert result is not None
        _, version, _ = result
        assert version == "1.11.0"

    def test_unknown_lib_none(self):
        assert _extract_from_filename("mylib-2.0.0.min.js") is None

    def test_no_version_none(self):
        assert _extract_from_filename("jquery.min.js") is None

    def test_case_insensitive(self):
        result = _extract_from_filename("Bootstrap-5.2.0.min.js")
        assert result is not None
        name, version, _ = result
        assert name == "Bootstrap"
        assert version == "5.2.0"


# ---------------------------------------------------------------------------
# _try_cdn_url
# ---------------------------------------------------------------------------


class TestTryCdnUrl:
    def test_jsdelivr_npm(self):
        url = "https://cdn.jsdelivr.net/npm/jquery@3.7.1/dist/jquery.min.js"
        result = _try_cdn_url(url)
        assert result is not None
        name, version, _ = result
        assert name == "jQuery"
        assert version == "3.7.1"

    def test_jsdelivr_scoped_package(self):
        url = "https://cdn.jsdelivr.net/npm/@popperjs/core@2.11.8/dist/umd/popper.min.js"
        result = _try_cdn_url(url)
        assert result is not None
        name, version, _ = result
        assert name == "Popper.js"
        assert version == "2.11.8"

    def test_unpkg(self):
        url = "https://unpkg.com/react@18.2.0/umd/react.production.min.js"
        result = _try_cdn_url(url)
        assert result is not None
        name, version, _ = result
        assert name == "React"
        assert version == "18.2.0"

    def test_cdnjs(self):
        url = "https://cdnjs.cloudflare.com/ajax/libs/bootstrap/5.3.0/js/bootstrap.bundle.min.js"
        result = _try_cdn_url(url)
        assert result is not None
        name, version, _ = result
        assert name == "Bootstrap"
        assert version == "5.3.0"

    def test_googleapis(self):
        url = "https://ajax.googleapis.com/ajax/libs/jquery/3.7.1/jquery.min.js"
        result = _try_cdn_url(url)
        assert result is not None
        name, version, _ = result
        assert name == "jQuery"
        assert version == "3.7.1"

    def test_bootstrapcdn(self):
        url = "https://stackpath.bootstrapcdn.com/bootstrap/5.3.0/js/bootstrap.min.js"
        result = _try_cdn_url(url)
        assert result is not None
        name, version, _ = result
        assert name == "Bootstrap"
        assert version == "5.3.0"

    def test_code_jquery_com(self):
        url = "https://code.jquery.com/jquery-3.7.1.min.js"
        result = _try_cdn_url(url)
        assert result is not None
        name, version, _ = result
        assert name == "jQuery"
        assert version == "3.7.1"

    def test_unknown_cdn_package_none(self):
        url = "https://cdn.jsdelivr.net/npm/my-obscure-lib@1.0.0/dist/index.js"
        assert _try_cdn_url(url) is None

    def test_non_cdn_url_none(self):
        assert _try_cdn_url("https://example.com/assets/js/app.js") is None

    def test_hash_version_rejected(self):
        url = "https://cdn.jsdelivr.net/npm/jquery@abc123/dist/jquery.js"
        assert _try_cdn_url(url) is None


# ---------------------------------------------------------------------------
# _try_filename_version
# ---------------------------------------------------------------------------


class TestTryFilenameVersion:
    def test_jquery_versioned(self):
        url = "https://5sfashion.vn/frontend/assets/js/jquery-3.6.3.min.js"
        result = _try_filename_version(url)
        assert result is not None
        name, version, stem = result
        assert name == "jQuery"
        assert version == "3.6.3"

    def test_jquery_old_version(self):
        url = "https://769audio.vn/js/jquery-1.9.1.min.js"
        result = _try_filename_version(url)
        assert result is not None
        _, version, _ = result
        assert version == "1.9.1"

    def test_no_version_in_filename_none(self):
        # bootstrap.min.js has no version embedded
        assert _try_filename_version("https://example.com/library/bootstrap/js/bootstrap.min.js") is None

    def test_unknown_lib_none(self):
        assert _try_filename_version("https://example.com/js/mylib-2.0.0.min.js") is None


# ---------------------------------------------------------------------------
# _try_framework_pattern
# ---------------------------------------------------------------------------


class TestTryFrameworkPattern:
    def test_next_js_official_path(self):
        url = "https://example.com/_next/static/chunks/main.js"
        result = _try_framework_pattern(url)
        assert result is not None
        tech, version, slug = result
        assert tech == "Next.js"
        assert version is None
        assert slug == "next.js"

    def test_next_js_custom_base_path_chunk(self):
        # 2dep.vn pattern: /static/chunks/<name>-<16-hex>.js
        url = "https://2dep.vn/static/chunks/4841-17a8ef22630c2e4d.js"
        result = _try_framework_pattern(url)
        assert result is not None
        tech, version, _ = result
        assert tech == "Next.js"
        assert version is None

    def test_next_js_app_dir_chunk(self):
        url = "https://2dep.vn/static/chunks/app/layout-1439af072a807e67.js"
        result = _try_framework_pattern(url)
        assert result is not None
        assert result[0] == "Next.js"

    def test_nuxt_js(self):
        url = "https://example.com/_nuxt/entry.abc12345.js"
        result = _try_framework_pattern(url)
        assert result is not None
        assert result[0] == "Nuxt.js"

    def test_sveltekit(self):
        url = "https://example.com/_app/immutable/chunks/start.a1b2c3d4.js"
        result = _try_framework_pattern(url)
        assert result is not None
        assert result[0] == "SvelteKit"

    def test_gatsby(self):
        url = "https://example.com/page-data/index/page-data.json"
        result = _try_framework_pattern(url)
        assert result is not None
        assert result[0] == "Gatsby"

    def test_regular_js_none(self):
        assert _try_framework_pattern("https://example.com/assets/js/app.min.js") is None

    def test_non_next_chunk_no_match(self):
        # 15-char hex (not 16) should not match
        url = "https://example.com/static/chunks/app-17a8ef22630c2e4.js"
        assert _try_framework_pattern(url) is None


# ---------------------------------------------------------------------------
# extract_ver_params -- full integration
# ---------------------------------------------------------------------------


class TestExtractVerParams:
    def test_empty_input(self):
        assert extract_ver_params([]) == []

    def test_no_signals(self):
        urls = ["https://example.com/style.css", "https://example.com/main.a1b2c3.js"]
        assert extract_ver_params(urls) == []

    # -- query-param (original method) --

    def test_wp_plugin_ver(self):
        urls = [
            "https://2game.vn/wp-content/plugins/peepso/assets/js/jquery.autosize.min.js?ver=7.0.1.1"
        ]
        hits = extract_ver_params(urls)
        assert len(hits) == 1
        h = hits[0]
        assert h.tech == "PeepSo"
        assert h.version == "7.0.1.1"
        assert h.slug == "peepso"

    def test_v_param_jquery(self):
        urls = ["https://example.com/assets/js/jquery.min.js?v=3.7.1"]
        hits = extract_ver_params(urls)
        assert len(hits) == 1
        assert hits[0].tech == "jQuery"
        assert hits[0].version == "3.7.1"

    def test_single_integer_version_rejected(self):
        urls = ["https://example.com/wp-content/plugins/jetpack/js/jp.js?ver=3"]
        assert extract_ver_params(urls) == []

    def test_hash_ver_param_no_filename_version(self):
        # ?ver=abc123 is rejected; filename has no version either
        urls = ["https://example.com/assets/js/app.js?ver=abc123"]
        assert extract_ver_params(urls) == []

    def test_version_too_long_rejected(self):
        urls = ["https://example.com/wp-content/plugins/woocommerce/js/woo.js?ver=1.2.3.4.5.6.7.8.9.0.1"]
        assert extract_ver_params(urls) == []

    def test_ampersand_ver_param(self):
        urls = ["https://example.com/wp-content/plugins/elementor/js/elementor.js?foo=1&ver=3.18.0"]
        hits = extract_ver_params(urls)
        assert len(hits) == 1
        assert hits[0].tech == "Elementor"
        assert hits[0].version == "3.18.0"

    # -- versioned filename (new method) --

    def test_jquery_versioned_filename(self):
        urls = ["https://5sfashion.vn/frontend/assets/js/jquery-3.6.3.min.js"]
        hits = extract_ver_params(urls)
        assert len(hits) == 1
        assert hits[0].tech == "jQuery"
        assert hits[0].version == "3.6.3"

    def test_multiple_sites_jquery_versioned(self):
        urls = [
            "https://568play.vn/st-ms/mainsite-3/js/jquery-1.11.0.min.js",
            "https://5giay.vn/js/jquery/jquery-1.11.0.min.js",
            "https://769audio.vn/js/jquery-1.9.1.min.js",
        ]
        hits = extract_ver_params(urls)
        tech_versions = {(h.tech, h.version) for h in hits}
        # jquery-1.11.0 from two sites deduped to one; jquery-1.9.1 separate
        assert ("jQuery", "1.11.0") in tech_versions
        assert ("jQuery", "1.9.1") in tech_versions
        assert len(hits) == 2

    def test_bootstrap_versioned_filename(self):
        urls = ["https://example.com/js/bootstrap-5.3.0.bundle.min.js"]
        hits = extract_ver_params(urls)
        assert len(hits) == 1
        assert hits[0].tech == "Bootstrap"
        assert hits[0].version == "5.3.0"

    # -- CDN URL (new method) --

    def test_cdn_jsdelivr_jquery(self):
        urls = ["https://cdn.jsdelivr.net/npm/jquery@3.7.1/dist/jquery.min.js"]
        hits = extract_ver_params(urls)
        assert len(hits) == 1
        assert hits[0].tech == "jQuery"
        assert hits[0].version == "3.7.1"

    def test_cdn_bootstrapcdn(self):
        urls = ["https://stackpath.bootstrapcdn.com/bootstrap/4.5.0/js/bootstrap.min.js"]
        hits = extract_ver_params(urls)
        assert len(hits) == 1
        assert hits[0].tech == "Bootstrap"
        assert hits[0].version == "4.5.0"

    def test_cdn_takes_priority_over_filename_ver(self):
        # URL is both a CDN URL AND has ?ver= -- CDN wins (checked first)
        url = "https://cdn.jsdelivr.net/npm/jquery@3.7.1/dist/jquery.min.js?ver=3.7.0"
        hits = extract_ver_params([url])
        assert len(hits) == 1
        assert hits[0].version == "3.7.1"  # CDN version, not query param

    # -- framework pattern (new method, version=None) --

    def test_next_js_detected_from_chunk_url(self):
        urls = [
            "https://2dep.vn/static/chunks/4841-17a8ef22630c2e4d.js",
            "https://2dep.vn/static/chunks/app/layout-1439af072a807e67.js",
            "https://2dep.vn/static/chunks/app/page-41fd59028fc0af22.js",
        ]
        hits = extract_ver_params(urls)
        # All three deduplicate to one Next.js hit (same tech, no version)
        assert len(hits) == 1
        h = hits[0]
        assert h.tech == "Next.js"
        assert h.version is None

    def test_next_js_official_path(self):
        urls = ["https://example.com/_next/static/chunks/main.a1b2c3.js"]
        hits = extract_ver_params(urls)
        assert len(hits) == 1
        assert hits[0].tech == "Next.js"
        assert hits[0].version is None

    def test_nuxt_detected(self):
        hits = extract_ver_params(["https://example.com/_nuxt/app.abc12345.js"])
        assert len(hits) == 1
        assert hits[0].tech == "Nuxt.js"

    def test_framework_and_library_same_run(self):
        urls = [
            "https://2dep.vn/static/chunks/4841-17a8ef22630c2e4d.js",
            "https://2dep.vn/assets/js/jquery-3.6.3.min.js",
        ]
        hits = extract_ver_params(urls)
        tech_set = {h.tech for h in hits}
        assert "Next.js" in tech_set
        assert "jQuery" in tech_set

    # -- dedup --

    def test_dedup_same_tech_version_multiple_urls(self):
        urls = [
            "https://example.com/wp-content/plugins/peepso/assets/js/a.js?ver=7.0.1.1",
            "https://example.com/wp-content/plugins/peepso/assets/js/b.js?ver=7.0.1.1",
        ]
        hits = extract_ver_params(urls)
        assert len(hits) == 1
        assert hits[0].url.endswith("a.js?ver=7.0.1.1")

    def test_same_tech_different_versions_both_kept(self):
        urls = [
            "https://example.com/wp-content/plugins/woocommerce/js/woo.js?ver=8.0.0",
            "https://example.com/wp-content/plugins/woocommerce/js/cart.js?ver=8.0.1",
        ]
        hits = extract_ver_params(urls)
        assert {h.version for h in hits} == {"8.0.0", "8.0.1"}

    def test_framework_dedup_across_many_chunk_urls(self):
        # 10 different chunk URLs should collapse to one Next.js hit
        urls = [
            f"https://site.com/static/chunks/chunk{i:04d}-17a8ef22630c2e4{i:x}.js"
            for i in range(10)
        ]
        hits = extract_ver_params(urls)
        assert sum(1 for h in hits if h.tech == "Next.js") == 1

    # -- to_detection_dict --

    def test_to_detection_dict_with_version(self):
        urls = ["https://example.com/wp-content/plugins/jetpack/js/jp.min.js?ver=13.1.0"]
        d = extract_ver_params(urls)[0].to_detection_dict()
        assert d["source"] == "url-ver"
        assert d["product"] == "Jetpack"
        assert d["version"] == "13.1.0"
        assert d["template_id"] == "url-ver:jetpack"

    def test_to_detection_dict_version_none(self):
        urls = ["https://2dep.vn/static/chunks/4841-17a8ef22630c2e4d.js"]
        d = extract_ver_params(urls)[0].to_detection_dict()
        assert d["source"] == "url-ver"
        assert d["product"] == "Next.js"
        assert d["version"] is None

    # -- misc --

    def test_unknown_plugin_slug_falls_back_to_title_case(self):
        urls = ["https://example.com/wp-content/plugins/my-fancy-plugin/js/script.js?ver=2.1.0"]
        hits = extract_ver_params(urls)
        assert hits[0].tech == "My Fancy Plugin"

    def test_multiple_plugins_extracted(self):
        urls = [
            "https://2game.vn/wp-content/plugins/peepso/assets/js/jquery.autosize.min.js?ver=7.0.1.1",
            "https://2game.vn/wp-content/plugins/postbox/postbox-backgrounds.js?ver=7.0.1.1",
            "https://2game.vn/wp-content/plugins/elementor/assets/js/elementor.js?ver=3.18.0",
        ]
        hits = extract_ver_params(urls)
        names = {h.tech for h in hits}
        assert {"PeepSo", "Postbox", "Elementor"}.issubset(names)


# ---------------------------------------------------------------------------
# Pipeline source rank + reconcile integration
# ---------------------------------------------------------------------------


class TestPipelineIntegration:
    def test_url_ver_rank_below_wappalyzer(self):
        from fp.pipeline import _SOURCE_RANK
        assert _SOURCE_RANK["url-ver"] < _SOURCE_RANK["wappalyzer"]

    def test_url_ver_rank_above_bundle_leak(self):
        from fp.pipeline import _SOURCE_RANK
        assert _SOURCE_RANK["url-ver"] > _SOURCE_RANK["bundle-leak"]

    def test_wappalyzer_outranks_url_ver(self):
        from fp import pipeline as pl
        dets = [
            {"source": "wappalyzer", "product": "jQuery", "version": "3.7.0",
             "name": "jQuery", "tags": [], "extracted": {}, "template_id": "wap:jQuery",
             "matcher_name": None, "url": "https://t.test/", "category": None},
            {"source": "url-ver", "product": "jQuery", "version": "3.6.4",
             "name": "jQuery", "tags": [], "extracted": {}, "template_id": "url-ver:jquery",
             "matcher_name": None, "url": "https://t.test/js/jquery-3.6.4.min.js"},
        ]
        recs = pl.reconcile(dets, [])
        assert len(recs) == 1
        assert recs[0].version == "3.7.0"  # wappalyzer wins
        assert "url-ver" in recs[0].sources

    def test_url_ver_fills_missing_wappalyzer_version(self):
        from fp import pipeline as pl
        dets = [
            {"source": "wappalyzer", "product": "WooCommerce", "version": None,
             "name": "WooCommerce", "tags": [], "extracted": {}, "template_id": "wap:WooCommerce",
             "matcher_name": None, "url": "https://t.test/", "category": None},
            {"source": "url-ver", "product": "WooCommerce", "version": "8.0.0",
             "name": "WooCommerce", "tags": [], "extracted": {}, "template_id": "url-ver:woocommerce",
             "matcher_name": None, "url": "https://t.test/wp-content/plugins/woocommerce/js/woo.min.js?ver=8.0.0"},
        ]
        recs = pl.reconcile(dets, [])
        assert recs[0].version == "8.0.0"

    def test_url_ver_standalone_creates_record(self):
        from fp import pipeline as pl
        dets = [{"source": "url-ver", "product": "PeepSo", "version": "7.0.1.1",
                 "name": "PeepSo", "tags": [], "extracted": {}, "template_id": "url-ver:peepso",
                 "matcher_name": None, "url": "https://2game.vn/wp-content/plugins/peepso/js/a.js?ver=7.0.1.1"}]
        recs = pl.reconcile(dets, [])
        assert len(recs) == 1
        assert recs[0].name == "PeepSo"
        assert recs[0].version == "7.0.1.1"

    def test_framework_version_none_merges_into_record(self):
        from fp import pipeline as pl
        dets = [
            {"source": "wappalyzer", "product": "Next.js", "version": "14.0.0",
             "name": "Next.js", "tags": [], "extracted": {}, "template_id": "wap:Next.js",
             "matcher_name": None, "url": "https://t.test/", "category": None},
            {"source": "url-ver", "product": "Next.js", "version": None,
             "name": "Next.js", "tags": [], "extracted": {}, "template_id": "url-ver:next.js",
             "matcher_name": None, "url": "https://t.test/static/chunks/4841-17a8ef22630c2e4d.js"},
        ]
        recs = pl.reconcile(dets, [])
        assert len(recs) == 1
        assert recs[0].version == "14.0.0"  # wappalyzer version preserved
        assert "url-ver" in recs[0].sources
