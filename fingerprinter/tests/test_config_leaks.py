"""Tests for fp.config_leaks (Nuxt/Next/Remix/window.ENV blob extraction)."""

from __future__ import annotations

import json

from fp.config_leaks import ConfigLeak, extract_config_leaks


def _by_key(leaks: list[ConfigLeak]) -> dict[str, ConfigLeak]:
    """Helper: index leaks by key_path (last segment) for assertion convenience."""
    return {leak.key_path.rsplit(".", 1)[-1].split("[", 1)[0]: leak for leak in leaks}


# ---------------------------------------------------------------------------
# Reference fixture: wappalyzer.com __NUXT__ blob (verified 2026-04-30)
# ---------------------------------------------------------------------------


WAPPALYZER_NUXT_HTML = """\
<!doctype html><html><head><title>Wappalyzer</title></head><body>
<script>
window.__NUXT__={config:{
  BASE_URL:"https://api.wappalyzer.com/v2/",
  DATASETS_BASE_URL:"https://lists.wappalyzer.com/",
  BULK_LOOKUP_BASE_URL:"https://lookup.wappalyzer.com/",
  COGNITO_USER_POOL_ID:"us-east-1_TgUo66wcF",
  COGNITO_CLIENT_ID:"1tot574rv0d11jagsgglrr0a47",
  STRIPE_PUBLIC_KEY:"pk_live_51HabcdEFGHijklmnop1234567890QRSTuvwxyz",
  ENABLE_NEW_DASH:"true"
}};
</script>
</body></html>
"""


class TestNuxtFixture:
    """Backlog item #3 reference fixture must extract all four leak classes."""

    def setup_method(self):
        self.leaks = extract_config_leaks(WAPPALYZER_NUXT_HTML)
        self.by_key = _by_key(self.leaks)

    def test_three_backend_urls_extracted(self):
        urls = [l for l in self.leaks if l.leak_class == "backend_url"]
        hosts = {l.value for l in urls}
        assert "https://api.wappalyzer.com/v2/" in hosts
        assert "https://lists.wappalyzer.com/" in hosts
        assert "https://lookup.wappalyzer.com/" in hosts

    def test_cognito_pool_classified_as_auth_id(self):
        l = self.by_key["COGNITO_USER_POOL_ID"]
        assert l.leak_class == "auth_id"
        assert l.value == "us-east-1_TgUo66wcF"

    def test_cognito_client_classified_as_auth_id(self):
        l = self.by_key["COGNITO_CLIENT_ID"]
        assert l.leak_class == "auth_id"

    def test_stripe_key_classified_as_api_key(self):
        l = self.by_key["STRIPE_PUBLIC_KEY"]
        assert l.leak_class == "api_key"
        assert l.value.startswith("pk_live_")

    def test_framework_attributed_to_nuxt(self):
        assert all(l.framework == "nuxt" for l in self.leaks)


# ---------------------------------------------------------------------------
# Next __NEXT_DATA__ -- strict JSON path
# ---------------------------------------------------------------------------


class TestNextData:
    def test_extracts_url_from_nested_props(self):
        payload = {
            "props": {
                "pageProps": {
                    "apiUrl": "https://api.example.com/v1",
                    "PROJECT_ID": "demo-12345",
                }
            },
            "buildId": "abc",
        }
        html = (
            f'<!doctype html><html><head>'
            f'<script id="__NEXT_DATA__" type="application/json">{json.dumps(payload)}</script>'
            f'</head></html>'
        )
        leaks = extract_config_leaks(html)
        klasses = {(l.leak_class, l.value) for l in leaks}
        assert ("backend_url", "https://api.example.com/v1") in klasses
        assert ("auth_id", "demo-12345") in klasses
        assert all(l.framework == "next" for l in leaks)

    def test_key_path_is_dotted(self):
        payload = {"props": {"pageProps": {"BACKEND_URL": "https://b.test/"}}}
        html = (
            f'<script id="__NEXT_DATA__" type="application/json">{json.dumps(payload)}</script>'
        )
        leaks = extract_config_leaks(html)
        urls = [l for l in leaks if l.leak_class == "backend_url"]
        assert urls[0].key_path == "props.pageProps.BACKEND_URL"

    def test_malformed_json_falls_back_to_regex(self):
        # Truncated/invalid JSON inside the script tag -- shouldn't crash and
        # should still surface a key:"value" pair via regex fallback.
        html = (
            '<script id="__NEXT_DATA__" type="application/json">'
            '{"props":{"API_URL":"https://api.broken.test/v1",'  # missing closer
            '</script>'
        )
        leaks = extract_config_leaks(html)
        assert any(
            l.value == "https://api.broken.test/v1" and l.leak_class == "backend_url"
            for l in leaks
        )


# ---------------------------------------------------------------------------
# Remix __remixContext
# ---------------------------------------------------------------------------


class TestRemixContext:
    def test_extracts_remix_blob(self):
        html = """\
<script>
window.__remixContext = {state:{loaderData:{},
  apiBase:"https://api.remixed.test/v2",
  AUTH0_CLIENT_ID:"abc123def456"}};
</script>
"""
        leaks = extract_config_leaks(html)
        assert any(
            l.framework == "remix" and l.value == "https://api.remixed.test/v2"
            for l in leaks
        )
        assert any(
            l.framework == "remix" and l.leak_class == "auth_id"
            and l.value == "abc123def456"
            for l in leaks
        )


# ---------------------------------------------------------------------------
# window.ENV / window.__INITIAL_STATE__ / window.config
# ---------------------------------------------------------------------------


class TestGenericWindowEnv:
    def test_window_env(self):
        html = '<script>window.ENV = {API_URL:"https://api.envvar.test/"};</script>'
        leaks = extract_config_leaks(html)
        assert leaks[0].framework == "window-env"
        assert leaks[0].leak_class == "backend_url"

    def test_window_initial_state(self):
        html = (
            '<script>window.__INITIAL_STATE__={config:{'
            'GRAPHQL_ENDPOINT:"https://gql.example.com/graphql"}};</script>'
        )
        leaks = extract_config_leaks(html)
        assert any(l.value == "https://gql.example.com/graphql" for l in leaks)

    def test_window_config(self):
        html = (
            '<script>window.config = {'
            'firebaseProjectId:"my-fb-app-1234",'  # _ID-suffix would miss this name; auth-key catches it via "firebase"
            'API_BASE:"https://api.cfg.test/"};</script>'
        )
        leaks = extract_config_leaks(html)
        urls = [l for l in leaks if l.leak_class == "backend_url"]
        assert urls and urls[0].value == "https://api.cfg.test/"


# ---------------------------------------------------------------------------
# Classification edge cases
# ---------------------------------------------------------------------------


class TestClassification:
    def test_aws_access_key_classified_as_api_key(self):
        html = '<script>window.ENV={KEY:"AKIAIOSFODNN7EXAMPLE"};</script>'
        leaks = extract_config_leaks(html)
        assert leaks and leaks[0].leak_class == "api_key"

    def test_google_api_key_classified(self):
        html = '<script>window.ENV={MAPS_KEY:"AIzaSyA-abcdefghijklmnopqrstuvwxyz123456"};</script>'
        leaks = extract_config_leaks(html)
        assert leaks and leaks[0].leak_class == "api_key"

    def test_uninteresting_keys_dropped(self):
        # No URL prefix, no credential pattern, no key-name match -> dropped.
        html = '<script>window.ENV={greeting:"hello",version:"1"};</script>'
        leaks = extract_config_leaks(html)
        assert leaks == []

    def test_key_with_url_suffix_promoted_via_value(self):
        # Value is a URL -> backend_url regardless of key name.
        html = '<script>window.ENV={someThing:"https://x.test/"};</script>'
        leaks = extract_config_leaks(html)
        assert leaks and leaks[0].leak_class == "backend_url"


# ---------------------------------------------------------------------------
# Dedup + empty input
# ---------------------------------------------------------------------------


class TestDedupAndEmpty:
    def test_empty_input_returns_empty(self):
        assert extract_config_leaks("") == []
        assert extract_config_leaks(b"") == []

    def test_no_blob_returns_empty(self):
        html = "<html><body>plain page, no SPA framework</body></html>"
        assert extract_config_leaks(html) == []

    def test_same_pair_in_two_blobs_deduped(self):
        # Same (framework, key, value) appears in both Nuxt-style and a
        # generic window.ENV block; only one should survive within each
        # framework's own pass. Across frameworks they are distinct entries
        # (different framework attribution), which is intentional.
        html = """\
<script>window.__NUXT__={config:{API_URL:"https://api.dup.test/"}};</script>
<script>window.__NUXT__={config:{API_URL:"https://api.dup.test/"}};</script>
"""
        leaks = extract_config_leaks(html)
        # Two Nuxt blobs with identical (key, value) -> one leak.
        nuxt = [l for l in leaks if l.framework == "nuxt"]
        assert len(nuxt) == 1

    def test_handles_bytes_input(self):
        html = '<script>window.ENV={API:"https://b.test/"};</script>'
        leaks = extract_config_leaks(html.encode("utf-8"))
        assert leaks and leaks[0].value == "https://b.test/"


# ---------------------------------------------------------------------------
# JS string escape handling
# ---------------------------------------------------------------------------


class TestEscapes:
    def test_escaped_forward_slash_in_url(self):
        # Some bundlers escape "/" inside JSON-in-script payloads.
        html = '<script>window.ENV={API:"https:\\/\\/escaped.test\\/v1"};</script>'
        leaks = extract_config_leaks(html)
        assert leaks and leaks[0].value == "https://escaped.test/v1"

    def test_escaped_quote_inside_value(self):
        html = r'<script>window.ENV={MSG_URL:"https://x.test/say\"hi"};</script>'
        leaks = extract_config_leaks(html)
        assert leaks and 'say"hi' in leaks[0].value


# ---------------------------------------------------------------------------
# to_dict shape
# ---------------------------------------------------------------------------


def test_to_dict_shape():
    html = '<script>window.ENV={API_URL:"https://x.test/"};</script>'
    leaks = extract_config_leaks(html)
    d = leaks[0].to_dict()
    assert set(d.keys()) == {"framework", "key_path", "value", "leak_class"}
