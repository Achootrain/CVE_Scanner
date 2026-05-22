"""Lift L3-only additions (lab.db) up to L1 snapshot.json so re-seed preserves them.

Adds:
  - jsdelivr /npm/ + /gh/ URL patterns -> _CDN_PATTERNS
  - 13 npm-package aliases -> _CDN_PKG_MAP and _JS_LIB_MAP
  - OpenResty header probe -> version_probes_CATALOG
"""
import json
from pathlib import Path

SNAP = Path(__file__).resolve().parent / 'url_ver_lab' / 'snapshot.json'
data = json.loads(SNAP.read_text(encoding='utf-8'))

# ---- 1. _CDN_PATTERNS: add jsdelivr npm + gh ----
JSD_NPM = r'jsdelivr\.net/npm/((?:@[^/@]+/)?[^/@]+)@([=v]*\d+\.\d+\.\d+[0-9A-Za-z\-]*)(?=[/?#]|$)'
JSD_GH  = r'jsdelivr\.net/gh/[^/@]+/((?:@[^/@]+/)?[^/@]+)@([=v]*\d+\.\d+\.\d+[0-9A-Za-z\-]*)(?=[/?#]|$)'

def has_pattern(p):
    return any(row.get('pattern') == p for row in data['_CDN_PATTERNS'])

added_cdn = 0
for pat, family in [(JSD_NPM, 'cdn: jsdelivr_npm'), (JSD_GH, 'cdn: jsdelivr_gh')]:
    if not has_pattern(pat):
        data['_CDN_PATTERNS'].append({
            'pattern': pat,
            'flags': 32,
            'pkg_group': 1,
            'version_group': 2,
            'fixed_name': None,
            'family': family,
            'origin': 'research:jsdelivr',
        })
        added_cdn += 1

# ---- 2. aliases (npm-pkg-slug -> canonical name) ----
ALIASES = {
    'vanilla-lazyload':                          'LazyLoad',
    'dayjs':                                     'Day.js',
    'slick-carousel':                            'Slick',
    'remixicon':                                 'Remix Icon',
    '@mdi/font':                                 'Material Design Icons',
    'bootstrap-icons':                           'Bootstrap Icons',
    'jquery-validation':                         'jQuery Validation',
    'hls.js':                                    'hls.js',
    '@splidejs/splide-extension-auto-scroll':    'Splide Auto Scroll',
    '@splidejs/splide-extension-intersection':   'Splide Intersection',
    '@finsweet/cookie-consent':                  'Finsweet Cookie Consent',
    'recombee-js-api-client':                    'Recombee JS API Client',
    '@unicorn-fail/drupal-bootstrap-styles':     'Drupal Bootstrap Styles',
}

cdn_map = data['_CDN_PKG_MAP']
js_map  = data['_JS_LIB_MAP']
added_alias = 0
for slug, tech in ALIASES.items():
    if slug not in cdn_map:
        cdn_map[slug] = tech
        added_alias += 1
    if slug not in js_map:
        js_map[slug] = tech

# ---- 3. version_probes_CATALOG: OpenResty header probe ----
OPENRESTY = {
    'name': 'Nginx',
    'path': '/',
    'regex': r'(?im)^server:\s*openresty/(\d+\.\d+\.\d+)\.\d+',
    'method': 'GET',
    'version_group': 1,
    'ok_status': [200],
    'part': 'header',
    'content_hint': None,
    'headers': {},
}
if not any(p.get('regex') == OPENRESTY['regex'] for p in data['version_probes_CATALOG']):
    data['version_probes_CATALOG'].append(OPENRESTY)
    added_probe = 1
else:
    added_probe = 0

# ---- meta: note this update ----
data.setdefault('_meta', {})['last_research_merge'] = '2026-05-17: jsdelivr loop + openresty + wp plugin aliases'

SNAP.write_text(json.dumps(data, indent='\t', ensure_ascii=False) + '\n', encoding='utf-8')
print(f'updated snapshot.json: +{added_cdn} CDN patterns, +{added_alias} aliases, +{added_probe} probe')
print(f'totals now: _CDN_PATTERNS={len(data["_CDN_PATTERNS"])}, _CDN_PKG_MAP={len(cdn_map)}, _JS_LIB_MAP={len(js_map)}, version_probes_CATALOG={len(data["version_probes_CATALOG"])}')
