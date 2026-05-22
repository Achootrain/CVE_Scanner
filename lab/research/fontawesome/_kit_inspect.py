"""One-shot: inspect FA kit JS bodies to see what version markers exist."""
import re
import sys
sys.path.insert(0, r'D:\DATN2\fingerprinter')
import fetchlib

fetcher = fetchlib.make_fetcher('curl_cffi')
urls = [
    'https://use.fontawesome.com/f455f83be3.js',
    'https://use.fontawesome.com/b6de74fbb9.js',
]
for u in urls:
    print(f'=== {u} ===')
    res = fetcher.fetch(u, timeout=10, verify_ssl=False, extra_headers={})
    print(f'  status_tag={res.status_tag} http={res.http_status} bytes={len(res.body) if res.body else 0}')
    if not res.body:
        continue
    body = res.body
    # Show first 400 chars
    print(f'  head: {body[:400]!r}')
    # Search for explicit version markers
    for label, pat in [
        ('version_assign', r'version\s*[:=]\s*["\'](\d+\.\d+(?:\.\d+)?)["\']'),
        ('release_url',    r'releases/v(\d+\.\d+(?:\.\d+)?)'),
        ('banner_comment', r'Font Awesome (?:Free|Pro)?\s*(\d+\.\d+(?:\.\d+)?)'),
        ('any_semver',     r'(\d+\.\d+\.\d+)'),
    ]:
        ms = re.findall(pat, body, re.I)
        if ms:
            print(f'  [{label}] {ms[:5]}')
    print()
