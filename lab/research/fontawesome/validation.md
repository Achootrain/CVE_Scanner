# Font Awesome plugin CVE validation

Targets probed: **69**  (FA-positive sites from data/scan_results.jsonl)
Rules:          **18**  (one per CVE-bearing plugin slug)
Probes:         **1242**  (target x rule x path)

## Summary

| Slug | Status | CVEs | Installed | Vulnerable | Worst CVSS |
|------|--------|------|-----------|------------|-----------|
| `advanced-custom-fields-font-awesome` | active | 1 | 0 | 0 | 6.4 |
| `agp-font-awesome-collection` | closed | 2 | 0 | 0 | 8.8 |
| `better-font-awesome` | active | 2 | 0 | 0 | 8.8 |
| `block-for-font-awesome` | active | 2 | 0 | 0 | 8.8 |
| `contact-form-7-star-rating-with-font-awersome` | closed | 1 | 0 | 0 | 5.9 |
| `eds-font-awesome` | active | 1 | 0 | 0 | 6.4 |
| `font-awesome` | active | 1 | 3 | 0 | 5.4 |
| `font-awesome-4-menus` | closed | 2 | 0 | 0 | 5.4 |
| `font-awesome-integration` | closed | 1 | 0 | 0 | 5.4 |
| `font-awesome-more-icons` | closed | 1 | 0 | 0 | 5.4 |
| `font-awesome-wp` | closed | 1 | 0 | 0 | 6.5 |
| `incredible-font-awesome` | closed | 1 | 0 | 0 | 6.5 |
| `perfect-font-awesome-integration` | active | 2 | 0 | 0 | 6.5 |
| `shortcode-for-font-awesome` | active | 1 | 0 | 0 | 5.4 |
| `ss-font-awesome-icon` | active | 1 | 0 | 0 | 6.5 |
| `surbma-font-awesome` | active | 1 | 0 | 0 | 6.5 |
| `wp-font-awesome` | active | 2 | 0 | 0 | 5.4 |
| `wp-font-awesome-share-icons` | closed | 1 | 0 | 0 | 6.4 |

## Confirmed installs

### `font-awesome` (Font Awesome)
- Installed on 3 site(s); 0 confirmed vulnerable
- CVEs covered: CVE-2022-4478
  - [ok] `https://admon.com.vn` -> version `5.1.5` (patched)
  - [ok] `https://azg.com.vn` -> version `5.1.3` (patched)
  - [ok] `https://beetechno.com.vn` -> version `5.1.4` (patched)

## Probe statistics

- 404: 751
- 200 w/o version: 412  (likely soft-404 / SPA shell)
- error: 8  (timeout, TLS, DNS, etc.)
- other status: 68
