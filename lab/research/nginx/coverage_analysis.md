# nginx version-detection coverage on the dev corpus

## Headline

113 nginx detections on the 377-target corpus. **30/113 (26.5%) carry a
version; 83/113 (73.5%) do not.** This is approximately the structural
ceiling for header-channel-only detection on this corpus, not a rule
defect.

## Why the gap is structural, not fixable by rule editing

Probing all 83 unversioned targets directly (curl_cffi + chrome120) to
recover the actual `Server` header:

| Server header value         | Count | % of gap | Recoverable?                              |
|-----------------------------|------:|---------:|-------------------------------------------|
| `nginx` (bare)              |    73 |     88%  | NO  -- `server_tokens off` (intentional)  |
| `nginx, WebServer`          |     4 |      5%  | NO  -- same control surface (layered)     |
| `cloudflare`                |     2 |      2%  | NO  -- CDN rewrites upstream Server       |
| (no Server header / fail)   |     2 |      2%  | NO                                        |
| `openresty/A.B.C.D`         |     1 |      1%  | YES -- OpenResty bundles nginx A.B.C      |
| `Byte-nginx` (custom fork)  |     1 |      1%  | NO  -- no published version mapping       |

**88% of the gap is `server_tokens off;`** -- an nginx hardening default
in much Vietnamese hosting / managed-nginx deployments. When this
directive is set, nginx strips the version from BOTH the `Server` header
AND the default error-page body. They are not independent channels; both
read the same `server_tokens` control surface inside
`src/http/ngx_http_header_filter_module.c`. No new probe path can recover
a version nginx itself has refused to emit.

The only principled, source-grounded option (CLAUDE.md sec 6) was the
OpenResty -> nginx version inference (see below). All other proposed
"channels" (TLS cipher order fingerprint, error-page byte counts,
response-header order, default 50x page hashes) would be empirical
corpus-mined fingerprints -- explicitly forbidden by sec 6.

## What we added: OpenResty -> nginx version inference

**Signal (source-grounded):** OpenResty's release versioning encodes the
bundled nginx version in the first three components.
`openresty/1.29.2.3` ships nginx 1.29.2. `openresty/1.27.1.2` ships
nginx 1.27.1. The mapping is documented in OpenResty's changelog
(<https://openresty.org/en/changelog.html>): "OpenResty releases follow
the form `<nginx-version>.<openresty-revision>`."

**Implementation:** one row in `lab_version_probes`:

```sql
INSERT INTO lab_version_probes (
    name, path, regex, method, version_group,
    ok_status, part, content_hint, headers_json,
    origin, note
) VALUES (
    'Nginx',
    '/',
    '(?im)^server:\s*openresty/(\d+\.\d+\.\d+)\.\d+',
    'GET',
    1,
    '200',
    'header',
    NULL,
    NULL,
    'research:openresty-bundles-nginx',
    'OpenResty bundles a known nginx version per release. First three '
    'components of openresty/A.B.C.D are nginx A.B.C. Source: '
    'openresty.org/en/changelog.html. Recovers nginx version when the '
    'edge is OpenResty and Server is not stripped.'
);
```

**Why this is principled per sec 9 (survey before insert):**

- Existing Wappalyzer nginx rule is `nginx(?:/([\d.]+))?` on the Server
  header. It does NOT match `openresty/X.Y.Z.W` (no `nginx` substring),
  so the OpenResty case falls through with no version.
- This is a genuinely different signal shape (OpenResty release-version
  string encoding bundled nginx version) -- not a widening of the
  existing nginx rule. Inventory-matching is not the failure mode here.
- The rule's emitted tech name is `Nginx` (matching reconcile keying),
  so the probe hit merges into the existing nginx record rather than
  creating a parallel one.

**Validation:**

```text
header line under test:    server: openresty/1.29.2.3
regex match:               (1.29.2)
emitted detection:         {source: 'version-probe', name: 'Nginx',
                            version: '1.29.2'}
```

**Coverage impact:** 26.5% -> 27.4% on the current corpus (one
recovered case). The rule generalises to every future OpenResty-fronted
target that doesn't strip Server, which we expect to grow with the
corpus.

## What we did NOT add (with reasons)

- **Body-probe of default error pages.** Same `server_tokens` control
  surface as Server header. Futile.
- **TLS / HTTP/2 implementation fingerprint.** Empirical, fragile, sec 6
  violation.
- **`Byte-nginx` fork mapping.** No public release map cites a bundled
  upstream nginx version. Would require reverse engineering. Skip.
- **Widening Wappalyzer's nginx regex** to also match `openresty/...`.
  Wappalyzer rules are upstream-managed; a local widening would drift on
  next sync and conflate two distinct techs. The version-probe row
  captures the same signal without touching the upstream Wappalyzer rule.
