# Phase 03 — Response-side Transforms

## Context Links
- Design doc §4.2, §4.3
- Phase 01 (response filter chain), Phase 02 (no direct dep)
- ACs: AC-15 leak headers, AC-16 Server policy, AC-18 Location rewrite, AC-19 error page

## Overview
- **Priority:** P1
- **Status:** completed
- **Description:** Strip WAF/proxy fingerprint headers, apply Server-header strategy, rewrite internal Location URLs, replace Pingora default error pages with neutral content-negotiated page.

## Key Insights
- Pingora may inject `Server` / `Via` defaults at h1/h2 layer — must scrub on the way out, not just trust upstream.
- Location rewrite must handle both absolute (`http://10.0.0.5/path`) and relative (`/path`) — relative passes through unchanged.
- Error-page factory replaces phase-01 stub. Negotiates by `Accept`: `application/json` → `{"error":"..."}`, else `text/plain`. No HTML by default (smaller surface). HTML tier opt-in later.

## Requirements
**Functional**
- Strip headers: `Via`, `X-Powered-By-WAF`, `X-WAF-*`, any header in config blocklist.
- `ServerHeaderPolicy::Passthrough` (default — preserves AC-04) | `Strip`.
- `LocationRewritePolicy`: if `Location` host matches `host_config.remote_host` (or configured internal pattern), rewrite to public host (`host_config.host`), preserve scheme based on listener TLS.
- `ErrorPageFactory::render(status, accept) -> (ResponseHeader, Bytes)` — neutral body, no Pingora fingerprint, used by `fail_to_proxy` and phase-01 fail-closed.

**Non-Functional**
- Files ≤ 150 LoC.
- Unit-testable without Pingora.

## Architecture
**Pattern application**
- *Strategy* (`ServerHeaderPolicy`, `LocationRewritePolicy`) — config-driven enum with `apply(&mut ResponseHeader)`.
- *Factory* (`ErrorPageFactory`) — content-negotiated renderer. Returns owned bytes + minimal headers; caller writes to session.
- *Pipeline*: `via-strip → server-policy → location-rewrite → custom-blocklist`.

**Data flow**
```
upstream_response_filter(resp):
    response_chain.apply(resp, fctx)
fail_to_proxy(err) → ErrorPageFactory::render → write_response
```

## Related Code Files
**Create**
- `crates/gateway/src/filters/response-via-strip-filter.rs`
- `crates/gateway/src/filters/response-header-blocklist-filter.rs`
- `crates/gateway/src/filters/response-location-rewriter.rs`
- `crates/gateway/src/policies/server-header-policy.rs`
- `crates/gateway/src/policies/location-rewrite-policy.rs`
- `crates/gateway/src/error-page/error-page-factory.rs`
- `crates/gateway/src/error-page/mod.rs`

**Modify**
- `crates/gateway/src/proxy.rs` — register response filters; replace `respond_error` calls with `ErrorPageFactory`; implement Pingora `fail_to_proxy` callback
- `HostConfig` — add `strip_server_header: bool` (default false), `header_blocklist: Vec<String>`

## Implementation Steps
1. Extend `HostConfig` with `strip_server_header` (default false → preserves AC-04) and `header_blocklist` (default `["x-powered-by-waf", "x-waf-version"]`).
2. Implement `ResponseViaStripFilter` — unconditional `remove_header("via")`.
3. Implement `ResponseHeaderBlocklistFilter` — iterate config list, `remove_header`.
4. Implement `ServerHeaderPolicy` strategy + `apply` — passthrough = no-op; strip = `remove_header("server")`.
5. Implement `LocationRewritePolicy`:
   - Parse `Location` value as URL.
   - If host matches `remote_host` or configured internal regex → swap host to `host_config.host`, swap scheme to listener scheme.
   - Relative or matching public host → no-op.
   - Malformed URL → leave untouched, `tracing::warn!`.
6. Implement `ErrorPageFactory`:
   - `render(status: u16, accept: Option<&str>) -> (ResponseHeader, Bytes)`.
   - JSON branch when accept contains `application/json`.
   - Plain text default.
   - **Never** sets `Server`; explicitly removes it after `ResponseHeader::build`.
7. Wire `fail_to_proxy` ProxyHttp callback to use factory (covers 502/504 from upstream failures — AC-19).
8. Replace phase-01 fail-closed stub body with factory call.
9. Unit tests per filter/policy/factory.

## Todo List
- [x] HostConfig fields + serde defaults
- [x] `ResponseViaStripFilter` + tests
- [x] `ResponseHeaderBlocklistFilter` + tests
- [x] `ServerHeaderPolicy` (passthrough/strip) + tests
- [x] `LocationRewritePolicy` + tests (absolute internal, absolute public, relative, malformed)
- [x] `ErrorPageFactory` + tests (json/plain/missing accept)
- [x] Wire `fail_to_proxy` callback
- [x] Register response filters in chain

## Completion Notes
- 16 new unit tests (5 filters/policies + 5 ErrorPageFactory + 6 location-rewrite/server-policy variants); workspace 395/395 pass; clippy clean; fmt clean.
- Files added (snake_case translation per plan §Naming):
  - `crates/gateway/src/filters/response_via_strip_filter.rs`
  - `crates/gateway/src/filters/response_header_blocklist_filter.rs`
  - `crates/gateway/src/filters/response_location_rewriter.rs`
  - `crates/gateway/src/filters/response_server_policy_filter.rs` (thin chain wrapper around `ServerHeaderPolicy`)
  - `crates/gateway/src/policies/server_header_policy.rs`
  - `crates/gateway/src/policies/location_rewrite_policy.rs`
  - `crates/gateway/src/error_page/{mod.rs, error_page_factory.rs}`
- `HostConfig` extended: `strip_server_header` (default false), `header_blocklist` (default `["x-powered-by-waf","x-waf-version"]`).
- `proxy.rs` now overrides `fail_to_proxy` (Pingora callback) → `ErrorPageFactory::render` → write headers+body. Pingora default error-page bypassed.
- Fail-closed branch in `request_filter` switched from static body to factory output.
- Coverage tool note: `cargo-llvm-cov` not installed locally (per plan risk §6). CI gate deferred until tool installed or `tarpaulin` fallback configured.

## Success Criteria
- AC-15: leak-scan regex `(?i)via|x-powered-by|x-waf` zero matches across 50 sample responses.
- AC-16: `strip=false` preserves backend Server byte-for-byte; `strip=true` removes it; **never** substituted with WAF identifier.
- AC-18: 302 from backend `http://backend:8080/x` → client receives `https://public/x`.
- AC-19: trigger 502 (kill backend) → response body has no "Pingora", no stack, content-negotiated by Accept.
- Coverage ≥ 95% on the new files.

## Risk Assessment
| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|-----------|
| URL parsing of `Location` panics on malformed input | L | M | Use `url::Url::parse` returning Result; warn-log + passthrough |
| Stripping `Server` breaks AC-04 byte-identical | H (by design) | L | Make it opt-in (default off); document tradeoff in AC-16 |
| `fail_to_proxy` not invoked for all error paths | M | H | Audit Pingora error sites; cover at least connect/timeout/upstream-503 in tests |

## Security Considerations
- Error-page factory must not echo request data into body (XSS risk).
- Header blocklist case-insensitive (HTTP headers are case-insensitive).

## Next Steps
- Phase 04: body filter for internal-ref leaks (AC-17).
