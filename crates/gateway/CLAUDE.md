# gateway

Pingora-based reverse-proxy data plane. Terminates TLS, routes HTTP/1, HTTP/2, and HTTP/3 traffic, applies the WAF engine, load-balances to upstreams, and serves cached responses.

## Features
- **Reverse proxy**: Pingora `pingora-proxy` integration for L7 forwarding.
- **Routing**: host/path matching to upstream pools.
- **Load balancing**: pool selection and upstream health-aware dispatch.
- **TLS / SSL**: ACME (`instant-acme`) certificate issuance, dynamic SNI, `rcgen` self-signed fallback.
- **HTTP/3**: QUIC + h3 listener (`quinn`, `h3`, `h3-quinn`).
- **Cache**: response caching backed by `moka`.
- **Tunnel**: connection tunnel handling (e.g., for cluster / forwarded traffic).
- **Per-request context**: shared state plumbed through the proxy phases.
- **Filter chain**: pluggable request/response filters — XFF, real-IP, forwarded host/proto, hop-by-hop scrub, host policy, response Server/Location/Via header policies, response body internal-ref masker, response header blocklist.
- **Header / location policies**: host header, server header, and Location-rewrite policy modules consumed by filters.
- **Error pages**: factory for WAF-decision and proxy error responses.
- **Tiered classification**: per-host tier classifier with hot-reloadable policy registry and compiled-rule matcher (consumes `waf-common::tier`).
- **Access phase**: dedicated pipeline stage running access-control + relay + device-fp checks before upstream selection.
- **Upstream ALPN** (per-host): configurable TLS ALPN advertisement toward the origin, default `H2H1`.

## Upstream ALPN

`HostConfig::upstream_alpn` (`waf_common::UpstreamAlpn`) controls which HTTP
versions Pingora advertises in the TLS ClientHello when connecting to an upstream
over `ssl: true`. The helper `apply_upstream_alpn()` (in `proxy.rs`, symmetric
with `apply_fr039_timeouts`) maps the enum to `pingora_core::protocols::ALPN`
before returning the peer.

| Value | Pingora ALPN | When to use |
|---|---|---|
| `H2H1` *(default)* | `h2, http/1.1` | Modern CDN-fronted origins (CloudFront, etc.). Lets the server pick h2. |
| `H1Only` | `http/1.1` | Legacy origins that advertise h2 but mis-implement it. |
| `H2Only` | `h2` | gRPC backends or strict h2-only origins. Handshake fails if server doesn't speak h2. |

No-op when `ssl: false` (plaintext TCP has no ALPN). Hot-reloaded through the
existing config watcher — no restart needed after changing the field.

## Response body internal-ref masking (AC-17)

`response_body_filter` runs an in-place regex masker over upstream response
chunks (see `filters/response_body_mask_filter.rs`). Patterns and the mask
token come from `HostConfig::{internal_patterns, mask_token, body_mask_max_bytes}`.

Scope limits (FR-001):

- **Compressed bodies are NOT masked.** If `Content-Encoding` is anything other
  than `identity` (or absent), the masker is disabled for that response and a
  `tracing::debug!` line is emitted. Body decompression for gzip handled by
  FR-033 (`response_body_content_scanner.rs`); deflate + brotli deferred to
  FR-033b.
- `Content-Length` is stripped when masking is enabled (replacement length
  differs from match length); Pingora switches to chunked transfer.
- A per-host byte ceiling (`body_mask_max_bytes`, default 1 MiB) caps work;
  bytes beyond the ceiling are forwarded unchanged with a single warn log.
- Patterns that fail to compile are dropped (fail-open). A bad regex must
  never 502 a host.

## Response body content scanner (FR-033)

`response_body_filter` also runs a built-in catalog scanner
(`filters/response_body_content_scanner.rs`) over the same upstream response
chunks. The scanner detects four leak categories — stack traces, verbose
errors, API keys / secrets, internal IPs — and replaces every match with the
hardcoded module constant `MASK_TOKEN = b"[redacted]"`.

Filter chain order in `response_body_filter`: FR-033 (decompress + catalog
scan) → FR-034 (JSON field redact, when PR #18 merges) → AC-17 (operator
regex). FR-033 owns gzip decompression, so the downstream layers always see
plaintext.

Scope limits:

- gzip-only decompression in v1 (`response_body_decompressor.rs`); deflate +
  brotli + zstd / lz4 deferred to FR-033b.
- Defenses: 4 MiB output cap, 8 MiB input cap, 100:1 ratio guard. Fail-open
  on decode error (forward original bytes + `tracing::warn!`).
- Content-Type allowlist at `response_filter`: only `text/*`,
  `application/json`, `application/xml`, `application/problem+json`,
  `application/javascript`. Skips `application/grpc*`, `text/event-stream`,
  `application/octet-stream`.
- `Content-Length` and `Transfer-Encoding` are dropped unconditionally when
  the scanner enables. `Content-Encoding` is dropped only when gzip
  decompression succeeded.
- Cache key is content-hash `(host_name, xxhash64(body_scan_*))` — no
  `Arc::as_ptr`, so a config reload cannot bleed compiled patterns across
  hosts.

`HostConfig` exposes only two opt-in fields (defaults preserve passthrough):
`body_scan_enabled`, `body_scan_max_body_bytes`. All other knobs are module
constants.

## Response body sensitive-field redaction (FR-034)

`response_body_filter` also runs a JSON field-name redactor (see
`filters/response_json_field_redactor.rs`) per host. Active families and
extras come from `HostConfig::{redact_pci, redact_banking, redact_identity,
redact_secrets, redact_pii, redact_phi, redact_extra_fields, redact_mask_token,
redact_max_bytes, redact_case_insensitive}`.

Composes with AC-17: FR-034 runs first, buffering chunks until EOS (or
`redact_max_bytes`, default 256 KiB), parsing, redacting, then emitting the
full body. AC-17 then runs over the FR-034 output. While FR-034 is buffering,
`*body` is set to `None` so AC-17 sees nothing.

Skip conditions match AC-17 (non-identity `Content-Encoding`) plus a JSON
content-type gate (only `application/json` and `application/*+json`;
`text/event-stream` and `application/x-ndjson` rejected). Fail-open on cap
overflow / malformed JSON / parse error.

Defaults all OFF — every `redact_*` family toggle defaults to `false`. Hosts
that don't opt in see zero behaviour change.

## Folder Structure
```
src/
├── lib.rs
├── proxy.rs               # Pingora ProxyHttp impl, orchestrates phases
├── proxy_waf_response.rs  # Response building utilities
├── protocol.rs            # Wire-protocol helpers (HTTP version, scheme, etc.)
├── pipeline/              # Filter chains + access phase
│   ├── mod.rs
│   ├── access_phase.rs    # Access-control + relay + device-fp stage
│   ├── request_filter_chain.rs
│   └── response_filter_chain.rs
├── filters/               # Individual request/response filters
│   ├── request_xff_filter.rs
│   ├── request_real_ip_filter.rs
│   ├── request_forwarded_host_filter.rs
│   ├── request_forwarded_proto_filter.rs
│   ├── request_host_policy_filter.rs
│   ├── request_hop_by_hop_filter.rs
│   ├── response_body_mask_filter.rs
│   ├── response_header_blocklist_filter.rs
│   ├── response_server_policy_filter.rs
│   ├── response_location_rewriter.rs
│   └── response_via_strip_filter.rs
├── policies/              # Reusable header / rewrite policy logic
│   ├── host_header_policy.rs
│   ├── server_header_policy.rs
│   └── location_rewrite_policy.rs
├── error_page/            # Block / error response factory
│   └── error_page_factory.rs
├── ctx_builder/           # Request context construction
│   └── request_ctx_builder.rs
├── tiered/                # Per-host tier classifier
│   ├── compiled_rule.rs
│   ├── tier_classifier.rs
│   ├── tier_config_watcher.rs
│   └── tier_policy_registry.rs
├── router.rs              # Host/path → upstream routing
├── lb.rs                  # Load balancer
├── ssl.rs                 # ACME + TLS cert management
├── http3.rs               # QUIC/H3 listener
├── cache.rs               # Response cache (moka)
├── tunnel.rs              # Tunnel forwarder
└── context.rs             # Per-request context structs

benches/tier_classifier_bench.rs
```

## Dependencies
Depends on `waf-common`, `waf-engine`, `waf-storage`. Pulls `pingora-core` / `pingora-proxy` / `pingora-http`, `quinn`, `h3` + `h3-quinn`, `rustls`, `instant-acme`, `rcgen`, `moka`, `reqwest`, `arc-swap`, `notify`, `dashmap`, `parking_lot`, `regex`.

## Testing & coverage (FR-001 phase-06)

Unit tests live inline (`#[cfg(test)] mod tests` per file) under `filters/`,
`policies/`, `error_page/`, `pipeline/`, `ctx_builder/`, plus `protocol.rs`.
Run them with:

```bash
cargo test -p gateway
```

CI enforces a 95% line-coverage gate on those scoped files via
[`cargo-llvm-cov`](https://github.com/taiki-e/cargo-llvm-cov). Reproduce locally:

```bash
cargo install cargo-llvm-cov --locked       # one-time
rustup component add llvm-tools-preview     # one-time

cargo llvm-cov -p gateway \
  --ignore-filename-regex '(cache|lb|tunnel|ssl|http3|proxy|proxy_waf_response|context|router|lib|request_ctx_builder|protocol)\.rs$|/tests/|/benches/' \
  --fail-under-lines 95
```

End-to-end Pingora-driven integration tests (the 17 AC-mapped suites in the
phase-06 plan) are **deferred to phase-06b**. They require a `WafEngine` test
seam that does not bind to a live PostgreSQL `Database`; see
`plans/260428-1010-fr-001-reverse-proxy-impl/phase-06-test-harness-coverage.md`
for the deferral rationale.

## Cache module coverage (FR-009 phase-05)

Separate 95% line-coverage gate scoped to `crates/gateway/src/cache/**`.
Inline tests live per-file (`cache/store.rs`, `cache/policy.rs`, every
`cache/gates/*.rs`, `cache/tag_index.rs`, `cache/rule.rs`, `cache/rule_set.rs`,
`cache/watcher.rs`, `cache/config.rs`); end-to-end pipeline tests live in
`tests/cache_integration.rs` and `tests/cache_hot_reload.rs`.

Reproduce the gate locally:

```bash
cargo llvm-cov -p gateway --summary-only \
  --ignore-filename-regex '(context|http3|lb|lib|protocol|proxy|proxy_waf_response|router|ssl|tunnel)\.rs$|/(ctx_builder|error_page|filters|pipeline|policies|tiered)/|crates/(waf-|prx-)|/tests/|/benches/'
```

CI enforces ≥95% via the `cache-coverage` job in `.github/workflows/ci.yml`.

Benches (criterion):

```bash
cargo bench -p gateway --bench cache_resolver_bench --bench cache_purge_bench
```

Targets: `resolve_critical_bypass` < 10µs, `resolve_route_match_hit` < 50µs,
`resolve_no_match_fallback` < 30µs, `put_with_5_tags` < 5µs,
`purge_by_tag_10k_keys` < 50ms.
