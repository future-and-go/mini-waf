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

## Response body internal-ref masking (AC-17)

`response_body_filter` runs an in-place regex masker over upstream response
chunks (see `filters/response_body_mask_filter.rs`). Patterns and the mask
token come from `HostConfig::{internal_patterns, mask_token, body_mask_max_bytes}`.

Scope limits (FR-001):

- **Compressed bodies are NOT masked.** If `Content-Encoding` is anything other
  than `identity` (or absent), the masker is disabled for that response and a
  `tracing::debug!` line is emitted. Body decompression is FR-033's problem.
- `Content-Length` is stripped when masking is enabled (replacement length
  differs from match length); Pingora switches to chunked transfer.
- A per-host byte ceiling (`body_mask_max_bytes`, default 1 MiB) caps work;
  bytes beyond the ceiling are forwarded unchanged with a single warn log.
- Patterns that fail to compile are dropped (fail-open). A bad regex must
  never 502 a host.

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
