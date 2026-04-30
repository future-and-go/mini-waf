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

## Folder Structure
```
src/
├── lib.rs
├── proxy.rs               # Pingora ProxyHttp impl, orchestrates phases
├── proxy_waf_response.rs  # Response building utilities
├── pipeline/              # Filter chains (request & response)
│   ├── mod.rs
│   ├── request_filter_chain.rs
│   └── response_filter_chain.rs
├── ctx_builder/           # Request context construction
│   ├── mod.rs
│   └── request_ctx_builder.rs
├── router.rs              # Host/path → upstream routing
├── lb.rs                  # Load balancer
├── ssl.rs                 # ACME + TLS cert management
├── http3.rs               # QUIC/H3 listener
├── cache.rs               # Response cache (moka)
├── tunnel.rs              # Tunnel forwarder
└── context.rs             # Per-request context structs
```

## Dependencies
Depends on `waf-common`, `waf-engine`, `waf-storage`. Pulls `pingora-*`, `quinn`, `h3`, `rustls`, `instant-acme`, `rcgen`, `moka`, `reqwest`.

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
