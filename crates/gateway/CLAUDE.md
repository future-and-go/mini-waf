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
  `tracing::debug!` line is emitted. Body decompression is FR-033's problem.
- `Content-Length` is stripped when masking is enabled (replacement length
  differs from match length); Pingora switches to chunked transfer.
- A per-host byte ceiling (`body_mask_max_bytes`, default 1 MiB) caps work;
  bytes beyond the ceiling are forwarded unchanged with a single warn log.
- Patterns that fail to compile are dropped (fail-open). A bad regex must
  never 502 a host.

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
