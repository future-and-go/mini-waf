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
