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
