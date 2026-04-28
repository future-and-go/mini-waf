# prx-waf

Top-level binary crate. Wires every other crate together and launches the WAF process: gateway data plane, admin API, cluster, engine, and storage.

## Features
- **CLI entrypoint**: `clap`-driven command parsing for the `prx-waf` binary.
- **Bootstrap**: installs the rustls default CryptoProvider before any TLS use, loads config, initializes tracing.
- **Service composition**: spawns gateway (Pingora), admin API (Axum), and cluster (QUIC) services on a shared Tokio runtime.
- **Lifecycle**: graceful shutdown / signal handling for the whole process.

## Folder Structure
```
src/
└── main.rs   # Binary entrypoint, CLI, bootstrap, service wiring
```

## Dependencies
Depends on every workspace crate: `waf-common`, `waf-storage`, `waf-engine`, `waf-api`, `waf-cluster`, `gateway`. Plus `clap`, `tokio`, `tracing-subscriber`, `pingora-core`, `pingora-proxy`, `rustls` (direct, for `install_default()`).
