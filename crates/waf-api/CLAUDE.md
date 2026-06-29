# waf-api

Axum-based admin/control-plane HTTP API. Serves the embedded admin UI, exposes management endpoints, and pushes realtime updates over WebSockets.

## Features
- **REST API**: rules, plugins, tunnels, cache, cluster, stats, notifications, CrowdSec.
- **Auth**: Argon2 password hashing, JWT issuance, middleware-enforced sessions.
- **Static UI**: embeds React admin panel (Refine + AntD) via `rust-embed` (built by `build.rs`).
- **WebSocket**: realtime stats / log streaming.
- **Health**: liveness + readiness endpoints.
- **Email**: outbound notifications via `lettre`.
- **App state**: shared handle to engine, storage, and cluster components.

## Folder Structure
```
build.rs                      # Generates admin-panel/dist placeholder
src/
├── lib.rs / server.rs        # Axum app + router wiring
├── state.rs                  # Shared AppState
├── error.rs                  # API error type
├── middleware.rs             # Auth / logging middleware
├── auth.rs                   # Login, JWT, password hashing
├── handlers.rs               # Generic handlers
├── rules_api.rs              # Rule CRUD endpoints
├── plugins.rs                # Plugin management
├── tunnels.rs                # Tunnel management
├── cache_api.rs              # Cache control
├── cluster.rs                # Cluster status / control
├── crowdsec.rs               # CrowdSec config endpoints
├── stats.rs                  # Stats endpoints
├── notifications.rs          # Notification config + dispatch
├── panel_api.rs              # Admin panel config endpoints
├── security.rs               # Security-related endpoints
├── health.rs                 # Health checks
├── websocket.rs              # WS upgrade + streaming
└── static_files.rs           # Embedded admin UI serving
```

## Dependencies
Depends on `waf-common`, `waf-storage`, `waf-engine`, `waf-cluster`, `gateway`. Stack: `axum`, `tower-http`, `sqlx`, `argon2`, `jsonwebtoken`, `lettre`, `rust-embed`, `reqwest`.
