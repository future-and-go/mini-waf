# WAF

> High-performance reverse-proxy Web Application Firewall built in Rust on Pingora.

Single-binary deployable WAF: terminates TLS, proxies HTTP/1.1/2/3 to configured upstreams, runs a multi-phase detection pipeline (SQLi, XSS, RCE, path traversal, RFI/LFI, SSRF, scanner / bot detection, custom rules, OWASP CRS), and ships with an embedded React admin UI for hosts, rules, certs, and security events.

---

## Features

**Detection & protection**
- Multi-phase rule pipeline: SQLi / XSS (libinjection), RCE, directory traversal, RFI/LFI, SSRF (with DNS-rebinding guard + RFC-1918 block), scanner detection, bot detection
- Per-tier request classification (Critical / High / Medium / CatchAll) with per-tier fail-mode, DDoS threshold, and cache policy
- Access gate: IP / host allow + block lists (Patricia trie, dual-stack v4/v6)
- Rate limiting: token-bucket burst + sliding-window sustained, per IP / session, memory or Valkey/Redis backed with circuit-breaker fallback
- Honeypot / canary paths: exact-match traps that pin score to max and ban the source IP
- Iterative URL decoding (up to 3 rounds) to defeat encoding bypasses
- Risk scorer aggregating signals across detectors with hot-reloadable bands

**Rules**
- OWASP Core Rule Set bundled (~500 active rules across 8 categories)
- Hot-reload via file watcher and `SIGHUP` — no downtime
- Rhai scripting and WebAssembly (`wasmtime`) plugins for custom logic
- Custom YAML rule format with `path`, `query`, `headers`, `body`, `cookies` selectors

**Proxy & cache**
- HTTP/1.1, HTTP/2, HTTP/3 (QUIC) — ALPN-aware shared listener
- Weighted round-robin upstream load balancing
- Per-host upstream ALPN selection (`h2h1` / `h1_only` / `h2_only`)
- Smart response caching (in-process Moka LRU or Valkey/Redis backend) with tier-aware bypass, tag-based purge, per-route TTL via YAML

**TLS**
- Let's Encrypt automation (ACME v2) with auto-renewal
- Static cert mount (drop `cert.pem` + `key.pem` under the TLS path)
- Self-signed fallback for local development

**Storage & ops**
- PostgreSQL 16+ for all config, rules, users, security events, stats
- AES-256-GCM encryption at rest for sensitive values
- VictoriaLogs sidecar (managed child process) for audit + tracing log retention
- Embedded React admin UI served from `/ui/` with JWT + TOTP auth, WebSocket event stream, i18n (11 locales)

**Clustering (optional)**
- 3-node HA mesh over QUIC + mTLS, automatic leader election
- Rule sync (incremental + snapshot, lz4-compressed)
- Workers forward write operations to the main node

---

## Quick start

### Docker Compose (single node — fastest)

```bash
git clone https://github.com/future-and-go/mini-waf
cd mini-waf
docker compose up -d
```

| Port | Purpose |
| --- | --- |
| `16880` | HTTP proxy (`:80` inside container) |
| `16843` | HTTPS proxy (`:443` inside container) |
| `16827` | Admin UI + API (`http://localhost:16827/ui/`) |

Default admin: `admin` / `admin123` — **change immediately on first login.**

### Manual build (Rust 1.91+, PostgreSQL 16+, Node 22+ for the admin panel)

```bash
# Frontend (embedded into the binary via rust_embed)
cd web/admin-panel && npm ci && npm run build && cd ../..

# Backend
cargo build --release --features gateway/valkey

# Bootstrap database
createdb waf && createuser waf
./target/release/waf -c configs/default.toml migrate
./target/release/waf -c configs/default.toml seed-admin
./target/release/waf -c configs/default.toml run
```

Health probe: `curl http://127.0.0.1:9527/health`

---

## CLI

```
waf [OPTIONS] <COMMAND>

Options:
  -c, --config <FILE>   Config file [default: configs/default.toml]

Commands:
  run          Start proxy + admin API
  migrate      Run database migrations
  seed-admin   Create default admin user
  rules        List / load / validate / reload rules
  sources      Remote rule source management
  bot          Bot detection management
  cluster      Cluster status / nodes / token generation
  crowdsec     CrowdSec integration management
```

Examples:
```bash
waf rules list --category sqli
waf rules reload
waf cluster token generate --ttl 24h
```

---

## Configuration

TOML file. Full reference in [Deployment Guide](./docs/deployment-guide.md).

```toml
[proxy]
listen_addr     = "0.0.0.0:80"
listen_addr_tls = "0.0.0.0:443"

[api]
listen_addr = "0.0.0.0:9527"

[storage]
database_url    = "postgresql://waf:waf@127.0.0.1:5432/waf"
max_connections = 20

[cache]
enabled          = true
max_size_mb      = 256
default_ttl_secs = 60
backend          = "memory"     # "memory" | "embedded" | "standalone" | "cluster"

[rules]
dir                  = "rules/"
hot_reload           = true
enable_builtin_owasp = true
```

Sensitive values can be sourced from `/etc/waf/env` via systemd `EnvironmentFile=`.

---

## Architecture

**Request flow**
```
Client
  ↓  TCP / TLS / QUIC
[Tier classifier]
  ↓
Access gate          (host gate + IP allow/block)
  ↓
Rate limit + DDoS    (token-bucket + sliding window)
  ↓
Scanner + bot detect
  ↓
Attack detectors     (SQLi, XSS, RCE, dir-traversal, SSRF, sensitive-data)
  ↓
Custom rules + OWASP CRS
  ↓
Risk scorer / honeypot
  ↓
Upstream (load-balanced)
```

**Cluster topology (optional HA)**
```
Main node  ── PostgreSQL ── rule registry ── admin UI
   │
   └── QUIC/mTLS ──► Worker nodes (stateless, in-memory rule cache)
```

Full design in [System Architecture](./docs/system-architecture.md).

---

## Deployment

| Target | Command |
| --- | --- |
| Single node (Docker) | `docker compose up -d` |
| Multi-node cluster | `docker compose -f docker-compose.cluster.yml up -d` |
| Systemd (bare-metal) | See [Deployment Guide](./docs/deployment-guide.md) — unit file in repo root |

Liveness probe: `GET /health` on the admin API port. JSON response includes `status`, `version`, and component health for `database`, `waf_engine`, `cache`, `plugins`, `tunnels`.

---

## API & admin UI

70+ admin endpoints. JWT-protected (except `/api/auth/login`). Notable routes:

| Path | Purpose |
| --- | --- |
| `/api/auth/login` | Username + password (+ TOTP) login |
| `/api/hosts` | CRUD: virtual hosts and upstreams |
| `/api/security-events` | Recent blocks / detections |
| `/api/reload` | Hot reload rules / config |
| `/api/cluster/status` | Cluster topology (when enabled) |
| `/ws/events` | WebSocket: live security events |
| `/ws/logs` | WebSocket: live structured logs |

Admin UI: `http://<host>:9527/ui/` — Dashboard, Hosts, Rules, Certificates, Security Events, Custom Rules, Cluster. Real-time event stream + i18n (en, zh, ru, ka, ar, de, es, fr, ja, ko, et).

---

## Documentation

- [System Architecture](./docs/system-architecture.md) — components, topology, storage layer
- [Request Pipeline](./docs/request-pipeline.md) — phases and decision flow
- [Deployment Guide](./docs/deployment-guide.md) — Docker, systemd, cluster, config reference
- [Code Standards](./docs/code-standards.md) — Rust 2024 conventions, error handling
- [Custom Rules Syntax](./docs/custom-rules-syntax.md) — YAML rule schemas
- [Access Lists](./docs/access-lists.md) — IP / host allow + block lists
- [Tiered Protection](./docs/tiered-protection.md) — per-tier policy reference
- [Cluster Guide](./docs/cluster-guide.md) — HA setup and operations
- [Cluster Design](./docs/cluster-design.md) — QUIC/mTLS, election, rule sync

---

## Development

```bash
# build + test + lint
cargo build --release
cargo test
cargo clippy -- -D warnings
cargo fmt --all -- --check

# end-to-end
./tests/e2e-cluster.sh                 # runs all suites, dumps JUnit/JSON/MD/HTML to tests/artifacts/

# local hot-iteration with a postgres container only
docker compose up -d postgres
cargo run -- -c configs/default.toml run
```

### Repository layout

| Crate | Purpose |
| --- | --- |
| `crates/prx-waf` | Binary entry point — CLI, bootstrap, service wiring |
| `crates/gateway` | Pingora proxy, HTTP/3, TLS / ACME, response cache, request pipeline |
| `crates/waf-engine` | Detection engine — rules, plugins, device-fp, risk scorer, CrowdSec |
| `crates/waf-storage` | PostgreSQL layer (sqlx), migrations, models |
| `crates/waf-api` | Axum REST API + WebSocket, JWT / TOTP, embedded admin UI |
| `crates/waf-common` | Shared types — config, request context, action enums |
| `crates/waf-cluster` | Cluster consensus (QUIC/mTLS), rule sync, leader election |
| `web/admin-panel` | React 18 + Refine + Ant Design admin SPA (embedded at build time) |

---

## Contributing

1. Fork → feature branch (`git checkout -b feat/my-feature`)
2. Follow [Code Standards](./docs/code-standards.md)
3. Run `cargo test` and `cargo clippy -- -D warnings`
4. `cargo fmt --all` before pushing
5. Open a PR with a clear description and test plan

---

## License

Dual-licensed under MIT or Apache 2.0 — your choice.
