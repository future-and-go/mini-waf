# PRX-WAF

> High-performance Web Application Firewall (WAF) built on Pingora

![Build](https://img.shields.io/badge/build-passing-brightgreen)
![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue)
![Rust](https://img.shields.io/badge/rust-2024--edition-orange)
![PostgreSQL](https://img.shields.io/badge/postgresql-16%2B-blue)

PRX-WAF is a production-ready reverse proxy WAF built on [Pingora](https://github.com/cloudflare/pingora) (Cloudflare's Rust HTTP proxy). It provides multi-phase attack detection, rule-based automation, WASM plugins, CrowdSec integration, and a Vue 3 admin UI — all in a single deployable binary.

---

## Key Features

**Core Protection**

- HTTP/1.1, HTTP/2, HTTP/3 (QUIC) via quinn; weighted round-robin load balancing
- 10+ attack detection phases: SQLi, XSS, RCE, path traversal, RFI/LFI, SSRF, scanner detection
- libinjection-based SQLi/XSS detection via libinjectionrs (low false-positive)
- SSRF protection with DNS rebinding guard and RFC-1918 blocking
- Iterative URL decoding (up to 3 rounds) to prevent encoding bypasses
- CC/DDoS protection with sliding-window rate limiting per IP

**Rules & Automation**

- OWASP Core Rule Set (CRS) support; 51 built-in rules (7 CVE patches, 24 OWASP, 6 advanced)
- Hot-reload: file watcher (notify) + SIGHUP handler; atomic reload without downtime
- Rhai scripting engine for custom detection rules (sandboxed)
- ModSecurity rule parser (basic subset: ARGS, REQUEST_HEADERS, REQUEST_URI, REQUEST_BODY)
- WASM plugin system (wasmtime 43; sandboxed)
- Remote rule source loading (async, configurable size/timeout, fails safe)

**Integrations**

- CrowdSec: Bouncer (decision cache from LAPI) + AppSec (remote HTTP inspection) + Log Pusher
- Sensitive word detection via Aho-Corasick multi-pattern matching
- Anti-hotlink protection (Referer-based validation per host)
- Notification system: Email (SMTP), Webhook, Telegram

**Clustering & High Availability**

- Cluster mesh: QUIC mTLS on port 16851; automatic leader election (Raft-lite)
- Rule sync: incremental or full snapshot (lz4 compression)
- Attack log aggregation on main node
- Workers forward write operations; main as control plane
- See [Cluster Deployment](./docs/deployment-guide.md#cluster-deployment-3-node-ha)

**Infrastructure**

- Let's Encrypt automation via instant-acme (ACME v2, auto-renewal)
- Response caching: moka LRU with TTL and size limits
- PostgreSQL 16+ storage: all config, rules, logs, stats persisted
- AES-256-GCM encryption at rest for sensitive values
- Vue 3 Admin UI with JWT + TOTP authentication, real-time WebSocket monitoring

---

## Quick Start

### Docker Compose (Single Node)

```bash
git clone https://github.com/openprx/prx-waf
cd prx-waf
docker compose up -d
```

- HTTP proxy: `http://localhost:16880`
- HTTPS proxy: `https://localhost:16843`
- Admin UI: `http://localhost:16827/ui/` (admin / admin123 — change immediately)

### Manual Build

**Prerequisites:** Rust 1.86+, PostgreSQL 16+

```bash
cargo build --release
createdb prx_waf && createuser prx_waf

./target/release/prx-waf -c configs/default.toml migrate
./target/release/prx-waf -c configs/default.toml seed-admin
./target/release/prx-waf -c configs/default.toml run
```

---

## CLI Reference

```
prx-waf [OPTIONS] <COMMAND>

Options:
  -c, --config <FILE>   Config file [default: configs/default.toml]

Commands:
  run          Start proxy + API server
  migrate      Run database migrations
  seed-admin   Create default admin user (admin/admin123)
  crowdsec     CrowdSec integration management
  rules        Rule list, load, validate, hot-reload
  sources      Rule source management
  bot          Bot detection management
  cluster      Cluster management (status, nodes, token generation)
```

**Examples:**

```bash
prx-waf rules list --category sqli
prx-waf rules reload
prx-waf cluster token generate --ttl 24h
prx-waf crowdsec status
```

---

## Configuration

Configuration is loaded from a TOML file. See [Deployment Guide](./docs/deployment-guide.md) for complete reference.

```toml
[proxy]
listen_addr     = "0.0.0.0:80"
listen_addr_tls = "0.0.0.0:443"

[api]
listen_addr = "127.0.0.1:9527"

[storage]
database_url    = "postgresql://prx_waf:prx_waf@127.0.0.1:5432/prx_waf"
max_connections = 20

[cache]
enabled          = true
max_size_mb      = 256
default_ttl_secs = 60

[rules]
dir            = "rules/"
hot_reload     = true
enable_builtin_owasp = true

[cluster]
enabled     = false
role        = "auto"
listen_addr = "0.0.0.0:16851"
seeds       = []
```

---

## Crate Structure

| Crate         | LOC        | Purpose                                                 |
| ------------- | ---------- | ------------------------------------------------------- |
| `prx-waf`     | 1,552      | Binary: CLI entry point, server bootstrap               |
| `gateway`     | 1,868      | Pingora proxy, HTTP/3, SSL automation, response caching |
| `waf-engine`  | 11,154     | Detection pipeline (16 phases), rules engine, plugins   |
| `waf-storage` | 2,293      | PostgreSQL layer (sqlx), migrations, models             |
| `waf-api`     | 4,040      | Axum REST API, JWT/TOTP, WebSocket, embedded UI         |
| `waf-common`  | 1,457      | Shared types: RequestCtx, WafDecision, config           |
| `waf-cluster` | 3,804      | Cluster consensus (QUIC/mTLS), rule sync, election      |
| **Total**     | **26,168** | Production Rust WAF                                     |

---

## Architecture

**Request Flow (16-Phase Pipeline)**

```
Client → TCP/TLS/QUIC → IP allow/block (phases 1-4)
  → CC rate limit (phase 5) → Scanner detect (phase 6)
  → Bot detect (phase 7) → SQL injection (phase 8)
  → XSS (phase 9) → RCE (phase 10) → Dir traversal (phase 11)
  → Custom rules (phase 12) → OWASP CRS (phase 13)
  → Sensitive data (phase 14) → Anti-hotlink (phase 15)
  → CrowdSec (phase 16) → Backend (with LB)
```

**Cluster Topology (High Availability)**

```
Main Node (control plane, DB, rules)
├── PostgreSQL storage
├── Rule registry + changelog
└── Admin UI

Worker Nodes (data plane, stateless)
├── In-memory rule cache (synced)
└── Forward writes to main via QUIC
```

For detailed architecture, see [System Architecture](./docs/system-architecture.md).

---

## Deployment

- **Single Node**: `docker compose up -d` (default)
- **3-Node Cluster HA**: `docker compose -f docker-compose.cluster.yml up -d`
- **Systemd**: Service unit included; see [Deployment Guide](./docs/deployment-guide.md)

Health check: `curl http://localhost:9527/health`

---

## API Reference

**Endpoints** (all require JWT token except `/api/auth/login` and `/health`)

| Method         | Path                  | Description               |
| -------------- | --------------------- | ------------------------- |
| POST           | `/api/auth/login`     | Obtain JWT token          |
| GET            | `/api/hosts`          | List proxy hosts          |
| POST           | `/api/hosts`          | Create proxy host         |
| GET/PUT/DELETE | `/api/hosts/:id`      | Get/update/delete host    |
| GET/POST       | `/api/block-ips`      | IP blocklist              |
| GET/POST       | `/api/block-urls`     | URL blocklist             |
| GET            | `/api/attack-logs`    | Security events           |
| POST           | `/api/reload`         | Hot-reload rules          |
| GET            | `/api/cluster/status` | Cluster health            |
| WS             | `/ws/events`          | Real-time security events |
| WS             | `/ws/logs`            | Real-time access logs     |

See [API docs](./docs/system-architecture.md) for all 70+ endpoints.

---

## Admin UI

- **Login**: JWT + TOTP authentication
- **Views**: Dashboard, Hosts, Rules, Certificates, Security Events, Custom Rules, Cluster
- **Monitoring**: Real-time WebSocket event stream, attack timelines
- **i18n**: 11 locales (English, Chinese, Russian, Georgian, Arabic, German, Spanish, French, Japanese, Korean, Estonian)

**Access**: `http://localhost:16827/ui/`

---

## Documentation

- [System Architecture](./docs/system-architecture.md) — 16-phase pipeline, cluster topology
- [Code Standards](./docs/code-standards.md) — Rust 2024, safety rules, error handling
- [Deployment Guide](./docs/deployment-guide.md) — Docker, systemd, cluster setup
- [Project Overview & PDR](./docs/project-overview-pdr.md) — Vision, requirements, success metrics
- [Design Guidelines](./docs/design-guidelines.md) — Admin UI patterns, WebSocket usage
- [Project Roadmap](./docs/project-roadmap.md) — v0.2.0 release, upcoming milestones
- [Cluster Design](./docs/cluster-design.md) — Deep technical design (QUIC/mTLS, election, sync)
- [Cluster Guide](./docs/cluster-guide.md) — Cluster quick-start and operations

---

## Development

**Build & Test**

```bash
cargo build --release
cargo test
cargo clippy -- -D warnings
cargo fmt --all -- --check
```

**E2E Testing**

```bash
# Full test suite (runs all 5 shell-based runners: rules-engine, gateway, api, cluster, report-renderer)
./tests/e2e-cluster.sh

# Outputs JUnit, JSON, Markdown, HTML artifacts to tests/artifacts/
```

**Run Locally**

```bash
docker compose up -d postgres
cargo build
cargo sqlx db create
cargo sqlx migrate run
cargo run --bin prx-waf -- -c configs/default.toml run
```

---

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feat/my-feature`)
3. Follow [Code Standards](./docs/code-standards.md)
4. Run tests and clippy before commit
5. Submit a pull request

---

## License

Licensed under Apache License, Version 2.0 or MIT (your choice).

Authors: OpenPRX Community | Repository: [github.com/openprx/prx-waf](https://github.com/openprx/prx-waf) | Version: 0.2.0
