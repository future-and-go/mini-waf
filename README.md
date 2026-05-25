# PRX-WAF

> High-performance Web Application Firewall (WAF) built on Pingora

![Build](https://img.shields.io/badge/build-passing-brightgreen)
![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue)
![Rust](https://img.shields.io/badge/rust-2024--edition-orange)
![PostgreSQL](https://img.shields.io/badge/postgresql-16%2B-blue)

PRX-WAF is a production-ready reverse proxy WAF built on [Pingora](https://github.com/cloudflare/pingora) (Cloudflare's Rust HTTP proxy). It provides multi-phase attack detection, rule-based automation, WASM plugins, CrowdSec integration, and a React 18.3 + Refine admin UI — all in a single deployable binary.

---

## Key Features

**Core Protection**

- HTTP/1.1, HTTP/2, HTTP/3 (QUIC) via quinn; weighted round-robin load balancing
- **Phase-0 access gate (FR-008)**: per-tier IP/Host whitelist + blacklist (Patricia trie, dual-stack v4/v6)
- **Tiered request classification (FR-002)**: 4 tiers (Critical/High/Medium/CatchAll) with per-tier policies (fail-mode, DDoS threshold, cache policy)
- **Rate limiting (FR-004)**: token-bucket (burst) + sliding-window (sustained) per tier; IP + session keys; memory/Redis stores with circuit-breaker fallback
- **Smart response caching (FR-009)**: tier-aware bypass (CRITICAL never cached), tag-based purge index, per-route TTL via YAML
- 16-phase attack detection: SQLi, XSS, RCE, path traversal, RFI/LFI, SSRF, scanner detection, custom rules, CrowdSec
- libinjection-based SQLi/XSS detection via libinjectionrs (low false-positive)
- SSRF protection with DNS rebinding guard and RFC-1918 blocking
- Iterative URL decoding (up to 3 rounds) to prevent encoding bypasses
- CC/DDoS protection with sliding-window rate limiting per IP

**Rules & Automation**

- OWASP Core Rule Set (CRS): 556 YAML rules (8 categories: OWASP 274, ModSecurity 46, CVE 43, Advanced 77, Bot 42, GeoIP 2, API 64, Custom 8)
- Hot-reload: file watcher + SIGHUP; atomic reload without downtime
- Rhai scripting + WASM plugins (wasmtime 43) for custom detection
- Remote rule source async loading (10MB limit, 30s timeout)

**Integrations**

- CrowdSec: Bouncer + AppSec + Log Pusher
- Sensitive word detection (Aho-Corasick) + anti-hotlink protection
- Notifications: Email, Webhook, Telegram

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
- React 18.3 + Refine admin UI with Ant Design 5, JWT + TOTP authentication, real-time WebSocket monitoring

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

| Crate         | Prod LOC | Purpose                                                 |
| ------------- | -------- | ------------------------------------------------------- |
| `prx-waf`     | ~2K      | Binary: CLI entry point, server bootstrap               |
| `gateway`     | ~15K     | Pingora proxy, HTTP/3, SSL automation, response caching |
| `waf-engine`  | ~55K     | Detection pipeline (16 phases), rules engine, plugins   |
| `waf-storage` | ~5K      | PostgreSQL layer (sqlx), migrations, models             |
| `waf-api`     | ~8K      | Axum REST API, JWT/TOTP, WebSocket, embedded UI         |
| `waf-common`  | ~3K      | Shared types: RequestCtx, WafAction, config             |
| `waf-cluster` | ~7K      | Cluster consensus (QUIC/mTLS), rule sync, election      |
| **Total (Prod)** | **~95K** | Production Rust WAF (plus ~27K tests)                   |

---

## Architecture

**Request Flow (Phase-0 + 16-Phase Pipeline)**

```
Client → TCP/TLS/QUIC → [Tier Classification]
  → Phase-0: Host gate + IP blacklist + IP whitelist (access lists)
  → IP allow/block (phases 1-4)
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

70+ endpoints available. Key routes: `/api/auth/login`, `/api/hosts`, `/api/security-events`, `/api/reload`, `/api/cluster/status`, WebSocket streams `/ws/events` and `/ws/logs`. All endpoints require JWT except login. See [System Architecture](./docs/system-architecture.md) for complete reference.

---

## Admin UI

- **Login**: JWT + TOTP authentication
- **Views**: Dashboard, Hosts, Rules, Certificates, Security Events, Custom Rules, Cluster
- **Monitoring**: Real-time WebSocket event stream, attack timelines
- **i18n**: 11 locales (English, Chinese, Russian, Georgian, Arabic, German, Spanish, French, Japanese, Korean, Estonian)

**Access**: `http://localhost:16827/ui/`

---

## Documentation

- [System Architecture](./docs/system-architecture.md) — Topology, components, storage, cluster, panel-config API
- [Request Pipeline](./docs/request-pipeline.md) — Tier classification, Phase-0 access gate, 16-phase rule pipeline
- [Code Standards](./docs/code-standards.md) — Rust 2024, safety rules, error handling
- [Deployment Guide](./docs/deployment-guide.md) — Docker, systemd, cluster setup, config reference
- [Project Overview & PDR](./docs/project-overview-pdr.md) — Vision, requirements, success metrics
- [Design Guidelines](./docs/design-guidelines.md) — Admin UI patterns, WebSocket usage
- [Project Roadmap](./docs/project-roadmap.md) — v0.2.0 release, upcoming milestones
- [Tiered Protection](./docs/tiered-protection.md) — Request tier classification and per-tier policies (FR-002)
- [Access Lists](./docs/access-lists.md) — IP/Host whitelist + blacklist operator guide (FR-008)
- [Custom Rules Syntax](./docs/custom-rules-syntax.md) — File-based and DB-driven rule schemas
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

Authors: OpenPRX Community | Repository: [github.com/openprx/prx-waf](https://github.com/openprx/prx-waf) | Version: 1.0.0
