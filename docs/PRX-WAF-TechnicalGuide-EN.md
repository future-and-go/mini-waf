# PRX-WAF — Comprehensive Technical Guide

> **F&G WAF** · Web Application Firewall · Version 0.2.0 · Rust 2024 Edition · Pingora-based  
> Full WAF solution: all features, all rules, complete setup guide.

---

## Table of Contents

1. [Introduction](#1-introduction)
2. [System Architecture](#2-system-architecture)
3. [Quick Start & Installation](#3-quick-start--installation)
4. [Admin UI Walkthrough](#4-admin-ui-walkthrough)
   - 4.1 [Login](#41-login)
   - 4.2 [Dashboard](#42-dashboard)
   - 4.3 [Hosts](#43-hosts)
   - 4.4 [IP Rules](#44-ip-rules)
   - 4.5 [URL Rules](#45-url-rules)
   - 4.6 [Security Events](#46-security-events)
   - 4.7 [Security Logs](#47-security-logs)
   - 4.8 [SSL Certificates](#48-ssl-certificates)
   - 4.9 [CC Protection & Rate Limiting](#49-cc-protection--rate-limiting)
   - 4.10 [Notifications](#410-notifications)
   - 4.11 [Settings](#411-settings)
   - 4.12 [Rule Manager](#412-rule-manager)
   - 4.13 [Custom Rules](#413-custom-rules)
   - 4.14 [Rule Sources](#414-rule-sources)
   - 4.15 [Rule Analytics](#415-rule-analytics)
   - 4.16 [Bot Management](#416-bot-management)
   - 4.17 [CrowdSec Integration](#417-crowdsec-integration)
   - 4.18 [Cache Dashboard](#418-cache-dashboard)
   - 4.19 [TX Velocity & Sequence](#419-tx-velocity--sequence)
5. [WAF Detection Pipeline](#5-waf-detection-pipeline)
6. [Complete Rule Catalog](#6-complete-rule-catalog)
7. [Configuration Reference](#7-configuration-reference)
8. [Clustering & High Availability](#8-clustering--high-availability)
9. [REST API Reference](#9-rest-api-reference)
10. [CLI Reference](#10-cli-reference)
11. [Security Best Practices](#11-security-best-practices)
12. [Troubleshooting](#12-troubleshooting)

---

## 1. Introduction

PRX-WAF (branded **F&G WAF**) is a production-ready, high-performance Web Application Firewall and reverse proxy built on [Cloudflare Pingora](https://github.com/cloudflare/pingora) in Rust 2024 edition. It provides:

- **Multi-protocol support**: HTTP/1.1, HTTP/2, HTTP/3 (QUIC via quinn)
- **16-phase attack detection pipeline** covering SQLi, XSS, RCE, LFI/RFI, SSRF, SSTI, XXE, Deserialization, Prototype Pollution, WebShell uploads, and more
- **612+ built-in rules** (OWASP CRS, CVE patches, Advanced, Bot Detection, ModSecurity, OWASP API Security)
- **Custom rules engine**: DB-driven JSON DSL with AND/OR/NOT trees + Rhai scripting
- **Risk-based cumulative scoring** (FR-025): L0 seed + L1 accumulation + L2 anomaly/velocity
- **Device fingerprinting** (FR-010): TLS JA3/JA4 + HTTP/2 Akamai hash
- **Transaction velocity detection** (FR-012): cross-endpoint fintech fraud patterns
- **CrowdSec integration**: Bouncer + AppSec + Log Pusher
- **QUIC mTLS clustering**: Raft-lite election, lz4-compressed rule sync
- **React 18 Admin UI**: JWT + TOTP 2FA, real-time WebSocket monitoring, 11 locales
- **PostgreSQL 16+ storage**: all config, logs, rules with AES-256-GCM encryption at rest

### Key Statistics (live system)

| Metric | Value |
|--------|-------|
| Total Rules Loaded | **612** |
| Rule Categories | **36** |
| Security Events (demo) | **3,718** blocked |
| Supported Protocols | HTTP/1.1, HTTP/2, HTTP/3 |
| Admin UI Languages | 11 locales |

---

## 2. System Architecture

### 2.1 Crate Structure

PRX-WAF is a Rust workspace of **7 crates** (~26,168 LOC total):

| Crate | LOC | Purpose |
|-------|-----|---------|
| `prx-waf` | 1,552 | Binary: CLI entry point, server bootstrap |
| `gateway` | 1,868 | Pingora reverse proxy, HTTP/3, TLS/ACME, Valkey/moka cache |
| `waf-engine` | 11,154 | 16-phase detection pipeline, rules engine, WASM plugins, risk scoring |
| `waf-storage` | 2,293 | PostgreSQL layer (sqlx), migrations, AES-256-GCM at rest |
| `waf-api` | 4,040 | Axum REST API, JWT+TOTP, WebSocket, embedded React UI |
| `waf-common` | 1,457 | Shared types: RequestCtx, WafDecision, TierPolicy, config |
| `waf-cluster` | 3,804 | QUIC mTLS cluster, Raft-lite election, rule sync |
| **Total** | **26,168** | |

### 2.2 Request Processing Flow

```mermaid
flowchart TD
    Client([Client]) --> Proto[TCP/TLS/QUIC\nHTTP 1.1 / 2 / 3]
    Proto --> Tier[Tier Classification FR-002\nCritical / High / Medium / CatchAll]
    Tier --> Relay[Pre-Phase: Relay Detection FR-007\nXFF validation · ASN · Tor exit]
    Relay --> DevFP[Pre-Phase: Device Fingerprinting FR-010\nJA3/JA4 · H2 Akamai · ip_hopping]
    DevFP --> P0[Phase-0: Access Gate FR-008\nHost gate → IP blacklist → IP whitelist]
    P0 --> P14[Phases 1-4: IP & URL Fast-Path\nWhitelist / Blacklist]
    P14 --> P5[Phase 5: Rate Limiting FR-004\nToken-bucket + Sliding-window]
    P5 --> P55[Phase 5.5: DDoS Detection FR-005\nPer-IP / Per-FP / Per-Tier]
    P55 --> P56[Phase 5.6: TX Velocity FR-012\nSequence · Withdrawal burst]
    P56 --> P57[Phase 5.7: Behavioral Anomaly FR-011\n16-slot ring · cadence · path]
    P57 --> P6[Phase 6: Scanner Detection]
    P6 --> P7[Phase 7: Bot Detection]
    P7 --> P8[Phase 8: SQL Injection\nlibinjection + 19 regex]
    P8 --> P9[Phase 9: XSS\nlibinjection + regex]
    P9 --> P10[Phase 10: RCE / Command Injection]
    P10 --> P11[Phase 11: Directory Traversal / SSRF]
    P11 --> P12[Phase 12: Custom Rules FR-003\nJSON DSL + Rhai]
    P12 --> P13[Phase 13: OWASP CRS\n24+ categories]
    P13 --> P14b[Phase 14: Sensitive Data\nAho-Corasick]
    P14b --> P15[Phase 15: Anti-Hotlink\nReferer validation]
    P15 --> P16[Phase 16: CrowdSec\nBouncer + AppSec]
    P16 --> Risk[Post: Risk Scoring FR-025\nL0+L1+L2 · decay · thresholds]
    Risk --> Decision{Decision}
    Decision -->|Allow| Cache[FR-009 Smart Cache\nValkey / moka LRU]
    Cache --> Backend([Upstream Backend])
    Decision -->|Block| Block403([403 Forbidden\nlog → security_events])
    Decision -->|Challenge| Challenge([429 / CAPTCHA\nJS proof-of-work])
```

### 2.3 Component Interaction

```mermaid
graph LR
    UI[React Admin UI] -->|JWT REST + WS| API[waf-api\nAxum]
    API -->|sqlx| DB[(PostgreSQL 16)]
    API -->|ArcSwap| Engine[waf-engine]
    GW[gateway\nPingora] -->|check ctx| Engine
    Engine -->|attack log| DB
    GW -->|upstream| Backend[Backend]
    Cluster[waf-cluster\nQUIC mTLS] -->|rule sync| GW
    Cluster -->|Raft-lite| DB
```

### 2.4 Tier Classification (FR-002)

Every request is classified into one of four tiers **before** any WAF phase runs:

```mermaid
flowchart LR
    Req([Request]) --> TierReg{TierPolicyRegistry\n.classify}
    TierReg -->|path /login POST| Crit[Critical\nfail-close\n50 RPS\nno-cache]
    TierReg -->|path /api/*| High[High\nfail-close\n200 RPS\nshort-TTL]
    TierReg -->|auth user pages| Med[Medium\nfail-open\n1000 RPS\ndefault-TTL]
    TierReg -->|everything else| CA[CatchAll\nfail-open\nunlimited\naggressive-cache]
    Crit & High & Med & CA --> WAF[WAF Phases 1-16]
```

| Tier | Typical Traffic | Fail-Mode | DDoS Threshold | Cache |
|------|----------------|-----------|----------------|-------|
| **Critical** | Login, payment, auth | Close (block on error) | 50 RPS | No cache |
| **High** | API surfaces, microservices | Close | 200 RPS | Short TTL (30s) |
| **Medium** | Authenticated pages, assets | Open (allow on error) | 1,000 RPS | Default (300s) |
| **CatchAll** | Everything else | Open | Unlimited | Aggressive (3600s) |

---

## 3. Quick Start & Installation

### 3.1 Docker Compose (Recommended)

**Prerequisites:** Docker Compose v1.3+, 4 GB RAM, ports 80/443/16827 free.

```bash
git clone https://github.com/openprx/prx-waf
cd prx-waf

# (Optional) Edit docker-compose.yml to set DB password, ports
nano docker-compose.yml

# Start all services
docker compose up -d

# Verify health
curl http://localhost:16827/health

# Access Admin UI
open http://localhost:16827/ui/
# Default credentials: admin / admin123  ← CHANGE IMMEDIATELY
```

**Port mapping:**

| Host Port | Container Port | Service |
|-----------|---------------|---------|
| `16880` | `80` | HTTP proxy (incoming traffic) |
| `16843` | `443` | HTTPS proxy (TLS termination) |
| `16827` | `9527` | Admin API + UI |
| `15432` | `5432` | PostgreSQL (optional direct access) |

### 3.2 Manual Build (Rust)

**Prerequisites:** Rust 1.86+, PostgreSQL 16+

```bash
# Build release binary
cargo build --release

# Database setup
createdb prx_waf
createuser prx_waf
psql -c "GRANT ALL ON DATABASE prx_waf TO prx_waf;"

# Run migrations
./target/release/prx-waf -c configs/default.toml migrate

# Create default admin
./target/release/prx-waf -c configs/default.toml seed-admin

# Start server
./target/release/prx-waf -c configs/default.toml run
```

### 3.3 Systemd Service

```bash
# Install binary
sudo install -m 0755 target/release/prx-waf /usr/local/bin/prx-waf
sudo useradd -r -s /sbin/nologin prx-waf
sudo mkdir -p /etc/prx-waf /var/lib/prx-waf /var/log/prx-waf
sudo install -m 0640 -o prx-waf configs/default.toml /etc/prx-waf/config.toml
```

Create `/etc/systemd/system/prx-waf.service`:

```ini
[Unit]
Description=PRX-WAF (F&G WAF) Reverse Proxy and WAF
After=network-online.target postgresql.service
Wants=network-online.target

[Service]
Type=simple
User=prx-waf
ExecStart=/usr/local/bin/prx-waf -c /etc/prx-waf/config.toml run
Restart=on-failure
RestartSec=10s
AmbientCapabilities=CAP_NET_BIND_SERVICE
LimitNOFILE=65535
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now prx-waf
sudo systemctl status prx-waf
```

### 3.4 Podman Compose (Alternative)

```bash
podman-compose down && podman-compose up -d --build
# Uses Dockerfile.prebuilt (local binary, fast rebuild)
```

---

## 4. Admin UI Walkthrough

The Admin Panel is a **React 18.3 + Refine + Ant Design 5** SPA served at `http://<host>:16827/ui/`.  
Authentication: **JWT** + optional **TOTP 2FA**.  
All pages support real-time updates via **WebSocket**.

### 4.1 Login

![Login page](screenshots/screencapture-localhost-16827-ui-login-2026-05-22-22_29_46.png)

*Figure 4.1 — F&G WAF Admin login screen*

- Enter **Username** and **Password**
- If TOTP is configured, enter the 6-digit OTP code after password
- JWT token is stored in browser; session expires per configured TTL
- Default credentials (change immediately): `admin` / `admin123`

---

### 4.2 Dashboard

![Dashboard](screenshots/screencapture-localhost-16827-ui-login-2026-05-22-22_30_23.png)

*Figure 4.2 — Real-time WAF Dashboard showing all metrics*

The Dashboard is the central monitoring view. It displays:

**Top metrics cards:**
| Metric | Description |
|--------|-------------|
| Total Requests | All requests processed |
| Blocked | Requests that were blocked |
| Allowed | Requests that passed through |
| Block Rate | Blocked / Total percentage |
| Hosts | Number of active proxy hosts |
| Unique Attackers | Distinct attacker IPs detected |
| Rules Loaded | Total rules currently active (612) |
| Categories | Rule category count (35) |
| Challenged | Requests returned challenge (CAPTCHA/JS) |
| Honeypot Hits | Requests matching honeypot trap paths |

**Charts:**
- **Traffic (last 24h)**: Line chart — Legitimate (blue) vs Blocked (red)
- **Attack Categories**: Bar chart — breakdown by attack type (scanner, rce, ssrf, sqli, xss, etc.)
- **Enforcement Actions**: Pie chart — block vs allow distribution
- **Risk Score Distribution**: Color-coded band — Allowed / Challenged / Blocked counts
- **Endpoint Attack Heatmap**: Time vs path heatmap of attack patterns
- **Top Attacking Countries**: Geographic attack origin map
- **Top 20% Attackers**: Most active attacking IPs
- **Top Attacking IPs**: Ranked IP list with block counts
- **Top Triggered Rules**: Most fired rule IDs
- **Top IPs by Risk**: Highest cumulative risk scores
- **Detection Engines**: Status of all 12 detection subsystems
- **Recent Security Events**: Live feed of last 20 blocked events
- **Live Security Events**: WebSocket real-time stream

**Filters:** Host selector, Action filter (All/Block/Allow/Challenge), Time window (1h/6h/24h/7d), Reset button.

---

### 4.3 Hosts

![Hosts page with New Host dialog](screenshots/screencapture-localhost-16827-ui-login-2026-05-22-22_30_42.png)

*Figure 4.3 — Proxy Hosts management (New Host dialog open)*

**Hosts** define the upstream backend mappings for the reverse proxy.

**Sidebar sections visible:** Dashboard, Hosts, IP Rules, URL Rules, Security Events, Security Logs, SSL Certificates, CC Protection, Notifications, Settings, **Rules** (Rule Manager, Custom Rules, Rule Sources, Rule Analytics, Bot Detection), **Cluster** (Overview, Join Tokens, Sync Status), **CrowdSec** (CS Settings, CS Decisions, CS Stats), **Cache** (Cache Dashboard), **Fraud Detection** (TX Velocity)

**New Host dialog fields:**

| Field | Description | Example |
|-------|-------------|---------|
| Host | Domain/hostname to match | `api.example.com` |
| Port | Listening port for this vhost | `80` |
| Upstream | Backend server IP/hostname | `127.0.0.1` |
| Upstream Port | Backend port | `8080` |
| Remarks | Optional description | `Production API` |
| SSL | Enable TLS termination | toggle |
| Guard | Enable WAF inspection | toggle (default ON) |
| Start | Enable this host | toggle (default ON) |
| Log only | Log-only mode (no blocking) | toggle |

> **Hot-reload:** Host changes take effect immediately without restart.

---

### 4.4 IP Rules

![IP Rules page](screenshots/screencapture-localhost-16827-ui-login-2026-05-22-22_31_06.png)

*Figure 4.4 — IP Rules: Allow List (left) and Block List (right)*

IP Rules provide **per-host CIDR-based access control**:

- **Allow List** — IPs/CIDRs that bypass inspection (depending on tier whitelist mode)
- **Block List** — IPs/CIDRs that are immediately blocked with 403

Supported formats: `192.168.1.5`, `10.0.0.0/8`, `2001:db8::/32` (IPv4 and IPv6)

Fields: IP/CIDR input + Host code filter (or blank for global)

> **Phase mapping:** Allow List → Phase 1 (fast-path allow), Block List → Phase 2 (fast-path block)

---

### 4.5 URL Rules

![URL Rules page](screenshots/screencapture-localhost-16827-ui-login-2026-05-22-22_31_23.png)

*Figure 4.5 — URL Rules: Allow URLs (left) and Block URLs (right)*

URL Rules provide **path-based access control**:

- **Allow URLs** — paths that bypass the entire WAF pipeline (Phase 3)
- **Block URLs** — paths that are immediately blocked (Phase 4)

Supported patterns:
- Literal: `/health`, `/api/public`
- Regex: `^/admin/.*`, `\.(jpg|png|gif)$`
- Wildcard: `/static/*`

Fields: URL pattern input + Host code filter

> **Note:** URL allowlist entries skip ALL downstream WAF phases — use carefully.

---

### 4.6 Security Events

![Security Events page](screenshots/screencapture-localhost-16827-ui-login-2026-05-22-22_31_37.png)

*Figure 4.6 — Security Events: attack log with 3,718 events*

Security Events is the **primary attack log**. Each event records:

| Field | Description |
|-------|-------------|
| Time | Timestamp of the blocked request |
| Client IP | Source IP address |
| Method | HTTP method (GET, POST, etc.) |
| Path | Request URI path |
| Rule | Rule category that triggered |
| Rule ID | Specific rule identifier (e.g., `SSRF-006`) |
| Action | Decision: block / allow / challenged |

**Tabs:** All actions · Block · Allow · Challenged · Honeypot

**Filters:** Host code, Client IP, Rule ID, Rule name, Path, Action, Country

**Total events shown:** 3,718 (186 pages × 20/page)

#### Event Detail Panel

![Security Event Detail](screenshots/screencapture-localhost-16827-ui-login-2026-05-22-22_34_04.png)

*Figure 4.6b — Event Detail: Request Info, Rule Info, Attack Payload*

Clicking any event opens a detail panel showing:
- **Request Info**: Time, Host code, Client IP, Method, Path, Action
- **Rule Info**: Rule name, Rule ID
- **Attack Payload**: The actual payload that triggered the rule (e.g., `localhost / loopback hostname |localhost| referenced from cookie`)
- **Quick action**: "Create Custom Rule from This Event" button

#### Create Custom Rule from Event

![Create Custom Rule from Event](screenshots/screencapture-localhost-16827-ui-login-2026-05-22-22_34_17.png)

*Figure 4.6c — Auto-generate custom rule from attack event*

The wizard pre-fills:
- Name: `Block SSRF from 151.101.2.137`
- Host: auto-detected host code
- Description: auto-generated with event UUID and timestamp
- Priority: 1 (highest)
- Conditions: AND tree with ip eq, method eq, OR header:referer contains conditions
- Action: block / 403

---

### 4.7 Security Logs

![Security Logs page](screenshots/screencapture-localhost-16827-ui-login-2026-05-22-22_31_57.png)

*Figure 4.7 — Security Logs: full access log with advanced filters*

Security Logs shows **all requests** (allowed and blocked). Features:

- **Advanced filter panel**: Rule, ip, ct_scan_id, time range, column selector
- **Column chooser**: Toggle visible columns (Time, Event, Block, Allow, etc.)
- **Export**: CSV export of filtered logs
- **100 pages** of log entries (high volume)

Log entry fields: Role, ip, ct_scan_id, time, columns selector

---

### 4.8 SSL Certificates

![SSL Certificates page](screenshots/screencapture-localhost-16827-ui-login-2026-05-22-22_32_08.png)

*Figure 4.8 — SSL Certificates management (Upload Certificate dialog)*

**SSL Certificates** manages TLS certificates for HTTPS termination:

**Upload Certificate dialog fields:**
| Field | Description |
|-------|-------------|
| Host | Host entry this cert applies to |
| Domain | Domain name (e.g., `example.com`) |
| Certificate PEM | PEM-encoded certificate chain |
| Private Key PEM | PEM-encoded private key |

**Additional features:**
- **Upload Cert** (manual PEM upload)
- **Let's Encrypt ACME**: automatic certificate provisioning via instant-acme (ACME v2)
- **Auto-renewal**: background renewal 30 days before expiry
- Table shows: Domain, Expires date, Status (valid/expired/pending)

---

### 4.9 CC Protection & Rate Limiting

![CC Protection page](screenshots/screencapture-localhost-16827-ui-login-2026-05-22-22_32_26.png)

*Figure 4.9 — CC Protection & Rate Limiting + Anti-Hotlink Config*

This page covers two subsystems:

**Load Balancer Backends (left panel):**
- Add backend upstream servers for load balancing
- Each backend: IP/hostname + port + weight
- Health check configuration

**Anti-Hotlink Config (right panel):**
| Field | Description |
|-------|-------------|
| Host code | Apply to specific host or `*` for global |
| Enabled | Toggle hotlink protection |
| Allow empty referer | Allow requests with no Referer header |
| Redirect URL | Optional redirect for hotlinked resources |

> **Rate limiting** is configured via `configs/rate-limit.yaml` (hot-reload). See §7.3 for full schema.

---

### 4.10 Notifications

![Notifications page](screenshots/screencapture-localhost-16827-ui-login-2026-05-22-22_32_40.png)

*Figure 4.10 — Notifications: New Notification Config dialog*

Configure alert channels for security events:

**New Notification Config dialog:**
| Field | Options | Description |
|-------|---------|-------------|
| Name | (text) | Config name |
| Channel | Webhook / Email / Telegram | Delivery channel |
| Event | Attack Detected / Rate Limited / etc. | Trigger condition |
| Host code | (text) | Scope to specific host |
| Channel Config (JSON) | `{}` | Channel-specific settings |

**Webhook example config:**
```json
{
  "url": "https://hooks.slack.com/services/...",
  "method": "POST",
  "headers": {"Content-Type": "application/json"}
}
```

**Telegram example config:**
```json
{
  "bot_token": "123456:ABC-DEF",
  "chat_id": "-100123456789"
}
```

---

### 4.11 Settings

![Settings page](screenshots/screencapture-localhost-16827-ui-login-2026-05-22-22_32_55.png)

*Figure 4.11 — System Settings: full configuration panel*

The Settings page exposes runtime configuration for the WAF engine:

**System Status:**
- Version, Active Visitors, Total Requests
- Config file path, Rate config path, Panel TOML path

**Shadow Mode (dry-run):**
- When enabled: compute block decisions but don't enforce — log only
- Useful for testing new rules without impacting traffic

**Risk Thresholds:**
- Allow (0): slider → default 31
- Challenge (1): slider → default 74  
- Block from score: → 75
- Visual threshold band (green → orange → red)

**Challenge Engine:**
- Challenge type: `JS challenge` (client-side JavaScript proof-of-work)

**Honeypot Paths:**
- Paths flagged as honeypots (any request → logged as honeypot hit)
- Default: `/env`, `/pCloud/config`, `/.git/config`, `/passwd/credentials`, `/.aws/credentials`

**Response Filtering:**
- Block stack traces in responses: toggle (default ON)
- Redact JSON fields: `password`, `token`, `secret`, `api_key`

**Trusted IPs/CIDRs (bypass list):**
- IPs that skip automated checks
- Default: `127.0.0.1/32`, `::1/128`, `90.181.2.131`

**Rate Limits & Session:**
| Setting | Default | Description |
|---------|---------|-------------|
| Default rate limit (reqs) | 100 | Per-IP request limit |
| Burst limit | 200 | Token-bucket burst capacity |
| Session expiry (seconds) | 3600 | Session TTL |
| Global rate limit (reqs, 0=off) | 0 | Global rate cap |
| Request timeout (seconds, 0=off) | 30 | Per-request timeout |
| Fail open (upstream unavailable) | toggle | Fail-open when backend down |

**Auto-block:**
- Enabled: toggle
- Minimum events: 6
- Window (seconds): 60

**Threat Intelligence:**
Tabs: Tor Exit Nodes · Blocked ASNs

Feed Status table shows rule sources with counts:
| Source | Rules Enabled |
|--------|--------------|
| advanced | 77 enabled |
| owasp-crs | 328/636 enabled |
| modsecurity | 46 enabled |
| cve-patches | 43 enabled |
| bot-detection | 42 enabled |
| owasp-api | 64 enabled |
| custom | 10 enabled |

**Configuration:** Shows API URL, WS URL for this instance.

---

### 4.12 Rule Manager

![Rule Management page](screenshots/screencapture-localhost-16827-ui-login-2026-05-22-22_33_06.png)

*Figure 4.12 — Rule Management: 612 rules across 36 categories*

The Rule Manager shows **all 612 built-in rules** with full details:

**Stats bar:**
- Total Rules: **612**
- Enabled: **612**
- Disabled: **0**
- Categories: **36**

**Table columns:**
| Column | Description |
|--------|-------------|
| Rule ID | Unique identifier (e.g., `ADV-SSTI-001`) |
| Name | Human-readable rule name |
| Category | Detection category (ssti, prototype-pollution, sqli, etc.) |
| Source | Rule set (advanced, owasp-crs, cve-patches, etc.) |
| Severity | critical / high / medium / low |
| Action | block / log / allow |
| Status | Enable / Disable toggle |

**Filters:** Search by name, filter by category, source, status

**Sample visible rules (first page):**
- `ADV-SSTI-001` — SSTI - Generic Expression Evaluation Test (`${7*7}`)
- `ADV-SSTI-002` — SSTI - Jinja2 Config Object Access
- `ADV-SSTI-003` — SSTI - Jinja2 Class Traversal for RCE
- `ADV-SSTI-004` — SSTI - Twig Template Engine Exploitation
- `ADV-SSTI-005` — SSTI - Freemarker Template Injection
- `ADV-SSTI-006` — SSTI - Velocity Template Injection
- `ADV-SSTI-007` — SSTI - Smarty PHP Template Injection
- `ADV-SSTI-008` — SSTI - Pebble Template Injection (Java)
- `ADV-SSTI-009` — SSTI - Mako Template Injection (Python)
- `ADV-SSTI-010` — SSTI - ERB Template Injection (Ruby)
- `ADV-SSTI-011` — SSTI - Handlebars/Mustache Template Injection
- `ADV-SSTI-012` — SSTI - Spring EL (SpEL) Injection
- `ADV-SSTI-013` — SSTI - Generic Polyglot Detection Probe
- `ADV-PROTO-001` — Prototype Pollution - `__proto__` in JSON Body
- `ADV-PROTO-002` — Prototype Pollution - `__proto__` in Query String
- ... (612 total, 31 pages)

#### Import Rules Dialog

![Import Rules dialog](screenshots/screencapture-localhost-16827-ui-login-2026-05-22-22_33_33.png)

*Figure 4.12b — Import Rules: load from file path or URL*

- **Source**: file path (`rules/custom.yaml`) or URL (`https://...`)
- **Format**: YAML (default) or JSON

---

### 4.13 Custom Rules

![Custom Rules page](screenshots/screencapture-localhost-16827-ui-login-2026-05-22-22_33_48.png)

*Figure 4.13 — Custom Rules: Create Custom Rule drawer*

Custom Rules are **DB-stored rules** fully managed via the UI.

**Create Custom Rule drawer fields:**

| Field | Type | Description |
|-------|------|-------------|
| Name | text | Rule name |
| Host | dropdown | Target host or `*` for global |
| Description | textarea | Rule description |
| Priority | number | Lower = higher priority (default: 100) |
| Action | dropdown | block / allow / log / challenge |
| Action status | number | HTTP status code (default: 403) |
| Action message | text | Custom response message |
| Enabled | toggle | Active or inactive |
| Visual / JSON | tabs | Condition builder mode |
| + Add AND group | button | Add AND condition group |
| + Add OR group | button | Add OR condition group |
| Rhai Script | textarea | Override with Rhai expression |

**Condition fields available:** `ip`, `path`, `query`, `method`, `body`, `host`, `user_agent`, `content_type`, `content_length`, `header:<name>`, `cookie:<name>`, `geo_country`, `geo_iso`

**Operators:** `eq`, `ne`, `contains`, `not_contains`, `starts_with`, `ends_with`, `regex`, `wildcard`, `in_list`, `not_in_list`, `cidr_match`, `gt`, `lt`, `gte`, `lte`, `detect_sqli`, `detect_xss`

**Example rule (JSON mode):**
```json
{
  "name": "Block admin from untrusted IPs",
  "host_code": "myapp",
  "priority": 10,
  "action": "block",
  "action_status": 403,
  "risk_delta": 50,
  "match_tree": {
    "and": [
      { "field": "path", "operator": "starts_with", "value": "/admin/" },
      { "not": { "field": "ip", "operator": "cidr_match", "value": "10.0.0.0/8" } }
    ]
  }
}
```

---

### 4.14 Rule Sources

![Rule Sources page](screenshots/screencapture-localhost-16827-ui-login-2026-05-22-22_34_31.png)

*Figure 4.14 — Rule Sources: built-in sources and Add Rule Source dialog*

**Built-in Sources** (read-only, always present):

| Source | Rules | Type |
|--------|-------|------|
| advanced | 77 rules | builtin |
| bot-detection | 42 rules | builtin |
| custom | 10 rules | builtin |
| cve-patches | 43 rules | builtin |
| geoip | 2 rules | builtin |
| modsecurity | 46 rules | builtin |
| owasp-api | 64 rules | builtin |
| owasp-crs | 328 rules | builtin |

**Add Rule Source dialog:**
| Field | Description |
|-------|-------------|
| Source Name | Identifier for this source |
| Type | Remote URL |
| URL | `https://example.com/rules.yaml` |
| Format | YAML / JSON |
| Update Interval | Seconds between syncs (default: 86400 = 24h) |

**Actions:** Sync All, Add Source

---

### 4.15 Rule Analytics

![Rule Analytics page](screenshots/screencapture-localhost-16827-ui-login-2026-05-22-22_34_43.png)

*Figure 4.15 — Rule Analytics: attack distribution, top rules, traffic timeline*

**Charts:**
- **Total WAF Requests by Rule Group** (donut): scanner, rce, ssrf, owasp-crs, advanced, sqli, xss, api-security, mass-assignment, data-leakage, lxe, txd, path-traversal, other
- **WAF Actions** (donut): block distribution

**Top Blocked Request URIs:** Treemap of most attacked paths:
- `/favicon.ico` — 22 hits
- `/` — 22 hits  
- `/gpanel/` — 19 hits
- `/api/dashboard/stats` — 10 hits
- `/api/feedbacks` — 10 hits
- `/login` — 1 hit
- ... and many more paths

**Top Triggered Rules:**
| Rule | Count |
|------|-------|
| Scanner | 1,836 |
| RCE | 400 |
| SSRF | 389 |
| SQL Injection | 193 |
| XSS | (count) |
| SSTI - Generic Expression Evaluation Test (`${7*7}`) | 47 |
| SSRF - Dangerous URL Schemes (file, gopher, dict) | 41 |
| PHP Injection Attack: PHP Script File Upload Found | 43 |
| PHP Injection Attack: Variable Access Found | 43 |
| Node.js Injection Attack V2 | 40 |

**Traffic timeline:** Line chart showing request volume over time

**Rules Details table:** Time-based drill-down with Rule ID, Action, Rule name, Path, Client IP, Host code, Country

**Filters:** Time range (1h/6h/24h/7d), Host filter, Export CSV, Refresh

---

### 4.16 Bot Management

![Bot Management page](screenshots/screencapture-localhost-16827-ui-login-2026-05-22-22_34_52.png)

*Figure 4.16 — Bot Management: categorized bot detection patterns*

Bot Management organizes detection patterns into tabs:

**Tab: Good Bots (Allow) — 8 patterns**
Googlebot, Bingbot, DuckDuckBot, Slurp, Baiduspider, YandexBot, facebot, ia_archiver — allowed crawlers.

**Tab: Bad Bots (Block) — 3 active patterns:**

| ID | Name | Pattern | Action |
|----|------|---------|--------|
| BOT-BAD-001 | Scrapy web scraper | `(?i)\bscrapy\b` | block |
| BOT-BAD-007 | Generic crawler/spider/scraper UA | `(?i)\b(crawler\|spider\|scraper)\b` | block |
| BOT-BAD-008 | Harvester / extractor tool | `(?i)\b(harvest\|extractor)\b` | block |

**Tab: AI Crawlers — 8 patterns**
GPTBot, Claude-Web, CCBot, anthropic-ai, Bytespider, PetalBot, etc.

**Tab: SEO Tools — 3 patterns**
Ahrefs, Semrush, Moz

**Tab: Custom — 0 patterns** (user-defined)

**Tab: Relay / Proxy** — proxy detection patterns

**Test User-Agent tool:** Enter any UA string and click Test to check which pattern it matches.

#### Add Bot Pattern Dialog

![Add Bot Pattern dialog](screenshots/screencapture-localhost-16827-ui-login-2026-05-22-22_34_59.png)

*Figure 4.16b — Add Bot Pattern: regex + name + action*

| Field | Description |
|-------|-------------|
| Pattern (regex) | e.g., `(?i)\bMyBot\b` |
| Name | Human-readable name |
| Action | Block / Allow |
| Description | Optional description |

---

### 4.17 CrowdSec Integration

#### CS Settings

![CrowdSec Settings](screenshots/screencapture-localhost-16827-ui-login-2026-05-22-22_35_43.png)

*Figure 4.17a — CrowdSec Integration Settings*

| Field | Description |
|-------|-------------|
| Enable CrowdSec Integration | Master toggle |
| Mode | Bouncer (pull decisions from LAPI) |
| Fallback Action | Allow (fail open) / Block (fail close) |
| LAPI URL | `http://127.0.0.1:8080` |
| Bouncer API Key | API key from CrowdSec LAPI |
| Update Frequency | Seconds between decision syncs (default: 10) |

Actions: **Save Configuration**, **Test Connection**

**Current status:** CrowdSec Inactive (not yet configured)

#### CS Decisions

![CrowdSec Decisions](screenshots/screencapture-localhost-16827-ui-login-2026-05-22-22_35_58.png)

*Figure 4.17b — CrowdSec Decisions: active ban/captcha decisions from LAPI*

Table columns: Value (IP/CIDR), Type (ban/captcha), Scenario, Origin, Scope, Duration

Filters: IP/value, type, scenario

#### CS Stats

![CrowdSec Statistics](screenshots/screencapture-localhost-16827-ui-login-2026-05-22-22_36_08.png)

*Figure 4.17c — CrowdSec Statistics: cache performance*

| Metric | Value |
|--------|-------|
| Cached Decisions | 0 |
| Cache Hits | 0 |
| Cache Hit Rate | 0.0% |

Charts: Decisions by Type (pie), Top Scenarios (bar)

---

### 4.18 Cache Dashboard

![Cache Dashboard](screenshots/screencapture-localhost-16827-ui-login-2026-05-22-22_36_17.png)

*Figure 4.18 — Cache Dashboard: real-time cache performance metrics*

**Metrics:**
| Metric | Value |
|--------|-------|
| Hit Ratio | 0.0% |
| Entries | 0 |
| Memory Used | 1.0 MB |
| Ops / sec | 0 |

**Hit / Miss Timeline (60 min):** Line chart of cache hit/miss rates

**Top Cached Routes:** Table — Route, Hits, Entries

**Backend Info:**
| Field | Value |
|-------|-------|
| Mode | Standalone |
| Version | 8.1.6 |
| Circuit Breaker | closed ✓ |
| Connected | ✓ |
| Memory Used | 1.1 MB / 256.0 MB (0.4%) |

**Cache Actions:**
- **Purge by Tag** — invalidate cached entries by tag
- **Purge by Route** — invalidate specific route cache
- **Flush All Cache** — clear entire cache (destructive)

---

### 4.19 TX Velocity & Sequence

![TX Velocity page](screenshots/screencapture-localhost-16827-ui-login-2026-05-22-22_36_26.png)

*Figure 4.19 — TX Velocity & Sequence: FR-012 cross-endpoint fraud detection*

**FR-012** detects fintech-style fraud patterns across multiple endpoints.

**Metrics:**
| Metric | Description |
|--------|-------------|
| Sequence Violations | Login→OTP→Deposit completed < 1500ms |
| Withdrawal Bursts | ≥5 withdrawals in 60-second window |
| Limit-Change Storms | ≥3 limit-change requests in 5 minutes |
| Total TX Events | All tracked transaction events |

**Detection Thresholds** (from `configs/tx-velocity.yaml`):

| Signal | Condition |
|--------|-----------|
| `TX-SEQ-*` | Login → OTP → Deposit sequence completed in < 1500 ms |
| `TX-WITHDRAW-*` | ≥ 5 withdrawals within a 60-second window |
| `TX-LIMIT-*` | ≥ 3 limit-change requests within 5 minutes |

**Signal Distribution:** Chart showing signal type breakdown

**Recent TX Events table:** Time, Signal Type, Rule ID, Client IP, Action, Rule

> Config: `configs/tx-velocity.yaml` · "To change thresholds: edit configs/tx-velocity.yaml and reload rules."

---

## 5. WAF Detection Pipeline

### 5.1 Full Pipeline Diagram

```mermaid
flowchart LR
    subgraph PRE ["Pre-Processing"]
        direction TB
        FR007[Relay Detection FR-007\nXFF · ASN · Tor exit\n→ ClientIdentity]
        FR010[Device Fingerprinting FR-010\nJA3/JA4 · H2 Akamai\n→ DeviceIdentity]
    end

    subgraph GATE ["Phase-0: Access Gate FR-008"]
        HG[Host Gate\nper-tier FQDN allowlist]
        BL[IP Blacklist\nPatricia-trie CIDR]
        WL[IP Whitelist\nCIDR → full_bypass or blacklist_only]
        HG --> BL --> WL
    end

    subgraph FAST ["Phases 1-4: Fast-Path"]
        P1[Phase 1\nIP Whitelist]
        P2[Phase 2\nIP Blacklist]
        P3[Phase 3\nURL Whitelist\n→ bypass all]
        P4[Phase 4\nURL Blocklist]
    end

    subgraph RATE ["Phases 5-5.7: Rate & Behavior"]
        P5[Phase 5: Rate Limit FR-004\nToken-bucket + Sliding-window\nIP key + Session key]
        P55[Phase 5.5: DDoS FR-005\nPer-IP · Per-FP · Per-Tier\nBan TTL 60s · RiskBump]
        P56[Phase 5.6: TX Velocity FR-012\nSequence · Withdrawal · LimitChange]
        P57[Phase 5.7: Behavioral Anomaly FR-011\n16-slot ring · cadence · path]
    end

    subgraph ATK ["Phases 6-11: Attack Detection"]
        P6[Phase 6: Scanner Detection\nNikto · Nessus · OpenVAS UA patterns]
        P7[Phase 7: Bot Detection\nHeadless markers · credential-stuffing tools]
        P8[Phase 8: SQL Injection\nlibinjection + 19 regex patterns\nURL-decode 3 rounds]
        P9[Phase 9: XSS\nlibinjection + regex]
        P10[Phase 10: RCE\nShell metachar · EL injection · Log4Shell]
        P11[Phase 11: Traversal + SSRF\n../ · RFC1918 · DNS rebinding]
    end

    subgraph RULES ["Phases 12-16: Rule Engines"]
        P12[Phase 12: Custom Rules FR-003\nAND/OR/NOT tree\nJSON DSL + Rhai]
        P13[Phase 13: OWASP CRS\n24+ categories]
        P14[Phase 14: Sensitive Data\nAho-Corasick PII]
        P15[Phase 15: Anti-Hotlink\nReferer validation]
        P16[Phase 16: CrowdSec\nBouncer + AppSec]
    end

    subgraph POST ["Post-Decision"]
        RS[Risk Scoring FR-025\nL0 seed + L1 accu + L2 anomaly+velocity\nDecay · Thresholds]
        Cache[FR-009 Smart Cache\nValkey / moka LRU\nTier-aware TTL · Tag purge]
    end

    PRE --> GATE --> FAST --> RATE --> ATK --> RULES --> POST
```

### 5.2 Phase-by-Phase Reference

| Phase | Name | FR | Mechanism | Block Condition |
|-------|------|-----|-----------|-----------------|
| 0 | Access Gate | FR-008 | Patricia-trie CIDR, Host gate | host not in allowlist / IP in blacklist |
| 1 | IP Whitelist | — | CIDR table lookup | — (allow path) |
| 2 | IP Blacklist | — | CIDR table lookup | IP matches blocklist CIDR |
| 3 | URL Whitelist | — | regex + literal path match | — (bypass all path) |
| 4 | URL Blocklist | — | regex + literal path match | path matches blocklist |
| 5 | Rate Limiting | FR-004 | Token-bucket + sliding-window | exceeds IP or session limit |
| 5.5 | DDoS Detection | FR-005 | Per-IP/FP/Tier sliding-window | HardBurst → Ban or RiskBump |
| 5.6 | TX Velocity | FR-012 | Sequence FSM + ring buffer | sequence anomaly → risk signal |
| 5.7 | Behavioral Anomaly | FR-011 | 16-slot ring, signal cap ≤40 | anomaly → risk signal |
| 6 | Scanner Detection | — | UA fingerprint + request patterns | scanner signature match |
| 7 | Bot Detection | — | UA analysis + headless markers | bad bot UA match |
| 8 | SQLi Detection | — | libinjection + 19 regex | SQLi payload detected |
| 9 | XSS Detection | — | libinjection + regex | XSS payload detected |
| 10 | RCE Detection | — | Shell metachar + EL patterns | RCE payload detected |
| 11 | Traversal/SSRF | FR-016 | Path normalization + RFC1918 | traversal or SSRF detected |
| 12 | Custom Rules | FR-003 | AND/OR/NOT condition tree | rule condition matches |
| 13 | OWASP CRS | — | 24+ pre-compiled pattern sets | CRS rule match |
| 14 | Sensitive Data | — | Aho-Corasick multi-pattern | sensitive keyword in request |
| 15 | Anti-Hotlink | — | Referer header validation | Referer not in allowlist |
| 16 | CrowdSec | — | LAPI decision cache + AppSec | IP has active ban/captcha decision |
| Post | Risk Scoring | FR-025 | L0+L1+L2 accumulation | score ≥ challenge/block threshold |

---

## 6. Complete Rule Catalog

### 6.1 OWASP Core Rule Set (`rules/owasp-crs/`) — 328 rules

| File | Rule IDs | Category | Description |
|------|----------|----------|-------------|
| `sqli.yaml` | CRS-942100..942551 | sqli | SQL injection via libinjection + function/keyword patterns |
| `xss.yaml` | CRS-941100..941999 | xss | Cross-site scripting (DOM, reflected, stored) |
| `lfi.yaml` | CRS-930100..930999 | lfi | Local file inclusion, path traversal |
| `rfi.yaml` | CRS-931100..931999 | rfi | Remote file inclusion via HTTP/FTP/PHP schemes |
| `rce.yaml` | CRS-932100..932999 | rce | OS command injection, shell metacharacters |
| `generic-attack.yaml` | CRS-950100..950999 | generic | General attack patterns and anomaly detection |
| `protocol-enforcement.yaml` | CRS-920100..920999 | protocol | HTTP protocol compliance validation |
| `method-enforcement.yaml` | CRS-911100..911999 | protocol | HTTP method restrictions |
| `scanner-detection.yaml` | CRS-913100..913999 | scanner | Vulnerability scanner UA signatures (Nmap, Nikto, OpenVAS, etc.) |
| `session-fixation.yaml` | CRS-943100..943999 | session | Session fixation attack patterns |
| `multipart-attack.yaml` | CRS-922100..922999 | upload | Multipart body attack vectors |
| `php-injection.yaml` | CRS-933100..933999 | php | PHP code injection patterns |
| `java-injection.yaml` | CRS-944100..944999 | java | Java/Spring expression injection |
| `web-shells.yaml` | CRS-955100..955999 | webshell | Web shell upload/access signatures |
| `data-leakage.yaml` | CRS-950900..950999 | outbound | Response data leakage detection |
| `data-leakage-sql.yaml` | CRS-951100..951999 | outbound | SQL error messages in responses |
| `data-leakage-java.yaml` | CRS-952100..952999 | outbound | Java exception leakage in responses |
| `response-web-shells.yaml` | CRS-955200..955999 | outbound | Web shell indicators in responses |
| `response-iis-errors.yaml` | CRS-950120..950199 | outbound | IIS error message detection |
| `response-php-errors.yaml` | CRS-953100..953999 | outbound | PHP error detail exposure |
| `response-sql-errors.yaml` | CRS-951200..951999 | outbound | SQL error detail in responses |
| `response-ruby-errors.yaml` | CRS-954100..954999 | outbound | Ruby exception detail exposure |
| `protocol-attack.yaml` | CRS-921100..921999 | protocol | HTTP request smuggling, header injection |
| `response-data-leakage.yaml` | CRS-950100..950199 | outbound | Generic sensitive data in responses |

### 6.2 CVE Patches (`rules/cve-patches/`) — 43 rules

| File | CVEs | Category | Description |
|------|------|----------|-------------|
| `2021-log4shell.yaml` | CVE-2021-44228, CVE-2021-45046, CVE-2021-45105 | rce | Log4Shell JNDI injection — multiple obfuscation variants, case-insensitive |
| `2022-spring4shell.yaml` | CVE-2022-22965, CVE-2022-22963 | rce | Spring Framework `class.module.classLoader` exploitation |
| `2022-text4shell.yaml` | CVE-2022-42889 | rce | Apache Commons Text string interpolation RCE |
| `2023-moveit.yaml` | CVE-2023-34362, CVE-2023-35036 | sqli/rce | MOVEit Transfer SQL injection + authentication bypass |
| `2024-xz-backdoor.yaml` | CVE-2024-3094 | backdoor | XZ Utils backdoor detection patterns |
| `2024-recent.yaml` | Multiple 2024 CVEs | mixed | Recent 2024 critical vulnerability patches |
| `2025-recent.yaml` | Multiple 2025 CVEs | mixed | Recent 2025 critical vulnerability patches |

**Example rule — Log4Shell:**
```yaml
kind: custom_rule_v1
id: CVE-2021-LOG4J-001
name: Log4Shell JNDI injection in all fields (primary pattern)
enabled: true
action: block
pattern: (?i)\$\{(?:[\w+.:/-]+\$\{[\w+.:/-]+\})?(?:j|J|\$\{(?:lower|upper):\w+\})...
category: rce
severity: critical
tags: [cve-2021-44228, log4shell, jndi, rce, critical]
reference: https://nvd.nist.gov/vuln/detail/CVE-2021-44228
```

### 6.3 Advanced Rules (`rules/advanced/`) — 77 rules

| File | Category | Rules | Description |
|------|----------|-------|-------------|
| `ssrf.yaml` | ssrf | ~15 | SSRF — RFC1918 ranges in params, DNS rebinding, loopback, cloud metadata IPs |
| `ssti.yaml` | ssti | 13 | SSTI — Jinja2, Twig, Freemarker, Velocity, Smarty, Pebble, Mako, ERB, Handlebars, SpEL |
| `xxe.yaml` | xxe | ~10 | XXE — DOCTYPE SYSTEM/PUBLIC, entity references, parameter entities |
| `deserialization.yaml` | deserialization | ~12 | Java/PHP/Python deserialization payloads, ysoserial gadget chains |
| `prototype-pollution.yaml` | prototype-pollution | 7 | JS `__proto__`, `constructor.prototype`, `Object.prototype` manipulation |
| `webshell-upload.yaml` | webshell | ~20 | Web shell file upload: .php/.asp/.jsp with code signatures |

**SSTI rules detail (13 rules):**
- `ADV-SSTI-001`: Generic `${7*7}` expression evaluation test
- `ADV-SSTI-002`: Jinja2 `config` object access
- `ADV-SSTI-003`: Jinja2 class traversal for RCE (`__class__.__mro__`)
- `ADV-SSTI-004`: Twig `{{7*'7'}}` template exploitation
- `ADV-SSTI-005`: Freemarker `<#assign>` directive injection
- `ADV-SSTI-006`: Velocity `#set($x=...)` injection
- `ADV-SSTI-007`: Smarty PHP template injection
- `ADV-SSTI-008`: Pebble Java template injection
- `ADV-SSTI-009`: Mako Python template injection
- `ADV-SSTI-010`: ERB Ruby `<%= %>` injection
- `ADV-SSTI-011`: Handlebars/Mustache template injection
- `ADV-SSTI-012`: Spring EL (SpEL) expression injection
- `ADV-SSTI-013`: Generic polyglot detection probe

**Prototype Pollution rules (7 rules):**
- `ADV-PROTO-001` through `ADV-PROTO-007`: `__proto__`, `constructor.prototype`, `Object.prototype`, bracket notation in JSON body, query string, body, query

### 6.4 Bot Detection Rules (`rules/bot-detection/`) — 42 rules

| File | Category | Description |
|------|----------|-------------|
| `credential-stuffing.yaml` | credential-stuffing | SentryMBA, Storm, Apex, SNIPR, BlackBullet, SilverBullet, Woxy, Lauth |
| `crawlers.yaml` | crawler | Unauthorized web crawlers, scraper bot UAs |
| `scraping.yaml` | scraping | Data scraping behavioral patterns and tool signatures |

### 6.5 OWASP API Security Rules (`rules/owasp-api/`) — 64 rules

| File | OWASP API Category | Description |
|------|-------------------|-------------|
| `broken-auth.yaml` | API2:2023 Broken Authentication | JWT none algorithm, algorithm confusion, weak token patterns |
| `data-exposure.yaml` | API3:2023 Excessive Data Exposure | Sensitive field patterns in API responses |
| `injection.yaml` | API8:2023 Injection | GraphQL injection, REST/SOAP-specific vectors |
| `mass-assignment.yaml` | API6:2023 Mass Assignment | Suspicious bulk parameter assignment |
| `rate-abuse.yaml` | API4:2023 Rate Limiting | API endpoint rate abuse patterns |

### 6.6 ModSecurity-Compatible Rules (`rules/modsecurity/`) — 46 rules

| File | Category | Description |
|------|----------|-------------|
| `ip-reputation.yaml` | ip-reputation | Tor exit headers, empty UA, known bad IP signals |
| `dos-protection.yaml` | dos | Request rate anomaly, HTTP flood signatures |
| `data-leakage.yaml` | data-leakage | Outbound data leakage patterns |
| `response-checks.yaml` | response | HTTP response anomaly detection |

### 6.7 GeoIP & Threat Intel Rules

| File | Category | Description |
|------|----------|-------------|
| `geoip/country-blocklist.yaml` | geoip | Block traffic from specific countries (ISO codes) |
| `threat-intel/hyperscaler-asn-seed.yaml` | asn | AWS, GCP, Azure, Cloudflare ASN seed list for classification |

### 6.8 Custom File-Based Rules (`rules/custom/`) — 10 rules

User-defined rules in `rules/custom/*.yaml` following the `custom_rule_v1` schema.

**Schema:**
```yaml
kind: custom_rule_v1
id: CUSTOM-001                    # Unique rule ID
name: "Rule name"
enabled: true
priority: 100                     # Lower = higher priority
host_code: "myapp"                # or "*" for global
action: block                     # block | allow | log | challenge
action_status: 403
action_msg: "Blocked by WAF"
risk_delta: 50                    # Contribution to FR-025 risk score (0-100)

# Option 1: Match tree (preferred)
match_tree:
  and:
    - field: path
      operator: starts_with
      value: /admin/
    - not:
        field: ip
        operator: cidr_match
        value: 10.0.0.0/8

# Option 2: Rhai script (advanced)
script: |
  ctx.path.starts_with("/api/") && ctx.method == "DELETE"

# Option 3: Legacy flat conditions
conditions:
  - field: user_agent
    operator: contains
    value: "bot"
condition_op: and
```

**Included sample rules:**
- `example.yaml` — basic example
- `fr003-sample-cookie-session.yaml` — cookie-based session blocking
- `fr003-sample-nested-blacklist.yaml` — nested AND/OR/NOT example
- `fr003-sample-wildcard-admin.yaml` — wildcard path protection

---

## 7. Configuration Reference

### 7.1 Main Config (`configs/default.toml`)

```toml
# ── Proxy listener ────────────────────────────────────────────────────────────
[proxy]
listen_addr     = "0.0.0.0:80"
listen_addr_tls = "0.0.0.0:443"

# ── Admin API + UI ────────────────────────────────────────────────────────────
[api]
listen_addr = "0.0.0.0:9527"

# ── PostgreSQL storage ────────────────────────────────────────────────────────
[storage]
database_url    = "postgresql://prx_waf:prx_waf@postgres:5432/prx_waf"
max_connections = 20

# ── Response caching (FR-009) ─────────────────────────────────────────────────
[cache]
enabled          = true
max_size_mb      = 256
default_ttl_secs = 60
max_ttl_secs     = 3600
rules_path       = "rules/cache.yaml"    # per-route TTL rules (hot-reload)
backend          = "memory"              # memory | embedded | standalone | cluster

# ── HTTP/3 QUIC (optional) ────────────────────────────────────────────────────
[http3]
enabled     = false
listen_addr = "0.0.0.0:443"

# ── Security hardening ────────────────────────────────────────────────────────
[security]
admin_ip_allowlist       = []           # CIDRs allowed to access Admin API
max_request_body_bytes   = 10485760     # 10 MB max body
api_rate_limit_rps       = 0            # Admin API rate limit (0=disabled)
cors_origins             = []           # CORS origins (empty=allow all)

# ── DDoS protection (FR-005) ─────────────────────────────────────────────────
[ddos]
enabled = true
store   = "memory"

[ddos.per_ip]
threshold_rps = 1000
window_secs   = 1
ban_ttl_secs  = 60

[ddos.per_tier]
critical_threshold_rps  = 50
high_threshold_rps      = 200
medium_threshold_rps    = 1000
catchall_threshold_rps  = 5000

# ── Rate limiting (FR-004) ────────────────────────────────────────────────────
[rate_limit]
config_path = "configs/rate-limit.yaml"

# ── Admin panel runtime config ────────────────────────────────────────────────
[panel]
config_path = "waf-panel.toml"

# ── Proxy hosts ───────────────────────────────────────────────────────────────
[[hosts]]
host        = "example.com"
port        = 80
remote_host = "127.0.0.1"
remote_port = 8080
guard_status = true
```

### 7.2 Tiered Protection (`configs/default.toml` — `[tiered_protection]`)

```toml
[tiered_protection]
default_tier = "catch_all"

# Classifier rules — highest priority evaluated first
[[tiered_protection.classifier_rules]]
priority = 100
tier     = "critical"
path     = { kind = "exact",  value = "/login" }
method   = ["POST"]

[[tiered_protection.classifier_rules]]
priority = 90
tier     = "high"
path     = { kind = "prefix", value = "/api/" }

[[tiered_protection.classifier_rules]]
priority = 80
tier     = "high"
host     = { kind = "suffix", value = ".internal.example.com" }

# Per-tier policies — all four required
[tiered_protection.policies.critical]
fail_mode          = "close"
ddos_threshold_rps = 50
cache_policy       = { mode = "no_cache" }
risk_thresholds    = { allow = 10, challenge = 40, block = 70 }

[tiered_protection.policies.high]
fail_mode          = "close"
ddos_threshold_rps = 200
cache_policy       = { mode = "short_ttl", ttl_seconds = 30 }
risk_thresholds    = { allow = 20, challenge = 50, block = 80 }

[tiered_protection.policies.medium]
fail_mode          = "open"
ddos_threshold_rps = 1000
cache_policy       = { mode = "default", ttl_seconds = 300 }
risk_thresholds    = { allow = 30, challenge = 60, block = 85 }

[tiered_protection.policies.catch_all]
fail_mode          = "open"
ddos_threshold_rps = 4294967295
cache_policy       = { mode = "aggressive", ttl_seconds = 3600 }
risk_thresholds    = { allow = 35, challenge = 65, block = 90 }
```

### 7.3 Rate Limiting (`configs/rate-limit.yaml`)

```yaml
version: 1
tiers:
  critical:
    ip:
      burst_capacity: 10
      burst_refill_per_s: 5.0
      window_secs: 60
      window_limit: 100
    session:
      burst_capacity: 5
      burst_refill_per_s: 2.0
      window_secs: 60
      window_limit: 50
  high:
    ip:
      burst_capacity: 50
      burst_refill_per_s: 20.0
      window_secs: 60
      window_limit: 500
  medium:
    ip:
      burst_capacity: 100
      burst_refill_per_s: 50.0
      window_secs: 60
      window_limit: 2000
  catch_all:
    ip:
      burst_capacity: 200
      burst_refill_per_s: 100.0
      window_secs: 60
      window_limit: 5000
```

### 7.4 Access Lists (`rules/access-lists.yaml`)

```yaml
version: 1
dry_run: false          # true = log-only mode

ip_whitelist:           # CIDR or bare IP, v4+v6
  - 10.0.0.0/8
  - 192.168.1.5
  - 2001:db8::/32

ip_blacklist:
  - 203.0.113.0/24
  - 198.51.100.42

host_whitelist:         # per-tier FQDN allowlist (empty = gate OFF)
  critical:
    - api.example.com
    - secure.example.com
  high:
    - api.example.com
  medium: []
  catch_all: []

tier_whitelist_mode:    # full_bypass | blacklist_only (safer default)
  critical:  blacklist_only
  high:      blacklist_only
  medium:    full_bypass
  catch_all: full_bypass
```

### 7.5 Device Fingerprinting (`configs/device-fp.yaml` or `rules/device-fp.yaml`)

```yaml
device_fp:
  schema_version: 1
  enabled: true
  hot_reload: true

  capture:
    tls:
      enabled: true
      algorithms: [ja3, ja4]
    h2:
      enabled: true
      hash: akamai

  store:
    backend: memory        # memory | redis
    ttl_secs: 3600

  providers:
    - name: ip_hopping
      window_secs: 600
      max_distinct_ips: 3
      signal_weight: 25
    - name: fp_conflict
      window_secs: 600
      max_distinct_uas: 4
      signal_weight: 30
    - name: ua_entropy
      min_entropy_x100: 250
      signal_weight: 15
    - name: ua_blocklist
      blocklist_patterns:
        - "(?i)curl-impersonate"
        - "(?i)nuclei"
      signal_weight: 40
    - name: h2_anomaly
      signal_weight: 35
```

### 7.6 TX Velocity (`configs/tx-velocity.yaml`)

```yaml
tx_velocity:
  schema_version: 1
  enabled: false          # flip to true to activate
  session_cookie: SESSIONID
  signal_cooldown_ms: 5000
  session_ttl_secs: 600

  role_patterns:
    - role: Login
      pattern: "(?i)^/(?:login|signin|auth/login)$"
    - role: Otp
      pattern: "(?i)^/(?:otp|verify|mfa)$"
    - role: Deposit
      pattern: "(?i)^/(?:deposit|topup|fund)$"
    - role: Withdrawal
      pattern: "(?i)^/(?:withdraw|payout|cashout)$"
    - role: LimitChange
      pattern: "(?i)^/(?:limit|settings/transfer)$"

  classifiers:
    sequence_timing:
      enabled: true
      roles: [Login, Otp, Deposit]
      max_duration_ms: 1500
    withdrawal_velocity:
      enabled: true
      max_count: 5
      window_secs: 60
    limit_change_burst:
      enabled: true
      max_count: 3
      window_secs: 300
```

### 7.7 Response Cache (`rules/cache.yaml`)

```yaml
version: 1
rules:
  - path: "^/api/public/.*"
    ttl_seconds: 300
    tags: [api, public]
  - path: "^/static/.*"
    ttl_seconds: 86400
    tags: [static]
  - path: "^/api/auth/.*"
    ttl_seconds: 0        # never cache auth endpoints
```

---

## 8. Clustering & High Availability

### 8.1 Cluster Topology

```mermaid
graph TD
    subgraph Main ["Main Node (Control Plane)"]
        DB[(PostgreSQL)]
        Rules[Rule Registry + Changelog]
        AdminUI[Admin UI]
        Raft[Raft-lite Leader]
    end

    subgraph W1 ["Worker Node B"]
        Cache1[In-memory Rule Cache]
        Proxy1[Pingora Proxy]
    end

    subgraph W2 ["Worker Node C"]
        Cache2[In-memory Rule Cache]
        Proxy2[Pingora Proxy]
    end

    Main -->|lz4 rule sync\nQUIC mTLS :16851| W1
    Main -->|lz4 rule sync\nQUIC mTLS :16851| W2
    W1 -->|forward writes\nQUIC mTLS| Main
    W2 -->|forward writes\nQUIC mTLS| Main
    LB[Load Balancer] --> Proxy1
    LB --> Proxy2
    LB --> Main
```

### 8.2 Quick Start — 3-Node Docker Cluster

```bash
# 1. Generate cluster certificates (once)
podman-compose -f docker-compose.cluster.yml run --rm cluster-init
# Output:
#   cluster-ca.pem, cluster-ca.key
#   node-a.pem, node-a.key
#   node-b.pem, node-b.key
#   node-c.pem, node-c.key

# 2. Start all 3 nodes
podman-compose -f docker-compose.cluster.yml up -d

# 3. Verify health
curl http://localhost:16827/health    # node-a (main)
curl http://localhost:16828/health    # node-b (worker)
curl http://localhost:16829/health    # node-c (worker)

# 4. Check cluster status
curl http://localhost:16827/api/cluster/status | python3 -m json.tool

# 5. Run E2E tests
./tests/e2e-cluster.sh
# Artifacts: tests/artifacts/{junit.xml, test-results.json, test-results.md, test-results.html}
```

### 8.3 Node Configuration

**Main node (`configs/node-a.toml`):**
```toml
[cluster]
enabled     = true
node_id     = "node-a"
role        = "main"
listen_addr = "0.0.0.0:16851"
seeds       = []

[cluster.crypto]
ca_cert       = "/certs/cluster-ca.pem"
ca_key        = "/certs/cluster-ca.key"   # main only
node_cert     = "/certs/node-a.pem"
node_key      = "/certs/node-a.key"
auto_generate = false
```

**Worker node (`configs/node-b.toml`):**
```toml
[cluster]
enabled     = true
node_id     = "node-b"
role        = "worker"
listen_addr = "0.0.0.0:16851"
seeds       = ["node-a:16851"]            # or IP: ["10.0.0.1:16851"]

[cluster.crypto]
ca_cert   = "/certs/cluster-ca.pem"
ca_key    = ""                            # workers do NOT need CA key
node_cert = "/certs/node-b.pem"
node_key  = "/certs/node-b.key"
```

### 8.4 Cluster Operations

```bash
# Check cluster status
prx-waf cluster status

# Generate worker join token (24h TTL)
prx-waf cluster token generate --ttl 24h

# Force rule sync to all workers
curl -X POST http://localhost:16827/api/cluster/sync \
  -H "Authorization: Bearer <token>"
```

---

## 9. REST API Reference

Base URL: `http://<host>:16827/api/`  
Authentication: `Authorization: Bearer <jwt_token>` (except `/api/auth/login` and `/health`)

### 9.1 Authentication

```bash
# Login
curl -X POST http://localhost:16827/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin123"}'
# Response: {"token":"eyJ...","expires_in":3600}

# Refresh token
curl -X POST http://localhost:16827/api/auth/refresh \
  -H "Authorization: Bearer <token>"
```

### 9.2 Full Endpoint Table

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/auth/login` | Get JWT token |
| POST | `/api/auth/refresh` | Refresh JWT token |
| GET | `/api/hosts` | List proxy hosts |
| POST | `/api/hosts` | Create host |
| GET | `/api/hosts/:id` | Get host |
| PUT | `/api/hosts/:id` | Update host |
| DELETE | `/api/hosts/:id` | Delete host |
| GET | `/api/block-ips` | List IP blocklist |
| POST | `/api/block-ips` | Add IP to blocklist |
| DELETE | `/api/block-ips/:id` | Remove IP |
| GET | `/api/block-urls` | List URL blocklist |
| POST | `/api/block-urls` | Add URL pattern |
| DELETE | `/api/block-urls/:id` | Remove URL pattern |
| GET | `/api/attack-logs` | Attack logs (paginated) |
| GET | `/api/security-events` | Security events (paginated, filterable) |
| GET | `/api/security-events/:id` | Single event detail |
| GET | `/api/stats/timeseries-by-category` | Hourly counts per category |
| POST | `/api/reload` | Hot-reload all rules |
| GET | `/api/cluster/status` | Cluster topology + health |
| POST | `/api/cluster/tokens` | Generate join token |
| GET | `/api/custom-rules` | List custom rules |
| POST | `/api/custom-rules` | Create custom rule |
| GET | `/api/custom-rules/:id` | Get custom rule |
| PUT | `/api/custom-rules/:id` | Update custom rule |
| DELETE | `/api/custom-rules/:id` | Delete custom rule |
| GET | `/api/rules` | List all built-in rules |
| PUT | `/api/rules/:id/toggle` | Enable/disable rule |
| GET | `/api/rule-sources` | List rule sources |
| POST | `/api/rule-sources` | Add remote source |
| DELETE | `/api/rule-sources/:id` | Remove source |
| GET | `/api/ssl` | List certificates |
| POST | `/api/ssl` | Upload certificate |
| DELETE | `/api/ssl/:id` | Delete certificate |
| GET | `/api/crowdsec/settings` | CrowdSec config |
| PUT | `/api/crowdsec/settings` | Update CrowdSec config |
| GET | `/api/crowdsec/decisions` | Active decisions |
| GET | `/api/crowdsec/stats` | CrowdSec statistics |
| GET | `/api/cache/stats` | Cache performance stats |
| POST | `/api/cache/purge/tag` | Purge cache by tag |
| POST | `/api/cache/purge/route` | Purge cache by route |
| POST | `/api/cache/flush` | Flush all cache |
| GET | `/api/notifications` | List notification configs |
| POST | `/api/notifications` | Create notification config |
| DELETE | `/api/notifications/:id` | Delete notification |
| GET | `/health` | Health check (no auth) |
| WS | `/ws/events` | Real-time security event stream |
| WS | `/ws/logs` | Real-time access log stream |

---

## 10. CLI Reference

```
prx-waf [OPTIONS] <COMMAND>

Options:
  -c, --config <FILE>   Config file [default: configs/default.toml]
  -h, --help            Print help
  -V, --version         Print version

Commands:
  run          Start proxy + API server (all subsystems)
  migrate      Run PostgreSQL database migrations
  seed-admin   Create default admin user (admin/admin123)
  crowdsec     CrowdSec integration management
  rules        Rule management
  sources      Remote rule source management
  bot          Bot detection management
  cluster      Cluster management
```

**Rules subcommands:**
```bash
prx-waf rules list                    # List all rules
prx-waf rules list --category sqli    # Filter by category
prx-waf rules list --source owasp-crs # Filter by source
prx-waf rules reload                  # Hot-reload from disk + DB
prx-waf rules validate                # Validate YAML rule files
```

**Cluster subcommands:**
```bash
prx-waf cluster status                         # Node topology
prx-waf cluster token generate --ttl 24h       # Join token
```

**CrowdSec subcommands:**
```bash
prx-waf crowdsec status    # Connection status
prx-waf crowdsec sync      # Force sync decisions
```

---

## 11. Security Best Practices

1. **Change default credentials immediately** — `admin / admin123` must be changed on first login.
2. **Restrict Admin API access** — Set `admin_ip_allowlist` to management CIDRs only.
3. **Enable TOTP 2FA** — Configure via Settings → System Settings for admin accounts.
4. **Use TLS for Admin API** — Place behind nginx/Caddy with valid certificate in production.
5. **Strong database password** — Never use default `prx_waf` password in production.
6. **Enable AES-256-GCM encryption** — Sensitive config values are encrypted at rest by default.
7. **Configure Let's Encrypt** — Enable ACME auto-renewal for proxy HTTPS certificates.
8. **Use `blacklist_only` whitelist mode** — Default; only opt into `full_bypass` for fully trusted IPs.
9. **Test with `dry_run: true`** — Validate new access list rules before enabling enforcement.
10. **Monitor Dashboard regularly** — Watch for block rate spikes and unusual attack category trends.
11. **Configure alert notifications** — Set up Telegram/Webhook for critical (Critical-tier) attack events.
12. **3-node minimum for HA clusters** — 1 Main + 2 Workers ensures quorum during node failure.
13. **Set `max_request_body_bytes`** — Limit request body size to prevent memory exhaustion.
14. **Review honeypot hits** — Honeypot triggers indicate active reconnaissance; investigate IPs.
15. **Keep rules up-to-date** — Sync remote rule sources periodically for latest CVE patches.

---

## 12. Troubleshooting

| Symptom | Likely Cause | Resolution |
|---------|-------------|------------|
| 403 on all requests | IP in blacklist or access-list blocks | Check `rules/access-lists.yaml` and IP Rules in Admin UI |
| Admin UI unreachable | API server not started or port blocked | `curl http://localhost:16827/health` |
| Rules not updating | Hot-reload not triggered | `POST /api/reload` or `kill -HUP <pid>` |
| High false-positive rate | Rule too aggressive | Review Security Events, use `dry_run: true` |
| Cluster nodes disconnected | Certificate mismatch or network | Check `/api/cluster/status`, verify CA cert shared |
| Rate limit false positives | Threshold too low for traffic | Increase `ddos_threshold_rps` or adjust rate-limit YAML |
| Cache not working | Valkey not reachable | Check `backend` in `[cache]` config, circuit breaker status |
| Login fails | Wrong credentials or TOTP drift | `prx-waf seed-admin` to reset; check TOTP clock sync |
| High memory usage | Cache `max_size_mb` too large | Reduce `max_size_mb` in `[cache]` config |
| CrowdSec inactive | Not configured | Set LAPI URL + API key in CS Settings |
| TX Velocity not detecting | `enabled: false` | Set `enabled: true` in `configs/tx-velocity.yaml` |

**Health check:**
```bash
curl http://localhost:16827/health
# {"status":"ok","version":"0.2.0","uptime_secs":12345}
```

**View logs:**
```bash
# Docker Compose
docker compose logs -f prx-waf

# Systemd
journalctl -u prx-waf -f

# Structured log fields: access_decision, access_reason, tier, phase, rule_id, client_ip
```

**Hot-reload rules:**
```bash
# Via API
curl -X POST http://localhost:16827/api/reload \
  -H "Authorization: Bearer <token>"

# Via signal
kill -HUP $(pgrep prx-waf)

# Via CLI
prx-waf rules reload
```

---

*PRX-WAF (F&G WAF) · Version 0.2.0 · Rust 2024 · Pingora · © OpenPRX Community*
