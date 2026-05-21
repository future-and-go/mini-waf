# Deployment Guide

Single-node deployment with Docker Compose, Systemd, and configuration. For multi-node cluster setups, see [Cluster Guide](./cluster-guide.md).

## Single-Node Docker Compose

### Prerequisites

- Docker Compose v1.3+ (or Podman Compose)
- 4GB RAM minimum, 2 CPU cores
- Ports 80, 443, 16827 available

### Quick Start

```bash
git clone https://github.com/openprx/prx-waf
cd prx-waf

# Edit environment in docker-compose.yml (DB password, etc.)
nano docker-compose.yml

# Start
docker compose up -d

# Verify health
curl http://localhost:16827/health

# Access Admin UI
# http://localhost:16827/ui/
# Default: admin / admin123
```

### Configuration

```yaml
# docker-compose.yml
version: '3.8'
services:
  postgres:
    image: postgres:16-alpine
    environment:
      POSTGRES_DB: prx_waf
      POSTGRES_USER: prx_waf
      POSTGRES_PASSWORD: changeme123
    ports:
      - "15432:5432"
    volumes:
      - postgres_data:/var/lib/postgresql/data

  prx-waf:
    build: .
    # Or use prebuilt: image: openprx/prx-waf:latest
    depends_on:
      - postgres
    environment:
      DATABASE_URL: postgresql://prx_waf:changeme123@postgres:5432/prx_waf
    ports:
      - "16880:80"      # HTTP proxy
      - "16843:443"     # HTTPS proxy (TLS)
      - "16827:9527"    # Admin API + UI
    cap_add:
      - NET_ADMIN       # For setting socket options
    ulimits:
      nofile: 65535
      nproc: 4096
    restart: unless-stopped

volumes:
  postgres_data:
```

### First Run

On container startup, migrations run automatically:

```bash
# Check logs
docker compose logs prx-waf

# Create default admin
docker compose exec prx-waf \
  /app/prx-waf -c /etc/prx-waf/config.toml seed-admin

# Login with admin / admin123
# Change password immediately!
```

### Scaling Single-Node

```bash
# Increase database connections
docker compose exec postgres psql -U prx_waf -d prx_waf << EOF
ALTER DATABASE prx_waf SET max_connections = 100;
EOF

# Increase WAF worker threads
docker compose exec prx-waf prx-waf --config ... run --worker-threads 8
```

---

## Systemd Deployment

### Prerequisites

- Rust 1.86+ (or pre-built binary)
- PostgreSQL 16+ (separate server)
- Linux with systemd
- User: `prx-waf` (unprivileged)

### Build

```bash
cargo build --release

# Binary: target/release/prx-waf
# Size: ~80MB (with debug info), ~12MB (stripped)
```

### Install

```bash
# Create user
sudo useradd -r -s /sbin/nologin prx-waf

# Install binary
sudo install -m 0755 target/release/prx-waf /usr/local/bin/prx-waf

# Create config directory
sudo mkdir -p /etc/prx-waf
sudo chown prx-waf:prx-waf /etc/prx-waf
sudo chmod 750 /etc/prx-waf

# Install config
sudo install -m 0640 -o prx-waf -g prx-waf configs/default.toml /etc/prx-waf/config.toml

# Create data directory
sudo mkdir -p /var/lib/prx-waf
sudo chown prx-waf:prx-waf /var/lib/prx-waf
sudo chmod 750 /var/lib/prx-waf

# Create log directory
sudo mkdir -p /var/log/prx-waf
sudo chown prx-waf:prx-waf /var/log/prx-waf
```

### Systemd Unit

**File: `/etc/systemd/system/prx-waf.service`**

```ini
[Unit]
Description=PRX-WAF Reverse Proxy and WAF
Documentation=https://docs.openprx.dev/en/prx-waf/
After=network-online.target postgresql.service
Wants=network-online.target

[Service]
Type=simple
User=prx-waf
Group=prx-waf

# Security hardening
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
ProtectClock=yes
ProtectHostname=yes
ReadWritePaths=/var/lib/prx-waf /var/log/prx-waf
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
RestrictNamespaces=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes

# Capabilities
AmbientCapabilities=CAP_NET_BIND_SERVICE
Capabilities=CAP_NET_BIND_SERVICE+ep

# Resource limits
LimitNOFILE=65535
LimitNPROC=4096
MemoryLimit=2G

# Restart policy
Restart=on-failure
RestartSec=10s
StartLimitInterval=60s
StartLimitBurst=3

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=prx-waf

# Start
ExecStart=/usr/local/bin/prx-waf -c /etc/prx-waf/config.toml run

# Graceful shutdown (15s timeout, then SIGKILL)
KillMode=mixed
KillSignal=SIGTERM
TimeoutStopSec=15s

[Install]
WantedBy=multi-user.target
```

**Enable and start:**

```bash
sudo systemctl daemon-reload
sudo systemctl enable prx-waf
sudo systemctl start prx-waf
sudo systemctl status prx-waf
```

**Monitor:**

```bash
# Logs
sudo journalctl -u prx-waf -f

# Restart
sudo systemctl restart prx-waf

# Check health
curl http://localhost:16827/health
```

---

## Configuration Reference

### Risk Scorer Backend: Memory vs Redis

**Memory Backend (single-node default)**
```toml
[risk]
enabled = true
store:
  backend = "memory"
```
- Best for: Development, small single-node deployments
- No external dependencies
- Risk state lost on restart
- Suitable for <100 RPS

**Redis Backend (cluster / high-volume)**
```toml
[risk]
enabled = true
store:
  backend = "redis"
  redis:
    url = "redis://localhost:6379"
    key_prefix = "waf:risk:"
    op_timeout_ms = 100
    breaker_threshold = 5
    cache_capacity = 10000
```

**Requirements**
- Redis 6.0+ (Lua scripting + EXPIRE)
- Network connectivity: WAF → Redis
- Recommended: Redis Persistence (RDB/AOF)

**Circuit Breaker & Fail-Open**
- After `breaker_threshold` (default: 5) consecutive failures, circuit opens
- Fallback to in-memory LRU cache (`cache_capacity`, default: 10k entries)
- No request blocking during Redis outage

**Monitoring**
- Log entries for circuit breaker open/close events
- Metrics: `redis_ops_total`, `redis_failures_total`, `redis_cache_hits_total`
- Check Redis: `redis-cli -h <host> -p <port> PING`

---

### Challenge Credit HMAC Secret

Challenge credit tokens protect against replay and sharing attacks. Each token is HMAC-signed and bound to the requesting actor.

**Configuration**

```toml
[risk.challenge]
enabled = true
ttl_secs = 300                  # Token validity (5 minutes)
hmac_secret_path = "/var/lib/waf/challenge-hmac.key"
lru_size = 100000               # In-process nonce cache
header_name = "X-WAF-Cred"      # Request header
valid_delta = -25               # Risk delta: token valid
invalid_delta = +20             # Risk delta: bad signature
replay_delta = +30              # Risk delta: token consumed
expired_delta = +10             # Risk delta: past TTL
```

**Secret Management**

- **Auto-generation**: On first boot, if `hmac_secret_path` doesn't exist, a 32-byte random secret is generated
- **Permissions**: Created with `0600` mode (owner read/write only)
- **Persistence**: Never auto-rotates; persists across restarts
- **Cluster**: All nodes MUST share identical secret for token verification

**Rotation Procedure**

Schedule during low-traffic windows:

1. **Generate new secret**:
   ```bash
   head -c 32 /dev/urandom > /var/lib/waf/challenge-hmac.key.new
   chmod 600 /var/lib/waf/challenge-hmac.key.new
   ```

2. **Drain in-flight tokens**:
   - Wait 5 minutes (token TTL) for expiry
   - Or restart with brief downtime (30s)

3. **Stop WAF**:
   ```bash
   docker compose down  # or systemctl stop prx-waf
   ```

4. **Replace secret**:
   ```bash
   mv /var/lib/waf/challenge-hmac.key.new /var/lib/waf/challenge-hmac.key
   ```

5. **Restart**:
   ```bash
   docker compose up -d  # or systemctl start prx-waf
   ```

**Impact**: All in-flight tokens become invalid. Clients must re-complete challenges to obtain new tokens.

**Token Lifecycle**

```
[Client] → Challenge page → JS-PoW completion → /api/challenge/mint (POST)
                                                       ↓
                                         [Server issues token]
                                         (HMAC-signed payload)
                                                       ↓
[Client] → Subsequent request with X-WAF-Cred header
                                                       ↓
           [WafEngine verifies signature + binding + TTL + nonce]
                                                       ↓
                  Valid: -25 delta (credit)
                  Invalid: +20 delta (bad sig/binding)
                  Replay: +30 delta (nonce consumed)
                  Expired: +10 delta (past TTL)
```

**Nonce Cache**

- **Size**: ~50 bytes per entry → ~5 MB for 100K entries
- **Eviction**: When full, LRU evicts oldest nonce
- **TTL**: Auto-expire after `ttl_secs + grace_period`
- **Per-node**: Cache is node-local; clustering does NOT synchronize nonces

**Risk Deltas (Configurable)**

| Outcome | Default | Description |
|---------|---------|-------------|
| Valid | -25 | Challenge passed; actor earns credit |
| Invalid | +20 | Malformed token, bad HMAC, or binding mismatch |
| Replay | +30 | Token already consumed (nonce in cache) |
| Expired | +10 | Token past TTL |

**Troubleshooting**

- **Tokens failing verification**: Verify HMAC secret identical on all nodes; check file permissions
- **"Nonce already consumed"**: LRU collisions (rare); increase `lru_size` or check token TTL
- **File permission errors**:
  ```bash
  ls -la /var/lib/waf/challenge-hmac.key
  sudo chown prx-waf:prx-waf /var/lib/waf/challenge-hmac.key
  sudo chmod 600 /var/lib/waf/challenge-hmac.key
  ```

---

### Cache Rules (rules/cache.yaml)

Per-route TTL configuration with hot-reload.

**Location**: `rules/cache.yaml` (relative to working directory)

**How it works**:
1. Create `rules/cache.yaml` with route patterns and TTL values
2. Save file → file watcher detects change (≤500ms)
3. New ruleset compiled and hot-swapped (lock-free ArcSwap)
4. No downtime, no deployment required

**Example schema**:
```yaml
version: 1
defaults:
  ttl_seconds: 60
rules:
  - id: "fast-api"
    match:
      path_pattern: "^/api/v1/data"
    ttl_seconds: 10
    tags: ["api", "fast-changing"]
  - id: "static-long"
    match:
      path_pattern: "\\.(css|js|woff2)$"
    ttl_seconds: 86400
    tags: ["static", "immutable"]
  - id: "never-cache"
    match:
      path_pattern: "^/(admin|login)"
    ttl_seconds: 0
    tags: ["sensitive"]
```

**Verdict pipeline**:
- Tier default TTL → Method filter (GET/HEAD/OPTIONS only) → Auth check → Per-route rule match → Upstream Cache-Control → Fallback to tier default

**Stats tracked**:
- `bypassed_authenticated` — Requests bypassed by auth
- `bypassed_explicit_deny` — Requests hitting `ttl_seconds: 0` rules
- `purges_tag` — Entries purged via tag-based API
- `purges_route` — Entries purged via route-id API
- `tag_index_size` — Current tag→key mappings
- Standard cache hit/miss/eviction counters

**Validation**:
```bash
prx-waf rules validate rules/cache.yaml
```

---

### Seed Layer Data Files

IP reputation baseline evaluation — Evaluates Tor exits, datacenter ASN classes, and whitelist.

**File locations**:
- Dev: `configs/seed/`
- Prod: `/etc/prx-waf/seed/`

**File formats**:

| File | Format | Refresh | Purpose |
|------|--------|---------|---------|
| `tor-exits.txt` | Newline-delimited IPs | Hourly via check.torproject.org | Identifies Tor exit nodes |
| `asn-classes.csv` | CSV: `cidr,asn,classification` | Manual (operator updates) | IP blocks tagged datacenter/badlist/normal |
| `risk-whitelist.txt` | Newline-delimited CIDRs | Manual (operator updates) | Bypasses all risk scoring (full Allow) |

**Example schemas**:
```
# tor-exits.txt
198.51.100.45
203.0.113.89
192.0.2.200

# asn-classes.csv
10.0.0.0/8,16509,datacenter
192.168.1.0/24,65001,normal
203.0.113.0/24,65432,badlist

# risk-whitelist.txt
10.20.0.0/16
2001:db8::/32
```

**Hot-reload**: Files watched automatically; changes take effect within 500ms via ArcSwap (lock-free). Syntax errors logged; previous version retained.

---

### Cache Admin API Endpoints

Tag-based purge — Invalidate logical groups of cached entries without flushing entire cache.

All endpoints require admin JWT token + IP allowlist. Request body validated: tag/route_id ≤64 chars, ASCII alnum + `_-:` only.

| Method | Path | Body | Response | Purpose |
|--------|------|------|----------|---------|
| POST | `/api/cache/purge/tag` | `{"tag":"catalog"}` | `{"ok":true,"purged":142,"duration_ms":7}` | Purge entries with this tag |
| POST | `/api/cache/purge/route` | `{"route_id":"static-assets"}` | `{"ok":true,"purged":89,"duration_ms":3}` | Purge entries by rule |
| GET | `/api/cache/stats` | — | `{...,"purges_tag":500,...}` | Cache metrics |

**Example**:
```bash
curl -X POST http://localhost:16827/api/cache/purge/tag \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"tag":"api"}'
```

---

### Main Config (default.toml)

```toml
[proxy]
listen_addr     = "0.0.0.0:80"
listen_addr_tls = "0.0.0.0:443"
worker_threads  = 4

[api]
listen_addr = "127.0.0.1:9527"
admin_ip_allowlist = []

[storage]
database_url    = "postgresql://prx_waf:prx_waf@127.0.0.1:5432/prx_waf"
max_connections = 20

[cache]
enabled          = true
max_size_mb      = 256
default_ttl_secs = 60
max_ttl_secs     = 3600
rules_path       = "rules/cache.yaml"

[http3]
enabled     = false
listen_addr = "0.0.0.0:443"
cert_pem    = "/etc/ssl/certs/server.pem"
key_pem     = "/etc/ssl/private/server.key"

[security]
max_request_body_bytes  = 10485760
api_rate_limit_rps      = 100
cors_origins            = []

[tiered_protection]
default_tier = "catch_all"

[[tiered_protection.classifier_rules]]
priority = 100
tier = "critical"
path = { kind = "exact", value = "/login" }

[rules]
dir            = "rules/"
hot_reload     = true
reload_debounce_ms = 500
enable_builtin_owasp = true
enable_builtin_bot = true
enable_builtin_scanner = true

[[rules.sources]]
name   = "custom"
path   = "rules/custom/"
format = "yaml"

[[rules.sources]]
name            = "owasp-crs"
url             = "https://rules.openprx.dev/owasp-crs.yaml"
format          = "yaml"
update_interval = 86400

[cluster]
enabled     = false
node_id     = ""
role        = "auto"
listen_addr = "0.0.0.0:16851"
seeds       = []

[cluster.crypto]
auto_generate = true
ca_validity_days = 3650
node_validity_days = 365

[crowdsec]
enabled = false
mode = "bouncer"
lapi_url = "http://127.0.0.1:8080"
api_key = ""
update_frequency_secs = 10

[[hosts]]
host = "example.com"
port = 80
remote_host = "127.0.0.1"
remote_port = 8080
ssl = false
```

### Environment Variables

```bash
# Override config values
PRX_WAF_PROXY__LISTEN_ADDR=0.0.0.0:80
PRX_WAF_STORAGE__DATABASE_URL=postgresql://...
PRX_WAF_STORAGE__MAX_CONNECTIONS=20
PRX_WAF_API__ADMIN_IP_ALLOWLIST=10.0.0.0/8,192.168.0.0/16
```

---

## TLS Certificate Management

### Native TLS Listener (file-based certs)

Bind the WAF directly on `proxy.listen_addr_tls` (default `0.0.0.0:443`) by
declaring at least one `[[hosts]]` entry with `tls_terminate = true` and
on-disk `cert_file` / `key_file` paths:

```toml
[proxy]
listen_addr     = "0.0.0.0:80"
listen_addr_tls = "0.0.0.0:443"

[[hosts]]
host          = "example.com"
port          = 443
remote_host   = "127.0.0.1"
remote_port   = 8080
ssl           = false  # upstream is plaintext (HTTP) — the WAF terminates TLS
tls_terminate = true   # bind this cert on the WAF's port 443
cert_file     = "/etc/mini-waf/certs/example.com/fullchain.pem"
key_file      = "/etc/mini-waf/certs/example.com/privkey.pem"
```

`tls_terminate` (listener bind) and `ssl` (upstream uses TLS) are independent
knobs. The matrix:

| `tls_terminate` | `ssl` | Effect |
|---|---|---|
| `true`  | `false` | WAF terminates HTTPS for clients, forwards plaintext to upstream (most common) |
| `true`  | `true`  | WAF terminates client TLS, re-encrypts to an HTTPS upstream |
| `false` | `true`  | No WAF listener bind; passthrough to upstream over HTTPS via a different terminator |
| `false` | `false` | Plaintext end-to-end (legacy / behind an external TLS proxy) |

Behavior:

- Listener is opt-in. With no `tls_terminate = true` host, port 443 stays closed
  and the proxy keeps serving plaintext only (legacy behaviour preserved).
- Each `tls_terminate = true` host is validated independently at startup:
  - `cert_file` / `key_file` paths must exist on disk.
  - PEM content is parsed before being handed to Pingora (catches mismatched
    keypairs, corrupted PEM, or non-PEM files without panicking the proxy).
  - Any host that fails one of these checks is logged at ERROR level and
    skipped. Other valid TLS-terminating hosts still bind.
- If every `tls_terminate = true` host fails validation, the listener is not
  bound and the proxy keeps serving plaintext only.
- The **leaf certificate must appear first** in `fullchain.pem` (before any
  intermediates). The validator detects the reversed order and surfaces an
  actionable error rather than silently failing the TLS handshake.
- ALPN advertises `h2,http/1.1`; HTTP/2 over TLS is enabled automatically.

### Multi-domain (SNI) deployments

The current rustls-backed listener uses a single `with_single_cert`
`ServerConfig`. To serve multiple hostnames on the same port 443, use a
**SAN certificate** that includes every served hostname (issue one Let's
Encrypt cert with `-d a.example.com -d b.example.com …`). The first
`[[hosts]]` entry with valid cert/key wins; additional `tls_terminate = true`
hosts log a warning at boot. Per-host distinct certs via a custom SNI resolver
are planned in a follow-up.

### Let's Encrypt (Automatic — DB-backed, in development)

```toml
[[hosts]]
host = "example.com"
ssl = true
acme_enabled = true
acme_email = "admin@example.com"
```

The ACME issuance pipeline (`SslManager` in `crates/gateway/src/ssl.rs`) issues
certificates, stores PEM in PostgreSQL, and exposes an auto-renewal task. It
is wired for the management API but does **not** yet feed certificates back
into the runtime TLS listener — operators currently provision certs to the
filesystem and point `cert_file` / `key_file` at them.

### Manual Certificate

```bash
# Generate self-signed (for testing)
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365

# Upload via API
curl -X POST http://localhost:16827/api/certificates \
  -H "Authorization: Bearer $TOKEN" \
  -F "certificate=@cert.pem" \
  -F "private_key=@key.pem" \
  -F "host=example.com"
```

---

## Health Checks

### Liveness Probe

```bash
curl -f http://localhost:16827/health || exit 1
```

**Response**: `200 OK` (alive) or `503 Service Unavailable` (dead)

### Kubernetes Probes

```yaml
livenessProbe:
  httpGet:
    path: /health
    port: 16827
  initialDelaySeconds: 10
  periodSeconds: 5

readinessProbe:
  httpGet:
    path: /api/status
    port: 16827
  initialDelaySeconds: 5
  periodSeconds: 3
```

---

## Monitoring & Logging

### Structured Logs

```json
{
  "timestamp": "2026-04-17T10:30:45.123Z",
  "level": "INFO",
  "target": "prx_waf::server",
  "message": "Rule reloaded",
  "rule_id": "CRS-941100",
  "version": 42
}
```

### Log Levels

```bash
# Control verbosity
RUST_LOG=debug prx-waf run
RUST_LOG=prx_waf=info,gateway=debug prx-waf run
```

### Metrics Export

Coming in v0.3.0: Prometheus metrics endpoint (`/metrics`).

---

## Backup & Recovery

### PostgreSQL Backup

```bash
# Full backup
pg_dump prx_waf > backup.sql

# Compressed backup
pg_dump prx_waf | gzip > backup.sql.gz

# Schedule daily (cron)
0 2 * * * pg_dump prx_waf | gzip > /backups/prx_waf-$(date +\%Y\%m\%d).sql.gz

# Keep last 30 days
find /backups -name "prx_waf-*.sql.gz" -mtime +30 -delete
```

### Recovery

```bash
# Restore
psql prx_waf < backup.sql

# Or from compressed
gunzip -c backup.sql.gz | psql prx_waf
```

---

## Upgrade Procedure

### Minor Version (0.2.x → 0.2.y)

No database migrations needed:

```bash
# Docker
docker compose pull
docker compose up -d

# Systemd
sudo systemctl stop prx-waf
sudo cp target/release/prx-waf /usr/local/bin/prx-waf
sudo systemctl start prx-waf
```

### Major Version (0.2.x → 0.3.0)

Check [CHANGELOG](../CHANGELOG.md) for breaking changes:

```bash
# Backup database
pg_dump prx_waf | gzip > backup-0.2.0.sql.gz

# Run migrations
prx-waf -c config.toml migrate

# Restart with new binary
prx-waf -c config.toml run
```

---

## Troubleshooting

| Issue | Solution |
|-------|----------|
| Port in use | `lsof -i :16880` → `kill -9 <PID>` or change `listen_addr` |
| DB connection failed | Check `DATABASE_URL` env var, verify PostgreSQL running |
| High memory | Check `curl localhost:16827/api/cache/stats`, reduce `max_size_mb` |
| Rules not reloading | `prx-waf rules validate <file>`, check `hot_reload = true` |
| Cache rules stuck | `touch rules/cache.yaml` to trigger watcher |

**Manual reload**: `curl -X POST localhost:16827/api/reload -H "Authorization: Bearer $TOKEN"`

---

## Performance Tuning

```toml
[storage]
max_connections = 50  # Increase for high concurrency

[proxy]
worker_threads = 8    # Match CPU core count

[cache]
max_size_mb = 512
default_ttl_secs = 300
```

See [System Architecture](./system-architecture.md) for performance baselines.

---

## See Also

- [Cluster Guide](./cluster-guide.md) — Multi-node setup, certificate generation, cluster operations
- [System Architecture](./system-architecture.md) — Performance baselines
- [Custom Rules](./custom-rules-syntax.md) — Rule syntax
