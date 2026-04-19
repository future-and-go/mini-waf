# Deployment Guide

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

## 3-Node Cluster (High Availability)

### Prerequisites

- Docker Compose v1.3+
- 12GB RAM (4GB per node), 6 CPU cores
- Ports 80, 443 (public); 16851 (cluster, internal only)

### Certificate Generation

```bash
docker compose -f docker-compose.cluster.yml run --rm cluster-init
```

Output:
```
Generated cluster certificates:
  CA:     /certs/cluster-ca.pem (keep secure)
  Node A: /certs/node-a.pem + node-a.key
  Node B: /certs/node-b.pem + node-b.key
  Node C: /certs/node-c.pem + node-c.key
```

Certificates stored in Docker volume `cluster_certs` (persisted).

### Start Cluster

```bash
docker compose -f docker-compose.cluster.yml up -d

# Wait for node-a to become main
sleep 10

# Verify all nodes healthy
curl http://localhost:16827/health  # node-a
curl http://localhost:16828/health  # node-b
curl http://localhost:16829/health  # node-c

# Check cluster topology
curl http://localhost:16827/api/cluster/status | jq .
```

### Configuration Files

**node-a.toml** (main)
```toml
[cluster]
enabled = true
node_id = "node-a"
role = "main"
listen_addr = "0.0.0.0:16851"
seeds = []  # First node has no seeds

[storage]
database_url = "postgresql://prx_waf:changeme123@postgres:5432/prx_waf"
```

**node-b.toml** (worker)
```toml
[cluster]
enabled = true
node_id = "node-b"
role = "worker"
listen_addr = "0.0.0.0:16851"
seeds = ["node-a:16851"]  # Point to main

[storage]
database_url = ""  # Empty: forward-only mode (writes go to main)
```

**node-c.toml** (worker) — same as node-b, different node_id

### Cluster Operations

**Check topology:**
```bash
curl -s http://localhost:16827/api/cluster/status | jq .

# Output:
# {
#   "main_node_id": "node-a",
#   "nodes": [
#     { "id": "node-a", "role": "main", "status": "healthy" },
#     { "id": "node-b", "role": "worker", "status": "healthy" },
#     { "id": "node-c", "role": "worker", "status": "healthy" }
#   ],
#   "term": 1,
#   "rules_version": 42
# }
```

**Add a rule on main:**
```bash
curl -X POST http://localhost:16827/api/custom-rules \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Block /admin",
    "pattern": "^/admin",
    "action": "block"
  }'

# Workers sync within 10s
sleep 10

# Verify worker has rule
curl http://localhost:16828/api/custom-rules
```

**Kill main, verify failover:**
```bash
docker compose -f docker-compose.cluster.yml stop node-a

# Wait <500ms for election
sleep 1

# Check new main
curl http://localhost:16827/api/cluster/status

# Output shows node-b or node-c as main
```

**Rejoin killed node:**
```bash
docker compose -f docker-compose.cluster.yml start node-a

# node-a rejoins as worker (won't try to be main again)
# Full rule sync happens
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

### Main Config (default.toml)

```toml
[proxy]
listen_addr     = "0.0.0.0:80"        # HTTP
listen_addr_tls = "0.0.0.0:443"       # HTTPS
worker_threads  = 4                    # CPU-bound threads (default: CPU count)

[api]
listen_addr = "127.0.0.1:9527"        # Management API
admin_ip_allowlist = []                # Empty = allow all (set in prod)

[storage]
database_url    = "postgresql://prx_waf:prx_waf@127.0.0.1:5432/prx_waf"
max_connections = 20                   # Connection pool size

[cache]
enabled          = true
max_size_mb      = 256
default_ttl_secs = 60
max_ttl_secs     = 3600

[http3]
enabled     = false                    # HTTP/3 (QUIC)
listen_addr = "0.0.0.0:443"
cert_pem    = "/etc/ssl/certs/server.pem"
key_pem     = "/etc/ssl/private/server.key"

[security]
max_request_body_bytes  = 10485760     # 10 MB
api_rate_limit_rps      = 100          # Per IP
cors_origins            = []

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
update_interval = 86400  # 24h

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

[cluster.sync]
rules_interval_secs = 10
config_interval_secs = 30
events_batch_size = 100

[cluster.election]
timeout_min_ms = 150
timeout_max_ms = 300
heartbeat_interval_ms = 50

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
PRX_WAF_CLUSTER__ENABLED=true
PRX_WAF_CLUSTER__NODE_ID=node-a
PRX_WAF_CLUSTER__ROLE=main
```

---

## TLS Certificate Management

### Let's Encrypt (Automatic)

```toml
# In host config:
[[hosts]]
host = "example.com"
ssl = true
acme_enabled = true
acme_email = "admin@example.com"
# Certificate auto-renewed 30 days before expiry
```

Certificates stored in PostgreSQL `certificates` table.

### Manual Certificate

```bash
# Generate self-signed (for testing)
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365

# Upload via Admin UI or API
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

**Response:** `200 OK` (alive) or `503 Service Unavailable` (dead)

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

### Structured Logs (stdout/stderr)

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
# Control verbosity via RUST_LOG
RUST_LOG=debug prx-waf run
RUST_LOG=prx_waf=info,gateway=debug prx-waf run
```

### Metrics Export (Future)

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

### Cluster CA Key Backup

```bash
# Export encrypted CA key from database
curl -s http://localhost:16827/api/cluster/ca-backup \
  -H "Authorization: Bearer $TOKEN" \
  > cluster-ca-backup.enc

# Store securely (S3, vault, etc.)
# Passphrase stored in secure location (not in backup)
```

---

## Upgrade Procedure

### Minor Version (0.2.x → 0.2.y)

No database migrations needed. Just restart:

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

Check [CHANGELOG](../CHANGELOG.md) for breaking changes.

```bash
# Backup database
pg_dump prx_waf | gzip > backup-0.2.0.sql.gz

# Run migrations
prx-waf -c config.toml migrate

# Restart with new binary
prx-waf -c config.toml run
```

### Rolling Update (Cluster)

For zero-downtime upgrades:

1. Stop worker node-b
2. Deploy new binary to node-b
3. Start node-b (syncs from node-a)
4. Repeat for node-c
5. Finally: stop node-a, upgrade, restart

Clients load-balance across nodes; no traffic loss.

---

## Troubleshooting

### Port Already in Use

```bash
# Check what's using port 16880
lsof -i :16880

# Kill if needed
kill -9 <PID>

# Or change port in config
[proxy]
listen_addr = "0.0.0.0:8080"
```

### Database Connection Failed

```bash
# Verify database is running
psql postgresql://prx_waf:prx_waf@localhost:5432/prx_waf

# Check DATABASE_URL env var
echo $DATABASE_URL

# Connection string format:
# postgresql://user:password@host:port/database
```

### Cluster Node Not Joining

```bash
# Check logs
journalctl -u prx-waf -n 100 | grep cluster

# Verify network connectivity
nc -zv node-a.example.com 16851

# Check QUIC port is open
netstat -tlnp | grep 16851
```

### High Memory Usage

```bash
# Check cache size
curl http://localhost:16827/api/cache/stats | jq .

# Reduce cache size in config
[cache]
max_size_mb = 128  # Reduce from 256

# Restart
systemctl restart prx-waf
```

### Rules Not Reloading

```bash
# Check if hot-reload is enabled
grep hot_reload config.toml

# Manually reload
curl -X POST http://localhost:16827/api/reload \
  -H "Authorization: Bearer $TOKEN"

# Check rule validation
prx-waf rules validate rules/custom.yaml
```

---

## Performance Tuning

### Database Connection Pool

```toml
[storage]
max_connections = 50  # Increase for high concurrency
```

### Worker Threads

```toml
[proxy]
worker_threads = 8  # Match CPU core count
```

### Cache Size

```toml
[cache]
max_size_mb = 512   # Increase for static-heavy workloads
default_ttl_secs = 300  # Longer TTL
```

### Cluster Sync Intervals

```toml
[cluster.sync]
rules_interval_secs = 5  # More frequent
events_batch_size = 500  # Larger batches
```

See [System Architecture](./system-architecture.md) for performance baselines.
