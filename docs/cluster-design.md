# PRX-WAF Cluster Design Document

**Author:** David (AI CEO)
**Date:** 2026-03-16
**Status:** Finalized (v0.1.0-rc.1 and v0.2.0)
**Version:** 2.0

**Related:** See also [`./cluster-protocol.md`](./cluster-protocol.md) for QUIC protocol specification, wire format, election algorithm, rule sync, and implementation phases.

---

## 1. Executive Summary

Add clustering capability to prx-waf so that multiple WAF instances form a self-organizing mesh network. Each node can serve as either **main** (control plane) or **worker** (data plane), with one elected main per cluster. All inter-node communication runs over **QUIC** (TLS 1.3 built-in encryption), eliminating the need for an external VPN layer.

### Goals

- **Horizontal scaling** — distribute traffic across N nodes
- **High availability** — automatic failover when main goes down
- **Zero-trust networking** — mTLS between all nodes, encrypted by default
- **Centralized management** — single Admin UI manages entire cluster
- **Decentralized processing** — each node independently processes traffic

### Non-Goals (v1)

- Cross-datacenter / multi-region clustering (future)
- Automatic traffic load balancing between nodes (each node handles its own traffic)
- Shared session state / sticky sessions across nodes

---

## 2. Architecture Overview

```
                         QUIC Mesh (TLS 1.3 encrypted)
                    ┌─────────────────────────────────────┐
                    │                                     │
   ┌────────────┐   │   ┌────────────┐   ┌────────────┐   │
   │  Node A    │◄──┼──►│  Node B    │◄──┤  Node C    │   │
   │  (main)    │   │   │  (worker)  │   │  (worker)  │   │
   │            │◄──┼───┼────────────┼───┤            │   │
   └────────────┘   │   └────────────┘   └────────────┘   │
                    │                                     │
                    └─────────────────────────────────────┘

Data flows:
  main → workers:  rules, config, certificate updates
  workers → main:  attack logs, stats, health reports
  bidirectional:   heartbeat, election, control messages
```

### 2.1 Node Roles

| Role | Responsibilities | Database | API Mode |
|------|-----------------|----------|----------|
| **Main** | Rule authoring, config authority, certificate CA, log aggregation, stats dashboard | PostgreSQL (primary) | Read-Write |
| **Worker** | Traffic processing, in-memory rule cache, attack detection, log forwarding | None required (cache-only) | Read-Only (writes forwarded to main) |
| **Candidate** | Transitional state during election | Depends on previous role | Read-Only |

### 2.2 Role Assignment

Three modes (configured via `cluster.role`):

1. **`main`** — Always runs as main. Fails if another main exists.
2. **`worker`** — Always runs as worker. Requires a reachable main.
3. **`auto`** (default) — Participates in election. First node becomes main; subsequent nodes become workers. If main dies, remaining nodes elect a new main.

---

## 3. Codebase Audit Findings

> **This section documents the actual state of the codebase as of 2026-03-16 and corrects
> assumptions made in the original v1.0 design draft. Read carefully before implementing.**

### 3.1 Actual Crate Structure

```
crates/
├── prx-waf/        # Binary entry point — sync fn main, NOT async
├── gateway/        # Pingora reverse proxy + HTTP/3 listener (already uses quinn/rustls)
├── waf-engine/     # WAF rule matching, detection pipeline, RuleRegistry
├── waf-storage/    # PostgreSQL access via sqlx PgPool ONLY (no SQLite)
├── waf-api/        # Axum REST API + Admin UI static file serving
└── waf-common/     # Shared types: RequestCtx, HostConfig, AppConfig, crypto
```

### 3.2 QUIC/TLS Dependencies Already Present — Not New

The original draft treated quinn, rustls, and rcgen as new dependencies. **They already
exist** in workspace.dependencies as Phase 5 additions:

```toml
# Already in workspace Cargo.toml
quinn          = { version = "0.11", features = ["rustls"] }
rustls         = { version = "0.23", features = ["ring"] }
rcgen          = "0.13"
h3             = "0.0.8"
h3-quinn       = "0.0.10"
rustls-pemfile = "2"
```

The `gateway` crate already uses `quinn` + `rustls` + `h3` for HTTP/3 serving
(`crates/gateway/src/http3.rs`). This file is a complete working reference for:

- Building `rustls::ServerConfig` from PEM files
- Wrapping it in `quinn::crypto::rustls::QuicServerConfig`
- Creating `quinn::Endpoint` servers
- Handling async QUIC connection streams with `tokio::spawn`

The `waf-cluster` transport layer can adopt these patterns directly with minimal rework.

### 3.3 Pingora Uses OpenSSL, Not rustls

**Correction from v1.0 draft:** The claim "rustls is already a Pingora dependency" is
incorrect.

Inspecting `Cargo.lock`: `pingora-core` depends on `openssl-probe`, confirming Pingora
0.8 uses **OpenSSL** for its proxy TLS. The `rustls` crate is present in the workspace
independently for the HTTP/3 feature — the two TLS stacks coexist without conflict, as
proven by the existing build. Do not assume rustls comes from Pingora.

### 3.4 waf-storage: PostgreSQL Only — No SQLite

`waf-storage/Cargo.toml` uses sqlx with only the `postgres` feature:

```toml
# workspace Cargo.toml
sqlx = { version = "0.8", features = ["postgres", "runtime-tokio", "macros", "migrate", "chrono", "uuid"] }
```

The `Database` struct wraps `sqlx::PgPool` exclusively:

```rust
// crates/waf-storage/src/db.rs
pub struct Database {
    pub pool: PgPool,
    event_tx: broadcast::Sender<serde_json::Value>,
}
```

The original design proposed SQLite as a worker-side rule cache. This would require
adding `sqlite` to sqlx features and significant conditional compilation across
waf-storage. The **simpler and correct approach**:

- Workers maintain an **in-memory `RuleRegistry`** populated via cluster sync
- No SQLite needed — rules already live in-memory via `Arc<RwLock<RuleRegistry>>`
- Workers connect to PostgreSQL only if explicitly configured (for local log writes)
- Workers without a DB forward all write operations to main via the Forward stream

### 3.5 Rules Are File-Based — Not Pure DB-Based

Rules have two sources in the current system:

1. **File-based** (YAML/JSON/ModSec in `rules/` directory) — loaded by `RuleManager`,
   compiled into an in-memory `RuleRegistry` with `version: u64`
2. **Database custom rules** — stored in PostgreSQL, loaded by `WafEngine`

The `Rule` struct (`crates/waf-engine/src/rules/registry.rs`) already derives
`Serialize + Deserialize`, making it trivially wire-serializable without protobuf.
`RuleRegistry.version: u64` is the natural sync version tracker — it already increments
on every `insert()` or `remove()`.

### 3.6 Runtime Model: sync main() with Separate Thread-per-Runtime

The actual startup flow (`crates/prx-waf/src/main.rs`):

```rust
fn main() -> anyhow::Result<()> {   // sync, NOT async
    let config = load_config()?;
    run_server(config)?;
}

fn run_server(config: AppConfig) -> anyhow::Result<()> {
    // One shared init runtime
    let rt = tokio::runtime::Builder::new_multi_thread()...build()?;
    let (engine, router, api_state) = rt.block_on(init_async(&config))?;

    // API server: own thread + own runtime
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_multi_thread()...build()?;
        rt.block_on(start_api_server(...));
    });

    // HTTP/3 server: own thread + own runtime
    if config.http3.enabled {
        std::thread::spawn(move || {
            let rt = ...;
            rt.block_on(gateway::http3::start_http3_server(...));
        });
    }

    // Pingora blocks the main thread forever
    server.run_forever();
}
```

**Impact on cluster design:** The cluster node cannot be started with `cluster.start().await`
in the main async context because Pingora takes over the main thread. The cluster QUIC
listener **must** follow the same `std::thread::spawn` + own-runtime pattern used by the
API and HTTP/3 servers.

### 3.7 WafEngine Component Architecture

```rust
// crates/waf-engine/src/engine.rs
pub struct WafEngine {
    pub store: Arc<RuleStore>,
    pub custom_rules: Arc<CustomRulesEngine>,
    crowdsec_checker: OnceLock<Arc<CrowdSecChecker>>,
    appsec_client: OnceLock<Arc<AppSecClient>>,
    geoip: OnceLock<Arc<GeoIpService>>,
    // ...
}
// Rule reload: engine.reload_rules().await?
```

The `OnceLock` pattern for optional components is the established precedent. The cluster
integration follows the same pattern.

### 3.8 CrowdSec on Workers

Workers run their own CrowdSec bouncer integration, each contacting its own CrowdSec LAPI
independently. No cluster-level CrowdSec sync is needed.

### 3.9 WASM Plugin Gap

`WafEngine` loads WASM plugins from PostgreSQL via `db.list_wasm_plugins()`. Workers
cannot receive WASM binaries without dedicated binary sync. **v1 decision:** Workers
operate without WASM plugins. Explicitly documented as a v1 limitation.

### 3.10 Dependency Gap Analysis

| Dependency | Status | Notes |
|-----------|--------|-------|
| `quinn = "0.11"` | ✅ Already in workspace | Used in gateway (HTTP/3) |
| `rustls = "0.23"` | ✅ Already in workspace | Used in gateway (HTTP/3) |
| `rcgen = "0.13"` | ✅ Already in workspace | Used in gateway (ACME TLS) |
| `rustls-pemfile = "2"` | ✅ Already in workspace | Used in gateway |
| `serde_json` | ✅ Already in workspace | All cluster types use it |
| `aes-gcm` | ✅ Already in waf-common | Reuse for CA key encryption |
| `prost = "0.13"` | ❌ Not present | Avoided — use serde_json instead |
| `prost-build = "0.13"` | ❌ Not present | Avoided — no protobuf |
| `lz4_flex = "0.11"` | ❌ Not present | **Only genuinely new dep** |
| SQLite sqlx feature | ❌ Not present | Not needed — in-memory cache |

**Recommendation: Drop protobuf.** Use `serde_json` for wire encoding. All `Rule` and
cluster message types already implement `Serialize + Deserialize`. JSON is adequate at
cluster-internal LAN rates and eliminates a build.rs compilation step, prost-build, and
proto file maintenance.

---

## 4. Technology Stack

### 4.1 Transport Components

| Component | Choice | Status | Rationale |
|-----------|--------|--------|-----------|
| QUIC transport | **quinn** v0.11 | ✅ In workspace | Already proven in gateway/http3.rs |
| TLS backend | **rustls** v0.23 | ✅ In workspace | Coexists with Pingora's OpenSSL |
| Certificate generation | **rcgen** v0.13 | ✅ In workspace | Used in gateway for ACME |
| Serialization | **serde_json** | ✅ In workspace | Rule/message types already serializable |
| Compression | **lz4_flex** v0.11 | ❌ New dep | Full snapshot compression only |
| CA key encryption | **aes-gcm** v0.10 | ✅ In waf-common | Reuse existing crypto.rs |

### 4.2 Why QUIC Over Alternatives

| Feature | QUIC | WireGuard | Plain TCP+TLS | gRPC |
|---------|------|-----------|---------------|------|
| Built-in encryption | TLS 1.3 ✅ | Noise ✅ | TLS 1.3 ✅ | TLS 1.3 ✅ |
| Multiplexed streams | Native ✅ | No ❌ | No ❌ | HTTP/2 ✅ |
| 0-RTT reconnection | Yes ✅ | Yes ✅ | No ❌ | No ❌ |
| NAT traversal | UDP ✅ | UDP ✅ | TCP ❌ | TCP ❌ |
| Already in codebase | Yes ✅ | No ❌ | Partial | No ❌ |
| Extra dependencies | None ✅ | kernel/boringtun | tokio-tls | tonic+hyper |

---

## 5. Cryptography & Security

### 5.1 Certificate Hierarchy

```
Root CA (generated by first main node via rcgen — already in workspace)
├── Main Node Certificate (signed by CA)
├── Worker Node Certificate A (signed by CA)
└── Worker Node Certificate B (signed by CA)
```

### 5.2 Certificate Lifecycle

| Event | Action |
|-------|--------|
| **First main startup** | Generate CA keypair (Ed25519) + self-signed cert (10yr). Generate node cert signed by CA (1yr). Encrypt CA key with AES-GCM using cluster passphrase. |
| **Worker join** | Worker generates keypair + CSR via rcgen. Sends CSR to main. Main signs and returns node cert + CA cert. |
| **Certificate renewal** | Main auto-renews node certs 7 days before expiry. Pushes new cert via control stream. |
| **Node removal** | Add cert serial to CRL. Broadcast CRL to all nodes. Revoked node disconnected. |
| **Main failover** | New main inherits CA key from cluster state (encrypted, replicated at join time). |

Note: `aes-gcm` is already a `waf-common` dependency, used in the existing `crypto.rs`.
CA key encryption reuses those helpers directly.

### 5.3 Join Token Flow

```
1. Admin generates join token on main:
   $ prx-waf cluster token generate --ttl 1h
   → abc123-def456-ghi789  (HMAC-SHA256 signed, includes expiry)

2. Worker starts with token:
   $ prx-waf run --cluster-join main.example.com:16851 --token abc123-def456-ghi789

3. Worker connects to main via QUIC (server-only TLS initially — no client cert yet)
4. Worker sends: JoinRequest { token, csr_pem, node_info }
5. Main validates token + signs CSR → JoinResponse { node_cert_pem, ca_cert_pem, cluster_state }
6. Worker reconnects with mTLS (both sides verified by CA)
7. Main broadcasts: NodeJoined to all peers
```

---

## 7. Migration Path

### 7.1 Standalone → Cluster (Zero Breaking Changes)

`ClusterConfig::default()` has `enabled: false`. All existing deployments continue
working without any configuration change. Cluster is strictly opt-in.

### 7.2 Upgrade Path for Existing Deployments

1. Deploy cluster-capable binary to **all** nodes simultaneously (or rolling, but keep
   `cluster.enabled = false` until all nodes are upgraded)
2. On the designated main: add `[cluster] enabled = true; role = "main"`, restart
3. Generate join token: `prx-waf cluster token generate --ttl 24h`
4. On each worker: add `[cluster] enabled = true; seeds = ["<main>:16851"]`, set token, restart
5. Workers auto-sync rules from main within `sync.rules_interval_secs`
6. Verify all nodes healthy via Admin UI cluster dashboard

---

## 8. Risk Assessment

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| Split-brain (two mains) | Low | High | Fencing tokens + quorum requirement (N/2+1) |
| CA key loss on main failure | Low | Critical | CA key replicated (encrypted) to workers at join |
| QUIC on lossy WAN | Medium | Medium | Retry with exponential backoff + full sync fallback |
| Election storm (rapid role changes) | Low | Medium | Exponential backoff + term dampening |
| Worker rule cache stale after long partition | Medium | Medium | Force full sync on rejoin + version assertion |
| Pingora + cluster thread interference | None | None | Separate threads/runtimes — no shared state |
| prost build system complexity | N/A | N/A | Avoided entirely by using serde_json |
| SQLite complexity in waf-storage | N/A | N/A | Avoided entirely by using in-memory cache |
| WASM plugins missing on workers | Certain (v1) | Low | Documented limitation; add in v2 |

---

## 9. Future Considerations (Post v1)

- **mDNS auto-discovery:** LAN peer discovery without static seed configuration
- **WASM plugin sync:** Binary blob distribution to workers via cluster stream
- **Multi-region:** Cross-datacenter clustering with region-aware routing
- **Distributed rate limiting:** Shared CC counters across cluster nodes
- **Traffic load balancing:** Anycast + cluster-level request distribution
- **Observability:** Distributed tracing across cluster nodes (OpenTelemetry)

---

## Appendix A: Crate Structure

### A.1 New Crate: `waf-cluster`

```
crates/waf-cluster/
├── Cargo.toml
├── src/
│   ├── lib.rs              # pub use ClusterNode, ClusterConfig, NodeRole
│   ├── node.rs             # NodeState, NodeRole enum, role state machine
│   ├── transport/
│   │   ├── mod.rs          # QUIC connection manager
│   │   ├── server.rs       # QUIC mTLS listener (reuses gateway/http3.rs patterns)
│   │   ├── client.rs       # QUIC dialer (connect to peer)
│   │   └── frame.rs        # Length-prefixed JSON codec for quinn streams
│   ├── crypto/
│   │   ├── mod.rs
│   │   ├── ca.rs           # CA generation via rcgen (already in workspace)
│   │   ├── node_cert.rs    # Node cert signing + CSR validation
│   │   └── store.rs        # AES-GCM key storage (reuse waf-common::crypto)
│   ├── discovery/
│   │   └── static_seeds.rs # Static peer list from ClusterConfig.seeds (mDNS deferred)
│   ├── sync/
│   │   ├── mod.rs
│   │   ├── rules.rs        # Rule sync using RuleRegistry.version + serde_json + lz4
│   │   ├── config.rs       # Config sync (TOML string)
│   │   └── events.rs       # Attack log batching + forwarding to main
│   ├── election/
│   │   ├── mod.rs          # Raft-lite leader election (term, vote, timeout)
│   │   └── state.rs        # Election state machine
│   ├── health/
│   │   ├── mod.rs          # Heartbeat sender/receiver
│   │   └── detector.rs     # Phi-accrual failure detector
│   └── protocol/
│       └── messages.rs     # All ClusterMessage types (serde_json, no protobuf)
│
└── tests/
    ├── integration.rs      # 2-node QUIC connect + heartbeat
    ├── election_test.rs    # State machine edge cases
    └── sync_test.rs        # Rule version diff + full snapshot
```

### A.2 Dependency Graph (Corrected)

```
prx-waf (binary)
├── gateway        (Pingora proxy + HTTP/3; quinn/rustls/rcgen already here)
├── waf-engine     (rule matching; RuleRegistry is the sync unit)
├── waf-storage    (PostgreSQL; main only — workers optional)
├── waf-api        (Axum REST + Admin UI)
├── waf-common     (AppConfig extended with ClusterConfig)
└── waf-cluster    (NEW)
    ├── quinn          ✅ already workspace dep
    ├── rustls         ✅ already workspace dep
    ├── rcgen          ✅ already workspace dep
    ├── rustls-pemfile ✅ already workspace dep
    ├── serde_json     ✅ already workspace dep
    ├── aes-gcm        ✅ already waf-common dep
    ├── lz4_flex       ❌ ONLY GENUINELY NEW DEP
    └── waf-common     ✅
```

### A.3 Cargo.toml for waf-cluster

```toml
[package]
name = "waf-cluster"
version.workspace = true
edition.workspace = true
license.workspace = true

[dependencies]
waf-common  = { path = "../waf-common" }
waf-engine  = { path = "../waf-engine" }
waf-storage = { path = "../waf-storage" }

quinn          = { workspace = true }
rustls         = { workspace = true }
rcgen          = { workspace = true }
rustls-pemfile = { workspace = true }
tokio          = { workspace = true }
serde          = { workspace = true }
serde_json     = { workspace = true }
tracing        = { workspace = true }
anyhow         = { workspace = true }
thiserror      = { workspace = true }
rand           = { workspace = true }
aes-gcm        = { workspace = true }
bytes          = { workspace = true }
dashmap        = { workspace = true }

lz4_flex = "0.11"   # Only new dep — used for full rule snapshot compression
```

Add to workspace root `Cargo.toml`:
```toml
# [workspace.dependencies]
lz4_flex = "0.11"

# [workspace] members
"crates/waf-cluster",
```

### A.4 Changes to Existing Crates

#### waf-common — Minimal (no breaking changes)

```rust
// crates/waf-common/src/config.rs — add field with Default
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    pub proxy: ProxyConfig,
    pub api: ApiConfig,
    pub storage: StorageConfig,
    // ... all existing fields unchanged ...
    #[serde(default)]
    pub cluster: ClusterConfig,   // NEW — default is disabled, zero behavior change
}

// New types in waf-common:
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusterConfig {
    #[serde(default)]
    pub enabled: bool,          // false by default
    #[serde(default)]
    pub node_id: String,        // auto-generated from hostname if empty
    #[serde(default = "default_role")]
    pub role: String,           // "auto" | "main" | "worker"
    #[serde(default = "default_cluster_addr")]
    pub listen_addr: String,
    #[serde(default)]
    pub seeds: Vec<String>,
    #[serde(default)]
    pub crypto: ClusterCryptoConfig,
    #[serde(default)]
    pub sync: ClusterSyncConfig,
    #[serde(default)]
    pub election: ClusterElectionConfig,
}

impl Default for ClusterConfig {
    fn default() -> Self { Self { enabled: false, /* all other defaults */ } }
}
```

```rust
// crates/waf-common/src/lib.rs
pub use config::ClusterConfig;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NodeRole { Main, Worker, Candidate }

pub struct NodeId(pub String);
impl NodeId {
    pub fn from_hostname() -> Self {
        let host = hostname::get()
            .ok()
            .and_then(|h| h.into_string().ok())
            .unwrap_or_else(|| "unknown".to_string());
        Self(format!("{}-{}", host, &uuid::Uuid::new_v4().to_string()[..8]))
    }
}
```

#### waf-engine — Minimal

```rust
// Add to crates/waf-engine/src/lib.rs
#[async_trait::async_trait]
pub trait RuleReloader: Send + Sync {
    async fn on_rules_updated(&self, version: u64) -> anyhow::Result<()>;
}

// WafEngine gets a trivial impl — no structural change needed
#[async_trait::async_trait]
impl RuleReloader for WafEngine {
    async fn on_rules_updated(&self, _version: u64) -> anyhow::Result<()> {
        self.reload_rules().await
    }
}
// RuleRegistry is already pub — cluster reads .version and .rules directly
```

#### waf-storage — None Required

The `Database` struct is PostgreSQL-only and stays that way. Workers that have no
database configured operate in **forward-only mode** — a lightweight enum in waf-cluster:

```rust
// crates/waf-cluster/src/node.rs — cluster-internal only, not in waf-storage
pub enum StorageMode {
    Full(Arc<waf_storage::Database>),   // main node (or worker with local DB)
    ForwardOnly,                         // worker with no DB — forwards writes to main
}
```

No changes to waf-storage's public API or types.

#### waf-api — Medium

```rust
// New file: crates/waf-api/src/cluster.rs
// Endpoints only active when cluster.enabled = true

// GET  /api/cluster/status
// GET  /api/cluster/nodes
// GET  /api/cluster/nodes/:id
// POST /api/cluster/token         (admin only — generate join token)
// POST /api/cluster/nodes/remove  (admin only)

// Worker API behavior:
// - Read endpoints: served from local in-memory cache
// - Write endpoints: forward via ClusterNode.forward_to_main(req) → HTTP 202
// - On disconnect from main: return HTTP 503 with "cluster main unavailable"
```

#### prx-waf/src/main.rs — Medium (correct threading model)

```rust
fn run_server(config: AppConfig) -> anyhow::Result<()> {
    // ... existing init (unchanged) ...

    if config.cluster.enabled {
        let cluster_cfg = config.cluster.clone();
        let engine_ref = Arc::clone(&engine);
        let storage_mode = if config.storage.database_url.is_empty() {
            waf_cluster::StorageMode::ForwardOnly
        } else {
            waf_cluster::StorageMode::Full(Arc::clone(&db))
        };

        // Cluster MUST run in its own thread + runtime — same pattern as API server
        // Cannot be awaited in main because Pingora blocks the main thread
        std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .expect("BUG: failed to build cluster runtime");
            rt.block_on(async move {
                if let Err(e) = waf_cluster::ClusterNode::run(
                    cluster_cfg,
                    engine_ref,
                    storage_mode,
                ).await {
                    tracing::error!("Cluster node exited with error: {e}");
                }
            });
        });
    }

    // Pingora blocks the main thread forever (unchanged)
    server.run_forever();
}
```

---

## Appendix B: Admin UI — Cluster Dashboard

### B.1 New Pages

| Page | Route | Description |
|------|-------|-------------|
| Cluster Overview | `/cluster` | Mesh topology view, node status |
| Node Detail | `/cluster/nodes/:id` | Health, stats, last sync times |
| Join Tokens | `/cluster/tokens` | Generate/revoke join tokens |
| Sync Status | `/cluster/sync` | Per-node rule version, drift alerts |

### B.2 Cluster Overview Wireframe

```
┌──────────────────────────────────────────────────────────┐
│  Cluster: prx-waf-production          Status: Healthy    │
│  Nodes: 3/3 online    Main: node-a    Term: 7            │
├──────────────────────────────────────────────────────────┤
│                                                          │
│   ┌─────────┐     ┌─────────┐     ┌─────────┐          │
│   │ node-a  │─────│ node-b  │─────│ node-c  │          │
│   │ ★ MAIN  │     │ worker  │     │ worker  │          │
│   │ 2.3k rps│     │ 1.8k rps│     │ 2.1k rps│          │
│   │ CPU: 34%│     │ CPU: 28%│     │ CPU: 31%│          │
│   └─────────┘     └─────────┘     └─────────┘          │
│                                                          │
├──────────────────────────────────────────────────────────┤
│  Rules Version: 142    Config Version: 8                 │
│  Total Cluster RPS: 6,200    Total Blocked: 847          │
│  Last Sync: 3s ago    Election Term: 7                   │
└──────────────────────────────────────────────────────────┘
```

---

## Appendix C: Port Allocation

| Port | Service |
|------|---------|
| 16880 | HTTP proxy |
| 16843 | HTTPS proxy |
| 16827 | Management API + Admin UI |
| **16851** | **QUIC cluster communication (NEW)** |

---

## Appendix D: Final Dependency Delta

The entire cluster feature adds exactly **one new workspace dependency**:

```toml
# workspace Cargo.toml — only change to [workspace.dependencies]
lz4_flex = "0.11"
```

All other required crates (quinn, rustls, rcgen, rustls-pemfile, serde_json, aes-gcm)
are already in the workspace. Estimated binary size increase: **~1 MB** (lz4_flex +
waf-cluster code), not the 2-3 MB estimated in v1.0 which assumed quinn/rustls were new.

---

## Appendix E: Reusing gateway/http3.rs Patterns

The cluster QUIC transport differs from HTTP/3 in only one key way: mTLS (client cert
verification). The existing `gateway/src/http3.rs` already shows the exact rustls +
quinn setup. The cluster transport adapts it as follows:

```rust
// gateway/src/http3.rs (existing — no client cert):
let mut tls_config = rustls::ServerConfig::builder()
    .with_no_client_auth()      // HTTP/3: no mTLS
    .with_single_cert(certs, key)?;
tls_config.alpn_protocols = vec![b"h3".to_vec()];

// waf-cluster/src/transport/server.rs (new — mTLS):
let verifier = Arc::new(ClusterCaVerifier::new(ca_cert_der));
let mut tls_config = rustls::ServerConfig::builder()
    .with_client_cert_verifier(verifier)   // cluster: verify peer cert against cluster CA
    .with_single_cert(node_certs, node_key)?;
tls_config.alpn_protocols = vec![b"prx-cluster/1".to_vec()];
// All remaining quinn setup is identical to http3.rs
```

`ClusterCaVerifier` implements `rustls::server::danger::ClientCertVerifier`, checking
that the peer's certificate was signed by the cluster CA. This is well-documented in the
rustls API and reduces implementation risk significantly.
