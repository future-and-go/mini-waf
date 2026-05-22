# PRX-WAF Cluster Protocol Specification

**Author:** David (AI CEO)
**Date:** 2026-03-16
**Status:** Finalized (v0.1.0-rc.1 and v0.2.0)
**Version:** 2.0

**Related:** See also [`./cluster-design.md`](./cluster-design.md) for architecture overview and security model.

---

## 1. QUIC Stream Protocol

### 1.1 Stream Allocation

| Stream | Direction | Priority | Description |
|--------|-----------|----------|-------------|
| **Control** | Bidirectional | Highest | Heartbeat, election, membership |
| **RuleSync** | Main → Worker | High | Rule updates (incremental or full snapshot) |
| **ConfigSync** | Main → Worker | High | TOML config updates |
| **EventLog** | Worker → Main | Medium | Attack logs, security events |
| **Stats** | Worker → Main | Low | Metrics via QUIC datagrams (unreliable OK) |
| **Forward** | Bidirectional | Per-request | API write forwarding |

### 1.2 Wire Format: Length-Prefixed JSON

No protobuf. All message types use `serde_json`. Frame format:

```
┌──────────────────┬────────────────────────────────┐
│  u32 (4 bytes)   │  JSON bytes (variable length)  │
│  big-endian len  │  serde_json::to_vec(msg)        │
└──────────────────┴────────────────────────────────┘
```

This is idiomatic over `quinn::SendStream` / `RecvStream` using `bytes::BufMut`.

### 1.3 Message Type Definitions

```rust
// crates/waf-cluster/src/protocol/messages.rs

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ClusterMessage {
    Heartbeat(Heartbeat),
    ElectionVote(ElectionVote),
    ElectionResult(ElectionResult),
    JoinRequest(JoinRequest),
    JoinResponse(JoinResponse),
    NodeLeave { node_id: String },
    RuleSyncRequest(RuleSyncRequest),
    RuleSyncResponse(RuleSyncResponse),
    ConfigSync(ConfigSync),
    EventBatch(EventBatch),
    StatsBatch(StatsBatch),
    ApiForward(ApiForward),
    ApiForwardResponse(ApiForwardResponse),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Heartbeat {
    pub sequence: u64,
    pub timestamp_ms: u64,
    pub node_id: String,
    pub role: NodeRole,
    pub uptime_secs: u64,
    pub cpu_percent: f64,
    pub memory_used_bytes: u64,
    pub total_requests: u64,
    pub blocked_requests: u64,
    pub rules_version: u64,
    pub config_version: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ElectionVote {
    pub term: u64,
    pub candidate_id: String,
    pub last_log_index: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ElectionResult {
    pub term: u64,
    pub elected_id: String,
    pub voter_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JoinRequest {
    pub token: String,
    pub csr_pem: String,
    pub node_info: NodeInfo,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JoinResponse {
    pub accepted: bool,
    pub reason: Option<String>,
    pub node_cert_pem: String,
    pub ca_cert_pem: String,
    pub cluster_state: ClusterState,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeInfo {
    pub node_id: String,
    pub hostname: String,
    pub version: String,
    pub listen_addr: String,
    pub capabilities: Vec<String>,   // ["waf", "proxy", "api"]
}

/// Rule sync — reuses waf_engine::rules::registry::Rule directly (already Serialize+Deserialize).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleSyncRequest {
    pub current_version: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleSyncResponse {
    pub version: u64,
    pub sync_type: SyncType,
    /// Incremental: changed rules only (empty if full)
    pub changes: Vec<RuleChange>,
    /// Full: lz4-compressed JSON of Vec<Rule> (empty if incremental)
    pub snapshot_lz4: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SyncType { Incremental, Full }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleChange {
    pub op: ChangeOp,
    pub rule_id: String,
    /// Serialized Rule struct; None if op == Delete
    pub rule_json: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ChangeOp { Upsert, Delete }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigSync {
    pub version: u64,
    pub config_toml: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventBatch {
    pub node_id: String,
    pub events: Vec<SecurityEvent>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityEvent {
    pub timestamp_ms: u64,
    pub client_ip: String,
    pub method: String,
    pub path: String,
    pub host: String,
    pub rule_id: Option<String>,
    pub action: String,
    pub geo_country: String,
    pub node_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatsBatch {
    pub node_id: String,
    pub timestamp_ms: u64,
    pub total_requests: u64,
    pub blocked_requests: u64,
    pub allowed_requests: u64,
    pub top_ips: std::collections::HashMap<String, u64>,
    pub top_rules: std::collections::HashMap<String, u64>,
    pub top_countries: std::collections::HashMap<String, u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusterState {
    pub main_node_id: String,
    pub nodes: Vec<NodeInfo>,
    pub rules_version: u64,
    pub config_version: u64,
    pub term: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiForward {
    pub request_id: String,
    pub method: String,
    pub path: String,
    pub body: Vec<u8>,
    pub headers: std::collections::HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiForwardResponse {
    pub request_id: String,
    pub status: u16,
    pub body: Vec<u8>,
}
```

---

## 2. Raft-Lite Election Protocol

Simplified Raft — leader election only. Log replication is handled by the rules sync
protocol, not Raft entries.

### 2.1 State Machine

```
                 timeout
  ┌──────────┐ ──────────► ┌──────────────┐
  │  Worker   │             │  Candidate   │
  │ (follower)│ ◄────────── │ (requesting  │
  └──────────┘  election    │   votes)     │
       ▲        lost        └──────────────┘
       │                         │ majority
       │                         ▼
       │                    ┌──────────┐
       └────────────────────│   Main   │
           step down        │ (leader) │
                            └──────────┘
```

### 2.2 Election Rules

1. Each node has a monotonically increasing **term** counter
2. Worker starts election timeout (random 150-300ms)
3. If no heartbeat from main within timeout → become Candidate
4. Candidate increments term, votes for self, requests votes from all peers
5. Node grants vote if: candidate term > current term AND haven't voted this term
6. Candidate wins if: receives majority votes (N/2 + 1)
7. Winner becomes Main, broadcasts `ElectionResult`
8. Losers reset to Worker, accept new Main
9. If split vote → random backoff, retry next term

### 2.3 Failure Detection

**Phi-accrual failure detector** (Cassandra-style):

- Track heartbeat inter-arrival time distribution per peer
- Compute φ = `−log10(P(t > now − last_heartbeat))`
- φ > 8 → suspect failure, emit warning
- φ > 12 → declare dead, trigger election if it was main

Advantage over fixed timeout: automatically adapts to network jitter.

---

## 3. Rule Synchronization

### 3.1 Version Tracking

`RuleRegistry.version: u64` (already in codebase) is the sync key. It increments on
every `insert()` or `remove()`. No new versioning infrastructure needed.

```
Worker request: RuleSyncRequest { current_version: 42 }

Main logic:
  registry = rule_manager.registry.read().unwrap()
  if registry.version == 42 → send empty RuleSyncResponse (no-op)
  else if changelog covers [42..registry.version] → send incremental
  else (worker too far behind or changelog evicted) → send full snapshot
```

### 3.2 Full Snapshot Serialization

```rust
// Main: serialize + compress
let registry = rule_manager.registry.read().unwrap();
let rules: Vec<_> = registry.rules.values().collect();
let json = serde_json::to_vec(&rules).context("rule snapshot serialize")?;
let compressed = lz4_flex::compress_prepend_size(&json);
// Send as RuleSyncResponse { sync_type: Full, snapshot_lz4: compressed, .. }

// Worker: decompress + apply
let json = lz4_flex::decompress_size_prepended(&msg.snapshot_lz4)
    .context("rule snapshot decompress")?;
let rules: Vec<waf_engine::rules::registry::Rule> = serde_json::from_slice(&json)
    .context("rule snapshot deserialize")?;
let mut registry = engine.rule_registry.write().unwrap();
registry.rules.clear();
registry.by_category.clear();
registry.by_source.clear();
for rule in rules { registry.insert(rule); }
registry.version = msg.version;
engine.on_rules_updated(msg.version).await?;
```

### 3.3 Incremental Change Log

```rust
// crates/waf-cluster/src/sync/rules.rs
pub struct RuleChangelog {
    /// Ring buffer: (version_after_change, RuleChange)
    changes: std::collections::VecDeque<(u64, RuleChange)>,
    /// Keep last N changes; if worker needs more → force full sync
    max_retained: usize,  // default 500
}

impl RuleChangelog {
    pub fn push(&mut self, version: u64, change: RuleChange) {
        if self.changes.len() >= self.max_retained {
            self.changes.pop_front();
        }
        self.changes.push_back((version, change));
    }

    pub fn delta_since(&self, from_version: u64) -> Option<Vec<RuleChange>> {
        // Returns None if from_version is too old (evicted from ring buffer)
        let first = self.changes.front().map(|(v, _)| *v).unwrap_or(0);
        if from_version < first { return None; }
        Some(
            self.changes.iter()
                .filter(|(v, _)| *v > from_version)
                .map(|(_, c)| c.clone())
                .collect()
        )
    }
}
```

### 3.4 Sync Triggers

| Trigger | Action |
|---------|--------|
| Worker connects to main | Full sync immediately |
| Admin creates/edits/deletes rule via API | Main pushes incremental to all workers |
| Periodic poll (every `sync.rules_interval_secs`) | Worker sends RuleSyncRequest; main responds if version differs |
| Worker rejoins after disconnect | Full sync (safer than relying on stale changelog) |

### 3.5 WASM Plugin Sync (v1 Limitation)

WASM plugins are binary blobs stored in PostgreSQL. Worker nodes **do not receive WASM
plugins** in v1. Workers run the WAF engine without plugin support. Add to deployment
documentation: "WASM plugins require the main node; workers skip plugin execution in v1."

---

## 4. Configuration Reference

### 4.1 Full Configuration Reference

```toml
# ─── Cluster Configuration ────────────────────────────────────
[cluster]
# Enable clustering. Default: false — zero behavior change for existing deployments.
enabled = false

# Unique node identifier. Auto-generated from hostname+uuid suffix if empty.
node_id = ""

# Role assignment. "auto" participates in election.
# Values: "auto" | "main" | "worker"
role = "auto"

# QUIC listen address for cluster communication.
listen_addr = "0.0.0.0:16851"

# Static seed nodes. At least one reachable seed required to join a cluster.
seeds = []
# Example: seeds = ["10.0.0.1:16851", "10.0.0.2:16851"]

# ─── Crypto ───────────────────────────────────────────────────
[cluster.crypto]
ca_cert    = "/app/certs/cluster-ca.pem"
node_cert  = "/app/certs/node.pem"
node_key   = "/app/certs/node.key"

# Auto-generate CA and node certs on first startup. Required for initial main.
auto_generate       = true
ca_validity_days    = 3650   # 10 years
node_validity_days  = 365    # 1 year
renewal_before_days = 7      # auto-renew 7 days before expiry

# ─── Sync ─────────────────────────────────────────────────────
[cluster.sync]
rules_interval_secs        = 10    # periodic rule version check
config_interval_secs       = 30
events_batch_size          = 100   # flush event batch at this count
events_flush_interval_secs = 5     # flush even if batch not full
stats_interval_secs        = 10
events_queue_size          = 10000 # drop oldest if worker falls behind

# ─── Election ─────────────────────────────────────────────────
[cluster.election]
timeout_min_ms        = 150    # random election timeout range
timeout_max_ms        = 300
heartbeat_interval_ms = 50     # main → workers heartbeat
phi_suspect           = 8.0
phi_dead              = 12.0

# ─── Health ───────────────────────────────────────────────────
[cluster.health]
check_interval_secs   = 5
max_missed_heartbeats = 3
```

### 4.2 CLI Commands

```bash
prx-waf cluster status                    # Show cluster topology + health
prx-waf cluster nodes                     # List all nodes
prx-waf cluster token generate            # Generate join token (1h default TTL)
prx-waf cluster token generate --ttl 24h

# Node join (add to run command)
prx-waf run --cluster-join <main_addr> --token <token>

# Emergency role control
prx-waf cluster promote <node_id>
prx-waf cluster demote  <node_id>
prx-waf cluster remove  <node_id>
```

---

## 5. Testing Strategy

### 5.1 Unit Tests

- Certificate generation round-trip (rcgen: generate CA → sign CSR → verify)
- Join token HMAC: generate → validate → expire
- JSON message serialization/deserialization for all `ClusterMessage` variants
- Election state machine: all state transitions, split-vote recovery
- Phi-accrual: verify φ increases correctly with delayed heartbeats
- RuleChangelog: ring buffer eviction, delta_since boundary conditions

### 5.2 Integration Tests

```rust
// tests/integration.rs — example structure
#[tokio::test]
async fn two_nodes_connect_and_heartbeat() {
    // Spawn main + worker in-process with ephemeral ports
    // Assert worker receives heartbeat within 200ms
}

#[tokio::test]
async fn mtls_rejects_unknown_cert() {
    // Worker with wrong CA cert → connection rejected
}

#[tokio::test]
async fn rule_created_on_main_appears_on_worker() {
    // Create rule via main API → assert worker RuleRegistry updated within 5s
}

#[tokio::test]
async fn api_write_on_worker_forwarded_to_main() {
    // POST to worker API → 202 Accepted → main DB has new record
}
```

### 5.3 Chaos Tests

- Kill main → verify election completes, new main elected within 500ms
- Network partition: 3 nodes, disconnect node-a → [b, c] elect new main, node-a isolated
- Split-brain: 2 partitions each with 1 node — neither can win (no majority of 3)
- Slow network: delay heartbeats 200ms → phi-accrual adapts, no false election
- Rejoin after partition heal → rule sync catches up

### 5.4 Performance Benchmarks

| Metric | Target |
|--------|--------|
| Heartbeat RTT (LAN) | < 1ms |
| Heartbeat RTT (WAN 50ms) | < 55ms |
| Rule sync latency (incremental) | < 100ms |
| Full rule snapshot (1000 rules) | < 2s |
| Election completion (LAN 3-node) | < 500ms |
| Event forwarding throughput | > 10,000 events/sec |

---

## 6. Implementation Phases

> **Effort estimates use Claude-hours.** Claude AI performs all development 24/7 with no
> context-switching overhead, roughly 3-5x faster than human-hours for comparable tasks.
> Estimates assume no blocking external dependencies (network, hardware, vendor APIs).

### Phase 1: Foundation — QUIC Transport + mTLS (~14 Claude-hours)

**Goal:** Two nodes can discover each other, establish mTLS QUIC connection, and exchange heartbeats.

| Task | Est. | Crate | Notes |
|------|------|-------|-------|
| Create `waf-cluster` crate + Cargo.toml | 0.5h | waf-cluster | Module stubs, workspace registration |
| ClusterConfig + NodeRole in waf-common | 0.5h | waf-common | Add optional field to AppConfig; Default = disabled |
| Protocol message types (§1.3) | 1h | waf-cluster/protocol | All structs + serde derives |
| Length-prefixed JSON frame codec | 1h | waf-cluster/transport/frame.rs | Read/write `u32 + JSON` over quinn streams |
| QUIC mTLS server (reuse gateway/http3.rs pattern) | 2h | waf-cluster/transport/server.rs | Switch to `with_client_cert_verifier` for mTLS |
| QUIC client dialer | 1.5h | waf-cluster/transport/client.rs | Connect to peer, send JoinRequest |
| CA certificate generation (rcgen — already in workspace) | 1h | waf-cluster/crypto/ca.rs | Ed25519 + 10yr self-signed |
| Node certificate signing + CSR validation | 1h | waf-cluster/crypto/node_cert.rs | |
| AES-GCM CA key storage (reuse waf-common::crypto) | 0.5h | waf-cluster/crypto/store.rs | Passphrase-derived key |
| Join token: HMAC-SHA256 generate + validate | 0.5h | waf-cluster/crypto | sha2 already in workspace |
| Heartbeat send/receive on control stream | 1h | waf-cluster/health | Periodic tokio::time::interval |
| Static seed discovery | 0.5h | waf-cluster/discovery | Read ClusterConfig.seeds |
| Thread launch in prx-waf/main.rs | 0.5h | prx-waf | std::thread::spawn + own runtime |
| Integration test: 2-node connect + heartbeat | 2h | waf-cluster/tests | |
| **Phase 1 subtotal** | **~14h** | | |

### Phase 2: Rule and Config Sync (~14 Claude-hours)

**Goal:** Workers auto-sync rules from main; attack logs aggregated on main; API writes forwarded.

| Task | Est. | Crate | Notes |
|------|------|-------|-------|
| RuleChangelog ring buffer on main | 1h | waf-cluster/sync/rules.rs | VecDeque, max 500 entries |
| Full snapshot: serialize RuleRegistry → lz4 | 1h | waf-cluster/sync/rules.rs | lz4_flex::compress_prepend_size |
| Incremental sync: send changelog delta | 1h | waf-cluster/sync/rules.rs | Filter by version |
| Worker: receive + apply rule updates | 1.5h | waf-cluster/sync/rules.rs | RuleRegistry write lock + insert |
| RuleReloader trait + WafEngine impl | 0.5h | waf-engine | Thin wrapper on reload_rules() |
| Config sync protocol (TOML string) | 1h | waf-cluster/sync/config.rs | |
| Attack event batching on worker | 1h | waf-cluster/sync/events.rs | tokio::time::interval flush |
| Event forwarding to main (EventBatch stream) | 1h | waf-cluster/sync/events.rs | |
| Main: write forwarded events to PostgreSQL | 0.5h | waf-cluster/sync/events.rs | Existing db.create_security_event() |
| Stats aggregation via QUIC datagrams | 1h | waf-cluster/sync | Unreliable send — quinn::Connection::send_datagram |
| API write forwarding: worker → main | 2h | waf-api | New cluster.rs handler; ApiForward stream |
| StorageMode enum in waf-cluster | 0.5h | waf-cluster/node.rs | Internal enum; no waf-storage changes |
| Integration test: create rule on main → synced to worker | 1.5h | tests | |
| **Phase 2 subtotal** | **~14h** | | |

### Phase 3: Election + Failover (~16 Claude-hours)

**Goal:** Cluster survives main failure with automatic re-election, no manual intervention.

| Task | Est. | Crate | Notes |
|------|------|-------|-------|
| Raft-lite election state machine (term, vote, timeout) | 3h | waf-cluster/election | All state transitions + split-vote handling |
| Phi-accrual failure detector | 2h | waf-cluster/health/detector.rs | Sliding window + phi formula |
| Main → Worker role demotion on new election | 1h | waf-cluster/node.rs | Role state machine |
| Worker → Main promotion (connect DB if configured) | 2h | waf-cluster/node.rs | Conditional DB connect |
| CA key replication to workers on join | 2h | waf-cluster/crypto | Encrypted quorum storage |
| Split-brain prevention (fencing token / term check) | 1h | waf-cluster/election | Reject stale-term leaders |
| CLI subcommands: cluster status/promote/demote/remove | 1h | prx-waf | Clap subcommands |
| Integration test: kill main → worker promoted in < 500ms | 2h | tests | |
| Chaos test: network partition + split-brain prevention | 1.5h | tests | Simulate packet drops |
| Concurrent election test: single winner | 0.5h | tests | |
| **Phase 3 subtotal** | **~16h** | | |

### Phase 4: Admin UI + Polish (~10 Claude-hours)

**Goal:** Full cluster management via Admin UI; 3-node cluster deployable with docker-compose.

| Task | Est. | Crate | Notes |
|------|------|-------|-------|
| API endpoints /api/cluster/* | 2h | waf-api | Follow existing axum handler patterns |
| Cluster Overview page (Vue 3 + Tailwind) | 2.5h | admin-ui | SVG mesh topology + node cards |
| Node Detail page | 1h | admin-ui | Health chart, stats, sync status |
| Join Token management page | 1h | admin-ui | Generate/list/revoke tokens |
| Sync Status page | 1h | admin-ui | Per-node rule version, drift alerts |
| i18n keys (en/zh/ru/ka) | 1h | admin-ui | Follow existing i18n pattern in en.ts etc. |
| 3-node cluster docker-compose test + deployment docs | 1.5h | tests + docs | |
| **Phase 4 subtotal** | **~10h** | | |

**Total: ~54 Claude-hours across 4 phases.**
