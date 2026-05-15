# System Architecture

See also: [Data Storage & Cluster Architecture](./data-storage-architecture.md) for cluster setup, PostgreSQL schema, caching, and operational details.

---

## High-Level Topology

```
┌─────────────────────────────────────────────────────────────┐
│                    Clients (Internet)                        │
└────────────────────────┬────────────────────────────────────┘
                         │
        ┌────────────────┼────────────────┐
        ▼                ▼                ▼
    HTTP/1.1         HTTP/2            HTTP/3 (QUIC)
    (port 80)      (port 443)         (port 443)
        │                │                │
        └────────────────┴────────────────┘
                         │
        ┌────────────────▼────────────────┐
        │      Pingora Reverse Proxy      │
        │   (gateway crate)               │
        │  - TLS termination (OpenSSL)    │
        │  - Load balancing (round-robin) │
        │  - Response caching (moka LRU)  │
        │  - Health checks                │
        │  - RequestFilter chain (phase01)│
        │  - ResponseFilter chain (phase01)
        └────────────────┬────────────────┘
                         │
        ┌────────────────▼────────────────┐
        │    WafEngine (16-phase checks)  │
        │   (waf-engine crate)            │
        │  - IP allow/block               │
        │  - URL patterns                 │
        │  - Rate limiting (CC/DDoS)      │
        │  - Scanner + Bot detection      │
        │  - SQLi/XSS/RCE/Traversal       │
        │  - Custom rules (Rhai/JSON)     │
        │  - OWASP CRS (24 rules)         │
        │  - Sensitive data detection     │
        │  - Anti-hotlink                 │
        │  - CrowdSec integration         │
        │  - Device fingerprinting        │
        │    (FR-010: TLS ClientHello +   │
        │     H2 frame capture)           │
        └────────────────┬────────────────┘
                         │
        ┌────────────────▼────────────────┐
        │   Decision: Allow / Block       │
        │   (WafAction::Allow/Block)      │
        └────────────┬───────────────────┘
                     │
     ┌───────────────┴───────────────┐
     ▼                               ▼
  ALLOW                            BLOCK
     │                               │
     ▼                               ▼
Backend                        Return 403 Forbidden
(upstream                       (or 429 for rate limit)
server)                         Log: security_events +
                                attack_logs
```

---

## Request Lifecycle

Per-request flow runs in five stages:

1. **Pre-Phase — Relay Detection (FR-007)** — `RelayDetector::evaluate` validates XFF / X-Real-IP headers, detects trusted-proxy chains, classifies ASN (residential/datacenter/Tor), and emits signals. Output `ClientIdentity { real_ip, asn_class, asn, signals }` attached to `RequestCtx` for downstream rule predicates.
2. **Pre-Phase — Tier Classification (FR-002)** — `TierPolicyRegistry::classify` resolves `(Tier, Arc<TierPolicy>)` from request parts; result attached to `RequestCtx` before any phase.
3. **Phase-0 — Access Gate (FR-008)** — Host gate → IP blacklist → IP whitelist (per-tier `full_bypass`/`blacklist_only` dispatch). *Future*: IP evaluation to use `ClientIdentity.real_ip` instead of peer IP. Short-circuits before the rule pipeline.
4. **Phases 1–16 — Rule Pipeline** — IP/URL filtering → **FR-004 rate limiting (IP + session keys, token-bucket + sliding-window per tier)** → **FR-005 DDoS detection (per-IP/per-fingerprint/per-tier sliding-window with dynamic banning and graceful degrade)** → **FR-011 behavioral anomaly detection (per-actor cadence/path classifiers, 16-slot ring, signal cap ≤40)** → **FR-012 transaction velocity (session role-tagging, sequence timing, withdrawal bursts)** → payload attacks (SQLi/XSS/RCE/traversal) → custom rules → OWASP CRS → sensitive data → anti-hotlink → CrowdSec. Final decision: Allow / Block / Challenge.
5. **Risk Scoring (FR-025)** — **L0 Seed (Tor/ASN/whitelist baseline) + L1 Accumulation (per-actor state machine, IP/fingerprint/session triple-index with merge-on-collide) + L2 Anomaly (JA4↔UA mismatch, XFF chain, header sanity) + L2 Velocity (sliding window, sequence FSM)**. Risk deltas accumulated from all upstream checks and signals. Decay mechanism reduces stale risk. Thresholds gate: Allow (<X) / Challenge (X–Y) / Block (>Y). Hot-reload config via ArcSwap. Emits `X-WAF-Risk-Score` header. Integrates with tier-specific risk policies.
6. **Post-Decision — FR-009 Smart Caching** — If Allow: tier gate (CRITICAL never cached) → Chain-of-Responsibility gates → store response in moka LRU if eligible (tags indexed for purge).

Full per-phase walkthrough, mermaid diagrams, and post-decision handling: see **[request-pipeline.md](./request-pipeline.md)**.

### Outbound Phase — Response Header Sanitization (FR-035)

When a request is allowed and an upstream response arrives, Pingora invokes
`WafProxy::response_filter` (after the cache layer). If `[outbound] enabled`
is true, the configured `HeaderFilter` walks every response header and
strips:

- **Server-fingerprint** headers — `Server`, `X-Powered-By`, `X-AspNet-Version`,
  `X-AspNetMvc-Version`, `X-Runtime`, `X-Version`, `X-Generator`.
- **Debug / internal** headers — any name with prefix `X-Debug-`, `X-Internal-`,
  `X-Backend-`, `X-Real-IP`, `X-Forwarded-Server`.
- **Error-detail** headers — any name with prefix `X-Error-`, `X-Exception-`,
  `X-Stack-`, `X-Trace-`.
- Optionally: any header whose VALUE matches a PII regex (email, credit card,
  SSN, phone, RFC-1918 IP, JWT). Off by default — adds regex cost per header.

Operator-supplied exact names and prefixes (`strip_headers`, `strip_prefixes`)
extend the built-in lists. Matching is case-insensitive (RFC 9110 §5.1).
Security headers (HSTS, CSP, X-Frame-Options, etc.) are never stripped.

Standards: OWASP ASVS V14.4, CWE-200, CWE-209, RFC 9110 §7.6, NIST SP 800-53 SI-11.

---

## Component Interaction

### Gateway (Pingora) → WafEngine

```rust
// In gateway::proxy.rs
impl ProxyHttp for WafProxy {
    async fn request_filter(&mut self, session: &mut Session) -> Result<()> {
        let req = &session.req_header;
        
        // Build RequestCtx with tier classification (FR-002)
        let mut builder = RequestCtxBuilder::new(session, ...);
        if let Some(registry) = &self.tier_registry {
            builder = builder.with_tier_registry(registry);
        }
        let ctx = builder.build()?;
        // ctx.tier and ctx.tier_policy now populated from TierPolicyRegistry
        
        // Ask WafEngine to check all 16 phases
        let decision = self.engine.check(&ctx).await?;
        
        match decision.action {
            WafAction::Allow => {
                // Continue to backend
                Ok(())
            },
            WafAction::Block => {
                // Return 403 (or 429 based on tier policy)
                session.send_response(403, "Forbidden")?;
                Ok(())
            },
            // ... other actions
        }
    }
}
```

### Gateway → RelayDetector (FR-007)

```rust
// In gateway::proxy.rs, early in request_filter()
let detector = &self.relay_detector;  // RelayDetector instance
let client_identity = detector.evaluate(
    peer_ip,                            // TCP remote address
    &req.headers,                       // HTTP headers (XFF, X-Real-IP, etc.)
    &self.relay_config,                 // RelayConfig (trusted-proxy CIDRs, ASN db)
)?;

// Output: ClientIdentity {
//   real_ip: IpAddr,               // Derived from XFF or fallback to peer_ip
//   asn_class: AsnClass,           // Datacenter / Residential / Tor
//   asn: Option<u32>,              // BGP ASN if found
//   signals: Vec<Signal>,          // XffSpoofPrivate, XffMalformed, ExcessiveHopDepth, TorExit, etc.
// }

// Attach to RequestCtx for rule predicates (FR-025/026)
let mut builder = RequestCtxBuilder::new(session, ...);
builder = builder.with_client_identity(client_identity);
// ... rest of ctx building
```

**Multi-provider architecture:**
- `XffValidator` — parses XFF chain, detects spoofing (private IPs in trusted section)
- `ProxyChainAnalyzer` — counts hop depth, emits `ExcessiveHopDepth` signal if >32
- `AsnClassifier` — mmdb lookup (IPinfo Lite primary, fallback iptoasn TSV)
- `TorExitMatcher` — checks IP against Tor exit node set (refreshed hourly via HTTP+ETag)

**Hot-reload:** File watcher on `rules/relay.yaml` monitors config changes (trusted-proxy CIDRs, ASN db path, Tor feed URL, refresh intervals). Changes propagate via `ArcSwap` (lock-free atomic swap) with ≤1s latency.

### Gateway → DeviceFpDetector (FR-010)

Operator guide: [`device-fingerprinting.md`](device-fingerprinting.md).

```mermaid
flowchart LR
    CH[TLS ClientHello bytes] -->|patched pingora hook| Cap[ConnCtx]
    H2[HTTP/2 frames] -->|H2FrameTap| Cap
    Cap --> FP[FingerprintRegistry: ja3 / ja4 / h2 akamai]
    FP --> Key((FpKey))
    Key --> Store[(IdentityStore: Memory or Redis)]
    Store --> Obs[Observation]
    Key --> Disp[ProviderRegistry.dispatch<br/>FR-010: ip_hopping, ua_entropy, etc.]
    Obs --> Disp
    Key --> BRec[BehaviorRecorder<br/>FR-011: burst_interval, regularity, etc.]
    BRec --> BProv[Behavior Providers<br/>zero_depth, missing_referer]
    BProv --> Disp
    Disp --> Sigs[Vec&lt;Signal&gt;]
    Sigs --> Agg[RiskAggregator.submit -- FR-025 plug-in]
    Sigs --> Out[DeviceIdentity to gateway ctx]
```

```rust
// In gateway::proxy.rs, immediately after RelayDetector
let detector = &self.device_fp_detector;  // Arc<DeviceFpDetector>
let device_identity = detector
    .process(peer_ip, user_agent, &conn_ctx)  // ConnCtx holds raw L4 capture
    .await;

// Output: DeviceIdentity {
//   key: Arc<FpKey>,            // Composite ja3 / ja4 / h2_akamai hashes
//   signals: Vec<Signal>,       // FpConflict, IpHopping, LowEntropyUa, UaBlocklisted, H2Anomaly
// }
```

**Pipeline (`DeviceFpDetector::process`):**
1. `FingerprintRegistry::assemble` → `FpKey` from `RawCapture`.
2. `IdentityStore::observe` (when configured + key non-empty) → `Observation` (sliding-window distinct IPs/UAs).
3. `ProviderRegistry::dispatch` → `Vec<Signal>`.
4. `RiskAggregator::submit` (fire-and-forget) → FR-025 plug-in.

#### FR-025 plug-in contract

`device_fp/` ships `RiskAggregator` (in `crates/waf-engine/src/device_fp/aggregator.rs`) and a `NoopAggregator` default. FR-025 lives in its own crate, implements the trait, and is wired in by the binary:

```rust
use waf_engine::device_fp::{DeviceFpDetector, RiskAggregator, FpKey, Signal};

pub struct ScoringAggregator {
    tx: tokio::sync::mpsc::Sender<Job>,
}

#[async_trait::async_trait]
impl RiskAggregator for ScoringAggregator {
    async fn submit(&self, key: &FpKey, signals: &[Signal]) {
        let job = Job { key: key.clone(), signals: signals.to_vec() };
        if self.tx.try_send(job).is_err() {
            tracing::warn!("risk-scorer queue full, dropping submission");
        }
    }
}

// Wiring:
let detector = DeviceFpDetector::new(cfg, registry)
    .with_store(Arc::new(MemoryIdentityStore::default()))
    .with_aggregator(Arc::new(ScoringAggregator::new()));
```

**Contract rules:**
- `submit` is async but MUST NOT block the caller — fan out to a bounded channel internally and drop-with-warn on overflow.
- Caller treats `submit` as fire-and-forget; no result, no error path.
- `key` is borrowed; clone if the impl retains it past the call.
- `device_fp/` never depends on the FR-025 crate — wiring lives at the binary entry point only.

`LoggingAggregator` (same module) is a test/dev impl that records submissions into a bounded ring buffer for assertions.

### WafEngine → Risk Scorer (FR-025)

**Cumulative risk scoring subsystem** — Tracks per-actor risk state and applies threshold gates to emit Allow / Challenge / Block decisions. Integrates signals from all upstream checks (rule matches, anomalies, DDoS) and decays stale risk. Pluggable backend (memory or Redis).

**L0 seed layer evaluation:** IP reputation baseline (Tor exits, ASN classification, whitelist) evaluated before other risk layers via file-based data sources (`configs/seed/`). Whitelist entries bypass all scoring (immediate Allow).

```
Seed Layer (Tor/ASN/Whitelist) ─────┐
                                    │
Upstream Signals (rules, ddos, etc.)├──► Scorer::score(ctx, fp_key, deltas, now_ms)
    │
    ├─ Build RiskKey (IP, fingerprint, session triple-index)
    │
    ├─ RiskStore::apply(key, deltas, now_ms)
    │   │ (Memory or Redis backend)
    │   ├─ Memory: in-process HashMap with optional decay call
    │   │
    │   └─ Redis: Lua script atomically (single RTT)
    │       ├─ Fetch or create RiskState + owner_id
    │       ├─ Apply decay (raw_score decays by 0-50 points)
    │       ├─ Fold in new contributors (signal deltas)
    │       ├─ Clamp score to [0, 100]
    │       └─ EXPIRE key (per ttl_secs config)
    │
    ├─ Threshold gate: decide(score, tier_policy.risk_thresholds)
    │   ├─ score < allow_threshold    → Allow
    │   ├─ score < challenge_threshold → Challenge (CAPTCHA, JS POW)
    │   └─ score >= challenge_threshold → Block
    │
    └─ Emit X-WAF-Risk-Score header + return WafAction
```

**RiskKey triple-index (collision & merge strategy):**
- IP-based: `waf:risk:idx:ip:{client_ip}` (Redis) or memory key
- Fingerprint-based: `waf:risk:idx:fp:{fp_hash}` (Redis) or memory key
- Session-based: `waf:risk:idx:sid:{session_id}` (Redis) or memory key

When multiple keys match a single request, all three states merge via `force_max_script` (Redis) or in-memory merge (highest score wins, contributors union).

**Backend Configuration (Phase 7)**

| Aspect | Memory | Redis |
|--------|--------|-------|
| **Deployment** | Single-node / dev | Cluster / high-volume |
| **Storage** | In-process HashMap | Distributed key-value |
| **Persistence** | Lost on restart | Persisted (RDB/AOF) |
| **Consistency** | Per-request local | Atomic Lua scripts |
| **Failover** | N/A | Circuit breaker + LRU fallback |
| **Config** | `store.backend = "memory"` | `store.backend = "redis"` + redis.* |

**Redis Lua Scripts (Atomic Operations)**
1. `apply_script` — Decay + fold deltas + EXPIRE in single RTT
2. `mint_or_get_owner_script` — Idempotent owner_id creation (UUID v4)
3. `force_max_script` — Merge colliding keys by score (used during incident response)

**Circuit Breaker & Fail-Open (Redis Only)**
- Opens after `breaker_threshold` (default: 5) consecutive failures
- Falls back to in-memory LRU cache (`cache_capacity`, default: 10k)
- Requests proceed with local cache; Redis resync on next success
- No request blocking during Redis outage

**L2 Anomaly Layer (Phase 5):** Inline synchronous detectors evaluated per-request: (1) JA4↔UA mismatch (TLS fingerprint vs User-Agent family incompatibility, +20), (2) XFF chain sanity (malformed or excessive hop counts, +10 cap), (3) Header sanity (missing required headers or impossible combinations, +15 cap).

**L2 Velocity Layer (Phase 5):** Request-rate and transaction-sequence detectors: (1) Sliding window (60×1s ring buffer; request-rate threshold breach → +25), (2) Sequence FSM (Login→OTP→Withdrawal path validation; out-of-order or timing anomalies → +30).

**Risk contributions:**
- Rule matches (e.g., SQLi detected) — delta from `rule.risk_score_delta` in YAML (0–50 points)
- Signal providers (FR-010, FR-011, FR-012 anomalies) — delta from signal enum (5–20 points)
- DDoS detector verdicts (FR-005) — delta bump for detected floods (5–30 points)
- L2 Anomaly detectors (JA4↔UA, XFF, headers) — delta 10–20 points
- L2 Velocity detectors (sliding window, sequence FSM) — delta 25–30 points

**Decay mechanism:**
- Linear decay: `raw_score -= decay_factor * time_ms` (configurable, default 1 pt/min)
- Floor: score never drops below 0 or above 100
- Clean streak: increments when no new signals in a window (soft reset threshold)

**Configuration (hot-reload via `configs/risk.yaml`):**
```yaml
[risk]
enabled = true
decay_enabled = true
decay_factor_per_min = 1.0        # Points lost per minute of inactivity
allow_threshold = 30              # Risk score below this → Always Allow
challenge_threshold = 60          # Risk score [allow, challenge) → Challenge
use_ip_key = true
use_fingerprint_key = true
use_session_key = true            # Requires session cookie / FR-010 FpKey
max_state_age_secs = 3600         # Purge risk states older than this
```

**Integration points:**
- **During rule evaluation** (Phase N) — Accumulate risk deltas in `RequestCtx.risk_deltas`
- **Post-rule pipeline** — `Scorer::score()` applies accumulated deltas + applies decay + thresholds
- **Header emission** — `X-WAF-Risk-Score: <0-100>` sent in all responses
- **Tier policy** — `tier_policy.risk_thresholds` (allow/challenge/block points) per tier

**Module:** `crates/waf-engine/src/risk/` (scorer.rs, key.rs, state.rs, score.rs, decay.rs, threshold.rs, config.rs, reload.rs, store/, seed/, anomaly/, velocity/, ingest/, tests/).

### WafEngine → PostgreSQL Storage

```rust
// In waf-engine::engine.rs
pub struct WafEngine {
    pub store: Arc<RuleStore>,           // In-memory registry
    pub db: Arc<Database>,               // PostgreSQL connection pool
    pub custom_rules: Arc<CustomRulesEngine>,
}

// On startup: load rules from disk + database
async fn init(db: Arc<Database>) -> Result<Self> {
    // Load built-in YAML rules from disk
    let yaml_rules = load_yaml_rules("rules/")?;
    
    // Load custom rules from PostgreSQL
    let custom_rules = db.list_custom_rules().await?;
    
    // Build RuleRegistry (in-memory)
    let registry = RuleRegistry::new();
    for rule in yaml_rules.chain(custom_rules) {
        registry.insert(rule);
    }
    
    Ok(Self {
        store: Arc::new(RuleStore { registry }),
        db,
        custom_rules: Arc::new(CustomRulesEngine::new()),
    })
}

// During request: write to database
async fn log_attack(&self, event: SecurityEvent) -> Result<()> {
    self.db.create_security_event(event).await?;
    Ok(())
}
```

### WafAPI → Database → Admin UI

```
Admin UI (Vue 3)
    │
    ├─ POST /api/hosts  ────────────►  Axum Router
    │                                      │
    │                                      ▼
    │                             JWT Auth Middleware
    │                                      │
    │                                      ▼
    │                             Handler: create_host()
    │                                      │
    │                                      ▼
    │                             Database: db.create_host()
    │                                      │
    │                                      ▼
    │                             PostgreSQL: INSERT INTO hosts
    │                                      │
    │  ◄──── JSON Response ────────────────┘
```

