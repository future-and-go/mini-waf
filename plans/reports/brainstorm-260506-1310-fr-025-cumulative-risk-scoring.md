---
title: "FR-025 Cumulative Risk Scoring — Production Design Brainstorm"
date: 2026-05-06 13:10 +07
type: brainstorm
slug: fr-025-cumulative-risk-scoring
upstream:
  - analysis/requirements.md (FR-025, FR-026, FR-027, FR-028)
  - plans/reports/research-260430-1639-risk-score-design-brainstorm.md
  - plans/reports/spec-260430-1709-risk-score-requirements-and-tech-spec.md
status: pending-approval
---

# FR-025 Cumulative Risk Scoring — Production Design

## 1. Context (WHY this matters)

A WAF that drops malicious requests one-by-one is a **packet filter**, not a security gateway. Real attackers spread across requests: scout one, probe two, exploit three. Each individual request looks clean-ish; the **pattern** is the threat.

FR-025 is the brain that remembers. Every detection signal — rule match, anomaly, fingerprint conflict, bot timing, ASN reputation — flows into a single 0–100 number stored against the actor's identity. FR-027 reads that number and decides Allow / Challenge / Block. Without FR-025, every other detector (FR-010 fingerprinting, FR-011 anomaly, FR-012 velocity) emits signals into the void.

**Acceptance criteria (verbatim from `analysis/requirements.md`):**
- FR-025: Per `{IP + device fingerprint + session}`; **does not reset per request**.
- FR-026: Increases on rule match / failed challenge / anomaly / suspicious ASN / fingerprint conflict. Decreases on successful challenge / sustained normal behavior.
- FR-027: Configurable thresholds — `<30 Allow`, `30-70 Challenge`, `>70 Block`.
- FR-028: Canary / honeypot path → auto max risk score + block IP.

**Why "cumulative" matters:** if score reset every request, a sophisticated bot spreads its tells across 100 requests, never tripping any threshold. Real defense is per-actor accumulation.

---

## 2. What's Already Built (don't rebuild)

The codebase already has the seams for FR-025. We are filling the missing piece, not starting from zero.

| Built | What it does | Where |
|---|---|---|
| `RiskAggregator` trait | Fire-and-forget submit point. Doc-comment literally says **"the seam where device-fp signals flow out to FR-025"** | `crates/waf-engine/src/device_fp/aggregator.rs:41` |
| `Signal` enum | 12 variants emitted by FR-010/011/012/005 (FpConflict, IpHopping, BurstInterval, Regularity, ZeroDepth, MissingReferer, TxSequenceTooFast, WithdrawalVelocity, …) | `device_fp/signal.rs` |
| `IdentityStore` trait | Memory + Redis backends (feature-gated). Conformance suite ready. | `device_fp/identity/` |
| `CounterStore` trait | Same trait pattern for FR-005 DDoS counters. Memory + Redis. | `checks/ddos/store/` |
| `RiskBumpAction` | Already submits DDoS verdicts to aggregator — proves the seam works. | `checks/ddos/action/risk.rs` |
| `Check` trait | Pipeline contract for inserting new checks. | `checks/mod.rs:36` |
| `WafDecision` (Allow/Block/Challenge) | Action sink already supports the three FR-027 outcomes. | `waf-common` |
| `tx_velocity` per-session keying | Cookie → session resolution already implemented. Reusable. | `checks/tx_velocity/` |

**The gap:** the receiving end — the actual scorer — is `NoopAggregator`. Signals are produced, then dropped on the floor.

---

## 3. Approach (WHY this design pattern)

### 3.1 Pattern: Layered Pipeline + Event-Sourced State

Two design patterns combined, each chosen for a specific reason.

**Layered pipeline** (a.k.a. **Chain of Responsibility**) — the score is composed by walking through ordered layers (L0 reputation → L1 rules → L2 anomalies → L2 velocity → L3 decay → tier mult). Each layer is a pure function with bounded latency. This is identical to how the existing `Check` pipeline works in `checker.rs`.

> **WHY layered?** Determinism + budget control. Every layer has a hard latency budget (e.g. L0 ≤ 100µs, L2 ≤ 1ms). If we composed signals as a free-form async DAG, p99 would balloon under load. Strict ordering lets us short-circuit (e.g. skip expensive LSH when score is far from threshold).

**Event-sourced state** — store doesn't hold the *score*; it holds the *contributors* (a bounded ring of `(rule_id, delta, ts_ms)` events). Score is recomputed on read by folding the contributors. This is the same idea as a **CQRS read-model**: write events, derive views.

> **WHY event-sourced?** Two payoffs:
> 1. **Auditability (FR-RS-121)** — `X-WAF-Rule-Id` must be the dominant contributor. Without per-event retention you cannot answer "which detector drove this block?".
> 2. **Replay harness (NFR-RS-013)** — tuning the decay parameters requires re-scoring historical traffic. If we only stored the final integer, we could not.
>
> **Pitfall to avoid:** storing **unbounded** contributor history. We cap at 8 most-recent (SmallVec inline) — beyond that, audit log carries the full record. The store is hot-path; the log is cold archive.

> **Jargon checkpoint:**
> - **CQRS** = Command-Query Responsibility Segregation. Write path and read path use different models. Lets you optimize each independently.
> - **Event sourcing** = persist the *changes* (events), derive the *state* from them. Mirrors how git works (commits, not snapshots).
> - **Pure function** = same input → same output, no side effects. Easy to unit-test, easy to reason about concurrency.

### 3.2 Pattern: Trait + Backends (mirror existing IdentityStore)

`RiskStore` is a trait. Two production backends:

```rust
// New file: crates/waf-engine/src/risk/store/store_trait.rs
#[async_trait]
pub trait RiskStore: Send + Sync {
    async fn read(&self, key: &RiskKey) -> anyhow::Result<RiskState>;
    async fn apply(&self, key: &RiskKey, deltas: &[Contributor], now_ms: i64)
        -> anyhow::Result<RiskState>;  // returns post-update state
    async fn force_max(&self, key: &RiskKey, now_ms: i64) -> anyhow::Result<()>; // FR-028
    async fn purge_expired(&self, now_ms: i64) -> anyhow::Result<usize>;
    async fn reset_all(&self) -> anyhow::Result<()>; // BG-06 reset_state hook
}
```

> **WHY a trait, not a concrete `RiskStore` struct?** Production WAFs run multi-node. Memory backend serves single-node; Redis backend serves cluster. The `device_fp::IdentityStore` and `ddos::CounterStore` already prove this pattern in this codebase — reuse it. Same `redis-store` Cargo feature flag.
>
> **Common pitfall (avoid):** writing the trait against the concrete `RedisClient`. Then memory backend has to embed Redis. The trait must be backend-agnostic — only `async fn read/apply/...` and a result type.

### 3.3 Pattern: Hybrid Sync-Read + Async-Submit

This reconciles three constraints that look contradictory:

| Constraint | Reads / Writes |
|---|---|
| FR-RS-013: Score must reflect post-current-request state | **Sync write on hot path.** |
| `RiskAggregator::submit` MUST NOT block (existing contract) | **Async ingest from device_fp.** |
| NFR-RS-001: ≤3ms p99 risk-eval contribution at 5k rps | Both must be fast. |

Resolution — **two ingress paths, one store**:

```
                   ┌────────────────────────────────────────────────┐
                   │          Request Hot Path (sync)                │
                   │                                                 │
   request ────►   │  build RiskKey                                  │
                   │  collect SyncDeltas:                            │
                   │    • L0 reputation seed                         │
                   │    • L1 rule_engine output (Vec<rule_id,delta>) │
                   │    • L2 anomaly checks for THIS request         │
                   │  store.apply(key, sync_deltas, now)             │
                   │    └─► returns post-update RiskState            │
                   │  set X-WAF-Risk-Score header                    │
                   │  threshold gate → Action (Allow/Challenge/Block)│
                   └────────────────────────────────────────────────┘
                                  ▲
                                  │ fire-and-forget enqueue
                                  │
                   ┌──────────────┴─────────────────────────────────┐
                   │   AsyncIngestWorker (bounded MPSC channel)     │
                   │                                                │
   device_fp ─►    │  signal stream from FR-010/011/012:            │
   providers       │    BurstInterval, FpConflict, ZeroDepth, …     │
                   │  worker translates Signal → Contributor        │
                   │  store.apply(key, [contributor], now)          │
                   │  metrics: queue_depth, drop_count              │
                   └────────────────────────────────────────────────┘
```

> **WHY hybrid?** The signals from FR-010/011/012 fire from background captures (TLS handshake, behavioral aggregator) — they don't align 1:1 with the request currently in-flight. Forcing them through the sync hot path adds non-deterministic latency depending on capture state. Decoupling them via MPSC matches the `RiskAggregator` contract that already exists, preserves p99, and converges within ~one request-round-trip.
>
> **Common pitfall:** trying to make the *current* request see signals from the *current* request's TLS-handshake fingerprint capture. The capture happens at the TLS layer before HTTP routing — there is a small but real time delta. Don't fight physics. Score uses last-known state; convergence is fast enough that benchmarks pass.

### 3.4 Pattern: Identity Triple as `Arc<RwLock<RiskState>>`

The `{IP, device_fp, session}` triple is **three independent lookup keys pointing to the same state**. Triple lookup → take `max(score)` across the three. This kills two evasion patterns simultaneously:

- IP rotation, same JA4 → JA4 key still flagged
- JA4 randomization, same IP → IP key still flagged
- Both rotated, same session cookie → session key still flagged

```rust
pub struct RiskKey {
    pub peer_ip: IpAddr,
    pub fp_hash: u64,             // truncated hash of FpKey (existing type)
    pub session_id: Option<SessionId>,
}
```

> **WHY take the MAX, not the SUM, across the three keys?** A single actor must not be triple-counted. If the same person triggers a rule, we don't want it to add +50 to all three keys and get +150 effective score. Each key is a *view* of the same actor. Max captures "worst observed evidence under any identity facet".
>
> **Common pitfall:** keying state under each leg separately and then having three diverging scores. The store layout that fixes this (per spec §B.2): `Arc<RwLock<RiskState>>` shared across three `DashMap` indices via cloned `Arc`. Update once, all three indices see it.

### 3.5 Session ID — configurable cookie + WAF-issued fallback

Session is the third leg of the triple. Options chosen:

1. **Read upstream cookie**, name configurable (`session.cookie_name`, default tries common names: `session`, `PHPSESSID`, `JSESSIONID`, `connect.sid`).
2. **WAF-issued fallback**: when configured tier requires it AND no upstream cookie present, WAF mints a signed cookie (`X-WAF-Sid`) on response. Subsequent requests see it.
3. **None** when neither present — triple still works (`Option<SessionId>`); IP+fp legs carry the load.

> **WHY both?** Backends with sticky sessions (the typical case for FR-002 CRITICAL tier — login/OTP/deposit) emit cookies. We piggyback those for free. But cookieless flows (curl, first-ever request) still need *some* continuity beyond IP+fp — the WAF-issued cookie supplies it.
>
> **Pitfall:** never collide with backend's cookie name. WAF cookie name is `X-WAF-Sid` (configurable), httpOnly, SameSite=Lax, signed with HMAC.

### 3.6 Pattern: Threshold Gate as a Pure Function (FR-027)

```rust
// crates/waf-engine/src/risk/threshold.rs
pub fn decide(score: u8, cfg: &Thresholds, override_block: bool) -> WafAction {
    if override_block { return WafAction::Block; }     // FR-RS-102 high-confidence rule
    if score >= cfg.t_block { WafAction::Block }
    else if score >= cfg.t_allow { WafAction::Challenge }
    else { WafAction::Allow }
}
```

> **WHY pure?** Easy to unit-test exhaustively (boundary values, off-by-one). Easy to swap thresholds at runtime — `cfg` is read from `ArcSwap<Thresholds>` (already the codebase pattern for hot-reload).

### 3.7 Canary / Honeypot (FR-028) as a Special-Case Layer

Canary paths are configured (e.g. `/admin-test`, `/api-debug`). When matched:
- `store.force_max(key, now)` — sets all three keys' state to score=100 with `pinned_until_ms = now + ban_ttl`.
- Append IP to FR-008 dynamic blacklist via existing `BlockIpRepo`.
- Decision short-circuits to Block before threshold gate.

> **WHY a separate layer instead of a +100 delta?** A delta can be decayed away in 30 minutes. A canary hit is a confessed scanner — they should be banned for hours. `pinned_until_ms` floors the score during that window regardless of decay. Mirrors how `DynamicBanTable` already works in FR-005 phase-5.

---

## 4. Module Layout (Production)

```
crates/waf-engine/src/risk/
├── mod.rs                       # public surface: Scorer, RiskStore, types
├── key.rs                       # RiskKey, SessionId, fp_hash derivation
├── state.rs                     # RiskState, Contributor, ContributorKind
├── score.rs                     # Pure score-fold function (event → integer)
├── decay.rs                     # Pure decay function
├── threshold.rs                 # Pure threshold gate
├── tier.rs                      # Route → tier classifier (longest-prefix)
├── seed/                        # L0 reputation seed
│   ├── mod.rs
│   ├── tor.rs                   # Tor exit list
│   ├── asn.rs                   # IP→ASN trie
│   └── whitelist.rs             # short-circuit
├── anomaly/                     # L2 per-request anomaly detectors
│   ├── mod.rs
│   ├── ja4_ua_mismatch.rs
│   ├── xff_chain.rs
│   └── header_sanity.rs
├── velocity/                    # L2 sliding-window counters
│   ├── mod.rs
│   ├── window.rs                # ring-buffer, 1s buckets
│   └── sequence.rs              # Login→OTP→Withdrawal FSM
├── canary.rs                    # FR-028 honeypot layer
├── ingest/
│   ├── mod.rs
│   ├── aggregator_impl.rs       # impl RiskAggregator for ScoringAggregator
│   ├── signal_to_contributor.rs # Signal enum → Contributor mapping
│   └── worker.rs                # MPSC consumer worker
├── store/
│   ├── mod.rs
│   ├── store_trait.rs           # RiskStore trait + RiskKey traits
│   ├── memory.rs                # DashMap-based, single-node
│   ├── redis.rs                 # cluster, feature = "redis-store"
│   └── conformance.rs           # shared test suite (mirrors device_fp/identity/)
├── config.rs                    # YAML schema + ArcSwap hot-reload
├── reload.rs                    # notify-watcher (mirrors FR-005, FR-010)
└── tests/
    ├── lifecycle.rs
    ├── identity_triple.rs
    ├── threshold_boundaries.rs
    ├── reset_state.rs
    ├── canary.rs
    └── conformance_redis.rs     # gated on `redis-store`
```

> **WHY this many files?** Project rule: each file ≤200 LoC, kebab-case names, descriptive enough to be self-documenting under grep. The split mirrors `device_fp/` structure exactly so contributors don't context-switch between modules.

---

## 5. Acceptance-Criteria Coverage Table

Mapping every requirement to the artifact that satisfies it.

| Req | Where it lives | How |
|---|---|---|
| FR-025 (triple key) | `risk/key.rs` + `risk/store/memory.rs` | `RiskKey` struct; three `DashMap` indices share `Arc<RwLock<RiskState>>` |
| FR-025 (no per-request reset) | `risk/store/memory.rs` | TTL-based eviction (default 30 min idle); never per-request clear |
| FR-026 (increases — rule match) | `risk/score.rs` + rule engine plumbing | Rule output emits `Vec<(rule_id, delta)>`; folded as positive contributors |
| FR-026 (increases — failed challenge) | `risk/ingest/signal_to_contributor.rs` | Future Signal::ChallengeFailed → +20 |
| FR-026 (increases — anomaly) | `risk/anomaly/*` + `risk/ingest/` | Sync anomalies (header/XFF) inline; async via Signal enum |
| FR-026 (increases — suspicious ASN) | `risk/seed/asn.rs` | Datacenter/Tor/badASN add seed delta |
| FR-026 (increases — fp conflict) | `risk/ingest/signal_to_contributor.rs` | `Signal::FpConflict` → +20 contributor |
| FR-026 (decreases — successful challenge) | `risk/ingest/` | Future Signal::ChallengePassed → negative contributor |
| FR-026 (decreases — sustained normal) | `risk/decay.rs` | `decay(clean_streak, elapsed_seconds)` |
| FR-027 (thresholds, configurable) | `risk/threshold.rs` + `risk/config.rs` | `Thresholds { t_allow, t_block }` reload via ArcSwap |
| FR-028 (canary force max + block IP) | `risk/canary.rs` | `force_max` + append to `BlockIpRepo` |
| Performance ≤3ms p99 | Layered budget (§3.1), MPSC for async signals (§3.3) | Per-layer latency budgets enforced via `criterion` benches |
| Persistence across requests | `RiskStore` trait + memory + redis backends | TTL eviction, never per-request reset |
| Multi-node cluster | `redis-store` feature | Same trait, redis backend with atomic INCRBY scripts |

---

## 6. Common Pitfalls (production hazards seen in WAF projects)

> Listing these because the spec doc didn't enumerate them.

1. **Lock contention on the score state.** Naïve impl: one big `Mutex<HashMap<RiskKey, RiskState>>`. At 5k rps, every request blocks every other. **Fix:** `DashMap` (sharded; default 64 shards = 64-way parallelism) + per-state `parking_lot::RwLock` (cheap, no poison). Project rule already bans `std::sync::Mutex`.

2. **Score going stale because Redis writes are async-and-lost.** If we batch writes and a node crashes, scores reset. **Fix:** synchronous Redis SET with 100ms timeout in the apply path; on timeout fall back to memory cache for this node, log the divergence, continue. Resilience over perfection.

3. **Triple-counting.** Already covered (§3.4) — `Arc<RwLock>` shared across the three indices, NOT three independent states.

4. **Score-explosion via unbounded delta sums.** Adversary triggers rule N times in a millisecond → score = +500. **Fix:** clamp the *raw accumulator* per-request to `[0, 100]` BEFORE applying tier multiplier. Spec §B.3 already states this.

5. **Decay erasing legitimate evidence.** Attacker waits 30 min, score drops to 0, attack resumes. **Fix:** `MAX_DECAY=50`. Even a fully-decayed key retains 50 points of evidence until explicit reset/credit. Spec §A.1.7 already stipulates this; just don't be tempted to relax it during tuning.

6. **Whitelist short-circuit applied AFTER expensive layers.** Pure CPU waste. **Fix:** seed layer checks whitelist FIRST and returns score=0 immediately, bypassing all subsequent layers.

7. **Headers leaking score on cached responses.** FR-009 smart cache may serve responses bypassing the WAF check chain. **Fix:** cache key includes `score_band` (allow/challenge/block); cached responses still get the header injected from RiskState lookup at egress. (This is the integration point with FR-009 — flag for that team.)

8. **Forgetting that `reset_state` must be atomic.** Half-cleared store → half-evaluated requests get nonsense scores. **Fix:** `reset_all()` takes exclusive lock briefly (≤50ms target per spec §B.10), atomically swaps DashMap contents.

9. **HMAC secret regenerated on every restart.** Challenge tokens minted before restart become invalid → all clients re-challenged simultaneously → thundering herd. **Fix:** persist secret to file; regenerate only on first boot. Spec §A.1.8 FR-RS-085 covers this.

10. **MPSC channel unbounded.** Memory leak under attack. **Fix:** bounded channel (default 65536 capacity); on overflow drop-with-warn (matches existing `RiskAggregator` doc). Add a Prometheus counter `risk_ingest_dropped_total`.

---

## 7. Phasing (production rollout)

Built incrementally so we can ship FR-025 alone (minimum viable score), then layer richness without re-architecting.

| Phase | Scope | Verify |
|---|---|---|
| **P1** Skeleton | `RiskKey`, `RiskState`, `RiskStore` trait, memory backend, `Scorer` orchestrator stub, threshold gate, audit log integration | Unit tests on pure functions; integration test asserting `X-WAF-Risk-Score` header on every response |
| **P2** Reputation seed (L0) | `seed/` module: Tor list, ASN classifier, whitelist short-circuit, hot-reload | Microbenchmark <100µs/lookup; integration test with sample bad ASN |
| **P3** Rule deltas (L1) | Rule engine emits `Vec<(rule_id, delta)>`; scorer ingests | YAML rule schema extension; unit tests on rule matching → delta |
| **P4** Async ingest | `ScoringAggregator` impl + MPSC worker; wire `RiskBumpAction` (FR-005) and FR-010/011/012 signals | Existing tests continue passing; add property test on convergence |
| **P5** Anomaly + velocity (L2) | XFF chain, header sanity, sliding-window counters, sequence detector | Lifecycle test: attack → score rises → normal traffic → score decays |
| **P6** Canary (FR-028) | `canary.rs` + integration with `BlockIpRepo` | Test: GET `/admin-test` → score=100, IP appears in block list |
| **P7** Redis backend | `store/redis.rs` behind `redis-store` feature; conformance suite | Same conformance tests as memory backend; cluster integration test |
| **P8** Challenge credit (FR-006 dependency) | `challenge_credit/` module; HMAC token; consumed-nonce LRU | Replay-attack test; binding-mismatch test |
| **P9** Tuning + dashboard | Replay harness; dashboard live feed; metrics export | Replay 24h of audit log, compare scores; < 1% deviation |

> **WHY this order?** Each phase compiles and runs. P1 alone passes the BG-01 gate (header on every response). P5 passes BG-11 (lifecycle moves on benign traffic). P7 makes it cluster-ready. P8 closes FR-027 fully (challenge actually reduces score). Skipping ahead causes integration debt.

---

## 8. Risks & Mitigations

| Risk | Severity | Mitigation |
|---|---|---|
| Redis becomes unavailable mid-attack | High | Fail-open on MEDIUM/CATCH_ALL, fail-closed on CRITICAL (NFR-RS-015). Memory backend stays in process as last-resort cache. |
| MPSC backpressure under DDoS — signals dropped | Medium | Drop-with-warn is acceptable (synth signals are best-effort). Sync deltas (rules, seed) keep flowing in hot path. |
| Tier multiplier stacks with rule-action override → score=120 → clamp to 100 → loses ordering info | Low | Always retain pre-clamp `raw_score` in audit log for debugging; runtime decision uses clamped value. |
| Session cookie collision with backend | Medium | Cookie name configurable; default `X-WAF-Sid` is non-standard. Add startup check that warns if upstream cookie of same name observed. |
| Score becomes oracle for attackers (`X-WAF-Risk-Score` header reveals state) | Medium | Header is mandated by interop contract (BG-01) — cannot remove. Mitigate by adding small jitter (±2) on egress in production mode (deterministic mode for benchmarks). Defer this to phase tuning. |
| Decay tuning fails replay test | Medium | Replay harness in P9 gates parameter changes. Don't ship without a baseline replay. |
| Triple-key max gets exploited via session-cookie spoofing (attacker sets known-good session) | Medium | `SessionId` includes WAF-side HMAC component; spoofed cookie fails verification → treated as `None`. |

---

## 9. Open Questions (for clarification before /ck:plan)

1. **Audit log integration:** the existing pipeline uses VictoriaLogs (`260502-victorialog` plan). Does the risk module emit its own audit event, or piggyback the existing per-request log entry with extra fields (`risk_score`, `score_seed`, `contributors`)? — recommend **piggyback** to avoid double writes.
2. **Session cookie name discovery:** should we configure ONE cookie name per host, or auto-detect from a list and remember per-host? — recommend **per-host config**, with a sensible default list as fallback.
3. **HMAC secret rotation:** spec says persist; what's the rotation policy? Quarterly? On `reset_state` it must NOT regenerate (FR-RS-113). — recommend **manual rotation only, documented in ops runbook**, no automatic rotation.
4. **LSH fuzzy JA4 (FR-RS-041):** in scope for production v1 or defer? Adds rensa dep + L3 latency layer. — recommend **defer to P9** (feature-flagged), v1 ships without it.
5. **Tier multiplier float rounding:** spec uses `f32` at the very last step. Risk of platform-divergent rounding causing benchmark non-determinism. — recommend **integer math** via `(score * mult_x100 + 50) / 100` to keep determinism (FR-RS-014 / BG-10).

---

## 10. Recommended Decision

**Go forward with:**
- Full spec scope (FR-RS-001..125), phased per §7.
- Trait + memory + redis backends mirroring existing `IdentityStore`/`CounterStore`.
- Configurable cookie + WAF-issued fallback for session.
- Hybrid sync-read/async-submit wired through existing `RiskAggregator` seam.
- Integer-only score arithmetic (no `f32`) to lock determinism.

**Defer to follow-up plans:**
- FR-006 challenge engine (P8 dependency lives here, but the JS-PoW implementation is its own ticket).
- FR-RS-041 LSH fuzzy match (rensa crate, performance-sensitive).
- Dashboard live-feed visualization (P9 — feeds the FR-029/030 dashboard).

---

## Key Takeaways

- **Don't reinvent seams** — `RiskAggregator`, `Signal`, `IdentityStore`, `CounterStore` already exist and are designed for FR-025. Wire into them.
- **Layered pipeline + event-sourced state** is the production pattern. Pure functions per layer; bounded contributors per state.
- **Triple-key takes max, not sum** — three views of one actor, not three actors.
- **Hybrid ingest** — sync deltas in hot path (rules, seed, per-request anomaly); async signals via MPSC for fire-and-forget device-fp output.
- **Decay is bounded** — `MAX_DECAY=50` prevents adversary from waiting out the score.
- **Phase incrementally** — P1 alone satisfies BG-01; later phases add richness without re-architecting.
- **Integer math everywhere** — float rounding on tier multiplier breaks BG-10 determinism. Use `(s * mult_x100 + 50) / 100`.

---

## Learn More

- Existing seams: `crates/waf-engine/src/device_fp/aggregator.rs` (the trait this design plugs into).
- Pattern reference: Martin Fowler — [Event Sourcing](https://martinfowler.com/eaaDev/EventSourcing.html), [CQRS](https://martinfowler.com/bliki/CQRS.html).
- DashMap concurrency: [docs.rs/dashmap](https://docs.rs/dashmap) — sharded concurrent map used elsewhere in this codebase.
- Cloudflare's writeup on WAF risk scoring: [Cloudflare Bot Score docs](https://developers.cloudflare.com/bots/concepts/bot-score/) (concept, not implementation).
- Prior art in this repo: `plans/reports/research-260430-1639-risk-score-design-brainstorm.md` and `plans/reports/spec-260430-1709-risk-score-requirements-and-tech-spec.md`.
