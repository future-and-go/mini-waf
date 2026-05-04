# FR-012 Transaction Velocity & Sequence — Brainstorm Report

**Date:** 2026-05-04
**Source req:** `analysis/requirements.md` §3.1 FR-012
**Status:** Design approved

---

## 1. Problem Statement

Detect cross-endpoint behavioral anomalies invisible to single-request checks:
- Login→OTP→Deposit timing too fast (script/bot)
- Withdrawal velocity (N withdrawals in T sec → fraud)
- Rapid limit-change bursts (account-takeover precursor)

Output = `Signal` to existing `RiskAggregator`; risk engine (FR-025/27) decides Allow/Challenge/Block.

---

## 2. Acceptance Criteria Coverage

| FR-012 criterion | Mechanism |
|---|---|
| Cross-endpoint tracking | EndpointRoleTagger + per-session ring buffer |
| Login→OTP→Deposit timing | SequenceTimingClassifier (min interval per transition) |
| Withdrawal velocity | WithdrawalVelocityClassifier (count in window) |
| Rapid limit-change | LimitChangeBurstClassifier (count in window) |
| Hot-reload (FR-021) | ArcSwap<TxVelocityConfig> watched via `notify` |
| Per-tier scoping (FR-023) | Per-tier thresholds in YAML |
| Risk integration (FR-025/27) | Emit `Signal` to `RiskAggregator` |
| p99 ≤ 5ms (NFR) | DashMap O(1) + 16-slot scan + 3 classifiers ≈ <50µs |

---

## 3. Approaches Evaluated

| # | Approach | Verdict |
|---|---|---|
| A | **Mirror FR-011 BehaviorRecorder** (DashMap + ring buffer + Classifier strategy) | ✅ Chosen — DRY, proven in this codebase, low risk |
| B | Full state-machine per sequence (Login→OTP→Deposit FSM) | ❌ Over-engineered; sliding-window suffices; YAGNI |
| C | Event-bus + actor model | ❌ Hackathon overkill; new infrastructure |
| D | Reuse rate-limit (FR-004) store with new keys | ❌ Semantics mismatch; rate-limit is counter-only, FR-012 needs ordered events |

---

## 4. Final Design

### 4.1 Architecture

```
Request ─► EndpointRoleTagger (YAML-driven)
            └─► SessionKey = cookie ?? device_fp
                  └─► TxSequenceRecorder (DashMap<SessionKey, ActorTx>)
                        ├─ append (role, ts_ms, status) → 16-slot ring buffer
                        └─ run Classifiers:
                             ├─ SequenceTimingClassifier
                             ├─ WithdrawalVelocityClassifier
                             └─ LimitChangeBurstClassifier
                                   └─► RiskAggregator (existing)
```

Janitor task purges idle entries (TTL ≥ longest window, default 10 min).

### 4.2 Module Layout

```
crates/waf-engine/src/checks/tx_velocity/
├── mod.rs                 // Check trait impl, plug into engine.rs:111
├── config.rs              // YAML schema + serde
├── role_tagger.rs         // path regex → EndpointRole
├── recorder.rs            // DashMap + ring buffer + janitor
├── classifier.rs          // Classifier trait
└── classifiers/
    ├── sequence_timing.rs
    ├── withdrawal_velocity.rs
    └── limit_change_burst.rs
```

### 4.3 Design Patterns

| Pattern | Usage | Justification |
|---|---|---|
| Strategy | `Classifier` trait + impls | Add new patterns w/o touching recorder; mirrors FR-011 |
| Repository (in-mem) | `TxStore = DashMap<SessionKey, ActorTx>` | Hides storage; future Redis swap if needed |
| Ring buffer | `events: ArrayVec<Event, 16>` | O(1) append, bounded mem per session |
| Builder/Config | `ArcSwap<TxVelocityConfig>` + `notify` | Matches FR-004 hot-reload |
| Observer (light) | Recorder.append → fan-out to Classifiers | Decouples ingest from detection |

### 4.4 Key Types (sketch)

```rust
enum EndpointRole { Login, Otp, Deposit, Withdrawal, LimitChange, None }

struct Event { role: EndpointRole, ts_ms: u64, ok: bool }

struct ActorTx {
    events: ArrayVec<Event, 16>,
    last_signal_ms: u64,  // dedupe
}

trait Classifier: Send + Sync {
    fn evaluate(&self, actor: &ActorTx, now_ms: u64) -> Option<Signal>;
}
```

`SessionKey = (host, session_cookie)` else `(host, fp_key)`. Reuses cookie extraction from `crates/waf-engine/src/checks/rate_limit/check.rs:90`.

### 4.5 Config (YAML)

```yaml
tx_velocity:
  endpoint_roles:
    - { role: login,        path: "^/api/login$" }
    - { role: otp,          path: "^/api/otp" }
    - { role: deposit,      path: "^/api/deposit" }
    - { role: withdrawal,   path: "^/api/withdraw" }
    - { role: limit_change, path: "^/api/account/limit" }
  classifiers:
    sequence_timing:
      min_login_to_otp_ms: 1500
      min_otp_to_deposit_ms: 2000
    withdrawal_velocity:
      max_per_window: 3
      window_sec: 60
    limit_change_burst:
      max_per_window: 2
      window_sec: 300
  signal_cooldown_ms: 5000
```

### 4.6 Decisions (from clarifications)

- Endpoint config: **YAML, hot-reloadable**
- Identity key: **session cookie + device_fp fallback**
- State scope: **node-local DashMap, session affinity via `cluster_forward`**
- Action: **Signal-only → RiskAggregator** (no direct block)

---

## 5. Risks & Mitigations

| Risk | Mitigation |
|---|---|
| Memory growth (many sessions) | Janitor TTL purge (FR-011 pattern, `recorder.rs:113`) |
| False positives on fast humans | Conservative defaults + cumulative-risk threshold (FR-025) |
| Cluster: session lands on different node | Session affinity via `cluster_forward.rs`; documented limit |
| Cookie-less evasion | device_fp fallback in SessionKey |
| Hot-reload race | `ArcSwap` atomic swap (FR-004 precedent) |

---

## 6. Out of Scope (YAGNI)

- Persistent state across restarts (ephemeral OK)
- Cross-node Redis sync (deferred)
- ML scoring (FR-046, separate P1)
- Per-authenticated-user identity (session cookie suffices)

---

## 7. Success Metrics

- Detects Login→OTP→Deposit completed in <3s (synthetic test)
- Detects ≥3 withdrawals/60s
- Detects ≥2 limit-changes/300s
- Per-request overhead <100µs (measured via `cargo bench`)
- Zero false positives on legitimate baseline traffic suite
- Hot-reload of `tx_velocity` config without restart

---

## 8. Next Steps

1. Run `/ck:plan` with this report as context → produce phased implementation plan
2. Phase order suggestion:
   - P1: config + role_tagger + recorder skeleton
   - P2: 3 classifiers + signal emission
   - P3: integrate into `engine.rs` checker chain
   - P4: tests (unit + e2e via existing test harness)
   - P5: docs update (`docs/request-pipeline.md`, new `docs/transaction-velocity.md`)

---

## 9. Unresolved Questions

1. Default endpoint paths for hackathon backend — confirm with organizer's sandbox routes (req §9 Q1)
2. Should signal cooldown be per-classifier or global? Default global 5s, revisit if noisy
3. Cluster session affinity — verify `cluster_forward` keys on session cookie; if not, file follow-up
