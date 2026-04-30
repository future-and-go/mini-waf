---
title: "Risk Score — Requirements & Technical Spec"
date: 2026-04-30 17:09 +04
type: spec
slug: risk-score-requirements-and-tech-spec
scope: risk-score subsystem only
upstream: plans/reports/research-260430-1639-risk-score-design-brainstorm.md
status: stand-alone reference doc
---

# Risk Score — Requirements & Technical Spec

Distilled from the brainstorm at `plans/reports/research-260430-1639-risk-score-design-brainstorm.md`. **Scope: risk-score subsystem only.** Adjacent systems (rule-engine YAML schema, challenge HTTP transport, control-plane endpoints, dashboard, audit-log writer) are referenced where they cross the boundary but not specified here.

ID conventions: `FR-RS-NNN` = functional requirement, `NFR-RS-NNN` = non-functional, `BG-NN` = bench-compliance gate (1:1 mapping to brainstorm §1 C1–C12).

---

# PART A — REQUIREMENTS

## A.1 Functional Requirements

### A.1.1 Identity & Keying

| ID | Requirement | Source |
|----|-------------|--------|
| FR-RS-001 | Risk state MUST be keyed on the triple `(peer_ip, ja4_hash, session_id)`. Score for a request = `max(score(peer_ip), score(ja4_hash), score(session_id))`. | brainstorm §3.1 |
| FR-RS-002 | `peer_ip` MUST come from TCP `peer_addr` only. `X-Forwarded-For` and `X-Real-IP` MUST NOT be used as identity. | BG-08 / interop §6 |
| FR-RS-003 | Loopback addresses `127.0.0.X` MUST be treated as distinct identities (X varies per benchmark client). | BG-08 |
| FR-RS-004 | `ja4_hash` MUST be a 64-bit truncated hash of the canonical JA4 string computed from the inner ClientHello (post-ECH if applicable). | brainstorm §2.1, Q8 |
| FR-RS-005 | `session_id` is `Some(s)` only when (a) WAF-issued cookie present, OR (b) upstream session cookie present. Otherwise `None`. The triple is still functional with `None` in the third slot. | Q3 |
| FR-RS-006 | Whitelisted IP/FQDN MUST short-circuit the score to `0` regardless of all other layers. | FR-008 |

### A.1.2 Score Composition

| ID | Requirement | Source |
|----|-------------|--------|
| FR-RS-010 | Score is a single integer in `[0, 100]` after clamp. | BG-01 |
| FR-RS-011 | Pre-clamp accumulator MUST be `seed + Σ rule_deltas + Σ anomaly_deltas + Σ velocity_deltas − decay`. | brainstorm §3.2 |
| FR-RS-012 | After clamp, tier multiplier MUST be applied per request route. Result re-clamped to `[0, 100]`. | brainstorm §3.9 |
| FR-RS-013 | Score MUST reflect state **after** evaluating the current request (not before). | BG-02 |
| FR-RS-014 | Score MUST be computed deterministically: same input + same store state → same output. No randomness in the hot path. | BG-10 |
| FR-RS-015 | Score logic MUST be identical in `enforce` and `log_only` modes. Only the *enforcement gate* differs. | BG-07 |
| FR-RS-016 | Honeypot/canary path hit MUST force score to `100` and persist the offending key on a hot-blacklist. | FR-028 |

### A.1.3 Reputation Seed (Layer 0)

| ID | Requirement | Source |
|----|-------------|--------|
| FR-RS-020 | Tor exit list match → seed `+30`. List loaded at startup from configurable file path. | brainstorm §3.3, FR-042 |
| FR-RS-021 | Bad-ASN list match → seed `+15`. | FR-007 |
| FR-RS-022 | Datacenter ASN classification on CRITICAL-tier route → seed `+10`. | brainstorm §3.3 |
| FR-RS-023 | Residential ASN → seed `+0`. Mobile ASN with abnormal concurrency → handled in §A.1.5 anomaly. | — |
| FR-RS-024 | ASN lookup MUST come from a local file (MaxMind .mmdb provided by user, OR public-BGP-derived radix trie shipped with binary). MUST NOT bundle MaxMind .mmdb in our binary. | Q2 |
| FR-RS-025 | Seed is computed once on first observation of a key, cached, refreshed on Tor-list TTL (1h). | brainstorm §7 |

### A.1.4 Rule Deltas (Layer 1)

| ID | Requirement | Source |
|----|-------------|--------|
| FR-RS-030 | Rule engine emits `Vec<(rule_id, delta)>` per request. Delta is signed `i16`. | FR-022 |
| FR-RS-031 | Rule action (`allow/challenge/block`) is advisory; the threshold gate selects final action. **Exception:** rules with `action: block` and confidence-flag set bypass threshold (high-confidence block). | brainstorm §3.4 |
| FR-RS-032 | Each delta MUST persist with its `rule_id` and `ts_ms` so the dominant contributor can be selected for `X-WAF-Rule-Id`. | BG-09 |

### A.1.5 Anomaly Deltas (Layer 2)

| ID | Anomaly | Δ | Source |
|----|---------|---|--------|
| FR-RS-040 | JA4 in known-bad cluster (exact match) | `+20` | §2.1 |
| FR-RS-041 | JA4 in fuzzy bad cluster (LSH Jaccard ≥ 0.8) | `+10` | §2.3, Q9 |
| FR-RS-042 | JA4 ↔ User-Agent family mismatch | `+15` | §2.1 |
| FR-RS-043 | Missing `Accept-Language` + non-browser JA4 family | `+10` | §2.1 |
| FR-RS-044 | XFF chain length > 2 | `+10` | FR-007 |
| FR-RS-045 | XFF claims RFC1918 IP while peer is public | `+15` | FR-017 |
| FR-RS-046 | Same `ja4_hash` from > 5 distinct `peer_ip` in 60s | `+20` | FR-010 |
| FR-RS-047 | Same `session_id` from > 3 distinct `ja4_hash` in 60s | `+25` | session theft |
| FR-RS-048 | Inter-request interval `<` 50ms for 5+ consecutive requests | `+15` | FR-011 |
| FR-RS-049 | Zero-depth session (1 path, no Referer) on CRITICAL tier | `+10` | FR-011 |
| FR-RS-050 | h2 SETTINGS frame fingerprint mismatches UA-claimed browser (Tier-A bonus) | `+10` | FR-010 |
| FR-RS-051 | Mobile ASN + > 100 concurrent sessions same key | `+15` | brainstorm §3.3 |
| FR-RS-052 | Decoded payload nested encoding > 2 layers | `+10` | evasion |

### A.1.6 Velocity / Sequence Deltas (Layer 2 cont.)

| ID | Pattern | Δ | Source |
|----|---------|---|--------|
| FR-RS-060 | Per-tier req-rate threshold exceeded | `+10` per overshoot decade | FR-004 |
| FR-RS-061 | > 3 failed logins on same key in 5 min | `+20` | FR-018 |
| FR-RS-062 | Login → OTP → Withdrawal sequence end-to-end < 30s | `+25` | FR-012 |
| FR-RS-063 | > 10 distinct paths in 60s (recon scan) | `+15` | FR-019 |
| FR-RS-064 | Client-attributable 4xx > 10 in 60s AND distinct paths > 5 | `+15` | Q7 |
| FR-RS-065 | OPTIONS-method abuse pattern | `+5` | FR-019 |
| FR-RS-066 | Velocity counters MUST use sliding windows of 60s and 600s, two counters per key. | brainstorm §3.6 |
| FR-RS-067 | 5xx responses MUST NOT trigger any score boost. | Q7 |

### A.1.7 Decay (Layer 3 — score reduction)

| ID | Requirement | Source |
|----|-------------|--------|
| FR-RS-070 | Decay MUST be bounded: at most `MAX_DECAY = 50` points removed without an explicit `reset_state` or successful challenge. | brainstorm §3.7, BG-11 |
| FR-RS-071 | Decay rate combines per-clean-request and wall-clock components: `decay = floor(clean_streak / 5) + floor(elapsed_seconds / 30)`, capped at `MAX_DECAY`. | brainstorm §3.7 |
| FR-RS-072 | A request that contributes any positive delta MUST reset `clean_streak` to 0 and update `last_bad_ms`. | brainstorm §3.7 |
| FR-RS-073 | Decay parameters MUST be config-driven (not hard-coded) so tuning via replay harness is possible without rebuild. | Q4 |

### A.1.8 Challenge Credit

| ID | Requirement | Source |
|----|-------------|--------|
| FR-RS-080 | Challenge token format: `b64(nonce) \|\| ts \|\| difficulty \|\| hmac(secret, nonce \|\| ts \|\| difficulty \|\| peer_ip \|\| ja4_hash)`. HMAC MUST bind ALL params (lesson from CVE-2025-68113). | Q6 |
| FR-RS-081 | Credit applied only when ALL of: HMAC verifies, `now − ts < 300s`, PoW nonce meets stated difficulty, nonce not in consumed-set, submitting client `(peer_ip, ja4_hash)` matches HMAC binding. | Q6 |
| FR-RS-082 | Credit values: JS challenge `−15`; PoW d=4 `−20`, d=5 `−25`, d=6 `−30`. Replay attempt (consumed nonce) `+30` penalty. | Q6 |
| FR-RS-083 | After a credit applies, the same key MUST send 5+ clean requests before another credit can apply (anti-grinding). | Q6 |
| FR-RS-084 | Consumed-nonce set MUST be a bounded LRU (≤ 100k entries, 5min TTL). | Q6 |
| FR-RS-085 | HMAC secret MUST persist across WAF restarts (file at startup; regenerate only on first boot). `reset_state` MUST NOT regenerate the secret. | Q-new-2 |

### A.1.9 Tier Multiplier

| ID | Requirement | Source |
|----|-------------|--------|
| FR-RS-090 | Routes MUST be classified into one of `CRITICAL`, `HIGH`, `MEDIUM`, `CATCH_ALL` via a `tiers:` block in `waf.yaml` using longest-prefix-match. | Q5 |
| FR-RS-091 | Multipliers: CRITICAL `1.2`, HIGH `1.1`, MEDIUM `1.0`, CATCH_ALL `0.8`. | brainstorm §3.9 |
| FR-RS-092 | Multiplier applied **after** clamp to `[0,100]`, then re-clamped. Result is the final `X-WAF-Risk-Score`. | brainstorm §3.9 |

### A.1.10 Decision Thresholds

| ID | Requirement | Source |
|----|-------------|--------|
| FR-RS-100 | Default thresholds: `t_allow = 30`, `t_block = 70`. MUST be overridable via config. | FR-027, BG-12 |
| FR-RS-101 | Action selection: `score < t_allow` → `allow`; `t_allow ≤ score < t_block` → `challenge`; `score ≥ t_block` → `block`. | FR-027 |
| FR-RS-102 | High-confidence block rule (FR-RS-031 exception) MUST override threshold and produce `block`. | brainstorm §3.4 |
| FR-RS-103 | When mode = `log_only`, the action selection MUST produce the intended action (for header), but enforcement MUST NOT apply. | BG-07 |

### A.1.11 Storage & Lifecycle

| ID | Requirement | Source |
|----|-------------|--------|
| FR-RS-110 | Risk store MUST be in-memory only (no disk persistence required). | scope |
| FR-RS-111 | TTL eviction: keys idle for > 30 min MUST be removed by background sweeper. | brainstorm §5 |
| FR-RS-112 | `reset_state` MUST clear all risk store maps synchronously, atomically, before returning success. | BG-06 |
| FR-RS-113 | `reset_state` MUST NOT touch the audit log file or HMAC secret. | BG-06 / Q-new-2 |
| FR-RS-114 | Concurrent updates to the same key MUST be serialized (per-state lock) so score is monotonic across simultaneous requests. | brainstorm §7 |

### A.1.12 Headers & Audit Output

| ID | Requirement | Source |
|----|-------------|--------|
| FR-RS-120 | `X-WAF-Risk-Score` (integer 0–100) MUST appear on every response: `allow`, `block`, `challenge`, `rate_limit`, `timeout`, `circuit_breaker`. | BG-01 |
| FR-RS-121 | `X-WAF-Rule-Id` MUST be the dominant contributor's id, or `none` when score is purely seed/decay-driven. | BG-09 |
| FR-RS-122 | `X-WAF-Mode` MUST reflect the mode of the policy that drove the dominant contributor. | interop §5.3 |
| FR-RS-123 | Optional bonus headers: `X-WAF-JA4` (full string), `X-WAF-JA4-Hash` (u64 hex). | Q1 |
| FR-RS-124 | Audit log entry per request MUST include at minimum: `request_id`, `ts_ms`, `ip`, `method`, `path`, `action`, `risk_score`, `mode`. | interop §6 |
| FR-RS-125 | Audit log SHOULD include score breakdown: `score_seed`, `score_rule_delta`, `score_anomaly_delta`, `score_velocity_delta`, `score_decay`, `contributors[]`. (Bonus observability.) | brainstorm §6 |
| FR-RS-126 | `request_id` in audit log MUST equal `X-WAF-Request-Id` 1:1. | interop §5.3 |

---

## A.2 Non-Functional Requirements

| ID | Category | Requirement |
|----|----------|-------------|
| NFR-RS-001 | Performance | p99 latency contribution from full risk-score evaluation MUST be ≤ 3ms at 5,000 rps (leaving 2ms budget for the rest of the WAF pipeline). |
| NFR-RS-002 | Performance | L0 (reputation seed) MUST be ≤ 100µs per request. |
| NFR-RS-003 | Performance | L1 (rule deltas application) MUST be ≤ 1ms per request. |
| NFR-RS-004 | Performance | L2 (anomaly + velocity) MUST be ≤ 1ms per request. |
| NFR-RS-005 | Performance | L3 (LSH fuzzy match — bonus path) MUST be ≤ 2ms when invoked, AND MUST only invoke when score ∈ [25, 75]. |
| NFR-RS-006 | Memory | Risk store MUST stay under 256MB at 1M unique keys with 30-min TTL. |
| NFR-RS-007 | Memory | Consumed-nonce LRU MUST stay under 16MB. |
| NFR-RS-008 | Determinism | No `rand::*` usage in hot path. Any pseudo-random derivation MUST seed from a stable per-run salt. |
| NFR-RS-009 | Concurrency | All shared maps MUST use sharded concurrent containers (e.g., `dashmap::DashMap`) and per-state `parking_lot::RwLock`. NO `std::sync::Mutex`. |
| NFR-RS-010 | Safety | NO `.unwrap()` / `.expect()` / `panic!` / `todo!` / `unimplemented!` outside `#[cfg(test)]`. (Project Iron Rule #1, #3.) |
| NFR-RS-011 | Configurability | Thresholds, decay parameters, delta values for all signals, tier multipliers — ALL config-driven via `waf.yaml`. |
| NFR-RS-012 | Observability | Every score change MUST be attributable: contributor list with `(rule_id, delta, ts_ms)` retained for at least the last 8 contributors per key. |
| NFR-RS-013 | Testability | Pure-function score core (no I/O, no time except injected) so unit tests can drive deterministic scenarios. |
| NFR-RS-014 | Privacy | No secrets, no raw credentials, no session tokens in logs/headers. JA4 is allowed (not PII per Q1). |
| NFR-RS-015 | Resilience | If the risk store is unavailable (e.g., poisoned shard), the engine MUST fail closed on CRITICAL tier (return 503), fail open on MEDIUM/CATCH_ALL. | 

---

## A.3 Bench-Compliance Gates (verbatim from brainstorm §1)

These are pass/fail per the interop contract. Each maps to one or more FR-RS above.

| ID | Gate | Mapped FR-RS |
|----|------|--------------|
| BG-01 | `X-WAF-Risk-Score` int 0–100 on every response | FR-RS-010, 120 |
| BG-02 | Score reflects post-current-request state | FR-RS-013 |
| BG-03 | Cumulative per `{IP+device_fp+session}`, not per-request | FR-RS-001 |
| BG-04 | Increases on rule/challenge-fail/anomaly/ASN/fp-conflict | A.1.4–A.1.6 |
| BG-05 | Decreases on challenge success + sustained normal | A.1.7, A.1.8 |
| BG-06 | `reset_state` clears risk; preserves audit log | FR-RS-112, 113 |
| BG-07 | `log_only`: same evaluation, no enforcement | FR-RS-015, 103 |
| BG-08 | IP = peer_addr, NOT XFF; `127.0.0.X` distinct | FR-RS-002, 003 |
| BG-09 | `X-WAF-Rule-Id` = dominant contributor or `none` | FR-RS-121 |
| BG-10 | Deterministic (same in → same out) | FR-RS-014, NFR-RS-008 |
| BG-11 | Score moves on benign traffic (lifecycle) | FR-RS-070–073 |
| BG-12 | Thresholds configurable | FR-RS-100, NFR-RS-011 |

---

# PART B — TECHNICAL SPECIFICATION

## B.1 Module Layout

```
crates/waf-engine/src/risk/
├── mod.rs                          # public surface
├── key.rs                          # RiskKey type, hashing, lookup helpers
├── state.rs                        # RiskState, Contributor
├── store.rs                        # RiskStore (DashMap-based, triple-indexed)
├── reputation.rs                   # L0: Tor list, ASN classifier, IP→ASN trie
├── rules_apply.rs                  # L1: applies rule-engine outputs to score
├── anomaly.rs                      # L2: JA4↔UA, header sanity, fp conflict
├── velocity.rs                     # L2: sliding-window counters, sequence detector
├── lsh.rs                          # L3 (optional): rensa-based fuzzy JA4 match
├── decay.rs                        # decay function (pure)
├── challenge_credit.rs             # PoW token verify, consumed-nonce LRU, credit
├── tier.rs                         # route → tier classifier (longest-prefix)
├── thresholds.rs                   # decision gate, action mapping
├── score.rs                        # orchestrator: assembles all layers
└── tests/
    ├── lifecycle.rs                # accumulate / decay / reset
    ├── identity.rs                 # triple-key max-score
    ├── log_only_invariance.rs      # score identical in both modes
    ├── replay_harness.rs           # consumes waf_audit.log, recomputes
    └── property.rs                 # proptest: clamp invariants, monotonicity
```

File names use `snake_case` per Rust convention. All files target ≤200 LoC; split when exceeded (project rule).

## B.2 Data Types

```rust
// crates/waf-engine/src/risk/key.rs
#[derive(Clone, Hash, Eq, PartialEq, Debug)]
pub struct RiskKey {
    pub peer_ip: std::net::IpAddr,
    pub ja4_hash: u64,
    pub session_id: Option<SessionId>,
}

#[derive(Clone, Hash, Eq, PartialEq, Debug)]
pub struct SessionId(pub compact_str::CompactString); // "<uuid>.<hmac>"

// crates/waf-engine/src/risk/state.rs
pub struct RiskState {
    pub score_post_tier: u8,             // final 0..=100
    pub raw_score: i32,                  // pre-clamp, pre-tier
    pub seed: i16,                       // L0 contribution (cached)
    pub last_seen_ms: u64,
    pub last_bad_ms: u64,
    pub clean_streak: u32,
    pub contributors: smallvec::SmallVec<[Contributor; 8]>,
    pub credit_streak_clean: u8,         // 0..=5, counts toward FR-RS-083
}

#[derive(Clone, Debug)]
pub struct Contributor {
    pub rule_id: compact_str::CompactString,
    pub delta: i16,
    pub ts_ms: u64,
}

// crates/waf-engine/src/risk/store.rs
pub struct RiskStore {
    by_ip:      dashmap::DashMap<IpAddr,    Arc<parking_lot::RwLock<RiskState>>>,
    by_ja4:     dashmap::DashMap<u64,       Vec<Weak<parking_lot::RwLock<RiskState>>>>,
    by_session: dashmap::DashMap<SessionId, Arc<parking_lot::RwLock<RiskState>>>,
    consumed_nonces: dashmap::DashMap<u128, u64>, // nonce → expiry_ms
    hmac_secret: Arc<[u8; 32]>,
}
```

Notes:
- `parking_lot` mandated by project rule; no `std::sync::Mutex`.
- `compact_str::CompactString` for short IDs to avoid heap allocation.
- `smallvec::SmallVec<[Contributor; 8]>` keeps the contributor history inline for ≤8 entries (covers >95% of cases).

## B.3 Score Formula (final, normative)

```
let raw = seed
        + sum(rule_deltas)
        + sum(anomaly_deltas)
        + sum(velocity_deltas)
        - decay(clean_streak, elapsed_seconds);

let clamped: u8 = raw.clamp(0, 100) as u8;

let post_tier: u8 = ((clamped as f32) * tier_multiplier(route))
                      .round()
                      .clamp(0.0, 100.0) as u8;
```

Floating-point used only at the very last step (single multiply) — kept deterministic by rounding mode. All sums are `i32`.

## B.4 Concrete Parameters (initial values; all config-driven)

| Param | Default | Config key |
|-------|---------|------------|
| `t_allow` | 30 | `risk.thresholds.allow` |
| `t_block` | 70 | `risk.thresholds.block` |
| `MAX_DECAY` | 50 | `risk.decay.max` |
| Per-clean-request decay rate | 1 per 5 reqs | `risk.decay.per_clean_requests` |
| Wall-clock decay rate | 1 per 30s | `risk.decay.per_seconds` |
| Idle TTL | 1800s | `risk.store.idle_ttl_seconds` |
| Tor list refresh | 3600s | `risk.tor.refresh_seconds` |
| Consumed-nonce LRU size | 100_000 | `risk.challenge.nonce_lru_size` |
| Consumed-nonce TTL | 300s | `risk.challenge.nonce_ttl_seconds` |
| Anti-grind clean reqs | 5 | `risk.challenge.anti_grind_clean` |
| Tier mults | 1.2/1.1/1.0/0.8 | `tiers.<NAME>.multiplier` |
| Velocity windows | 60s, 600s | `risk.velocity.windows` |

## B.5 Reputation Seed Implementation

- IP→ASN: radix trie of CIDR → `(asn, asn_name, kind)` where `kind ∈ {residential, datacenter, mobile, unknown}`.
  - Build at startup from MaxMind .mmdb if present, else from public-BGP fallback file.
  - Lookup: O(log n), <1µs measured target.
- Tor exit list: `HashSet<IpAddr>`. Reload every `risk.tor.refresh_seconds`. On reload, log `(added, removed, total)`.
- Whitelist: `HashSet<IpAddr> ∪ HashSet<FQDN>`. Whitelist hit short-circuits the entire pipeline.

## B.6 Anomaly + Velocity Implementation Notes

- JA4↔UA family check: maintain `enum Ja4Family { Browser, Curl, Python, Java, Go, Headless, Unknown }` derived from `ja4_a` prefix and known bad-cluster lookups. UA family derived from substring matching. Mismatch matrix is constant.
- Sliding-window counters: ring buffer of bucketed counts (1s buckets, 600 slots) per key. Old buckets reused circularly.
- Sequence detector (FR-RS-062): per-session FSM `Idle → Login → OTP → Withdrawal` with `entered_at_ms` per state. Trigger on terminal-state entry within 30s of Login.

## B.7 Decay Function (pure)

```rust
// crates/waf-engine/src/risk/decay.rs
pub fn decay(
    clean_streak: u32,
    elapsed_seconds: u64,
    cfg: &DecayConfig,
) -> i32 {
    let from_streak = (clean_streak / cfg.per_clean_requests) as i32;
    let from_clock  = (elapsed_seconds / cfg.per_seconds) as i32;
    (from_streak + from_clock).min(cfg.max as i32)
}
```

Pure function. Unit-testable without store. No allocations.

## B.8 Challenge Credit (token format)

```
TOKEN := base64url(NONCE_16B) || "." || base64url(TS_8B || DIFFICULTY_1B) || "." || base64url(HMAC_SHA256_32B)

HMAC_INPUT := NONCE_16B || TS_8B || DIFFICULTY_1B || PEER_IP_BYTES || JA4_HASH_8B
HMAC_KEY   := server-side persisted secret (32B, see FR-RS-085)
```

Verification steps must run in this order, returning early on any failure (constant-time-comparable):
1. Parse token; reject malformed.
2. `now_ms − ts_ms < 300_000`; else `expired`.
3. HMAC verify (constant-time); else `invalid`.
4. Verify submitting `(peer_ip, ja4_hash)` matches HMAC binding; else `bound_mismatch`.
5. Verify SHA256(nonce ‖ submitted_proof_nonce) has ≥ `difficulty` leading zero bits; else `unsolved`.
6. Atomic compare-and-insert into consumed-nonce LRU; if already present → `replay`, return `+30` penalty.
7. Apply credit per FR-RS-082.

## B.9 Tier Classification (longest-prefix match)

```rust
// crates/waf-engine/src/risk/tier.rs
pub struct TierClassifier {
    routes: radix_trie::Trie<String, Tier>,
    default_tier: Tier,
}
impl TierClassifier {
    pub fn classify(&self, path: &str) -> Tier {
        self.routes.get_ancestor_value(path)
            .copied()
            .unwrap_or(self.default_tier)
    }
}
```

Built once from `waf.yaml`. Read-only at runtime.

## B.10 Storage Operations Spec

| Operation | Concurrency | Latency target |
|-----------|-------------|----------------|
| `get_or_create(key)` | DashMap shard lock | <5µs |
| `update(key, fn)` | per-state RwLock write | <10µs |
| `read_for_header(key)` | per-state RwLock read | <2µs |
| `reset_all()` | exclusive across all maps; bench tool waits | <50ms (synchronous, atomic) |
| `evict_idle()` | background, low-priority | not on critical path |

`reset_all`: clears `by_ip`, `by_ja4`, `by_session`, `consumed_nonces`. **Does NOT** touch `hmac_secret`.

## B.11 Header & Audit Field Mapping

| Output | Source field |
|--------|--------------|
| `X-WAF-Risk-Score` | `RiskState.score_post_tier` |
| `X-WAF-Action` | computed by thresholds + override rules |
| `X-WAF-Rule-Id` | `top_contributor(state).rule_id` or `"none"` |
| `X-WAF-Mode` | per-rule `mode` of top contributor; default = engine-wide mode |
| `X-WAF-JA4` (bonus) | full JA4 string |
| `X-WAF-JA4-Hash` (bonus) | `format!("{:016x}", ja4_hash)` |
| audit `risk_score` | `score_post_tier` |
| audit `contributors` | last 8 `Contributor` entries |
| audit `score_seed` | `state.seed` |
| audit `score_rule_delta` | sum of contributors with `rule_id` starting `rule-` |
| audit `score_anomaly_delta` | sum of contributors with `rule_id` starting `anom-` |
| audit `score_velocity_delta` | sum of contributors with `rule_id` starting `vel-` |
| audit `score_decay` | latest decay value applied |

## B.12 Test Criteria

Unit tests (mandatory, ≥ 90% line coverage on `risk/` module):

- `lifecycle::accumulates_on_attack` — one SQLi rule-match → score ≥ 50.
- `lifecycle::decays_on_clean` — after attack, 25 clean requests → score drops below `t_allow`.
- `lifecycle::decay_is_bounded` — even with 100k clean requests + 24h wait, an initial-100 score never reaches 0 without explicit reset/credit.
- `identity::triple_max` — three keys with different scores; lookup returns the max.
- `identity::ip_rotation_detected` — same JA4 from 6 IPs in 60s → `+20` anomaly.
- `log_only_invariance` — same request stream in `enforce` vs `log_only` produces identical score, headers, audit entries; only enforcement effect differs.
- `reset_state::clears_score` — after reset, key score = seed (0 if new).
- `reset_state::preserves_log` — audit log file size + content unchanged.
- `challenge::credit_grants` — valid PoW reduces score by configured value.
- `challenge::replay_penalizes` — same nonce twice → second attempt adds penalty, no credit.
- `challenge::binding_enforced` — token bound to A's IP/JA4 cannot be redeemed by B.
- `tier::longest_prefix` — `/login/page` matches `/login`, scores under CRITICAL.
- `determinism::same_input` — replay 10k canned requests; score sequence identical across 100 runs.

Property tests (proptest):

- Score always within `[0, 100]` after clamp + tier multiplier.
- Decay never produces a negative final score.
- Adding a positive delta never decreases the final score (monotonic in deltas, ignoring decay).
- Whitelist override → score == 0, regardless of any other signal sequence.

Integration test:

- Replay harness consumes a real `waf_audit.log` and recomputes scores; produces a diff report. Used for tuning decay parameters (FR-RS-073).

## B.13 Performance Budget Per Layer (re-stated, normative)

| Layer | Budget | Skip condition |
|-------|--------|----------------|
| L0 (reputation seed) | ≤ 100µs | cached after first lookup per key |
| L1 (rule deltas) | ≤ 1ms | n/a — always runs |
| L2 (anomaly + velocity) | ≤ 1ms | n/a — always runs |
| L3 (LSH fuzzy) | ≤ 2ms | skipped when score < 25 OR > 75 |
| Persist + headers | ≤ 200µs | n/a |
| **Total** | **≤ 3ms p99** | leaves 2ms for non-risk WAF code |

## B.14 Configuration Schema (`waf.yaml`, risk section)

```yaml
risk:
  thresholds:
    allow: 30
    block: 70
  decay:
    max: 50
    per_clean_requests: 5
    per_seconds: 30
  store:
    idle_ttl_seconds: 1800
  tor:
    list_path: "./threat-intel/tor-exit.txt"
    refresh_seconds: 3600
  asn:
    mmdb_path: "./threat-intel/geolite2-asn.mmdb"
    fallback_trie_path: "./threat-intel/asn-public.trie"
  challenge:
    secret_path: "./var/waf-hmac-secret"
    nonce_lru_size: 100000
    nonce_ttl_seconds: 300
    anti_grind_clean: 5
  velocity:
    windows: [60, 600]
  signals:
    # all delta values listed in §A.1.5/A.1.6 are overridable here
    ja4_bad_cluster_exact: 20
    ja4_bad_cluster_fuzzy: 10
    ja4_ua_mismatch: 15
    # ... (full table mirrors A.1.5/A.1.6)

tiers:
  CRITICAL:
    paths: ["/login", "/otp", "/deposit", "/withdrawal"]
    multiplier: 1.2
    fail_mode: fail-close
  HIGH:
    paths: ["/api/*"]
    multiplier: 1.1
    fail_mode: fail-close
  MEDIUM:
    paths: ["/game/*", "/user/*"]
    multiplier: 1.0
    fail_mode: fail-open
  CATCH_ALL:
    paths: ["/*"]
    multiplier: 0.8
    fail_mode: fail-open
```

---

## Cross-Reference: FR-RS → Brainstorm Section

| FR-RS range | Brainstorm section |
|-------------|---------------------|
| 001–006 | §3.1 Identity Triple |
| 010–016 | §3.2 Score Composition + §0 Exec |
| 020–025 | §3.3 Reputation Seed |
| 030–032 | §3.4 Rule Deltas |
| 040–052 | §3.5 Anomaly Deltas |
| 060–067 | §3.6 Velocity / Sequence |
| 070–073 | §3.7 Decay |
| 080–085 | §3.8 Challenge Credit + Q6 |
| 090–092 | §3.9 Tier Multiplier |
| 100–103 | §4 Lifecycle + §1 BG-12 |
| 110–114 | §5 Storage Sketch + §2.4 reset semantics |
| 120–126 | §6 Audit-Log Schema + §1 BG-01/09 |

---

## Open Items Inherited (from brainstorm §11.1)

These remain open after this spec — they need empirical or operational decisions, not more design:

1. **Decay parameter tuning** (NFR-RS via FR-RS-073) — final values come from replay harness post-dry-run.
2. **HMAC secret bootstrap** (FR-RS-085) — file path and on-first-boot generation procedure to be defined in deployment doc.
3. **JA4 collision FP rate** — measure during dry-run; if > 0.5%, lower FR-RS-040 from `+20` to `+15`.
4. **rensa crate maintenance check** — verify last commit before locking dependency; fall back to `lsh-rs` if abandoned.
5. **Public-BGP IP→ASN refresh cadence** (FR-RS-024 fallback) — currently startup-only; production needs weekly refresh job.
