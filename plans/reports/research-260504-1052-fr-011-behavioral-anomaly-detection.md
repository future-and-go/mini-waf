# Research + Brainstorm: FR-011 Behavioral Anomaly Detection

**Date:** 2026-05-04 10:52 (Asia/Saigon)
**Scope:** FR-011 in `analysis/requirements.md` — propose technical solution + design pattern, cover all AC, plan ≥90% test coverage.
**Audience:** Engineer building this on top of `waf-engine` (Pingora-based, Rust 2024).

---

## 1. Context

### Problem
Spec line: *"Bot timing detection, zero-depth sessions, missing Referer, inter-request interval < 50ms."*

Goal: turn behavioral signals (per-actor, across a short time horizon) into risk-score deltas that feed FR-RS-048 / FR-RS-049 in the existing risk-score spec.

### Why behavioral, not just signature
WAF research (2025) shows ~45% of hostile bot traffic bypasses signature/IP-based WAFs because bots now rotate IPs, spoof UA, and use headless browsers. Behavioral timing + session-shape heuristics catch what signatures miss — they're cheap, deterministic, and hard to evade without slowing the bot down to human speed (which is the win condition).

### Existing infra to reuse (already in tree)
- `waf-engine/src/device_fp/identity/` — `IdentityStore` trait (`memory.rs` + `redis.rs`), conformance suite, janitor task. Per-`FpKey` aggregation already exists.
- `waf-engine/src/device_fp/registry.rs` + `aggregator.rs` — risk-signal provider pattern.
- `waf-engine/src/device_fp/providers/{ua_blocklist,ua_entropy,fp_conflict,ip_hopping,h2_anomaly}.rs` — exact pattern to follow for new behavioral providers.
- `waf-engine/src/checks/rate_limit/` — sliding-window primitives + DashMap usage.

**Verdict:** zero new infra. Add one module + N providers under `device_fp/providers/`.

---

## 2. Acceptance Criteria → Signals (decomposition)

| AC term | Signal | Risk delta source |
|---|---|---|
| Bot timing detection | inter-request interval coefficient-of-variation < threshold (regularity) over N≥5 reqs | new |
| Inter-request interval < 50ms | last-N intervals: ≥5 consecutive < 50ms | FR-RS-048 (+15) |
| Zero-depth sessions | distinct path count == 1 AND no Referer chain on CRITICAL tier | FR-RS-049 (+10) |
| Missing Referer | navigational request (non-asset, non-API entry) without Referer + no prior in-session req | new (~+5) |

All four collapse into **one per-actor sliding-window state struct** + **four cheap classifiers** that read it.

---

## 3. Technical Solution

### 3.1 Architecture (one diagram)

```
                Pingora request_filter
                        │
                        ▼
            ┌───────────────────────────┐
            │ behavior::Recorder        │  (writes; O(1) lock-free)
            │  upsert(ActorKey, Sample) │
            └────────────┬──────────────┘
                         │
                         ▼
        ┌────────────────────────────────────┐
        │ ActorBehavior  (DashMap value)     │
        │  ring<Sample, 16>  // last 16 reqs │
        │  distinct_paths: SmallSet<8>       │
        │  last_referer_target: Option<…>    │
        │  updated_at: Instant               │
        └────────────────┬───────────────────┘
                         │ borrowed read
                         ▼
            ┌───────────────────────────┐
            │ behavior::Classifier(s)   │  (impl RiskSignalProvider)
            │  - BurstInterval          │  → +15
            │  - RegularityCadence      │  → +10
            │  - ZeroDepthSession       │  → +10
            │  - MissingReferer         │  → +5
            └────────────┬──────────────┘
                         ▼
                   risk aggregator
                  (existing FR-010 path)
```

### 3.2 Where it lives

```
crates/waf-engine/src/
└── device_fp/
    ├── behavior/                      ← NEW
    │   ├── mod.rs                     (public API + Recorder)
    │   ├── state.rs                   (ActorBehavior, Sample, ring buffer)
    │   ├── config.rs                  (thresholds, window sizes)
    │   ├── recorder.rs                (write path, DashMap)
    │   └── providers/
    │       ├── burst_interval.rs      (FR-RS-048)
    │       ├── regularity.rs          (CV-based bot timing)
    │       ├── zero_depth.rs          (FR-RS-049)
    │       └── missing_referer.rs
    └── providers/                     ← register the 4 above
```

### 3.3 Actor key

Reuse `FpKey` from `device_fp::types`. It already binds {device_fp + IP-class} so behavioral state survives IP rotation when fingerprint is stable, and survives UA spoofing when device is stable. **Don't invent a new key** — DRY.

### 3.4 State struct (the core data)

```rust
// state.rs — keep <80 LOC
pub(crate) const WINDOW: usize = 16;

#[derive(Clone, Copy)]
pub(crate) struct Sample {
    pub ts_ms: u64,           // monotonic ms since recorder boot
    pub path_hash: u64,       // xxhash of normalized path
    pub had_referer: bool,
    pub tier: Tier,           // CRITICAL/HIGH/MEDIUM/CATCH_ALL
}

pub(crate) struct ActorBehavior {
    samples: ArrayDeque<Sample, WINDOW>, // ring; arraydeque crate or hand-rolled
    distinct_paths: ArrayVec<u64, 8>,    // small bounded set
    updated_ms: u64,
}
```

**Bounded memory per actor:** ~16 × 24 B + 8 × 8 B = ~448 B. At 1M actors → ~430 MB worst-case; janitor TTL keeps it well below.

### 3.5 Storage: DashMap, not Mutex<HashMap>

```rust
pub struct Recorder {
    actors: DashMap<FpKey, ActorBehavior>, // sharded, lock-free reads
    cfg: Arc<ArcSwap<BehaviorConfig>>,     // hot-reloadable; see §5
}
```

- DashMap is the project's standard (see `rate_limit/`).
- Janitor reuses the `spawn_janitor` pattern from `device_fp::identity::memory`.
- For multi-instance: behavioral state is **ephemeral, per-node** in v1 (KISS). Risk score itself already syncs via identity store. Only escalate to Redis if the Attack Battle is multi-node (open question #2 below).

### 3.6 Classifiers (RiskSignalProvider impls)

Each is ~30–50 LOC. Pure functions over `&ActorBehavior`. No I/O, no allocs in hot path.

```rust
// burst_interval.rs — FR-RS-048
fn evaluate(&self, b: &ActorBehavior) -> Option<RiskSignal> {
    let intervals = b.samples.windows(2)
        .map(|w| w[1].ts_ms.saturating_sub(w[0].ts_ms))
        .collect::<ArrayVec<_, 15>>();
    let burst_run = intervals.iter().rev()
        .take_while(|&&d| d < 50).count();
    (burst_run >= 5).then(|| RiskSignal::new("burst_interval", 15))
}
```

```rust
// regularity.rs — bot timing (cadence detection)
// CV = stddev / mean. CV < 0.15 over ≥6 samples = robotic.
// Skips if intervals are all >2s (cron-ish but slow ≠ attack).
```

```rust
// zero_depth.rs — FR-RS-049
fn evaluate(&self, b: &ActorBehavior) -> Option<RiskSignal> {
    let n = b.samples.len();
    let critical_hits = b.samples.iter().filter(|s| s.tier == Tier::Critical).count();
    let no_chain = b.samples.iter().all(|s| !s.had_referer);
    (n >= 4 && b.distinct_paths.len() == 1 && critical_hits >= 2 && no_chain)
        .then(|| RiskSignal::new("zero_depth", 10))
}
```

```rust
// missing_referer.rs
// Fires only on first-in-session navigational GET to a non-entry path
// without Referer. Excludes: /, /index, /login, asset paths, API JSON.
```

### 3.7 Hot path budget

Recorder write: 1 DashMap shard lock + ring push + small-vec scan ≤ 8 elems = **<1 µs** typical.
Classifier read: shared shard, 4 × O(WINDOW) = ~64 iterations = **<2 µs**.
Total <5 µs at p99 → fits the 5 ms WAF budget with massive headroom.

---

## 4. Design Patterns

| Pattern | Where | Why |
|---|---|---|
| **Strategy** (`RiskSignalProvider` trait) | each classifier | Already the project convention for FR-010; 4 small files beats one giant match. |
| **Observer / Pipeline** | Recorder writes → providers read | Decouples capture from classification; classifiers are stateless. |
| **Ring buffer (bounded queue)** | `ArrayDeque<Sample, 16>` | O(1) push, fixed memory, no alloc — KISS over time-bucketed sliding window. |
| **Atomic swap config** (arc-swap) | thresholds | Hot-reload without restart (FR-021). Reuse `relay::reload` pattern. |
| **Janitor task** | TTL eviction | Direct copy of `device_fp::identity::memory::spawn_janitor`. |

**Rejected:** Visitor (overkill, 4 providers); Actor model / channels (latency); per-actor Mutex (DashMap shards already give you that).

---

## 5. Configuration (YAML, hot-reloadable)

### 5.1 Location & format

Co-locate under existing `configs/device-fp.yaml` (new top-level `behavior:` block) — sibling to FR-010 fingerprint signals. **No new config file** (KISS, matches repo convention for FR-010 grouping).

```yaml
# configs/device-fp.yaml (excerpt — new behavior: block)
behavior:
  window_size: 16              # ring buffer per actor; 4..=64
  actor_ttl_secs: 600          # janitor evicts idle actors

  burst_interval:              # FR-RS-048
    threshold_ms: 50
    min_consecutive: 5
    risk_delta: 15

  regularity:                  # bot timing (CV-based cadence)
    min_samples: 6
    cv_threshold: 0.15         # (0.0, 1.0]
    min_mean_ms: 100           # ignore slow regular polling
    risk_delta: 10

  zero_depth:                  # FR-RS-049
    min_samples: 4
    critical_hits_required: 2
    risk_delta: 10

  missing_referer:
    risk_delta: 5
    exempt_paths:    ["/", "/login", "/index", "/health"]
    exempt_prefixes: ["/static/", "/assets/", "/api/"]
```

Defaults shipped in repo; per-route override via existing rule scoping (FR-023).

### 5.2 Hot-reload pipeline

Reuse the **`access/reload.rs` pattern verbatim**: `notify::RecommendedWatcher` + `arc_swap::ArcSwap<BehaviorConfig>`. No admin API surface (audit-friendly, GitOps-native).

```
configs/device-fp.yaml ── inotify/FSEvent ──► notify::Watcher
                                                    │ debounce 200 ms
                                                    ▼
                                        parse YAML  →  validate
                                                    │
                                            ┌───────┴───────┐
                                            ▼               ▼
                                        OK: swap        ERR: keep last-good
                                  ArcSwap::store(Arc::new(cfg))   + tracing::warn!
                                            │
                                            ▼
                              providers read via ArcSwap::load() per eval
                                  (no lock contention, no caching)
```

### 5.3 Validation rules (block bad config from going live)

Validation runs **before** the atomic swap. On any failure, the running config is preserved.

| Field | Rule |
|---|---|
| `window_size` | `4 ≤ x ≤ 64` |
| `actor_ttl_secs` | `60 ≤ x ≤ 86_400` |
| `*.risk_delta` | `0 ≤ x ≤ 100` |
| `*.min_samples` | `2 ≤ x ≤ window_size` |
| `burst_interval.threshold_ms` | `1 ≤ x ≤ 10_000` |
| `burst_interval.min_consecutive` | `2 ≤ x ≤ window_size - 1` |
| `regularity.cv_threshold` | `0.0 < x ≤ 1.0` |
| `regularity.min_mean_ms` | `1 ≤ x ≤ 60_000` |
| `zero_depth.critical_hits_required` | `1 ≤ x ≤ min_samples` |
| `missing_referer.exempt_*` | each entry non-empty, ≤ 256 chars |

Failure mode aligned with FR-036/037 spirit: **never crash live WAF on a typo**.

### 5.4 Coupling

`Recorder::new(cfg: Arc<ArcSwap<BehaviorConfig>>)` — config injected, not owned. Each provider holds the same `Arc<ArcSwap<…>>` and dereferences via `cfg.load()` per evaluation. Config struct is `Clone + Send + Sync` and small (~200 B) — swap is cheap.

---

## 6. Test Strategy (≥90% coverage)

**Coverage tool:** `cargo llvm-cov --workspace --html` (already in CI per other reports).

### 6.1 Unit (per file, target 100% lines on classifiers)

| File | Tests |
|---|---|
| `state.rs` | ring wraps at WINDOW; distinct_paths bounded; clone semantics |
| `recorder.rs` | upsert creates; concurrent inserts (loom or 100-thread stress); TTL purge |
| `burst_interval.rs` | 5-burst fires; 4-burst silent; non-consecutive silent; intervals exactly 50ms silent (boundary); empty samples silent |
| `regularity.rs` | CV<0.15 fires; CV>0.15 silent; mean<100ms gated to burst; <6 samples silent; all-equal intervals (CV=0) fires |
| `zero_depth.rs` | 1 path + 2 critical + no referer fires; with referer silent; 2 paths silent; on MEDIUM tier silent |
| `missing_referer.rs` | exempt path silent; exempt prefix silent; first nav fires; subsequent in-session silent |
| `config.rs` | parse round-trip; reject `window_size = 0`; reject `cv_threshold = 1.5`; reject `min_consecutive > window`; reject empty exempt entry |
| `reload.rs` | valid file → `ArcSwap` updated; malformed YAML → old config retained + warn logged; debounced (no double-swap on rapid edits) |

### 6.2 Integration

`crates/waf-engine/tests/behavior_acceptance.rs`:
- **AC1:** simulate 6 reqs at 30 ms each → expect `burst_interval` signal + +15 risk delta after aggregator pass.
- **AC2:** 8 reqs same path on `/admin/critical`, no Referer → `zero_depth` + +10.
- **AC3:** GET `/dashboard/profile` with no Referer, no prior session → `missing_referer` + +5.
- **AC4:** human-like trace (intervals: 2300, 1800, 4100, 950, 2700 ms, varied paths, Referer chain) → **no** signals.
- **AC5 (reload):** boot with valid YAML → flip `burst_interval.risk_delta` from 15 → 25 on disk → within 500 ms next eval emits +25; then write malformed YAML → next eval still emits +25 + warn line present.

### 6.3 Property-based (`proptest`)

- Random Sample sequences: classifier never panics; risk delta in [0, max_per_class]; idempotent under same input.
- Window invariant: `samples.len() ≤ WINDOW` always.

### 6.4 Concurrency

- `loom` test on Recorder upsert (small interleaving) — 1 test, gated `#[cfg(loom)]`.
- Stress: 1000 tokio tasks × 1000 inserts → no panics, final actor count correct.

### 6.5 Bench (not coverage, but required for FR perf budget)

`benches/behavior_eval.rs` — Criterion: target <3 µs per request end-to-end (recorder write + 4 classifier evals).

### 6.6 Coverage gates

- CI fails if `cargo llvm-cov --fail-under-lines 90` for `device_fp/behavior/**` (includes `config.rs` + `reload.rs`).
- Branch coverage spot-check via `--show-missing-lines` for each provider.

---

## 7. Common Pitfalls (anti-targets)

1. **System time for intervals** — wall clock can jump backwards. Use `tokio::time::Instant` deltas → store as monotonic `u64 ms` since recorder start.
2. **Unbounded actor map** — without TTL janitor, memory leaks under churn. Reuse identity-store janitor pattern verbatim.
3. **Counting assets in zero-depth** — `/style.css` would falsely depth-pad. Filter samples by tier or path-class before counting `distinct_paths`.
4. **Triggering on legitimate AJAX polling** — regularity check must require mean interval ≥ 100 ms AND CV < 0.15 to avoid flagging well-behaved heartbeat clients.
5. **False positive on prefetch** — Chrome `<link rel=prefetch>` issues no-Referer GETs. Treat `Sec-Purpose: prefetch` as exempt.
6. **Hot-reload race** — read thresholds via `arc_swap::Guard` per-eval, never cache across requests.
7. **Sharing state across nodes silently** — be explicit: v1 = node-local. Document. Open question for cluster mode.

---

## 8. Implementation Plan (suggested phase ordering)

1. `state.rs` + `recorder.rs` + janitor + unit tests.
2. Wire Recorder into Pingora `request_filter` (one call site).
3. `burst_interval.rs` + acceptance test (smallest, validates pipeline end-to-end).
4. `zero_depth.rs` + `missing_referer.rs` + `regularity.rs` in parallel.
5. Config + arc-swap reload + integration with rule scoping.
6. Bench, coverage gate, docs in `docs/codebase-summary.md`.

Estimated: ~600 LOC implementation + ~900 LOC tests. 2–3 dev-days.

---

## 9. Resources

- [Arroyo: 10x faster sliding windows in Rust](https://www.arroyo.dev/blog/how-arroyo-beats-flink-at-sliding-windows/) — windowing primitives reference
- [DashMap docs](https://docs.rs/dashmap/latest/dashmap/) — concurrency contract we rely on
- [Bot recognition in a Web store (Iliou et al.)](https://www.sciencedirect.com/science/article/pii/S1084804520300515) — academic basis for session-shape features (depth, referer chain)
- [Efficient on-the-fly Web bot detection](https://www.sciencedirect.com/science/article/pii/S0950705121003373) — early-classification approach on active sessions
- [Anti-Bot Protection Guide 2025](https://litport.net/blog/anti-bot-protection-guide-practical-strategies-to-combat-automated-threats-26359) — practitioner overview, timing-regularity rationale
- [45% of hostile bot traffic bypasses WAFs](https://dev.to/botconductstandard/45-of-hostile-bot-traffic-passes-your-waf-heres-why-what-behavioral-detection-reveals-when-you-12mh) — motivation

Internal:
- `plans/reports/spec-260430-1709-risk-score-requirements-and-tech-spec.md` — FR-RS-048/049 deltas
- `plans/reports/brainstorm-260429-0954-fr-001-012-build-order.md` — depends on FR-010 (already done)

---

## 10. Unresolved Questions

1. **Asset-tier exclusion source**: do we read tier from rule engine output or precompute path → tier in Recorder? (Affects coupling.)
2. **Cluster mode**: is Attack Battle single-node? If multi-node, do we mirror behavior state via Redis (cost: +1 RTT per request) or accept per-node windows (risk: bot rotates across nodes to dilute samples)?
3. **Session identity for `missing_referer`**: do we treat first request from a previously-unseen `FpKey` as "first in session", or do we issue a WAF cookie? Open from FR-001..012 build-order brainstorm.
4. **CV threshold tuning**: 0.15 is a starting guess. Need a labeled traffic sample (or Red Team dry run output) to calibrate before code freeze.
5. **Sec-Purpose: prefetch handling** — is it safe to fully exempt, or risk-discount only? Browser support varies.
