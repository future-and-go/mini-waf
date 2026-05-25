---
phase: 1
title: "PR-A: audit_emitter core + intel_status + CI pre-flight (TDD)"
status: pending
priority: P1
effort: "2d"
dependencies: []
pr_branch: "feat/audit-emitter-core-issue-60-a"
loc_estimate: 1200
red_team_applied: F-F-3, F-S-2, F-S-4, F-S-6, F-F-1, F-F-5, F-F-6, F-F-7, F-F-8, F-F-9, F-F-12, F-A-3 (regex), BP6, BP7, BP8
---

# Phase 1: audit_emitter core

## Overview

Ship core `audit_emitter/` module (rate-limited, supervised, WS-decoupled, 2-layer rate-limit), `FeedStatusRegistry` skeleton (phase 02 populates), CI pre-flight, dep-cycle audit. **Không có caller wiring** (relay/tx_velocity wiring ở phase 02/03). TOML config knob default-off. Drop honeypot scaffolding.

**Red-team applied**: orphan-API warn (F-F-3), drop-log + 4096 floor (F-S-2), global token bucket layer 2 (F-S-4), atomic snapshot + entry().or_insert_with() (F-S-6), tracing on counter incs (F-F-1 / BP7), paused-clock tests (F-F-5), single load_full() snapshot (F-F-6), Copy key (u128, &'static str) (F-F-7), CI pre-flight inline (F-F-8), FeedStatusRegistry moved here (F-F-9), cargo tree dep-cycle check (F-F-12), rule_id regex contract (BP6 / F-A-3), testcontainers Postgres smoke excluded from coverage (BP8 / F-F-4).

## Requirements

### Functional
- `AuditEmitter::new(db, sink, cfg)` build emitter, spawn supervisor + janitor tasks
- `AuditEmitter::emit(ctx, rule_id, rule_name, action, detail) -> EmitOutcome` với 4 outcomes: `Disabled` / `Emitted` / `RateLimited` / `QueueFullDropped`
- **2-layer rate limit** (F-S-4):
  - Layer 1: per `(client_ip, rule_id)` per `window_secs` (default 60)
  - Layer 2: per `rule_id` global token bucket via `tokio::sync::Semaphore`; default **flat 100 permits/s/rule** for all 6 built-in rule_ids. Refill task `Semaphore::add_permits(deficit)` every 1s. Per-rule override map trong TOML: `[audit_emitter.global_rate]\nBOT-XFF-001 = 200`
- **Bucket key** (F-F-7) = `(u128, &'static str)` Copy type. IPv4 → `to_ipv6_mapped()` → u128 octets. Zero-alloc hot path.
  - **Invariant**: rule_id phải là `&'static str` const literal. audit_emitter chỉ cover built-in rule_ids (`BOT-*`, `TX-*`, future `HONEYPOT-*`). Custom user-defined rules (FR-003) KHÔNG đi qua audit_emitter — separate code path. Document trong `mod.rs` doc comment.
- **Detail sanitisation** (F-S-5 / phases 02, 03 share helper): `audit_emitter::sanitize_detail(raw: &str) -> String` — `serde_json::to_string` (escape JSON control chars + quotes + backslash) + manual `.replace('<', "&lt;").replace('>', "&gt;").replace('&', "&amp;")` cho HTML chars + truncate boundary-safe at 4096 bytes. NO new dep (uses existing `serde_json` workspace dep)
- WS broadcast OUTSIDE rate-limit gate (subscribers thấy mọi detection)
- Atomic `try_reserve` via `DashMap::entry().or_insert_with()` (F-S-6) → rollback nếu `try_send` Full/Closed
- Supervisor per-event `tokio::spawn` + panic recovery
- Janitor periodic prune buckets (cap `max_keys`)
- Single `cfg.load_full()` snapshot at emit entry (F-F-6) — downstream all reads từ same snapshot; avoids torn reads
- Hot-reload `enabled` + `window_secs` qua ArcSwap; warn cho construction-time knobs
- **Startup invariant** (F-F-3): nếu `enabled = true` AND zero callers wired (no relay_ctx + no tx_velocity_store with audit_emitter) → `warn!("audit_emitter enabled but no detection modules wired")`
- **Rule_id regex contract** (BP6 / F-A-3): `emit()` validates rule_id matches `^[A-Z]+-[A-Z]+-\d{3}$`; fail loud trong tests (`debug_assert!`), log+drop trong prod (`metrics.inc_invalid_rule_id`)
- **Observability** (BP7 / F-F-1): mỗi `inc_*` (rate_limited, queue_full_dropped, db_insert_failed, worker_restarted) pair với `tracing::warn!(target="audit_emitter")` hoặc `error!` for panics. Test asserts log emission alongside counter inc
- **FeedStatusRegistry skeleton** (F-F-9): `crates/waf-engine/src/intel_status.rs` — empty default `available=false`. Phase 02 populates trên feed load. Public API: `snapshot() -> FeedStatusSnapshot`, `mark_loaded(tor_count, asn_count)`

### Non-functional
- Hot path alloc-free khi `enabled = false` AND khi bucket Copy key path
- TOML config default `[audit_emitter] enabled = false` trong `configs/default.toml`
- `channel_capacity` default floor 4096 (raised từ `parallelism*64` per F-S-2)
- Coverage ≥ 90% trên crate `waf-engine` audit_emitter module (BP8 testcontainers excluded from numerator)
- `cargo fmt`, `cargo clippy` clean
- BP1 (no finding codes), BP4 (no literal-constant assert), BP6 (regex contract), BP7 (tracing pairs), BP8 (test stratification) all applied

## Architecture

```
detection_module  emit(ctx, rule_id, …) ┐
                                        ├─→ AuditEmitter
                                        │       │
                                        │       ├─ cfg = self.cfg.load_full()  (single snapshot)
                                        │       ├─ short-circuit if !cfg.enabled
                                        │       ├─ regex validate rule_id (BP6)
                                        │       ├─ broadcast (WS) — always fires
                                        │       ├─ LAYER 1: per-key bucket.try_reserve
                                        │       │     (key = (u128, &'static str) Copy)
                                        │       ├─ LAYER 2: global token bucket per rule_id
                                        │       │     (flat 100 tokens/s/rule, TOML per-rule override, refill async via Semaphore::add_permits)
                                        │       └─ mpsc.try_send → spawn_supervisor
                                        │           ├─ Full/Closed → rollback bucket reservation
                                        │           │              → inc_queue_full_dropped + warn!
                                        │           └─ Ok → inc_emitted
                                        │
                              ArcSwap<AuditEmitterConfig>
                                        │
                              janitor (interval ticker)
                              ├─ bucket gc (drop expired, cap max_keys LRU by expires_ms)
                              └─ global_bucket refill ticker
```

Components (1 per file):
- `mod.rs` — `AuditEmitter` struct + public API (`new`, `emit`, `reload_config`, `is_enabled`, `metrics_snapshot`); regex contract validator
- `config.rs` — `AuditEmitterConfig` (TOML deserialise) + defaults (channel_capacity floor 4096)
- `bucket.rs` — `BucketStore` (DashMap-backed `(u128, &'static str) → expires_ms`), `make_key_copy`, `now_epoch_ms`, `try_reserve` (atomic via `entry().or_insert_with()`), `rollback`, `gc`
- `global_bucket.rs` — `GlobalRateBucket` (per-rule_id token bucket; tokio::sync::Semaphore-backed, refill task)
- `worker.rs` — `spawn_supervisor` (DB INSERT loop với panic recovery) + `spawn_janitor`
- `broadcast.rs` — `BroadcastSink` trait + `NoopBroadcastSink` + `DbBroadcastSink` (reuse `notifications.rs` WS infra nếu khả thi, else channel riêng)
- `metrics.rs` — `AuditEmitterMetrics` (atomic counters: `emitted`, `rate_limited`, `queue_full_dropped`, `db_insert_failed`, `worker_restarted`, `invalid_rule_id`, `global_rate_limited`)

Plus phase-01 owned (outside audit_emitter/):
- `crates/waf-engine/src/intel_status.rs` — `FeedStatusRegistry` skeleton (F-F-9, populated by phase 02)

## Related Code Files

### Create
- `crates/waf-engine/src/audit_emitter/mod.rs`
- `crates/waf-engine/src/audit_emitter/config.rs`
- `crates/waf-engine/src/audit_emitter/bucket.rs`
- `crates/waf-engine/src/audit_emitter/global_bucket.rs` (F-S-4 layer 2: `Semaphore`-backed per-rule_id buckets, refill task)
- `crates/waf-engine/src/audit_emitter/sanitize.rs` (F-S-5 shared helper: `sanitize_detail` + tests)
- `crates/waf-engine/src/audit_emitter/worker.rs`
- `crates/waf-engine/src/audit_emitter/broadcast.rs`
- `crates/waf-engine/src/audit_emitter/metrics.rs`
- `crates/waf-engine/src/intel_status.rs` (F-F-9 skeleton)
- `crates/waf-engine/tests/audit_emitter_unit.rs`
- `crates/waf-engine/tests/audit_emitter_cardinality.rs`
- `crates/waf-engine/tests/audit_emitter_postgres_smoke.rs` (BP8 / F-F-4 — testcontainers, CI-required, EXCLUDED from coverage gate)

### Modify
- `crates/waf-engine/src/lib.rs` (add `pub mod audit_emitter; pub mod intel_status;`)
- `crates/waf-engine/src/engine.rs` (add `set_audit_emitter(Arc<AuditEmitter>)` setter; no propagation yet — verifies API compile-time; F-F-3 startup warn check)
- `crates/waf-common/src/config.rs` (add `AuditEmitterToml` section)
- `configs/default.toml` (add `[audit_emitter]` section, `enabled = false`, `channel_capacity = 0` (0=auto with 4096 floor), global bucket settings)
- `crates/waf-engine/Cargo.toml` (verify `arc-swap` đã trong workspace deps; add `testcontainers = { version = "*", features = ["postgres"] }` to dev-deps)
- `.github/workflows/ci.yml` (conditional — only if Step 0 finds rust-toolchain mismatch with summary.md §13 rocky9 + 1.91)

### Delete
None — PR #62's `risk/canary.rs` + `risk/scorer.rs` honeypot mods KHÔNG mang sang (BP2).

## Implementation Steps (TDD)

### Step 0 — Pre-flight (mandatory before any code change)

0.1. **CI toolchain audit** (F-F-8): `cat .github/workflows/ci.yml | grep -E 'rust-toolchain|rust-version|toolchain'`. Compare against summary.md §13 (`rocky9 + rust 1.91`). If mismatch:
   - Update CI workflow trong cùng PR-A (DON'T tách PR-0).
   - Document deviation lý do trong PR description.

0.2. **Dep-cycle check** (F-F-12): `cargo tree -p waf-engine | grep waf-storage` + `cargo tree -p waf-storage | grep waf-engine`. Nếu cycle, decision needed (`Database` trait should be tách sang `waf-common` hay `waf-storage` đứng riêng) — STOP và escalate.

0.3. **Read main fresh**: `crates/waf-engine/src/engine.rs` (942 LOC), `crates/waf-api/src/notifications.rs` + `websocket.rs` (to decide `DbBroadcastSink` reuse vs separate channel).

### Step 1 — Write failing tests first

1.1. `tests/audit_emitter_unit.rs` — 16 integration tests (all paused-clock per BP4):
- `disabled_emit_returns_disabled_without_alloc`
- `enabled_emit_first_call_returns_emitted_and_queues_row`
- `same_key_within_window_returns_rate_limited_no_db_row`
- `ws_broadcast_fires_for_rate_limited_emit`
- `queue_full_returns_queue_full_dropped_and_rolls_back_bucket`
- `queue_full_drop_emits_warn_log` (BP7)
- `next_emit_after_rollback_succeeds`
- `distinct_keys_dont_share_bucket`
- `window_expiry_allows_next_emit`
- `hot_reload_enabled_takes_effect_on_next_emit`
- `hot_reload_construction_knob_logs_warn`
- `single_load_full_snapshot_prevents_torn_read` (F-F-6 fuzz N=1000)
- `concurrent_reserve_with_gc_no_double_insert` (F-S-6 stress)
- `enabled_with_no_callers_logs_warning` (F-F-3 CRITICAL — startup invariant)
- `invalid_rule_id_format_dropped_with_warn` (BP6 regex contract)
- `global_token_bucket_layer_2_limits_per_rule_across_ips` (F-S-4)

1.2. `tests/audit_emitter_cardinality.rs` — 5 scenarios:
- `single_ip_burst_only_one_db_row_per_window`
- `10k_unique_ips_fanout_each_emits_once`
- `10k_unique_ips_fanout_rss_delta_under_5mb` (F-F-7 memory cap proof)
- `mixed_burst_hot_ip_doesnt_starve_cold_ips`
- `max_keys_eviction_under_cap`

1.3. Inline unit tests per module — 25 tests covering helpers:
- `make_key_copy_zero_alloc_ipv4_via_to_ipv6_mapped`
- `make_key_copy_ipv6_passes_through`
- `now_epoch_ms_monotonic`
- `bucket_store_try_reserve_concurrent_atomic` (loom or N=10k stress)
- `metrics_counter_atomicity`
- `global_bucket_refill_async_no_stall`
- `rule_id_regex_validator_matches_3_segment_grammar`
- (plus existing 18 from PR #62 ported)

1.4. Behavioral panic-recovery test trong `worker.rs` (no literal-constant assert per BP4; paused clock per F-F-5):
```rust
#[tokio::test(start_paused = true)]
async fn worker_panic_emits_error_log_and_continues() {
    let mock_db = MockDatabase::with_one_panic_then_ok();
    let (emitter, mut log_capture) = setup_with_log_subscriber(mock_db);
    emitter.emit(/* event 1 — panics */);
    emitter.emit(/* event 2 — succeeds */);
    time::advance(POST_PANIC_BACKOFF + Duration::from_millis(1)).await;
    assert!(log_capture.contains_error("audit emitter: DB insert panicked"));  // BP7
    assert_eq!(emitter.metrics_snapshot().worker_restarted, 1);
    assert_eq!(mock_db.insert_count(), 1);  // 2nd succeeded
}
```

1.5. `tests/audit_emitter_postgres_smoke.rs` (BP8 — testcontainers, marked `#[cfg(feature = "integration-tests")]`):
- `real_postgres_insert_security_event_row` — spin testcontainers PG, verify migration applied, insert row, query back, assert columns match
- `migration_index_present_for_risk_distribution_query` — verify phase 04 dependency
CI workflow: separate step `cargo test --features integration-tests -- --test audit_emitter_postgres_smoke`. **EXCLUDED khỏi coverage gate** (BP8) via `cargo llvm-cov --no-include integration-tests` flag.

1.5. Run tests trong Docker `rocky9 + rust 1.91` (per summary.md §13 build cmd):
```bash
docker run --platform=linux/amd64 --rm -v "$(pwd):/src" -w /src rockylinux:9 sh -lc '
  dnf install -y --allowerasing gcc gcc-c++ make pkg-config openssl-devel cmake git perl ca-certificates curl &&
  curl --proto =https --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain 1.91 --profile minimal &&
  . $HOME/.cargo/env &&
  cargo test --features gateway/valkey -p waf-engine --test audit_emitter_unit --test audit_emitter_cardinality
'
```
**Expected: all tests FAIL** (no impl yet).

### Step 2 — Implement minimum to pass

2.1. `config.rs` — `AuditEmitterConfig { enabled: bool, window_secs: u64, channel_capacity: usize, gc_interval_secs: u64, max_keys: usize }` + `Default` (`enabled = false`, `window_secs = 60`, `channel_capacity = available_parallelism * 64`, `gc_interval_secs = 30`, `max_keys = 10_000`).

2.2. `bucket.rs` — `BucketStore` wraps `DashMap<Arc<(String, &'static str)>, i64>` (key → expires_ms). `try_reserve` atomic via `entry().and_modify().or_insert_with()` returning bool. `rollback` removes entry only if expires_ms matches. `gc` drops expired + caps to `max_keys` (LRU by expires_ms).

2.3. `metrics.rs` — `AtomicU64` per counter + `snapshot()` returns plain struct.

2.4. `broadcast.rs` — Trait + `NoopBroadcastSink` (test default) + `DbBroadcastSink` placeholder. Phase 01 verify reuse vs separate channel; tài liệu trong code comment ngắn ngọn (no plan refs per BP1).

2.5. `worker.rs` — `spawn_supervisor` per-event `tokio::spawn` + JoinError → panic recovery → `inc_worker_restarted` + backoff. **NO** `POST_PANIC_BACKOFF` literal-constant assertion test (BP4); use behavioral test only.

2.6. `mod.rs` — `AuditEmitter` orchestration:
- WS broadcast first (always)
- `bucket.try_reserve` gate
- Build `CreateSecurityEvent`
- `tx.try_send` + rollback on Full/Closed
- Return `EmitOutcome`

2.7. `engine.rs` — `WafEngine::set_audit_emitter(Arc<AuditEmitter>)` stores Arc trong `engine`. **No-op propagation** — Phase 02/03 sẽ extend propagate vào tx_velocity_store / relay.

2.8. `configs/default.toml` + `waf-common/src/config.rs` — TOML schema:
```toml
[audit_emitter]
enabled = false
window_secs = 60
channel_capacity = 0     # 0 → auto: available_parallelism * 64
gc_interval_secs = 30
max_keys = 10000
```

2.9. Run tests again → **all pass**.

### Step 3 — Refactor + verify

3.1. Run `cargo fmt --all` + `cargo clippy --workspace --all-targets`.
3.2. Coverage report via `cargo llvm-cov` trong Docker. Verify ≥ 90% trên `audit_emitter` module.
3.3. Grep gate (BP1):
```bash
grep -rE '(F[0-9]\.[0-9]|CC[0-9]|red-team patched|red-team F)' crates/waf-engine/src/audit_emitter/ crates/waf-engine/tests/audit_emitter_*.rs
# expected: exit 1 (no matches)
```
3.4. Squash to 1 commit. Push.
3.5. `gh pr create` với description (senior-dev style, no personal details).

### Step 4 — PR draft body

```markdown
## Summary

Adds the shared `audit_emitter/` module — rate-limited, supervised, WS-decoupled
emission layer that materialises detection signals as `security_events` rows.
No callers wired yet (follow-up PRs land relay + tx_velocity hooks).

## Rationale

Detection modules currently produce internal signals but never persist them.
Admin panel surfaces (Relay, TX Velocity, Reputation, Risk Distribution) depend
on rows tagged with stable `rule_id` strings. This PR delivers the bridge so
follow-ups can wire callers without reinventing rate-limit / supervisor logic.

## Design

- **Hot-path alloc-free** when `enabled = false`.
- **WS broadcast** fires for every detection — independent of the rate-limit
  gate. Subscribers see live events; DB writes are throttled.
- **Atomic try_reserve** prevents the race where two concurrent emits with
  the same `(client_ip, rule_id)` both observe a free slot and both queue rows.
- **try_send rollback** — if the bounded channel is full, the bucket
  reservation is rolled back so the next request is not blacked out for a
  full window.
- **Supervisor pattern** — each DB INSERT runs inside its own `tokio::spawn`;
  a panic increments `worker_restarted`, sleeps a short backoff, resumes
  draining. A poison-pill row cannot kill the worker.
- **Hot-reload safe** for `enabled` + `window_secs` via ArcSwap; construction-
  time knobs log a warn so operators are not silently surprised.

## Activation

Default-off in production. Operator opts in via `configs/default.toml`:
```toml
[audit_emitter]
enabled = true
```

## Tests

- 31 unit tests across `audit_emitter::{config,metrics,broadcast,bucket,worker}`
- 10 integration tests (`audit_emitter_unit.rs`) covering ordering: bucket-
  claim-after-try_send, queue-full-rollback, WS-outside-gate, disabled-fast-path
- 4 cardinality scenarios (`audit_emitter_cardinality.rs`)
- Behavioral panic-recovery test (no literal-constant assertion)
- Coverage ≥ 90% (`cargo llvm-cov` in Docker rocky9 + rust 1.91)

## Out of scope

- Caller wiring (relay/tx_velocity) — follow-up PRs.
- API endpoints (`/api/reputation/*`, `/api/stats/risk-distribution`) — follow-up PR.
- Honeypot emit branch — deferred until risk Scorer is wired into the gateway.
```

## Success Criteria

- [ ] All tests in step 1 pass (failing → passing transition documented)
- [ ] `cargo fmt --all -- --check` exit 0
- [ ] `cargo clippy --workspace --all-targets` exit 0 (no warnings)
- [ ] Coverage ≥ 90% on `audit_emitter` module
- [ ] Grep gate BP1: 0 finding-code references
- [ ] BP3: TOML config present, default `enabled = false`
- [ ] BP4: no literal-constant equality assertions
- [ ] PR opened on GitHub, CI green, NOT merged
- [ ] 1 squashed commit on branch `feat/audit-emitter-core-issue-60-a`

## Risk Assessment

| Risk | Mitigation |
|---|---|
| `DbBroadcastSink` overlap với `notifications.rs` WS — duplicate channels | Read `crates/waf-api/src/notifications.rs` + `websocket.rs` trong step 2.4; reuse infra nếu khả thi, else document why separate |
| ArcSwap `cfg.window_secs` hot-reload race — old `expires_ms` calculated with old window | Acceptable — existing buckets keep old expiry; only new emits use new window |
| `available_parallelism` panic trên unusual env | Fallback `unwrap_or(NonZeroUsize::new(4).unwrap())` |
| Test `panic_in_insert_does_not_kill_worker` flaky vì timing | Use mpsc `recv()` với timeout 2s + retry assertion |
| Coverage gate fail vì error branches khó test | Use `MockDatabase` trait with controllable behavior (panic/err/ok) |

## Next Phase

Phase 02 (relay wiring) + Phase 03 (tx_velocity wiring) đều blocked by phase 01 merge. Có thể chạy parallel (no shared files).
