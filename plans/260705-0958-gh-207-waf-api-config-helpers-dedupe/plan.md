---
title: "GH-207 waf-api/risk dedupe: shared config-file helpers, RiskConfig serde mapping, unified Clock"
description: "Collapse resolve_path + atomic tmp-write-rename copied across 9 waf-api modules into one config_files.rs, unify the risk-pipeline clock on the existing Clock trait, and verify RiskConfig serde mapping lands via GH-196. Behavior-preserving."
status: completed
priority: P3
issue: https://github.com/future-and-go/mini-waf/issues/207
branch: "main-harness"
tags: [task, area:api, refactor, gh-207]
blockedBy: [260705-0953-gh-196-risk-admin-api-engine-wiring]
blocks: []
created: "2026-07-05T03:14:19.994Z"
createdBy: "ck:plan"
source: skill
---

# GH-207 waf-api/risk dedupe: shared config-file helpers, RiskConfig serde mapping, unified Clock

## Overview

Issue: https://github.com/future-and-go/mini-waf/issues/207 (P3 task, CONFIRMED
by multi-agent review 2026-07-03; all claims re-verified on HEAD `9ee484b`,
2026-07-05). Pure dedupe, no behavior change. Three independent duplications:

1. **`resolve_path` + atomic tmp-write-rename copied ×9.** Byte-identical
   `fn resolve_path(state, relative)` (walk `main_config_file` up two parents,
   `join(relative)`) appears in `risk_api.rs:21`, `tier_policies_api.rs:14`,
   `relay_api.rs:16`, `challenge_api.rs:17`, `access_lists_api.rs:18`,
   `device_fp_api.rs:15`, `ddos_api.rs:37`, `tx_velocity_api.rs:25`; `geo_api.rs:20`
   is the same walk with the path hardcoded (`rules_path`). The atomic write
   (`create_dir_all` + `serde_yaml::to_string` + `path.with_extension("yaml.tmp")`
   + `tokio::fs::write` + `tokio::fs::rename`) is duplicated in all of these plus
   `write_rules` (`geo_api.rs:46`). A fix to root resolution or atomic-write
   behavior must land 10 times. Read side varies (see Key Decisions). `tls.rs`
   has a *different* sync `std::fs` PEM writer — deliberately out of scope.
2. **risk_api hand-mapped RiskConfig serde.** `yaml_to_fe` / `default_risk_fe` /
   `fe_to_yaml` (`risk_api.rs:60-132`) hand-map every field through
   `serde_json::Value`, duplicating `waf_engine::risk::config::RiskConfig`
   (already `Serialize + Deserialize`). **This item is owned by GH-196 Phase 3**
   (`plans/260705-0953-gh-196-risk-admin-api-engine-wiring/phase-03-risk-config-put-get-serde-round-trip.md`),
   which rewrites GET/PUT to serde round-trip and deletes the three mappers.
   Here it is **verification-only** (see Phase 3).
3. **Three clock idioms in one pipeline.** Private `unix_now_ms()`
   (`risk/ingest/aggregator_impl.rs:99`, stamps `Job.submitted_ms` in `submit`)
   vs the `Clock` trait + `SystemClock` + `MockClock`
   (`checks/ddos/detector/clock.rs:13-30`, re-exported at `detector/mod.rs:17`,
   used only by `per_tier.rs`) vs `chrono::Utc::now().timestamp_millis()`
   (`risk/store/memory.rs:50` purge loop; also `risk/ingest/worker.rs:75`
   process/lag timestamp). The aggregator cannot be mock-clock tested. Fix:
   promote `Clock` to a neutral module and inject it through the ingest path.

Blast radius is small: `ScoringAggregator::start*` has **zero production
callers** (grep: only doc `ingest/mod.rs:36` + tests), and `start_purge_loop`
has zero callers on HEAD — both are exercised by tests only, so Clock injection
is low-risk. `resolve_path`/writer migration is internal (private module fns).

## Phases

| Phase | Name | Status |
|-------|------|--------|
| 1 | [Shared config_files module and migrate 9 waf-api modules](./phase-01-shared-config-files-module-and-migrate-9-waf-api-modules.md) | Completed |
| 2 | [Unified Clock injected into risk ingest and purge loop](./phase-02-unified-clock-injected-into-risk-ingest-and-purge-loop.md) | Completed |
| 3 | [RiskConfig serde verify and acceptance quality gates](./phase-03-riskconfig-serde-verify-and-acceptance-quality-gates.md) | Completed |

## Key Decisions

- **Two write primitives, one atomic core.** `config_files.rs` exposes
  `write_yaml_str(path, &str)` (the atomic `create_dir_all` + tmp + rename) and a
  thin `write_yaml(path, &Value)` that serializes then calls `write_yaml_str`.
  Value writers (risk, tier_policies, access_lists, device_fp, challenge, geo)
  use `write_yaml`; typed-doc writers (relay `RelayDetectionDocument`, ddos
  `DdosDocument`, tx_velocity `TxVelocityDocument`) serialize their own doc then
  call `write_yaml_str`. Rationale: the *bug surface* the issue names is the
  atomic-write behavior, not the serialization — sharing only the primitive
  preserves each module's typed contract and error text (YAGNI: no forced
  generic writer).
- **Reads stay per-module, one shared Value reader.** Expose
  `read_yaml_opt(path) -> Option<Value>` for the silent-default Value readers
  (risk, tier_policies, access_lists, device_fp; geo's `read_rules` calls it then
  `.get("rules")`). Do **not** migrate the typed readers (relay/ddos/tx_velocity
  `from_str::<T>`) or `challenge_api`'s `read_yaml` (returns `BadRequest` on parse
  error — a deliberate 400, not a silent default). Their read semantics differ;
  forcing a shared generic would change error behavior. Behavior-preserving wins.
- **geo migrates, tls does not.** `geo_api`'s `rules_path` becomes
  `resolve_path(state, "configs/geo-rules.yaml")` and `write_rules` becomes
  `write_yaml(path, &json!({"rules": rules}))`. `tls.rs` keeps its own writer:
  it is sync `std::fs` at init time, writes PEM cert+key pairs (not YAML) with
  `chmod 600` on the key — a different contract; migrating it is scope creep.
- **`Clock` moves to `crate::time`.** New `pub mod time` in waf-engine holds the
  `Clock` trait + `SystemClock` + `test_utils::MockClock` (moved verbatim from
  `checks/ddos/detector/clock.rs`). `detector/clock.rs` becomes a re-export shim
  (`pub use crate::time::{Clock, SystemClock};` + `test_utils`) so `per_tier.rs`
  (`use super::clock::Clock`, `super::super::clock::test_utils::MockClock`) and
  the `detector/mod.rs:17` re-export keep resolving unchanged. Rationale: risk
  ingest must not reach *up* into ddos detector internals for a clock.
- **Clock threads submit→worker.** `ScoringAggregator` gains `clock: Arc<dyn
  Clock>` (default `SystemClock`, plus a test ctor); `submit` replaces
  `unix_now_ms()`. The *same* clock is passed into `spawn_worker` → `process_job`,
  replacing `chrono::Utc::now()` at `worker.rs:75` so submit-vs-process lag
  (`lag_ms`) is deterministic under one `MockClock`. `start_purge_loop` takes an
  `Arc<dyn Clock>` (default `SystemClock`), replacing `chrono` at `memory.rs:50`.
  `unix_now_ms` is deleted. Out of scope: `chrono` in `redis.rs:574` and the test
  files (`conformance_redis.rs`, `redis_failover.rs`) — those are `timestamp_nanos`
  unique-id seeds, not pipeline wall-clock.
- **No new abstractions beyond the shared module + Clock injection** (YAGNI/KISS).
  Never encode plan/phase/issue IDs in code comments, test names, or commits.

## Dependencies

- **blockedBy `260705-0953-gh-196-risk-admin-api-engine-wiring`.** Item 2 (delete
  the risk_api mappers via serde round-trip) is implemented there (GH-196 Phase 3),
  and GH-196 also churns `risk_api.rs` GET/PUT — landing GH-207's `risk_api.rs`
  helper migration on top avoids a merge conflict. If GH-196 has **not** landed
  when GH-207 is implemented, item 2 stays deferred and Phase 3 records it as
  "pending upstream" (still migrate risk_api's `resolve_path`/`write_yaml` in
  Phase 1 regardless — that is independent of the mapper deletion).
- **Overlaps `260705-0958-gh-197-geo-rules-enforcement-wiring` on `geo_api.rs`.**
  GH-197 rewrites geo *handlers* (`create/patch/delete_geo_rule`, schema/mapping,
  `lookup_ip`) but keeps the flat-row file shape and does **not** touch the
  `rules_path`/`write_rules` persistence helpers this plan migrates. Different
  lines, same file — whichever lands second rebases the small helper swap. No
  logical conflict (both preserve the `{rules: [...]}` file contract).

## Acceptance Criteria

- [ ] Single `crates/waf-api/src/config_files.rs`; `resolve_path` + atomic writer
      defined once; all 9 modules call it; per-module read semantics preserved
      (Phase 1).
- [ ] `tls.rs` documented as out-of-scope in the plan; unchanged (Phase 1).
- [ ] `Clock` lives in `crate::time`; ddos detector paths unchanged via shim;
      `ScoringAggregator` + worker + `start_purge_loop` take a `Clock`;
      `unix_now_ms` and `memory.rs`/`worker.rs` pipeline `chrono` removed; a
      MockClock test drives aggregator submit→process lag deterministically
      (Phase 2).
- [ ] risk_api hand-mapped defaults deleted via GH-196 serde round-trip, or item
      recorded as deferred-to-GH-196 if not yet landed (Phase 3).
- [ ] Existing waf-api + waf-engine tests green before and after; `cargo build`,
      `clippy`, `fmt` clean; no public HTTP contract or config-file shape change
      (Phase 3).

## Validation

- Per phase: `cargo test -p waf-api` (Phase 1), `cargo test -p waf-engine risk::`
  and `checks::ddos::` (Phase 2), full `cargo test` + `cargo clippy --all-targets`
  + `cargo fmt --check` (Phase 3).
- Behavior-preserving proof: capture the touched test suites green on HEAD
  *before* each phase, re-run *after*; diff must show refactor-only changes.
