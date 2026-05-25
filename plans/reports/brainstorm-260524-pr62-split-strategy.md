---
report: brainstorm
date: 2026-05-24
scope: PR #62 deep review + ship strategy
branch: main @ 61a75e6b
status: design-approved, awaiting plan
---

# PR #62 Deep Review + Ship Strategy

## Problem statement

PR #62 (`feat(audit): backend gap layer for admin panel security events`) đã mở 6 ngày, 5078 LOC, 46 files, 0 reviews, CONFLICTING với main. Author = lotusdubai. Giải quyết gap thực tế của issue #60: `audit_emitter` infra + relay/tx_velocity persistence + 2 admin API endpoints. Docs (`PRX-WAF-TechnicalGuide-{EN,VI}.md`) document `TX-SEQ-*` / `TX-WITHDRAW-*` / `TX-LIMIT-*` như đã hoạt động, nhưng main không emit — docs aspirational, PR #62 sẽ làm chúng đúng sự thật.

Cần ship strategy + best-practice cleanup; không merge PR #62 nguyên trạng.

## Approaches evaluated

| Path | Pros | Cons | Verdict |
|---|---|---|---|
| **A. Tách 3-4 PR nhỏ** | Mỗi PR <800 LOC, dễ review, ship dần, isolate breaking change | Coordination cost, dependency chain | **CHỌN** |
| B. Polish + ship single PR | 1 review session | Size là root cause 0-reviews; rework conflict 7 files | Loại |
| C. Scope-trim, ship 1 PR | Smaller surface | Vẫn ~3k LOC, vẫn nhiều hơn comfort zone reviewer | Loại |
| D. Redesign | Optionally fit main hiện tại | 90% code đã valid, lãng phí | Loại |

## Best-practice cleanup (mandatory regardless of split)

| # | Cleanup | Reason | Files affected |
|---|---|---|---|
| BP1 | Remove **147 references** finding codes (`F1.3`, `F1.4`, `F1.5`, `CC4`, `C2`, `I4`, `F3.1`, `F4.1`, "red-team patched") khỏi code comments + test assertions | Vi phạm `.claude/rules/review-audit-self-decision.md` §5: comments must explain *why*, not *origin* | `audit_emitter/{mod,broadcast,bucket,worker}.rs`, `relay/audit_map.rs`, `tx_velocity/audit_map.rs`, `risk/canary.rs`, `tests/audit_emitter_{unit,cardinality}.rs` |
| BP2 | **Drop honeypot scaffolding** (`HONEYPOT_RULE_ID`, emit branch trong `risk/scorer.rs`, 2 regression tests) | Iron Rule #3 — dormant branch = incomplete impl. Re-add khi Scorer wired vào gateway (1-line change tại đó). Naming khi re-add: **`HONEYPOT-001`** (2-segment, symmetric với `BOT-XFF-*` / `TX-SEQ-*`) | `risk/canary.rs`, `risk/scorer.rs` |
| BP3 | **Activation knob TOML thay vì env var** | `WAF_AUDIT_EMITTER_ENABLED=1` chệch convention `configs/default.toml`. Đổi sang `[audit_emitter] enabled = false`; ArcSwap hot-reload đã support | `waf-common/src/config.rs`, `configs/default.toml`, `audit_emitter/config.rs` |
| BP4 | **Replace brittle constant-equality test** `assert_eq!(POST_PANIC_BACKOFF, Duration::from_secs(1))` | Test literal value → tuning break test for no behavioural reason. Thay bằng behavioural assert (e.g. "after panic, next event drained within 2s") | `audit_emitter/worker.rs` test module |
| BP5 | **Resolve API endpoint overlap**: deprecate stub `/api/threat-intel/status` (returns `available: false`); reputation API `/api/reputation/{status,refresh}` là canonical. Stub giữ 1 release với `X-Deprecated: true` header + 308 redirect sang `/api/reputation/status` | Tránh FE có 2 source of truth | `waf-api/src/stats.rs:236-253`, `waf-api/src/reputation.rs` (mới), `server.rs` routes |

## Recommended solution: 4-PR split

### PR-A: `feat(audit-emitter): shared rate-limited emission core`
**Branch**: `feat/audit-emitter-core-issue-60-a`
**LOC estimate**: ~900 (5 new modules + tests + config)
**Files**:
- New: `crates/waf-engine/src/audit_emitter/{mod,broadcast,bucket,config,metrics,worker}.rs`
- New: `crates/waf-engine/tests/audit_emitter_unit.rs`
- New: `crates/waf-engine/tests/audit_emitter_cardinality.rs`
- Modify: `crates/waf-engine/src/lib.rs` (add `pub mod audit_emitter`)
- Modify: `crates/waf-engine/src/engine.rs` (add `set_audit_emitter` setter; no callers yet)
- Modify: `crates/waf-engine/Cargo.toml` (no new deps — `arc-swap` đã có)
- Modify: `crates/waf-common/src/config.rs` + `configs/default.toml` (add `[audit_emitter]` section per BP3)

**Acceptance**:
- `cargo check --features gateway/valkey` pass trong Docker rocky9 + rust 1.95
- 31 unit + 10 integration + 4 cardinality tests pass
- Coverage ≥ 90% (per rules.md)
- Default-off in prod (TOML `enabled = false`)
- BP1 (no finding codes) + BP4 (no brittle test) applied
- `cargo fmt --all -- --check` clean, `cargo clippy --workspace --all-targets` clean

**Out of scope**: caller wiring (PR-B, PR-C), API endpoints (PR-D), honeypot.

---

### PR-B: `feat(relay): emit BOT-XFF / BOT-RELAY signals to security_events`
**Branch**: `feat/audit-emitter-relay-wiring-issue-60-b`
**Blocked by**: PR-A merged
**LOC estimate**: ~600
**Files**:
- New: `crates/waf-engine/src/relay/audit_map.rs` (signal → CreateSecurityEvent mapping)
- New: `crates/waf-engine/src/relay/intel/{mod,status}.rs` (feed status registry — needed cho PR-D `/api/reputation/status`, nhưng infra layer ở PR-B)
- Modify: `crates/waf-engine/src/relay/mod.rs`
- Modify: `crates/gateway/src/proxy.rs` (relay signal hook tại post-resolve, exact line shift sau commit `331efc43`/PR #103 — verify trong implementation)

**Acceptance**:
- `BOT-XFF-*`, `BOT-RELAY-*`, `BOT-RELAY-TOR-001` rule_ids xuất hiện trong `security_events` khi relay fire
- Smoke test trong Docker: trigger XFF spoof → row inserted với expected rule_id
- Coverage ≥ 90%
- Tests dùng mock DB (per rules.md item 6: "create mocks" for dependencies)
- BP1 cleanup applied

**Conflict resolution note**: `proxy.rs:432` (PR #62) đã shift do commit `331efc43`. Verify hook anchor mới (likely sau `effective_host_header()` resolve nhưng trước upstream peer).

---

### PR-C: `feat(tx-velocity): emit TX-SEQ / TX-WITHDRAW / TX-LIMIT signals`
**Branch**: `feat/audit-emitter-tx-velocity-wiring-issue-60-c`
**Blocked by**: PR-A merged (PR-B parallel OK — no shared files)
**LOC estimate**: ~700
**Files**:
- New: `crates/waf-engine/src/checks/tx_velocity/audit_map.rs`
- Modify: `crates/waf-engine/src/checks/tx_velocity/{check,recorder,mod}.rs` (insert `record_with_audit` emit hook giữa classifier result và `tokio::spawn(submit)`)
- Modify: `crates/waf-engine/src/engine.rs` (`set_audit_emitter` propagate vào `tx_velocity_store`)

**Acceptance**:
- 3 rule_ids emit khi classifier breach
- Mock DB tests pass
- Coverage ≥ 90%
- BP1 cleanup applied

---

### PR-D: `feat(waf-api): reputation status/refresh + risk-distribution endpoints`
**Branch**: `feat/audit-emitter-admin-api-issue-60-d`
**Blocked by**: PR-B merged (cần `FeedStatusRegistry` từ PR-B)
**LOC estimate**: ~700
**Files**:
- New: `crates/waf-api/src/reputation.rs` (`GET /api/reputation/status`, `POST /api/reputation/refresh`)
- New: `crates/waf-api/src/stats_risk_distribution.rs` (`GET /api/stats/risk-distribution`)
- Modify: `crates/waf-api/src/server.rs` (routes + deprecate `/api/threat-intel/status` per BP5: 308 redirect + `X-Deprecated: true` header)
- Modify: `crates/waf-api/src/stats.rs` (`threat_intel_status` → deprecated, redirect)
- Modify: `crates/waf-api/src/state.rs`, `lib.rs`, `panel_api.rs` (wiring)
- Modify: `crates/waf-storage/src/{db,repo}.rs` (risk-distribution query — option A: action-band approximation, response carries `approximation: true`)

**Acceptance**:
- 2 endpoints return 200 với valid payload
- `/api/threat-intel/status` 308 → `/api/reputation/status` + `X-Deprecated: true`
- Coverage ≥ 90% (7 band-mapping tests từ original PR #62 mang sang)
- FE-side smoke (curl) test trong Docker
- Conflict resolution: `server.rs`, `repo.rs`, `lib.rs` đã bị touched bởi PR #99/#100 — rebase carefully

---

### (Deferred) Future PR-E: Honeypot activation
Khi Scorer wired vào gateway (separate roadmap), add:
- `HONEYPOT_RULE_ID` constant tại `risk/canary.rs`
- Emit branch tại `risk/scorer.rs`
- `Scorer::set_audit_emitter` getter + caller propagate
- Tests cover activation path
- Cesc/protonmns ack `HONEYPOT-001` naming via #60 thread (per V2 spirit)

## Implementation risks

1. **Conflict resolution `proxy.rs`** (1401 LOC, recently touched by PR #91/#92/#103/#101 — Host header + TLS dance). PR-B's hook anchor likely shifted. Mitigation: implementer verify trong từng PR rebase.
2. **`engine.rs:set_audit_emitter` propagation** đã đổi structure sau 6 ngày. Mitigation: re-read main `engine.rs` (942 LOC) trước khi extract patch.
3. **Test coverage gate 90%** mandatory per rules.md item 6. PR #62 hiện chưa public coverage report. Mitigation: chạy `cargo llvm-cov` trong Docker từng PR.
4. **Squash 1 commit/PR** per rules.md item 10. Mitigation: implementer squash khi push.
5. **Glibc compat**: build trong Docker `rocky9 + rust 1.95.0` per summary.md §13. Mitigation: reuse build command từ summary.

## Success metrics

- Mỗi PR PR-A, PR-B, PR-C, PR-D merged trong ≤ 2 review cycles (vs 0 reviews trên PR #62 hiện)
- 0 finding-code references trong final code (regex check)
- `cargo fmt`, `cargo clippy`, `cargo test`, coverage ≥ 90% pass trong Docker
- Tổng LOC = ~2900 (PR-A 900 + B 600 + C 700 + D 700) vs 5078 PR #62 — giảm 43% (do drop honeypot + scaffolding + plan/report files không cần ship lại)
- Issue #60: track audit_emitter live trên prod sau PR-D + PR-E deferred

## Next steps

1. **Close PR #62** với comment redirect sang 4 PR mới (giữ branch `feat/issue-60-backend-gap` 1 release làm reference)
2. **Run `/ck:plan`** với plan path = brainstorm summary này để extract 4 phase files (PR-A, PR-B, PR-C, PR-D)
3. Implementer chạy từng phase qua `/ck:cook --phase <N>`
4. Cuối mỗi phase: `/ck:test` → `/ck:code-review` → tạo PR (chưa merge, per user instruction)
5. CI checks pass trên mỗi PR trước khi assign reviewers

## Open questions

- Có cần migrate `attack_logs` schema (legacy) cho risk-distribution option B exact band không? (Hiện option A approximation đã đủ FE work.) Defer tới khi FE feedback `approximation: true` UX khó chịu.
- WS broadcast hiện đi vào `BroadcastSink` trait — main đã có Notification WS infra (`waf-api/src/notifications.rs` + `websocket.rs`); cần verify trong PR-A là `DbBroadcastSink` reuse infrastructure đó hay tạo channel riêng. Reuse preferred (DRY) — nhưng nếu infra hiện không support per-event push thì PR-A có channel riêng tạm thời.
