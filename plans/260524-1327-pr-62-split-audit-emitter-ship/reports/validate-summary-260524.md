---
report: validate-summary
plan: pr-62-split-audit-emitter-ship
date: 2026-05-24
gate: critical-questions interview
status: passed
---

# Validate Summary — Critical Questions Resolved

Post-red-team plan có 4 điểm hand-wavy chạm hard-spec decision boundaries. Resolved.

## Decisions locked

| # | Question | Decision | Applied to |
|---|---|---|---|
| V1 | F-S-1 cluster gate cho `/api/reputation/refresh` | **DB advisory lock** `pg_try_advisory_lock(REPUTATION_REFRESH_LOCK_ID)` (RAII guard via `Drop`); cluster-safe. Lock-busy → 200 + `refresh_skipped: true` | phase-04 §Functional, §2; plan.md risk register |
| V2 | F-S-4 layer-2 global token bucket rate | **Flat 100/s/rule** default cho 6 built-in rule_ids; per-rule override map qua `[audit_emitter.global_rate]` TOML. Refill async qua `Semaphore::add_permits(deficit)` mỗi 1s | phase-01 §Functional, §Architecture, §Create (`global_bucket.rs`) |
| V3 | F-S-5 detail sanitisation library | **`serde_json::to_string` + manual HTML escape** (`<`, `>`, `&`) + 4KB boundary-safe truncate. NO new dep. Shared helper `audit_emitter::sanitize::sanitize_detail` ship trong phase 01; phase 02/03 import | phase-01 §Functional, §Create (`sanitize.rs`); phase-02 §2.1; phase-03 §Functional |
| V4 | F-A-7 schema versioning | **In-body marker only**: `data.api_version: "v2"` + `data.schema: "<endpoint>.v1"`. URL gi unversioned (`/api/reputation/...`, `/api/stats/...`, `/api/audit/...`). Phase 4b future có thể add `/api/v2/` nếu breaking change phát sinh | phase-04 §Functional |

## F-F-7 invariant documented (no question needed)

Bucket key `(u128, &'static str)` requires rule_id là `&'static str` const literal:
- audit_emitter chỉ cover **built-in** rule_ids (`BOT-XFF-001`, `BOT-RELAY-001`, `BOT-TOR-001`, `TX-SEQ-001`, `TX-WITHDRAW-001`, `TX-LIMIT-001`, future `HONEYPOT-001`, plus internal `AUDIT-RATELIMIT-001`)
- Custom user-defined rules (FR-003 admin upload) KHÔNG đi qua audit_emitter — separate code path
- Documented trong `mod.rs` doc comment + tested via regex contract (BP6)

## Carry-over (acceptable deferrals)

| # | Item | Why deferred |
|---|---|---|
| C1 | `DbBroadcastSink` reuse `notifications.rs` WS infra hay separate channel | Cần đọc `notifications.rs` + `websocket.rs` (200+ LOC) trong implementation; default = reuse (DRY). Phase 01 §2.4 |
| C2 | `proxy.rs` hook anchor exact line | Verify trong implementation sau khi diff commit `331efc43`. Phase 02 §2.3 |
| C3 | `recorder.rs` Arc field vs param pattern | Verify khi đọc 521 LOC. Phase 03 §2.2 |
| C4 | `panel_api.rs` admin-auth pattern wrap auto hay explicit | Verify khi đọc. Phase 04 §Modify |

Tất cả C1-C4 là legitimate scout-during-implementation steps, không phải spec gap.

## Plan files final state

| File | Status |
|---|---|
| `plan.md` | Updated — BP1–BP8 invariants, dependency graph (phase 04 ← phase 01), risk register reflects 4 validate decisions |
| `phase-01-audit-emitter-core.md` | Updated — ~1200 LOC est, 11 red-team findings + 3 validate decisions applied (TOML global rate, sanitize helper, F-F-7 invariant doc) |
| `phase-02-relay-wiring.md` | Updated — ~550 LOC, rule_id rename `BOT-TOR-001`, F-S-3 peer_addr only, F-S-5 sanitize via phase-01 helper |
| `phase-03-tx-velocity-wiring.md` | Updated — ~750 LOC, F-S-5 sanitize via phase-01 helper, HMAC session_fp truncate 16 hex |
| `phase-04-admin-api-endpoints.md` | Updated — ~900 LOC, 2-step deprecation (200 + Deprecation/Sunset/Link, NOT 308), admin-auth, advisory lock, `/api/audit/metrics`, mandatory index, in-body api_version v2 only |
| `reports/red-team-synthesis-260524.md` | Existing |
| `reports/validate-summary-260524.md` | This file |

## Whole-plan consistency gate

| Check | Result |
|---|---|
| 0 stale `308 redirect` outside phase 4b/defer context | PASS |
| 0 stale `BOT-RELAY-TOR-001` outside rename narrative | PASS |
| 0 stale `X-Deprecated` outside drop-narrative | PASS |
| Dependency graph: 01 ← (02 ‖ 03 ‖ 04) | PASS |
| LOC sum ≈ 3400 (matches synthesis estimate) | PASS |
| BP1–BP8 invariants present trong plan.md | PASS |
| All 24 red-team findings + 4 validate decisions traced to specific phase | PASS |

## Open carry-over questions (out of plan scope)

- Existing workspace có sẵn `governor` / similar rate-limit primitive không? (cosmetic — `Semaphore` đủ; ưu tiên khi implement)
- Production `security_events` row count → `CREATE INDEX CONCURRENTLY` đủ hay cần off-peak window? (Phase 04 step 0 verify staging trước)
- Reverse-proxy mount prefix có dùng prod không? (F-A-9 test scope)
- Release cadence (weekly main-merge hay tagged release)? (F-A-1 sunset date calculation)

## Ready for next step

Plan đầy đủ for `/ck:cook` execution. 4 PRs sẽ create theo dependency chain (PR-A first, B/C/D parallel sau A merge). KHÔNG merge tự động — đợi CI + reviewers per user instruction.
