---
plan: pr-62-split-audit-emitter-ship
title: "PR #62 split + audit_emitter ship (issue #60)"
status: pending
created: 2026-05-24
revised: 2026-05-24
mode: tdd
source_brainstorm: plans/reports/brainstorm-260524-pr62-split-strategy.md
red_team_synthesis: plans/260524-1327-pr-62-split-audit-emitter-ship/reports/red-team-synthesis-260524.md
supersedes_pr: 62
issue: 60
---

# Plan: PR #62 split → 4 PRs (audit_emitter + admin panel backend gap)

## Context

PR #62 (`feat(audit): backend gap layer for admin panel security events`, 5078 LOC, 46 files, 0 reviews, 6 ngày stale, CONFLICTING) tách thành **4 PR nhỏ + cleanup mandatory + 1 deferred PR-E (honeypot)**. Brainstorm summary: `plans/reports/brainstorm-260524-pr62-split-strategy.md`.

**Constraint:** không merge ngay — chỉ tạo PR + đợi CI + reviewers (per user instruction). Follow `rules.md`.

## Approach

TDD per phase: viết failing tests trước, implement đến pass, refactor. Lock behavior `relay/`, `tx_velocity/` hiện tại trước khi thêm emit hooks.

## Phases

| # | Phase | Blocked by | LOC est | PR branch |
|---|---|---|---|---|
| 01 | audit-emitter core + intel_status + CI pre-flight (TDD) | — | ~1200 | `feat/audit-emitter-core-issue-60-a` |
| 02 | relay wiring (TDD) | 01 | ~550 | `feat/audit-emitter-relay-wiring-issue-60-b` |
| 03 | tx_velocity wiring (TDD) | 01 (parallel với 02) | ~750 | `feat/audit-emitter-tx-velocity-wiring-issue-60-c` |
| 04 | admin API endpoints (TDD) | 01 (parallel với 02/03) | ~900 | `feat/audit-emitter-admin-api-issue-60-d` |
| — | (deferred) honeypot activation | Scorer wired into gateway | ~250 | future |

**Note**: phase 04 dependency raised từ [2] sang [1] sau red-team F-F-9 — `FeedStatusRegistry` moved to phase 01 (empty default). Phase 02/03/04 có thể chạy parallel sau phase 01 merge.

## Cross-phase invariants (BP1–BP7)

| # | Invariant | Enforce in |
|---|---|---|
| BP1 | 0 finding-code references (`F1.x`, `CC4`, `C2`, `I4`, `F3.x`, `F4.x`, "red-team patched") trong comments/tests. Grep gate cuối mỗi phase. | All phases |
| BP2 | Honeypot scaffolding KHÔNG ship trong 4 phase này | Phase 01 (drop `risk/canary.rs` + `risk/scorer.rs` mods) |
| BP3 | Activation knob TOML config (`[audit_emitter] enabled = false`), KHÔNG env var | Phase 01 |
| BP4 | Behavioral test (no literal-constant assert) cho `worker.rs` panic-recovery; dùng `tokio::test(start_paused=true)` + `time::advance` cho mọi backoff/window/GC tests | Phase 01 |
| BP5 | `/api/threat-intel/status` deprecate **2-step**: this release tr 200 + same JSON shape + RFC 9745 `Deprecation: true` + RFC 8594 `Sunset: <date>` + `Link: </api/reputation/status>; rel=successor-version`. 308 redirect defer next release (separate PR). | Phase 04 |
| BP6 | Rule_id grammar `^[A-Z]+-[A-Z]+-\d{3}$` validated at emit time (fail loud in tests, log+drop in prod). `BOT-RELAY-TOR-001` rename → `BOT-TOR-001` ở phase 02 + tech guide update same PR. | Phase 01 (regex), 02 (rename) |
| BP7 | Observability invariant: mỗi `metrics.inc_*` (rate_limited, queue_full_dropped, db_insert_failed, worker_restarted) **pair** với `tracing::warn!` hoặc `error!` (target=`audit_emitter`). Test `worker_panic_emits_error_log`. | Phase 01 |
| BP8 | Test stratification: unit qua mocks (rules.md item 6); integration qua testcontainers Postgres smoke per phase, CI-required, **EXCLUDED khỏi coverage gate numerator** | All phases |

## Constraints (rules.md)

- 1 commit per PR (squash khi push)
- PR description: senior-dev style, không có personal details / original prompt
- CI checks pass trên mỗi PR trước khi assign reviewers
- Docker build (rocky9 + rust 1.91), local env không có Rust
- Test coverage ≥ 90% per phase
- Mock dependencies (DB, WS) trong tests
- Conventional commits (`feat:`, `fix:`, …)
- Vietnamese answers trong reports/comments (nhưng commit messages tiếng Anh per convention codebase)

## Success criteria (whole plan)

- 4 PRs mở trên GitHub, CI green, chưa merge
- `cargo clippy --workspace --all-targets` clean trên mỗi PR
- `cargo fmt --all -- --check` clean
- Coverage report cho mỗi PR ≥ 90%
- 0 finding-code references trong final code (regex check `grep -rE '(F[0-9]\.[0-9]|CC[0-9]|red-team patched)' crates/`)
- PR #62 closed với link sang plan này + 4 PR mới
- Docs (`PRX-WAF-TechnicalGuide-{EN,VI}.md`) reflect reality: sau khi 4 PR merged, `BOT-XFF-*`/`BOT-RELAY-*`/`TX-SEQ-*`/`TX-WITHDRAW-*`/`TX-LIMIT-*` thực sự emit

## Risk register

| Risk | Mitigation |
|---|---|
| Conflict resolution `proxy.rs` (PR-B): hook anchor `proxy.rs:432` shift sau commit `331efc43`/PR #103 | Phase 02 verify lại exact line sau khi `effective_host_header()` resolve |
| `engine.rs:set_audit_emitter` propagation đã đổi structure trên main | Phase 01 re-read main `engine.rs` (942 LOC) trước khi extract |
| 90% coverage gate fail | TDD per phase đảm bảo test trước; mock DB cho unit; testcontainers smoke cho integration (excluded từ gate per BP8) |
| PR-D rebase conflict với PR #99/#100 đã merge (server.rs, repo.rs, lib.rs) | Phase 04 rebase trên main tươi, verify route ordering |
| `DbBroadcastSink` overlap với `notifications.rs` WS infra | Phase 01 verify reuse vs separate channel; default reuse (DRY) |
| **Anonymous DoS qua `/api/reputation/refresh`** (red-team F-S-1 CRITICAL) | Phase 04: admin-auth middleware bắt buộc + cluster-safe gate via `pg_try_advisory_lock(REPUTATION_REFRESH_LOCK_ID)` (RAII guard); refused calls return 200 + `refresh_skipped: true` |
| **Phase 01 orphan API silent no-op** (F-F-3 CRITICAL): enabled=true nhưng zero callers wired → DB empty | Phase 01 startup warn invariant; test `enabled_with_no_callers_logs_warning` |
| **XFF spoof poisoning + IP rotation bypass per-IP gate** (F-S-3/F-S-4 HIGH) | Phase 02 dùng peer_addr only; phase 01 add 2nd-layer global token bucket per rule_id |
| **Stored-XSS / PII leak via detail field** (F-S-5 HIGH) | Phase 02/03 audit_map → structured JSON, strip query-string, 4KB cap, escape test |
| **CI runner toolchain mismatch** (F-F-8 HIGH) | Phase 01 Step 0 pre-flight check `.github/workflows/ci.yml` rust-toolchain; update CI same PR nếu mismatch |
| **DashMap Arc-String unbounded memory** (F-F-7 HIGH) | Bucket key = `(u128, &'static str)` Copy (IPv4 via `to_ipv6_mapped`) |
| **`risk_distribution_query` unbounded DB CPU** (F-S-7 MED) | Mandatory index migration + `statement_timeout=5s` + cap hours default 168 |

## Out of scope

- Honeypot activation (deferred — chờ Scorer wired vào gateway)
- ML scoring (FR-046)
- Live WS replay of historical audit rows
- Risk-distribution option B (exact band qua `security_events.risk_score` schema migration) — option A approximation OK
- FE wiring (FE team owns)

## Open questions

- `DbBroadcastSink` reuse `notifications.rs` infra hay channel riêng? → Phase 01 verify khi đọc `notifications.rs` + `websocket.rs`
- Risk-distribution legacy `attack_logs` table populate? → Defer per brainstorm Open Q
