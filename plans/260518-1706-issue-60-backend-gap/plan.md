---
title: "Issue #60 Backend Gap — Audit Event Emission Layer"
status: in-progress
priority: P0
created: 2026-05-18
issue: https://github.com/future-and-go/mini-waf/issues/60
blockedBy: []
blocks:
  - project:260501-2003-fr007-relay-proxy-detection  # FE chờ rule_id labeling
related:
  - project:260504-1632-fr-012-transaction-velocity  # FR-012 detection done, missing emit
  - project:260506-1329-fr-025-cumulative-risk-scoring # FR-025 score exists, missing API surface
  - project:260511-1114-fr006-challenge-engine        # FR-006 done, FE only
---

# Issue #60 Backend Gap — Audit Event Emission Layer

## Context

Issue #60 (`Admin Panel Missing FR Coverage`) liệt kê 7 sub-issue FE. Phân tích codebase (`plans/reports/analysis-260518-issue-60-backend-gap.md`) cho thấy **4/7 sub-issue có backend gap thật**: detection modules (relay, tx_velocity, canary) phát hiện signal nhưng không persist row `security_events` với `rule_id` query-able. Hệ quả: nếu chỉ làm FE, các page mới (Relay tab, TX Velocity page, Honeypot filter) sẽ rỗng trong demo & Attack Battle.

Plan này là **extension layer** — không re-implement detection logic, chỉ thêm "event emission" path từ các detection module → `security_events` table.

## Goal

Khép kín gap giữa internal detection signals và visible audit trail, đồng thời bổ sung 2 API endpoint còn thiếu (reputation status/refresh + risk distribution).

**Mandatory acceptance:**

1. `security_events` chứa row với rule_id `BOT-RELAY-*`, `BOT-PROXY-*`, `BOT-XFF-*` khi relay providers phát hiện signal.
2. `security_events` chứa row với rule_id `TX-SEQ-*`, `TX-WITHDRAW-*`, `TX-LIMIT-*` khi TX velocity breach detected.
3. `security_events` chứa row với rule_id `HONEY-*` action=`block` khi canary path bị hit.
4. `GET /api/reputation/status` + `POST /api/reputation/refresh` hoạt động với admin auth.
5. `GET /api/stats/risk-distribution` trả về band-aggregated counts (decision A vs B chốt ở Phase 0).
6. Cardinality test pass: 1k req/s sustained ép cùng 1 IP signal → DB INSERT ≤ 1/60s/IP/rule_id.
7. 90%+ line coverage trên `audit_emitter` module + signal→rule_id maps.
8. Không regression trên 7 plan FR đã merged/in-progress.
9. **Feature flag** `[audit_emitter] enabled = true|false` trong global config (env-layered per V1: prod=false, staging=true default) + `AuditEmitterConfig::enabled` field; kill switch qua config reload không cần redeploy.
10. **Observability** cho 4 silent-loss mode: rate_limited, queue_full_dropped, worker_panic_restarted, db_insert_failed — 4 metrics + warn log + 1 supervisor task auto-restart worker.
11. **WebSocket broadcast decoupled** từ rate-limit gate: WS subscribers nhận mọi detection (cheap, in-memory), DB chỉ persist 1/window/IP/rule_id.

## Approach (chốt từ research)

| Component | Quyết định | Nguồn |
|-----------|-----------|-------|
| Bucket store | `Arc<DashMap<Arc<str>, Entry>>` — mirror `MemoryCounterStore` (ddos/store/memory.rs) | researcher-260518-audit-emitter-rate-limit.md |
| Bucket key | `"{client_ip}#{rule_id}"` (Arc<str>) | same |
| Window / TTL | 60s emit window, 120s entry TTL, 60s GC tick | same |
| Max keys | 100k (default), LRU evict oldest `expires_ms` khi vượt | same |
| Backpressure | `tokio::sync::mpsc::channel(512)` + drop-warn khi `try_send` Full | same |
| Race | Unconditional `replace` (lossy update; audit semantics tolerant) | same |
| Risk distribution endpoint | **Option A — approximation từ `action_breakdown`** (85% accuracy, 2h, no schema migration). Option B rejected vì `WafDecision` không carry `risk_score` → plumbing thêm ~6-8h + hot-path impact. | researcher-260518-risk-distribution-approach.md |

## Phases

| # | Phase | Status | Priority | Effort | Depends on |
|---|-------|--------|----------|--------|------------|
| 0 | [Entry-point discovery + research consolidation](phase-00-research-consolidation.md) | pending | P0 | 3h | — |
| 1 | [Shared audit emitter + rate limiter](phase-01-audit-emitter.md) | pending | P0 | 6h | 0 |
| 2 | [FR-007 relay event emission](phase-02-relay-emission.md) | pending | P0 | 5h | 1 |
| 3 | [FR-012 tx_velocity event emission](phase-03-tx-velocity-emission.md) | pending | P0 | 7h | 1 |
| 4 | [FR-028 honeypot event emission](phase-04-honeypot-emission.md) | **blocked** (reviewer ack rule_id) | P0 | 2h | 1 + reviewer-ack |
| 5 | [FR-042 reputation status/refresh API](phase-05-reputation-api.md) | pending | P1 | 5h | — |
| 6 | [FR-025 risk distribution API](phase-06-risk-distribution-api.md) | pending | P1 | 2h | 0 |
| 7 | [Integration tests + cardinality validation](phase-07-tests-and-cardinality.md) | pending | P0 | 5h | 2,3,4 |

**Critical path:** 0 → 1 → (2 ∥ 3 ∥ 4) → 7. Phase 5 và 6 chạy song song với critical path.

**Total estimate:** ~28-32h backend sau khi corrected entry points + supervisor + feature flag (P0: 28h, P1: 7h).

## Out of scope

- Frontend cho 7 sub-issue (do FE team triển khai sau khi BE landed).
- Schema migration adding `security_events.risk_score INTEGER` (đợi Phase 6 chốt approach).
- New detection rules — chỉ wire existing detection → emission.
- ML scoring (FR-046).
- Real-time WebSocket push của audit events.

## Risks & open questions

- **Rate-limit suppression vs audit completeness**: bucket có thể che hit thật trong burst. Mitigation: metric counter cho suppressed events, alert nếu > 5%/phút.
- **Honeypot rule_id prefix** chưa chốt với reviewer (`HONEY-001` vs `HONEYPOT-001` vs `CANARY-001`). Phase 0 sẽ chốt.
- **Risk distribution accuracy** (option A approximation vs option B schema migration) — chốt ở Phase 0 sau khi đọc researcher #2.
- **Cross-plan coordination**: 5 FR plan đã in-progress/completed; nếu owner đang refactor, có thể conflict. Phase 0 walk entry points THỰC TẾ: `gateway/src/proxy.rs:432` (relay), `recorder.rs:201` (tx_velocity classifier signal emit), `risk/scorer.rs:178` (canary caller).

## Red-team patches applied (2026-05-18)

Red-team review (`reports/red-team-260518-plan-review.md`) found 5 load-bearing failures. Patches applied:

| # | Issue | Fix location |
|---|-------|--------------|
| F2.1/F3.1/F4.1/F5.1 | Entry points trong các phase 2-5 hoàn toàn sai (engine.rs không phải nơi đúng) | Phase 0 rewrite — code-walk discovery, not "verify unchanged" |
| F1.3 | Bucket-claim BEFORE try_send → 120s blackout per IP/rule_id sau 1 lần Full | Phase 1 §Architecture — reorder: try_send first, claim bucket on Success |
| F1.2 | Plan ghi nhầm `try_send` drop oldest — thực tế drop NEW event | Phase 1 §Architecture + metric tên đổi `dropped_new_on_full` |
| F1.5/CC4 | `repo.broadcast_event` fire chỉ khi INSERT thành công → WS feed mất 98% events | Phase 1 — emit WS broadcast BEFORE rate-limit gate (decouple) |
| CC2 | Không có rollback / feature flag | plan.md acceptance + Phase 1 — `AuditEmitterConfig::enabled: bool` |
| F0.1 | Default `HONEY-001` sau 24h timeout polluteHistorical rows | Phase 0 — escalate thay vì default, const ở 1 chỗ + DB UPDATE script trong cùng PR |
| F2.2 | Mapping Signal enum sai (5 variants không tồn tại) | Phase 2 §Requirements — bảng đúng theo `relay/signal.rs:30-47` |
| F6.2 | "50/50 split challenge → yellow+orange" là số bịa | Phase 6 — leave `elevated` 0 hoặc dùng midpoint thresholds thực tế |
| F6.1 | `CREATE INDEX` không CONCURRENTLY (option B) | Phase 6 — drop index trong migration; manual op nếu cần |
| F7.1 | Cardinality test chỉ 1 IP — bot net 10k IPs dangerous case không cover | Phase 7 — thêm multi-IP stress test |

Estimate revised: **22h → 28-32h backend** sau khi correct entry points.

## Reports

- Analysis: `plans/reports/analysis-260518-issue-60-backend-gap.md`
- Researcher 1 (rate-limit): `plans/reports/researcher-260518-audit-emitter-rate-limit.md`
- Researcher 2 (risk distribution): `plans/reports/researcher-260518-risk-distribution-approach.md` (compiled từ scout trực tiếp; agent stalled)
- Red-team review: `plans/260518-1706-issue-60-backend-gap/reports/red-team-260518-plan-review.md`

## Validation Log

### Session 1 — 2026-05-18

Validation interview kết quả (4 questions, all resolved):

| # | Decision point | Choice | Propagation |
|---|---------------|--------|-------------|
| V1 | Feature flag default state | **Per-env layered (prod=false, staging=true)** | Phase 1: config reads env-specific override; KHÔNG hardcode `enabled=true`. Phase 0: verify env-layer plumbing trong `crates/waf-common/src/config.rs`. |
| V2 | Honeypot rule_id locking | **Ask reviewer + block Phase 4 cho ack** | Phase 4 frontmatter `dependencies: [1, "reviewer-ack-honeypot-rule-id"]`. Phase 0 Step 7: post issue comment + add `BLOCKED` tag tới Phase 4 task. |
| V3 | Channel capacity default | **Auto-tune `num_cpus::get() * 256`** | Phase 1: `AuditEmitterConfig::default()` uses `num_cpus::get().saturating_mul(256).max(512)`. Phase 0: verify `num_cpus` crate trong workspace Cargo.toml (likely already qua tokio dep tree, else add). |
| V4 | WS BroadcastSink prod impl | **Wire vào existing `repo.broadcast_event`** | Phase 1: `BroadcastSink::ws_impl()` wrap pattern từ `crates/waf-storage/src/repo.rs:430`. Phase 0 Step 2.5: copy verbatim function chain `broadcast_event` → WS hub. |

### Whole-Plan Consistency Sweep

- [x] phase-01 updated: feature flag env-layered + auto-tune capacity + WS wire reference
- [x] phase-00 updated: 3 extra walk targets (num_cpus, env config layer, broadcast_event chain)
- [x] phase-04 updated: explicit block-on-ack dependency
- [x] plan.md acceptance criterion #9 updated: "default theo env layer, không hardcode"
- [x] No stale `default=true` references in phase files
