# Phân tích Issue #60 — Backend gap vs Frontend gap

**Ngày:** 2026-05-18
**Issue:** https://github.com/future-and-go/mini-waf/issues/60 — *Admin Panel Missing FR Coverage*
**Tác giả issue:** @protonmns
**Phạm vi:** 7 sub-issue (FR-006, FR-007, FR-012, FR-025/026/027, FR-028, FR-030, FR-042)

---

## 1. Tóm tắt

Issue #60 được mở dưới góc nhìn frontend ("Backend Endpoints already exist, no backend work needed"). Sau khi scout codebase, **giả định này chỉ đúng 3/7 sub-issue**. 4 sub-issue còn lại có **gap thật ở backend** — module detection tồn tại trong code Rust, nhưng **không emit row vào `security_events` table với `rule_id` mà frontend dự kiến query**.

→ Nếu chỉ làm frontend theo spec hiện tại của issue #60, các page mới (Bot Management Relay tab, Transaction Velocity page, Honeypot tab) sẽ **luôn rỗng** trong demo và Attack Battle. Đây là rủi ro lớn cho điểm "Security Effectiveness" (40 pts) và "Intelligence & Adaptiveness" (20 pts) của rubric.

---

## 2. Phương pháp scout

Đối với mỗi FR, kiểm tra 3 layer:

1. **Module Rust có tồn tại không?** — `ls crates/waf-engine/src/<feature>/`
2. **Có emit row vào `security_events` với `rule_id` không?** — `grep -rn "create_security_event\|rule_id" crates/waf-engine/src/<feature>/`
3. **API endpoint frontend cần có sẵn không?** — `grep -n "route(...)" crates/waf-api/src/server.rs`

Evidence chính:
- `crates/waf-engine/src/engine.rs:843-893` — `log_security_event()` là điểm DUY NHẤT ghi `security_events`, chỉ chạy khi `WafDecision` có kết quả từ rule engine.
- Các "internal detection" (relay signal, tx velocity recorder, canary) **bypass đường này** — chỉ mutate state nội bộ (risk score, ban table, RAM counter).

---

## 3. Bảng đánh giá 7 sub-issue

| # | FR | Module Rust | Emit `security_events` với `rule_id`? | API endpoint mới cần? | Verdict |
|---|----|------|---|---|---|
| 1 | FR-006 Challenge | `challenge/` ✅ | ✅ Engine ghi `action=challenge` khi rule YAML set action này (`engine.rs:855`) | Không | **Frontend gap** |
| 2 | FR-007 Relay & Proxy | `relay/` ✅ | ❌ Emit `Signal::TorExit/XffMalformed/ProxyChain/AsnSuspect` enum — **không có rule_id `BOT-RELAY-*`/`BOT-PROXY-*`/`BOT-XFF-SPOOF`** | Không (nếu fix gap labeling) | **Backend gap** |
| 3 | FR-012 Transaction Velocity | `checks/tx_velocity/` ✅ | ❌ `recorder.rs` chỉ track in-memory session events; **không insert `security_events.rule_id='TX-SEQ-*'`** | Không (nếu fix gap labeling) | **Backend gap** |
| 4 | FR-025/026/027 Risk Score | `risk/{scorer,state,threshold}.rs` ✅ | ⚠️ Cumulative score per (IP+device+session) trong RAM | **Có** — `GET /api/stats/risk-distribution` (per-band histogram) | **Backend gap (API + có thể schema)** |
| 5 | FR-028 Canary/Honeypot | `risk/canary.rs` ✅ | ❌ `check_and_ban()` chỉ `tracing::warn!()` + bump risk score; **không insert `rule_id='HONEY-*'`** | Không (nếu fix gap labeling) | **Backend gap** |
| 6 | FR-007/042 IP Reputation | `relay/intel/` ✅ | N/A (feed loader, không phải detection) | **Có 2 endpoint**: `GET /api/reputation/status` + `POST /api/reputation/refresh` | **Backend gap (API)** |
| 7 | FR-030 Geo Map | `stats.rs::stats_geo` ✅ | ✅ Đã có `/api/stats/geo`, `/api/stats/overview.top_countries` | Không (optional: `?country=` filter cho security-events) | **Frontend gap** |

**Tổng:** 3 sub-issue chỉ thiếu frontend (#1, #5/Settings UI, #7). 4 sub-issue có backend gap cần xử lý trước hoặc song song (#2, #3, #4, #6) — riêng #5 (Honeypot) **chia làm 2**: persistence layer (backend) + table UI (frontend).

---

## 4. Root cause kiến trúc

Detection modules trong codebase hiện tại được thiết kế để **drive decision** (raise risk score → trigger `WafAction::Block/Challenge`), không phải để **emit audit trail** cho dashboard. Đường đi từ "detection bắt được pattern" → "row trong `security_events`" chỉ tồn tại qua rule engine (`engine.rs::log_security_event`).

Hệ quả:
- Relay providers (`xff_validator`, `proxy_chain`, `tor_exit`, `asn_classifier`) phát ra `Signal` enum được consume nội bộ.
- TX velocity `recorder.rs` track session events in-memory để compute velocity, không persist từng event riêng lẻ.
- Canary hit chỉ tăng risk score và ban IP qua `BanAction`, không log row với `rule_id`.

Dashboard `/api/stats/overview`, `/api/security-events?rule_id=…` chỉ thấy được những gì đi qua rule engine.

---

## 5. Đề xuất chiến lược (high-level)

### Ưu tiên P0 (cần cho Attack Battle)

| Gap | Đề xuất | Lý do | Effort ước tính |
|-----|---------|-------|---|
| Relay signal → `security_events` (#2) | Wrap `RelayRegistry::evaluate()` → mỗi `Signal` non-empty sinh `CreateSecurityEvent` với `rule_id = signal_to_rule_id(s)`. Map: `xff_validator`→`BOT-XFF-SPOOF`, `proxy_chain`→`BOT-PROXY`, `tor_exit`→`BOT-RELAY-TOR`, `asn_classifier`→`BOT-RELAY-ASN` | Tận dụng provider names có sẵn. KISS: 1 hàm map. | ~3h backend + 3h frontend |
| TX velocity breach → `security_events` (#3) | Trong `tx_velocity::check.rs::evaluate()`, khi return "breach", emit security_event với rule_id `TX-SEQ-001` / `TX-WITHDRAW-001` / `TX-LIMIT-001` (tuỳ pattern) | Đặt tại `check.rs` (decision layer), không phải `recorder.rs` (hot path) | ~4h backend + 6h frontend |
| Canary hit → `security_events` (#5) | Trong `canary.rs::check_and_ban()`, thay `warn!` bằng `db.create_security_event(... rule_id="HONEY-001" action="block")` | Honeypot hit là sự kiện hiếm, chấp nhận thêm 1 `Arc<Database>` dependency | ~2h backend + 4h frontend |

### Ưu tiên P1

| Gap | Đề xuất | Effort |
|-----|---------|---|
| Reputation status API (#6) | Thêm `GET /api/reputation/status` (delegate `RelayConfig::stats()`) + `POST /api/reputation/refresh` (gọi `relay/reload::trigger`) | ~2h backend + 3h frontend |
| Risk distribution API (#4) | `GET /api/stats/risk-distribution` aggregate count-per-band. **Lựa chọn**: (a) approximation từ `action_breakdown` (1h, sai số ~10%); (b) thêm cột `security_events.risk_score INTEGER` + migration zero-downtime (4h, chính xác) | ~1-4h backend + 5h frontend |

### Ưu tiên P2

| Gap | Đề xuất | Effort |
|-----|---------|---|
| Frontend pure (#1 Challenge UI, #7 Geo Map) | Theo issue #60 spec, không cần backend mới | ~7h frontend |

---

## 6. Rủi ro & trade-off

### 6.1 Cardinality blow-up trong Attack Battle

Relay signal phát ra rất nhanh dưới DDoS (mỗi request có thể trigger 1-3 signal). Nếu mỗi signal → 1 row `security_events`, ở 5000 req/s baseline → 5000-15000 INSERT/s vào Postgres → **kill DB**.

**Mitigation**: rate-limit per (IP, rule_id) — bucket 1 row / 60s / IP / rule_id. Helper có thể đặt ở `engine.rs` chung cho cả 3 fix (relay, TX velocity, canary).

### 6.2 Schema migration FR-025

Để có histogram chính xác (option b), cần `ALTER TABLE security_events ADD COLUMN risk_score INTEGER DEFAULT 0`. Migration zero-downtime: backfill async sau khi deploy. Trade-off vs option a (approximation): chính xác cho phần "Intelligence" score của judge, nhưng thêm 1 cột vào hot table.

YAGNI verdict: bắt đầu với **option a** (approximation từ action_breakdown), đo accuracy gap với dữ liệu thực, chỉ migrate nếu judge thực sự nhìn vào histogram.

### 6.3 Sequence của implementation

PR #58 (FR-030 endpoint heatmap) vừa merge. Các fix backend ở phần 5 KHÔNG block FE issue #1 và #7 (đã có data). Có thể song song:

- **Track A (backend)**: #2, #3, #5 backend → unblock FE tab/page.
- **Track B (frontend)**: #1, #7 ngay; #4 với approximation; chờ Track A xong cho #2/#3/#5 frontend.

---

## 7. Câu hỏi cần chốt với @protonmns

1. **Honeypot rule_id prefix** — backend nên emit `HONEY-001` / `HONEYPOT-001` / `CANARY-001`? Cần thống nhất trước khi FE filter.
2. **Risk histogram precision** — approximation (option a) đủ cho rubric không, hay phải có per-score bucket chính xác (option b, cần migration)?
3. **Sub-issue scope** — backend gap có nên tách thành issue #61/#62/#63 riêng để FE team không bị block, hay xử lý trong cùng issue #60 với note "blocked-by-backend"?
4. **Attack Battle timeline** — code freeze tuần 6. P0 backend gap (#2/#3/#5) hết ~9h effort + FE ~13h → cần kết luận có làm cả không, hay drop để focus chỗ khác.

---

## 8. Open questions

- Có nên cộng dồn cả `signal_to_rule_id` map vào `waf-common::types::RuleId` enum, hay để string literal phân tán ở mỗi module?
- Rate-limit bucket nên đặt ở `engine.rs` (centralized) hay ở từng emitter (decentralized)? Centralized dễ tune; decentralized linh hoạt.
- `POST /api/reputation/refresh` cần auth admin hay không? (`/api/rules/reload` hiện tại yêu cầu bearer token admin — follow pattern).
