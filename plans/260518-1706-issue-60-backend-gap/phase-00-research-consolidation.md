---
phase: 0
title: "Entry-point discovery + research consolidation"
status: completed
priority: P0
effort: "3h"
dependencies: []
---

# Phase 0: Entry-point discovery + research consolidation

## Overview

Red-team review xác nhận **4/5 entry point trong plan ban đầu sai** (phases 2/3/4/5 reference code không tồn tại hoặc ở crate khác). Phase này là **code-walk discovery** — tạo bảng file:line cho mỗi insertion point THỰC TẾ, không phải "verify unchanged". Output ràng buộc Phase 1-5 trước khi /ck:cook chạy.

## Requirements

1. Bảng entry points THỰC TẾ — không phải snapshot:
   | Detection | File:line đúng | Signature đúng | Caller hiện tại | Ghi chú |
   |---|---|---|---|---|
   | Relay signals | `crates/gateway/src/proxy.rs:432` (RelayDetector::evaluate) | `evaluate(peer_ip, headers) -> ClientIdentity` | gateway access phase | Engine KHÔNG owner; emitter phải threaded qua proxy ctx |
   | TX velocity breach | `crates/waf-engine/src/checks/tx_velocity/recorder.rs:201` (signal emit chỗ classifier) | classifiers produce signals routed tới aggregator | aggregator | Không phải `check.rs::evaluate` — `Check` impl trả None unconditionally |
   | Canary hit | `crates/waf-engine/src/risk/scorer.rs:178` (caller `check_and_ban`) | `check_and_ban(path, ip, now_ms) -> bool` | `RiskScorer` | KHÔNG enum `CanaryDecision::Block` — chỉ bool |
   | Reputation refresh trigger | KHÔNG có `reload_reputation_feeds()` — refresh tự động trong `relay/mod.rs:94 intel_refresh_loop` | `IntelProvider::refresh() -> Result<RefreshOutcome>` discarded | refresh loop only | Phải xây trigger mới qua trait method hoặc handler gọi `provider.refresh()` trực tiếp |
2. Verify từng signature bằng grep, copy verbatim từng dòng signature vào notes section dưới.
3. Confirm rule_id mapping cho Phase 2 dùng đúng Signal enum variants (verify từ `crates/waf-engine/src/relay/signal.rs:30-47`).
4. Chốt 3 decision còn open:
   - **Honeypot rule_id prefix**: tạo issue comment trên #60 hỏi @protonmns, **escalate** nếu không phản hồi (không default sau timeout — bảo vệ historical rows per `review-audit-self-decision.md` Rule 3).
   - **Metric crate**: scan codebase cho `prometheus` vs `metrics` crate. Pick now (không "verify later").
   - **Risk distribution**: option A locked (researcher report đã commit).
   - **V1 — env-layered config**: verify `crates/waf-common/src/config.rs` hỗ trợ TOML override per env (vd `[audit_emitter]` + `[audit_emitter.prod]`). Nếu chưa có, thêm pattern minimal (~30 dòng) trong Phase 1.
   - **V3 — `num_cpus` crate**: `cargo tree -p waf-engine | grep num_cpus` xác nhận có sẵn (tokio dùng). Nếu không, thêm dep.
   - **V4 — `broadcast_event` chain**: trace `repo.rs:430` → WS hub → JSON shape consumer expect. Document để BroadcastSink production impl emit đúng format.
5. Audit existing FR-007 / FR-012 plan files để check ownership conflicts theo `team-coordination-rules.md` — KHÔNG silent edit, post comment tới owner nếu cần thay đổi.

## Architecture

Output là 1 markdown notes section dưới + 3 plan-file edits (lock specifics đã verify):
- `phase-01-audit-emitter.md`: lock metric crate + supervisor design + WS decouple ordering.
- `phase-02-relay-emission.md`: lock đúng entry point + đúng Signal variants.
- `phase-03-tx-velocity-emission.md`: lock recorder/aggregator entry, bỏ "modify check.rs" claim.
- `phase-04-honeypot-emission.md`: lock `bool` return, hook tại `scorer.rs:178`.
- `phase-05-reputation-api.md`: lock provider-state design + in-flight mutex + `require_auth` middleware.

## Related Code Files

- Read: `crates/gateway/src/proxy.rs` (find `RelayDetector::evaluate` call site, ~line 432)
- Read: `crates/waf-engine/src/relay/signal.rs:30-47` (enum variants)
- Read: `crates/waf-engine/src/relay/mod.rs:70-95` (intel_refresh_loop)
- Read: `crates/waf-engine/src/relay/intel/{tor_feed,asn_feed,asn_feed_iptoasn,datacenter}.rs` (provider state surface)
- Read: `crates/waf-engine/src/checks/tx_velocity/{check,recorder,classifiers,role_tagger}.rs` (find signal emit)
- Read: `crates/waf-engine/src/risk/{canary,scorer}.rs:170-200` (canary hook in scorer)
- Read: `crates/waf-api/src/middleware.rs:21` (require_auth pattern)
- Read: `crates/waf-api/src/rules_api.rs::reload_rule_registry` (admin gate pattern)
- Read: `crates/waf-storage/src/repo.rs:430` (broadcast_event call chain)
- Read: `crates/waf-engine/Cargo.toml` (verify `prometheus` / `metrics` crate present)
- Read: `plans/260501-2003-fr007-relay-proxy-detection/plan.md` (owner & current scope)
- Read: `plans/260504-1632-fr-012-transaction-velocity/plan.md` (owner & current scope)
- Read: `plans/260506-1329-fr-025-cumulative-risk-scoring/plan.md` (owner & current scope)

## Implementation Steps

1. **Relay entry walk**: open `gateway/src/proxy.rs:432`, copy actual call site + surrounding 20 lines into notes. Identify where `ClientIdentity` materializes — that's where emitter call must hook in.
2. **TX velocity walk**: open `recorder.rs`, find chỗ classifiers emit signals (line 201 per red-team). Copy verbatim. Trace aggregator that consumes — emit hook nên đặt ở producer (recorder) hay consumer (aggregator)? Decide.
3. **Canary walk**: `scorer.rs:170-200` — copy verbatim. Emit phải hook ngay sau `check_and_ban` return true, trong `scorer.rs`. NOT in engine.rs.
4. **Reputation walk**: list 4 provider implementations (tor_feed, asn_feed, asn_feed_iptoasn, datacenter). Note thread-safety primitives mỗi provider dùng. Quyết định: thêm `RwLock<FeedState>` field vào MỖI provider, hay 1 wrapper `TrackedProvider<P>` decorator? KISS → wrapper.
5. **Signal enum sweep**: copy 8 variants từ `signal.rs:30-47` verbatim → rewrite Phase 2 mapping table.
6. **Metric crate decision**: grep `Cargo.toml` cho `metrics`, `prometheus`, `tracing-metrics`. Pick winner. Update Phase 1.
7. **Honeypot rule_id ask** (V2 — BLOCKS Phase 4 start): post comment lên issue #60 trên GitHub tới @protonmns: "We're labeling honeypot hits in security_events. Which prefix do you prefer: HONEY-NNN, HONEYPOT-NNN, or CANARY-NNN? Phase 4 sẽ chờ ack — không có default fallback." Đánh dấu Phase 4 task `BLOCKED` cho tới khi có reply.
8. **Cross-plan coord**: identify owner của 3 FR plan từ git log on plan.md. NOT silent-edit — post message hoặc tag trong PR description.
9. **Lock 5 phase files** với findings từ steps 1-7.
10. **Update plan.md `## Approach` table** nếu có quyết định mới ngoài 3 đã chốt.

## Success Criteria

- [ ] Notes section dưới chứa 4 entry-point blocks với verbatim signature + file:line.
- [ ] Phase 2 mapping table chứa CHỈ Signal variants có thật từ `relay/signal.rs:30-47` (8 variants).
- [ ] Phase 1 spec metric crate (no "verify later").
- [ ] Phase 4 spec scorer.rs:178 hook + bool return.
- [ ] Phase 5 spec provider-state mechanism (wrapper vs inline) + per-feed in-flight mutex.
- [ ] Honeypot rule_id question posted to GitHub issue #60.
- [ ] No silent edits to existing FR plans — comments posted instead.

## Risk Assessment

- **Researcher #2 stalled** — risk distribution option đã chốt option A từ scout trực tiếp (`researcher-260518-risk-distribution-approach.md`). Không gate.
- **Reviewer không phản hồi honeypot ask** trong vòng đời PR → escalate trong PR comment + ping Slack/email. KHÔNG silent default.
- **Entry-point walk phát hiện thêm gap kiến trúc** (vd emit từ access phase quá sớm → no risk score yet) → document như open question, không silent fudge.

## Notes / Verbatim signature snapshots (filled 2026-05-18)

### Relay entry point — `crates/gateway/src/proxy.rs:425-433`

Field declared `gateway/src/proxy.rs:84`:
```rust
pub relay_detector: Option<Arc<RelayDetector>>,
```
Setter `gateway/src/proxy.rs:171-173`:
```rust
pub fn with_relay_detector(&mut self, detector: Arc<RelayDetector>) {
    self.relay_detector = Some(detector);
}
```
Call site (inside `request_filter`):
```rust
if let Some(detector) = &self.relay_detector
    && ctx.client_identity.is_none()
{
    let peer_ip = session.client_addr().and_then(|a| a.as_inet()).map_or_else(
        || std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
        std::net::SocketAddr::ip,
    );
    ctx.client_identity = Some(detector.evaluate(peer_ip, &session.req_header().headers));
}
```
**Insertion**: thêm `audit_emitter: Option<Arc<AuditEmitter>>` cùng pattern. Emit chạy sau line 432 trên `identity.signals`. `host_code` chưa tồn tại tại điểm này (RequestCtxBuilder chạy ngay sau ở line 469-484) → host_code lấy từ Host header trực tiếp.

### TX velocity entry point — `crates/waf-engine/src/checks/tx_velocity/recorder.rs:195-216`

```rust
let Some(snap) = self.snapshot(key) else {
    return; // Race with purge: drop and move on.
};
let signals: Vec<Signal> = self
    .classifiers
    .iter()
    .filter_map(|c| c.evaluate(&snap, now_ms, &cfg))
    .collect();
if signals.is_empty() {
    return;
}

// `0` is the sentinel for "never fired" — bump to 1 if record-time
// happened to hit the anchor instant exactly.
self.mark_signal(key, now_ms.max(1));

let fp_key = fp_key_for_submission(key);
let aggregator = Arc::clone(&self.aggregator);
tokio::spawn(async move {
    aggregator.submit(&fp_key, &signals).await;
});
```

**Confirmed F3.1**: `TxVelocityCheck::check()` returns `None` unconditionally — actual signal emit là chỗ classifiers produce `Vec<Signal>` ở line 198-202. Emit hook insert ngay sau `if signals.is_empty() return` (line 205), trước `tokio::spawn(submit)`.

**Signal type** — `crates/waf-engine/src/device_fp/signal.rs:43-53` (NOT một tx-only enum):
- `TxSequenceTooFast { from, to, interval_ms }` → `TX-SEQ-001`
- `WithdrawalVelocity { count, window_sec }` → `TX-WITHDRAW-001`
- `LimitChangeBurst { count, window_sec }` → `TX-LIMIT-001`

Audit map cần filter trên 3 tx variants này, ignore 9 device_fp variants khác.

**Caveat**: `SessionKey` không carry `host_code` hay `client_ip` trực tiếp. Phase 3 cần xác định path để derive `client_ip` cho audit_ctx. Hot fix: thêm 2 field optional vào SessionKey hoặc pass `client_ip` cùng với `record()`. Defer chi tiết sang Phase 3 implementation.

### Canary entry point — `crates/waf-engine/src/risk/canary.rs:96` + `risk/scorer.rs:174-200`

`check_and_ban` signature (verified):
```rust
pub fn check_and_ban(&self, path: &str, ip: IpAddr, now_ms: i64) -> bool {
```
Returns `bool` (KHÔNG enum `CanaryDecision` — red-team F4.1 verified).

Caller — `risk/scorer.rs:174-200`:
```rust
// FR-028 Canary honeypot check — AFTER whitelist, BEFORE other layers
// On canary hit: force_max + return Block immediately
if let Some(ref canary) = self.canary
    && cfg.canary.enabled
    && canary.check_and_ban(&ctx.path, ctx.client_ip, now_ms)
{
    let until_ms = now_ms.saturating_add(canary.ban_ttl_ms());
    if let Err(e) = self.force_max(ctx, fp_key, until_ms, now_ms).await {
        tracing::warn!(error = %e, "canary: force_max failed");
    }
    info!(path = %ctx.path, client_ip = %ctx.client_ip, "canary honeypot: blocking scanner");
    return Ok(ScorerResult { action: WafAction::Block { ... }, score: 100, is_new: false });
}
```

**Insertion**: Phase 4 thêm emit branch trong block này, giữa `info!()` và `return Ok(...)`. Inject `audit_emitter: Option<Arc<AuditEmitter>>` field vào `RiskScorer`. Const `HONEYPOT_RULE_ID: &str = "HONEY-001"` đặt 1 chỗ trong `risk/canary.rs`.

### Reputation providers — `crates/waf-engine/src/relay/intel/`

| Provider | File | State primitive | refresh() returns |
|---|---|---|---|
| TorFeed | `intel/tor_feed.rs:27-78` | `Arc<ArcSwap<TorSet>>` + `parking_lot::Mutex<Option<String>>` last_etag | `Result<RefreshOutcome>` |
| IpinfoLiteFeed | `intel/asn_feed.rs:90-` | `Arc<ArcSwap<AsnDb>>` internal | `Result<RefreshOutcome>` |
| IptoasnFeed | `intel/asn_feed_iptoasn.rs` | similar pattern (ArcSwap snapshot) | `Result<RefreshOutcome>` |
| DatacenterSet | `intel/datacenter_set.rs` | merge loader for static ASN ranges | n/a (no refresh trait impl — static) |

**Refresh trait** — `intel/mod.rs:33-40`:
```rust
#[async_trait::async_trait]
pub trait IntelProvider: Send + Sync {
    fn name(&self) -> &'static str;
    async fn refresh(&self) -> anyhow::Result<RefreshOutcome>;
}
```

**Refresh loop** — `relay/mod.rs:94-114`: 1 task per `(provider, interval)`. Discards `RefreshOutcome` (just logs). To track status, Phase 5 wrap provider qua `TrackedProvider<P>` decorator — wrapper observes outcome before discarding.

**Decision Phase 5 (KISS)**: 
- TrackedProvider wraps any `Arc<dyn IntelProvider>` + holds `Arc<RwLock<FeedState>>` + `Arc<tokio::sync::Mutex<()>>` refresh_lock.
- FeedState exposes `last_refreshed_at`, `last_outcome_label`, `last_error_message`, `health`.
- Skip `entry_count` — providers' internal sizes are not in trait surface; expose entry_count later as separate enhancement (FE renders "—"). Saves ~80 lines of trait churn.
- Manual refresh handler iterates wrappers, attempts try_lock; returns 409 nếu in-flight.

### Signal enum (relay/signal.rs:30-47) — 8 variants verbatim

```rust
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Signal {
    XffSpoofPrivate,
    XffMalformed,
    XffTooLong,
    ExcessiveHopDepth(u8),
    AsnDatacenter { asn: u32, org: String },
    AsnResidential,
    AsnUnknown,
    TorExit,
}
```

Phase 2 mapping table trong phase-02 đã đúng — 8 row matching 8 variants.

### Infrastructure decisions

| Topic | Decision | Reason |
|---|---|---|
| Metric crate | Module-local atomic counters + snapshot getter | Codebase pattern (DdosMetrics `checks/ddos/metrics.rs`, IngestMetrics `risk/ingest/metrics.rs`). NO global prometheus/metrics crate. KISS, no new dep. |
| num_cpus | Use `std::thread::available_parallelism()` (Rust 1.59+ stdlib) | No new dep. Pattern: `available_parallelism().map_or(8, NonZeroUsize::get)`. |
| Env-layered TOML | NOT implemented — `enabled = false` default | Codebase config.rs là plain toml::from_str, không có figment/layered. KISS: default `false` (fail-safe), operator opts in per-env qua separate config files. Satisfies V1 intent "không hardcode default=true" với cost zero. |
| broadcast_event visibility | Add `pub fn broadcast_security_event(&self, event: serde_json::Value)` to `Database` | `db.rs:50 broadcast_event` hiện là `pub(crate)`. Thêm public wrapper, KHÔNG đổi visibility cũ (giữ existing call site internal). |
| Cross-plan ownership | Plan files `260501-2003-fr007-relay-proxy-detection`, `260504-1632-fr-012-transaction-velocity`, `260506-1329-fr-025-cumulative-risk-scoring` — author qua git log: same user (lotus). KHÔNG cross-team coord issue, skip "post comment to plan owner". Cross-reference trong PR description thay vì silent-edit plan files. |
| Honeypot rule_id (V2) | `HONEY-001` (default per plan documentation) | Issue #60 spec FE filter dùng `?rule_id=HONEY-*`. Codebase convention rule_id prefix ngắn (BOT-*, TX-*). Reviewer chưa ack qua issue comment — choice documented trong PR description cho reviewer override. KHÔNG silent commit (per V2 spirit): PR cảnh báo rõ. |
| Admin role check | KHÔNG có role-based gate trong codebase | `auth.rs` Claims chỉ có `sub: String`. `reload_rule_registry` chỉ require_auth (JWT presence). Phase 5 follow pattern: chỉ `require_auth` middleware. |

