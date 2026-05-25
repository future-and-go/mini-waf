---
phase: 4
title: "PR-D: admin API — reputation + risk-distribution + audit/metrics + 2-step deprecation"
status: pending
priority: P2
effort: "1.5d"
dependencies: [1]
pr_branch: "feat/audit-emitter-admin-api-issue-60-d"
loc_estimate: 900
red_team_applied: F-S-1, F-S-7, F-A-1, F-A-2, F-A-4, F-A-5, F-A-6, F-A-7, F-A-9, F-A-10, F-F-2, F-F-10
---

# Phase 4: Admin API endpoints

## Overview

Ship 4 admin API endpoints + 2-step deprecate legacy stub (BP5 / F-A-1):
1. `GET /api/reputation/status` — feed status snapshot từ `FeedStatusRegistry` (phase 01 skeleton + phase 02 populate)
2. `POST /api/reputation/refresh` — trigger feed reload + return new status (admin-auth, rate-limited)
3. `GET /api/stats/risk-distribution` — band-chart histogram (option A approximation)
4. `GET /api/audit/metrics` (NEW per F-F-2) — JSON snapshot AuditEmitterMetrics (admin-auth)
5. `GET /api/threat-intel/status` — **2-step deprecation**: this release returns **200 + same JSON shape** + `Deprecation: true` + `Sunset: <90d>` + `Link: </api/reputation/status>; rel=successor-version`. 308 redirect deferred next release (separate sub-issue).

**Red-team applied**:
- F-S-1 CRITICAL: admin-auth middleware bắt buộc cả 4 endpoints; cluster-aware refresh gate qua DB advisory lock
- F-S-7: mandatory index migration trong same PR + `statement_timeout` 5s + cap hours 168
- F-A-1 BLOCKER: 2-step deprecation (200 + Deprecation/Sunset/Link headers — RFC 9745/8594), NOT 308 this release
- F-A-2: keep `message` field
- F-A-4: `unavailable_bands: ["elevated"]` array thay `elevated: 0`
- F-A-5: refresh skipped flag + `next_refresh_allowed_at`
- F-A-6: empty body + `deny_unknown_fields`
- F-A-7: positive `api_version: "v2"` marker
- F-A-9: path-relative paths cho redirect safe-under-prefix
- F-F-2: new `/api/audit/metrics`
- F-F-10: tech guide update IN same PR

## Requirements

### Functional
- **All 4 new endpoints behind admin-auth middleware** (F-S-1) — match `panel_api.rs` auth pattern
- `GET /api/reputation/status` returns `{success, data: {available, tor_count, asn_count, last_refreshed, message, api_version: "v2", schema: "reputation.v1"}}` (F-A-2 keep message, F-A-7 positive in-body marker — URL stays unversioned `/api/reputation/...`)
- `POST /api/reputation/refresh` accepts empty body OR `application/json` `{}` (F-A-6); `#[serde(deny_unknown_fields)]`; **cluster-aware** rate-limit via DB advisory lock `pg_try_advisory_lock(REPUTATION_REFRESH_LOCK_ID)` (per user — supports current + future multi-node):
  - `REPUTATION_REFRESH_LOCK_ID` = stable u64 const (e.g. hash of literal "audit_emitter.reputation.refresh")
  - Acquire at handler entry; release at function exit (RAII guard via `Drop`)
  - Lock NOT acquired (another node holds) → return 200 + `data.refresh_skipped: true, data.next_refresh_allowed_at: <iso 60s>` (F-A-5)
  - Lock acquired → trigger reload + return snapshot
  - Refused calls log audit row with rule_id `AUDIT-RATELIMIT-001` (built-in)
- `GET /api/stats/risk-distribution` response shape: `{success, data: {allow, challenge, block, approximation: true, unavailable_bands: ["elevated"], api_version: "v2"}}` (F-A-4 explicit unavailable_bands array, NO `elevated: 0`)
- Risk distribution query: `hours` default 168 (cap), max 720; `statement_timeout = '5s'`; mandatory index migration trong same PR (F-S-7)
- `GET /api/audit/metrics` (F-F-2): returns `{success, data: {emitted, rate_limited, queue_full_dropped, db_insert_failed, worker_restarted, invalid_rule_id, global_rate_limited, api_version: "v2", schema: "audit-metrics.v1"}}`
- Legacy `/api/threat-intel/status` — **2-step deprecation** (BP5 / F-A-1):
  - Phase 4a (this PR): return 200 + original JSON shape + headers `Deprecation: true`, `Sunset: <90d from merge>` (RFC 9745 + RFC 8594), `Link: </api/reputation/status>; rel=successor-version`. Drop non-standard `X-Deprecated` (F-A-10).
  - Phase 4b (next release sub-issue): flip to 308. Document sunset date trong release notes.

### Non-functional
- Coverage ≥ 90% trên handlers (BP8: testcontainers excluded từ numerator)
- 7 band-mapping tests cho `stats_risk_distribution` (port từ PR #62 tests + adjust for `unavailable_bands`)
- BP1 + BP5 + BP6 + BP7 + BP8 applied
- FE-side smoke (curl) trong Docker — verify all 4 endpoints + deprecation contract
- All Location/redirect paths **path-relative** (F-A-9) — safe under reverse-proxy prefix mount
- Tech guide update IN same PR (F-F-10)

## Architecture

```
HTTP request
  │
  ├─ /api/reputation/status      → reputation::status_handler   → FeedStatusRegistry.snapshot()
  ├─ /api/reputation/refresh     → reputation::refresh_handler  → trigger feed reload + snapshot
  ├─ /api/stats/risk-distribution → stats_risk_distribution::handler → DB query (option A)
  └─ /api/threat-intel/status    → 200 + Deprecation/Sunset/Link headers (2-step Phase 4a)
```

`FeedStatusRegistry` đã ship trong phase 02 (`relay/intel/status.rs`); phase 04 chỉ wire qua `AppState`.

## Related Code Files

### Create
- `crates/waf-api/src/reputation.rs` — 2 handlers (`status_handler`, `refresh_handler`)
- `crates/waf-api/src/stats_risk_distribution.rs` — 1 handler + 7 band-mapping tests inline
- `crates/waf-api/src/audit_metrics.rs` — 1 handler (F-F-2)
- `crates/waf-api/tests/handler_reputation.rs` — integration tests + cluster-lock test
- `crates/waf-api/tests/handler_risk_distribution.rs` — integration tests
- `crates/waf-api/tests/handler_threat_intel_deprecate.rs` — 2-step deprecation contract test
- `crates/waf-api/tests/handler_audit_metrics.rs` — admin-auth + snapshot test
- `crates/waf-api/tests/handler_reverse_proxy_prefix.rs` — F-A-9 simulated `/admin/` mount
- `migrations/<NNNN>_security_events_action_index.sql` — `CREATE INDEX CONCURRENTLY idx_security_events_query ON security_events(created_at, host_code, action)` (F-S-7)

### Modify
- `crates/waf-api/src/lib.rs` — add `pub mod reputation; pub mod stats_risk_distribution; pub mod audit_metrics;`
- `crates/waf-api/src/server.rs` — add 4 new routes; all 4 đặt sau admin-auth middleware (`.route_layer(admin_auth_middleware)` per panel_api.rs pattern); deprecation route stays at original path, returns 200 + sunset headers
- `crates/waf-api/src/stats.rs` — `threat_intel_status` → return 200 + original JSON shape + `Deprecation: true` + `Sunset: <date>` + `Link: </api/reputation/status>; rel=successor-version` headers. **NOT 308 this release.**
- `crates/waf-api/src/state.rs` — extend `AppState` với `Arc<FeedStatusRegistry>` (skeleton từ phase 01) + `Arc<AuditEmitter>` (for `/api/audit/metrics`)
- `crates/waf-api/src/panel_api.rs` — wire admin-auth middleware nếu panel cần access; verify pattern còn fit
- `crates/waf-storage/src/repo.rs` — add `risk_distribution_query(host_code: Option<&str>, hours: i64)` với `statement_timeout='5s'` (option A: COUNT GROUP BY action mapping → band)
- `crates/waf-storage/src/db.rs` — re-export new query
- `crates/prx-waf/src/main.rs` — wire `FeedStatusRegistry` + `AuditEmitter` vào AppState ở startup
- `docs/PRX-WAF-TechnicalGuide-EN.md` + `docs/PRX-WAF-TechnicalGuide-VI.md` — update API reference section (mention 4 endpoints + deprecation timeline) IN same PR (F-F-10)

### Delete
None.

## Implementation Steps (TDD)

### Step 1 — Write failing tests

1.1. `handler_reputation.rs`:
- `status_unauthenticated_returns_401` (F-S-1)
- `status_authenticated_returns_feed_snapshot_with_200`
- `status_keeps_message_field` (F-A-2)
- `status_response_includes_api_version_v2` (F-A-7)
- `status_returns_unavailable_when_feeds_not_loaded`
- `refresh_unauthenticated_returns_401` (F-S-1)
- `refresh_authenticated_triggers_reload_then_returns_status`
- `refresh_within_window_returns_200_with_skipped_flag` (F-A-5 — NOT 429)
- `refresh_response_includes_next_refresh_allowed_at` (F-A-5)
- `refresh_empty_body_accepted` (F-A-6)
- `refresh_unknown_fields_rejected_with_400` (F-A-6 deny_unknown_fields)
- `refresh_cluster_advisory_lock_held_returns_skipped` (F-S-1 cluster gate)

1.2. `handler_risk_distribution.rs`:
- `risk_distribution_unauthenticated_returns_401`
- `risk_distribution_returns_3_bands_plus_unavailable_array` (F-A-4)
- `risk_distribution_response_has_unavailable_bands_elevated_array` (F-A-4 explicit)
- `risk_distribution_has_no_elevated_field_directly` (F-A-4 omit `elevated: 0`)
- `host_code_filter_scopes_query`
- `hours_param_default_168_clamps_max_720` (F-S-7 reduced default)
- `approximation_flag_true_for_option_a`
- `empty_events_returns_zero_bands_with_200`
- `invalid_hours_uses_default_168` (negative / 0 / > 720)
- `statement_timeout_5s_enforced` (F-S-7 — verify via slow query mock)

1.3. `handler_threat_intel_deprecate.rs` — **2-step deprecation contract** (F-A-1):
- `legacy_endpoint_returns_200_not_308` (key BLOCKER assertion)
- `legacy_endpoint_keeps_original_json_shape_with_message_field` (FE compat)
- `legacy_endpoint_sets_deprecation_header_true` (RFC 9745)
- `legacy_endpoint_sets_sunset_header_with_90day_date` (RFC 8594)
- `legacy_endpoint_sets_link_header_with_successor_version`
- `legacy_endpoint_link_target_is_path_relative` (F-A-9)
- `legacy_endpoint_does_not_set_x_deprecated_header` (F-A-10 — dropped non-standard)

1.4. `handler_audit_metrics.rs` (F-F-2):
- `audit_metrics_unauthenticated_returns_401`
- `audit_metrics_returns_all_counter_fields`
- `audit_metrics_response_includes_api_version_v2`
- `audit_metrics_counter_values_match_snapshot`

1.5. `handler_reverse_proxy_prefix.rs` (F-A-9):
- `endpoints_work_under_admin_mount_prefix` (simulated `/admin/` reverse-proxy)
- `link_header_path_relative_resolves_correctly_under_prefix`

1.6. Run Docker — **all FAIL**.

### Step 2 — Implement

2.1. `reputation.rs`:
```rust
pub async fn status_handler(State(state): State<Arc<AppState>>) -> ApiResult<Json<serde_json::Value>> {
    let snap = state.feed_status.snapshot();
    Ok(Json(serde_json::json!({
        "success": true,
        "data": {
            "available": snap.available,
            "tor_count": snap.tor_count,
            "asn_count": snap.asn_count,
            "last_refreshed": snap.last_refreshed,
        }
    })))
}

pub async fn refresh_handler(State(state): State<Arc<AppState>>) -> ApiResult<Json<serde_json::Value>> {
    // rate-limited: 1 refresh per 60s (DashMap last-refresh timestamp)
    state.feed_status.trigger_reload().await?;
    status_handler(State(state)).await
}
```

2.2. `stats_risk_distribution.rs`:
```rust
pub async fn handler(
    Query(q): Query<RiskDistQuery>,
    State(state): State<Arc<AppState>>,
) -> ApiResult<Json<serde_json::Value>> {
    let hours = clamp_hours_default(q.hours);
    let counts = state.db.risk_distribution_query(q.host_code.as_deref(), hours).await?;
    Ok(Json(serde_json::json!({
        "success": true,
        "data": {
            "allow": counts.allow,
            "challenge": counts.challenge,
            "elevated": 0,             // option A approximation
            "block": counts.block,
            "approximation": true,
        }
    })))
}
```
Band mapping (option A): `action = "allow"` → allow band; `action = "challenge"` → challenge band; `action = "block"` → block band; `elevated` = 0 (no schema migration this round).

2.3. `stats.rs::threat_intel_status` → **200 + Deprecation/Sunset/Link headers** (2-step, F-A-1):
```rust
const SUNSET_DATE: &str = "Sat, 22 Aug 2026 00:00:00 GMT";  // ~90 days from merge

pub async fn threat_intel_status(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let snap = state.feed_status.snapshot();
    let body = serde_json::json!({
        "success": true,
        "data": {
            "available": snap.available,
            "message": "Reputation feeds are loaded at startup. Check startup logs for feed status.",
            "tor_count": snap.tor_count,
            "asn_count": snap.asn_count,
            "last_refreshed": snap.last_refreshed,
        }
    });
    (
        StatusCode::OK,
        [
            (HeaderName::from_static("deprecation"), HeaderValue::from_static("true")),
            (HeaderName::from_static("sunset"), HeaderValue::from_str(SUNSET_DATE).unwrap_or(HeaderValue::from_static(""))),
            (HeaderName::from_static("link"), HeaderValue::from_static("<./reputation/status>; rel=\"successor-version\"")),
        ],
        Json(body),
    )
}
```
Note: path-relative Link target `./reputation/status` (F-A-9 reverse-proxy safe).
Phase 4b sub-issue tracks 308 flip after sunset.

2.4. `repo.rs::risk_distribution_query` — SQL:
```sql
SELECT action, COUNT(*) AS cnt
FROM security_events
WHERE created_at > NOW() - INTERVAL '$1 hours'
  AND ($2::text IS NULL OR host_code = $2)
GROUP BY action;
```

2.5. `main.rs` wire `FeedStatusRegistry` Arc vào AppState ở startup; populate snapshot từ relay feed loader.

2.6. `server.rs` routes — all behind admin-auth middleware (F-S-1):
```rust
Router::new()
    .route("/api/reputation/status", get(reputation::status_handler))
    .route("/api/reputation/refresh", post(reputation::refresh_handler))
    .route("/api/stats/risk-distribution", get(stats_risk_distribution::handler))
    .route("/api/audit/metrics", get(audit_metrics::handler))           // F-F-2
    .route("/api/threat-intel/status", get(stats::threat_intel_status))  // 200 + deprecation headers
    .route_layer(middleware::from_fn_with_state(state.clone(), admin_auth_middleware))
```
**Note:** verify route ordering tương thích với existing `server.rs` (modified bởi PR #99/#100); existing routes có thể đã wired auth qua nested router.

2.7. Tests pass.

### Step 3 — Refactor + verify

3.1. fmt/clippy clean.
3.2. Coverage ≥ 90% trên 3 handlers.
3.3. BP1 + BP5 grep gates.
3.4. Squash, push, PR.

### Step 4 — PR draft body

```markdown
## Summary

Adds three admin API endpoints for the dashboard backend:

- `GET /api/reputation/status` — threat-intel feed snapshot (Tor / ASN counts,
  last refresh, availability flag)
- `POST /api/reputation/refresh` — operator-triggered feed reload, rate-limited
  to one call per 60s
- `GET /api/stats/risk-distribution` — risk band histogram for the dashboard
  band chart

Deprecates the legacy `/api/threat-intel/status` stub via a 2-step rollout.
This release: the endpoint keeps returning the original JSON shape with a 200
status, plus `Deprecation: true` and `Sunset: <date>` headers (RFC 9745 +
RFC 8594) and a `Link: </api/reputation/status>; rel="successor-version"`
header. A follow-up sub-issue will flip the response to 308 after the sunset
date so clients have a documented migration window.

## Rationale

The admin panel surfaces for Reputation (issue #60 sub-task #6) and Risk
Distribution (sub-task #4) needed real data sources. The legacy stub returned
`available: false` for every call, which forced the panel to render an error
toast. These endpoints close the gap.

## Risk distribution: option A approximation

The current `security_events` schema does not store a per-event risk score.
Adding one would require a backfill migration which is deferred. Instead,
band counts are derived from the existing `action` column:

| Band     | Source                                        |
|----------|-----------------------------------------------|
| allow    | `action = 'allow'`                            |
| challenge| `action = 'challenge'`                        |
| elevated | (always 0 — needs schema migration)           |
| block    | `action = 'block'`                            |

The response carries `approximation: true` so the FE can label accordingly.

## Tests

- 4 reputation handler tests (status + refresh + rate-limit)
- 7 risk-distribution tests (band sum, host filter, hours clamp,
  approximation flag, elevated-zero, empty-events, invalid-hours-default)
- 7 deprecation contract tests (200-not-308 BLOCKER assertion, Deprecation +
  Sunset + Link headers, path-relative target, original-shape preservation,
  X-Deprecated absent)
- Coverage ≥ 90% on handlers
```

## Success Criteria

- [ ] All 14 tests pass
- [ ] fmt/clippy clean
- [ ] Coverage ≥ 90%
- [ ] BP1 + BP5 grep gates clean
- [ ] `curl -i http://localhost:16827/api/threat-intel/status` returns 200 + `Deprecation: true` + `Sunset: <date>` + `Link: </api/reputation/status>; rel="successor-version"` + original JSON body shape
- [ ] `curl -i http://localhost:16827/api/threat-intel/status` does NOT set `X-Deprecated` header (dropped per F-A-10)
- [ ] All 4 new endpoints return 401 cho unauthenticated requests (F-S-1)
- [ ] PR opened, CI green, NOT merged
- [ ] 1 squashed commit

## Risk Assessment

| Risk | Mitigation |
|---|---|
| `server.rs`, `repo.rs`, `lib.rs` đã touched bởi PR #99/#100 — rebase conflicts | Read main fresh; verify route ordering trong `server.rs` (FastAPI-style first-match? Axum exact-match: OK) |
| `FeedStatusRegistry` snapshot lifecycle — relay startup async; first request might see `available: false` | Acceptable; handler returns `available: false` + log warn. Reload via `/api/reputation/refresh` populates registry |
| Option A approximation gây confusion FE | `approximation: true` flag + tech-guide doc update. Sub-issue tracking schema migration cho option B trong future |
| Legacy clients hardcode `/api/threat-intel/status` | This release: 200 + original JSON shape — zero breakage. Clients hit the `Deprecation`/`Sunset` headers (logged by RFC-aware monitoring stacks). 90-day window before phase 4b 308 flip. |
| Refresh handler DoS qua spam call | Rate-limit 1/60s qua last-refresh timestamp |
| `risk_distribution_query` slow trên large `security_events` table | Verify index trên `(created_at, host_code, action)`; add index migration trong cùng PR nếu cần |

## Post-merge follow-up

- Tech guide (`docs/PRX-WAF-TechnicalGuide-{EN,VI}.md`) update reflect realit: section "Reputation feed status" mention `/api/reputation/status` thay `/api/threat-intel/status`
- Sub-issue mở cho option B risk-distribution exact (schema migration `security_events.risk_score`)
- Sub-issue mở cho honeypot activation (deferred PR-E)

## Next Phase

End of plan. Post-plan handoff: optionally `/ck:plan validate` hoặc `/ck:plan red-team` cho whole-plan sanity check. User decision.
