---
phase: 3
title: API-Layer
status: completed
effort: 2h
priority: P1
depends_on:
  - 2
---

# Phase 3: API Layer — Handler + Route + Backward Compat

## Context Links

- Research: `research/researcher-existing-stats-backend.md` §Q3, §Q5, §Q7, §Q8 (envelope, query parsing, ApiResult).
- Research: `research/researcher-heatmap-data-model.md` (final API contract).
- Existing: `crates/waf-api/src/stats.rs:1-111` (handlers + `TimeseriesQuery` pattern).
- Existing: `crates/waf-api/src/server.rs:155-157` (existing `/api/stats/*` route block).

## Overview

Three handler-layer changes:

1. **New handler** `stats_endpoints` returning sparse heatmap JSON envelope.
2. **Refactor** `stats_overview` to parse optional query params `host_code`, `action`, `hours` and pass to `get_stats_overview(&StatsFilter)`.
3. **Register** new route `GET /api/stats/endpoints` under same JWT-protected block as siblings.

Backward compat is the dominant constraint: empty query MUST return byte-equivalent JSON to current behavior (frontend at `web/admin-panel/src/pages/dashboard/index.tsx` depends on it).

## Key Insights

- Envelope = `{ "success": true, "data": {...} }` (researcher 1 §Q3).
- `hours.unwrap_or(24).clamp(1, 720)` is the established pattern (researcher 1 §Q8).
- Shared helper `clamp_hours(opt) -> i64` removes the duplicate clamp between `stats_timeseries` and `stats_endpoints`. **KISS:** simple inline `pub(crate) fn`, no module split.
- `OverviewQuery.hours` is `Option<i64>` — when `None`, pass through as `None` to storage (preserves all-time behavior).

## Requirements

### Functional

- `GET /api/stats/endpoints?hours=24&host_code=h1&action=block` → `{ success: true, data: { cells, total_events, paths_sampled, categories_total, window_hours, generated_at } }`.
- `GET /api/stats/endpoints` (no params) → same shape, `hours` defaulted to 24.
- `GET /api/stats/overview` (no params) → byte-equivalent JSON to current pre-refactor response.
- `GET /api/stats/overview?host_code=h1` → same shape, filtered to host `h1`.
- `hours` clamped to `1..=720`; values outside silently clamped (matches existing `stats_timeseries`).
- Auth: same JWT middleware layer as existing stats endpoints (route placed inside same `Router` block).

### Non-Functional

- No `.unwrap()` / `.expect()` in handlers.
- `cargo check -p waf-api` passes.
- Handler body ≤ 30 LOC each (KISS).

## Architecture

### Request flow (new endpoint)

```
GET /api/stats/endpoints?...
        │
        ▼
JWT middleware (existing) ──▶ stats_endpoints handler
        │                          │
        │                          ├─ parse EndpointsQuery (serde)
        │                          ├─ clamp hours (1..=720)
        │                          ├─ build HeatmapFilter
        │                          └─ state.db.get_endpoint_heatmap(&filter).await?
        │                                 │
        ▼                                 ▼
   JSON envelope ◀── serde_json::json! ── EndpointHeatmap
```

### Request flow (refactored overview)

```
GET /api/stats/overview?host_code=&action=&hours=
        │
        ▼
stats_overview handler
        │
        ├─ parse OverviewQuery
        ├─ build StatsFilter (Option fields preserved → None = all-time)
        ├─ state.db.get_stats_overview(&filter).await?
        └─ same envelope as before
```

## Related Code Files

**Modify:**
- `crates/waf-api/src/stats.rs` — add `EndpointsQuery`, `OverviewQuery`, `stats_endpoints` fn; refactor `stats_overview`; add `clamp_hours` helper.
- `crates/waf-api/src/server.rs` — register `/api/stats/endpoints` route.

**Create:** none.

**Delete:** none.

## Implementation Steps

### Step 1 — Add helpers + Query structs (with empty-string-as-none deserializer)

**Fix F4:** the dashboard frontend at `web/admin-panel/src/pages/dashboard/index.tsx:70` calls `/api/stats/overview` with no params today, but once the new filter inputs ship it WILL emit `?host_code=&action=` (empty strings) when the user clears a select dropdown. Default serde behavior on `Option<String>` deserializes `""` as `Some("")`, which then matches **zero rows** instead of "no filter". We MUST normalize `""` → `None` at the deserializer.

At top of `crates/waf-api/src/stats.rs` (after the existing `TimeseriesQuery`):

```rust
use serde::Deserializer;

/// Deserialize `Option<String>` such that an empty or whitespace-only value
/// becomes `None`. Required for query-param filters that the frontend sends
/// as empty strings when the user clears a control.
fn empty_string_as_none<'de, D>(de: D) -> Result<Option<String>, D::Error>
where
    D: Deserializer<'de>,
{
    let opt = Option::<String>::deserialize(de)?;
    Ok(opt.and_then(|s| {
        let t = s.trim();
        if t.is_empty() { None } else { Some(t.to_string()) }
    }))
}

#[derive(Deserialize)]
pub struct EndpointsQuery {
    #[serde(default, deserialize_with = "empty_string_as_none")]
    pub host_code: Option<String>,
    #[serde(default, deserialize_with = "empty_string_as_none")]
    pub action: Option<String>,
    /// Number of hours to look back (1..=720, default 24)
    pub hours: Option<i64>,
}

#[derive(Deserialize)]
pub struct OverviewQuery {
    #[serde(default, deserialize_with = "empty_string_as_none")]
    pub host_code: Option<String>,
    #[serde(default, deserialize_with = "empty_string_as_none")]
    pub action: Option<String>,
    /// Optional time window (None = all-time, current default)
    pub hours: Option<i64>,
}

/// Clamp optional hours param to 1..=720, defaulting to 24 when None.
/// Used for endpoints that REQUIRE a window (e.g., heatmap, timeseries).
fn clamp_hours_default(opt: Option<i64>) -> i64 {
    opt.unwrap_or(24).clamp(1, 720)
}

/// Clamp optional hours param to 1..=720 IF provided; pass through None unchanged.
/// Used for endpoints whose default is "all-time" (e.g., overview).
fn clamp_hours_optional(opt: Option<i64>) -> Option<i64> {
    opt.map(|h| h.clamp(1, 720))
}
```

**File:line citation:** `empty_string_as_none` lives in `crates/waf-api/src/stats.rs` (private, top of file). Helper is private — no re-export.

**Refactor existing `stats_timeseries`** at `crates/waf-api/src/stats.rs:89` to use `clamp_hours_default` (DRY win, surgical change to `let hours = ...` line).

**Optional follow-up (out of scope):** apply `empty_string_as_none` to the existing `TimeseriesQuery::host_code` too. Note in changelog only; do NOT bundle into this PR unless trivial.

### Step 2 — New `stats_endpoints` handler

Append to `stats.rs`:

```rust
/// GET /api/stats/endpoints
///
/// Path × Attack-Category heatmap. Returns sparse cells (only non-zero
/// (path, category) combinations) plus metadata for the dashboard heatmap
/// component. See `plans/260515-1714-fr030-dashboard-backend/research/researcher-heatmap-data-model.md`.
pub async fn stats_endpoints(
    State(state): State<Arc<AppState>>,
    Query(q): Query<EndpointsQuery>,
) -> ApiResult<Json<serde_json::Value>> {
    let filter = waf_storage::HeatmapFilter {
        hours: clamp_hours_default(q.hours),
        host_code: q.host_code,
        action: q.action,
    };
    let heatmap = state.db.get_endpoint_heatmap(&filter).await?;
    Ok(Json(serde_json::json!({
        "success": true,
        "data": {
            "cells": heatmap.cells,
            "metadata": {
                "total_events":     heatmap.total_events,
                "paths_sampled":    heatmap.paths_sampled,
                "categories_total": heatmap.categories_total,
                "window_hours":     heatmap.window_hours,
                "timestamp":        heatmap.generated_at,
            }
        }
    })))
}
```

### Step 3 — Refactor `stats_overview` to accept filters

Change signature:

```rust
// BEFORE
pub async fn stats_overview(State(state): State<Arc<AppState>>) -> ApiResult<...>

// AFTER
pub async fn stats_overview(
    State(state): State<Arc<AppState>>,
    Query(q): Query<OverviewQuery>,
) -> ApiResult<Json<serde_json::Value>> {
    let filter = waf_storage::StatsFilter {
        hours:     clamp_hours_optional(q.hours),
        host_code: q.host_code,
        action:    q.action,
    };
    let overview = state.db.get_stats_overview(&filter).await?;
    // ... rest of body UNCHANGED (live counters merge + JSON build)
}
```

**Critical:** Do NOT change the `serde_json::json!({...})` block — same keys, same order. Backward compat depends on this.

### Step 4 — Register route in `server.rs` (auth-protected block — I5 fix)

**Fix I5:** the new route MUST sit in the SAME `Router` builder chain as `/api/stats/overview` (verified at `crates/waf-api/src/server.rs:155-157`). That chain has the JWT middleware applied via `.layer(...)` AFTER all routes are accumulated. Placing the new route elsewhere (e.g., in the public-routes group) silently exposes it without auth.

**Pre-step grep verification (mandatory before editing):**
```bash
grep -n "/api/stats/" crates/waf-api/src/server.rs
# Expect 3 lines (overview, timeseries, geo) at ~155-157 — capture exact line numbers.

grep -n "jwt_auth\|JwtAuth\|require_auth\|.layer" crates/waf-api/src/server.rs | head -20
# Identify the .layer(...) call that wraps the stats routes — this is the
# auth boundary the new route must end up INSIDE of.
```

In the same `Router` chain (immediately adjacent to the existing `.route("/api/stats/overview", ...)`), add:

```rust
.route("/api/stats/endpoints", get(stats_endpoints))
```

**Post-edit grep verification:**
```bash
grep -n "/api/stats/" crates/waf-api/src/server.rs
# Expect 4 lines now — endpoints added contiguously with siblings.

# Confirm the new line sits BEFORE the .layer(jwt_auth) call that protects
# the block (Axum applies layers to ALL routes added prior to .layer).
```

Phase 4 includes a test asserting `GET /api/stats/endpoints` with no `Authorization` header returns **401** (not 200, not 404).

### Step 5 — Compile gate

```bash
docker run --rm -v $PWD:/work -w /work rust:1.91-slim-bookworm \
  sh -c "cargo check -p waf-api"
```

Exits 0. Address any warning before phase 4.

## Todo List

- [ ] Add `empty_string_as_none` private deserializer to `stats.rs` (F4).
- [ ] Add `EndpointsQuery`, `OverviewQuery` structs to `stats.rs` with `#[serde(default, deserialize_with = "empty_string_as_none")]` on `host_code`/`action`.
- [ ] Add `clamp_hours_default` + `clamp_hours_optional` helpers.
- [ ] Refactor `stats_timeseries` to use `clamp_hours_default` (DRY win).
- [ ] Add `stats_endpoints` handler.
- [ ] Refactor `stats_overview` signature + filter build.
- [ ] Grep verify pre-edit: confirm `/api/stats/overview` line + `.layer(...)` boundary in `server.rs`.
- [ ] Register `/api/stats/endpoints` route in `server.rs` INSIDE the JWT-protected block.
- [ ] Grep verify post-edit: 4 `/api/stats/` routes contiguous, all BEFORE `.layer(...)`.
- [ ] Run `cargo check -p waf-api` via Docker.
- [ ] Smoke test via `curl` (optional; formal test in phase 4).

## Success Criteria

- [ ] `GET /api/stats/endpoints` registered (grep `server.rs` confirms).
- [ ] `stats.rs` has NO `.unwrap()`/`.expect()` outside `#[cfg(test)]`.
- [ ] `cargo check -p waf-api` exits 0.
- [ ] `cargo fmt --all -- --check` exits 0.
- [ ] Smoke: with empty DB, `curl http://localhost:16827/api/stats/endpoints -H 'Authorization: Bearer <token>'` returns `{"success":true,"data":{"cells":[],"metadata":{...}}}`.
- [ ] Smoke: `curl http://localhost:16827/api/stats/overview` returns same shape as before refactor (manually diff JSON keys).

## Risk Assessment

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|-----------|
| Overview JSON shape drift breaks frontend | Med | High | Phase 4 snapshot test asserts byte-equivalence with empty filters |
| Route registered outside auth layer | Low | Critical | Place INSIDE same `Router` block as siblings; grep verify; phase 4 has auth-required test |
| `clamp_hours_default` vs `clamp_hours_optional` confusion | Low | Med | Doc comments + descriptive names; review at code review |
| Type mismatch on `waf_storage::HeatmapFilter` (private?) | Low | Low | Confirm `pub` in models.rs + re-export in waf-storage `lib.rs` |
| Query param parse error returns 422 instead of 400 | Low | Low | Axum default; matches existing pattern |

## Security Considerations

- New endpoint MUST be auth-protected — placed in same `Router` block as `stats_overview` (JWT layer applied).
- No user-controlled SQL: filter values bound, not interpolated (delegated to storage layer).
- `host_code` filter validated only by sqlx parameterization; pattern matches existing `stats_timeseries`.

## Rollback Plan

1. Revert `stats.rs` + `server.rs` changes.
2. Storage layer (phase 2) remains forward-compatible: callers can still call `get_stats_overview(&StatsFilter::default())`.

## Next Steps

Phase 4 writes integration tests achieving ≥90% coverage on the new code.
