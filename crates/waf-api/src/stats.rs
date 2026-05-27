/// Statistics and analytics API handlers.
use std::sync::Arc;

use axum::{
    Json,
    extract::{Query, State},
};
use serde::{Deserialize, Deserializer};

use crate::error::ApiResult;
use crate::state::AppState;

// ---------------------------------------------------------------------------
// Deserializer helpers
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Query structs
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct TimeseriesQuery {
    pub host_code: Option<String>,
    /// Number of hours to look back (default 24)
    pub hours: Option<i64>,
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

// ---------------------------------------------------------------------------
// Hour-clamping helpers
// ---------------------------------------------------------------------------

/// Clamp optional hours param to 1..=720, defaulting to 24 when None.
/// Used for endpoints that REQUIRE a window (e.g., heatmap, timeseries).
fn clamp_hours_default(opt: Option<i64>) -> i64 {
    opt.unwrap_or(24).clamp(1, 720)
}

/// Clamp optional hours to 1..=720, preserving `None`.
/// Used for endpoints where the window is OPTIONAL (e.g., overview defaults
/// to all-time data). Pairs with [`clamp_hours_default`].
#[allow(clippy::single_option_map)] // named helper is the readability win here
fn clamp_hours_optional(opt: Option<i64>) -> Option<i64> {
    opt.map(|h| h.clamp(1, 720))
}

// ---------------------------------------------------------------------------
// Overview-totals helper
// ---------------------------------------------------------------------------

/// Pick `(total_requests, total_blocked)` for the overview endpoint.
///
/// Uses the live atomic counters when the query is unfiltered AND the proxy
/// has handled at least one request this session; otherwise falls back to
/// the DB aggregates. Filtered queries (`host_code` / `action`) always read
/// from the DB because the live counters are global and cannot honour those
/// predicates — returning the global figure for a filtered request would
/// over-report (and the block-rate would be wrong) for every host/action
/// dashboard view.
const fn select_overview_totals(
    live_requests: u64,
    live_blocked: u64,
    db_requests: u64,
    db_blocked: u64,
    is_filtered: bool,
) -> (u64, u64) {
    if !is_filtered && live_requests > 0 {
        (live_requests, live_blocked)
    } else {
        (db_requests, db_blocked)
    }
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// GET /api/stats/overview
///
/// Returns aggregated WAF metrics for the dashboard:
/// - Live atomic counters (`total_requests_live`, `total_blocked_live`) that
///   reflect traffic processed by the proxy since startup.
/// - Historical counters from `security_events` and `attack_logs`.
/// - Derived series for category/action/country pie charts.
/// - Compact recent-event feed so the UI can render without a second round-trip.
pub async fn stats_overview(
    State(state): State<Arc<AppState>>,
    Query(q): Query<OverviewQuery>,
) -> ApiResult<Json<serde_json::Value>> {
    let filter = waf_storage::StatsFilter {
        hours: clamp_hours_optional(q.hours),
        host_code: q.host_code,
        action: q.action,
    };
    let is_filtered = filter.host_code.is_some() || filter.action.is_some();
    let overview = state.db.get_stats_overview(&filter).await?;
    let total_requests_live = state.total_requests();
    let total_blocked_live = state.total_blocked();

    // The live atomic counters reflect *only* the current process uptime,
    // while the DB aggregates survive across restarts but miss traffic that
    // the proxy allowed (the `security_events` table only receives detector
    // hits).  Return the live counter as the primary metric whenever the
    // proxy has processed at least one request this session; otherwise fall
    // back to the DB aggregate so the UI still shows useful data immediately
    // after a restart. Filtered queries (host_code / action) must always
    // use the DB aggregates because the live counter is global and cannot
    // honour those predicates.
    #[allow(clippy::cast_sign_loss)] // DB counts are non-negative by construction
    let db_requests = overview.total_requests.max(0) as u64;
    #[allow(clippy::cast_sign_loss)]
    let db_blocked = overview.total_blocked.max(0) as u64;

    let (total_requests, total_blocked) = select_overview_totals(
        total_requests_live,
        total_blocked_live,
        db_requests,
        db_blocked,
        is_filtered,
    );
    let total_allowed = total_requests.saturating_sub(total_blocked);

    let block_rate = if total_requests == 0 {
        0.0_f64
    } else {
        #[allow(clippy::cast_precision_loss)]
        let r = (total_blocked as f64) / (total_requests as f64);
        (r * 10_000.0).round() / 10_000.0
    };

    Ok(Json(serde_json::json!({
        "success": true,
        "data": {
            "total_requests": total_requests,
            "total_blocked": total_blocked,
            "total_allowed": total_allowed,
            "block_rate": block_rate,
            "total_requests_live": total_requests_live,
            "total_blocked_live": total_blocked_live,
            "total_requests_db": overview.total_requests,
            "total_blocked_db": overview.total_blocked,
            "hosts_count": overview.hosts_count,
            "unique_attackers": overview.unique_attackers,
            "top_ips": overview.top_ips,
            "top_rules": overview.top_rules,
            "top_countries": overview.top_countries,
            "top_isps": overview.top_isps,
            "category_breakdown": overview.category_breakdown,
            "action_breakdown": overview.action_breakdown,
            "recent_events": overview.recent_events,
        }
    })))
}

/// GET /api/stats/timeseries
pub async fn stats_timeseries(
    State(state): State<Arc<AppState>>,
    Query(q): Query<TimeseriesQuery>,
) -> ApiResult<Json<serde_json::Value>> {
    let hours = clamp_hours_default(q.hours);
    let series = state.db.get_stats_timeseries(q.host_code.as_deref(), hours).await?;
    Ok(Json(serde_json::json!({ "success": true, "data": series })))
}

/// GET `/api/stats/timeseries-by-category`
///
/// Same time semantics as `stats_timeseries` (hourly buckets, last `hours`
/// hours, optionally scoped to a single host) but rows are split by attack
/// category. Used by the Rule Analytics stacked timeline chart.
///
/// Response is `Vec<CategoryTimeSeriesPoint>` in the standard
/// `{"success": true, "data": […]}` envelope. Rows for an hour bucket where
/// no category fired are simply absent — the frontend fills gaps when rendering.
pub async fn stats_timeseries_by_category(
    State(state): State<Arc<AppState>>,
    Query(q): Query<TimeseriesQuery>,
) -> ApiResult<Json<serde_json::Value>> {
    let hours = q.hours.unwrap_or(24).clamp(1, 720);
    let series = state
        .db
        .get_stats_timeseries_by_category(q.host_code.as_deref(), hours)
        .await?;
    Ok(Json(serde_json::json!({ "success": true, "data": series })))
}

/// GET /api/stats/geo — `GeoIP` distribution of blocked requests
pub async fn stats_geo(State(state): State<Arc<AppState>>) -> ApiResult<Json<serde_json::Value>> {
    let geo = state.db.get_geo_stats().await?;
    Ok(Json(serde_json::json!({
        "success": true,
        "data": {
            "top_countries": geo.top_countries,
            "top_cities": geo.top_cities,
            "top_isps": geo.top_isps,
            "country_distribution": geo.country_distribution,
        }
    })))
}

/// GET /api/stats/endpoints
///
/// Path × Attack-Category heatmap. Returns sparse cells (only non-zero
/// (path, category) combinations) plus metadata for the dashboard heatmap
/// component.
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

/// GET /api/threat-intel/status
///
/// PATCH 4: gracefully-degraded reputation feed status endpoint.
/// Real-time feed stats are not exposed at runtime; returns a structured
/// response so the frontend receives 200 (not 404) and can render a
/// "feeds loaded at startup" message instead of an error toast.
pub async fn threat_intel_status(State(_state): State<Arc<AppState>>) -> ApiResult<Json<serde_json::Value>> {
    Ok(Json(serde_json::json!({
        "success": true,
        "data": {
            "available": false,
            "message": "Reputation feeds are loaded at startup. Check startup logs for feed status.",
            "tor_count": null,
            "asn_count": null,
            "last_refreshed": null,
        }
    })))
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clamp_hours_default_uses_24_when_none() {
        assert_eq!(clamp_hours_default(None), 24);
    }

    #[test]
    fn clamp_hours_default_clamps_below_one() {
        assert_eq!(clamp_hours_default(Some(0)), 1);
        assert_eq!(clamp_hours_default(Some(-99)), 1);
    }

    #[test]
    fn clamp_hours_default_clamps_above_720() {
        assert_eq!(clamp_hours_default(Some(721)), 720);
        assert_eq!(clamp_hours_default(Some(i64::MAX)), 720);
    }

    #[test]
    fn clamp_hours_default_passes_through_in_range() {
        assert_eq!(clamp_hours_default(Some(1)), 1);
        assert_eq!(clamp_hours_default(Some(168)), 168);
        assert_eq!(clamp_hours_default(Some(720)), 720);
    }

    #[test]
    fn clamp_hours_optional_preserves_none() {
        assert_eq!(clamp_hours_optional(None), None);
    }

    #[test]
    fn clamp_hours_optional_clamps_both_ends() {
        assert_eq!(clamp_hours_optional(Some(0)), Some(1));
        assert_eq!(clamp_hours_optional(Some(99_999)), Some(720));
    }

    #[test]
    fn clamp_hours_optional_passes_through_in_range() {
        assert_eq!(clamp_hours_optional(Some(24)), Some(24));
        assert_eq!(clamp_hours_optional(Some(720)), Some(720));
    }

    #[test]
    fn empty_string_as_none_treats_empty_as_none() {
        let q: EndpointsQuery = serde_json::from_value(serde_json::json!({
            "host_code": "",
            "action": "",
        }))
        .expect("parse");
        assert_eq!(q.host_code, None);
        assert_eq!(q.action, None);
    }

    #[test]
    fn empty_string_as_none_treats_whitespace_as_none() {
        let q: OverviewQuery = serde_json::from_value(serde_json::json!({
            "host_code": "   ",
            "action": "\t",
        }))
        .expect("parse");
        assert_eq!(q.host_code, None);
        assert_eq!(q.action, None);
    }

    #[test]
    fn empty_string_as_none_preserves_trimmed_value() {
        let q: OverviewQuery = serde_json::from_value(serde_json::json!({
            "host_code": " h1 ",
            "action": "block",
        }))
        .expect("parse");
        assert_eq!(q.host_code.as_deref(), Some("h1"));
        assert_eq!(q.action.as_deref(), Some("block"));
    }

    #[test]
    fn empty_string_as_none_handles_missing_keys() {
        let q: OverviewQuery = serde_json::from_value(serde_json::json!({})).expect("parse");
        assert_eq!(q.host_code, None);
        assert_eq!(q.action, None);
        assert_eq!(q.hours, None);
    }

    #[test]
    fn empty_string_as_none_handles_explicit_null() {
        let q: OverviewQuery = serde_json::from_value(serde_json::json!({
            "host_code": null,
            "action": null,
            "hours": null,
        }))
        .expect("parse");
        assert_eq!(q.host_code, None);
        assert_eq!(q.action, None);
        assert_eq!(q.hours, None);
    }

    // ── select_overview_totals (live vs DB selection) ─────────────────────

    /// Unfiltered query with live traffic this session prefers the live counters.
    #[test]
    fn select_overview_totals_unfiltered_prefers_live() {
        let (req, blk) = select_overview_totals(100, 20, 5_000, 1_000, false);
        assert_eq!((req, blk), (100, 20));
    }

    /// Unfiltered query with no live traffic falls back to DB aggregates.
    #[test]
    fn select_overview_totals_unfiltered_no_live_uses_db() {
        let (req, blk) = select_overview_totals(0, 0, 5_000, 1_000, false);
        assert_eq!((req, blk), (5_000, 1_000));
    }

    /// Filtered query must always use DB even when live counters are non-zero —
    /// the live counter is global and cannot honour `host_code` / `action`.
    #[test]
    fn select_overview_totals_filtered_ignores_live() {
        let (req, blk) = select_overview_totals(100, 20, 5_000, 1_000, true);
        assert_eq!((req, blk), (5_000, 1_000));
    }

    /// Filtered query with no live traffic uses DB — same as unfiltered fallback.
    #[test]
    fn select_overview_totals_filtered_no_live_uses_db() {
        let (req, blk) = select_overview_totals(0, 0, 5_000, 1_000, true);
        assert_eq!((req, blk), (5_000, 1_000));
    }

    /// Empty DB AND no live traffic → zeroes; the handler's block-rate path
    /// must still be safe (division-by-zero guard lives in the caller).
    #[test]
    fn select_overview_totals_all_zero_returns_zero() {
        let (req, blk) = select_overview_totals(0, 0, 0, 0, false);
        assert_eq!((req, blk), (0, 0));
    }
}
