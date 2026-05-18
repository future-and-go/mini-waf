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
    let overview = state.db.get_stats_overview(&filter).await?;
    let total_requests_live = state.total_requests();
    let total_blocked_live = state.total_blocked();

    // The live atomic counters reflect *only* the current process uptime,
    // while the DB aggregates survive across restarts but miss traffic that
    // the proxy allowed (the `security_events` table only receives detector
    // hits).  Return the live counter as the primary metric whenever the
    // proxy has processed at least one request this session; otherwise fall
    // back to the DB aggregate so the UI still shows useful data immediately
    // after a restart.
    #[allow(clippy::cast_sign_loss)] // DB counts are non-negative by construction
    let db_requests = overview.total_requests.max(0) as u64;
    #[allow(clippy::cast_sign_loss)]
    let db_blocked = overview.total_blocked.max(0) as u64;

    let total_requests = if total_requests_live > 0 {
        total_requests_live
    } else {
        db_requests
    };
    let total_blocked = if total_requests_live > 0 {
        total_blocked_live
    } else {
        db_blocked
    };
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
}
