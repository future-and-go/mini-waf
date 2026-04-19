/// Statistics and analytics API handlers.
use std::sync::Arc;

use axum::{
    Json,
    extract::{Query, State},
};
use serde::Deserialize;

use crate::error::ApiResult;
use crate::state::AppState;

#[derive(Deserialize)]
pub struct TimeseriesQuery {
    pub host_code: Option<String>,
    /// Number of hours to look back (default 24)
    pub hours: Option<i64>,
}

/// GET /api/stats/overview
///
/// Returns aggregated WAF metrics for the dashboard:
/// - Live atomic counters (`total_requests_live`, `total_blocked_live`) that
///   reflect traffic processed by the proxy since startup.
/// - Historical counters from `security_events` and `attack_logs`.
/// - Derived series for category/action/country pie charts.
/// - Compact recent-event feed so the UI can render without a second round-trip.
pub async fn stats_overview(State(state): State<Arc<AppState>>) -> ApiResult<Json<serde_json::Value>> {
    let overview = state.db.get_stats_overview().await?;
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
    let hours = q.hours.unwrap_or(24).clamp(1, 720);
    let series = state.db.get_stats_timeseries(q.host_code.as_deref(), hours).await?;
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
