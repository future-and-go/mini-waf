//! FR-025 — risk distribution endpoint.
//!
//! Returns counts per risk band (`allow`, `challenge`, `elevated`, `block`)
//! derived from the existing `security_events.action` column. This is the
//! option-A approximation locked in `phase-06-risk-distribution-api.md` —
//! exact per-row `risk_score` would require a schema migration; for the
//! current iteration the dashboard reads bands from action boundaries.

use std::sync::Arc;

use axum::{
    Json,
    extract::{Query, State},
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use waf_common::panel_config::WafPanelConfig;

use crate::error::{ApiError, ApiResult};
use crate::state::AppState;

/// Public maximum for the `hours` query parameter — kept in sync with the
/// repo-side clamp (`waf_storage::repo::clamp_hours_for_sql`). Values above
/// this are rejected at the handler boundary so callers get an explicit
/// 400 instead of a silent server-side clamp.
const HOURS_PUBLIC_MAX: i64 = 720;

#[derive(Debug, Clone, Deserialize, Default)]
pub struct RiskDistributionQuery {
    pub host_code: Option<String>,
    pub action: Option<String>,
    /// Look-back window. Defaults to 24h, clamped to `[1, 720]`.
    pub hours: Option<i64>,
}

#[derive(Debug, Clone, Copy, Serialize)]
struct BandOut {
    label: &'static str,
    min: u32,
    max: u32,
    count: i64,
    color: &'static str,
}

/// `GET /api/stats/risk-distribution` handler.
pub async fn stats_risk_distribution(
    State(state): State<Arc<AppState>>,
    Query(q): Query<RiskDistributionQuery>,
) -> ApiResult<Json<Value>> {
    // Validate at the boundary: reject out-of-range hours so operators get
    // an explicit 400 instead of a silent clamp that could mask a bug in
    // the caller (e.g., a UI control off by 10x). The server-side clamp in
    // `clamp_hours_for_sql` is a defense-in-depth backstop, not the primary
    // contract.
    let hours = match q.hours {
        Some(h) if !(1..=HOURS_PUBLIC_MAX).contains(&h) => {
            return Err(ApiError::BadRequest(format!(
                "hours must be between 1 and {HOURS_PUBLIC_MAX} (got {h})"
            )));
        }
        Some(h) => h,
        None => 24,
    };

    let thresholds = load_thresholds(&state);

    let aggregates = state
        .db
        .get_action_aggregates(q.host_code.as_deref(), q.action.as_deref(), hours)
        .await?;

    let bands = bucket_actions(&aggregates, &thresholds);

    Ok(Json(json!({
        "success": true,
        "data": {
            "bands": bands,
            "thresholds": {
                "risk_allow": thresholds.risk_allow,
                "risk_challenge": thresholds.risk_challenge,
                "risk_block": thresholds.risk_block,
            },
            "approximation": true,
            "notes": "elevated band always 0 — exact risk score requires schema option B",
            "generated_at": Utc::now().to_rfc3339(),
        }
    })))
}

/// Narrow risk thresholds projection used by `bucket_actions`.
///
/// Decoupled from `WafPanelConfig` (which has 10+ fields) so the bucket
/// logic depends only on the 3 fields it actually reads — M5 fix. Bounds
/// are clamped to `0..=100` to avoid producing bands where `min > max`
/// when an operator hand-edits TOML beyond the documented ordering — M6
/// fix.
#[derive(Debug, Clone, Copy)]
struct RiskThresholds {
    allow: u32,
    challenge: u32,
    block: u32,
}

const SCORE_MAX: u32 = 100;

impl RiskThresholds {
    fn from_panel(cfg: &WafPanelConfig) -> Self {
        let allow = cfg.risk_allow.min(SCORE_MAX);
        let challenge = cfg.risk_challenge.clamp(allow, SCORE_MAX);
        let block = cfg.risk_block.clamp(challenge, SCORE_MAX);
        Self {
            allow,
            challenge,
            block,
        }
    }
}

/// Read panel thresholds from the in-memory `ArcSwap` snapshot.
///
/// The snapshot is loaded once at bootstrap and refreshed whenever an
/// authenticated operator hits `PUT /api/panel-config`. Reading from
/// disk on every request was a deliberate denial-of-service vector — even
/// with auth, hammering the endpoint forced continuous I/O and TOML parsing.
fn load_thresholds(state: &AppState) -> Arc<WafPanelConfig> {
    state.panel_config.load_full()
}

/// Pure mapping from action aggregates to 4 risk bands.
///
/// - `allow` + `log_only` → green
/// - `challenge` → yellow
/// - `block` + `redirect` → red
/// - `elevated` (orange) stays at 0 in option A
fn bucket_actions(aggregates: &[(String, i64)], thresholds: &WafPanelConfig) -> [BandOut; 4] {
    let t = RiskThresholds::from_panel(thresholds);
    let mut green: i64 = 0;
    let mut yellow: i64 = 0;
    let mut red: i64 = 0;
    for (action, count) in aggregates {
        match action.as_str() {
            "allow" | "log_only" => green = green.saturating_add(*count),
            "challenge" => yellow = yellow.saturating_add(*count),
            "block" | "redirect" => red = red.saturating_add(*count),
            _ => {}
        }
    }

    [
        BandOut {
            label: "allow",
            min: 0,
            max: t.allow,
            count: green,
            color: "green",
        },
        BandOut {
            label: "challenge",
            min: t.allow,
            max: t.challenge,
            count: yellow,
            color: "yellow",
        },
        BandOut {
            label: "elevated",
            min: t.challenge,
            max: t.block,
            count: 0,
            color: "orange",
        },
        BandOut {
            label: "block",
            min: t.block,
            max: SCORE_MAX,
            count: red,
            color: "red",
        },
    ]
}

// Surface used by handler-level tests in `crates/waf-api/tests/`. Kept here
// so the test crate doesn't have to depend on the full server module.
#[doc(hidden)]
pub mod __test_helpers {
    use super::{BandOut, WafPanelConfig, bucket_actions};

    #[must_use]
    pub fn bucket_actions_for_test(aggregates: &[(String, i64)], cfg: &WafPanelConfig) -> [(String, i64); 4] {
        let bands = bucket_actions(aggregates, cfg);
        bands.map(|b: BandOut| (b.label.to_string(), b.count))
    }
}

#[cfg(test)]
#[allow(clippy::indexing_slicing)]
mod tests {
    use super::*;

    fn cfg() -> WafPanelConfig {
        WafPanelConfig::default()
    }

    #[test]
    fn allow_and_log_only_collapse_to_green() {
        let agg = vec![("allow".into(), 100), ("log_only".into(), 25)];
        let bands = bucket_actions(&agg, &cfg());
        assert_eq!(bands[0].label, "allow");
        assert_eq!(bands[0].count, 125);
        assert_eq!(bands[3].count, 0);
    }

    #[test]
    fn challenge_lands_on_yellow_band() {
        let agg = vec![("challenge".into(), 7)];
        let bands = bucket_actions(&agg, &cfg());
        assert_eq!(bands[1].label, "challenge");
        assert_eq!(bands[1].count, 7);
    }

    #[test]
    fn block_and_redirect_collapse_to_red() {
        let agg = vec![("block".into(), 10), ("redirect".into(), 3)];
        let bands = bucket_actions(&agg, &cfg());
        assert_eq!(bands[3].label, "block");
        assert_eq!(bands[3].count, 13);
    }

    #[test]
    fn unknown_actions_ignored() {
        let agg = vec![("unknown".into(), 99), ("allow".into(), 1)];
        let bands = bucket_actions(&agg, &cfg());
        assert_eq!(bands[0].count, 1);
        assert_eq!(bands[1].count, 0);
        assert_eq!(bands[2].count, 0);
        assert_eq!(bands[3].count, 0);
    }

    #[test]
    fn elevated_band_always_zero_in_option_a() {
        let agg = vec![("allow".into(), 100), ("challenge".into(), 50), ("block".into(), 25)];
        let bands = bucket_actions(&agg, &cfg());
        assert_eq!(bands[2].label, "elevated");
        assert_eq!(bands[2].count, 0, "option A keeps elevated empty by design");
    }

    #[test]
    fn empty_aggregates_yield_zero_bands() {
        let bands = bucket_actions(&[], &cfg());
        for b in &bands {
            assert_eq!(b.count, 0);
        }
    }

    #[test]
    fn thresholds_clamp_when_operator_exceeds_score_max() {
        // M6 fix: if operator hand-edits TOML so `risk_block > 100`, the
        // band must not have min > max — clamp instead.
        let panel = WafPanelConfig {
            risk_allow: 30,
            risk_challenge: 60,
            risk_block: 150,
            ..WafPanelConfig::default()
        };
        let bands = bucket_actions(&[], &panel);
        assert_eq!(bands[3].label, "block");
        assert_eq!(bands[3].min, 100, "block band min clamped to 100");
        assert_eq!(bands[3].max, 100, "block band max stays at SCORE_MAX");
        assert!(bands[3].min <= bands[3].max, "band must have non-inverted bounds");
    }

    #[test]
    fn thresholds_collapse_when_ordering_violated() {
        // Operator sets allow > challenge — clamp ensures challenge >= allow.
        let panel = WafPanelConfig {
            risk_allow: 80,
            risk_challenge: 20,
            risk_block: 30,
            ..WafPanelConfig::default()
        };
        let bands = bucket_actions(&[], &panel);
        // challenge clamps up to allow=80, block clamps up to challenge=80.
        assert_eq!(bands[1].min, 80);
        assert_eq!(bands[1].max, 80, "degenerate challenge band collapses to zero-width");
        assert_eq!(bands[2].min, 80);
        assert_eq!(bands[2].max, 80);
    }

    #[test]
    fn band_bounds_reflect_thresholds() {
        let thresholds = WafPanelConfig {
            risk_allow: 25,
            risk_challenge: 60,
            risk_block: 90,
            ..WafPanelConfig::default()
        };
        let bands = bucket_actions(&[], &thresholds);
        assert_eq!(bands[0].max, 25);
        assert_eq!(bands[1].min, 25);
        assert_eq!(bands[1].max, 60);
        assert_eq!(bands[2].min, 60);
        assert_eq!(bands[2].max, 90);
        assert_eq!(bands[3].min, 90);
        assert_eq!(bands[3].max, 100);
    }
}
