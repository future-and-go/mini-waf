//! FR-025 pure score-fold function.
//!
//! Takes a `RiskState` and a list of deltas, returns the updated state.
//! No I/O, no side effects — pure transformation.

use crate::risk::state::{Contributor, ContributorKind, RiskState};
use crate::rules::engine::RiskDelta;

/// Apply a batch of contributors to the state.
///
/// Updates `raw_score`, pushes contributors to the ring, bumps `last_updated_ms`,
/// and recalculates `clamped_score`. If `deltas` is empty, only timestamps update.
pub fn fold(state: &mut RiskState, deltas: &[Contributor], now_ms: i64) {
    state.last_updated_ms = now_ms;

    if deltas.is_empty() {
        state.clean_streak = state.clean_streak.saturating_add(1);
        return;
    }

    state.clean_streak = 0;

    for c in deltas {
        state.raw_score = state.raw_score.saturating_add(i32::from(c.delta));
        state.push_contributor(c.clone());
    }

    state.reclamp();
}

/// Compute the sum of deltas without mutating state.
#[must_use]
pub fn sum_deltas(deltas: &[Contributor]) -> i32 {
    deltas.iter().map(|c| i32::from(c.delta)).sum()
}

/// FR-025: Maximum per-request raw delta sum.
pub const MAX_PER_REQUEST_DELTA: i32 = 100;

/// Convert rule engine `RiskDelta` to a `Contributor` for the risk store.
#[must_use]
pub fn rule_delta_to_contributor(delta: &RiskDelta, ts_ms: i64) -> Contributor {
    Contributor::new(ContributorKind::Rule(delta.rule_id.clone()), delta.delta, ts_ms)
}

/// Convert a list of `RiskDelta`s to `Contributor`s.
#[must_use]
pub fn rule_deltas_to_contributors(deltas: &[RiskDelta], ts_ms: i64) -> Vec<Contributor> {
    deltas.iter().map(|d| rule_delta_to_contributor(d, ts_ms)).collect()
}

/// Compute the dominant contributor (highest |delta|) from current-request deltas.
///
/// Returns the `rule_id` of the rule with the largest absolute delta contribution.
/// Used for setting the `X-WAF-Rule-Id` header.
#[must_use]
pub fn dominant_contributor(deltas: &[RiskDelta]) -> Option<&str> {
    deltas.iter().max_by_key(|d| d.delta.abs()).map(|d| d.rule_id.as_str())
}

/// Clamp per-request deltas to `[0, 100]` by truncating oldest positive deltas.
///
/// This ensures a single request cannot exceed the score cap, while preserving
/// the most recent/impactful deltas. Negative deltas (credits) are kept as-is.
///
/// Returns a new vector with the clamped deltas and the raw (pre-clamp) sum.
#[must_use]
pub fn clamp_per_request_deltas(deltas: &[Contributor]) -> (Vec<Contributor>, i32) {
    if deltas.is_empty() {
        return (Vec::new(), 0);
    }

    let raw_sum = sum_deltas(deltas);

    // Sum only positive deltas for capping
    let positive_sum: i32 = deltas.iter().filter(|c| c.delta > 0).map(|c| i32::from(c.delta)).sum();

    if positive_sum <= MAX_PER_REQUEST_DELTA {
        return (deltas.to_vec(), raw_sum);
    }

    // Reverse order: newest first. Accumulate from newest, drop oldest when exceeding cap.
    let mut result: Vec<Contributor> = Vec::with_capacity(deltas.len());
    let mut running_positive = 0i32;

    for c in deltas.iter().rev() {
        if c.delta <= 0 {
            // Negative deltas always kept
            result.push(c.clone());
        } else {
            let candidate = running_positive + i32::from(c.delta);
            if candidate <= MAX_PER_REQUEST_DELTA {
                running_positive = candidate;
                result.push(c.clone());
            }
            // Otherwise skip (truncate oldest positive delta)
        }
    }

    // Restore original order (oldest first)
    result.reverse();
    (result, raw_sum)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, clippy::panic)]
mod tests {
    use super::*;
    use crate::risk::state::{ContributorKind, SeedKind};

    fn make_contributor(delta: i16) -> Contributor {
        Contributor::new(ContributorKind::Seed(SeedKind::Generic), delta, 1000)
    }

    #[test]
    fn fold_empty_increments_clean_streak() {
        let mut state = RiskState::new(1000);
        state.clean_streak = 5;
        fold(&mut state, &[], 2000);
        assert_eq!(state.clean_streak, 6);
        assert_eq!(state.last_updated_ms, 2000);
    }

    #[test]
    fn fold_with_deltas_resets_clean_streak() {
        let mut state = RiskState::new(1000);
        state.clean_streak = 5;
        let deltas = vec![make_contributor(10)];
        fold(&mut state, &deltas, 2000);
        assert_eq!(state.clean_streak, 0);
        assert_eq!(state.raw_score, 10);
        assert_eq!(state.clamped_score, 10);
    }

    #[test]
    fn fold_accumulates_deltas() {
        let mut state = RiskState::new(1000);
        let deltas = vec![make_contributor(30), make_contributor(25), make_contributor(-5)];
        fold(&mut state, &deltas, 2000);
        assert_eq!(state.raw_score, 50);
        assert_eq!(state.clamped_score, 50);
        assert_eq!(state.contributors.len(), 3);
    }

    #[test]
    fn fold_clamps_to_100() {
        let mut state = RiskState::new(1000);
        let deltas = vec![make_contributor(120)];
        fold(&mut state, &deltas, 2000);
        assert_eq!(state.raw_score, 120);
        assert_eq!(state.clamped_score, 100);
    }

    #[test]
    fn fold_clamps_to_0() {
        let mut state = RiskState::new(1000);
        state.raw_score = 10;
        let deltas = vec![make_contributor(-50)];
        fold(&mut state, &deltas, 2000);
        assert_eq!(state.raw_score, -40);
        assert_eq!(state.clamped_score, 0);
    }

    #[test]
    fn sum_deltas_computes_correctly() {
        let deltas = vec![make_contributor(10), make_contributor(-3), make_contributor(5)];
        assert_eq!(sum_deltas(&deltas), 12);
    }

    // ── clamp_per_request_deltas tests ────────────────────────────────────────

    #[test]
    fn clamp_empty_returns_empty() {
        let (clamped, raw) = clamp_per_request_deltas(&[]);
        assert!(clamped.is_empty());
        assert_eq!(raw, 0);
    }

    #[test]
    fn clamp_under_limit_returns_unchanged() {
        let deltas = vec![make_contributor(40), make_contributor(30), make_contributor(20)];
        let (clamped, raw) = clamp_per_request_deltas(&deltas);
        assert_eq!(clamped.len(), 3);
        assert_eq!(raw, 90);
        assert_eq!(sum_deltas(&clamped), 90);
    }

    #[test]
    fn clamp_over_limit_truncates_oldest() {
        // 40+40+40=120 > 100, should truncate the oldest (first 40)
        let deltas = vec![make_contributor(40), make_contributor(40), make_contributor(40)];
        let (clamped, raw) = clamp_per_request_deltas(&deltas);
        assert_eq!(raw, 120); // Raw sum preserved for audit
        assert_eq!(clamped.len(), 2); // Oldest truncated
        assert_eq!(sum_deltas(&clamped), 80); // 40+40 from newest two
    }

    #[test]
    fn clamp_preserves_negative_deltas() {
        // 40+60=100, plus a -10 credit
        let deltas = vec![make_contributor(40), make_contributor(-10), make_contributor(60)];
        let (clamped, raw) = clamp_per_request_deltas(&deltas);
        assert_eq!(raw, 90);
        assert_eq!(clamped.len(), 3); // All kept
        assert_eq!(sum_deltas(&clamped), 90);
    }

    #[test]
    fn clamp_negative_deltas_not_counted_against_cap() {
        // Positive: 60+60=120 > 100, should truncate oldest positive
        // Negative -5 should be preserved
        let deltas = vec![make_contributor(60), make_contributor(-5), make_contributor(60)];
        let (clamped, raw) = clamp_per_request_deltas(&deltas);
        assert_eq!(raw, 115);
        // Only newest positive (60) fits, plus the negative
        assert_eq!(clamped.len(), 2);
        // Should have -5 and 60
        let positive_sum: i32 = clamped.iter().filter(|c| c.delta > 0).map(|c| i32::from(c.delta)).sum();
        assert_eq!(positive_sum, 60);
    }

    // ── rule_delta_to_contributor tests ───────────────────────────────────────

    fn make_risk_delta(rule_id: &str, delta: i16) -> RiskDelta {
        RiskDelta {
            rule_id: rule_id.to_string(),
            delta,
        }
    }

    #[test]
    fn rule_delta_converts_to_contributor() {
        let delta = make_risk_delta("sqli-001", 40);
        let contrib = rule_delta_to_contributor(&delta, 1000);
        assert_eq!(contrib.delta, 40);
        assert_eq!(contrib.ts_ms, 1000);
        match contrib.kind {
            ContributorKind::Rule(id) => assert_eq!(id, "sqli-001"),
            _ => panic!("expected Rule kind"),
        }
    }

    #[test]
    fn rule_deltas_to_contributors_batch() {
        let deltas = vec![
            make_risk_delta("sqli-001", 40),
            make_risk_delta("xss-002", 35),
            make_risk_delta("rce-003", 60),
        ];
        let contribs = rule_deltas_to_contributors(&deltas, 2000);
        assert_eq!(contribs.len(), 3);
        assert_eq!(contribs[0].delta, 40);
        assert_eq!(contribs[1].delta, 35);
        assert_eq!(contribs[2].delta, 60);
        for c in &contribs {
            assert_eq!(c.ts_ms, 2000);
        }
    }

    // ── dominant_contributor tests ────────────────────────────────────────────

    #[test]
    fn dominant_empty_returns_none() {
        assert!(dominant_contributor(&[]).is_none());
    }

    #[test]
    fn dominant_single_returns_that_rule() {
        let deltas = vec![make_risk_delta("sqli-001", 40)];
        assert_eq!(dominant_contributor(&deltas), Some("sqli-001"));
    }

    #[test]
    fn dominant_picks_highest_abs_delta() {
        let deltas = vec![
            make_risk_delta("sqli-001", 30),
            make_risk_delta("rce-002", 50),
            make_risk_delta("xss-003", 20),
        ];
        assert_eq!(dominant_contributor(&deltas), Some("rce-002"));
    }

    #[test]
    fn dominant_negative_counted_by_abs() {
        // -60 has higher abs than 50
        let deltas = vec![make_risk_delta("credit-001", -60), make_risk_delta("rce-002", 50)];
        assert_eq!(dominant_contributor(&deltas), Some("credit-001"));
    }
}
