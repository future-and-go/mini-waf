//! FR-025 pure score-fold function.
//!
//! Takes a `RiskState` and a list of deltas, returns the updated state.
//! No I/O, no side effects — pure transformation.

use crate::risk::state::{Contributor, RiskState};

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

#[cfg(test)]
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
}
