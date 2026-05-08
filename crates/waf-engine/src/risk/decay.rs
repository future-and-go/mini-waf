//! FR-025 pure decay function.
//!
//! Applies time-based decay to risk scores. Clean requests (no risk events)
//! accumulate a streak; after enough clean requests, the score decays.
//! Decay has a floor of `MAX_DECAY` (50) — scores never drop below this via
//! automatic decay (only explicit credits can go lower).

use crate::risk::state::{Contributor, ContributorKind, RiskState};

/// Maximum points that can be decayed away automatically.
/// Scores above this floor require explicit credits to reduce further.
pub const MAX_DECAY: i32 = 50;

/// Minimum clean streak before decay kicks in.
pub const MIN_CLEAN_STREAK: u32 = 10;

/// Points decayed per clean request after `MIN_CLEAN_STREAK`.
pub const DECAY_RATE: i16 = 1;

/// Apply decay to the state if conditions are met.
///
/// Returns the decay delta applied (0 if no decay). Mutates state in place.
pub fn apply_decay(state: &mut RiskState, now_ms: i64) -> i16 {
    if state.clean_streak < MIN_CLEAN_STREAK {
        return 0;
    }

    if state.is_pinned(now_ms) {
        return 0;
    }

    let floor = MAX_DECAY;
    if state.raw_score <= floor {
        return 0;
    }

    let available = (state.raw_score - floor).min(i32::from(DECAY_RATE));
    if available <= 0 {
        return 0;
    }

    #[allow(clippy::cast_possible_truncation)]
    let decay_delta = -(available as i16); // safe: available is clamped to DECAY_RATE (1)
    state.raw_score = state.raw_score.saturating_add(i32::from(decay_delta));
    state.push_contributor(Contributor::new(ContributorKind::Decay, decay_delta, now_ms));
    state.reclamp();

    decay_delta
}

/// Calculate how much decay would apply without mutating state.
#[must_use]
pub fn preview_decay(state: &RiskState, now_ms: i64) -> i16 {
    if state.clean_streak < MIN_CLEAN_STREAK {
        return 0;
    }
    if state.is_pinned(now_ms) {
        return 0;
    }
    let floor = MAX_DECAY;
    if state.raw_score <= floor {
        return 0;
    }
    let available = (state.raw_score - floor).min(i32::from(DECAY_RATE));
    if available <= 0 {
        return 0;
    }
    #[allow(clippy::cast_possible_truncation)]
    {
        -(available as i16) // safe: available is clamped to DECAY_RATE (1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_decay_below_min_streak() {
        let mut state = RiskState::new(1000);
        state.raw_score = 80;
        state.clamped_score = 80;
        state.clean_streak = 5;

        let decay = apply_decay(&mut state, 2000);
        assert_eq!(decay, 0);
        assert_eq!(state.raw_score, 80);
    }

    #[test]
    fn decay_applies_after_min_streak() {
        let mut state = RiskState::new(1000);
        state.raw_score = 80;
        state.clamped_score = 80;
        state.clean_streak = 15;

        let decay = apply_decay(&mut state, 2000);
        assert_eq!(decay, -1);
        assert_eq!(state.raw_score, 79);
        assert_eq!(state.clamped_score, 79);
    }

    #[test]
    fn decay_stops_at_floor() {
        let mut state = RiskState::new(1000);
        state.raw_score = 51;
        state.clamped_score = 51;
        state.clean_streak = 15;

        let decay = apply_decay(&mut state, 2000);
        assert_eq!(decay, -1);
        assert_eq!(state.raw_score, 50);

        let decay2 = apply_decay(&mut state, 3000);
        assert_eq!(decay2, 0);
        assert_eq!(state.raw_score, 50);
    }

    #[test]
    fn decay_skipped_when_pinned() {
        let mut state = RiskState::new(1000);
        state.raw_score = 80;
        state.clamped_score = 80;
        state.clean_streak = 15;
        state.pinned_until_ms = Some(5000);

        let decay = apply_decay(&mut state, 2000);
        assert_eq!(decay, 0);
        assert_eq!(state.raw_score, 80);
    }

    #[test]
    fn preview_matches_apply() {
        let mut state = RiskState::new(1000);
        state.raw_score = 75;
        state.clamped_score = 75;
        state.clean_streak = 20;

        let preview = preview_decay(&state, 2000);
        let actual = apply_decay(&mut state, 2000);
        assert_eq!(preview, actual);
    }
}
