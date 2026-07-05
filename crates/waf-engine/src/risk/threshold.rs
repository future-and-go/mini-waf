//! Pure threshold gate.
//!
//! Maps a clamped risk score (0..=100) to a `WafAction` based on configured
//! thresholds. Uses the tier's `RiskThresholds` (allow, challenge, block).

use waf_common::WafAction;
use waf_common::tier::{FailMode, RiskThresholds};

/// Decide the action based on the score and thresholds.
///
/// - score < allow     → Allow
/// - score >= block    → Block
/// - otherwise         → Challenge
///
/// If `override_block` is true, always returns Block (used for honeypot pins).
#[must_use]
pub fn decide(score: u8, thresholds: &RiskThresholds, override_block: bool) -> WafAction {
    if override_block {
        return WafAction::Block {
            status: 403,
            body: Some("Access denied.".to_string()),
        };
    }

    let score_u32 = u32::from(score);

    if score_u32 < thresholds.allow {
        return WafAction::Allow;
    }

    if score_u32 >= thresholds.block {
        return WafAction::Block {
            status: 403,
            body: Some("Access denied.".to_string()),
        };
    }

    WafAction::Challenge
}

/// Decide the action when the risk store is degraded (backend unreachable).
///
/// The score is a best-known substitute, not authority, so the tier's
/// declared fail mode picks the policy:
///
/// - `FailMode::Open`  → [`decide`] on the best-known score: a cached high
///   score still defends; an unknown actor (score 0) is allowed.
/// - `FailMode::Close` → `Block { 503 }` regardless of score — never trust
///   a stale or absent score on a fail-closed tier.
#[must_use]
pub fn degraded_action(fail_mode: FailMode, score: u8, thresholds: &RiskThresholds, override_block: bool) -> WafAction {
    match fail_mode {
        FailMode::Open => decide(score, thresholds, override_block),
        FailMode::Close => WafAction::Block {
            status: 503,
            body: None,
        },
    }
}

/// Check if a score would result in Allow.
#[must_use]
pub const fn is_allowed(score: u8, thresholds: &RiskThresholds) -> bool {
    (score as u32) < thresholds.allow
}

/// Check if a score would result in Block.
#[must_use]
pub const fn is_blocked(score: u8, thresholds: &RiskThresholds) -> bool {
    (score as u32) >= thresholds.block
}

/// Check if a score would result in Challenge.
#[must_use]
pub const fn is_challenged(score: u8, thresholds: &RiskThresholds) -> bool {
    let s = score as u32;
    s >= thresholds.allow && s < thresholds.block
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_thresholds() -> RiskThresholds {
        RiskThresholds {
            allow: 30,
            challenge: 70,
            block: 90,
        }
    }

    #[test]
    fn degraded_open_trusts_best_known_score_across_bands() {
        let t = default_thresholds();
        // Same mapping as `decide` in every band: unknown actor allowed,
        // cached mid score challenged, cached high score blocked.
        assert!(matches!(
            degraded_action(FailMode::Open, 0, &t, false),
            WafAction::Allow
        ));
        assert!(matches!(
            degraded_action(FailMode::Open, 29, &t, false),
            WafAction::Allow
        ));
        assert!(matches!(
            degraded_action(FailMode::Open, 30, &t, false),
            WafAction::Challenge
        ));
        assert!(matches!(
            degraded_action(FailMode::Open, 89, &t, false),
            WafAction::Challenge
        ));
        assert!(matches!(
            degraded_action(FailMode::Open, 90, &t, false),
            WafAction::Block { status: 403, .. }
        ));
        assert!(matches!(
            degraded_action(FailMode::Open, 100, &t, false),
            WafAction::Block { status: 403, .. }
        ));
        // Pinned actor blocks even at a low cached score.
        assert!(matches!(
            degraded_action(FailMode::Open, 0, &t, true),
            WafAction::Block { status: 403, .. }
        ));
    }

    #[test]
    fn degraded_close_blocks_503_regardless_of_score() {
        let t = default_thresholds();
        for score in [0u8, 29, 30, 89, 90, 100] {
            assert!(
                matches!(
                    degraded_action(FailMode::Close, score, &t, false),
                    WafAction::Block {
                        status: 503,
                        body: None
                    }
                ),
                "fail-closed tier must block at score {score}"
            );
        }
        assert!(matches!(
            degraded_action(FailMode::Close, 0, &t, true),
            WafAction::Block { status: 503, .. }
        ));
    }

    #[test]
    fn score_below_allow_returns_allow() {
        let t = default_thresholds();
        assert!(matches!(decide(0, &t, false), WafAction::Allow));
        assert!(matches!(decide(29, &t, false), WafAction::Allow));
    }

    #[test]
    fn score_at_allow_returns_challenge() {
        let t = default_thresholds();
        assert!(matches!(decide(30, &t, false), WafAction::Challenge));
        assert!(matches!(decide(69, &t, false), WafAction::Challenge));
        assert!(matches!(decide(89, &t, false), WafAction::Challenge));
    }

    #[test]
    fn score_at_block_returns_block() {
        let t = default_thresholds();
        assert!(matches!(decide(90, &t, false), WafAction::Block { .. }));
        assert!(matches!(decide(100, &t, false), WafAction::Block { .. }));
    }

    #[test]
    fn override_block_always_blocks() {
        let t = default_thresholds();
        assert!(matches!(decide(0, &t, true), WafAction::Block { .. }));
        assert!(matches!(decide(50, &t, true), WafAction::Block { .. }));
    }

    #[test]
    fn helper_functions_match_decide() {
        let t = default_thresholds();

        assert!(is_allowed(0, &t));
        assert!(is_allowed(29, &t));
        assert!(!is_allowed(30, &t));

        assert!(!is_blocked(89, &t));
        assert!(is_blocked(90, &t));
        assert!(is_blocked(100, &t));

        assert!(!is_challenged(29, &t));
        assert!(is_challenged(30, &t));
        assert!(is_challenged(89, &t));
        assert!(!is_challenged(90, &t));
    }

    #[test]
    fn boundary_values() {
        let t = RiskThresholds {
            allow: 30,
            challenge: 70,
            block: 70,
        };
        assert!(matches!(decide(29, &t, false), WafAction::Allow));
        assert!(matches!(decide(30, &t, false), WafAction::Challenge));
        assert!(matches!(decide(69, &t, false), WafAction::Challenge));
        assert!(matches!(decide(70, &t, false), WafAction::Block { .. }));
    }
}
