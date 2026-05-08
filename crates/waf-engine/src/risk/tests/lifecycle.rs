//! FR-025 Phase 5: Risk lifecycle tests.
//!
//! Verifies the rise → decay → floor behavior end-to-end:
//! - Attack signals raise score
//! - Decay lowers score over time (with clean streak)
//! - `MAX_DECAY`=50 floor prevents complete erasure
//! - `clean_streak` increments on Allow + zero deltas

#![allow(
    clippy::cast_possible_truncation,
    clippy::uninlined_format_args,
    clippy::unwrap_used,
    clippy::expect_used
)]

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use crate::risk::decay::{MAX_DECAY, MIN_CLEAN_STREAK};
use crate::risk::key::RiskKey;
use crate::risk::score::fold;
use crate::risk::state::{Contributor, ContributorKind, RiskState, SeedKind};
use crate::risk::store::{MemoryRiskStore, RiskStore};

fn make_contributor(delta: i16, now_ms: i64) -> Contributor {
    Contributor::new(ContributorKind::Seed(SeedKind::Generic), delta, now_ms)
}

fn make_key() -> RiskKey {
    RiskKey::from_ip(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)))
}

#[tokio::test]
async fn decay_floor_prevents_complete_erasure() {
    let store = Arc::new(MemoryRiskStore::new());
    let key = make_key();

    // Initial attack: score = 80
    let deltas = vec![make_contributor(80, 1000)];
    let result = store.apply(&key, &deltas, 1000).await.unwrap();
    assert_eq!(result.state.clamped_score, 80);

    // Simulate many clean requests to build clean_streak
    // Each clean request increments clean_streak
    for i in 0..MIN_CLEAN_STREAK + 10 {
        let ts = 2000 + i64::from(i) * 100;
        // Empty deltas = clean request
        let _ = store.apply(&key, &[], ts).await.unwrap();
    }

    // After decay, score should be at most original - (requests - MIN_CLEAN_STREAK) * DECAY_RATE
    // But never below MAX_DECAY floor (50)
    let state = store.read(&key).await.unwrap().unwrap();

    // Score should be >= MAX_DECAY (50)
    assert!(
        state.clamped_score >= MAX_DECAY as u8,
        "Score {} should be >= MAX_DECAY floor {}",
        state.clamped_score,
        MAX_DECAY
    );
}

#[tokio::test]
async fn clean_streak_resets_on_positive_delta() {
    let store = Arc::new(MemoryRiskStore::new());
    let key = make_key();

    // Build up clean streak
    for i in 0..5 {
        let _ = store.apply(&key, &[], 1000 + i64::from(i) * 100).await;
    }

    let state1 = store.read(&key).await.unwrap().unwrap();
    assert_eq!(state1.clean_streak, 5);

    // Positive delta resets clean streak
    let deltas = vec![make_contributor(10, 2000)];
    let result = store.apply(&key, &deltas, 2000).await.unwrap();
    assert_eq!(result.state.clean_streak, 0);
}

#[tokio::test]
async fn clean_streak_increments_on_zero_deltas() {
    let store = Arc::new(MemoryRiskStore::new());
    let key = make_key();

    // Initial state
    let _ = store.apply(&key, &[make_contributor(50, 1000)], 1000).await;

    // Each empty apply should increment clean_streak
    for i in 1..=10 {
        let ts = 1000 + i64::from(i) * 100;
        let result = store.apply(&key, &[], ts).await.unwrap();
        assert_eq!(
            result.state.clean_streak, i,
            "After {} clean requests, streak should be {}",
            i, i
        );
    }
}

#[tokio::test]
async fn decay_only_starts_after_min_clean_streak() {
    let store = Arc::new(MemoryRiskStore::new());
    let key = make_key();

    // Start with score 70 (well above MAX_DECAY=50 floor)
    let _ = store.apply(&key, &[make_contributor(70, 1000)], 1000).await;

    // Decay runs BEFORE fold in apply(), so we need MIN_CLEAN_STREAK clean
    // requests to build up the streak, then ONE MORE for decay to trigger.
    // After MIN_CLEAN_STREAK requests: streak = MIN_CLEAN_STREAK, but decay
    // saw streak = MIN_CLEAN_STREAK-1 when it ran.
    for i in 1..=MIN_CLEAN_STREAK {
        let ts = 1000 + i64::from(i) * 100;
        let result = store.apply(&key, &[], ts).await.unwrap();
        assert_eq!(
            result.state.clamped_score, 70,
            "Score should not decay at streak {}, decay needs streak >= {}",
            result.state.clean_streak, MIN_CLEAN_STREAK
        );
    }

    // One more request: decay sees streak=MIN_CLEAN_STREAK and triggers
    let ts = 1000 + i64::from(MIN_CLEAN_STREAK + 1) * 100;
    let result = store.apply(&key, &[], ts).await.unwrap();
    assert!(
        result.state.clamped_score < 70,
        "Score should decay when decay sees streak >= {}, got {} with streak {}",
        MIN_CLEAN_STREAK,
        result.state.clamped_score,
        result.state.clean_streak
    );
}

#[tokio::test]
async fn score_cannot_go_negative_via_decay() {
    let store = Arc::new(MemoryRiskStore::new());
    let key = make_key();

    // Start with score at MAX_DECAY floor
    #[allow(clippy::cast_possible_truncation)]
    let initial_delta = MAX_DECAY as i16; // safe: MAX_DECAY=50 fits in i16
    let _ = store.apply(&key, &[make_contributor(initial_delta, 1000)], 1000).await;

    // Many clean requests should not push below floor
    for i in 0..100 {
        let ts = 2000 + i64::from(i) * 100;
        let result = store.apply(&key, &[], ts).await.unwrap();
        assert!(
            result.state.raw_score >= 0,
            "Raw score {} should never go negative",
            result.state.raw_score
        );
        // clamped_score is u8, always >= 0 by type
    }
}

#[test]
fn fold_preserves_clean_streak_on_empty_deltas() {
    let mut state = RiskState::new(1000);
    state.raw_score = 30;
    state.clamped_score = 30;
    state.clean_streak = 5;

    // Empty deltas should increment clean_streak
    fold(&mut state, &[], 2000);

    assert_eq!(state.clean_streak, 6);
    assert_eq!(state.raw_score, 30); // Unchanged
}

#[test]
fn fold_resets_clean_streak_on_positive_deltas() {
    let mut state = RiskState::new(1000);
    state.raw_score = 30;
    state.clamped_score = 30;
    state.clean_streak = 15;

    let deltas = vec![make_contributor(5, 2000)];
    fold(&mut state, &deltas, 2000);

    assert_eq!(state.clean_streak, 0);
    assert_eq!(state.raw_score, 35);
}

#[test]
fn decay_respects_max_decay_floor() {
    use crate::risk::decay::apply_decay;

    let mut state = RiskState::new(1000);
    state.raw_score = MAX_DECAY + 5; // 55
    #[allow(clippy::cast_possible_truncation)]
    {
        state.clamped_score = (MAX_DECAY + 5) as u8; // safe: 55 fits in u8
    }
    state.clean_streak = MIN_CLEAN_STREAK + 5;

    // Decay should bring score down but not below MAX_DECAY
    for i in 0..20 {
        let ts = 2000 + i64::from(i) * 100;
        apply_decay(&mut state, ts);
    }

    assert!(
        state.raw_score >= MAX_DECAY,
        "Score {} should not drop below MAX_DECAY floor {}",
        state.raw_score,
        MAX_DECAY
    );
}
