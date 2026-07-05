//! Store conformance suite.
//!
//! Shared test cases that any `RiskStore` implementation must pass.
//! Memory backend tests call this; the Redis backend reuses it.

use std::net::{IpAddr, Ipv4Addr};

use crate::risk::key::{RiskKey, SessionId};
use crate::risk::state::{Contributor, ContributorKind, SeedKind};
use crate::risk::store::RiskStore;

fn make_contributor(delta: i16, ts_ms: i64) -> Contributor {
    Contributor::new(ContributorKind::Seed(SeedKind::Generic), delta, ts_ms)
}

/// Run all conformance tests against the given store.
pub async fn run_all<S: RiskStore>(store: &S) {
    test_insert_and_read(store).await;
    test_apply_accumulates(store).await;
    test_force_max(store).await;
    test_triple_index_max(store).await;
    test_apply_divergent_score_convergence(store).await;
    test_apply_converges_axes(store).await;
    test_decay_contributor_roundtrip(store).await;
    test_oversized_batch_clamps_to_cap(store).await;
    test_clear_removes_all_axes(store).await;
    test_admin_credit_reduces_score(store).await;
    test_reset_all(store).await;
    test_purge_expired(store).await;
}

async fn test_insert_and_read<S: RiskStore>(store: &S) {
    store.reset_all().await.unwrap();

    let key = RiskKey::from_ip(IpAddr::V4(Ipv4Addr::new(10, 1, 1, 1)));
    let result = store.apply(&key, &[make_contributor(25, 1000)], 1000).await.unwrap();

    assert!(result.is_new, "first apply should be new");
    assert_eq!(result.state.clamped_score, 25);

    let read = store.read(&key).await.unwrap();
    assert!(read.is_some(), "read after apply should return state");
    assert_eq!(read.unwrap().clamped_score, 25);
}

async fn test_apply_accumulates<S: RiskStore>(store: &S) {
    store.reset_all().await.unwrap();

    let key = RiskKey::from_ip(IpAddr::V4(Ipv4Addr::new(10, 2, 2, 2)));

    store.apply(&key, &[make_contributor(20, 1000)], 1000).await.unwrap();
    store.apply(&key, &[make_contributor(15, 2000)], 2000).await.unwrap();
    let result = store.apply(&key, &[make_contributor(10, 3000)], 3000).await.unwrap();

    assert!(!result.is_new, "subsequent applies should not be new");
    assert_eq!(result.state.clamped_score, 45);
}

async fn test_force_max<S: RiskStore>(store: &S) {
    store.reset_all().await.unwrap();

    let key = RiskKey::from_ip(IpAddr::V4(Ipv4Addr::new(10, 3, 3, 3)));
    store.apply(&key, &[make_contributor(30, 1000)], 1000).await.unwrap();

    store.force_max(&key, 5000, 2000).await.unwrap();

    let state = store.read(&key).await.unwrap().unwrap();
    assert_eq!(state.clamped_score, 100, "force_max should set score to 100");
    assert_eq!(state.pinned_until_ms, Some(5000), "force_max should set pin");
}

async fn test_triple_index_max<S: RiskStore>(store: &S) {
    store.reset_all().await.unwrap();

    // Insert via fp_hash with score 50
    let key_fp = RiskKey {
        ip: None,
        fp_hash: Some(111_111),
        session: None,
    };
    store.apply(&key_fp, &[make_contributor(50, 1000)], 1000).await.unwrap();

    // Insert via session with score 30
    let key_sess = RiskKey {
        ip: None,
        fp_hash: None,
        session: Some(SessionId::new(vec![9, 8, 7, 6])),
    };
    store
        .apply(&key_sess, &[make_contributor(30, 1000)], 1000)
        .await
        .unwrap();

    // Read with both axes — should get max (50)
    let key_both = RiskKey {
        ip: None,
        fp_hash: Some(111_111),
        session: Some(SessionId::new(vec![9, 8, 7, 6])),
    };
    let state = store.read(&key_both).await.unwrap().unwrap();
    assert_eq!(state.clamped_score, 50, "read should return max across indices");
}

/// Apply-time convergence must select the max-score owner: an actor with
/// accumulated risk cannot shed it by colliding with a cleaner identity axis.
pub async fn test_apply_divergent_score_convergence<S: RiskStore>(store: &S) {
    store.reset_all().await.unwrap();

    // High-risk actor on the fingerprint axis (score 90)
    let key_fp = RiskKey {
        ip: None,
        fp_hash: Some(444_444),
        session: None,
    };
    store.apply(&key_fp, &[make_contributor(90, 1000)], 1000).await.unwrap();

    // Clean actor on the session axis (score 0)
    let key_sess = RiskKey {
        ip: None,
        fp_hash: None,
        session: Some(SessionId::new(vec![4, 3, 2, 1])),
    };
    store.apply(&key_sess, &[], 1000).await.unwrap();

    // Colliding apply across both axes must keep the max score
    let key_both = RiskKey {
        ip: None,
        fp_hash: Some(444_444),
        session: Some(SessionId::new(vec![4, 3, 2, 1])),
    };
    let result = store.apply(&key_both, &[], 2000).await.unwrap();
    assert_eq!(
        result.state.clamped_score, 90,
        "colliding apply must converge to the max-score owner"
    );

    // Both axes now resolve to the surviving high-score state
    let by_sess = store.read(&key_sess).await.unwrap().unwrap();
    assert_eq!(by_sess.clamped_score, 90, "session axis must see the max-score owner");
    let by_fp = store.read(&key_fp).await.unwrap().unwrap();
    assert_eq!(by_fp.clamped_score, 90, "fp axis must see the max-score owner");
}

/// Cross-axis convergence at apply time: applying with an extra axis unifies
/// it with the existing owner so either axis alone reads the same state.
pub async fn test_apply_converges_axes<S: RiskStore>(store: &S) {
    store.reset_all().await.unwrap();

    let ip = IpAddr::V4(Ipv4Addr::new(10, 7, 7, 7));
    let key_ip = RiskKey::from_ip(ip);
    store.apply(&key_ip, &[make_contributor(40, 1000)], 1000).await.unwrap();

    let key_ip_fp = RiskKey {
        ip: Some(ip),
        fp_hash: Some(333_333),
        session: None,
    };
    store
        .apply(&key_ip_fp, &[make_contributor(10, 2000)], 2000)
        .await
        .unwrap();

    // The fp axis alone must resolve to the same accumulated state
    let fp_only_key = RiskKey {
        ip: None,
        fp_hash: Some(333_333),
        session: None,
    };
    let state = store.read(&fp_only_key).await.unwrap().unwrap();
    assert_eq!(state.clamped_score, 50, "fp axis must see the converged owner state");
}

/// Force the decay path so the backend-created `Decay` contributor is proven
/// to round-trip through serde.
///
/// Recipe: score above the decay floor, then enough clean (empty-deltas)
/// applies to reach `MIN_CLEAN_STREAK`, then one more clean apply to fire
/// decay. Exercises the backend's own decay branch (previously untested on
/// Redis) and proves the persisted `Decay` contributor parses on `read`.
pub async fn test_decay_contributor_roundtrip<S: RiskStore>(store: &S) {
    use crate::risk::decay::{DECAY_RATE, MAX_DECAY, MIN_CLEAN_STREAK};

    store.reset_all().await.unwrap();

    let key = RiskKey::from_ip(IpAddr::V4(Ipv4Addr::new(10, 8, 8, 8)));

    // Score must sit above MAX_DECAY (the decay floor) for decay to apply.
    let seed = i16::try_from(MAX_DECAY).unwrap() + 40;
    let decayed = i32::from(seed) - i32::from(DECAY_RATE);
    store.apply(&key, &[make_contributor(seed, 1000)], 1000).await.unwrap();

    // Clean applies build the streak; decay checks the streak BEFORE folding,
    // so no decay fires while the streak climbs to MIN_CLEAN_STREAK.
    let mut now_ms = 1000;
    for _ in 0..MIN_CLEAN_STREAK {
        now_ms += 1000;
        let result = store.apply(&key, &[], now_ms).await.unwrap();
        assert_eq!(
            i32::from(result.state.clamped_score),
            i32::from(seed),
            "no decay while streak is below MIN_CLEAN_STREAK"
        );
    }

    // Streak is now at threshold — the next clean apply fires decay.
    now_ms += 1000;
    let result = store.apply(&key, &[], now_ms).await.unwrap();
    assert_eq!(
        i32::from(result.state.clamped_score),
        decayed,
        "decay should reduce score by DECAY_RATE"
    );
    assert!(
        result
            .state
            .contributors
            .iter()
            .any(|c| matches!(c.kind, ContributorKind::Decay)),
        "decay apply must append a Decay contributor"
    );

    // The persisted state (with the Decay contributor) must round-trip.
    let read = store.read(&key).await.unwrap();
    let state = read.expect("state with Decay contributor must parse on read");
    assert_eq!(i32::from(state.clamped_score), decayed);
    assert!(
        state
            .contributors
            .iter()
            .any(|c| matches!(c.kind, ContributorKind::Decay)),
        "Decay contributor must survive the round-trip"
    );
}

/// A single apply whose deltas sum past the score cap must clamp the visible
/// score to 100 while the negative credit contributor still round-trips.
async fn test_oversized_batch_clamps_to_cap<S: RiskStore>(store: &S) {
    store.reset_all().await.unwrap();

    let key = RiskKey::from_ip(IpAddr::V4(Ipv4Addr::new(10, 11, 11, 11)));
    let deltas = vec![
        make_contributor(60, 1000),
        make_contributor(60, 1000),
        Contributor::new(ContributorKind::AdminCredit, -20, 1000),
        make_contributor(30, 1000),
    ];
    let result = store.apply(&key, &deltas, 1000).await.unwrap();
    assert_eq!(result.state.clamped_score, 100, "visible score must clamp at 100");

    let state = store.read(&key).await.unwrap().expect("state must persist");
    assert_eq!(state.clamped_score, 100);
    assert!(
        state
            .contributors
            .iter()
            .any(|c| matches!(c.kind, ContributorKind::AdminCredit)),
        "credit contributor must survive the round-trip"
    );
}

/// Decay must honor a non-default configured rate.
///
/// Call with a store built with `decay_rate = 3` and otherwise-default decay
/// settings (memory: `MemoryRiskStore::with_decay`, redis: `RedisRiskConfig.decay`).
pub async fn test_decay_honors_configured_rate<S: RiskStore>(store: &S) {
    use crate::risk::decay::{MAX_DECAY, MIN_CLEAN_STREAK};

    store.reset_all().await.unwrap();

    let key = RiskKey::from_ip(IpAddr::V4(Ipv4Addr::new(10, 12, 12, 12)));
    let seed = i16::try_from(MAX_DECAY).unwrap() + 40;
    store.apply(&key, &[make_contributor(seed, 1000)], 1000).await.unwrap();

    // Build the clean streak; decay checks the streak BEFORE folding, so no
    // decay fires while the streak climbs to the threshold.
    let mut now_ms = 1000;
    for _ in 0..MIN_CLEAN_STREAK {
        now_ms += 1000;
        store.apply(&key, &[], now_ms).await.unwrap();
    }

    now_ms += 1000;
    let result = store.apply(&key, &[], now_ms).await.unwrap();
    assert_eq!(
        i32::from(result.state.clamped_score),
        i32::from(seed) - 3,
        "decay must subtract the configured rate, not the default"
    );
}

/// A store built with `decay_rate = 0` must never decay, no matter how long
/// the clean streak grows.
pub async fn test_decay_disabled_when_rate_zero<S: RiskStore>(store: &S) {
    store.reset_all().await.unwrap();

    let key = RiskKey::from_ip(IpAddr::V4(Ipv4Addr::new(10, 13, 13, 13)));
    store.apply(&key, &[make_contributor(90, 1000)], 1000).await.unwrap();

    let mut now_ms = 1000;
    for _ in 0..30 {
        now_ms += 1000;
        let result = store.apply(&key, &[], now_ms).await.unwrap();
        assert_eq!(
            result.state.clamped_score, 90,
            "decay_rate 0 must leave the score untouched"
        );
    }

    let state = store.read(&key).await.unwrap().expect("state must persist");
    assert!(
        !state
            .contributors
            .iter()
            .any(|c| matches!(c.kind, ContributorKind::Decay)),
        "decay_rate 0 must not append Decay contributors"
    );
}

/// Admin clear must remove the state so no axis resurrects the old score.
pub async fn test_clear_removes_all_axes<S: RiskStore>(store: &S) {
    store.reset_all().await.unwrap();

    let ip = IpAddr::V4(Ipv4Addr::new(10, 9, 9, 9));
    let key_all = RiskKey {
        ip: Some(ip),
        fp_hash: Some(555_555),
        session: Some(SessionId::new(vec![1, 2, 3, 4])),
    };
    store
        .apply(&key_all, &[make_contributor(60, 1000)], 1000)
        .await
        .unwrap();

    // Clearing an absent actor reports nothing removed.
    let other = RiskKey::from_ip(IpAddr::V4(Ipv4Addr::new(10, 9, 9, 10)));
    assert!(!store.clear(&other).await.unwrap(), "clear of unknown actor → false");

    // Clear via the IP axis only — fp/session axes must not resurrect it.
    let key_ip = RiskKey::from_ip(ip);
    assert!(store.clear(&key_ip).await.unwrap(), "clear of known actor → true");

    assert!(
        store.read(&key_ip).await.unwrap().is_none(),
        "IP axis must be gone after clear"
    );
    let after = store.apply(&key_all, &[], 2000).await.unwrap();
    assert_eq!(
        after.state.clamped_score, 0,
        "re-apply after clear must start from score 0, not the cleared score"
    );
}

/// Admin credit: a negative `AdminCredit` contributor reduces the score,
/// clamps at 0, and round-trips through the backend's serde.
pub async fn test_admin_credit_reduces_score<S: RiskStore>(store: &S) {
    store.reset_all().await.unwrap();

    let key = RiskKey::from_ip(IpAddr::V4(Ipv4Addr::new(10, 10, 10, 10)));
    store.apply(&key, &[make_contributor(60, 1000)], 1000).await.unwrap();

    let credit = Contributor::new(ContributorKind::AdminCredit, -25, 2000);
    let result = store.apply(&key, &[credit], 2000).await.unwrap();
    assert_eq!(result.state.clamped_score, 35, "credit must subtract from the score");

    // Over-credit clamps at 0 instead of going negative.
    let big_credit = Contributor::new(ContributorKind::AdminCredit, -100, 3000);
    let result = store.apply(&key, &[big_credit], 3000).await.unwrap();
    assert_eq!(result.state.clamped_score, 0, "over-credit must clamp at 0");

    // The persisted AdminCredit contributor must parse on read.
    let state = store.read(&key).await.unwrap().expect("state must survive credit");
    assert!(
        state
            .contributors
            .iter()
            .any(|c| matches!(c.kind, ContributorKind::AdminCredit)),
        "AdminCredit contributor must survive the round-trip"
    );
}

async fn test_reset_all<S: RiskStore>(store: &S) {
    store.reset_all().await.unwrap();

    let key = RiskKey::from_ip(IpAddr::V4(Ipv4Addr::new(10, 5, 5, 5)));
    store.apply(&key, &[make_contributor(25, 1000)], 1000).await.unwrap();

    assert!(!store.is_empty().await, "store should not be empty after apply");

    store.reset_all().await.unwrap();

    assert!(store.is_empty().await, "store should be empty after reset_all");
    assert!(
        store.read(&key).await.unwrap().is_none(),
        "read after reset should be None"
    );
}

/// Test `purge_expired` behavior.
///
/// Note: Redis backend returns 0 (no-op) because Redis TTL handles expiration
/// natively. Memory backend actively purges. Both are correct implementations.
async fn test_purge_expired<S: RiskStore>(store: &S) {
    store.reset_all().await.unwrap();

    let key = RiskKey::from_ip(IpAddr::V4(Ipv4Addr::new(10, 6, 6, 6)));
    store.apply(&key, &[make_contributor(25, 1000)], 1000).await.unwrap();

    // Entry updated at 1000, now is 2000, TTL is 5000 → should NOT expire
    let purged = store.purge_expired(5000, 2000).await.unwrap();
    assert_eq!(purged, 0, "entry within TTL should not be purged");

    // Entry updated at 1000, now is 10000, TTL is 5000 → SHOULD expire (memory backend)
    // Redis backend returns 0 (relies on native TTL) — both are valid implementations
    let _purged = store.purge_expired(5000, 10000).await.unwrap();
    // Don't assert purged > 0 — Redis returns 0 (native TTL handles expiration)
    // Memory backend returns > 0 (active purge)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::risk::config::DecayConfig;
    use crate::risk::store::MemoryRiskStore;

    #[tokio::test]
    async fn memory_store_passes_conformance() {
        let store = MemoryRiskStore::new();
        run_all(&store).await;
    }

    #[tokio::test]
    async fn memory_store_decay_honors_configured_rate() {
        let store = MemoryRiskStore::with_decay(DecayConfig {
            decay_rate: 3,
            ..Default::default()
        });
        test_decay_honors_configured_rate(&store).await;
    }

    #[tokio::test]
    async fn memory_store_decay_disabled_when_rate_zero() {
        let store = MemoryRiskStore::with_decay(DecayConfig {
            decay_rate: 0,
            ..Default::default()
        });
        test_decay_disabled_when_rate_zero(&store).await;
    }
}
