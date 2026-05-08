//! FR-025 store conformance suite.
//!
//! Shared test cases that any `RiskStore` implementation must pass.
//! Memory backend tests call this; Redis backend (P7) will reuse.

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

async fn test_purge_expired<S: RiskStore>(store: &S) {
    store.reset_all().await.unwrap();

    let key = RiskKey::from_ip(IpAddr::V4(Ipv4Addr::new(10, 6, 6, 6)));
    store.apply(&key, &[make_contributor(25, 1000)], 1000).await.unwrap();

    // Entry updated at 1000, now is 2000, TTL is 5000 → should NOT expire
    let purged = store.purge_expired(5000, 2000).await.unwrap();
    assert_eq!(purged, 0, "entry within TTL should not be purged");

    // Entry updated at 1000, now is 10000, TTL is 5000 → SHOULD expire
    let purged = store.purge_expired(5000, 10000).await.unwrap();
    assert!(purged > 0, "entry past TTL should be purged");
    assert!(
        store.read(&key).await.unwrap().is_none(),
        "purged entry should not be readable"
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::risk::store::MemoryRiskStore;

    #[tokio::test]
    async fn memory_store_passes_conformance() {
        let store = MemoryRiskStore::new();
        run_all(&store).await;
    }
}
