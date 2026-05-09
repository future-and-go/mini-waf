//! FR-025 — RiskKey collision/merge coverage.
//!
//! Verifies that triple-index `MemoryRiskStore` blends max(score) across
//! axes and unifies state on subsequent applies.

use std::net::{IpAddr, Ipv4Addr};

use waf_engine::risk::MemoryRiskStore;
use waf_engine::risk::key::{RiskKey, SessionId};
use waf_engine::risk::state::{Contributor, ContributorKind, SeedKind};
use waf_engine::risk::store::RiskStore;

fn delta(d: i16) -> Contributor {
    Contributor::new(ContributorKind::Seed(SeedKind::Generic), d, 1000)
}

#[tokio::test]
async fn fp_only_then_session_only_merges_to_max() {
    let s = MemoryRiskStore::new();
    let key_fp = RiskKey {
        ip: None,
        fp_hash: Some(42),
        session: None,
    };
    let key_sess = RiskKey {
        ip: None,
        fp_hash: None,
        session: Some(SessionId::new(b"sess1".to_vec())),
    };
    s.apply(&key_fp, &[delta(50)], 1000).await.unwrap();
    s.apply(&key_sess, &[delta(20)], 1000).await.unwrap();

    let merged = RiskKey {
        ip: None,
        fp_hash: Some(42),
        session: Some(SessionId::new(b"sess1".to_vec())),
    };
    let state = s.read(&merged).await.unwrap().unwrap();
    assert_eq!(state.clamped_score, 50);
}

#[tokio::test]
async fn ip_fp_session_blend_takes_max() {
    let s = MemoryRiskStore::new();
    let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));

    let k_ip = RiskKey::from_ip(ip);
    let k_fp = RiskKey {
        ip: None,
        fp_hash: Some(0xAB),
        session: None,
    };
    let k_sess = RiskKey {
        ip: None,
        fp_hash: None,
        session: Some(SessionId::new(b"X".to_vec())),
    };

    s.apply(&k_ip, &[delta(15)], 1000).await.unwrap();
    s.apply(&k_fp, &[delta(70)], 1000).await.unwrap();
    s.apply(&k_sess, &[delta(45)], 1000).await.unwrap();

    let combined = RiskKey {
        ip: Some(ip),
        fp_hash: Some(0xAB),
        session: Some(SessionId::new(b"X".to_vec())),
    };
    let state = s.read(&combined).await.unwrap().unwrap();
    assert_eq!(state.clamped_score, 70, "max across all axes");
}

#[tokio::test]
async fn apply_with_combined_key_unifies_indices() {
    let s = MemoryRiskStore::new();
    let ip = IpAddr::V4(Ipv4Addr::new(10, 9, 9, 9));
    let k_ip = RiskKey::from_ip(ip);
    let k_fp = RiskKey {
        ip: None,
        fp_hash: Some(0xC0DE),
        session: None,
    };

    s.apply(&k_ip, &[delta(40)], 1000).await.unwrap();
    s.apply(&k_fp, &[delta(20)], 1000).await.unwrap();

    let combined = RiskKey {
        ip: Some(ip),
        fp_hash: Some(0xC0DE),
        session: None,
    };
    let r = s.apply(&combined, &[delta(10)], 2000).await.unwrap();
    assert!(!r.is_new);
    assert_eq!(r.state.clamped_score, 50);

    // Both axes should now resolve to the same state.
    let via_ip = s.read(&k_ip).await.unwrap().unwrap();
    let via_fp = s.read(&k_fp).await.unwrap().unwrap();
    assert_eq!(via_ip.clamped_score, via_fp.clamped_score);
}

#[tokio::test]
async fn empty_key_apply_returns_synthetic_new() {
    let s = MemoryRiskStore::new();
    let k = RiskKey::default();
    let r = s.apply(&k, &[delta(50)], 1000).await.unwrap();
    assert!(r.is_new);
    assert_eq!(r.state.clamped_score, 0, "no-op for empty key");
}

#[tokio::test]
async fn force_max_no_op_for_empty_key() {
    let s = MemoryRiskStore::new();
    s.force_max(&RiskKey::default(), 5000, 1000).await.unwrap();
    assert!(s.is_empty().await);
}

#[tokio::test]
async fn ip_collision_apply_progresses_score() {
    let s = MemoryRiskStore::new();
    let key = RiskKey::from_ip(IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1)));
    s.apply(&key, &[delta(20)], 1000).await.unwrap();
    s.apply(&key, &[delta(10)], 2000).await.unwrap();
    let r = s.apply(&key, &[delta(5)], 3000).await.unwrap();
    assert!(!r.is_new);
    assert_eq!(r.state.clamped_score, 35);
}
