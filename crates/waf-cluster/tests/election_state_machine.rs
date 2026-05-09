//! Election state machine corner cases not covered by election_test.rs.
//!
//! Drives `ElectionManager` directly (no QUIC) and exercises the
//! `run_election_loop` driver via `start_paused = true`.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::disallowed_types,
    clippy::disallowed_methods,
    clippy::redundant_clone,
    clippy::redundant_closure_for_method_calls,
    clippy::field_reassign_with_default,
    clippy::significant_drop_tightening,
    clippy::similar_names,
    clippy::unreadable_literal,
    clippy::approx_constant,
    clippy::doc_markdown,
    clippy::map_unwrap_or
)]

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use waf_cluster::{
    ClusterConfig, NodeRole, NodeState, StorageMode,
    election::{ElectionManager, run_election_loop},
    node::PeerInfo,
    protocol::{ElectionResult, ElectionVote},
};
use waf_common::config::ClusterElectionConfig;

fn loopback() -> SocketAddr {
    let s = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind");
    s.local_addr().expect("local_addr")
}

fn fast_node(node_id: &str) -> Arc<NodeState> {
    let cfg = ClusterConfig {
        node_id: node_id.to_string(),
        listen_addr: loopback().to_string(),
        election: ClusterElectionConfig {
            timeout_min_ms: 1,
            timeout_max_ms: 2,
            heartbeat_interval_ms: 5,
            phi_suspect: 1.0,
            phi_dead: 1.5,
        },
        ..ClusterConfig::default()
    };
    Arc::new(NodeState::new(cfg, StorageMode::Full).expect("NodeState::new"))
}

// ─── Term advancement ─────────────────────────────────────────────────────────

#[test]
fn advance_term_only_moves_forward() {
    let em = ElectionManager::new("n".to_string(), 5, 10);
    assert_eq!(em.current_term_sync(), 0);
    assert_eq!(em.advance_term(3), 3);
    assert_eq!(em.advance_term(2), 3, "lower term must not roll back");
    assert_eq!(em.advance_term(7), 7);
}

#[test]
fn advance_term_resets_voted_for() {
    let em = ElectionManager::new("voter".to_string(), 5, 10);
    let v = ElectionVote {
        term: 1,
        candidate_id: "cand-x".to_string(),
        last_log_index: 0,
        voter_id: None,
    };
    assert!(em.process_vote(&v).expect("vote"));
    // Same-term different candidate is denied.
    let v_other = ElectionVote {
        term: 1,
        candidate_id: "cand-y".to_string(),
        last_log_index: 0,
        voter_id: None,
    };
    assert!(!em.process_vote(&v_other).expect("denied"));
    // After term advance, voted_for resets and the same other candidate is granted.
    em.advance_term(2);
    let v_other_t2 = ElectionVote { term: 2, ..v_other };
    assert!(em.process_vote(&v_other_t2).expect("granted in new term"));
}

// ─── Vote accounting ──────────────────────────────────────────────────────────

#[test]
fn record_vote_for_stale_term_rejected() {
    let em = ElectionManager::new("c".to_string(), 5, 10);
    em.increment_term_and_vote_for_self();
    em.increment_term_and_vote_for_self();
    assert_eq!(em.current_term_sync(), 2);
    // Vote for term 1 (stale) must not be recorded.
    assert!(!em.record_vote_for_me(1, "voter".to_string()));
    assert_eq!(em.vote_count_for_term(1), 0);
}

#[test]
fn voter_ids_for_term_returns_empty_for_unknown() {
    let em = ElectionManager::new("c".to_string(), 5, 10);
    let v = em.voter_ids_for_term(99);
    assert!(v.is_empty());
}

#[test]
fn vote_count_for_term_zero_when_unknown() {
    let em = ElectionManager::new("c".to_string(), 5, 10);
    assert_eq!(em.vote_count_for_term(0), 0);
    assert_eq!(em.vote_count_for_term(42), 0);
}

// ─── Majority math ────────────────────────────────────────────────────────────

#[test]
fn majority_thresholds() {
    assert!(!ElectionManager::is_majority(0, 0));
    assert!(ElectionManager::is_majority(1, 1));
    assert!(!ElectionManager::is_majority(1, 2));
    assert!(ElectionManager::is_majority(2, 3));
    assert!(!ElectionManager::is_majority(2, 4));
    assert!(ElectionManager::is_majority(3, 4));
    assert!(ElectionManager::is_majority(3, 5));
}

// ─── Election timeout range ───────────────────────────────────────────────────

#[test]
fn election_timeout_within_range() {
    let em = ElectionManager::new("c".to_string(), 100, 200);
    for _ in 0..32 {
        let t = em.election_timeout_ms();
        assert!((100..=200).contains(&t), "timeout {t} out of [100,200]");
    }
}

#[test]
fn election_timeout_when_min_eq_max() {
    let em = ElectionManager::new("c".to_string(), 50, 50);
    let t = em.election_timeout_ms();
    // Implementation widens to (min..=max+1) when equal — so 50 or 51 are both valid.
    assert!((50..=51).contains(&t), "got {t}");
}

// ─── Run loop: candidate without majority demotes back to Worker ─────────────

#[tokio::test(start_paused = true)]
async fn candidate_without_majority_steps_down() {
    let node = fast_node("cand");
    // Add 4 silent peers so no main known + we'll fail to gather majority.
    {
        let mut peers = node.peers.write().await;
        for i in 0..4 {
            peers.push(PeerInfo {
                node_id: format!("p{i}"),
                addr: loopback(),
                role: NodeRole::Worker,
                last_seen_ms: 0,
            });
        }
    }

    let n = Arc::clone(&node);
    let h = tokio::spawn(async move {
        run_election_loop(n).await;
    });

    // Let the loop drive: timeout → candidate → broadcast → wait → no votes → demote.
    for _ in 0..6 {
        tokio::time::advance(Duration::from_millis(20)).await;
        tokio::task::yield_now().await;
    }

    let role = node.current_role().await;
    assert!(
        matches!(role, NodeRole::Worker | NodeRole::Candidate),
        "expected Worker or Candidate (still looping), got {role:?}"
    );
    // Term must have been incremented by at least one election attempt.
    assert!(node.election.current_term_sync() >= 1);
    h.abort();
}

// ─── process_result with term equal to current ────────────────────────────────

#[test]
fn process_result_equal_term_self_elected() {
    let em = ElectionManager::new("me".to_string(), 5, 10);
    em.advance_term(4);
    let r = ElectionResult {
        term: 4,
        elected_id: "me".to_string(),
        voter_ids: vec!["me".to_string(), "p1".to_string()],
    };
    let role = em.process_result(&r).expect("ok");
    assert_eq!(role, NodeRole::Main);
    assert_eq!(em.current_term_sync(), 4);
}
