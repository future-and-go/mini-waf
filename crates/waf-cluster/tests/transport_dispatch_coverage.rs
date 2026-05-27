//! Exhaustive dispatch coverage for all 13 `ClusterMessage` variants.
//!
//! Tests verify serialize → deserialize round-trip and that both server and
//! client dispatch handle every variant without panicking.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::default_trait_access)]

use std::collections::HashMap;
use std::sync::Arc;

use waf_cluster::protocol::*;
use waf_cluster::transport::frame;

fn make_heartbeat() -> ClusterMessage {
    ClusterMessage::Heartbeat(Heartbeat {
        sequence: 1,
        timestamp_ms: 1000,
        node_id: "n1".to_string(),
        role: waf_common::config::NodeRole::Worker,
        uptime_secs: 60,
        cpu_percent: 12.5,
        memory_used_bytes: 1024,
        total_requests: 100,
        blocked_requests: 5,
        rules_version: 1,
        config_version: 1,
    })
}

fn make_election_vote() -> ClusterMessage {
    ClusterMessage::ElectionVote(ElectionVote {
        term: 1,
        candidate_id: "n1".to_string(),
        last_log_index: 0,
        voter_id: None,
    })
}

fn make_election_result() -> ClusterMessage {
    ClusterMessage::ElectionResult(ElectionResult {
        term: 1,
        elected_id: "n1".to_string(),
        voter_ids: vec!["n2".to_string()],
    })
}

fn make_join_request() -> ClusterMessage {
    ClusterMessage::JoinRequest(JoinRequest {
        token: "test-token".to_string(),
        csr_pem: "test-csr".to_string(),
        node_info: NodeInfo {
            node_id: "n2".to_string(),
            hostname: "host2".to_string(),
            version: "1.0.0".to_string(),
            listen_addr: "127.0.0.1:9001".to_string(),
            capabilities: vec!["waf".to_string()],
        },
    })
}

fn make_join_response() -> ClusterMessage {
    ClusterMessage::JoinResponse(JoinResponse {
        accepted: true,
        reason: None,
        node_cert_pem: String::new(),
        ca_cert_pem: String::new(),
        cluster_state: ClusterState {
            main_node_id: "n1".to_string(),
            nodes: Vec::new(),
            rules_version: 1,
            config_version: 1,
            term: 1,
        },
        encrypted_ca_key_b64: None,
    })
}

fn make_node_leave() -> ClusterMessage {
    ClusterMessage::NodeLeave {
        node_id: "n2".to_string(),
    }
}

const fn make_rule_sync_request() -> ClusterMessage {
    ClusterMessage::RuleSyncRequest(RuleSyncRequest { current_version: 0 })
}

const fn make_rule_sync_response() -> ClusterMessage {
    ClusterMessage::RuleSyncResponse(RuleSyncResponse {
        version: 1,
        sync_type: SyncType::Incremental,
        changes: Vec::new(),
        snapshot_lz4: Vec::new(),
    })
}

fn make_config_sync() -> ClusterMessage {
    ClusterMessage::ConfigSync(ConfigSync {
        version: 1,
        config_toml: "[cluster]\nnode_id = \"test\"".to_string(),
    })
}

fn make_event_batch() -> ClusterMessage {
    ClusterMessage::EventBatch(EventBatch {
        node_id: "n2".to_string(),
        events: vec![SecurityEvent {
            timestamp_ms: 1000,
            client_ip: "10.0.0.1".to_string(),
            method: "GET".to_string(),
            path: "/test".to_string(),
            host: "example.com".to_string(),
            rule_id: Some("r1".to_string()),
            action: "block".to_string(),
            geo_country: "US".to_string(),
            node_id: "n2".to_string(),
        }],
    })
}

fn make_stats_batch() -> ClusterMessage {
    ClusterMessage::StatsBatch(StatsBatch {
        node_id: "n2".to_string(),
        timestamp_ms: 1000,
        total_requests: 100,
        blocked_requests: 5,
        allowed_requests: 95,
        top_ips: HashMap::new(),
        top_rules: HashMap::new(),
        top_countries: HashMap::new(),
    })
}

fn make_api_forward() -> ClusterMessage {
    ClusterMessage::ApiForward(ApiForward {
        request_id: "req-001".to_string(),
        method: "POST".to_string(),
        path: "/api/rules".to_string(),
        body: b"{}".to_vec(),
        headers: HashMap::new(),
    })
}

fn make_api_forward_response() -> ClusterMessage {
    ClusterMessage::ApiForwardResponse(ApiForwardResponse {
        request_id: "req-001".to_string(),
        status: 200,
        body: b"ok".to_vec(),
    })
}

fn all_variants() -> Vec<(&'static str, ClusterMessage)> {
    vec![
        ("Heartbeat", make_heartbeat()),
        ("ElectionVote", make_election_vote()),
        ("ElectionResult", make_election_result()),
        ("JoinRequest", make_join_request()),
        ("JoinResponse", make_join_response()),
        ("NodeLeave", make_node_leave()),
        ("RuleSyncRequest", make_rule_sync_request()),
        ("RuleSyncResponse", make_rule_sync_response()),
        ("ConfigSync", make_config_sync()),
        ("EventBatch", make_event_batch()),
        ("StatsBatch", make_stats_batch()),
        ("ApiForward", make_api_forward()),
        ("ApiForwardResponse", make_api_forward_response()),
    ]
}

// ── Serde round-trip tests ───────────────────────────────────────────────────

#[tokio::test]
async fn serde_round_trip_all_variants() {
    for (name, msg) in all_variants() {
        let json = serde_json::to_vec(&msg).unwrap_or_else(|e| panic!("{name}: serialize failed: {e}"));
        let decoded: ClusterMessage =
            serde_json::from_slice(&json).unwrap_or_else(|e| panic!("{name}: deserialize failed: {e}"));
        let re_json = serde_json::to_vec(&decoded).unwrap_or_else(|e| panic!("{name}: re-serialize failed: {e}"));
        assert_eq!(json, re_json, "{name}: round-trip mismatch");
    }
}

#[tokio::test]
async fn frame_round_trip_all_variants() {
    for (name, msg) in all_variants() {
        let mut buf = Vec::new();
        frame::write_frame(&mut buf, &msg)
            .await
            .unwrap_or_else(|e| panic!("{name}: write_frame failed: {e}"));
        let decoded: ClusterMessage = frame::read_frame(&mut buf.as_slice())
            .await
            .unwrap_or_else(|e| panic!("{name}: read_frame failed: {e}"));
        let orig_json = serde_json::to_value(&msg).unwrap();
        let decoded_json = serde_json::to_value(&decoded).unwrap();
        assert_eq!(orig_json, decoded_json, "{name}: frame round-trip mismatch");
    }
}

// ── Server dispatch tests ────────────────────────────────────────────────────

mod server_dispatch {
    use super::*;
    use waf_cluster::node::{NodeState, PeerInfo, StorageMode};

    fn test_node_state() -> Arc<NodeState> {
        use waf_common::config::{ClusterConfig, ClusterElectionConfig};
        let config = ClusterConfig {
            node_id: "main-1".to_string(),
            role: "main".to_string(),
            election: ClusterElectionConfig {
                timeout_min_ms: 150,
                timeout_max_ms: 300,
                phi_suspect: 5.0,
                phi_dead: 8.0,
                ..Default::default()
            },
            ..Default::default()
        };
        Arc::new(NodeState::new(config, StorageMode::Full).unwrap())
    }

    #[tokio::test]
    async fn heartbeat_registers_peer() {
        let state = test_node_state();
        let msg = make_heartbeat();
        let resp = waf_cluster::transport::server::dispatch_message(msg, &state).await;
        assert!(resp.is_none());
        assert_eq!(state.total_nodes().await, 2);
    }

    #[tokio::test]
    async fn join_request_returns_join_response() {
        let state = test_node_state();
        let msg = make_join_request();
        let resp = waf_cluster::transport::server::dispatch_message(msg, &state).await;
        assert!(matches!(resp, Some(ClusterMessage::JoinResponse(_))));
    }

    #[tokio::test]
    async fn join_response_ignored_on_server() {
        let state = test_node_state();
        let msg = make_join_response();
        let resp = waf_cluster::transport::server::dispatch_message(msg, &state).await;
        assert!(resp.is_none());
    }

    #[tokio::test]
    async fn election_vote_request_grants() {
        let state = test_node_state();
        let msg = make_election_vote();
        let resp = waf_cluster::transport::server::dispatch_message(msg, &state).await;
        assert!(matches!(resp, Some(ClusterMessage::ElectionVote(_))));
    }

    #[tokio::test]
    async fn election_result_processed() {
        let state = test_node_state();
        let msg = make_election_result();
        let resp = waf_cluster::transport::server::dispatch_message(msg, &state).await;
        assert!(resp.is_none());
    }

    #[tokio::test]
    async fn node_leave_removes_peer() {
        let state = test_node_state();
        state
            .add_or_update_peer(PeerInfo {
                node_id: "n2".to_string(),
                addr: "127.0.0.1:9001".parse().unwrap(),
                role: waf_common::config::NodeRole::Worker,
                last_seen_ms: 1000,
            })
            .await;
        assert_eq!(state.total_nodes().await, 2);

        let msg = make_node_leave();
        let resp = waf_cluster::transport::server::dispatch_message(msg, &state).await;
        assert!(resp.is_none());
        assert_eq!(state.total_nodes().await, 1);
    }

    #[tokio::test]
    async fn rule_sync_request_returns_response() {
        let state = test_node_state();
        let msg = make_rule_sync_request();
        let resp = waf_cluster::transport::server::dispatch_message(msg, &state).await;
        assert!(matches!(resp, Some(ClusterMessage::RuleSyncResponse(_))));
    }

    #[tokio::test]
    async fn rule_sync_response_ignored_on_server() {
        let state = test_node_state();
        let msg = make_rule_sync_response();
        let resp = waf_cluster::transport::server::dispatch_message(msg, &state).await;
        assert!(resp.is_none());
    }

    #[tokio::test]
    async fn config_sync_handled() {
        let state = test_node_state();
        let msg = make_config_sync();
        let resp = waf_cluster::transport::server::dispatch_message(msg, &state).await;
        assert!(resp.is_none());
    }

    #[tokio::test]
    async fn event_batch_handled() {
        let state = test_node_state();
        let msg = make_event_batch();
        let resp = waf_cluster::transport::server::dispatch_message(msg, &state).await;
        assert!(resp.is_none());
    }

    #[tokio::test]
    async fn stats_batch_handled() {
        let state = test_node_state();
        let msg = make_stats_batch();
        let resp = waf_cluster::transport::server::dispatch_message(msg, &state).await;
        assert!(resp.is_none());
    }

    #[tokio::test]
    async fn api_forward_returns_response() {
        let state = test_node_state();
        let msg = make_api_forward();
        let resp = waf_cluster::transport::server::dispatch_message(msg, &state).await;
        match resp {
            Some(ClusterMessage::ApiForwardResponse(r)) => {
                assert_eq!(r.request_id, "req-001");
                // Returns 502 when no local API server is running (replay fails)
                assert!(r.status == 502 || r.status == 413);
            }
            other => panic!("expected ApiForwardResponse, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn api_forward_response_ignored_on_server() {
        let state = test_node_state();
        let msg = make_api_forward_response();
        let resp = waf_cluster::transport::server::dispatch_message(msg, &state).await;
        assert!(resp.is_none());
    }
}

// ── Client dispatch tests ────────────────────────────────────────────────────

mod client_dispatch {
    use super::*;
    use waf_cluster::node::{NodeState, PeerInfo, StorageMode};

    fn test_node_state() -> Arc<NodeState> {
        use waf_common::config::{ClusterConfig, ClusterElectionConfig};
        let config = ClusterConfig {
            node_id: "worker-1".to_string(),
            role: "worker".to_string(),
            election: ClusterElectionConfig {
                timeout_min_ms: 150,
                timeout_max_ms: 300,
                phi_suspect: 5.0,
                phi_dead: 8.0,
                ..Default::default()
            },
            ..Default::default()
        };
        Arc::new(NodeState::new(config, StorageMode::ForwardOnly).unwrap())
    }

    #[tokio::test]
    async fn heartbeat_registers_peer() {
        let state = test_node_state();
        let msg = make_heartbeat();
        waf_cluster::transport::client::dispatch_incoming(msg, &state).await;
        assert_eq!(state.total_nodes().await, 2);
    }

    #[tokio::test]
    async fn join_response_accepted() {
        let state = test_node_state();
        let msg = make_join_response();
        waf_cluster::transport::client::dispatch_incoming(msg, &state).await;
    }

    #[tokio::test]
    async fn join_request_ignored_on_client() {
        let state = test_node_state();
        let msg = make_join_request();
        waf_cluster::transport::client::dispatch_incoming(msg, &state).await;
    }

    #[tokio::test]
    async fn election_vote_grant() {
        let state = test_node_state();
        let msg = ClusterMessage::ElectionVote(ElectionVote {
            term: 1,
            candidate_id: "worker-1".to_string(),
            last_log_index: 0,
            voter_id: Some("n2".to_string()),
        });
        waf_cluster::transport::client::dispatch_incoming(msg, &state).await;
    }

    #[tokio::test]
    async fn election_result_processed() {
        let state = test_node_state();
        let msg = make_election_result();
        waf_cluster::transport::client::dispatch_incoming(msg, &state).await;
    }

    #[tokio::test]
    async fn node_leave_removes_peer() {
        let state = test_node_state();
        state
            .add_or_update_peer(PeerInfo {
                node_id: "n2".to_string(),
                addr: "127.0.0.1:9001".parse().unwrap(),
                role: waf_common::config::NodeRole::Worker,
                last_seen_ms: 1000,
            })
            .await;
        assert_eq!(state.total_nodes().await, 2);

        let msg = make_node_leave();
        waf_cluster::transport::client::dispatch_incoming(msg, &state).await;
        assert_eq!(state.total_nodes().await, 1);
    }

    #[tokio::test]
    async fn rule_sync_request_ignored_on_client() {
        let state = test_node_state();
        let msg = make_rule_sync_request();
        waf_cluster::transport::client::dispatch_incoming(msg, &state).await;
    }

    #[tokio::test]
    async fn rule_sync_response_handled() {
        let state = test_node_state();
        let msg = make_rule_sync_response();
        waf_cluster::transport::client::dispatch_incoming(msg, &state).await;
    }

    #[tokio::test]
    async fn config_sync_handled() {
        let state = test_node_state();
        let msg = make_config_sync();
        waf_cluster::transport::client::dispatch_incoming(msg, &state).await;
    }

    #[tokio::test]
    async fn event_batch_warns_on_client() {
        let state = test_node_state();
        let msg = make_event_batch();
        waf_cluster::transport::client::dispatch_incoming(msg, &state).await;
    }

    #[tokio::test]
    async fn stats_batch_warns_on_client() {
        let state = test_node_state();
        let msg = make_stats_batch();
        waf_cluster::transport::client::dispatch_incoming(msg, &state).await;
    }

    #[tokio::test]
    async fn api_forward_ignored_on_client() {
        let state = test_node_state();
        let msg = make_api_forward();
        waf_cluster::transport::client::dispatch_incoming(msg, &state).await;
    }

    #[tokio::test]
    async fn api_forward_response_handled() {
        let state = test_node_state();
        let msg = make_api_forward_response();
        waf_cluster::transport::client::dispatch_incoming(msg, &state).await;
    }
}
