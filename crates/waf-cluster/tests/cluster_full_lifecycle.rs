//! Full cluster lifecycle integration tests.
//!
//! Exercises join, rule sync, event aggregation, config sync, and election
//! in-process using real `NodeState` instances (no mocks for core logic).
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
    clippy::missing_const_for_fn,
    clippy::items_after_statements,
    clippy::format_push_string,
    clippy::err_expect,
    clippy::needless_pass_by_value,
    clippy::needless_raw_string_hashes,
    clippy::default_trait_access,
    clippy::await_holding_lock,
    unused_imports
)]

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::mpsc;

use waf_cluster::election::ElectionManager;
use waf_cluster::node::{NodeState, PeerInfo, StorageMode};
use waf_cluster::protocol::{
    ChangeOp, ClusterMessage, ConfigSync, ElectionResult, EventBatch, Heartbeat, JoinRequest, JoinResponse, NodeInfo,
    RuleSyncRequest, SecurityEvent, SyncType,
};
use waf_cluster::sync::config::{ConfigSyncer, SyncableConfig};
use waf_cluster::sync::events::EventBatcher;
use waf_cluster::sync::rules::{NoopReloader, RuleChangelog, apply_sync_response, handle_sync_request};
use waf_cluster::transport::client::ClusterClient;
use waf_cluster::transport::server::ClusterServer;
use waf_cluster::{ClusterConfig, NodeRole};
use waf_common::config::ClusterElectionConfig;
use waf_engine::{Rule, RuleRegistry};

fn install_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

fn random_loopback_addr() -> SocketAddr {
    let sock = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind UDP");
    sock.local_addr().expect("local_addr")
}

fn test_config(node_id: &str, role: &str) -> ClusterConfig {
    ClusterConfig {
        node_id: node_id.to_string(),
        role: role.to_string(),
        election: ClusterElectionConfig {
            timeout_min_ms: 150,
            timeout_max_ms: 300,
            phi_suspect: 5.0,
            phi_dead: 8.0,
            ..Default::default()
        },
        ..Default::default()
    }
}

fn sample_rule(id: &str) -> Rule {
    Rule {
        id: id.to_string(),
        name: format!("Rule {id}"),
        description: None,
        category: "test".to_string(),
        source: "test".to_string(),
        enabled: true,
        action: "block".to_string(),
        severity: Some("high".to_string()),
        pattern: Some(format!("pattern-{id}")),
        tags: vec![],
        metadata: HashMap::new(),
        risk_delta: None,
        risk_action: None,
    }
}

fn sample_event(id: u64, node_id: &str) -> SecurityEvent {
    SecurityEvent {
        timestamp_ms: 1_700_000_000_000 + id,
        client_ip: format!("10.0.0.{}", id % 256),
        method: "GET".into(),
        path: "/attack".into(),
        host: "target.example.com".into(),
        rule_id: Some(format!("r{id}")),
        action: "block".into(),
        geo_country: "US".into(),
        node_id: node_id.into(),
    }
}

fn make_node(node_id: &str, role: &str) -> Arc<NodeState> {
    let cfg = test_config(node_id, role);
    Arc::new(NodeState::new(cfg, StorageMode::Full).expect("NodeState::new"))
}

// ─── Test 1: Node join flow ──────────────────────────────────────────────────

#[tokio::test]
async fn node_join_flow_via_quic_transport() {
    install_crypto_provider();

    let server_addr = random_loopback_addr();
    let client_addr = random_loopback_addr();

    let ca = waf_cluster::crypto::ca::CertificateAuthority::generate(365).expect("CA");
    let ca_cert_der = ca.cert_der().expect("CA DER");

    let server_cert =
        waf_cluster::crypto::node_cert::NodeCertificate::generate("main-node", &ca, 1).expect("server cert");
    let client_cert =
        waf_cluster::crypto::node_cert::NodeCertificate::generate("worker-node", &ca, 1).expect("client cert");

    let server_state = make_node("main-node", "main");
    server_state
        .add_or_update_peer(PeerInfo {
            node_id: "worker-node".to_string(),
            addr: client_addr,
            role: NodeRole::Worker,
            last_seen_ms: 0,
        })
        .await;

    let server = ClusterServer::new(
        server_addr,
        ca_cert_der.clone(),
        server_cert.cert_pem.clone(),
        server_cert.key_pem.clone(),
    );

    let server_state_srv = Arc::clone(&server_state);
    tokio::spawn(async move {
        let _ = server.serve(server_state_srv).await;
    });
    tokio::time::sleep(Duration::from_millis(50)).await;

    let (_tx, rx) = mpsc::channel::<ClusterMessage>(16);
    let client = ClusterClient::new(
        server_addr,
        "worker-node".to_string(),
        ca_cert_der,
        client_cert.cert_pem,
        client_cert.key_pem,
    );

    let client_state = make_node("worker-node", "worker");
    let client_state_task = Arc::clone(&client_state);
    tokio::spawn(async move {
        let _ = client.run_with_reconnect(client_state_task, rx).await;
    });

    tokio::time::sleep(Duration::from_millis(200)).await;

    // Verify: main's peer list includes the worker
    let peers = server_state.peers.read().await;
    assert!(
        peers.iter().any(|p| p.node_id == "worker-node"),
        "main's peer list must include worker after join"
    );
    assert_eq!(server_state.total_nodes().await, 2);
}

// ─── Test 2: Rule sync propagation ──────────────────────────────────────────

#[tokio::test]
async fn rule_sync_propagation_full_then_incremental() {
    let main = make_node("main-1", "main");
    let rules: Vec<Rule> = (1..=3).map(|i| sample_rule(&format!("rule-{i}"))).collect();

    // Record 3 rule changes on main
    {
        let mut changelog = main.rule_changelog.write();
        for r in &rules {
            changelog.record_change(ChangeOp::Upsert, r.id.clone(), Some(r));
        }
    }
    {
        let mut registry = main.rule_registry.write();
        for r in &rules {
            registry.insert(r.clone());
        }
    }

    // Worker at version 0 → expects full snapshot
    let request_v0 = RuleSyncRequest { current_version: 0 };
    let changelog = main.rule_changelog.read();
    let all_rules: Vec<Rule> = main.rule_registry.read().rules.values().cloned().collect();
    let resp_full = handle_sync_request(&changelog, &request_v0, &all_rules).unwrap();
    drop(changelog);
    assert!(matches!(resp_full.sync_type, SyncType::Full));

    let mut worker_registry = RuleRegistry::default();
    let reloader = NoopReloader;
    apply_sync_response(resp_full, &mut worker_registry, &reloader)
        .await
        .unwrap();
    assert_eq!(worker_registry.rules.len(), 3);
    assert_eq!(worker_registry.version, 3);

    // Add another rule on main
    let rule_4 = sample_rule("rule-4");
    {
        let mut changelog = main.rule_changelog.write();
        changelog.record_change(ChangeOp::Upsert, rule_4.id.clone(), Some(&rule_4));
    }
    main.rule_registry.write().insert(rule_4.clone());

    // Worker at version 3 → incremental with 1 change
    let request_v3 = RuleSyncRequest {
        current_version: worker_registry.version,
    };
    let changelog = main.rule_changelog.read();
    let all_rules: Vec<Rule> = main.rule_registry.read().rules.values().cloned().collect();
    let resp_incr = handle_sync_request(&changelog, &request_v3, &all_rules).unwrap();
    drop(changelog);
    assert!(matches!(resp_incr.sync_type, SyncType::Incremental));
    assert_eq!(resp_incr.changes.len(), 1);
    assert_eq!(resp_incr.changes[0].rule_id, "rule-4");

    apply_sync_response(resp_incr, &mut worker_registry, &reloader)
        .await
        .unwrap();
    assert_eq!(worker_registry.rules.len(), 4);
    assert_eq!(worker_registry.version, 4);

    // Verify version tracking on NodeState
    main.set_rules_version(4).await;
    let rv = *main.rules_version.read().await;
    assert_eq!(rv, 4);
}

// ─── Test 3: Event aggregation ───────────────────────────────────────────────

#[tokio::test]
async fn event_aggregation_worker_to_main() {
    let batcher = EventBatcher::new("worker-1".into(), 5, 60_000);
    let (event_tx, event_rx) = mpsc::channel::<SecurityEvent>(32);
    let (batch_tx, mut batch_rx) = mpsc::channel::<EventBatch>(16);

    tokio::spawn(async move {
        waf_cluster::sync::events::run_event_batcher(batcher, event_rx, batch_tx).await;
    });

    // Push 5 events (matches batch_size=5 → immediate flush)
    for i in 1..=5 {
        event_tx.send(sample_event(i, "worker-1")).await.expect("send event");
    }

    let batch = tokio::time::timeout(Duration::from_secs(5), batch_rx.recv())
        .await
        .expect("batch should arrive within timeout")
        .expect("channel not closed");

    assert_eq!(batch.events.len(), 5, "batch must contain all 5 events");
    assert_eq!(batch.node_id, "worker-1");

    // Verify each event has correct fields
    for (i, ev) in batch.events.iter().enumerate() {
        let expected_ip = format!("10.0.0.{}", (i + 1) % 256);
        assert_eq!(ev.client_ip, expected_ip);
        assert_eq!(ev.action, "block");
    }

    // Push 3 more and close to verify partial flush
    for i in 6..=8 {
        event_tx.send(sample_event(i, "worker-1")).await.unwrap();
    }
    drop(event_tx);

    let partial = tokio::time::timeout(Duration::from_secs(5), batch_rx.recv())
        .await
        .expect("partial batch should flush on close")
        .expect("channel not closed");
    assert_eq!(partial.events.len(), 3);
}

// ─── Test 4: Config sync ─────────────────────────────────────────────────────

#[tokio::test]
async fn config_sync_version_gating() {
    let mut main_syncer = ConfigSyncer::new("main-1".into());
    let mut worker_syncer = ConfigSyncer::new("worker-1".into());

    let config = SyncableConfig {
        proxy: waf_common::config::ProxyConfig {
            listen_addr: "0.0.0.0:8080".into(),
            ..Default::default()
        },
        rules: Default::default(),
        cache: Default::default(),
        api: waf_common::config::ApiConfig {
            listen_addr: "0.0.0.0:9527".into(),
        },
    };

    // Build first sync on main — version uses a monotonic timestamp, so it is
    // always > 0 but the exact value is not predictable.
    let msg_v1 = main_syncer.build_sync(&config).unwrap();
    assert!(msg_v1.version > 0, "first version must be positive");

    // Worker applies the first version
    let applied = worker_syncer.apply_sync(&msg_v1, 1);
    assert!(applied.is_some());
    assert_eq!(worker_syncer.current_version(), msg_v1.version);

    // Duplicate is skipped (same version)
    let skipped = worker_syncer.apply_sync(&msg_v1, 1);
    assert!(skipped.is_none());

    // Build second sync — version must strictly advance
    let msg_v2 = main_syncer.build_sync(&config).unwrap();
    assert!(msg_v2.version > msg_v1.version, "second version must exceed first");

    // Worker applies the second version
    let applied_v2 = worker_syncer.apply_sync(&msg_v2, 1);
    assert!(applied_v2.is_some());
    assert_eq!(worker_syncer.current_version(), msg_v2.version);

    // Config version tracking on NodeState
    let node = make_node("main-1", "main");
    node.set_config_version(msg_v2.version).await;
    let cv = *node.config_version.read().await;
    assert_eq!(cv, msg_v2.version);
}

// ─── Test 5: Election after main death ───────────────────────────────────────

#[tokio::test]
async fn election_after_main_death() {
    let worker_a = make_node("worker-a", "worker");
    let worker_b = make_node("worker-b", "worker");

    // Simulate 3-node cluster: main + worker_a + worker_b
    // Main "dies" — workers detect and run election
    worker_a
        .add_or_update_peer(PeerInfo {
            node_id: "worker-b".to_string(),
            addr: random_loopback_addr(),
            role: NodeRole::Worker,
            last_seen_ms: 0,
        })
        .await;
    worker_b
        .add_or_update_peer(PeerInfo {
            node_id: "worker-a".to_string(),
            addr: random_loopback_addr(),
            role: NodeRole::Worker,
            last_seen_ms: 0,
        })
        .await;

    // Worker-a starts election
    let term = worker_a.election.increment_term_and_vote_for_self();
    assert_eq!(term, 1);

    // Worker-b grants vote to worker-a
    let vote_req = waf_cluster::protocol::ElectionVote {
        term: 1,
        candidate_id: "worker-a".to_string(),
        last_log_index: 0,
        voter_id: None,
    };
    let granted = worker_b.election.process_vote(&vote_req).unwrap();
    assert!(granted, "worker-b should grant vote to worker-a");

    // Worker-a receives the vote
    worker_a.election.record_vote_for_me(1, "worker-b".to_string());

    // Check majority: 2 out of 2 (main is dead, not counted)
    let votes = worker_a.election.vote_count_for_term(1);
    let total = worker_a.total_nodes().await; // worker-a + worker-b = 2
    assert!(
        ElectionManager::is_majority(votes, total),
        "worker-a should have majority ({votes}/{total})"
    );

    // Worker-a wins → broadcasts ElectionResult
    let result = ElectionResult {
        term: 1,
        elected_id: "worker-a".to_string(),
        voter_ids: worker_a.election.voter_ids_for_term(1),
    };

    // Worker-a promotes itself
    worker_a.promote_to_main().await;
    assert_eq!(worker_a.current_role().await, NodeRole::Main);

    // Worker-b processes the result and stays Worker
    let role_b = worker_b.election.process_result(&result).unwrap();
    assert_eq!(role_b, NodeRole::Worker);

    // Verify term advanced
    let new_term = worker_a.election.current_term_sync();
    assert!(new_term >= 1, "term must be >= 1 after election");
}

// ─── Test 6: Write forwarding roundtrip ──────────────────────────────────────

#[tokio::test]
async fn write_forwarding_roundtrip() {
    use waf_cluster::cluster_forward::{PendingForwards, forward_write};
    use waf_cluster::protocol::ApiForwardResponse;

    let (tx, mut rx) = mpsc::channel::<ClusterMessage>(16);
    let pending = PendingForwards::new();

    let mut headers = HashMap::new();
    headers.insert("Content-Type".to_string(), "application/json".to_string());

    let pending_for_resolve = pending.clone();
    let handle = tokio::spawn(async move {
        forward_write(
            &tx,
            &pending_for_resolve,
            "lifecycle-req-1".to_string(),
            "POST".to_string(),
            "/api/custom-rules".to_string(),
            b"{\"name\":\"test\"}".to_vec(),
            headers,
            5_000, // 5s timeout — generous for test
        )
        .await
    });

    // Simulate main receiving and replying
    let msg = tokio::time::timeout(Duration::from_secs(3), rx.recv())
        .await
        .expect("should receive forwarded message")
        .expect("channel not closed");

    match msg {
        ClusterMessage::ApiForward(fwd) => {
            assert_eq!(fwd.request_id, "lifecycle-req-1");
            assert_eq!(fwd.method, "POST");
            assert_eq!(fwd.path, "/api/custom-rules");

            // Main processes and replies
            pending
                .resolve(ApiForwardResponse {
                    request_id: fwd.request_id,
                    status: 201,
                    body: b"{\"id\":\"new-rule\"}".to_vec(),
                })
                .await;
        }
        other => panic!("Expected ApiForward, got {other:?}"),
    }

    let result = handle.await.unwrap();
    assert!(result.is_ok(), "forward_write should succeed");
    let resp = result.unwrap();
    assert_eq!(resp.status, 201);
}

// ─── Test 7: Full lifecycle sequence ─────────────────────────────────────────

#[tokio::test]
async fn full_lifecycle_join_sync_events_config_election() {
    // Simulates the complete cluster lifecycle in-process:
    // 1. Main starts, worker joins
    // 2. Rules are synced from main to worker
    // 3. Worker pushes security events, main receives batch
    // 4. Config is synced from main to worker
    // 5. Main dies, worker wins election

    // ── Phase 1: Join ─────────────────────────────────────────────────────
    let main = make_node("lifecycle-main", "main");
    let worker = make_node("lifecycle-worker", "worker");

    main.add_or_update_peer(PeerInfo {
        node_id: "lifecycle-worker".to_string(),
        addr: random_loopback_addr(),
        role: NodeRole::Worker,
        last_seen_ms: 0,
    })
    .await;
    worker
        .add_or_update_peer(PeerInfo {
            node_id: "lifecycle-main".to_string(),
            addr: random_loopback_addr(),
            role: NodeRole::Main,
            last_seen_ms: 0,
        })
        .await;

    assert_eq!(main.total_nodes().await, 2);
    assert_eq!(worker.total_nodes().await, 2);

    // ── Phase 2: Rule sync ────────────────────────────────────────────────
    let rules: Vec<Rule> = (1..=3).map(|i| sample_rule(&format!("lc-rule-{i}"))).collect();
    {
        let mut changelog = main.rule_changelog.write();
        let mut registry = main.rule_registry.write();
        for r in &rules {
            changelog.record_change(ChangeOp::Upsert, r.id.clone(), Some(r));
            registry.insert(r.clone());
        }
    }

    let request = RuleSyncRequest { current_version: 0 };
    let changelog = main.rule_changelog.read();
    let all_rules: Vec<Rule> = main.rule_registry.read().rules.values().cloned().collect();
    let response = handle_sync_request(&changelog, &request, &all_rules).unwrap();
    drop(changelog);

    let mut worker_registry = RuleRegistry::default();
    apply_sync_response(response, &mut worker_registry, &NoopReloader)
        .await
        .unwrap();
    assert_eq!(worker_registry.rules.len(), 3);
    assert_eq!(worker_registry.version, 3);

    // ── Phase 3: Event aggregation ────────────────────────────────────────
    let batcher = EventBatcher::new("lifecycle-worker".into(), 3, 60_000);
    let (event_tx, event_rx) = mpsc::channel::<SecurityEvent>(16);
    let (batch_tx, mut batch_rx) = mpsc::channel::<EventBatch>(16);

    tokio::spawn(async move {
        waf_cluster::sync::events::run_event_batcher(batcher, event_rx, batch_tx).await;
    });

    for i in 1..=3 {
        event_tx.send(sample_event(i, "lifecycle-worker")).await.unwrap();
    }

    let batch = tokio::time::timeout(Duration::from_secs(5), batch_rx.recv())
        .await
        .expect("batch should arrive")
        .expect("channel not closed");
    assert_eq!(batch.events.len(), 3);
    assert_eq!(batch.node_id, "lifecycle-worker");

    // ── Phase 4: Config sync ──────────────────────────────────────────────
    let mut main_syncer = ConfigSyncer::new("lifecycle-main".into());
    let mut worker_syncer = ConfigSyncer::new("lifecycle-worker".into());

    let syncable_config = SyncableConfig {
        proxy: waf_common::config::ProxyConfig {
            listen_addr: "0.0.0.0:80".into(),
            ..Default::default()
        },
        rules: Default::default(),
        cache: Default::default(),
        api: waf_common::config::ApiConfig {
            listen_addr: "0.0.0.0:9527".into(),
        },
    };
    let cfg_msg = main_syncer.build_sync(&syncable_config).unwrap();
    let applied = worker_syncer.apply_sync(&cfg_msg, 1);
    assert!(applied.is_some());
    assert_eq!(worker_syncer.current_version(), cfg_msg.version);

    // ── Phase 5: Election after main death ────────────────────────────────
    // Main dies — remove from peer list
    worker.remove_peer("lifecycle-main").await;

    // Worker starts election as sole node
    let term = worker.election.increment_term_and_vote_for_self();
    let votes = worker.election.vote_count_for_term(term);
    let total = worker.total_nodes().await; // just self = 1

    assert!(
        ElectionManager::is_majority(votes, total),
        "sole surviving node should self-elect"
    );

    worker.promote_to_main().await;
    assert_eq!(worker.current_role().await, NodeRole::Main);

    let final_term = worker.election.current_term_sync();
    assert!(final_term >= 1);
}
