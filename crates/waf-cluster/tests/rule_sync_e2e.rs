//! End-to-end rule sync tests covering full snapshot, incremental, and no-op cases.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::default_trait_access,
    clippy::await_holding_lock,
    clippy::significant_drop_tightening
)]

use std::sync::Arc;

use waf_cluster::node::{NodeState, StorageMode};
use waf_cluster::protocol::{ChangeOp, RuleSyncRequest};
use waf_cluster::sync::rules::{NoopReloader, RuleChangelog, apply_sync_response, handle_sync_request};
use waf_common::config::{ClusterConfig, ClusterElectionConfig};
use waf_engine::{Rule, RuleRegistry};

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

fn sample_rule(id: &str, name: &str) -> Rule {
    Rule {
        id: id.to_string(),
        name: name.to_string(),
        description: None,
        category: "test".to_string(),
        source: "test".to_string(),
        enabled: true,
        action: "block".to_string(),
        severity: Some("high".to_string()),
        pattern: None,
        tags: vec![],
        metadata: Default::default(),
        risk_delta: None,
        risk_action: None,
    }
}

#[tokio::test]
async fn full_snapshot_sync_from_version_zero() {
    let main_state = NodeState::new(test_config("main-1", "main"), StorageMode::Full).unwrap();
    let r1 = sample_rule("r1", "Rule 1");
    let r2 = sample_rule("r2", "Rule 2");
    let r3 = sample_rule("r3", "Rule 3");

    // Record 3 changes on main
    {
        let mut changelog = main_state.rule_changelog.write();
        changelog.record_change(ChangeOp::Upsert, "r1".into(), Some(&r1));
        changelog.record_change(ChangeOp::Upsert, "r2".into(), Some(&r2));
        changelog.record_change(ChangeOp::Upsert, "r3".into(), Some(&r3));
    }

    // Insert rules into main's registry
    {
        let mut registry = main_state.rule_registry.write();
        registry.insert(r1);
        registry.insert(r2);
        registry.insert(r3);
    }

    // Worker requests from version 0
    let request = RuleSyncRequest { current_version: 0 };
    let rules: Vec<Rule> = main_state.rule_registry.read().rules.values().cloned().collect();
    let changelog = main_state.rule_changelog.read();
    let response = handle_sync_request(&changelog, &request, &rules).unwrap();

    // Worker applies
    let mut worker_registry = RuleRegistry::default();
    let reloader = NoopReloader;
    apply_sync_response(response, &mut worker_registry, &reloader)
        .await
        .unwrap();

    assert_eq!(worker_registry.version, 3);
    assert_eq!(worker_registry.rules.len(), 3);
    assert!(worker_registry.rules.contains_key("r1"));
    assert!(worker_registry.rules.contains_key("r2"));
    assert!(worker_registry.rules.contains_key("r3"));
}

#[tokio::test]
async fn incremental_sync_returns_only_new_changes() {
    let mut changelog = RuleChangelog::new(500);
    let r1 = sample_rule("r1", "Rule 1");
    let r2 = sample_rule("r2", "Rule 2");
    let r3 = sample_rule("r3", "Rule 3");
    let r4 = sample_rule("r4", "Rule 4");
    let r5 = sample_rule("r5", "Rule 5");

    // Record 5 changes, simulate worker at version 2
    changelog.record_change(ChangeOp::Upsert, "r1".into(), Some(&r1));
    changelog.record_change(ChangeOp::Upsert, "r2".into(), Some(&r2));
    changelog.record_change(ChangeOp::Upsert, "r3".into(), Some(&r3));
    changelog.record_change(ChangeOp::Upsert, "r4".into(), Some(&r4));
    changelog.record_change(ChangeOp::Upsert, "r5".into(), Some(&r5));

    let all_rules = vec![r1, r2, r3, r4, r5];

    // Worker at version 2 requesting sync
    let request = RuleSyncRequest { current_version: 2 };
    let response = handle_sync_request(&changelog, &request, &all_rules).unwrap();

    assert!(matches!(
        response.sync_type,
        waf_cluster::protocol::SyncType::Incremental
    ));
    assert_eq!(response.changes.len(), 3);
    assert_eq!(response.version, 5);
}

#[tokio::test]
async fn noop_sync_when_worker_is_current() {
    let mut changelog = RuleChangelog::new(500);
    let r1 = sample_rule("r1", "Rule 1");

    changelog.record_change(ChangeOp::Upsert, "r1".into(), Some(&r1));

    let request = RuleSyncRequest { current_version: 1 };
    let response = handle_sync_request(&changelog, &request, &[r1]).unwrap();

    assert!(matches!(
        response.sync_type,
        waf_cluster::protocol::SyncType::Incremental
    ));
    assert!(response.changes.is_empty());
    assert_eq!(response.version, 1);
}

#[tokio::test]
async fn full_snapshot_fallback_when_worker_too_far_behind() {
    let mut changelog = RuleChangelog::new(10);

    // Record 15 changes into a buffer of size 10, so versions 1-5 are evicted
    let rules: Vec<Rule> = (1..=15)
        .map(|i| sample_rule(&format!("r{i}"), &format!("Rule {i}")))
        .collect();
    for r in &rules {
        changelog.record_change(ChangeOp::Upsert, r.id.clone(), Some(r));
    }

    // Worker at version 1 — oldest buffered is version 6
    let request = RuleSyncRequest { current_version: 1 };
    let response = handle_sync_request(&changelog, &request, &rules).unwrap();

    assert!(matches!(response.sync_type, waf_cluster::protocol::SyncType::Full));
    assert!(!response.snapshot_lz4.is_empty());
    assert_eq!(response.version, 15);

    // Apply the full snapshot
    let mut worker_registry = RuleRegistry::default();
    let reloader = NoopReloader;
    apply_sync_response(response, &mut worker_registry, &reloader)
        .await
        .unwrap();
    assert_eq!(worker_registry.rules.len(), 15);
    assert_eq!(worker_registry.version, 15);
}

#[tokio::test]
async fn node_state_rule_changelog_integration() {
    let state = Arc::new(NodeState::new(test_config("main-1", "main"), StorageMode::Full).unwrap());

    let r1 = sample_rule("r1", "Rule 1");
    let r2 = sample_rule("r2", "Rule 2");
    state
        .rule_changelog
        .write()
        .record_change(ChangeOp::Upsert, "r1".into(), Some(&r1));
    state
        .rule_changelog
        .write()
        .record_change(ChangeOp::Upsert, "r2".into(), Some(&r2));

    let changelog = state.rule_changelog.read();
    assert_eq!(changelog.current_version(), 2);

    // Worker at version 1 → incremental delta with 1 change (r2)
    let delta = changelog.delta_since(1);
    assert!(delta.is_some());
    assert_eq!(delta.unwrap().len(), 1);

    // Worker at version 0 → None (needs full snapshot since first buffered is v1)
    let delta_from_zero = changelog.delta_since(0);
    assert!(delta_from_zero.is_none());
}
