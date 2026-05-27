use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use async_trait::async_trait;
use waf_cluster::node::{NodeState, StorageMode};
use waf_cluster::{ClusterConfig, RuleReloader};
use waf_engine::RuleRegistry;

struct MockReloader {
    last_version: AtomicU64,
    reload_count: AtomicU64,
}

impl MockReloader {
    fn new() -> Self {
        Self {
            last_version: AtomicU64::new(0),
            reload_count: AtomicU64::new(0),
        }
    }
}

#[async_trait]
impl RuleReloader for MockReloader {
    async fn on_rules_updated(&self, version: u64) -> anyhow::Result<()> {
        self.last_version.store(version, Ordering::SeqCst);
        self.reload_count.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    async fn reload_from_registry(&self, _registry: &RuleRegistry) -> anyhow::Result<()> {
        self.reload_count.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

fn test_config(node_id: &str, role: &str) -> ClusterConfig {
    use waf_common::config::ClusterElectionConfig;
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

#[tokio::test]
async fn notify_rules_updated_calls_reloader() {
    let node = NodeState::new(test_config("bridge-1", "worker"), StorageMode::Full).unwrap();
    let mock = Arc::new(MockReloader::new());
    node.set_rule_reloader(Arc::clone(&mock) as Arc<dyn RuleReloader>);

    node.notify_rules_updated(42).await.unwrap();

    assert_eq!(mock.reload_count.load(Ordering::SeqCst), 1);
    let version = *node.rules_version.read().await;
    assert_eq!(version, 42);
}

#[tokio::test]
async fn notify_rules_updated_without_reloader_does_not_panic() {
    let node = NodeState::new(test_config("bridge-2", "worker"), StorageMode::Full).unwrap();
    node.notify_rules_updated(7).await.unwrap();
    let version = *node.rules_version.read().await;
    assert_eq!(version, 7);
}

#[tokio::test]
async fn rule_registry_concurrent_read_write() {
    let node = Arc::new(NodeState::new(test_config("bridge-3", "worker"), StorageMode::Full).unwrap());
    let registry = Arc::clone(&node.rule_registry);

    let writer = {
        let reg = Arc::clone(&registry);
        tokio::spawn(async move {
            let mut w = reg.write();
            w.insert(waf_engine::Rule {
                id: "TEST-001".to_string(),
                name: "Test rule".to_string(),
                description: None,
                category: "test".to_string(),
                source: "unit-test".to_string(),
                enabled: true,
                action: "block".to_string(),
                severity: None,
                pattern: None,
                tags: vec![],
                metadata: Default::default(),
                risk_delta: None,
                risk_action: None,
            });
        })
    };
    writer.await.unwrap();

    let reader = {
        let reg = Arc::clone(&registry);
        tokio::spawn(async move {
            let r = reg.read();
            r.get("TEST-001").map(|rule| rule.name.clone())
        })
    };
    let name = reader.await.unwrap();
    assert_eq!(name.as_deref(), Some("Test rule"));
}

#[tokio::test]
async fn reloader_receives_registry_and_can_read_rules() {
    struct RegistryInspector {
        found_rule: tokio::sync::Mutex<Option<String>>,
    }

    #[async_trait]
    impl RuleReloader for RegistryInspector {
        async fn on_rules_updated(&self, _version: u64) -> anyhow::Result<()> {
            Ok(())
        }
        async fn reload_from_registry(&self, registry: &RuleRegistry) -> anyhow::Result<()> {
            let name = registry.get("INSPECT-1").map(|r| r.name.clone());
            *self.found_rule.lock().await = name;
            Ok(())
        }
    }

    let node = NodeState::new(test_config("bridge-4", "worker"), StorageMode::Full).unwrap();

    {
        let mut reg = node.rule_registry.write();
        reg.insert(waf_engine::Rule {
            id: "INSPECT-1".to_string(),
            name: "Inspectable rule".to_string(),
            description: None,
            category: "test".to_string(),
            source: "unit-test".to_string(),
            enabled: true,
            action: "log".to_string(),
            severity: None,
            pattern: None,
            tags: vec![],
            metadata: Default::default(),
            risk_delta: None,
            risk_action: None,
        });
    }

    let inspector = Arc::new(RegistryInspector {
        found_rule: tokio::sync::Mutex::new(None),
    });
    node.set_rule_reloader(Arc::clone(&inspector) as Arc<dyn RuleReloader>);

    node.notify_rules_updated(10).await.unwrap();

    let found = inspector.found_rule.lock().await.clone();
    assert_eq!(found.as_deref(), Some("Inspectable rule"));
}
