//! End-to-end proof that `DDoS` risk bumps land on the actor the request-path
//! scorer actually reads: `RiskBumpAction` → sync `submit_ip` → ingest worker
//! → `MemoryRiskStore`, keyed by client IP.
//!
//! Deliberately runs on the default `current_thread` test runtime — the submit
//! side must be runtime-flavor agnostic (no `block_in_place`).

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use waf_engine::checks::ddos::{ActionExecutor, DetectorVerdict, RiskBumpAction};
use waf_engine::device_fp::aggregator::RiskAggregator;
use waf_engine::device_fp::types::{FingerprintValue, FpKey};
use waf_engine::risk::key::RiskKey;
use waf_engine::risk::state::ContributorKind;
use waf_engine::risk::store::{MemoryRiskStore, RiskStore};
use waf_engine::risk::{ScoringAggregator, SignalWeights};

fn start_pipeline() -> (Arc<dyn RiskStore>, Arc<ScoringAggregator>, tokio::task::JoinHandle<()>) {
    let store: Arc<dyn RiskStore> = Arc::new(MemoryRiskStore::new());
    let (agg, handle) = ScoringAggregator::start(Arc::clone(&store), SignalWeights::default());
    (store, Arc::new(agg), handle)
}

/// Poll the ingest metrics until `n` jobs were processed, bounded by a timeout.
async fn await_processed(agg: &ScoringAggregator, n: u64) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    while agg.metrics().processed_total() < n {
        assert!(
            tokio::time::Instant::now() < deadline,
            "worker did not process {n} job(s) in time"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

#[tokio::test]
async fn hard_burst_raises_scored_actor_state() {
    let (store, agg, _handle) = start_pipeline();
    let action = RiskBumpAction::new(agg.clone() as Arc<dyn RiskAggregator>);
    let ip: IpAddr = "198.51.100.77".parse().unwrap();

    let verdict = DetectorVerdict::HardBurst {
        reason: "burst",
        detector: "per_ip",
        rps: 500,
    };
    // Plain sync call — no runtime bridge involved.
    let result = action.execute(ip, &verdict, 1000);
    assert_eq!(result.risk_delta, 100);

    await_processed(&agg, 1).await;

    // Same key shape the request-path scorer builds for this client.
    let state = store
        .read(&RiskKey::from_ip(ip))
        .await
        .unwrap()
        .expect("risk state must exist under the client IP actor");
    assert!(state.clamped_score > 0);
    let contributor = state
        .contributors
        .iter()
        .find(|c| matches!(&c.kind, ContributorKind::Signal(name) if name == "ddos_burst"))
        .expect("ddos_burst contributor must be recorded");
    assert_eq!(contributor.delta, 100);
}

#[tokio::test]
async fn soft_anomaly_preserves_severity() {
    let (store, agg, _handle) = start_pipeline();
    let action = RiskBumpAction::new(agg.clone() as Arc<dyn RiskAggregator>);
    let ip: IpAddr = "198.51.100.78".parse().unwrap();

    let result = action.execute(ip, &DetectorVerdict::SoftAnomaly(37), 1000);
    assert_eq!(result.risk_delta, 37);

    await_processed(&agg, 1).await;

    let state = store.read(&RiskKey::from_ip(ip)).await.unwrap().unwrap();
    let contributor = state
        .contributors
        .iter()
        .find(|c| matches!(&c.kind, ContributorKind::Signal(name) if name == "ddos_burst"))
        .expect("ddos_burst contributor must be recorded");
    assert_eq!(contributor.delta, 37, "detector severity must survive end-to-end");
}

#[tokio::test]
async fn phantom_actor_regression() {
    let (store, agg, _handle) = start_pipeline();
    let action = RiskBumpAction::new(agg.clone() as Arc<dyn RiskAggregator>);
    let ip: IpAddr = "198.51.100.79".parse().unwrap();

    let verdict = DetectorVerdict::HardBurst {
        reason: "burst",
        detector: "per_ip",
        rps: 500,
    };
    action.execute(ip, &verdict, 1000);

    await_processed(&agg, 1).await;

    // The old implementation smuggled the IP inside a synthetic fingerprint
    // key; nothing may land under that phantom actor anymore.
    let smuggled = FpKey {
        ja3: Some(FingerprintValue::new(format!("ddos:{ip}"))),
        ja4: None,
        h2_akamai: None,
    };
    let phantom_key = RiskKey {
        ip: None,
        fp_hash: RiskKey::hash_fp_key(&smuggled),
        session: None,
    };
    assert!(
        store.read(&phantom_key).await.unwrap().is_none(),
        "no state may exist under the smuggled fingerprint actor"
    );
    // ...while the real IP actor does have state.
    assert!(store.read(&RiskKey::from_ip(ip)).await.unwrap().is_some());
}
