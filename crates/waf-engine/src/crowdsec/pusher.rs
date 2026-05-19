use std::sync::Arc;
use std::time::Duration;

use serde::Serialize;
use tokio::sync::Mutex;
use tokio::sync::watch;
use tracing::{info, warn};

use waf_common::DetectionResult;

use super::client::CrowdSecClient;
use super::config::PusherConfig;

const BATCH_SIZE: usize = 50;
const FLUSH_INTERVAL_SECS: u64 = 30;

#[derive(Debug, Clone, Serialize)]
struct AlertEvent {
    scenario: String,
    source_ip: String,
    rule_name: String,
    detail: String,
}

/// Pushes prx-waf WAF detections to `CrowdSec` as machine alerts.
///
/// Events are buffered and sent either when the buffer reaches `BATCH_SIZE`
/// or every `FLUSH_INTERVAL_SECS`, whichever comes first.
pub struct CrowdSecPusher {
    client: Arc<CrowdSecClient>,
    config: PusherConfig,
    buffer: Arc<Mutex<Vec<AlertEvent>>>,
}

impl CrowdSecPusher {
    pub fn new(client: Arc<CrowdSecClient>, config: PusherConfig) -> Self {
        Self {
            client,
            config,
            buffer: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Queue a WAF detection for the next batch push.
    pub async fn push_detection(&self, client_ip: &str, detection: &DetectionResult) {
        let event = AlertEvent {
            scenario: detection
                .rule_id
                .clone()
                .unwrap_or_else(|| "prx-waf/detection".to_string()),
            source_ip: client_ip.to_string(),
            rule_name: detection.rule_name.clone(),
            detail: detection.detail.clone(),
        };

        let mut buf = self.buffer.lock().await;
        buf.push(event);

        if buf.len() >= BATCH_SIZE {
            let batch = std::mem::take(&mut *buf);
            drop(buf);
            self.flush_batch(batch).await;
        }
    }

    async fn flush_batch(&self, batch: Vec<AlertEvent>) {
        if batch.is_empty() {
            return;
        }

        let token = match self
            .client
            .machine_auth(&self.config.login, &self.config.password)
            .await
        {
            Ok(t) => t,
            Err(e) => {
                warn!("CrowdSec machine auth failed: {}", e);
                return;
            }
        };

        let alerts = serde_json::json!(batch);
        match self.client.push_alerts(&token, alerts).await {
            Ok(()) => info!("Pushed {} WAF events to CrowdSec", batch.len()),
            Err(e) => warn!("Failed to push alerts to CrowdSec: {}", e),
        }
    }

    /// Background task: flush the event buffer on a timer and on shutdown.
    pub async fn run_flush_task(self: Arc<Self>, mut shutdown_rx: watch::Receiver<bool>) {
        let interval = Duration::from_secs(FLUSH_INTERVAL_SECS);
        loop {
            tokio::select! {
                () = tokio::time::sleep(interval) => {}
                result = shutdown_rx.changed() => {
                    if result.is_err() || *shutdown_rx.borrow() {
                        // Final flush before exit
                        let batch = {
                            let mut buf = self.buffer.lock().await;
                            std::mem::take(&mut *buf)
                        };
                        self.flush_batch(batch).await;
                        return;
                    }
                }
            }

            let batch = {
                let mut buf = self.buffer.lock().await;
                std::mem::take(&mut *buf)
            };
            self.flush_batch(batch).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use waf_common::Phase;

    fn unreachable_pusher() -> CrowdSecPusher {
        let client = Arc::new(CrowdSecClient::new("http://127.0.0.1:1".to_string(), "k".to_string()).expect("client"));
        CrowdSecPusher::new(
            client,
            PusherConfig {
                login: "m".to_string(),
                password: "p".to_string(),
            },
        )
    }

    fn detection() -> DetectionResult {
        DetectionResult {
            rule_id: Some("R1".to_string()),
            rule_name: "T".to_string(),
            phase: Phase::SqlInjection,
            detail: "d".to_string(),
            rule_action: None,
            action_status: None,
        }
    }

    #[tokio::test]
    async fn push_detection_buffers_event_below_threshold() {
        let p = unreachable_pusher();
        let det = detection();
        p.push_detection("1.2.3.4", &det).await;
        let snapshot = {
            let buf = p.buffer.lock().await;
            buf.clone()
        };
        let first = snapshot.first().expect("at least one event");
        assert_eq!(snapshot.len(), 1);
        assert_eq!(first.scenario, "R1");
        assert_eq!(first.source_ip, "1.2.3.4");
    }

    #[tokio::test]
    async fn push_detection_uses_default_scenario_when_rule_id_missing() {
        let p = unreachable_pusher();
        let det = DetectionResult {
            rule_id: None,
            ..detection()
        };
        p.push_detection("9.9.9.9", &det).await;
        let snapshot = {
            let buf = p.buffer.lock().await;
            buf.clone()
        };
        let first = snapshot.first().expect("at least one event");
        assert_eq!(first.scenario, "prx-waf/detection");
    }

    #[tokio::test]
    async fn flush_batch_empty_is_a_noop() {
        let p = unreachable_pusher();
        // Empty input — should return without attempting auth.
        p.flush_batch(Vec::new()).await;
    }
}
