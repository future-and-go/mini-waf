//! FR-005 phase-05 — Risk bump action for `DDoS` verdicts.
//!
//! Submits risk signals to FR-010's [`RiskAggregator`] when `DDoS` violations
//! are detected. Fire-and-forget via the sync `submit_ip` seam — the actor is
//! the client IP on the `RiskKey` IP axis, so the request-path scorer joins
//! the same state it reads for that IP. No blocking, no runtime required.

use std::net::IpAddr;
use std::sync::Arc;

use tracing::debug;

use crate::checks::ddos::detector::DetectorVerdict;
use crate::device_fp::aggregator::RiskAggregator;
use crate::device_fp::signal::Signal;

use super::{ActionExecutor, ActionResult};

/// Risk bump action that submits `DDoS` signals to the risk aggregator.
///
/// Uses [`Signal::DdosBurst`] to carry the detector-decided severity verbatim
/// to the scorer. The aggregator handles scoring asynchronously.
pub struct RiskBumpAction {
    aggregator: Arc<dyn RiskAggregator>,
}

impl RiskBumpAction {
    #[must_use]
    pub fn new(aggregator: Arc<dyn RiskAggregator>) -> Self {
        Self { aggregator }
    }
}

impl ActionExecutor for RiskBumpAction {
    fn name(&self) -> &'static str {
        "risk_bump"
    }

    fn execute(&self, ip: IpAddr, verdict: &DetectorVerdict, _now_ms: i64) -> ActionResult {
        // Determine risk delta from verdict
        let risk_delta = match verdict {
            DetectorVerdict::Allow => return ActionResult::noop(),
            DetectorVerdict::SoftAnomaly(delta) => *delta,
            DetectorVerdict::HardBurst { .. } => 100, // max risk for hard bursts
        };

        if risk_delta == 0 {
            return ActionResult::noop();
        }

        self.aggregator.submit_ip(ip, &[Signal::DdosBurst { risk_delta }]);

        debug!(
            action = "risk_bump",
            ip = %ip,
            risk_delta = risk_delta,
            "submitted DDoS risk signal"
        );

        ActionResult {
            banned: false,
            ban_ttl_s: None,
            risk_delta,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device_fp::aggregator::LoggingAggregator;

    fn make_risk_action() -> (LoggingAggregator, RiskBumpAction) {
        let agg = LoggingAggregator::new(16);
        let action = RiskBumpAction::new(Arc::new(agg.clone()));
        (agg, action)
    }

    #[test]
    fn ignores_allow_verdict() {
        let (agg, action) = make_risk_action();
        let ip: IpAddr = "192.168.1.1".parse().unwrap();

        let result = action.execute(ip, &DetectorVerdict::Allow, 1000);
        assert_eq!(result, ActionResult::noop());
        assert!(agg.is_empty());
    }

    #[test]
    fn submits_soft_anomaly() {
        let (agg, action) = make_risk_action();
        let ip: IpAddr = "10.0.0.1".parse().unwrap();

        let result = action.execute(ip, &DetectorVerdict::SoftAnomaly(50), 1000);
        assert_eq!(result.risk_delta, 50);
        assert!(!result.banned);

        let snap = agg.snapshot();
        assert_eq!(snap.len(), 1);
        let first = snap.first().expect("expected one submission");
        assert_eq!(first.actor_ip, Some(ip));
        assert!(matches!(
            first.signals.as_slice(),
            [Signal::DdosBurst { risk_delta: 50 }]
        ));
    }

    #[test]
    fn submits_hard_burst_max_risk() {
        let (agg, action) = make_risk_action();
        let ip: IpAddr = "172.16.0.1".parse().unwrap();

        let verdict = DetectorVerdict::HardBurst {
            reason: "burst",
            detector: "per_ip",
            rps: 100,
        };
        let result = action.execute(ip, &verdict, 1000);
        assert_eq!(result.risk_delta, 100);

        let snap = agg.snapshot();
        assert_eq!(snap.len(), 1);
        let first = snap.first().expect("expected one submission");
        assert_eq!(first.actor_ip, Some(ip));
        assert!(matches!(
            first.signals.as_slice(),
            [Signal::DdosBurst { risk_delta: 100 }]
        ));
    }

    #[test]
    fn zero_soft_anomaly_is_noop() {
        let (agg, action) = make_risk_action();
        let ip: IpAddr = "1.1.1.1".parse().unwrap();

        let result = action.execute(ip, &DetectorVerdict::SoftAnomaly(0), 1000);
        assert_eq!(result, ActionResult::noop());
        assert!(agg.is_empty());
    }
}
