//! FR-010 risk aggregation trait.
//!
//! Phase-02 ships the trait + a no-op default. The real consumer
//! (FR-025 risk scoring) plugs an implementation in via dependency
//! injection — `device_fp` never depends on the scorer crate.

use async_trait::async_trait;

use crate::device_fp::signal::Signal;
use crate::device_fp::types::FpKey;

#[async_trait]
pub trait RiskAggregator: Send + Sync {
    /// Submit a batch of signals tied to one fingerprint key. Implementations
    /// MUST NOT block the caller — fan out to a queue/channel internally.
    async fn submit(&self, key: &FpKey, signals: &[Signal]);
}

/// Default aggregator — discards all submissions. Used when no risk scorer
/// is wired in (e.g. boot order, dev profile, FR-025 disabled).
#[derive(Debug, Default)]
pub struct NoopAggregator;

#[async_trait]
impl RiskAggregator for NoopAggregator {
    async fn submit(&self, _key: &FpKey, _signals: &[Signal]) {}
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn noop_does_not_panic() {
        let agg = NoopAggregator;
        let key = FpKey {
            ja3: None,
            ja4: None,
            h2_akamai: None,
        };
        agg.submit(&key, &[]).await;
    }
}
