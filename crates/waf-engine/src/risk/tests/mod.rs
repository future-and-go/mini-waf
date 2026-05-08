//! FR-025 Integration tests for risk scoring lifecycle.

mod anomaly_combos;
mod canary;
mod lifecycle;

#[cfg(feature = "redis-store")]
mod conformance_redis;
#[cfg(feature = "redis-store")]
mod redis_failover;
