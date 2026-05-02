//! Per-fingerprint identity persistence trait.
//!
//! Two impls in v1: in-memory (default, phase-05) and Redis (phase-08
//! behind `redis-store` feature). All implementations MUST share the
//! conformance suite — phase-05 introduces it.

use std::net::IpAddr;

use async_trait::async_trait;

use crate::device_fp::types::{FpKey, IdentityRecord, Observation};

#[async_trait]
pub trait IdentityStore: Send + Sync {
    /// Record a new observation of `key` from `ip` + `ua` at `ts` (unix
    /// seconds). Returns the post-insert aggregate state.
    async fn observe(&self, key: &FpKey, ip: IpAddr, ua: &str, ts: i64) -> anyhow::Result<Observation>;

    /// Look up the persisted record for `key`. `Ok(None)` when the key
    /// was never seen or has expired out.
    async fn lookup(&self, key: &FpKey) -> anyhow::Result<Option<IdentityRecord>>;

    /// Sweep expired entries. Returns the number purged.
    async fn purge_expired(&self) -> anyhow::Result<usize>;
}
