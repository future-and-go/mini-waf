//! Redis identity store — phase-02 placeholder (feature `redis-store`).
//!
//! Real impl ships in phase-08. Phase-02 only proves the feature gate
//! compiles and the trait can be satisfied by a future Redis-backed type.

use std::net::IpAddr;

use async_trait::async_trait;

use crate::device_fp::identity::identity_trait::IdentityStore;
use crate::device_fp::types::{FpKey, IdentityRecord, Observation};

#[derive(Debug, Default)]
pub struct RedisIdentityStore;

#[async_trait]
impl IdentityStore for RedisIdentityStore {
    async fn observe(
        &self,
        _key: &FpKey,
        _ip: IpAddr,
        _ua: &str,
        ts: i64,
    ) -> anyhow::Result<Observation> {
        Ok(Observation {
            first_seen_unix: ts,
            last_seen_unix: ts,
            ..Observation::default()
        })
    }

    async fn lookup(&self, _key: &FpKey) -> anyhow::Result<Option<IdentityRecord>> {
        Ok(None)
    }

    async fn purge_expired(&self) -> anyhow::Result<usize> {
        Ok(0)
    }
}
