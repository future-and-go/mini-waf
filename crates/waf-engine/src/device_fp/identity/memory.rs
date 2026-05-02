//! In-memory identity store — phase-02 no-op skeleton.
//!
//! Records nothing, returns default `Observation` for every `observe()`,
//! `None` for every `lookup()`. The real `dashmap`-backed implementation
//! lands in phase-05; tests there populate it from the conformance suite.
//! Until then this lets callers wire the store without `Option<dyn ..>`.

use std::net::IpAddr;

use async_trait::async_trait;

use crate::device_fp::identity::identity_trait::IdentityStore;
use crate::device_fp::types::{FpKey, IdentityRecord, Observation};

#[derive(Debug, Default)]
pub struct MemoryIdentityStore;

impl MemoryIdentityStore {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

#[async_trait]
impl IdentityStore for MemoryIdentityStore {
    async fn observe(
        &self,
        _key: &FpKey,
        _ip: IpAddr,
        _ua: &str,
        ts: i64,
    ) -> anyhow::Result<Observation> {
        Ok(Observation {
            distinct_ips_in_window: 0,
            distinct_uas_in_window: 0,
            first_seen_unix: ts,
            last_seen_unix: ts,
        })
    }

    async fn lookup(&self, _key: &FpKey) -> anyhow::Result<Option<IdentityRecord>> {
        Ok(None)
    }

    async fn purge_expired(&self) -> anyhow::Result<usize> {
        Ok(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[tokio::test]
    async fn observe_returns_default_with_ts() {
        let store = MemoryIdentityStore::new();
        let key = FpKey {
            ja3: None,
            ja4: None,
            h2_akamai: None,
        };
        let obs = store
            .observe(&key, IpAddr::V4(Ipv4Addr::LOCALHOST), "ua", 42)
            .await
            .unwrap();
        assert_eq!(obs.first_seen_unix, 42);
        assert_eq!(obs.distinct_ips_in_window, 0);
        assert!(store.lookup(&key).await.unwrap().is_none());
        assert_eq!(store.purge_expired().await.unwrap(), 0);
    }
}
