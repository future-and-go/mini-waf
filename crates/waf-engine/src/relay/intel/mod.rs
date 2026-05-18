//! FR-007 — intel providers (ASN db, Tor list).
//!
//! Phase-01 declared `IntelProvider` for refresh contracts.
//! Phase-03 adds `AsnDb` trait + concrete loaders (mmdb, iptoasn TSV) and
//! the `DatacenterSet` merge loader.

pub mod asn_feed;
pub mod asn_feed_iptoasn;
pub mod atomic_swap;
pub mod datacenter_set;
pub mod feed_helpers;
pub mod http;
pub mod status;
pub mod tor_feed;

use std::net::IpAddr;

use anyhow::Error;

pub use asn_feed::IpinfoLiteFeed;
pub use asn_feed_iptoasn::IptoasnFeed;
pub use datacenter_set::DatacenterSet;
pub use tor_feed::TorFeed;

/// Result of a single `refresh()` call. `Failed` carries the underlying
/// error so the caller can choose between retain-last-good (default) and
/// fail-close (CRITICAL tier per brainstorm §4.9).
pub enum RefreshOutcome {
    Updated,
    NotModified,
    Failed(Error),
}

#[async_trait::async_trait]
pub trait IntelProvider: Send + Sync {
    fn name(&self) -> &'static str;

    /// Pull the latest snapshot. Implementations MUST be cancel-safe and
    /// MUST NOT panic on transient network errors (return `Failed` instead).
    async fn refresh(&self) -> anyhow::Result<RefreshOutcome>;
}

/// One ASN-database lookup hit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AsnRecord {
    pub asn: u32,
    pub org: String,
}

/// Pluggable ASN data backend. Implementations: `IpinfoLiteMmdb` (primary),
/// `IptoasnTsv` (fallback). `EmptyAsnDb` is the degraded mode when no DB
/// is configured or load fails with `fail_close=false`.
pub trait AsnDb: Send + Sync {
    fn lookup(&self, ip: IpAddr) -> Option<AsnRecord>;
    fn name(&self) -> &'static str;
}

/// No-op ASN db — every lookup returns None. Used when no provider is
/// configured, or when mmdb load fails and `asn.fail_close = false`.
pub struct EmptyAsnDb;

impl AsnDb for EmptyAsnDb {
    fn lookup(&self, _ip: IpAddr) -> Option<AsnRecord> {
        None
    }
    fn name(&self) -> &'static str {
        "empty"
    }
}
