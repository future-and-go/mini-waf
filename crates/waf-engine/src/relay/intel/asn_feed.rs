//! FR-007 phase-03 — `IPinfo` Lite mmdb-format ASN database.
//!
//! Generic mmdb reader: works with `IPinfo` Lite (fields `asn`, `as_name`)
//! and any compatible MMDB layout exposing those keys. `MaxMind` GeoLite2-ASN
//! uses different field names (`autonomous_system_number/_organization`)
//! and is tracked as a future variant; current build covers `IPinfo` Lite +
//! the TSV fallback (see `asn_feed_iptoasn.rs`).
//!
//! License keys (when fetching commercial mmdb files) are handled by the
//! refresh task in phase-04; this module only opens the local file.

use std::net::IpAddr;
use std::path::Path;

use anyhow::{Context, Result};
use maxminddb::Reader;
use serde::Deserialize;

use super::{AsnDb, AsnRecord};

/// `IPinfo` Lite mmdb (or any MMDB exposing the `IPinfo` schema).
pub struct IpinfoLiteMmdb {
    reader: Reader<Vec<u8>>,
}

#[derive(Debug, Deserialize)]
struct IpinfoLiteRecord<'a> {
    /// `"AS15169"` form — strip the `AS` prefix to parse u32.
    #[serde(default)]
    asn: Option<&'a str>,
    /// Human-readable org name. Some records omit it.
    #[serde(default)]
    as_name: Option<&'a str>,
}

impl IpinfoLiteMmdb {
    /// Open the mmdb at `path`. Reads the file fully into memory (mmap is
    /// gated behind a maxminddb feature; readfile is the portable default).
    pub fn open(path: &Path) -> Result<Self> {
        let reader = Reader::open_readfile(path).with_context(|| format!("opening ASN mmdb {}", path.display()))?;
        Ok(Self { reader })
    }
}

impl AsnDb for IpinfoLiteMmdb {
    fn lookup(&self, ip: IpAddr) -> Option<AsnRecord> {
        // mmdb returns Err on lookup miss in some versions; treat any error
        // as "no record" (matches the `AsnUnknown` semantics in the
        // classifier).
        let rec: IpinfoLiteRecord<'_> = self.reader.lookup(ip).ok()?;
        let asn_str = rec.asn?;
        let asn: u32 = asn_str.strip_prefix("AS").unwrap_or(asn_str).parse().ok()?;
        let org = rec.as_name.unwrap_or_default().to_string();
        Some(AsnRecord { asn, org })
    }

    fn name(&self) -> &'static str {
        "ipinfo_lite"
    }
}

/// Refresh task for an mmdb file.
///
/// Owns the destination path + optional URL; on `refresh()` performs the
/// HTTP-fetch → atomic-swap dance from `atomic_swap`. Reader
/// (`IpinfoLiteMmdb`) is rebuilt by phase-05's notify watcher when the
/// file changes.
pub struct IpinfoLiteFeed {
    url: Option<url::Url>,
    target: std::path::PathBuf,
    last_etag: parking_lot::Mutex<Option<String>>,
    http: reqwest::Client,
}

const MMDB_BOUNDS: super::atomic_swap::SizeBounds = 100 * 1024..=500 * 1024 * 1024;

impl IpinfoLiteFeed {
    #[must_use]
    pub const fn new(url: Option<url::Url>, target: std::path::PathBuf, http: reqwest::Client) -> Self {
        Self {
            url,
            target,
            last_etag: parking_lot::Mutex::new(None),
            http,
        }
    }
}

#[async_trait::async_trait]
impl super::IntelProvider for IpinfoLiteFeed {
    fn name(&self) -> &'static str {
        "ipinfo_lite_feed"
    }

    async fn refresh(&self) -> anyhow::Result<super::RefreshOutcome> {
        let name = self.name();
        super::feed_helpers::http_etag_swap(
            self.url.as_ref(),
            &self.target,
            &self.http,
            &self.last_etag,
            &MMDB_BOUNDS,
            name,
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn missing_path_errors() {
        let res = IpinfoLiteMmdb::open(&PathBuf::from("/nonexistent/asn.mmdb"));
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn airgap_mode_returns_not_modified() {
        use super::super::IntelProvider;
        let feed = IpinfoLiteFeed::new(
            None,
            PathBuf::from("/tmp/nonexistent.mmdb"),
            super::super::http::build_client(None).expect("client"),
        );
        let out = feed.refresh().await.expect("ok");
        assert!(matches!(out, super::super::RefreshOutcome::NotModified));
    }
}
