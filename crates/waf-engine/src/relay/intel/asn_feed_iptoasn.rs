//! FR-007 phase-03 — iptoasn.com TSV fallback ASN database.
//!
//! Format: `start_ip\tend_ip\tASN\tCC\tdescription` per line, ranges in
//! string form (IPv4 dotted, IPv6 standard). Loader splits IPv4/IPv6 into
//! two sorted vectors; lookup is a binary search for the containing range.
//! Records with `ASN=0` (unrouted ranges) are skipped.

use std::cmp::Ordering;
use std::fs;
use std::net::IpAddr;
use std::path::Path;

use anyhow::{Context, Result};

use super::{AsnDb, AsnRecord};

#[derive(Debug)]
struct Entry {
    start: u128,
    end: u128,
    asn: u32,
    org: String,
}

pub struct IptoasnTsv {
    v4: Vec<Entry>,
    v6: Vec<Entry>,
}

fn ip_to_u128(ip: IpAddr) -> u128 {
    match ip {
        IpAddr::V4(a) => u128::from(u32::from(a)),
        IpAddr::V6(a) => u128::from(a),
    }
}

fn parse_line(line: &str) -> Option<(IpAddr, IpAddr, u32, String)> {
    // iptoasn TSV may include a header row; skip non-IP first column.
    let mut parts = line.split('\t');
    let s_raw = parts.next()?;
    let e_raw = parts.next()?;
    let asn_raw = parts.next()?;
    let _cc = parts.next()?;
    let org = parts.next().unwrap_or("").to_string();

    let s: IpAddr = s_raw.parse().ok()?;
    let e: IpAddr = e_raw.parse().ok()?;
    let asn: u32 = asn_raw.parse().ok()?;
    if asn == 0 {
        return None;
    }
    Some((s, e, asn, org))
}

impl IptoasnTsv {
    pub fn load(path: &Path) -> Result<Self> {
        let body = fs::read_to_string(path).with_context(|| format!("reading iptoasn TSV {}", path.display()))?;
        let mut v4 = Vec::new();
        let mut v6 = Vec::new();
        for line in body.lines() {
            let Some((s, e, asn, org)) = parse_line(line) else {
                continue;
            };
            let entry = Entry {
                start: ip_to_u128(s),
                end: ip_to_u128(e),
                asn,
                org,
            };
            match s {
                IpAddr::V4(_) => v4.push(entry),
                IpAddr::V6(_) => v6.push(entry),
            }
        }
        v4.sort_by_key(|x| x.start);
        v6.sort_by_key(|x| x.start);
        Ok(Self { v4, v6 })
    }

    fn search(table: &[Entry], v: u128) -> Option<&Entry> {
        let idx = table
            .binary_search_by(|e| {
                if v < e.start {
                    Ordering::Greater
                } else if v > e.end {
                    Ordering::Less
                } else {
                    Ordering::Equal
                }
            })
            .ok()?;
        table.get(idx)
    }
}

impl AsnDb for IptoasnTsv {
    fn lookup(&self, ip: IpAddr) -> Option<AsnRecord> {
        let v = ip_to_u128(ip);
        let table = match ip {
            IpAddr::V4(_) => &self.v4,
            IpAddr::V6(_) => &self.v6,
        };
        let e = Self::search(table, v)?;
        Some(AsnRecord {
            asn: e.asn,
            org: e.org.clone(),
        })
    }

    fn name(&self) -> &'static str {
        "iptoasn"
    }
}

/// Refresh task for an iptoasn TSV.
///
/// URL pointing at a `.gz` triggers post-fetch decompression: fetch into
/// `target.gz`, decompress to `target.tmp`, rename `target.tmp` →
/// `target`. URL pointing at a plain TSV uses the standard atomic-swap
/// path.
pub struct IptoasnFeed {
    url: Option<url::Url>,
    target: std::path::PathBuf,
    last_etag: parking_lot::Mutex<Option<String>>,
    http: reqwest::Client,
}

const IPTOASN_BOUNDS: super::atomic_swap::SizeBounds = 1024 * 1024..=200 * 1024 * 1024;
const IPTOASN_GZ_BOUNDS: super::atomic_swap::SizeBounds = 256 * 1024..=50 * 1024 * 1024;

impl IptoasnFeed {
    #[must_use]
    pub const fn new(url: Option<url::Url>, target: std::path::PathBuf, http: reqwest::Client) -> Self {
        Self {
            url,
            target,
            last_etag: parking_lot::Mutex::new(None),
            http,
        }
    }

    fn is_gz(&self) -> bool {
        self.url.as_ref().is_some_and(|u| {
            let p = u.path();
            p.len() >= 3 && p[p.len() - 3..].eq_ignore_ascii_case(".gz")
        })
    }

    async fn refresh_plain(&self) -> anyhow::Result<super::RefreshOutcome> {
        super::feed_helpers::http_etag_swap(
            self.url.as_ref(),
            &self.target,
            &self.http,
            &self.last_etag,
            &IPTOASN_BOUNDS,
            "iptoasn_feed",
        )
        .await
    }

    async fn refresh_gz(&self) -> anyhow::Result<super::RefreshOutcome> {
        // Two-step swap: first land the .gz at `<target>.gz`, then
        // decompress into `<target>.tmp`, then rename → `target`.
        let mut gz_path = self.target.clone();
        let new_ext = gz_path
            .extension()
            .and_then(|s| s.to_str())
            .map_or_else(|| "gz".to_string(), |e| format!("{e}.gz"));
        gz_path.set_extension(new_ext);

        let outcome = super::feed_helpers::http_etag_swap(
            self.url.as_ref(),
            &gz_path,
            &self.http,
            &self.last_etag,
            &IPTOASN_GZ_BOUNDS,
            "iptoasn_feed",
        )
        .await?;

        if matches!(outcome, super::RefreshOutcome::Updated)
            && let Err(e) = decompress_gz_atomic(&gz_path, &self.target).await
        {
            return Ok(super::RefreshOutcome::Failed(e));
        }
        Ok(outcome)
    }
}

async fn decompress_gz_atomic(src: &std::path::Path, dst: &std::path::Path) -> anyhow::Result<()> {
    use anyhow::Context;
    let src = src.to_path_buf();
    let dst = dst.to_path_buf();
    tokio::task::spawn_blocking(move || -> anyhow::Result<()> {
        use std::io::{BufReader, copy};
        let f = std::fs::File::open(&src).with_context(|| format!("open {}", src.display()))?;
        let mut decoder = flate2::read::GzDecoder::new(BufReader::new(f));
        let mut tmp = dst.clone();
        let new_ext = tmp
            .extension()
            .and_then(|s| s.to_str())
            .map_or_else(|| "tmp".to_string(), |e| format!("{e}.tmp"));
        tmp.set_extension(new_ext);
        let mut out = std::fs::File::create(&tmp).with_context(|| format!("create {}", tmp.display()))?;
        copy(&mut decoder, &mut out).context("decompressing gzip body")?;
        out.sync_all().context("fsync decompressed tmp")?;
        std::fs::rename(&tmp, &dst).with_context(|| format!("rename {} -> {}", tmp.display(), dst.display()))?;
        Ok(())
    })
    .await
    .context("gzip decompress join")?
}

#[async_trait::async_trait]
impl super::IntelProvider for IptoasnFeed {
    fn name(&self) -> &'static str {
        "iptoasn_feed"
    }

    async fn refresh(&self) -> anyhow::Result<super::RefreshOutcome> {
        if self.is_gz() {
            self.refresh_gz().await
        } else {
            self.refresh_plain().await
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::net::Ipv4Addr;

    fn write_fixture(body: &str) -> tempfile::NamedTempFile {
        let mut f = tempfile::NamedTempFile::new().expect("temp");
        f.write_all(body.as_bytes()).expect("write");
        f
    }

    #[test]
    fn parses_and_finds_v4_range() {
        let tsv = "8.8.8.0\t8.8.8.255\t15169\tUS\tGOOGLE\n\
                   1.0.0.0\t1.0.0.255\t13335\tUS\tCLOUDFLARE\n";
        let f = write_fixture(tsv);
        let db = IptoasnTsv::load(f.path()).expect("load");
        let r = db.lookup(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))).expect("hit");
        assert_eq!(r.asn, 15169);
        assert_eq!(r.org, "GOOGLE");
    }

    #[test]
    fn miss_outside_any_range() {
        let tsv = "8.8.8.0\t8.8.8.255\t15169\tUS\tGOOGLE\n";
        let f = write_fixture(tsv);
        let db = IptoasnTsv::load(f.path()).expect("load");
        assert!(db.lookup(IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9))).is_none());
    }

    #[test]
    fn skips_zero_asn_and_malformed() {
        let tsv = "BAD LINE\n\
                   1.0.0.0\t1.0.0.255\t0\tZZ\tUNROUTED\n\
                   2.0.0.0\t2.0.0.255\t99\tXX\tOK\n";
        let f = write_fixture(tsv);
        let db = IptoasnTsv::load(f.path()).expect("load");
        assert!(db.lookup(IpAddr::V4(Ipv4Addr::new(1, 0, 0, 5))).is_none());
        assert_eq!(
            db.lookup(IpAddr::V4(Ipv4Addr::new(2, 0, 0, 5))).map(|r| r.asn),
            Some(99)
        );
    }
}
