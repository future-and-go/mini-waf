//! Automatic ip2region xdb file updater with hot-reload support.
//!
//! Downloads the latest `ip2region_v4.xdb` and `ip2region_v6.xdb` files from
//! the upstream GitHub repository (or a configurable URL), validates each
//! download, atomically replaces the on-disk files, and triggers a hot-reload
//! of the in-process [`GeoIpService`].

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use tracing::{debug, info, warn};

use crate::geoip::GeoIpService;
use crate::relay::intel::atomic_swap::stream_to_tmp;
use crate::validated_fetch::{USER_AGENT, build_validated_client};
use waf_common::config::GeoIpAutoUpdateConfig;

/// Default URL base for ip2region raw xdb files on GitHub.
const DEFAULT_GITHUB_BASE_URL: &str = "https://raw.githubusercontent.com/lionsoul2014/ip2region/master/data";

/// Maximum allowed xdb response body size (64 MiB — comfortable headroom over
/// the ~20 MB full xdb files). Enforced via `Content-Length` fast-reject and a
/// running cap while streaming to disk.
const MAX_XDB_RESPONSE_SIZE: u64 = 64 * 1024 * 1024;

/// Connection establishment timeout for updater requests.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// Total request timeout for `HEAD` update checks.
const HEAD_TIMEOUT: Duration = Duration::from_secs(30);

/// Total request timeout for xdb downloads (~20 MB files on slow links).
#[allow(clippy::duration_suboptimal_units)] // prefer `from_secs` over MSRV-gated `from_mins`
const DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(120);

// ── Public types ──────────────────────────────────────────────────────────────

/// Result of a single update cycle.
#[derive(Debug, Default)]
pub struct UpdateResult {
    /// Whether the IPv4 xdb file was newly downloaded/replaced.
    pub ipv4_updated: bool,
    /// Whether the IPv6 xdb file was newly downloaded/replaced.
    pub ipv6_updated: bool,
    /// Size of the IPv4 xdb file in bytes (0 if not updated).
    pub ipv4_size: u64,
    /// Size of the IPv6 xdb file in bytes (0 if not updated).
    pub ipv6_size: u64,
}

/// Downloads the latest ip2region xdb files from a configurable URL.
///
/// All download operations are atomic: files are first written to a `.tmp`
/// sibling, validated by opening them with `ip2region::Searcher`, and then
/// renamed into place.  A failed download never corrupts the existing files.
pub struct XdbUpdater {
    data_dir: PathBuf,
    /// Base URL from which xdb files are fetched (without trailing slash).
    github_base_url: String,
}

impl XdbUpdater {
    /// Create an updater that fetches from `github_base_url`.
    pub const fn new(data_dir: PathBuf, github_base_url: String) -> Self {
        Self {
            data_dir,
            github_base_url,
        }
    }

    /// Create an updater using the default upstream GitHub URL.
    pub fn with_default_url(data_dir: PathBuf) -> Self {
        Self::new(data_dir, DEFAULT_GITHUB_BASE_URL.to_string())
    }

    /// Check whether the remote xdb files appear to be newer than the local
    /// copies, using HTTP `HEAD` + `Content-Length` comparison.
    ///
    /// Returns `Ok(true)` when an update seems available (including when either
    /// file is missing locally).  Returns `Ok(false)` when both local files
    /// match the remote sizes.  Network errors are propagated.
    pub async fn check_update(&self) -> Result<bool> {
        // Missing file → definitely need to download; decided before any
        // network access (and before the source URL is validated).
        for filename in &["ip2region_v4.xdb", "ip2region_v6.xdb"] {
            if !self.data_dir.join(filename).exists() {
                debug!("GeoIP updater: {} not found locally — update needed", filename);
                return Ok(true);
            }
        }

        // One validated client per cycle — both files share the base host.
        let client = build_validated_client(&self.github_base_url, CONNECT_TIMEOUT, HEAD_TIMEOUT, USER_AGENT)?;

        for filename in &["ip2region_v4.xdb", "ip2region_v6.xdb"] {
            let local_path = self.data_dir.join(filename);
            let local_size = local_path.metadata().map_or(0, |m| m.len());
            let url = format!("{}/{}", self.github_base_url, filename);

            match client.head(&url).send().await {
                Ok(resp) if resp.status().is_success() => {
                    // Compare Content-Length if the server provides it.
                    if let Some(remote_size) = resp
                        .headers()
                        .get(reqwest::header::CONTENT_LENGTH)
                        .and_then(|v| v.to_str().ok())
                        .and_then(|s| s.parse::<u64>().ok())
                        && remote_size != local_size
                    {
                        debug!(
                            "GeoIP updater: {} size mismatch local={} remote={}",
                            filename, local_size, remote_size
                        );
                        return Ok(true);
                    }
                }
                Ok(resp) => {
                    warn!("GeoIP updater: HEAD {} returned {}", url, resp.status());
                }
                Err(e) => {
                    return Err(anyhow::anyhow!("GeoIP HEAD check failed for {url}: {e}"));
                }
            }
        }

        Ok(false)
    }

    /// Download the latest xdb files atomically.
    ///
    /// For each file:
    /// 1. Download to `<filename>.tmp` in `data_dir`.
    /// 2. Validate the download by opening it with `ip2region::Searcher`.
    /// 3. Atomically `rename` the tmp file to the final path.
    ///
    /// If any step fails the original file is left untouched.
    pub async fn download(&self) -> Result<UpdateResult> {
        std::fs::create_dir_all(&self.data_dir)
            .with_context(|| format!("Failed to create data dir: {}", self.data_dir.display()))?;

        let client = build_validated_client(&self.github_base_url, CONNECT_TIMEOUT, DOWNLOAD_TIMEOUT, USER_AGENT)?;

        let (ipv4_updated, ipv4_size) = self.download_one(&client, "ip2region_v4.xdb").await?;
        let (ipv6_updated, ipv6_size) = self.download_one(&client, "ip2region_v6.xdb").await?;

        Ok(UpdateResult {
            ipv4_updated,
            ipv6_updated,
            ipv4_size,
            ipv6_size,
        })
    }

    /// Full update cycle: `check_update` → `download` → hot-reload.
    ///
    /// If nothing changed (`check_update` returns `false`) this is a no-op and
    /// returns a zeroed `UpdateResult`.  Gracefully degrades: a failed download
    /// returns an error but the running engine keeps using the existing files.
    pub async fn update(&self, geoip: &GeoIpService) -> Result<UpdateResult> {
        let needs_update = self.check_update().await.unwrap_or_else(|e| {
            warn!(
                "GeoIP updater: check_update error (will attempt download anyway): {}",
                e
            );
            true
        });

        if !needs_update {
            return Ok(UpdateResult::default());
        }

        let result = self.download().await?;

        if (result.ipv4_updated || result.ipv6_updated)
            && let Err(e) = geoip.reload()
        {
            warn!("GeoIP updater: hot-reload failed after download: {}", e);
        }

        Ok(result)
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    /// Download a single xdb file atomically.  Returns `(updated, size_bytes)`.
    async fn download_one(&self, client: &reqwest::Client, filename: &str) -> Result<(bool, u64)> {
        let url = format!("{}/{}", self.github_base_url, filename);
        let final_path = self.data_dir.join(filename);
        let tmp_path = self.data_dir.join(format!("{filename}.tmp"));

        info!("GeoIP updater: downloading {} from {}", filename, url);

        let resp = client
            .get(&url)
            .send()
            .await
            .with_context(|| format!("GET request failed for {url}"))?;

        if !resp.status().is_success() {
            return Err(anyhow::anyhow!("HTTP {} downloading {}", resp.status(), url));
        }

        // Fast-reject a response that already advertises an oversized body.
        if let Some(len) = resp.content_length()
            && len > MAX_XDB_RESPONSE_SIZE
        {
            return Err(anyhow::anyhow!(
                "GeoIP xdb response too large: {len} bytes (max {MAX_XDB_RESPONSE_SIZE}) for {url}"
            ));
        }

        // Stream to the tmp file with a running byte cap — never buffer the
        // whole body in memory.
        if let Err(e) = stream_to_tmp(&tmp_path, resp, &(1..=MAX_XDB_RESPONSE_SIZE)).await {
            let _ = std::fs::remove_file(&tmp_path);
            return Err(e.context(format!("Failed to download {filename}")));
        }

        let size = tmp_path.metadata().map_or(0, |m| m.len());

        // Validate: try to open the tmp file as a Searcher.
        // Use NoCache policy to avoid loading ~20 MB into memory just for validation.
        if let Err(e) =
            ip2region::Searcher::new(tmp_path.to_string_lossy().to_string(), ip2region::CachePolicy::NoCache)
        {
            let _ = std::fs::remove_file(&tmp_path);
            return Err(anyhow::anyhow!("Downloaded {filename} failed validation: {e}"));
        }

        // Atomic rename to final path.
        std::fs::rename(&tmp_path, &final_path)
            .with_context(|| format!("Failed to rename {} → {}", tmp_path.display(), final_path.display()))?;

        info!("GeoIP updater: {} updated ({} bytes)", filename, size);

        Ok((true, size))
    }
}

// ── Background auto-updater task ──────────────────────────────────────────────

/// Spawn a background tokio task that periodically checks for and downloads
/// xdb updates, then hot-reloads the in-process [`GeoIpService`].
///
/// The returned `JoinHandle` should be kept alive for the process lifetime
/// (e.g. via `std::mem::forget`) or stored somewhere that outlives the task.
///
/// The first update check runs after one full `interval`; it does **not** run
/// immediately at startup (the engine already loaded the current files).
pub fn spawn_auto_updater(
    geoip: Arc<GeoIpService>,
    config: GeoIpAutoUpdateConfig,
    data_dir: PathBuf,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let updater = XdbUpdater::new(data_dir, config.source_url.clone());
        let interval = parse_duration(&config.interval);

        info!(
            "GeoIP auto-updater: started (interval={}, source={})",
            config.interval, config.source_url
        );

        loop {
            tokio::time::sleep(interval).await;

            match updater.update(&geoip).await {
                Ok(result) if result.ipv4_updated || result.ipv6_updated => {
                    info!(
                        "GeoIP xdb files updated — v4: {} bytes, v6: {} bytes",
                        result.ipv4_size, result.ipv6_size
                    );
                }
                Ok(_) => debug!("GeoIP xdb files already up to date"),
                Err(e) => warn!("GeoIP auto-update failed: {}", e),
            }
        }
    })
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Parse a human-friendly duration string into a [`Duration`].
///
/// Supported suffixes: `d` (days), `h` (hours), `m` (minutes), `s` (seconds).
/// Falls back to 7 days if the string is unrecognised.
pub fn parse_duration(s: &str) -> Duration {
    let s = s.trim();
    let (num_str, unit) = s
        .find(|c: char| c.is_alphabetic())
        .map_or((s, "s"), |pos| (&s[..pos], &s[pos..]));

    let n: u64 = num_str.parse().unwrap_or(7);

    let secs = match unit.to_lowercase().as_str() {
        "d" => n * 86_400,
        "h" => n * 3_600,
        "m" => n * 60,
        "s" => n,
        _ => {
            warn!("GeoIP updater: unrecognised duration '{}', defaulting to 7d", s);
            7 * 86_400
        }
    };

    Duration::from_secs(secs)
}

// ── Display helper ────────────────────────────────────────────────────────────

/// Return a human-readable summary of an xdb file at `path`.
pub fn xdb_file_info(path: &Path) -> String {
    if !path.exists() {
        return format!("{} (not found)", path.display());
    }

    let meta = match std::fs::metadata(path) {
        Ok(m) => m,
        Err(e) => return format!("{} (stat error: {})", path.display(), e),
    };

    let size = meta.len();
    let modified = meta.modified().map_or_else(
        |_| "unknown".to_string(),
        |t| {
            let secs = t.duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs();
            // Format as YYYY-MM-DD HH:MM:SS UTC (no chrono dep needed here)
            // SAFETY: secs from UNIX_EPOCH will not exceed i64::MAX in practice
            #[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
            let ts = secs as i64;
            chrono::DateTime::from_timestamp(ts, 0).map_or_else(
                || "unknown".to_string(),
                |d| d.format("%Y-%m-%d %H:%M:%S UTC").to_string(),
            )
        },
    );

    format!("{} ({} bytes, modified {})", path.display(), size, modified)
}

#[cfg(test)]
mod tests {
    //! Expected [`Duration`]s use `from_secs` with the same multipliers as
    //! [`parse_duration`] (`n * 86_400`, `n * 3_600`, …), not `from_hours` /
    //! `from_mins`, so tests stay aligned with production and older stable
    //! toolchains.
    #![allow(clippy::duration_suboptimal_units)]

    use super::*;

    #[test]
    fn parse_duration_days() {
        assert_eq!(parse_duration("7d"), Duration::from_secs(7 * 86_400));
    }

    #[test]
    fn parse_duration_hours() {
        assert_eq!(parse_duration("12h"), Duration::from_secs(12 * 3_600));
    }

    #[test]
    fn parse_duration_minutes() {
        assert_eq!(parse_duration("30m"), Duration::from_secs(30 * 60));
    }

    #[test]
    fn parse_duration_seconds() {
        assert_eq!(parse_duration("60s"), Duration::from_secs(60));
    }

    #[test]
    fn parse_duration_fallback() {
        // Unrecognised unit falls back to 7 days.
        assert_eq!(parse_duration("3x"), Duration::from_secs(7 * 86_400));
    }

    #[test]
    fn parse_duration_no_unit_treated_as_seconds() {
        // No unit suffix: parser treats the whole string as seconds.
        assert_eq!(parse_duration("45"), Duration::from_secs(45));
    }

    #[test]
    fn parse_duration_unparseable_number_falls_back_to_seven_days() {
        // No leading digits → unit becomes "zh" (unrecognised) → 7-day default.
        assert_eq!(parse_duration("zh"), Duration::from_secs(7 * 86_400));
    }

    #[test]
    fn xdb_file_info_reports_missing_file() {
        let path = std::path::Path::new("/nonexistent/doesnotexist.xdb");
        let info = xdb_file_info(path);
        assert!(info.contains("not found"));
    }

    #[test]
    fn xdb_file_info_reports_size_for_existing_file() {
        let tmp = tempfile::tempdir().expect("tmp");
        let path = tmp.path().join("dummy.xdb");
        std::fs::write(&path, b"abc").expect("write");
        let info = xdb_file_info(&path);
        assert!(info.contains("bytes"));
        assert!(info.contains("modified"));
    }

    #[test]
    fn updater_constructors_set_url_and_dir() {
        let tmp = tempfile::tempdir().expect("tmp");
        let custom = XdbUpdater::new(tmp.path().to_path_buf(), "https://example.com".to_string());
        assert_eq!(custom.github_base_url, "https://example.com");
        assert_eq!(custom.data_dir, tmp.path());

        let default = XdbUpdater::with_default_url(tmp.path().to_path_buf());
        assert_eq!(default.github_base_url, DEFAULT_GITHUB_BASE_URL);
    }

    #[tokio::test]
    async fn check_update_returns_true_when_files_missing() {
        let tmp = tempfile::tempdir().expect("tmp");
        // Use a non-routable URL so HEAD requests never hit the network for
        // the size-comparison branch — but since both files are missing, the
        // function returns Ok(true) before issuing a request (and before the
        // source URL is validated).
        let updater = XdbUpdater::new(tmp.path().to_path_buf(), "http://127.0.0.1:1".to_string());
        let res = updater.check_update().await.expect("missing files → Ok(true)");
        assert!(res);
    }

    /// Place dummy local xdb files so `check_update` proceeds to the network phase.
    fn write_dummy_xdb_files(dir: &Path) {
        std::fs::write(dir.join("ip2region_v4.xdb"), b"v4").expect("write v4");
        std::fs::write(dir.join("ip2region_v6.xdb"), b"v6").expect("write v6");
    }

    #[tokio::test]
    async fn check_update_rejects_private_host() {
        let tmp = tempfile::tempdir().expect("tmp");
        write_dummy_xdb_files(tmp.path());
        let updater = XdbUpdater::new(tmp.path().to_path_buf(), "http://127.0.0.1:9/data".to_string());
        let err = updater
            .check_update()
            .await
            .expect_err("loopback source must be rejected");
        assert!(err.to_string().contains("SSRF"), "unexpected error: {err:#}");
    }

    #[tokio::test]
    async fn download_rejects_private_host() {
        let tmp = tempfile::tempdir().expect("tmp");
        let updater = XdbUpdater::new(tmp.path().to_path_buf(), "http://10.0.0.1/data".to_string());
        let err = updater
            .download()
            .await
            .expect_err("private-range source must be rejected");
        assert!(err.to_string().contains("SSRF"), "unexpected error: {err:#}");
        assert!(!tmp.path().join("ip2region_v4.xdb").exists());
    }

    #[tokio::test]
    async fn download_rejects_imds_host() {
        let tmp = tempfile::tempdir().expect("tmp");
        let updater = XdbUpdater::new(tmp.path().to_path_buf(), "http://169.254.169.254/latest".to_string());
        let err = updater.download().await.expect_err("IMDS source must be rejected");
        assert!(err.to_string().contains("SSRF"), "unexpected error: {err:#}");
    }

    /// A production-shaped client for local-server tests.
    ///
    /// `build_validated_client` rejects loopback URLs by design, so the full
    /// `download()` wiring cannot be pointed at a local test server. These
    /// tests build the client through the same helper against a public
    /// IP-literal placeholder (never contacted) — same redirect policy,
    /// timeouts, and UA — then drive `download_one` at the local server.
    fn production_shaped_client() -> reqwest::Client {
        build_validated_client(
            "http://93.184.216.34/",
            CONNECT_TIMEOUT,
            Duration::from_secs(30),
            USER_AGENT,
        )
        .expect("public placeholder URL must validate")
    }

    #[tokio::test]
    async fn download_one_rejects_oversized_response() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        // Body one byte over the cap; the advertised Content-Length triggers
        // the fast-reject before any body byte is read.
        #[allow(clippy::cast_possible_truncation)]
        let body = vec![0u8; MAX_XDB_RESPONSE_SIZE as usize + 1];
        Mock::given(method("GET"))
            .and(path("/ip2region_v4.xdb"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(body))
            .mount(&server)
            .await;

        let tmp = tempfile::tempdir().expect("tmp");
        let updater = XdbUpdater::new(tmp.path().to_path_buf(), server.uri());

        let err = updater
            .download_one(&production_shaped_client(), "ip2region_v4.xdb")
            .await
            .expect_err("oversized response must be rejected");
        assert!(err.to_string().contains("too large"), "unexpected error: {err:#}");
        assert!(!tmp.path().join("ip2region_v4.xdb").exists(), "no final file");
        assert!(!tmp.path().join("ip2region_v4.xdb.tmp").exists(), "no tmp left behind");
    }

    #[tokio::test]
    async fn download_one_does_not_follow_redirect() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/ip2region_v4.xdb"))
            .respond_with(ResponseTemplate::new(302).insert_header("Location", "/elsewhere"))
            .mount(&server)
            .await;
        // The redirect target must never be fetched (verified on server drop).
        Mock::given(method("GET"))
            .and(path("/elsewhere"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"payload".to_vec()))
            .expect(0)
            .mount(&server)
            .await;

        let tmp = tempfile::tempdir().expect("tmp");
        let updater = XdbUpdater::new(tmp.path().to_path_buf(), server.uri());

        let err = updater
            .download_one(&production_shaped_client(), "ip2region_v4.xdb")
            .await
            .expect_err("redirect must surface as an error");
        assert!(err.to_string().contains("302"), "unexpected error: {err:#}");
        assert!(!tmp.path().join("ip2region_v4.xdb").exists());
    }

    #[tokio::test]
    async fn download_one_rejects_invalid_xdb_and_cleans_tmp() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/ip2region_v4.xdb"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"not a real xdb file".to_vec()))
            .mount(&server)
            .await;

        let tmp = tempfile::tempdir().expect("tmp");
        let updater = XdbUpdater::new(tmp.path().to_path_buf(), server.uri());

        let err = updater
            .download_one(&production_shaped_client(), "ip2region_v4.xdb")
            .await
            .expect_err("invalid xdb must fail Searcher validation");
        assert!(err.to_string().contains("validation"), "unexpected error: {err:#}");
        assert!(!tmp.path().join("ip2region_v4.xdb").exists(), "no final file");
        assert!(!tmp.path().join("ip2region_v4.xdb.tmp").exists(), "tmp cleaned up");
    }
}
