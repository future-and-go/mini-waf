//! `GeoIP` lookup service backed by ip2region xdb files.
//!
//! Uses `ArcSwapOption` for each searcher so the underlying xdb files can be
//! atomically replaced at runtime (hot-reload) without any reader downtime.

use std::net::IpAddr;
use std::sync::Arc;

use arc_swap::ArcSwapOption;
use ip2region::{CachePolicy, Searcher};
use tracing::{info, warn};
use waf_common::GeoIpInfo;

/// Thread-safe `GeoIP` lookup service with hot-reload support.
///
/// Construct once (during engine initialisation) then share via `Arc<GeoIpService>`.
/// The internal searchers can be atomically swapped at any time via [`reload`].
pub struct GeoIpService {
    /// Searcher loaded with the IPv4 xdb file, if available.
    ipv4: ArcSwapOption<Searcher>,
    /// Searcher loaded with the IPv6 xdb file, if available.
    ipv6: ArcSwapOption<Searcher>,
    /// Path to the IPv4 xdb file (used during reload).
    ipv4_path: String,
    /// Path to the IPv6 xdb file (used during reload).
    ipv6_path: String,
    /// Cache policy used when loading or reloading searchers.
    cache_policy: CachePolicy,
}

impl GeoIpService {
    /// Initialise the service.
    ///
    /// `ipv4_path` / `ipv6_path` may point to files that don't exist yet;
    /// missing files are silently skipped and the corresponding searcher is
    /// left as `None`.  `GeoIP` lookups for that address family will return
    /// an empty `GeoIpInfo`.
    pub fn init(ipv4_path: &str, ipv6_path: &str, cache_policy: CachePolicy) -> anyhow::Result<Self> {
        let ipv4 = load_searcher(ipv4_path, cache_policy, "IPv4");
        let ipv6 = load_searcher(ipv6_path, cache_policy, "IPv6");

        if ipv4.is_none() && ipv6.is_none() {
            warn!(
                "GeoIP: neither IPv4 nor IPv6 xdb files could be loaded; \
                 GeoIP lookups will be disabled. \
                 Run `prx-waf geoip download` to fetch the xdb files."
            );
        }

        Ok(Self {
            ipv4: ArcSwapOption::new(ipv4),
            ipv6: ArcSwapOption::new(ipv6),
            ipv4_path: ipv4_path.to_string(),
            ipv6_path: ipv6_path.to_string(),
            cache_policy,
        })
    }

    /// Returns `true` if at least one searcher is available.
    pub fn is_available(&self) -> bool {
        self.ipv4.load().is_some() || self.ipv6.load().is_some()
    }

    /// Hot-reload xdb files from disk without service interruption.
    ///
    /// Each address family is decided independently: a freshly loaded
    /// `Searcher` is atomically swapped in via `ArcSwapOption::store`; if the
    /// new load fails but a working searcher is currently present, the old
    /// searcher is **kept** (never replaced with `None`) and the failure is
    /// surfaced as an `Err`. A family that was `None` and stays `None`
    /// (first-time / degraded setup) is left untouched without error.
    ///
    /// Returns `Ok(true)` when at least one family swapped in a new searcher,
    /// `Ok(false)` when nothing loaded and nothing needed preserving, and
    /// `Err` naming the families whose working searcher was preserved because
    /// the new load failed.
    pub fn reload(&self) -> anyhow::Result<bool> {
        let mut swapped = false;
        let mut preserved: Vec<&str> = Vec::new();

        for (slot, path, label) in [
            (&self.ipv4, self.ipv4_path.as_str(), "IPv4"),
            (&self.ipv6, self.ipv6_path.as_str(), "IPv6"),
        ] {
            let new = load_searcher(path, self.cache_policy, label);
            match family_reload(new, slot.load().is_some()) {
                FamilyReload::Swap(searcher) => {
                    // Atomic swap — readers see either old or new, never a torn state.
                    slot.store(Some(searcher));
                    swapped = true;
                }
                FamilyReload::Preserve => preserved.push(label),
                FamilyReload::LeaveEmpty => {}
            }
        }

        if !preserved.is_empty() {
            anyhow::bail!(
                "GeoIP reload: new load failed for {}; kept previous searcher(s)",
                preserved.join(", ")
            );
        }
        if swapped {
            info!("GeoIP: hot-reloaded xdb files from disk");
        }
        Ok(swapped)
    }

    /// Look up the `GeoIP` information for `ip`.
    ///
    /// Loads the current searcher via `ArcSwapOption::load` (lock-free) and
    /// performs the lookup.  Returns a default (all-empty) `GeoIpInfo` if no
    /// searcher is available for the address family, or if the lookup fails.
    pub fn lookup(&self, ip: IpAddr) -> GeoIpInfo {
        // Load the current Arc for the correct address family.
        // The guard keeps the Arc alive for the duration of this lookup.
        let guard = match ip {
            IpAddr::V4(_) => self.ipv4.load(),
            IpAddr::V6(_) => self.ipv6.load(),
        };

        // Deref chain: Guard -> Option<Arc<Searcher>> -> Option<&Searcher>
        let Some(searcher) = guard.as_deref() else {
            return GeoIpInfo::default();
        };

        // Dispatch by family so the searcher gets the address value directly
        // — no per-lookup `ip.to_string()` allocation + re-parse.
        let result = match ip {
            IpAddr::V4(v4) => searcher.search(v4),
            IpAddr::V6(v6) => searcher.search(v6),
        };
        let raw = match result {
            Ok(r) => r,
            Err(e) => {
                warn!("GeoIP lookup failed for {}: {}", ip, e);
                return GeoIpInfo::default();
            }
        };

        parse_region(&raw)
    }
}

// ── Internal helpers ──────────────────────────────────────────────────────────

/// Per-family reload decision.
enum FamilyReload<T> {
    /// The new load succeeded — swap it in.
    Swap(T),
    /// The new load failed but a working searcher is present — keep it.
    Preserve,
    /// The new load failed and no searcher was present — stay empty.
    LeaveEmpty,
}

/// Decide what a reload does for one address family. A working searcher is
/// never replaced by a failed load; an empty slot stays empty without error.
fn family_reload<T>(new: Option<T>, current_present: bool) -> FamilyReload<T> {
    match new {
        Some(searcher) => FamilyReload::Swap(searcher),
        None if current_present => FamilyReload::Preserve,
        None => FamilyReload::LeaveEmpty,
    }
}

/// Attempt to open an xdb file and build a `Searcher`.
///
/// Returns `None` (with a log warning) if the file is absent or cannot be
/// opened, so callers can continue with degraded but functional behaviour.
fn load_searcher(path: &str, policy: CachePolicy, label: &str) -> Option<Arc<Searcher>> {
    if !std::path::Path::new(path).exists() {
        info!("GeoIP: {} xdb file not found at '{}' — skipping", label, path);
        return None;
    }

    match Searcher::new(path.to_string(), policy) {
        Ok(s) => {
            info!("GeoIP: {} searcher loaded from '{}'", label, path);
            Some(Arc::new(s))
        }
        Err(e) => {
            warn!("GeoIP: failed to load {} searcher from '{}': {}", label, path, e);
            None
        }
    }
}

/// Parse the ip2region result string into a `GeoIpInfo`.
///
/// The canonical format returned by ip2region is:
/// `Country|Province|City|ISP|iso-alpha2-code`
///
/// Fields may be `"0"` for unknown; those are normalised to an empty string.
fn parse_region(raw: &str) -> GeoIpInfo {
    if raw.is_empty() {
        return GeoIpInfo::default();
    }

    let mut parts = raw.splitn(5, '|');
    let country = normalize(parts.next().unwrap_or(""));
    let province = normalize(parts.next().unwrap_or(""));
    let city = normalize(parts.next().unwrap_or(""));
    let isp = normalize(parts.next().unwrap_or(""));
    // Uppercase at parse time so per-request geo checks can compare without
    // allocating (`geo_matches` uses plain `contains`).
    let mut iso_code = normalize(parts.next().unwrap_or(""));
    iso_code.make_ascii_uppercase();

    GeoIpInfo {
        country,
        province,
        city,
        isp,
        iso_code,
    }
}

/// Return an empty string for the ip2region sentinel value `"0"`.
#[inline]
fn normalize(s: &str) -> String {
    if s == "0" { String::new() } else { s.to_string() }
}

/// Convert a `cache_policy` string (from config) to ip2region's `CachePolicy`.
pub fn cache_policy_from_str(s: &str) -> CachePolicy {
    match s.to_lowercase().as_str() {
        "vector_index" => CachePolicy::VectorIndex,
        "no_cache" => CachePolicy::NoCache,
        _ => CachePolicy::FullMemory, // "full_memory" is the default
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_full_region() {
        let info = parse_region("China|Beijing|Beijing|CERNET|CN");
        assert_eq!(info.country, "China");
        assert_eq!(info.province, "Beijing");
        assert_eq!(info.city, "Beijing");
        assert_eq!(info.isp, "CERNET");
        assert_eq!(info.iso_code, "CN");
    }

    #[test]
    fn parse_unknown_fields() {
        let info = parse_region("China|0|0|ChinaNet|CN");
        assert_eq!(info.province, "");
        assert_eq!(info.city, "");
        assert_eq!(info.iso_code, "CN");
    }

    #[test]
    fn parse_empty() {
        let info = parse_region("");
        assert_eq!(info.country, "");
        assert_eq!(info.iso_code, "");
    }

    #[test]
    fn family_reload_swaps_on_successful_load() {
        assert!(matches!(family_reload(Some(1), true), FamilyReload::Swap(1)));
        assert!(matches!(family_reload(Some(1), false), FamilyReload::Swap(1)));
    }

    #[test]
    fn family_reload_preserves_working_searcher_on_failed_load() {
        assert!(matches!(family_reload::<i32>(None, true), FamilyReload::Preserve));
    }

    #[test]
    fn family_reload_leaves_empty_slot_empty() {
        assert!(matches!(family_reload::<i32>(None, false), FamilyReload::LeaveEmpty));
    }

    #[test]
    fn reload_with_no_files_and_no_searchers_is_ok_false() {
        let svc = GeoIpService::init("/nonexistent/v4.xdb", "/nonexistent/v6.xdb", CachePolicy::NoCache).expect("init");
        assert!(!svc.is_available());
        let result = svc.reload().expect("degraded reload must not error");
        assert!(!result, "nothing loaded and nothing preserved");
        assert!(!svc.is_available());
    }

    #[test]
    fn reload_with_corrupt_file_and_no_searcher_is_ok_false() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let path = dir.path().join("corrupt.xdb");
        std::fs::write(&path, b"not a real xdb file").expect("write");
        let path_str = path.to_str().expect("utf8 path");

        let svc = GeoIpService::init(path_str, "/nonexistent/v6.xdb", CachePolicy::NoCache).expect("init");
        assert!(!svc.is_available());
        // The corrupt file fails to load and no working searcher exists, so
        // this is the degraded first-time case — no error, slot stays empty.
        let result = svc.reload().expect("no working searcher to preserve");
        assert!(!result);
        assert!(!svc.is_available());
    }

    #[test]
    fn cache_policy_mapping() {
        assert!(matches!(cache_policy_from_str("full_memory"), CachePolicy::FullMemory));
        assert!(matches!(
            cache_policy_from_str("vector_index"),
            CachePolicy::VectorIndex
        ));
        assert!(matches!(cache_policy_from_str("no_cache"), CachePolicy::NoCache));
        assert!(matches!(cache_policy_from_str("unknown"), CachePolicy::FullMemory));
    }
}
