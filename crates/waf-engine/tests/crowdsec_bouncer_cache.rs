//! Tests for `crowdsec::cache::DecisionCache` — bouncer cache hit/miss/expired/eviction.
//!
//! Covers: exact-IP hit, CIDR-range hit, miss, TTL expiry via cleanup_expired,
//! apply_stream new+deleted, scenario filter inclusion/exclusion,
//! list_decisions, stats hit_rate, invalid IP/CIDR silently skipped,
//! compute_expiry with override TTL vs decision duration.

use std::net::IpAddr;
use std::time::Duration;

use waf_engine::crowdsec::cache::DecisionCache;
use waf_engine::crowdsec::config::CrowdSecConfig;
use waf_engine::crowdsec::models::{Decision, DecisionStream};

fn decision(scope: &str, value: &str, scenario: &str) -> Decision {
    Decision {
        id: 1,
        origin: "crowdsec".to_string(),
        scope: scope.to_string(),
        value: value.to_string(),
        type_: "ban".to_string(),
        scenario: scenario.to_string(),
        duration: Some("1h".to_string()),
        created_at: None,
    }
}

fn stream(decisions: Vec<Decision>) -> DecisionStream {
    DecisionStream {
        new: Some(decisions),
        deleted: None,
    }
}

// ── exact-IP hit ──────────────────────────────────────────────────────────────

#[test]
fn exact_ip_hit_increments_hits_counter() {
    let cache = DecisionCache::new(60);
    cache.apply_stream(
        stream(vec![decision("Ip", "10.0.0.1", "brute")]),
        &CrowdSecConfig::default(),
    );

    let ip: IpAddr = "10.0.0.1".parse().expect("ip");
    let result = cache.check_ip(&ip);
    assert!(result.is_some());
    assert_eq!(cache.hits.load(std::sync::atomic::Ordering::Relaxed), 1);
}

// ── CIDR range hit ────────────────────────────────────────────────────────────

#[test]
fn cidr_range_hit_for_address_within_range() {
    let cache = DecisionCache::new(60);
    cache.apply_stream(
        stream(vec![decision("Range", "192.168.1.0/24", "scan")]),
        &CrowdSecConfig::default(),
    );

    let ip: IpAddr = "192.168.1.100".parse().expect("ip");
    assert!(cache.check_ip(&ip).is_some());
}

#[test]
fn cidr_range_miss_for_address_outside_range() {
    let cache = DecisionCache::new(60);
    cache.apply_stream(
        stream(vec![decision("Range", "192.168.1.0/24", "scan")]),
        &CrowdSecConfig::default(),
    );

    let ip: IpAddr = "192.168.2.1".parse().expect("ip");
    assert!(cache.check_ip(&ip).is_none());
}

// ── miss counter ──────────────────────────────────────────────────────────────

#[test]
fn miss_increments_misses_counter() {
    let cache = DecisionCache::new(60);
    let ip: IpAddr = "8.8.8.8".parse().expect("ip");
    assert!(cache.check_ip(&ip).is_none());
    assert_eq!(cache.misses.load(std::sync::atomic::Ordering::Relaxed), 1);
}

// ── TTL expiry ────────────────────────────────────────────────────────────────

#[test]
fn expired_entry_removed_by_cleanup() {
    let cache = DecisionCache::new(0); // use decision duration
    let mut d = decision("Ip", "1.2.3.4", "test");
    d.duration = Some("0s".to_string()); // immediate expiry

    cache.apply_stream(stream(vec![d]), &CrowdSecConfig::default());
    // Sleep briefly so expires_at is in the past.
    std::thread::sleep(Duration::from_millis(10));
    cache.cleanup_expired();

    let ip: IpAddr = "1.2.3.4".parse().expect("ip");
    assert!(cache.check_ip(&ip).is_none());
    assert_eq!(cache.stats().total_cached, 0);
}

// ── apply_stream delete ───────────────────────────────────────────────────────

#[test]
fn deleted_decisions_are_removed() {
    let cache = DecisionCache::new(60);
    cache.apply_stream(
        stream(vec![
            decision("Ip", "1.0.0.1", "s"),
            decision("Range", "10.0.0.0/8", "s"),
            decision("Country", "RU", "s"),
        ]),
        &CrowdSecConfig::default(),
    );
    assert_eq!(cache.stats().total_cached, 3);

    cache.apply_stream(
        DecisionStream {
            new: None,
            deleted: Some(vec![
                decision("Ip", "1.0.0.1", "s"),
                decision("Range", "10.0.0.0/8", "s"),
                decision("Country", "RU", "s"),
            ]),
        },
        &CrowdSecConfig::default(),
    );
    assert_eq!(cache.stats().total_cached, 0);
}

// ── scenario filters ──────────────────────────────────────────────────────────

#[test]
fn scenarios_containing_filter_only_includes_matching() {
    let cache = DecisionCache::new(60);
    let config = CrowdSecConfig {
        scenarios_containing: vec!["brute".to_string()],
        ..CrowdSecConfig::default()
    };
    cache.apply_stream(
        stream(vec![
            decision("Ip", "1.0.0.1", "ssh-bruteforce"),
            decision("Ip", "1.0.0.2", "port-scan"),
        ]),
        &config,
    );
    assert_eq!(cache.stats().total_cached, 1);
    assert!(cache.check_ip(&"1.0.0.1".parse::<IpAddr>().expect("ip")).is_some());
    assert!(cache.check_ip(&"1.0.0.2".parse::<IpAddr>().expect("ip")).is_none());
}

#[test]
fn scenarios_not_containing_filter_excludes_matching() {
    let cache = DecisionCache::new(60);
    let config = CrowdSecConfig {
        scenarios_not_containing: vec!["whitelist".to_string()],
        ..CrowdSecConfig::default()
    };
    cache.apply_stream(
        stream(vec![
            decision("Ip", "2.0.0.1", "brute-whitelist"),
            decision("Ip", "2.0.0.2", "brute-force"),
        ]),
        &config,
    );
    assert_eq!(cache.stats().total_cached, 1);
    assert!(cache.check_ip(&"2.0.0.2".parse::<IpAddr>().expect("ip")).is_some());
}

// ── list_decisions ────────────────────────────────────────────────────────────

#[test]
fn list_decisions_returns_all_active_entries() {
    let cache = DecisionCache::new(60);
    cache.apply_stream(
        stream(vec![
            decision("Ip", "5.0.0.1", "s"),
            decision("Range", "172.16.0.0/12", "s"),
            decision("Country", "CN", "s"),
        ]),
        &CrowdSecConfig::default(),
    );
    assert_eq!(cache.list_decisions().len(), 3);
}

// ── stats hit_rate ────────────────────────────────────────────────────────────

#[test]
fn stats_hit_rate_zero_when_no_lookups() {
    let cache = DecisionCache::new(60);
    assert!((cache.stats().hit_rate_pct - 0.0).abs() < 1e-9);
}

#[test]
fn stats_hit_rate_100_when_all_hits() {
    let cache = DecisionCache::new(60);
    cache.apply_stream(stream(vec![decision("Ip", "3.3.3.3", "s")]), &CrowdSecConfig::default());
    let ip: IpAddr = "3.3.3.3".parse().expect("ip");
    cache.check_ip(&ip);
    let stats = cache.stats();
    assert!((stats.hit_rate_pct - 100.0).abs() < 1e-3);
}

// ── invalid scope values silently skipped ────────────────────────────────────

#[test]
fn invalid_ip_value_silently_skipped() {
    let cache = DecisionCache::new(60);
    cache.apply_stream(
        stream(vec![decision("Ip", "not-an-ip", "s")]),
        &CrowdSecConfig::default(),
    );
    assert_eq!(cache.stats().total_cached, 0);
}

#[test]
fn invalid_cidr_value_silently_skipped() {
    let cache = DecisionCache::new(60);
    cache.apply_stream(
        stream(vec![decision("Range", "definitely-not-cidr", "s")]),
        &CrowdSecConfig::default(),
    );
    assert_eq!(cache.stats().total_cached, 0);
}

// ── override TTL ignores decision duration ────────────────────────────────────

#[test]
fn override_ttl_uses_config_secs_not_decision_duration() {
    // cache_ttl_secs=3600 → entries expire in 1h regardless of duration="0s"
    let cache = DecisionCache::new(3600);
    let mut d = decision("Ip", "6.6.6.6", "s");
    d.duration = Some("0s".to_string()); // would expire immediately without override

    cache.apply_stream(stream(vec![d]), &CrowdSecConfig::default());
    // Entry should NOT be expired immediately because override TTL = 3600s.
    let ip: IpAddr = "6.6.6.6".parse().expect("ip");
    assert!(cache.check_ip(&ip).is_some());
}

// ── country/other scope ───────────────────────────────────────────────────────

#[test]
fn country_scope_stored_in_other_decisions() {
    let cache = DecisionCache::new(60);
    cache.apply_stream(
        stream(vec![decision("Country", "US", "geo-block")]),
        &CrowdSecConfig::default(),
    );
    assert_eq!(cache.stats().total_cached, 1);
    // IP lookup won't find it (different scope), but total_cached reflects it.
    let ip: IpAddr = "7.7.7.7".parse().expect("ip");
    assert!(cache.check_ip(&ip).is_none());
}
