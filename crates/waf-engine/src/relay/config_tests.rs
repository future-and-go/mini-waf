//! Unit tests for `RelayConfig` — kept in a sibling file to keep `config.rs`
//! ≤200 LOC per phase-01 NFR.

#![allow(clippy::duration_suboptimal_units)]

use std::time::Duration;

use super::*;

const SAMPLE_YAML: &str = r"
relay_detection:
  trusted_proxies:
    - 10.0.0.0/8
    - 173.245.48.0/20
  max_chain_depth: 3
  headers:
    forwarded_for: [X-Forwarded-For, X-Real-IP]
  asn:
    provider: ipinfo_lite
    mmdb_path: /var/lib/waf/ipinfo-lite.mmdb
    datacenter_lists:
      - /etc/waf/intel/x4bnet-datacenter.txt
    refresh:
      url: https://ipinfo.io/data/free/country_asn.mmdb
      interval: 24h
      etag: true
  tor:
    list_path: /var/lib/waf/tor-exit.txt
    refresh:
      url: https://check.torproject.org/torbulkexitlist
      interval: 1h
      etag: true
  signals:
    enabled: [xff_validator, proxy_chain, asn_classifier, tor_exit]
    risk_score_delta:
      xff_spoof_private: 30
      tor_exit: 50
";

#[test]
fn parses_brainstorm_sample() {
    let cfg = RelayConfig::from_yaml_str(SAMPLE_YAML).expect("sample must parse");
    assert_eq!(cfg.trusted_proxies.len(), 2);
    assert_eq!(cfg.max_chain_depth, 3);
    assert_eq!(cfg.headers.forwarded_for.len(), 2);
    assert_eq!(cfg.asn.datacenter_lists.len(), 1);
    assert_eq!(
        cfg.asn.refresh.as_ref().and_then(|r| r.interval),
        Some(Duration::from_secs(24 * 60 * 60))
    );
    assert_eq!(
        cfg.tor.refresh.as_ref().and_then(|r| r.interval),
        Some(Duration::from_secs(3600))
    );
    assert_eq!(cfg.signals.enabled.len(), 4);
    assert_eq!(cfg.signals.risk_score_delta.get("tor_exit"), Some(&50));
}

#[test]
fn empty_doc_yields_disabled_snapshot() {
    let cfg = RelayConfig::from_yaml_str("").expect("empty parses");
    assert!(cfg.signals.enabled.is_empty());
    assert_eq!(cfg.max_chain_depth, 3);
    assert_eq!(cfg.headers.forwarded_for.len(), 2);
}

#[test]
fn missing_signals_enabled_is_empty() {
    let yaml = "relay_detection:\n  max_chain_depth: 2\n";
    let cfg = RelayConfig::from_yaml_str(yaml).expect("must parse");
    assert!(cfg.signals.enabled.is_empty());
}

#[test]
fn rejects_invalid_cidr() {
    let yaml = "relay_detection:\n  trusted_proxies:\n    - 999.0.0.0/8\n";
    let err = RelayConfig::from_yaml_str(yaml).expect_err("bad CIDR must fail");
    let msg = format!("{err:#}");
    assert!(msg.contains("trusted_proxies") || msg.contains("invalid"), "got: {msg}");
}

#[test]
fn rejects_zero_max_chain_depth() {
    let yaml = "relay_detection:\n  max_chain_depth: 0\n";
    let err = RelayConfig::from_yaml_str(yaml).expect_err("0 must fail");
    assert!(format!("{err:#}").contains("max_chain_depth"));
}

#[test]
fn rejects_invalid_header_name() {
    let yaml = "relay_detection:\n  headers:\n    forwarded_for: [\"Bad Header!\"]\n";
    let err = RelayConfig::from_yaml_str(yaml).expect_err("bad header must fail");
    assert!(format!("{err:#}").contains("forwarded_for"));
}

#[test]
fn rejects_duplicate_signal() {
    let yaml = "relay_detection:\n  signals:\n    enabled: [tor_exit, tor_exit]\n";
    let err = RelayConfig::from_yaml_str(yaml).expect_err("dup must fail");
    assert!(format!("{err:#}").contains("duplicate"));
}

#[test]
fn rejects_bad_duration_unit() {
    let yaml = "relay_detection:\n  tor:\n    refresh:\n      interval: 24x\n";
    let err = RelayConfig::from_yaml_str(yaml).expect_err("bad unit must fail");
    assert!(format!("{err:#}").contains("unit") || format!("{err:#}").contains("24x"));
}
