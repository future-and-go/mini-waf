//! Default-value coverage for every substruct in `waf_common::config`.
//!
//! Each test instantiates the `Default` impl and asserts the
//! field values match the documented defaults so accidental drift breaks here.

#![allow(clippy::redundant_clone, clippy::no_effect_underscore_binding)]

use waf_common::config::{
    ApiConfig, AppConfig, CacheBackendKind, CacheConfig, ClusterConfig, ClusterCryptoConfig, ClusterElectionConfig,
    ClusterHealthConfig, ClusterSyncConfig, CommunityConfig, CrowdSecConfig, EmbeddedValkeyConfig,
    GeoIpAutoUpdateConfig, GeoIpConfig, Http3Config, NodeRole, ProxyConfig, RateLimitFileRef, RuleSourceEntry,
    RulesConfig, SecurityConfig, SqliScanConfig, StorageConfig, ValkeyClientConfig, VictoriaLogsConfig,
};

#[test]
fn proxy_config_defaults() {
    let p = ProxyConfig::default();
    assert_eq!(p.listen_addr, "0.0.0.0:80");
    assert_eq!(p.listen_addr_tls, "0.0.0.0:443");
    assert!(p.worker_threads.is_none());
    assert!(!p.trust_proxy_headers);
    assert!(p.trusted_proxies.is_empty());
    assert!(p.tls_cert_pem.is_none());
    assert!(p.tls_key_pem.is_none());
}

#[test]
fn api_storage_defaults() {
    let a = ApiConfig::default();
    assert_eq!(a.listen_addr, "127.0.0.1:9527");
    let s = StorageConfig::default();
    assert!(s.database_url.starts_with("postgresql://"));
    assert_eq!(s.max_connections, 20);
}

#[test]
fn cache_config_defaults() {
    let c = CacheConfig::default();
    assert!(c.enabled);
    assert_eq!(c.max_size_mb, 256);
    assert_eq!(c.default_ttl_secs, 60);
    assert_eq!(c.max_ttl_secs, 3600);
    assert!(c.rules_path.is_none());
    assert_eq!(c.backend, CacheBackendKind::Memory);
    let _embedded = c.embedded.clone();
    let _valkey = c.valkey.clone();
}

#[test]
fn embedded_valkey_defaults() {
    let e = EmbeddedValkeyConfig::default();
    assert!(e.binary_path.is_empty());
    assert_eq!(e.data_dir, "/tmp/prx-valkey");
    assert!(e.extra_args.is_empty());
}

#[test]
fn valkey_client_defaults() {
    let v = ValkeyClientConfig::default();
    assert_eq!(v.seeds, vec!["127.0.0.1:6379".to_string()]);
    assert!(v.password.is_empty());
    assert_eq!(v.db, 0);
    assert!(!v.tls);
    assert!(v.tls_ca_cert.is_none());
    assert_eq!(v.pool_size, 4);
    assert_eq!(v.connect_timeout_ms, 2_000);
    assert_eq!(v.command_timeout_ms, 500);
    assert_eq!(v.circuit_breaker_threshold, 5);
    assert_eq!(v.circuit_breaker_reset_secs, 30);
    assert!(v.fallback_to_memory);
}

#[test]
fn http3_defaults() {
    let h = Http3Config::default();
    assert!(!h.enabled);
    assert_eq!(h.listen_addr, "0.0.0.0:443");
    assert!(h.cert_pem.is_none());
    assert!(h.key_pem.is_none());
    assert!(h.upstream_tls_verify);
}

#[test]
fn security_defaults() {
    let s = SecurityConfig::default();
    assert!(s.admin_ip_allowlist.is_empty());
    assert_eq!(s.max_request_body_bytes, 10 * 1024 * 1024);
    assert_eq!(s.api_rate_limit_rps, 0);
    assert!(s.cors_origins.is_empty());
}

#[test]
fn crowdsec_defaults() {
    let c = CrowdSecConfig::default();
    assert!(!c.enabled);
    assert_eq!(c.mode, "bouncer");
    assert_eq!(c.lapi_url, "http://127.0.0.1:8080");
    assert!(c.api_key.is_empty());
    assert_eq!(c.update_frequency_secs, 10);
    assert_eq!(c.cache_ttl_secs, 0);
    assert_eq!(c.fallback_action, "allow");
    assert!(c.scenarios_containing.is_empty());
    assert!(c.scenarios_not_containing.is_empty());
    assert!(c.appsec_endpoint.is_none());
    assert!(c.appsec_key.is_none());
    assert_eq!(c.appsec_timeout_ms, 500);
    assert!(c.pusher_login.is_none());
    assert!(c.pusher_password.is_none());
}

#[test]
fn rules_defaults() {
    let r = RulesConfig::default();
    assert_eq!(r.dir, "rules/");
    assert!(r.hot_reload);
    assert_eq!(r.reload_debounce_ms, 500);
    assert!(r.enable_builtin_owasp);
    assert!(r.enable_builtin_bot);
    assert!(r.enable_builtin_scanner);
    assert!(r.sources.is_empty());
}

#[test]
fn geoip_and_auto_update_defaults() {
    let g = GeoIpConfig::default();
    assert!(!g.enabled);
    assert_eq!(g.ipv4_xdb_path, "data/ip2region_v4.xdb");
    assert_eq!(g.ipv6_xdb_path, "data/ip2region_v6.xdb");
    assert_eq!(g.cache_policy, "full_memory");
    let au = GeoIpAutoUpdateConfig::default();
    assert!(!au.enabled);
    assert_eq!(au.interval, "7d");
    assert!(au.source_url.contains("github"));
}

#[test]
fn community_defaults() {
    let c = CommunityConfig::default();
    assert!(!c.enabled);
    assert_eq!(c.server_url, "https://community.openprx.dev");
    assert!(c.api_key.is_none());
    assert!(c.machine_id.is_none());
    assert!(c.public_key.is_none());
    assert_eq!(c.batch_size, 50);
    assert_eq!(c.flush_interval_secs, 30);
    assert_eq!(c.sync_interval_secs, 300);
}

#[test]
fn sqli_defaults_and_denylist() {
    let s = SqliScanConfig::default();
    assert!(s.scan_headers);
    assert!(s.header_denylist.contains(&"cookie".to_string()));
    assert!(s.header_denylist.contains(&"host".to_string()));
    assert!(s.header_allowlist.is_empty());
    assert_eq!(s.header_scan_cap, 4096);
    assert_eq!(s.json_parse_cap, 256 * 1024);
}

#[test]
fn cluster_subconfig_defaults() {
    let c = ClusterConfig::default();
    assert!(!c.enabled);
    assert_eq!(c.role, "auto");
    assert_eq!(c.listen_addr, "0.0.0.0:16851");
    assert!(c.seeds.is_empty());

    let cr = ClusterCryptoConfig::default();
    assert!(cr.auto_generate);
    assert_eq!(cr.ca_validity_days, 3650);
    assert_eq!(cr.node_validity_days, 365);
    assert_eq!(cr.renewal_before_days, 7);

    let s = ClusterSyncConfig::default();
    assert_eq!(s.rules_interval_secs, 10);
    assert_eq!(s.events_batch_size, 100);
    assert_eq!(s.events_queue_size, 10_000);

    let e = ClusterElectionConfig::default();
    assert_eq!(e.timeout_min_ms, 150);
    assert_eq!(e.timeout_max_ms, 300);
    assert!((e.phi_dead - 12.0).abs() < f64::EPSILON);

    let h = ClusterHealthConfig::default();
    assert_eq!(h.check_interval_secs, 5);
    assert_eq!(h.max_missed_heartbeats, 3);
}

#[test]
fn vlogs_and_app_defaults() {
    let v = VictoriaLogsConfig::default();
    assert!(!v.enabled);
    assert_eq!(v.listen_addr, "127.0.0.1:9428");
    assert_eq!(v.retention_period, "30d");
    assert!(v.auto_install);
    assert_eq!(v.batch_size, 100);
    assert_eq!(v.flush_interval_ms, 1000);
    assert_eq!(v.channel_capacity, 10_000);

    let a = AppConfig::default();
    assert!(a.hosts.is_empty());
    assert!(a.cluster.is_none());
    let _r: RateLimitFileRef = a.rate_limit;
}

#[test]
fn rule_source_entry_serde() {
    let toml = r#"name = "rs"
path = "rules/local""#;
    let e: RuleSourceEntry = toml::from_str(toml).unwrap();
    assert_eq!(e.name, "rs");
    assert_eq!(e.format, "yaml");
    assert_eq!(e.update_interval, 86400);
}

#[test]
fn cache_backend_kind_serde_lowercase() {
    let m: CacheBackendKind = serde_json::from_str("\"memory\"").unwrap();
    assert_eq!(m, CacheBackendKind::Memory);
    let e: CacheBackendKind = serde_json::from_str("\"embedded\"").unwrap();
    assert_eq!(e, CacheBackendKind::Embedded);
    let s: CacheBackendKind = serde_json::from_str("\"standalone\"").unwrap();
    assert_eq!(s, CacheBackendKind::Standalone);
    let c: CacheBackendKind = serde_json::from_str("\"cluster\"").unwrap();
    assert_eq!(c, CacheBackendKind::Cluster);
}

#[test]
fn node_role_serde_snake_case() {
    let m: NodeRole = serde_json::from_str("\"main\"").unwrap();
    assert_eq!(m, NodeRole::Main);
    let w: NodeRole = serde_json::from_str("\"worker\"").unwrap();
    assert_eq!(w, NodeRole::Worker);
    let c: NodeRole = serde_json::from_str("\"candidate\"").unwrap();
    assert_eq!(c, NodeRole::Candidate);
}
