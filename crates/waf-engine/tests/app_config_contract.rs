//! Contract tests for the top-level application config (`AppConfig`) the
//! engine boots from: shipped defaults for every section, TOML/YAML loading
//! by file extension, admin-TLS validation at load time, and the proxy TLS
//! path pairing rule.
//!
//! These live in waf-engine so the engine's own suite pins the config
//! surface its subsystems (rules, crowdsec, geoip, community, sqli scan)
//! are wired from.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use waf_common::config::{AdminTlsMode, AppConfig, CacheBackendKind, ClusterConfig, load_config};

/// Smallest config file that satisfies the required (non-defaulted) fields.
const MINIMAL_TOML: &str = r#"
[proxy]
listen_addr = "127.0.0.1:8080"
listen_addr_tls = "127.0.0.1:8443"

[api]
listen_addr = "127.0.0.1:9001"

[storage]
database_url = "postgresql://user:pass@127.0.0.1:5432/waf"
max_connections = 5
"#;

const MINIMAL_YAML: &str = r#"
proxy:
  listen_addr: "127.0.0.1:8080"
  listen_addr_tls: "127.0.0.1:8443"
api:
  listen_addr: "127.0.0.1:9001"
storage:
  database_url: "postgresql://user:pass@127.0.0.1:5432/waf"
  max_connections: 5
"#;

fn write_config(dir: &tempfile::TempDir, name: &str, content: &str) -> String {
    let path = dir.path().join(name);
    std::fs::write(&path, content).expect("write config");
    path.to_str().expect("utf8 path").to_string()
}

// ── Shipped defaults ───────────────────────────────────────────────────────────

#[test]
fn app_config_default_composes_section_defaults() {
    let c = AppConfig::default();
    assert_eq!(c.proxy.listen_addr, "0.0.0.0:80");
    assert_eq!(c.proxy.listen_addr_tls, "0.0.0.0:443");
    assert!(c.proxy.worker_threads.is_none());
    assert!(!c.proxy.trust_proxy_headers);
    assert_eq!(c.api.listen_addr, "127.0.0.1:9527");
    assert_eq!(
        c.storage.database_url,
        "postgresql://prx_waf:prx_waf@127.0.0.1:5432/prx_waf"
    );
    assert_eq!(c.storage.max_connections, 20);
    assert!(c.hosts.is_empty());
    assert!(c.cluster.is_none(), "standalone by default");
    assert!(c.panel.config_path.is_none());
    assert!(c.rate_limit.config_path.is_none());
    assert!(c.tiered_protection.config_path.is_none());
}

#[test]
fn rules_defaults_enable_builtins_and_hot_reload() {
    let r = AppConfig::default().rules;
    assert_eq!(r.dir, "rules/");
    assert!(r.hot_reload);
    assert_eq!(r.reload_debounce_ms, 500);
    assert!(r.enable_builtin_owasp);
    assert!(r.enable_builtin_bot);
    assert!(r.enable_builtin_scanner);
    assert!(r.sources.is_empty());
}

#[test]
fn crowdsec_defaults_are_disabled_bouncer_failing_open() {
    let cs = AppConfig::default().crowdsec;
    assert!(!cs.enabled);
    assert_eq!(cs.mode, "bouncer");
    assert_eq!(cs.lapi_url, "http://127.0.0.1:8080");
    assert_eq!(cs.update_frequency_secs, 10);
    assert_eq!(cs.fallback_action, "allow");
    assert_eq!(cs.appsec_timeout_ms, 500);
    assert!(cs.appsec_endpoint.is_none());
}

#[test]
fn admin_tls_defaults_to_auto_https_with_redirect() {
    let tls = AppConfig::default().api.tls;
    assert!(tls.enabled);
    assert_eq!(tls.mode, AdminTlsMode::Auto);
    assert_eq!(tls.extra_sans, vec!["localhost", "127.0.0.1", "::1"]);
    assert_eq!(tls.validity_days, 365);
    assert_eq!(tls.renewal_before_days, 30);
    assert_eq!(tls.min_tls_version, "1.2");
    assert!(tls.http_redirect);
    assert!(tls.http_redirect_port.is_none());
}

#[test]
fn cache_defaults_to_in_memory_moka() {
    let cache = AppConfig::default().cache;
    assert!(cache.enabled);
    assert_eq!(cache.max_size_mb, 256);
    assert_eq!(cache.default_ttl_secs, 60);
    assert_eq!(cache.max_ttl_secs, 3600);
    assert!(cache.rules_path.is_none());
    assert_eq!(cache.backend, CacheBackendKind::Memory);
    assert_eq!(cache.embedded.data_dir, "/tmp/prx-valkey");
    assert!(cache.embedded.binary_path.is_empty());
    assert_eq!(cache.valkey.seeds, vec!["127.0.0.1:6379"]);
    assert_eq!(cache.valkey.pool_size, 4);
    assert_eq!(cache.valkey.connect_timeout_ms, 2_000);
    assert_eq!(cache.valkey.command_timeout_ms, 500);
    assert_eq!(cache.valkey.circuit_breaker_threshold, 5);
    assert_eq!(cache.valkey.circuit_breaker_reset_secs, 30);
    assert!(cache.valkey.fallback_to_memory);
}

#[test]
fn http3_and_security_defaults_are_conservative() {
    let c = AppConfig::default();
    assert!(!c.http3.enabled);
    assert_eq!(c.http3.listen_addr, "0.0.0.0:443");
    assert!(c.http3.upstream_tls_verify);
    assert_eq!(c.security.max_request_body_bytes, 10 * 1024 * 1024);
    assert_eq!(c.security.api_rate_limit_rps, 0);
    assert!(c.security.admin_ip_allowlist.is_empty());
    assert!(c.security.cors_origins.is_empty());
}

#[test]
fn outbound_header_filter_defaults_strip_fingerprints_but_not_pii() {
    let o = AppConfig::default().outbound;
    assert!(!o.enabled, "outbound filtering is opt-in");
    let h = o.headers;
    assert!(h.strip_server_info);
    assert!(h.strip_debug_headers);
    assert!(h.strip_error_detail);
    assert!(h.strip_php_fingerprint);
    assert!(h.strip_aspnet_fingerprint);
    assert!(h.strip_framework_fingerprint);
    assert!(h.strip_cdn_internal);
    assert!(!h.detect_pii_in_values, "PII regex scan is opt-in");
    assert!(!h.strip_session_headers_on_pii_match);
    assert_eq!(h.preserve_prefixes, vec!["x-waf-"]);
    assert_eq!(h.pii.max_scan_bytes, 8192);
    assert!(h.pii.disable_builtin.is_empty());
}

#[test]
fn geoip_defaults_point_at_bundled_xdb_paths() {
    let g = AppConfig::default().geoip;
    assert!(!g.enabled);
    assert_eq!(g.ipv4_xdb_path, "data/ip2region_v4.xdb");
    assert_eq!(g.ipv6_xdb_path, "data/ip2region_v6.xdb");
    assert_eq!(g.cache_policy, "full_memory");
    assert!(!g.auto_update.enabled);
    assert_eq!(g.auto_update.interval, "7d");
    assert!(g.auto_update.source_url.starts_with("https://"));
}

#[test]
fn community_defaults_are_disabled_with_public_server_url() {
    let c = AppConfig::default().community;
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
fn sqli_scan_defaults_skip_structural_headers() {
    let s = AppConfig::default().sqli_scan;
    assert!(s.scan_headers);
    assert_eq!(s.header_denylist.len(), 6);
    assert!(s.header_denylist.contains(&"cookie".to_string()));
    assert!(s.header_denylist.contains(&"host".to_string()));
    assert!(s.header_allowlist.is_empty());
    assert_eq!(s.header_scan_cap, 4096);
    assert_eq!(s.json_parse_cap, 256 * 1024);
}

#[test]
fn interop_and_audit_defaults_are_on() {
    let c = AppConfig::default();
    assert!(c.interop.enabled);
    assert!(!c.interop.benchmark_secret.is_empty());
    assert!(c.audit.enabled);
    assert_eq!(c.audit.log_path, "./waf_audit.log");
}

#[test]
fn cluster_config_default_is_inert_auto_role() {
    let c = ClusterConfig::default();
    assert!(!c.enabled);
    assert!(c.node_id.is_empty());
    assert_eq!(c.role, "auto");
    assert_eq!(c.listen_addr, "0.0.0.0:16851");
    assert!(c.seeds.is_empty());
    assert_eq!(c.crypto.ca_cert, "/app/certs/cluster-ca.pem");
    assert_eq!(c.crypto.node_cert, "/app/certs/node.pem");
    assert_eq!(c.crypto.node_key, "/app/certs/node.key");
    assert!(c.crypto.auto_generate);
    assert_eq!(c.crypto.ca_validity_days, 3650);
    assert_eq!(c.crypto.node_validity_days, 365);
    assert_eq!(c.crypto.renewal_before_days, 7);
    assert_eq!(c.sync.rules_interval_secs, 10);
    assert_eq!(c.sync.config_interval_secs, 30);
    assert_eq!(c.sync.events_batch_size, 100);
    assert_eq!(c.sync.events_flush_interval_secs, 5);
    assert_eq!(c.sync.stats_interval_secs, 10);
    assert_eq!(c.sync.events_queue_size, 10_000);
    assert_eq!(c.election.timeout_min_ms, 150);
    assert_eq!(c.election.timeout_max_ms, 300);
    assert_eq!(c.election.heartbeat_interval_ms, 50);
    assert!((c.election.phi_suspect - 8.0).abs() < f64::EPSILON);
    assert!((c.election.phi_dead - 12.0).abs() < f64::EPSILON);
    assert_eq!(c.health.check_interval_secs, 5);
    assert_eq!(c.health.max_missed_heartbeats, 3);
}

// ── ProxyConfig TLS path pairing ───────────────────────────────────────────────

#[test]
fn proxy_tls_paths_must_be_set_together() {
    let mut p = AppConfig::default().proxy;
    assert_eq!(p.resolve_tls_paths().unwrap(), None);

    p.tls_cert_pem = Some("cert.pem".into());
    assert!(p.resolve_tls_paths().is_err(), "cert without key must error");

    p.tls_key_pem = Some("key.pem".into());
    assert_eq!(
        p.resolve_tls_paths().unwrap(),
        Some(("cert.pem".to_string(), "key.pem".to_string()))
    );
}

// ── load_config: extension-driven format, defaults, validation ─────────────────

#[test]
fn load_config_reads_minimal_toml_and_fills_defaults() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_config(&dir, "waf.toml", MINIMAL_TOML);
    let c = load_config(&path).expect("minimal TOML loads");
    assert_eq!(c.proxy.listen_addr, "127.0.0.1:8080");
    assert_eq!(c.storage.max_connections, 5);
    // omitted sections come from serde defaults
    assert_eq!(c.rules.dir, "rules/");
    assert_eq!(c.cache.backend, CacheBackendKind::Memory);
    assert!(c.interop.enabled);
    assert!(c.cluster.is_none());
}

#[test]
fn load_config_parses_yaml_for_yaml_and_yml_extensions() {
    let dir = tempfile::tempdir().unwrap();
    for name in ["waf.yaml", "waf.yml", "waf.YAML"] {
        let path = write_config(&dir, name, MINIMAL_YAML);
        let c = load_config(&path).unwrap_or_else(|e| panic!("{name} should parse as YAML: {e}"));
        assert_eq!(c.api.listen_addr, "127.0.0.1:9001");
    }
}

#[test]
fn load_config_chooses_format_by_extension_not_content() {
    let dir = tempfile::tempdir().unwrap();
    // YAML content under a .toml name must fail the TOML parser
    let path = write_config(&dir, "waf.toml", MINIMAL_YAML);
    assert!(load_config(&path).is_err());
}

#[test]
fn load_config_errors_on_missing_file() {
    assert!(load_config("/nonexistent/prx-waf.toml").is_err());
}

#[test]
fn load_config_rejects_invalid_admin_tls_at_load_time() {
    let dir = tempfile::tempdir().unwrap();
    let content = format!("{MINIMAL_TOML}\n[api.tls]\nmin_tls_version = \"1.0\"\n");
    let path = write_config(&dir, "waf.toml", &content);
    let err = load_config(&path).unwrap_err();
    assert!(err.to_string().contains("min_tls_version"));
}

#[test]
fn load_config_parses_host_entries_with_optional_overrides() {
    let dir = tempfile::tempdir().unwrap();
    let content = format!(
        "{MINIMAL_TOML}\n[[hosts]]\nhost = \"example.com\"\nport = 443\nremote_host = \"10.0.0.2\"\nremote_port = 8443\nssl = true\nguard_status = true\ncert_file = \"c.pem\"\nkey_file = \"k.pem\"\nupstream_connect_timeout_ms = 1500\n"
    );
    let path = write_config(&dir, "waf.toml", &content);
    let c = load_config(&path).expect("hosts entry parses");
    assert_eq!(c.hosts.len(), 1);
    let h = &c.hosts[0];
    assert_eq!(h.host, "example.com");
    assert_eq!(h.remote_port, 8443);
    assert_eq!(h.ssl, Some(true));
    assert_eq!(h.upstream_connect_timeout_ms, Some(1500));
    // omitted optionals stay None so HostConfig defaults apply downstream
    assert!(h.owasp_set.is_none());
    assert!(h.block_scripted_clients.is_none());
    assert!(h.upstream_read_timeout_ms.is_none());
}
