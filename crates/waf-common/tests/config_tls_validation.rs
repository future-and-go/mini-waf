use waf_common::config::ProxyConfig;

#[test]
fn resolve_tls_paths_both_set() {
    let p = ProxyConfig {
        tls_cert_pem: Some("/etc/tls/cert.pem".to_string()),
        tls_key_pem: Some("/etc/tls/key.pem".to_string()),
        ..ProxyConfig::default()
    };
    let result = p.resolve_tls_paths().unwrap();
    assert_eq!(
        result,
        Some(("/etc/tls/cert.pem".to_string(), "/etc/tls/key.pem".to_string()))
    );
}

#[test]
fn resolve_tls_paths_both_none() {
    let p = ProxyConfig::default();
    let result = p.resolve_tls_paths().unwrap();
    assert!(result.is_none());
}

#[test]
fn resolve_tls_paths_partial_cert_only() {
    let p = ProxyConfig {
        tls_cert_pem: Some("/etc/tls/cert.pem".to_string()),
        tls_key_pem: None,
        ..ProxyConfig::default()
    };
    let err = p.resolve_tls_paths().unwrap_err();
    assert!(
        err.to_string().contains("Both tls_cert_pem and tls_key_pem"),
        "expected pair-required error, got: {err}"
    );
}

#[test]
fn resolve_tls_paths_partial_key_only() {
    let p = ProxyConfig {
        tls_cert_pem: None,
        tls_key_pem: Some("/etc/tls/key.pem".to_string()),
        ..ProxyConfig::default()
    };
    let err = p.resolve_tls_paths().unwrap_err();
    assert!(
        err.to_string().contains("Both tls_cert_pem and tls_key_pem"),
        "expected pair-required error, got: {err}"
    );
}

#[test]
fn toml_without_tls_fields_deserializes() {
    let toml = r#"
[proxy]
listen_addr = "0.0.0.0:80"
listen_addr_tls = "0.0.0.0:443"

[api]
listen_addr = "127.0.0.1:9527"

[storage]
database_url = "postgresql://x:x@localhost/x"
max_connections = 5
"#;
    let config: waf_common::config::AppConfig = toml::from_str(toml).unwrap();
    assert!(config.proxy.tls_cert_pem.is_none());
    assert!(config.proxy.tls_key_pem.is_none());
}

#[test]
fn toml_with_tls_fields_deserializes() {
    let toml = r#"
[proxy]
listen_addr = "0.0.0.0:80"
listen_addr_tls = "0.0.0.0:443"
tls_cert_pem = "/certs/cert.pem"
tls_key_pem = "/certs/key.pem"

[api]
listen_addr = "127.0.0.1:9527"

[storage]
database_url = "postgresql://x:x@localhost/x"
max_connections = 5
"#;
    let config: waf_common::config::AppConfig = toml::from_str(toml).unwrap();
    assert_eq!(config.proxy.tls_cert_pem.as_deref(), Some("/certs/cert.pem"));
    assert_eq!(config.proxy.tls_key_pem.as_deref(), Some("/certs/key.pem"));
}
