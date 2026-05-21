//! TLS listener bootstrap.
//!
//! Inspects `AppConfig.hosts` for entries with `tls_terminate = true` and
//! existing `cert_file` / `key_file` paths, then surfaces them as
//! `TlsHostBinding` records. `prx-waf::main` consumes these to call
//! `pingora_proxy::HttpProxyService::add_tls_with_settings` on the shared
//! `listen_addr_tls` socket. `tls_terminate` is independent of `HostEntry.ssl`
//! (which controls upstream TLS) so a WAF can terminate HTTPS for a host
//! while still forwarding plaintext to the backend.
//!
//! Per-host errors are isolated — a malformed entry never tears down TLS for
//! the other hosts. `collect_tls_bindings` returns the valid bindings and a
//! parallel list of errors so the caller can log each one and continue.
//!
//! Pingora's rustls listener panics inside `TlsSettings::build()` when the
//! PEM files can't be parsed. We pre-validate every cert/key pair with
//! `pingora_core::tls::load_certs_and_key_files` so a bad PEM is rejected as
//! an error, not a process crash. Tests inject a stub validator to keep the
//! unit suite hermetic.
//!
//! Multi-cert SNI is not yet supported — Pingora's rustls listener uses a
//! single `with_single_cert` `ServerConfig`. A SAN certificate covering every
//! served domain is the supported way to serve multiple hosts on one port.

use std::path::{Path, PathBuf};

use waf_common::config::{AppConfig, HostEntry};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsHostBinding {
    pub sni_host: String,
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum TlsBindingError {
    #[error("host '{host}' has tls_terminate=true but cert_file is missing/empty in config")]
    MissingCertPath { host: String },
    #[error("host '{host}' has tls_terminate=true but key_file is missing/empty in config")]
    MissingKeyPath { host: String },
    #[error("host '{host}': cert_file '{path}' does not exist on disk")]
    CertFileNotFound { host: String, path: String },
    #[error("host '{host}': key_file '{path}' does not exist on disk")]
    KeyFileNotFound { host: String, path: String },
    #[error(
        "host '{host}': PEM validation failed for cert '{cert}' / key '{key}': {reason}. \
         Common causes: wrong format (not PEM), corrupted file, cert and key don't match."
    )]
    InvalidPem {
        host: String,
        cert: String,
        key: String,
        reason: String,
    },
}

/// Result of scanning `AppConfig.hosts` for TLS-eligible entries.
///
/// Valid bindings and per-host errors are returned side by side so the caller
/// can log every problem without losing the working hosts.
#[derive(Debug, Default)]
pub struct TlsBindingScan {
    pub bindings: Vec<TlsHostBinding>,
    pub errors: Vec<TlsBindingError>,
}

pub fn collect_tls_bindings(config: &AppConfig) -> TlsBindingScan {
    collect_tls_bindings_with(config, &RealFs, &RealPemValidator)
}

trait FileChecker {
    fn exists(&self, path: &Path) -> bool;
}

trait PemValidator {
    fn validate(&self, cert: &Path, key: &Path) -> Result<(), String>;
}

struct RealFs;

impl FileChecker for RealFs {
    fn exists(&self, path: &Path) -> bool {
        path.exists()
    }
}

struct RealPemValidator;

impl PemValidator for RealPemValidator {
    fn validate(&self, cert: &Path, key: &Path) -> Result<(), String> {
        let cert_path_str = cert.to_string_lossy();
        let key_path_str = key.to_string_lossy();
        let load = || pingora_core::tls::load_certs_and_key_files(&cert_path_str, &key_path_str);

        match load() {
            Ok(Some((certs, parsed_key))) => {
                if verify_cert_key_pair(certs, parsed_key).is_ok() {
                    return Ok(());
                }
                // Original order failed. Retry with reversed chain to distinguish
                // a real pair mismatch from the common operator mistake of
                // putting intermediates before the leaf in fullchain.pem.
                if let Ok(Some((mut reversed_certs, reversed_key))) = load() {
                    reversed_certs.reverse();
                    if verify_cert_key_pair(reversed_certs, reversed_key).is_ok() {
                        return Err("cert chain order is reversed — the LEAF certificate must \
                             appear FIRST in fullchain.pem (before any intermediates)"
                            .to_string());
                    }
                }
                Err("cert/key validation failed — pair mismatch or unsupported algorithm. \
                     Verify the private key matches the leaf certificate's public key"
                    .to_string())
            }
            Ok(None) => Err("no usable certificate or private key found in PEM files".to_string()),
            Err(e) => Err(format!("{e}")),
        }
    }
}

/// Build a throwaway `rustls::ServerConfig` to prove the cert + key actually
/// belong together. `rustls::ConfigBuilder::with_single_cert` runs a
/// sign-and-verify probe using the private key and the cert's public key —
/// mismatched pairs return `Err` here instead of crashing Pingora later.
///
/// A per-call `Arc<CryptoProvider>` is used so the validator works in unit
/// tests that haven't installed a process-wide default provider.
fn verify_cert_key_pair(
    certs: Vec<pingora_core::tls::CertificateDer<'static>>,
    key: pingora_core::tls::PrivateKeyDer<'static>,
) -> Result<(), String> {
    use std::sync::Arc;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| format!("rustls protocol setup failed: {e}"))?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map(|_| ())
        .map_err(|e| format!("cert/key validation failed (likely pair mismatch or unsupported algorithm): {e}"))
}

fn collect_tls_bindings_with<F: FileChecker, V: PemValidator>(
    config: &AppConfig,
    fs: &F,
    validator: &V,
) -> TlsBindingScan {
    let mut scan = TlsBindingScan::default();
    for host in &config.hosts {
        match bind_for_host(host, fs, validator) {
            Ok(Some(binding)) => scan.bindings.push(binding),
            Ok(None) => {}
            Err(e) => scan.errors.push(e),
        }
    }
    scan
}

fn bind_for_host<F: FileChecker, V: PemValidator>(
    host: &HostEntry,
    fs: &F,
    validator: &V,
) -> Result<Option<TlsHostBinding>, TlsBindingError> {
    if !host.tls_terminate.unwrap_or(false) {
        return Ok(None);
    }

    let cert_path = match host.cert_file.as_deref().map(str::trim) {
        Some(p) if !p.is_empty() => PathBuf::from(p),
        _ => {
            return Err(TlsBindingError::MissingCertPath {
                host: host.host.clone(),
            });
        }
    };

    let key_path = match host.key_file.as_deref().map(str::trim) {
        Some(p) if !p.is_empty() => PathBuf::from(p),
        _ => {
            return Err(TlsBindingError::MissingKeyPath {
                host: host.host.clone(),
            });
        }
    };

    if !fs.exists(&cert_path) {
        return Err(TlsBindingError::CertFileNotFound {
            host: host.host.clone(),
            path: cert_path.display().to_string(),
        });
    }
    if !fs.exists(&key_path) {
        return Err(TlsBindingError::KeyFileNotFound {
            host: host.host.clone(),
            path: key_path.display().to_string(),
        });
    }

    // Pre-validate the PEM pair. Pingora's rustls listener panics in
    // `TlsSettings::build()` when files exist but can't be parsed; doing this
    // here surfaces the same problem as a recoverable error.
    if let Err(reason) = validator.validate(&cert_path, &key_path) {
        return Err(TlsBindingError::InvalidPem {
            host: host.host.clone(),
            cert: cert_path.display().to_string(),
            key: key_path.display().to_string(),
            reason,
        });
    }

    Ok(Some(TlsHostBinding {
        sni_host: host.host.clone(),
        cert_path,
        key_path,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use waf_common::config::HostEntry;

    struct StubFs {
        present: HashSet<PathBuf>,
    }

    impl StubFs {
        fn with(paths: &[&str]) -> Self {
            Self {
                present: paths.iter().map(PathBuf::from).collect(),
            }
        }
    }

    impl FileChecker for StubFs {
        fn exists(&self, path: &Path) -> bool {
            self.present.contains(path)
        }
    }

    struct AcceptAllPems;
    impl PemValidator for AcceptAllPems {
        fn validate(&self, _: &Path, _: &Path) -> Result<(), String> {
            Ok(())
        }
    }

    struct RejectAllPems(&'static str);
    impl PemValidator for RejectAllPems {
        fn validate(&self, _: &Path, _: &Path) -> Result<(), String> {
            Err(self.0.to_string())
        }
    }

    fn host(name: &str, tls_terminate: Option<bool>, cert: Option<&str>, key: Option<&str>) -> HostEntry {
        HostEntry {
            host: name.to_string(),
            port: 443,
            remote_host: "127.0.0.1".to_string(),
            remote_port: 8080,
            ssl: None,
            guard_status: None,
            cert_file: cert.map(String::from),
            key_file: key.map(String::from),
            owasp_set: None,
            block_scripted_clients: None,
            upstream_connect_timeout_ms: None,
            upstream_total_connection_timeout_ms: None,
            upstream_read_timeout_ms: None,
            upstream_write_timeout_ms: None,
            upstream_idle_timeout_ms: None,
            upstream_circuit_503_retry_after_s: None,
            tls_terminate,
        }
    }

    fn cfg(hosts: Vec<HostEntry>) -> AppConfig {
        AppConfig {
            hosts,
            ..AppConfig::default()
        }
    }

    #[test]
    fn no_hosts_returns_empty() {
        let scan = collect_tls_bindings_with(&cfg(vec![]), &StubFs::with(&[]), &AcceptAllPems);
        assert!(scan.bindings.is_empty());
        assert!(scan.errors.is_empty());
    }

    #[test]
    fn host_without_tls_terminate_skipped() {
        let cfg = cfg(vec![host("a.test", Some(false), None, None)]);
        let scan = collect_tls_bindings_with(&cfg, &StubFs::with(&[]), &AcceptAllPems);
        assert!(scan.bindings.is_empty());
        assert!(scan.errors.is_empty());
    }

    #[test]
    fn host_with_tls_terminate_none_skipped() {
        let cfg = cfg(vec![host("a.test", None, None, None)]);
        let scan = collect_tls_bindings_with(&cfg, &StubFs::with(&[]), &AcceptAllPems);
        assert!(scan.bindings.is_empty());
        assert!(scan.errors.is_empty());
    }

    #[test]
    fn tls_terminate_without_cert_path_records_error() {
        let cfg = cfg(vec![host("a.test", Some(true), None, Some("/k"))]);
        let scan = collect_tls_bindings_with(&cfg, &StubFs::with(&[]), &AcceptAllPems);
        assert!(scan.bindings.is_empty());
        assert_eq!(
            scan.errors,
            vec![TlsBindingError::MissingCertPath {
                host: "a.test".to_string(),
            }]
        );
    }

    #[test]
    fn tls_terminate_without_key_path_records_error() {
        let cfg = cfg(vec![host("a.test", Some(true), Some("/c"), None)]);
        let scan = collect_tls_bindings_with(&cfg, &StubFs::with(&[]), &AcceptAllPems);
        assert_eq!(
            scan.errors,
            vec![TlsBindingError::MissingKeyPath {
                host: "a.test".to_string(),
            }]
        );
    }

    #[test]
    fn ssl_true_alone_does_not_bind_listener() {
        // Regression guard for #91: `ssl` (upstream TLS) and `tls_terminate`
        // (listener bind) must stay orthogonal. A host with `ssl=true` but no
        // `tls_terminate` MUST NOT bind the WAF listener — that field controls
        // whether the proxy talks TLS to the upstream, nothing more.
        let entry = HostEntry {
            ssl: Some(true),
            tls_terminate: None,
            cert_file: Some("/c.pem".into()),
            key_file: Some("/k.pem".into()),
            ..host("a.test", None, None, None)
        };
        let scan = collect_tls_bindings_with(&cfg(vec![entry]), &StubFs::with(&["/c.pem", "/k.pem"]), &AcceptAllPems);
        assert!(
            scan.bindings.is_empty(),
            "ssl=true alone must not trigger listener bind"
        );
        assert!(scan.errors.is_empty(), "no error expected when not opted in");
    }

    #[test]
    fn ssl_and_tls_terminate_are_independent() {
        // Both fields can be set simultaneously: WAF terminates client TLS AND
        // re-encrypts to upstream HTTPS. Listener should bind regardless of
        // `ssl`.
        let entry = HostEntry {
            ssl: Some(true),
            tls_terminate: Some(true),
            cert_file: Some("/c.pem".into()),
            key_file: Some("/k.pem".into()),
            ..host("a.test", None, None, None)
        };
        let scan = collect_tls_bindings_with(&cfg(vec![entry]), &StubFs::with(&["/c.pem", "/k.pem"]), &AcceptAllPems);
        assert_eq!(scan.bindings.len(), 1);
        assert!(scan.errors.is_empty());
    }

    #[test]
    fn empty_cert_path_treated_as_missing() {
        let cfg = cfg(vec![host("a.test", Some(true), Some("  "), Some("/k"))]);
        let scan = collect_tls_bindings_with(&cfg, &StubFs::with(&[]), &AcceptAllPems);
        assert_eq!(
            scan.errors,
            vec![TlsBindingError::MissingCertPath {
                host: "a.test".to_string(),
            }]
        );
    }

    #[test]
    fn empty_key_path_treated_as_missing() {
        let cfg = cfg(vec![host("a.test", Some(true), Some("/c"), Some(""))]);
        let scan = collect_tls_bindings_with(&cfg, &StubFs::with(&[]), &AcceptAllPems);
        assert_eq!(
            scan.errors,
            vec![TlsBindingError::MissingKeyPath {
                host: "a.test".to_string(),
            }]
        );
    }

    #[test]
    fn missing_cert_file_on_disk_records_error() {
        let cfg = cfg(vec![host(
            "a.test",
            Some(true),
            Some("/etc/cert.pem"),
            Some("/etc/key.pem"),
        )]);
        let scan = collect_tls_bindings_with(&cfg, &StubFs::with(&["/etc/key.pem"]), &AcceptAllPems);
        assert_eq!(
            scan.errors,
            vec![TlsBindingError::CertFileNotFound {
                host: "a.test".to_string(),
                path: "/etc/cert.pem".to_string(),
            }]
        );
    }

    #[test]
    fn missing_key_file_on_disk_records_error() {
        let cfg = cfg(vec![host(
            "a.test",
            Some(true),
            Some("/etc/cert.pem"),
            Some("/etc/key.pem"),
        )]);
        let scan = collect_tls_bindings_with(&cfg, &StubFs::with(&["/etc/cert.pem"]), &AcceptAllPems);
        assert_eq!(
            scan.errors,
            vec![TlsBindingError::KeyFileNotFound {
                host: "a.test".to_string(),
                path: "/etc/key.pem".to_string(),
            }]
        );
    }

    #[test]
    fn malformed_pem_records_error() {
        let cfg = cfg(vec![host("a.test", Some(true), Some("/c.pem"), Some("/k.pem"))]);
        let scan = collect_tls_bindings_with(&cfg, &StubFs::with(&["/c.pem", "/k.pem"]), &RejectAllPems("not a PEM"));
        assert!(scan.bindings.is_empty());
        assert_eq!(scan.errors.len(), 1);
        match scan.errors.first() {
            Some(TlsBindingError::InvalidPem { host, reason, .. }) => {
                assert_eq!(host, "a.test");
                assert!(reason.contains("not a PEM"));
            }
            other => panic!("expected InvalidPem, got {other:?}"),
        }
    }

    #[test]
    fn valid_single_host_produces_binding() {
        let cfg = cfg(vec![host("a.test", Some(true), Some("/c.pem"), Some("/k.pem"))]);
        let scan = collect_tls_bindings_with(&cfg, &StubFs::with(&["/c.pem", "/k.pem"]), &AcceptAllPems);
        assert!(scan.errors.is_empty());
        assert_eq!(scan.bindings.len(), 1);
        let only = scan.bindings.first().unwrap();
        assert_eq!(only.sni_host, "a.test");
        assert_eq!(only.cert_path, PathBuf::from("/c.pem"));
        assert_eq!(only.key_path, PathBuf::from("/k.pem"));
    }

    #[test]
    fn multiple_tls_terminate_hosts_all_returned_in_order() {
        let cfg = cfg(vec![
            host("a.test", Some(true), Some("/a.pem"), Some("/ak.pem")),
            host("b.test", Some(false), None, None),
            host("c.test", Some(true), Some("/c.pem"), Some("/ck.pem")),
        ]);
        let scan = collect_tls_bindings_with(
            &cfg,
            &StubFs::with(&["/a.pem", "/ak.pem", "/c.pem", "/ck.pem"]),
            &AcceptAllPems,
        );
        let names: Vec<&str> = scan.bindings.iter().map(|b| b.sni_host.as_str()).collect();
        assert_eq!(names, vec!["a.test", "c.test"]);
        assert!(scan.errors.is_empty());
    }

    #[test]
    fn invalid_host_does_not_drop_valid_ones() {
        // Regression guard: previously a single broken TLS-terminating host
        // propagated `Err` and discarded every other binding. Now the bad host
        // surfaces as one entry in `errors`, and the good ones still bind.
        let cfg = cfg(vec![
            host("a.test", Some(true), Some("/a.pem"), Some("/ak.pem")),
            host("b.test", Some(true), None, Some("/bk.pem")),
            host("c.test", Some(true), Some("/c.pem"), Some("/ck.pem")),
        ]);
        let scan = collect_tls_bindings_with(
            &cfg,
            &StubFs::with(&["/a.pem", "/ak.pem", "/c.pem", "/ck.pem"]),
            &AcceptAllPems,
        );
        let names: Vec<&str> = scan.bindings.iter().map(|b| b.sni_host.as_str()).collect();
        assert_eq!(names, vec!["a.test", "c.test"]);
        assert_eq!(
            scan.errors,
            vec![TlsBindingError::MissingCertPath {
                host: "b.test".to_string(),
            }]
        );
    }

    #[test]
    fn error_display_messages_include_host_and_path() {
        let e = TlsBindingError::CertFileNotFound {
            host: "x".into(),
            path: "/p".into(),
        };
        let s = format!("{e}");
        assert!(s.contains('x'));
        assert!(s.contains("/p"));
    }

    #[test]
    fn invalid_pem_display_includes_paths_and_reason() {
        let e = TlsBindingError::InvalidPem {
            host: "h".into(),
            cert: "/c".into(),
            key: "/k".into(),
            reason: "boom".into(),
        };
        let s = format!("{e}");
        assert!(s.contains("/c"));
        assert!(s.contains("/k"));
        assert!(s.contains("boom"));
    }
}

#[cfg(test)]
mod real_fs_tests {
    //! Integration coverage for the production `RealFs` + `RealPemValidator`
    //! path. Hermetic — every file lives in a `tempfile::TempDir` and is
    //! deleted when the test exits.

    use super::*;
    use std::io::Write;
    use tempfile::TempDir;
    use waf_common::config::HostEntry;

    fn host(name: &str, cert: &Path, key: &Path) -> HostEntry {
        HostEntry {
            host: name.to_string(),
            port: 443,
            remote_host: "127.0.0.1".to_string(),
            remote_port: 8080,
            ssl: None,
            guard_status: None,
            cert_file: Some(cert.to_string_lossy().into_owned()),
            key_file: Some(key.to_string_lossy().into_owned()),
            owasp_set: None,
            block_scripted_clients: None,
            upstream_connect_timeout_ms: None,
            upstream_total_connection_timeout_ms: None,
            upstream_read_timeout_ms: None,
            upstream_write_timeout_ms: None,
            upstream_idle_timeout_ms: None,
            upstream_circuit_503_retry_after_s: None,
            tls_terminate: Some(true),
        }
    }

    fn write_file(dir: &Path, name: &str, content: &[u8]) -> PathBuf {
        let path = dir.join(name);
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(content).unwrap();
        path
    }

    /// Generate a self-signed cert + key pair. Uses `rcgen` (already a
    /// transitive workspace dep via `gateway::ssl::SslManager`). The output
    /// pair is byte-identical to what an operator would deploy from Let's
    /// Encrypt — proves the real PEM parser accepts it.
    fn make_valid_pem_pair() -> (Vec<u8>, Vec<u8>) {
        use rcgen::{CertificateParams, KeyPair};
        let kp = KeyPair::generate().unwrap();
        let params = CertificateParams::new(vec!["example.com".to_string()]).unwrap();
        let cert = params.self_signed(&kp).unwrap();
        (cert.pem().into_bytes(), kp.serialize_pem().into_bytes())
    }

    #[test]
    fn real_fs_accepts_valid_cert_and_key() {
        let tmp = TempDir::new().unwrap();
        let (cert_pem, key_pem) = make_valid_pem_pair();
        let cert = write_file(tmp.path(), "cert.pem", &cert_pem);
        let key = write_file(tmp.path(), "key.pem", &key_pem);
        let config = AppConfig {
            hosts: vec![host("example.com", &cert, &key)],
            ..AppConfig::default()
        };

        let scan = collect_tls_bindings(&config);
        assert!(scan.errors.is_empty(), "unexpected errors: {:?}", scan.errors);
        assert_eq!(scan.bindings.len(), 1);
        let binding = scan.bindings.first().unwrap();
        assert_eq!(binding.sni_host, "example.com");
        assert_eq!(binding.cert_path, cert);
        assert_eq!(binding.key_path, key);
    }

    #[test]
    fn real_fs_rejects_garbage_file_with_invalid_pem_error() {
        let tmp = TempDir::new().unwrap();
        let cert = write_file(tmp.path(), "cert.pem", b"this is not a PEM file");
        let key = write_file(tmp.path(), "key.pem", b"also not a PEM file");
        let config = AppConfig {
            hosts: vec![host("bad.example.com", &cert, &key)],
            ..AppConfig::default()
        };

        let scan = collect_tls_bindings(&config);
        assert!(scan.bindings.is_empty());
        assert_eq!(scan.errors.len(), 1);
        let first = scan.errors.first().unwrap();
        assert!(
            matches!(first, TlsBindingError::InvalidPem { host, .. } if host == "bad.example.com"),
            "expected InvalidPem for bad.example.com, got {first:?}"
        );
    }

    #[test]
    fn real_fs_rejects_missing_file_with_not_found_error() {
        let tmp = TempDir::new().unwrap();
        let cert = tmp.path().join("does_not_exist.pem");
        let key = write_file(tmp.path(), "key.pem", b"placeholder");
        let config = AppConfig {
            hosts: vec![host("ghost.example.com", &cert, &key)],
            ..AppConfig::default()
        };

        let scan = collect_tls_bindings(&config);
        assert!(scan.bindings.is_empty());
        let first = scan.errors.first().unwrap();
        assert!(
            matches!(first, TlsBindingError::CertFileNotFound { host, .. } if host == "ghost.example.com"),
            "expected CertFileNotFound for ghost.example.com, got {first:?}"
        );
    }

    #[test]
    fn real_fs_detects_reversed_chain_order() {
        // Operator put the intermediate before the leaf in fullchain.pem. The
        // private key still matches the leaf cert, but rustls would treat the
        // first cert (intermediate) as the end-entity and report a mismatch.
        // The validator's reverse-retry surfaces this as a chain-order error
        // with an actionable hint instead of a generic mismatch report.
        let tmp = TempDir::new().unwrap();
        let (leaf_pem, leaf_key_pem) = make_valid_pem_pair();
        let (mut wrong_order, _) = make_valid_pem_pair();
        wrong_order.extend_from_slice(&leaf_pem);
        let cert = write_file(tmp.path(), "fullchain.pem", &wrong_order);
        let key = write_file(tmp.path(), "key.pem", &leaf_key_pem);
        let config = AppConfig {
            hosts: vec![host("reversed.example.com", &cert, &key)],
            ..AppConfig::default()
        };

        let scan = collect_tls_bindings(&config);
        assert!(scan.bindings.is_empty());
        let first = scan.errors.first().unwrap();
        match first {
            TlsBindingError::InvalidPem { host, reason, .. } => {
                assert_eq!(host, "reversed.example.com");
                assert!(
                    reason.contains("chain order is reversed") || reason.contains("LEAF"),
                    "expected chain-order hint, got: {reason}"
                );
            }
            other => panic!("expected InvalidPem on reversed chain, got {other:?}"),
        }
    }

    #[test]
    fn real_fs_rejects_mismatched_cert_and_key() {
        // Regression guard for the pair-match check: without it Pingora's
        // `TlsSettings::build()` panics on this exact input.
        let tmp = TempDir::new().unwrap();
        let (cert_pem_a, _key_pem_a) = make_valid_pem_pair();
        let (_cert_pem_b, key_pem_b) = make_valid_pem_pair();
        let cert = write_file(tmp.path(), "cert.pem", &cert_pem_a);
        let key = write_file(tmp.path(), "key.pem", &key_pem_b);
        let config = AppConfig {
            hosts: vec![host("mismatched.example.com", &cert, &key)],
            ..AppConfig::default()
        };

        let scan = collect_tls_bindings(&config);
        assert!(scan.bindings.is_empty(), "binding should be rejected on mismatch");
        let first = scan.errors.first().unwrap();
        match first {
            TlsBindingError::InvalidPem { host, reason, .. } => {
                assert_eq!(host, "mismatched.example.com");
                assert!(
                    reason.contains("pair mismatch") || reason.contains("validation failed"),
                    "expected pair-mismatch wording in reason, got: {reason}"
                );
            }
            other => panic!("expected InvalidPem on mismatched pair, got {other:?}"),
        }
    }
}
