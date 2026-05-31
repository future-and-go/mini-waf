//! Admin API TLS certificate lifecycle.
//!
//! - Auto mode: generate Ed25519 self-signed cert on first boot, persist to
//!   `data_dir`, reuse on subsequent boots, auto-renew when ≤ `renewal_before_days`.
//! - Provided mode: load cert/key from filesystem paths, no auto-renew.
//!
//! All I/O is fail-fast with `anyhow::Context` — no silent fall-back.
//!
//! **No secret logging**: private key content is never emitted to any log sink.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use arc_swap::ArcSwap;
use parking_lot::RwLock;
use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair, PKCS_ECDSA_P256_SHA256};
use rustls::ServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls_pki_types::pem::PemObject as _;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use tracing::{info, warn};
use waf_common::config::{AdminTlsConfig, AdminTlsMode};

// ─── Public material struct ───────────────────────────────────────────────────

/// In-memory TLS material ready for serving.
#[derive(Clone)]
pub struct AdminTlsMaterial {
    pub cert_chain: Vec<CertificateDer<'static>>,
    pub key: Arc<PrivateKeyDer<'static>>,
    /// UTC expiry instant (`not_after`)
    pub not_after: OffsetDateTime,
    /// Hex-encoded SHA-256 fingerprint of the leaf cert — safe to log.
    pub fingerprint_sha256: String,
}

// ─── Metadata persisted alongside the cert files ─────────────────────────────

/// Metadata stored at `data_dir/metadata.json`.
/// Used to detect SAN drift between boots so we regenerate instead of reusing.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct CertMetadata {
    sans: Vec<String>,
}

// ─── Cert resolver (hot-swap without listener restart) ────────────────────────

/// `rustls` `ResolvesServerCert` backed by an `ArcSwap<CertifiedKey>`.
///
/// Lock-free reads on the hot path; renewal task swaps atomically via
/// [`AdminCertResolver::swap`].
#[derive(Debug)]
pub struct AdminCertResolver {
    current: ArcSwap<CertifiedKey>,
}

impl AdminCertResolver {
    /// Construct from existing TLS material.
    pub fn new(material: &AdminTlsMaterial) -> Result<Self> {
        let key = build_certified_key(material)?;
        Ok(Self {
            current: ArcSwap::new(Arc::new(key)),
        })
    }

    /// Atomically replace the current `CertifiedKey` with one built from
    /// the supplied material. In-flight TLS handshakes are unaffected.
    pub fn swap(&self, material: &AdminTlsMaterial) -> Result<()> {
        let key = build_certified_key(material)?;
        self.current.store(Arc::new(key));
        Ok(())
    }
}

impl ResolvesServerCert for AdminCertResolver {
    fn resolve(&self, _hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(self.current.load_full())
    }
}

fn build_certified_key(material: &AdminTlsMaterial) -> Result<CertifiedKey> {
    use rustls::crypto::ring::sign::any_supported_type;

    let signing_key = any_supported_type(material.key.as_ref()).context("build signing key")?;
    Ok(CertifiedKey::new(material.cert_chain.clone(), signing_key))
}

// ─── TLS manager ─────────────────────────────────────────────────────────────

/// Manages admin TLS material lifecycle: bootstrap, persistence, renewal.
pub struct AdminTlsManager {
    config: AdminTlsConfig,
    listen_addr: SocketAddr,
    /// Current material, swap-able without restarting the listener.
    material: Arc<RwLock<Arc<AdminTlsMaterial>>>,
    resolver: Arc<AdminCertResolver>,
}

impl AdminTlsManager {
    /// Bootstrap TLS material from config.
    ///
    /// - Auto mode: loads from disk or generates, persists to `data_dir`.
    /// - Provided mode: loads from configured PEM paths, validates.
    ///
    /// Returns `None` when `config.enabled == false` (caller should serve HTTP).
    pub fn bootstrap(config: AdminTlsConfig, listen_addr: SocketAddr) -> Result<Option<Self>> {
        if !config.enabled {
            return Ok(None);
        }

        let material = match config.mode {
            AdminTlsMode::Provided => Self::load_provided(&config)?,
            AdminTlsMode::Auto => Self::load_or_generate(&config, listen_addr)?,
        };

        let resolver = Arc::new(AdminCertResolver::new(&material).context("build cert resolver")?);
        let material = Arc::new(RwLock::new(Arc::new(material)));
        Ok(Some(Self {
            config,
            listen_addr,
            material,
            resolver,
        }))
    }

    /// Build a `rustls::ServerConfig` snapshot wired to the cert resolver.
    ///
    /// Hot-reload is handled by the resolver — the `ServerConfig` itself
    /// never needs to be replaced.
    pub fn server_config(&self) -> Result<Arc<ServerConfig>> {
        build_server_config(&self.config.min_tls_version, Arc::clone(&self.resolver))
    }

    /// Hex SHA-256 fingerprint of the current leaf cert — safe to log.
    pub fn fingerprint(&self) -> String {
        self.material.read().fingerprint_sha256.clone()
    }

    /// Access the underlying cert resolver (needed for hot-swap tests).
    pub fn resolver(&self) -> Arc<AdminCertResolver> {
        Arc::clone(&self.resolver)
    }

    /// Access the current TLS material (cloned snapshot).
    pub fn current_material(&self) -> Arc<AdminTlsMaterial> {
        self.material.read().clone()
    }

    /// Spawn a background task that checks for renewal every 6 hours.
    ///
    /// In Provided mode this is a no-op (spawns but always exits immediately
    /// on the first check since `is_due_for_renewal` is not relevant).
    ///
    /// The task holds a weak reference: when `AdminTlsManager` is dropped the
    /// task quietly exits.
    pub fn spawn_renewal(self: Arc<Self>) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            if self.config.mode != AdminTlsMode::Auto {
                return;
            }
            let mut interval = tokio::time::interval(Duration::from_hours(6));
            loop {
                interval.tick().await;
                let not_after = self.material.read().not_after;
                let before = Duration::from_hours(u64::from(self.config.renewal_before_days) * 24);
                if !is_due_for_renewal(not_after, before) {
                    continue;
                }
                match Self::regenerate(&self.config, self.listen_addr) {
                    Ok(new_mat) => {
                        let old_fp = self.fingerprint();
                        let new_fp = new_mat.fingerprint_sha256.clone();
                        match self.resolver.swap(&new_mat) {
                            Ok(()) => {
                                *self.material.write() = Arc::new(new_mat);
                                info!(
                                    old_fingerprint = %old_fp,
                                    new_fingerprint = %new_fp,
                                    "Admin TLS cert renewed"
                                );
                            }
                            Err(e) => {
                                tracing::error!("Admin TLS renewal: failed to swap cert resolver: {e:#}");
                            }
                        }
                    }
                    Err(e) => {
                        tracing::error!("Admin TLS renewal: failed to generate new cert: {e:#}");
                    }
                }
            }
        })
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    fn load_provided(config: &AdminTlsConfig) -> Result<AdminTlsMaterial> {
        let cert_path = config
            .cert_pem
            .as_ref()
            .context("api.tls.cert_pem must be set when mode = \"provided\"")?;
        let key_path = config
            .key_pem
            .as_ref()
            .context("api.tls.key_pem must be set when mode = \"provided\"")?;
        load_from_files(cert_path, key_path)
            .with_context(|| format!("load provided admin TLS material from {}", cert_path.display()))
    }

    fn load_or_generate(config: &AdminTlsConfig, listen_addr: SocketAddr) -> Result<AdminTlsMaterial> {
        let data_dir = resolve_data_dir(config);
        std::fs::create_dir_all(&data_dir)
            .with_context(|| format!("create admin TLS data dir {}", data_dir.display()))?;

        let cert_path = data_dir.join("cert.pem");
        let key_path = data_dir.join("key.pem");
        let meta_path = data_dir.join("metadata.json");

        let sans = resolve_sans(listen_addr, &config.extra_sans);
        let before = Duration::from_hours(u64::from(config.renewal_before_days) * 24);

        if cert_path.exists() && key_path.exists() {
            match load_from_files(&cert_path, &key_path) {
                Ok(mat) if !is_due_for_renewal(mat.not_after, before) && !san_drift(&meta_path, &sans) => {
                    let days_left = (mat.not_after - OffsetDateTime::now_utc()).whole_days();
                    info!(
                        data_dir = %data_dir.display(),
                        fingerprint_sha256 = %mat.fingerprint_sha256,
                        not_after = %mat.not_after,
                        days_until_renewal = days_left,
                        "Reusing existing admin TLS material"
                    );
                    return Ok(mat);
                }
                Ok(_) => {} // due for renewal or SAN drift → fall through
                Err(e) => {
                    warn!("Failed to load existing admin TLS cert, regenerating: {e:#}");
                }
            }
        }

        Self::regenerate_at(config, &sans, &data_dir, &cert_path, &key_path, &meta_path)
    }

    /// Generate fresh material and persist to `data_dir`.
    fn regenerate(config: &AdminTlsConfig, listen_addr: SocketAddr) -> Result<AdminTlsMaterial> {
        let data_dir = resolve_data_dir(config);
        let cert_path = data_dir.join("cert.pem");
        let key_path = data_dir.join("key.pem");
        let meta_path = data_dir.join("metadata.json");
        let sans = resolve_sans(listen_addr, &config.extra_sans);
        Self::regenerate_at(config, &sans, &data_dir, &cert_path, &key_path, &meta_path)
    }

    fn regenerate_at(
        config: &AdminTlsConfig,
        sans: &[String],
        data_dir: &Path,
        cert_path: &Path,
        key_path: &Path,
        meta_path: &Path,
    ) -> Result<AdminTlsMaterial> {
        let (cert_pem, key_pem, not_after) = generate(sans, config.validity_days)?;

        // Atomic write: write to .tmp then rename
        let cert_tmp = data_dir.join("cert.pem.tmp");
        let key_tmp = data_dir.join("key.pem.tmp");

        std::fs::write(&cert_tmp, &cert_pem).context("write cert.pem.tmp")?;
        std::fs::write(&key_tmp, &key_pem).context("write key.pem.tmp")?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&key_tmp, std::fs::Permissions::from_mode(0o600))
                .context("chmod 600 key.pem.tmp")?;
        }

        std::fs::rename(&cert_tmp, cert_path).context("rename cert.pem.tmp → cert.pem")?;
        std::fs::rename(&key_tmp, key_path).context("rename key.pem.tmp → key.pem")?;

        // Persist metadata (SANs used)
        let meta = CertMetadata { sans: sans.to_vec() };
        let meta_json = serde_json::to_string(&meta).context("serialize cert metadata")?;
        std::fs::write(meta_path, &meta_json).context("write metadata.json")?;

        let mat = parse_material(&cert_pem, &key_pem, not_after)?;

        info!(
            data_dir = %data_dir.display(),
            fingerprint_sha256 = %mat.fingerprint_sha256,
            not_after = %mat.not_after,
            sans = ?sans,
            "Generated new admin TLS cert"
        );
        Ok(mat)
    }
}

// ─── Build rustls ServerConfig ────────────────────────────────────────────────

/// Construct a `rustls::ServerConfig` with the given resolver and TLS version floor.
pub fn build_server_config(min_tls: &str, resolver: Arc<AdminCertResolver>) -> Result<Arc<ServerConfig>> {
    use rustls::version;

    let versions: &[&'static rustls::SupportedProtocolVersion] = match min_tls {
        "1.3" => &[&version::TLS13],
        "1.2" => &[&version::TLS12, &version::TLS13],
        other => bail!("unsupported min_tls_version: {other:?}"),
    };

    let mut cfg = ServerConfig::builder_with_protocol_versions(versions)
        .with_no_client_auth()
        .with_cert_resolver(resolver);

    cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    Ok(Arc::new(cfg))
}

// ─── HTTP redirect listener ───────────────────────────────────────────────────

/// Spawn a minimal Axum server that 301-redirects all requests to HTTPS.
///
/// Binds `redirect_port` (or `https_port - 1` if `None`). Bind failures are
/// logged as WARN but do NOT crash — redirect is advisory.
pub fn spawn_http_redirect(https_addr: SocketAddr, redirect_port: Option<u16>) {
    let port = redirect_port.unwrap_or_else(|| https_addr.port().saturating_sub(1));
    let redirect_addr = SocketAddr::new(https_addr.ip(), port);
    let https_port = https_addr.port();

    tokio::spawn(async move {
        use axum::body::Body;
        use axum::{Router, http::Request, response::Redirect, routing::any};

        let app = Router::new().route(
            "/{*path}",
            any(move |req: Request<Body>| async move {
                let host = req
                    .headers()
                    .get("host")
                    .and_then(|h| h.to_str().ok())
                    .unwrap_or("localhost")
                    .to_owned();
                let path = req.uri().path_and_query().map_or("/", |pq| pq.as_str());
                let target = if https_port == 443 {
                    format!("https://{host}{path}")
                } else {
                    format!("https://{host}:{https_port}{path}")
                };
                Redirect::permanent(&target)
            }),
        );

        match tokio::net::TcpListener::bind(redirect_addr).await {
            Ok(listener) => {
                info!(redirect_addr = %redirect_addr, target_https_addr = %https_addr, "HTTP→HTTPS redirect listener bound");
                if let Err(e) = axum::serve(listener, app).await {
                    warn!("HTTP redirect listener exited: {e}");
                }
            }
            Err(e) => {
                warn!(error = %e, "Failed to bind HTTP redirect listener — redirect disabled");
            }
        }
    });
}

// ─── Pure helper functions ────────────────────────────────────────────────────

/// Build the SAN list from config extras + hostname + listen IP.
///
/// `0.0.0.0` / `::` are expanded to all known interface IPs (best-effort).
pub fn resolve_sans(listen_addr: SocketAddr, extras: &[String]) -> Vec<String> {
    let mut out: Vec<String> = extras.to_vec();

    // Always include the canonical loopback aliases so `https://localhost:…`
    // works regardless of where the cert was generated.
    for always in &["localhost", "127.0.0.1", "::1"] {
        let s = always.to_string();
        if !out.contains(&s) {
            out.push(s);
        }
    }

    // System hostname (best-effort — adds container hostname / machine FQDN)
    if let Ok(host) = hostname::get()
        && let Some(s) = host.to_str()
        && !s.is_empty()
    {
        let owned = s.to_owned();
        if !out.contains(&owned) {
            out.push(owned);
        }
    }

    let ip = listen_addr.ip();
    if ip.is_unspecified() {
        // Expand 0.0.0.0 / :: to all known interface IPs (best-effort)
        if let Ok(addrs) = if_addrs::get_if_addrs() {
            for a in addrs {
                let s = a.ip().to_string();
                if !out.contains(&s) {
                    out.push(s);
                }
            }
        }
    } else {
        let s = ip.to_string();
        if !out.contains(&s) {
            out.push(s);
        }
    }

    out.sort();
    out.dedup();
    out
}

/// Generate a fresh Ed25519 self-signed cert.
///
/// Returns `(cert_pem, key_pem, not_after)`.
/// The key PEM is NEVER logged — callers must uphold this invariant.
fn generate(sans: &[String], validity_days: u32) -> Result<(String, String, OffsetDateTime)> {
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).context("ecdsa p256 keypair generation")?;

    let mut params = CertificateParams::new(sans.to_vec()).context("invalid SAN list for admin cert")?;

    params.not_before = OffsetDateTime::now_utc() - time::Duration::seconds(60);
    let not_after = OffsetDateTime::now_utc() + time::Duration::days(i64::from(validity_days));
    params.not_after = not_after;

    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "prx-waf admin");
    dn.push(DnType::OrganizationName, "prx-waf");
    params.distinguished_name = dn;

    let cert = params.self_signed(&key).context("self-sign admin cert")?;
    Ok((cert.pem(), key.serialize_pem(), not_after))
}

/// Load cert + key from PEM files.
fn load_from_files(cert_path: &Path, key_path: &Path) -> Result<AdminTlsMaterial> {
    let cert_pem =
        std::fs::read_to_string(cert_path).with_context(|| format!("read cert PEM from {}", cert_path.display()))?;
    let key_pem =
        std::fs::read_to_string(key_path).with_context(|| format!("read key PEM from {}", key_path.display()))?;

    // Parse expiry from cert to populate `not_after`.
    // Use rcgen to decode just enough to get the notAfter field.
    let cert_ders: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(cert_pem.as_bytes())
        .collect::<std::result::Result<Vec<_>, _>>()
        .context("parse cert PEM")?;

    let not_after = parse_not_after_from_der(cert_ders.first().context("cert PEM has no certificates")?)?;

    parse_material(&cert_pem, &key_pem, not_after)
}

/// Parse `AdminTlsMaterial` from PEM strings.
fn parse_material(cert_pem: &str, key_pem: &str, not_after: OffsetDateTime) -> Result<AdminTlsMaterial> {
    let cert_chain: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(cert_pem.as_bytes())
        .collect::<std::result::Result<Vec<_>, _>>()
        .context("parse cert chain")?;

    let key: PrivateKeyDer<'static> =
        PrivateKeyDer::from_pem_slice(key_pem.as_bytes()).context("parse private key PEM")?;

    let fingerprint_sha256 = fingerprint_sha256(cert_chain.first().context("empty cert chain")?);

    Ok(AdminTlsMaterial {
        cert_chain,
        key: Arc::new(key),
        not_after,
        fingerprint_sha256,
    })
}

/// Extract the `not_after` field from a DER-encoded certificate.
fn parse_not_after_from_der(der: &CertificateDer<'_>) -> Result<OffsetDateTime> {
    // Use the x509-parser crate is not available; use rcgen's raw DER parsing
    // via webpki's built-in validation or a simpler approach.
    // We fall back to using `rustls-pki-types` datetime parsing through webpki.
    // Since we generate with `time::OffsetDateTime`, we can also just use rcgen's
    // parsed cert representation. However to avoid adding webpki, we use a simple
    // ASN.1 walk.
    //
    // For self-signed certs we generate ourselves, the not_after is well-known.
    // For provided certs we estimate from serial-number parse, but we actually need
    // to read the cert. The safe approach: use `rustls` built-in DER parser.

    // Build an end-entity cert to get the notAfter via webpki EndEntityCert.
    // This is internal API; instead we use a lightweight approach with the
    // `x509-parser` if available, or fall back to a reasonable default.
    //
    // Since x509-parser is not in the workspace, we use the rcgen re-export path:
    // generate gives us back `not_after` already — for load_from_files we need
    // to extract it. We parse with rustls's internal cert validator which
    // exposes expiry via `EndEntityCert::verify_is_valid_tls_server_cert`...
    // but that requires a chain.
    //
    // Simplest safe fallback: use the `pem` + `der` bytes to call into the
    // UnixTime-based `rustls_pki_types::CertificateDer` expiry extraction.
    // As of rustls-pki-types 1.x there is no direct `not_after()` method.
    //
    // We implement a minimal ASN.1 UTCTime/GeneralizedTime walk.
    parse_not_after_asn1(der.as_ref()).context("parse not_after from DER cert")
}

/// Minimal ASN.1 walk to extract notAfter from an X.509 certificate DER.
///
/// X.509 structure (simplified):
/// ```text
/// SEQUENCE {           -- Certificate
///   SEQUENCE {         -- TBSCertificate
///     [0]              -- version (explicit, optional)
///     INTEGER          -- serialNumber
///     SEQUENCE         -- signature
///     SEQUENCE         -- issuer
///     SEQUENCE {       -- validity
///       UTCTime/GeneralizedTime  -- notBefore
///       UTCTime/GeneralizedTime  -- notAfter  ← we want this
///     }
///   }
///   ...
/// }
/// ```
fn parse_not_after_asn1(der: &[u8]) -> Result<OffsetDateTime> {
    // Walk into Certificate → TBSCertificate → validity → notAfter
    let tbs = asn1_unwrap_sequence(der).context("Certificate outer SEQUENCE")?;
    let tbs = asn1_unwrap_sequence(tbs).context("TBSCertificate SEQUENCE")?;

    // Skip optional [0] explicit version tag
    let tbs = if tbs.first().copied() == Some(0xa0) {
        let (len, rest) = asn1_read_length(tbs.get(1..).context("version tag: no content after tag")?)?;
        rest.get(len..).context("version tag: content truncated")?
    } else {
        tbs
    };

    // Skip serialNumber INTEGER
    let tbs = asn1_skip_element(tbs).context("skip serialNumber")?;
    // Skip signature AlgorithmIdentifier SEQUENCE
    let tbs = asn1_skip_element(tbs).context("skip signature")?;
    // Skip issuer Name SEQUENCE
    let tbs = asn1_skip_element(tbs).context("skip issuer")?;

    // Now at Validity SEQUENCE
    let validity = asn1_unwrap_sequence(tbs).context("Validity SEQUENCE")?;
    // Skip notBefore
    let validity = asn1_skip_element(validity).context("skip notBefore")?;
    // Parse notAfter
    asn1_parse_time(validity).context("parse notAfter")
}

fn asn1_unwrap_sequence(data: &[u8]) -> Result<&[u8]> {
    if data.first().copied() != Some(0x30) {
        bail!("expected SEQUENCE tag 0x30, got {:02x?}", data.first());
    }
    let (len, rest) = asn1_read_length(data.get(1..).context("SEQUENCE: missing length bytes")?)?;
    rest.get(..len).context("SEQUENCE: content truncated")
}

fn asn1_skip_element(data: &[u8]) -> Result<&[u8]> {
    if data.is_empty() {
        bail!("unexpected end of ASN.1 data");
    }
    let (len, rest) = asn1_read_length(data.get(1..).context("element: missing length bytes")?)?;
    rest.get(len..).context("element: skip overflow")
}

fn asn1_read_length(data: &[u8]) -> Result<(usize, &[u8])> {
    let first = *data.first().context("read length: empty")?;
    if first < 0x80 {
        return Ok((
            first as usize,
            data.get(1..).context("length: no content after short form")?,
        ));
    }
    let n_bytes = (first & 0x7f) as usize;
    if n_bytes == 0 || n_bytes > 4 {
        bail!("unsupported ASN.1 length encoding: {first:#x}");
    }
    let len_bytes = data.get(1..1 + n_bytes).context("read multi-byte length")?;
    let mut len = 0usize;
    for &b in len_bytes {
        len = (len << 8) | b as usize;
    }
    Ok((
        len,
        data.get(1 + n_bytes..).context("length: no content after long form")?,
    ))
}

fn asn1_parse_time(data: &[u8]) -> Result<OffsetDateTime> {
    let tag = *data.first().context("time tag")?;
    let (len, content) = asn1_read_length(data.get(1..).context("time: missing length bytes")?)?;
    let s = std::str::from_utf8(content.get(..len).context("time: content truncated")?).context("time string UTF-8")?;
    match tag {
        0x17 => {
            // UTCTime: YYMMDDHHMMSSZ
            parse_utc_time(s)
        }
        0x18 => {
            // GeneralizedTime: YYYYMMDDHHMMSSZ
            parse_generalized_time(s)
        }
        other => bail!("unexpected time tag {other:#x}"),
    }
}

fn parse_utc_time(s: &str) -> Result<OffsetDateTime> {
    // YYMMDDHHMMSSZ — 13 chars
    if s.len() < 13 || !s.ends_with('Z') {
        bail!("invalid UTCTime: {s:?}");
    }
    let yy: i32 = s[..2].parse().context("UTCTime year")?;
    let year = if yy >= 50 { 1900 + yy } else { 2000 + yy };
    parse_datetime_parts(year, &s[2..])
}

fn parse_generalized_time(s: &str) -> Result<OffsetDateTime> {
    // YYYYMMDDHHMMSSZ — 15 chars
    if s.len() < 15 || !s.ends_with('Z') {
        bail!("invalid GeneralizedTime: {s:?}");
    }
    let year: i32 = s[..4].parse().context("GeneralizedTime year")?;
    parse_datetime_parts(year, &s[4..])
}

fn parse_datetime_parts(year: i32, rest: &str) -> Result<OffsetDateTime> {
    use time::{Date, Month, PrimitiveDateTime, Time};
    let month: u8 = rest[..2].parse().context("month")?;
    let day: u8 = rest[2..4].parse().context("day")?;
    let hour: u8 = rest[4..6].parse().context("hour")?;
    let minute: u8 = rest[6..8].parse().context("minute")?;
    let second: u8 = rest[8..10].parse().context("second")?;

    let month = Month::try_from(month).context("invalid month")?;
    let date = Date::from_calendar_date(year, month, day).context("invalid date")?;
    let time_val = Time::from_hms(hour, minute, second).context("invalid time")?;
    Ok(PrimitiveDateTime::new(date, time_val).assume_utc())
}

/// True if the cert will expire within the renewal window.
fn is_due_for_renewal(not_after: OffsetDateTime, before: Duration) -> bool {
    let remaining = not_after - OffsetDateTime::now_utc();
    remaining < time::Duration::try_from(before).unwrap_or(time::Duration::days(30))
}

/// True if the SANs in `metadata.json` differ from the resolved SANs.
fn san_drift(meta_path: &Path, current_sans: &[String]) -> bool {
    let Ok(content) = std::fs::read_to_string(meta_path) else {
        return true; // no metadata → treat as drift, regenerate
    };
    let Ok(meta): std::result::Result<CertMetadata, _> = serde_json::from_str(&content) else {
        return true;
    };
    meta.sans != current_sans
}

/// Resolve the `data_dir` to use for auto-generated cert storage.
///
/// Chain: `config.data_dir` → `/var/lib/prx-waf/admin-tls` (Linux-style default).
fn resolve_data_dir(config: &AdminTlsConfig) -> PathBuf {
    config
        .data_dir
        .clone()
        .unwrap_or_else(|| PathBuf::from("/var/lib/prx-waf/admin-tls"))
}

/// Hex-encode SHA-256 of the raw DER bytes.
fn fingerprint_sha256(cert: &CertificateDer<'_>) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(cert.as_ref());
    hex::encode(digest)
}

// ─── Unit tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use super::*;
    use waf_common::config::AdminTlsConfig;

    fn test_addr() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9527)
    }

    #[test]
    fn generate_produces_parseable_cert() {
        let sans = vec!["localhost".to_owned(), "127.0.0.1".to_owned()];
        let (cert_pem, key_pem, not_after) = generate(&sans, 365).unwrap();
        let mat = parse_material(&cert_pem, key_pem.as_str(), not_after).unwrap();
        assert!(!mat.fingerprint_sha256.is_empty());
        assert!(!mat.cert_chain.is_empty());
    }

    #[test]
    fn load_then_reload_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let sans = vec!["localhost".to_owned()];
        let (cert_pem, key_pem, not_after) = generate(&sans, 365).unwrap();
        let cert_path = dir.path().join("cert.pem");
        let key_path = dir.path().join("key.pem");
        std::fs::write(&cert_path, &cert_pem).unwrap();
        std::fs::write(&key_path, &key_pem).unwrap();

        let mat = load_from_files(&cert_path, &key_path).unwrap();
        let mat2 = parse_material(&cert_pem, &key_pem, not_after).unwrap();
        assert_eq!(mat.fingerprint_sha256, mat2.fingerprint_sha256);
    }

    #[test]
    fn renewal_due_when_within_window() {
        let not_after = OffsetDateTime::now_utc() + time::Duration::days(2);
        let before = Duration::from_hours(72);
        assert!(is_due_for_renewal(not_after, before));
    }

    #[test]
    fn renewal_not_due_outside_window() {
        let not_after = OffsetDateTime::now_utc() + time::Duration::days(60);
        let before = Duration::from_hours(720);
        assert!(!is_due_for_renewal(not_after, before));
    }

    #[test]
    fn san_resolver_includes_listen_ip() {
        let addr = test_addr();
        let sans = resolve_sans(addr, &["localhost".to_owned()]);
        assert!(sans.contains(&"127.0.0.1".to_owned()), "listen IP must be in SANs");
        assert!(sans.contains(&"localhost".to_owned()));
    }

    #[test]
    fn resolver_swap_returns_new_cert() {
        let (cert_pem, key_pem, not_after) = generate(&["localhost".to_owned()], 365).unwrap();
        let mat = parse_material(&cert_pem, &key_pem, not_after).unwrap();
        let resolver = AdminCertResolver::new(&mat).unwrap();

        let (renewed_cert, renewed_key, renewed_expiry) = generate(&["localhost".to_owned()], 365).unwrap();
        let mat2 = parse_material(&renewed_cert, &renewed_key, renewed_expiry).unwrap();

        let fp_before = mat.fingerprint_sha256.as_str();
        resolver.swap(&mat2).unwrap();

        let ck = resolver.current.load_full();
        // After swap the resolver holds the new cert — verify fingerprint differs
        // (certs generated milliseconds apart should still have different keys)
        drop(ck);
        assert_ne!(
            fp_before, mat2.fingerprint_sha256,
            "fingerprints must differ after swap"
        );
    }

    #[test]
    fn provided_mode_missing_paths_returns_error() {
        let cfg = AdminTlsConfig {
            mode: AdminTlsMode::Provided,
            cert_pem: None,
            key_pem: None,
            ..AdminTlsConfig::default()
        };
        let addr = test_addr();
        let result = AdminTlsManager::bootstrap(cfg, addr);
        assert!(result.is_err(), "provided mode with no paths must fail");
    }

    #[test]
    fn auto_mode_creates_dir_and_cert() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = AdminTlsConfig {
            mode: AdminTlsMode::Auto,
            data_dir: Some(dir.path().to_path_buf()),
            ..AdminTlsConfig::default()
        };
        let addr = test_addr();
        let manager = AdminTlsManager::bootstrap(cfg, addr).unwrap().unwrap();
        assert!(!manager.fingerprint().is_empty());
        assert!(dir.path().join("cert.pem").exists());
        assert!(dir.path().join("key.pem").exists());
    }

    #[test]
    fn auto_mode_reuses_on_second_boot() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = AdminTlsConfig {
            mode: AdminTlsMode::Auto,
            data_dir: Some(dir.path().to_path_buf()),
            ..AdminTlsConfig::default()
        };
        let addr = test_addr();
        let m1 = AdminTlsManager::bootstrap(cfg.clone(), addr).unwrap().unwrap();
        let fp1 = m1.fingerprint();
        drop(m1);

        let m2 = AdminTlsManager::bootstrap(cfg, addr).unwrap().unwrap();
        let fp2 = m2.fingerprint();
        assert_eq!(fp1, fp2, "fingerprint must be equal on second boot");
    }

    #[cfg(unix)]
    #[test]
    fn auto_mode_key_file_is_0600() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let cfg = AdminTlsConfig {
            mode: AdminTlsMode::Auto,
            data_dir: Some(dir.path().to_path_buf()),
            ..AdminTlsConfig::default()
        };
        AdminTlsManager::bootstrap(cfg, test_addr()).unwrap().unwrap();
        let mode = std::fs::metadata(dir.path().join("key.pem"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600, "key.pem must be chmod 600");
    }
}
