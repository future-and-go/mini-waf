//! SSL/TLS Certificate Automation
//!
//! Manages TLS certificates for WAF-protected sites:
//!   - Storage in `PostgreSQL` (PEM format)
//!   - Let's Encrypt via ACME HTTP-01 challenge (instant-acme crate)
//!   - CSR generation via rcgen
//!   - Auto-renewal 30 days before expiry
//!   - Manual certificate upload API
//!
//! # ACME HTTP-01 Challenge
//!
//! The `SslManager` maintains an in-memory map of pending challenges.
//! The gateway proxy serves challenge tokens at:
//! `GET /.well-known/acme-challenge/{token}`

#![allow(clippy::duration_suboptimal_units)] // prefer `from_secs` over MSRV‑gated `from_mins`/`from_hours`

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use dashmap::DashMap;
use parking_lot::RwLock;

use tracing::{error, info, warn};
use uuid::Uuid;

use pingora_rustls::CertifiedKey;
use waf_storage::{Database, models::CreateCertificate};

use super::build_certified_key::build_certified_key;

// ── Challenge store ───────────────────────────────────────────────────────────

/// In-memory store for pending ACME HTTP-01 challenges.
///
/// Maps `token → key_authorization` for serving at
/// `/.well-known/acme-challenge/{token}`.
#[derive(Default)]
pub struct ChallengeStore {
    inner: RwLock<HashMap<String, String>>,
}

impl ChallengeStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Store a challenge token -> `key_authorization` pair.
    pub fn set(&self, token: String, key_auth: String) {
        self.inner.write().insert(token, key_auth);
    }

    /// Look up the key authorization for a token.
    pub fn get(&self, token: &str) -> Option<String> {
        self.inner.read().get(token).cloned()
    }

    /// Remove a challenge after it has been processed.
    pub fn remove(&self, token: &str) {
        self.inner.write().remove(token);
    }
}

// ── CertInfo ──────────────────────────────────────────────────────────────────

/// Parsed certificate information extracted from PEM.
#[derive(Debug, Clone)]
pub struct CertInfo {
    pub cert_pem: String,
    pub key_pem: String,
    pub chain_pem: Option<String>,
    pub not_before: chrono::DateTime<chrono::Utc>,
    pub not_after: chrono::DateTime<chrono::Utc>,
    pub subject: String,
    pub issuer: String,
}

// ── SslManager ────────────────────────────────────────────────────────────────

/// Manages TLS certificates for all WAF-protected hosts.
pub struct SslManager {
    db: Arc<Database>,
    /// Pending ACME HTTP-01 challenges
    pub challenges: Arc<ChallengeStore>,
    /// ACME contact email (None when operator has no ACME configured yet)
    acme_email: Option<String>,
    /// Use Let's Encrypt staging (true) or production (false)
    acme_staging: bool,
    /// In-memory `domain → CertifiedKey` map. Shared with `DbCertResolver` so
    /// the rustls handshake can do a lock-free per-SNI lookup. Hydrated at
    /// startup from the `certificates` table; refreshed by the background poll.
    cache: Arc<DashMap<String, Arc<CertifiedKey>>>,
    /// Set of hostnames with `tls_terminate=true` in the TOML config. The
    /// resolver consults this allowlist before returning a `CertifiedKey` —
    /// preserves the "WAF speaks plaintext + nginx fronts TLS" intent for hosts
    /// that have a cert in the DB but are not opted in to native termination.
    tls_terminate_hosts: Arc<RwLock<HashSet<String>>>,
}

impl SslManager {
    /// Construct a new `SslManager`.
    ///
    /// `acme_email` is `None` when the operator does not need ACME automation
    /// (manual PEM upload only). The cache and TLS-terminate allowlist start
    /// empty; call [`hydrate_cache`] and [`set_tls_terminate_hosts`] before
    /// binding the TLS listener.
    pub fn new(
        db: Arc<Database>,
        acme_email: Option<impl Into<String>>,
        acme_staging: bool,
    ) -> Self {
        Self {
            db,
            challenges: Arc::new(ChallengeStore::new()),
            acme_email: acme_email.map(Into::into),
            acme_staging,
            cache: Arc::new(DashMap::new()),
            tls_terminate_hosts: Arc::new(RwLock::new(HashSet::new())),
        }
    }

    /// Clone of the cache handle. Pass to [`crate::ssl::DbCertResolver::new`].
    pub fn cache_handle(&self) -> Arc<DashMap<String, Arc<CertifiedKey>>> {
        Arc::clone(&self.cache)
    }

    /// Clone of the `tls_terminate=true` host allowlist. Shared with the
    /// resolver to gate per-SNI lookup.
    pub fn tls_terminate_hosts_handle(&self) -> Arc<RwLock<HashSet<String>>> {
        Arc::clone(&self.tls_terminate_hosts)
    }

    /// Replace the `tls_terminate` allowlist with the given set of hostnames
    /// (lower-cased internally). Call at startup after parsing the TOML config
    /// and again after any host-config reload.
    pub fn set_tls_terminate_hosts<I: IntoIterator<Item = String>>(&self, hosts: I) {
        let mut set = self.tls_terminate_hosts.write();
        set.clear();
        for h in hosts {
            set.insert(h.to_ascii_lowercase());
        }
    }

    /// Load every active certificate from the database into the in-memory cache.
    ///
    /// Returns `(loaded, total_rows)`. Rows that fail to parse are logged and
    /// skipped — caller decides whether to fail-fast when `loaded == 0 && total_rows > 0`.
    pub async fn hydrate_cache(&self) -> anyhow::Result<(usize, usize)> {
        let rows = self.db.list_certificates(None).await?;
        let total = rows.len();
        let mut loaded = 0usize;
        for cert in rows {
            if cert.status != "active" {
                continue;
            }
            let Some(cert_pem) = cert.cert_pem.as_deref() else {
                continue;
            };
            let Some(key_pem) = cert.key_pem.as_deref() else {
                continue;
            };
            match build_certified_key(cert_pem, key_pem) {
                Ok(ck) => {
                    self.cache.insert(cert.domain.to_ascii_lowercase(), ck);
                    loaded += 1;
                }
                Err(e) => {
                    warn!(
                        domain = %cert.domain,
                        error = %e,
                        "skipping certificate that failed to parse"
                    );
                }
            }
        }
        info!("SslManager hydrated cache: {loaded}/{total} active certificates loaded");
        Ok((loaded, total))
    }

    /// Drop the cache entry for a domain. Subsequent handshakes for that SNI
    /// will fail until a fresh cert is loaded via [`reload_cert`] or
    /// [`hydrate_cache`].
    pub fn invalidate(&self, domain: &str) {
        let key = domain.to_ascii_lowercase();
        if self.cache.remove(&key).is_some() {
            info!(domain = %domain, "invalidated cached certificate");
        }
    }

    /// Reload a single certificate by id from the DB into the cache.
    ///
    /// Used by the admin API when an operator uploads a new PEM or forces a
    /// reload, and (later) by the ACME flow after a successful renewal.
    pub async fn reload_cert(&self, cert_id: Uuid) -> anyhow::Result<()> {
        let cert = self
            .db
            .get_certificate(cert_id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("certificate id {cert_id} not found"))?;
        if cert.status != "active" {
            self.invalidate(&cert.domain);
            return Ok(());
        }
        let (Some(cert_pem), Some(key_pem)) = (cert.cert_pem.as_deref(), cert.key_pem.as_deref()) else {
            self.invalidate(&cert.domain);
            anyhow::bail!("certificate id {cert_id} has no PEM material");
        };
        let ck = build_certified_key(cert_pem, key_pem)?;
        self.cache.insert(cert.domain.to_ascii_lowercase(), ck);
        info!(domain = %cert.domain, id = %cert_id, "reloaded cached certificate");
        Ok(())
    }

    /// Background task: re-hydrate the cache every `interval_secs` seconds.
    ///
    /// Phase 02 KISS choice — a coarse poll is sufficient for single-node, ~50
    /// hosts. Replace with `LISTEN/NOTIFY` if/when multi-cluster lands.
    pub fn spawn_cache_refresh_task(
        self: Arc<Self>,
        interval_secs: u64,
    ) -> tokio::task::JoinHandle<()> {
        let interval = Duration::from_secs(interval_secs.max(1));
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(interval);
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            // Skip the immediate first tick — the startup `hydrate_cache` call
            // has just populated everything.
            tick.tick().await;
            loop {
                tick.tick().await;
                if let Err(e) = self.hydrate_cache().await {
                    warn!("cache refresh failed: {e}");
                }
            }
        })
    }

    /// Upload a certificate manually (from file or API).
    ///
    /// Stores the PEM data directly without going through ACME.
    pub async fn upload_certificate(
        &self,
        host_code: &str,
        domain: &str,
        cert_pem: &str,
        key_pem: &str,
        chain_pem: Option<&str>,
    ) -> anyhow::Result<Uuid> {
        let req = CreateCertificate {
            host_code: host_code.to_string(),
            domain: domain.to_string(),
            cert_pem: Some(cert_pem.to_string()),
            key_pem: Some(key_pem.to_string()),
            chain_pem: chain_pem.map(str::to_string),
            auto_renew: Some(false),
        };
        let cert = self.db.create_certificate(req).await?;
        self.db.update_certificate_status(cert.id, "active", None).await?;
        info!("Uploaded certificate for domain {} (id={})", domain, cert.id);
        Ok(cert.id)
    }

    /// Request a new certificate via ACME HTTP-01 for `domain`.
    ///
    /// Stores challenge tokens so the gateway can serve them, then waits for
    /// ACME validation and stores the issued certificate in `PostgreSQL`.
    ///
    /// Requires `acme_email` to be set in the TLS config — returns an error
    /// when called on an `SslManager` constructed without one.
    pub async fn request_certificate(self: Arc<Self>, host_code: &str, domain: &str) -> anyhow::Result<Uuid> {
        use instant_acme::{Account, ChallengeType, Identifier, LetsEncrypt, NewAccount, NewOrder, OrderStatus};
        use rcgen::{CertificateParams, KeyPair};

        let acme_email = self
            .acme_email
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("tls.acme_email is not configured — set it in TOML before requesting an ACME cert"))?;

        info!("Requesting ACME certificate for domain: {}", domain);

        // Create or restore ACME account
        let server_url = if self.acme_staging {
            LetsEncrypt::Staging.url()
        } else {
            LetsEncrypt::Production.url()
        };

        let (account, _credentials) = Account::create(
            &NewAccount {
                contact: &[&format!("mailto:{acme_email}")],
                terms_of_service_agreed: true,
                only_return_existing: false,
            },
            server_url,
            None,
        )
        .await?;

        // Place new order
        let mut order = account
            .new_order(&NewOrder {
                identifiers: &[Identifier::Dns(domain.to_string())],
            })
            .await?;

        // Create a DB entry for tracking
        let req = CreateCertificate {
            host_code: host_code.to_string(),
            domain: domain.to_string(),
            cert_pem: None,
            key_pem: None,
            chain_pem: None,
            auto_renew: Some(true),
        };
        let cert_row = self.db.create_certificate(req).await?;
        let cert_id = cert_row.id;

        // Process HTTP-01 challenge
        let authorizations = order.authorizations().await?;
        for auth in &authorizations {
            let challenge = auth
                .challenges
                .iter()
                .find(|c| c.r#type == ChallengeType::Http01)
                .ok_or_else(|| anyhow::anyhow!("No HTTP-01 challenge available"))?;

            let key_auth = order.key_authorization(challenge);
            self.challenges
                .set(challenge.token.clone(), key_auth.as_str().to_string());

            order.set_challenge_ready(&challenge.url).await?;
        }

        // Wait for order to become ready (poll up to 60s)
        let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
        loop {
            tokio::time::sleep(Duration::from_secs(2)).await;
            let state = order.refresh().await?;
            match state.status {
                OrderStatus::Ready | OrderStatus::Valid => break,
                OrderStatus::Invalid => {
                    let _ = self
                        .db
                        .update_certificate_status(cert_id, "error", Some("ACME validation failed"))
                        .await;
                    anyhow::bail!("ACME order invalid for domain {domain}");
                }
                _ => {}
            }
            if tokio::time::Instant::now() > deadline {
                let _ = self
                    .db
                    .update_certificate_status(cert_id, "error", Some("ACME validation timeout"))
                    .await;
                anyhow::bail!("ACME validation timed out for domain {domain}");
            }
        }

        // Generate key pair and CSR
        let key_pair = KeyPair::generate()?;
        let csr_params = CertificateParams::new(vec![domain.to_string()])?;
        let csr = csr_params.serialize_request(&key_pair)?;

        // Finalize and download certificate
        order.finalize(csr.der()).await?;

        // Wait for certificate to be available
        let cert_chain = loop {
            tokio::time::sleep(Duration::from_secs(1)).await;
            if let Some(chain) = order.certificate().await? {
                break chain;
            }
        };

        let cert_pem = cert_chain;
        let key_pem = key_pair.serialize_pem();
        let now = chrono::Utc::now();
        let not_after = now + chrono::Duration::days(90); // typical LE validity

        self.db
            .update_certificate_pem(&waf_storage::models::UpdateCertificatePem {
                id: cert_id,
                cert_pem: &cert_pem,
                key_pem: &key_pem,
                chain_pem: None,
                not_before: now,
                not_after,
                issuer: "Let's Encrypt",
                subject: domain,
            })
            .await?;

        // Clean up challenges
        for auth in &authorizations {
            if let Some(c) = auth.challenges.iter().find(|c| c.r#type == ChallengeType::Http01) {
                self.challenges.remove(&c.token);
            }
        }

        info!(
            "Certificate issued for domain {} (id={}), valid until {}",
            domain, cert_id, not_after
        );
        Ok(cert_id)
    }

    /// Check certificates due for renewal and renew them.
    ///
    /// Should be called periodically (e.g., daily) by a background task.
    pub async fn renew_due_certificates(self: Arc<Self>) -> anyhow::Result<()> {
        let due = self.db.list_certificates_due_renewal(30).await?;
        if due.is_empty() {
            return Ok(());
        }

        info!("Found {} certificate(s) due for renewal", due.len());
        for cert in due {
            let mgr = Arc::clone(&self);
            let domain = cert.domain.clone();
            let host_code = cert.host_code.clone();
            tokio::spawn(async move {
                if let Err(e) = mgr.request_certificate(&host_code, &domain).await {
                    error!("Failed to renew certificate for {}: {}", domain, e);
                }
            });
        }

        Ok(())
    }

    /// Spawn the auto-renewal background task.
    ///
    /// Checks for certificates due renewal every 24 hours.
    pub fn spawn_renewal_task(self: Arc<Self>) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let interval = Duration::from_secs(86_400);
            loop {
                tokio::time::sleep(interval).await;
                if let Err(e) = Arc::clone(&self).renew_due_certificates().await {
                    warn!("Certificate renewal check failed: {}", e);
                }
            }
        })
    }

    /// Generate a self-signed certificate for a domain (useful for testing).
    pub fn generate_self_signed(domain: &str) -> anyhow::Result<(String, String)> {
        use rcgen::{CertificateParams, KeyPair};

        let key_pair = KeyPair::generate()?;
        let params = CertificateParams::new(vec![domain.to_string()])?;
        let cert = params.self_signed(&key_pair)?;

        Ok((cert.pem(), key_pair.serialize_pem()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_challenge_store() {
        let store = ChallengeStore::new();
        store.set("token123".into(), "keyauth456".into());
        assert_eq!(store.get("token123"), Some("keyauth456".to_string()));
        store.remove("token123");
        assert_eq!(store.get("token123"), None);
    }

    #[test]
    fn test_self_signed_generation() {
        let (cert_pem, key_pem) = SslManager::generate_self_signed("example.com").unwrap();
        assert!(cert_pem.contains("BEGIN CERTIFICATE"));
        assert!(key_pem.contains("BEGIN"));
    }
}
