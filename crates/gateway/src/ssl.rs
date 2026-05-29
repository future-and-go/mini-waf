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

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use parking_lot::RwLock;

use tracing::{error, info, warn};
use uuid::Uuid;

use waf_storage::{Database, models::CreateCertificate};

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
    /// ACME contact email
    acme_email: String,
    /// Use Let's Encrypt staging (true) or production (false)
    acme_staging: bool,
}

impl SslManager {
    pub fn new(db: Arc<Database>, acme_email: impl Into<String>, acme_staging: bool) -> Self {
        Self {
            db,
            challenges: Arc::new(ChallengeStore::new()),
            acme_email: acme_email.into(),
            acme_staging,
        }
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
    pub async fn request_certificate(self: Arc<Self>, host_code: &str, domain: &str) -> anyhow::Result<Uuid> {
        use instant_acme::{Account, ChallengeType, Identifier, LetsEncrypt, NewAccount, NewOrder, OrderStatus};
        use rcgen::{CertificateParams, KeyPair};

        info!("Requesting ACME certificate for domain: {}", domain);

        // Create or restore ACME account
        let server_url = if self.acme_staging {
            LetsEncrypt::Staging.url()
        } else {
            LetsEncrypt::Production.url()
        };

        let (account, _credentials) = Account::create(
            &NewAccount {
                contact: &[&format!("mailto:{}", self.acme_email)],
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
    fn test_challenge_store_default_is_empty() {
        let store = ChallengeStore::default();
        assert!(store.get("nope").is_none());
    }

    #[test]
    fn test_challenge_store_overwrite() {
        let store = ChallengeStore::new();
        store.set("t".into(), "v1".into());
        store.set("t".into(), "v2".into());
        assert_eq!(store.get("t"), Some("v2".to_string()));
    }

    #[test]
    fn test_challenge_store_multiple_tokens() {
        let store = ChallengeStore::new();
        store.set("a".into(), "ka".into());
        store.set("b".into(), "kb".into());
        assert_eq!(store.get("a"), Some("ka".to_string()));
        assert_eq!(store.get("b"), Some("kb".to_string()));
        store.remove("a");
        assert!(store.get("a").is_none());
        assert_eq!(store.get("b"), Some("kb".to_string()));
    }

    #[test]
    fn test_challenge_store_remove_missing_is_noop() {
        let store = ChallengeStore::new();
        store.remove("nonexistent");
        assert!(store.get("nonexistent").is_none());
    }

    #[test]
    fn test_self_signed_generation() {
        let (cert_pem, key_pem) = SslManager::generate_self_signed("example.com").expect("self-signed");
        assert!(cert_pem.contains("BEGIN CERTIFICATE"));
        assert!(key_pem.contains("BEGIN"));
    }

    #[test]
    fn test_self_signed_distinct_per_call() {
        let (c1, k1) = SslManager::generate_self_signed("a.test").expect("first");
        let (c2, k2) = SslManager::generate_self_signed("a.test").expect("second");
        // Each call generates a fresh key pair → PEM strings must differ.
        assert_ne!(c1, c2);
        assert_ne!(k1, k2);
    }

    #[test]
    fn test_self_signed_subdomain_and_punycode() {
        let (cert, _) = SslManager::generate_self_signed("api.example.org").expect("subdomain");
        assert!(cert.contains("BEGIN CERTIFICATE"));
        let (cert2, _) = SslManager::generate_self_signed("xn--bcher-kva.example").expect("punycode");
        assert!(cert2.contains("BEGIN CERTIFICATE"));
    }

    #[test]
    fn test_cert_info_clone_and_debug() {
        let now = chrono::Utc::now();
        let info = CertInfo {
            cert_pem: "PEM".into(),
            key_pem: "KEY".into(),
            chain_pem: Some("CHAIN".into()),
            not_before: now,
            not_after: now + chrono::Duration::days(90),
            subject: "CN=example.com".into(),
            issuer: "Let's Encrypt".into(),
        };
        let copy = info.clone();
        assert_eq!(copy.cert_pem, "PEM");
        assert_eq!(copy.subject, "CN=example.com");
        assert_eq!(copy.chain_pem.as_deref(), Some("CHAIN"));
        let debug_str = format!("{info:?}");
        assert!(debug_str.contains("CertInfo"));
        assert!(debug_str.contains("Let's Encrypt"));
    }

    #[test]
    fn test_cert_info_no_chain() {
        let now = chrono::Utc::now();
        let info = CertInfo {
            cert_pem: "PEM".into(),
            key_pem: "KEY".into(),
            chain_pem: None,
            not_before: now,
            not_after: now,
            subject: String::new(),
            issuer: String::new(),
        };
        assert!(info.chain_pem.is_none());
    }
}
