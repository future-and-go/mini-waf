//! PEM → `rustls::sign::CertifiedKey` builder.
//!
//! Shared between cache hydration (`SslManager::hydrate_cache`) and the ACME
//! finalize path (phase 03). Pure / synchronous / no I/O.

use std::sync::Arc;

use anyhow::{Context, Result, anyhow};
use pingora_rustls::CertifiedKey;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};

/// Parse a PEM cert chain + PEM private key into a rustls [`CertifiedKey`].
///
/// Uses the process-default rustls `CryptoProvider` (set up in `prx-waf` main
/// to `ring`) to derive the signing key. Returns an error — never panics — so
/// callers can log-and-skip bad rows during hydrate.
pub fn build_certified_key(cert_pem: &str, key_pem: &str) -> Result<Arc<CertifiedKey>> {
    let cert_chain: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cert_pem.as_bytes())
        .collect::<std::io::Result<Vec<_>>>()
        .context("failed to parse certificate chain from PEM")?;
    if cert_chain.is_empty() {
        return Err(anyhow!("certificate PEM contained no X.509 certificates"));
    }

    let key_der: PrivateKeyDer<'static> = rustls_pemfile::private_key(&mut key_pem.as_bytes())
        .context("failed to read private key from PEM")?
        .ok_or_else(|| anyhow!("private key PEM contained no key"))?;

    let provider = rustls::crypto::CryptoProvider::get_default()
        .ok_or_else(|| anyhow!("no rustls CryptoProvider installed"))?;
    let signing_key = provider
        .key_provider
        .load_private_key(key_der)
        .context("rustls failed to load the private key with the default provider")?;

    Ok(Arc::new(CertifiedKey::new(cert_chain, signing_key)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_empty_cert_chain() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let err = build_certified_key("", "-----BEGIN PRIVATE KEY-----\n-----END PRIVATE KEY-----\n")
            .expect_err("empty cert PEM must fail");
        assert!(format!("{err:#}").to_lowercase().contains("certificate"));
    }

    #[test]
    fn rejects_missing_private_key() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let err = build_certified_key("-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n", "")
            .expect_err("empty key PEM must fail");
        let msg = format!("{err:#}").to_lowercase();
        assert!(msg.contains("private key") || msg.contains("certificate"));
    }
}
