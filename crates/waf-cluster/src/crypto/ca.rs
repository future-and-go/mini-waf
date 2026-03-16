use anyhow::Result;

/// Cluster root Certificate Authority.
///
/// The first main node generates the CA on startup. The CA signs all node
/// certificates and is distributed to workers during the join handshake.
/// Full rcgen-based implementation is added in P1.
pub struct CertificateAuthority {
    cert_pem: String,
    key_pem: String,
}

impl CertificateAuthority {
    /// Generate a new self-signed CA keypair valid for `validity_days`.
    pub fn generate(_validity_days: u32) -> Result<Self> {
        Ok(Self {
            cert_pem: String::new(),
            key_pem: String::new(),
        })
    }

    /// Load an existing CA from PEM strings.
    pub fn from_pem(cert_pem: String, key_pem: String) -> Self {
        Self { cert_pem, key_pem }
    }

    pub fn cert_pem(&self) -> &str {
        &self.cert_pem
    }

    pub fn key_pem(&self) -> &str {
        &self.key_pem
    }
}
