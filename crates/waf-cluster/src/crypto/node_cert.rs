use anyhow::Result;

/// Manages per-node TLS certificates signed by the cluster CA.
///
/// Each node generates a keypair and CSR via rcgen, sends the CSR to main
/// during join, and stores the signed certificate for mTLS.
/// Full rcgen-based implementation is added in P1.
pub struct NodeCertManager {
    node_id: String,
}

impl NodeCertManager {
    pub fn new(node_id: String) -> Self {
        Self { node_id }
    }

    pub fn node_id(&self) -> &str {
        &self.node_id
    }

    /// Generate a Certificate Signing Request (CSR) PEM string.
    pub fn generate_csr(&self) -> Result<String> {
        Ok(String::new())
    }

    /// Sign a CSR PEM string using the provided CA certificate and key.
    /// Returns the signed node certificate as a PEM string.
    pub fn sign_csr(
        &self,
        _csr_pem: &str,
        _ca_cert_pem: &str,
        _ca_key_pem: &str,
        _validity_days: u32,
    ) -> Result<String> {
        Ok(String::new())
    }
}
