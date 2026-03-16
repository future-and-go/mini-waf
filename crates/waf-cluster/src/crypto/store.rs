use anyhow::Result;

/// Encrypted on-disk store for the cluster CA private key.
///
/// The CA key is encrypted with AES-256-GCM using a passphrase-derived key
/// and written to a file. This protects the key at rest and enables CA key
/// replication to workers (encrypted) during the join handshake.
/// Full AES-GCM implementation using waf_common::crypto is added in P1.
pub struct KeyStore {
    path: String,
}

impl KeyStore {
    pub fn new(path: &str) -> Self {
        Self {
            path: path.to_string(),
        }
    }

    pub fn path(&self) -> &str {
        &self.path
    }

    /// Load and decrypt the CA private key from disk.
    pub fn load_ca_key(&self) -> Result<Vec<u8>> {
        Ok(Vec::new())
    }

    /// Encrypt and persist the CA private key to disk.
    pub fn save_ca_key(&self, _key_bytes: &[u8], _passphrase: &str) -> Result<()> {
        Ok(())
    }
}
