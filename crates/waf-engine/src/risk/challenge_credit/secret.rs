//! HMAC secret bootstrap for challenge credit tokens.
//!
//! Loads secret from disk; generates 32 random bytes on first boot if absent.
//! Never auto-rotates (Iron Rule §11) — secret persists across restarts.

use std::fs;
use std::io::Write;
use std::path::Path;

use anyhow::{Context, Result};
use rand::RngCore;

/// HMAC secret key (32 bytes = 256 bits).
pub struct HmacSecret([u8; 32]);

impl std::fmt::Debug for HmacSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never expose secret bytes in debug output
        f.debug_struct("HmacSecret").field("0", &"[REDACTED]").finish()
    }
}

impl HmacSecret {
    /// Load secret from disk, or generate + persist if absent.
    ///
    /// # Errors
    /// Returns error if file read/write fails or generated secret can't be written.
    pub fn load_or_init(path: &Path) -> Result<Self> {
        if path.exists() {
            let bytes = fs::read(path).with_context(|| format!("read HMAC secret: {}", path.display()))?;

            if bytes.len() != 32 {
                anyhow::bail!(
                    "HMAC secret file must be exactly 32 bytes, got {} bytes: {}",
                    bytes.len(),
                    path.display()
                );
            }

            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            tracing::info!(path = %path.display(), "loaded HMAC secret from disk");
            return Ok(Self(arr));
        }

        // Generate new secret
        let mut secret = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut secret);

        // Ensure parent directory exists
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).with_context(|| format!("create secret dir: {}", parent.display()))?;
        }

        // Write with restricted permissions (0600)
        Self::write_with_mode(path, &secret)?;

        tracing::info!(path = %path.display(), "generated new HMAC secret");
        Ok(Self(secret))
    }

    /// Write secret bytes with 0600 permissions (Unix only).
    #[cfg(unix)]
    fn write_with_mode(path: &Path, secret: &[u8]) -> Result<()> {
        use std::os::unix::fs::OpenOptionsExt;

        let mut file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)
            .with_context(|| format!("create HMAC secret file: {}", path.display()))?;

        file.write_all(secret)
            .with_context(|| format!("write HMAC secret: {}", path.display()))?;
        Ok(())
    }

    /// Write secret bytes (Windows fallback — no mode bits).
    #[cfg(not(unix))]
    fn write_with_mode(path: &Path, secret: &[u8]) -> Result<()> {
        fs::write(path, secret).with_context(|| format!("write HMAC secret: {}", path.display()))?;
        Ok(())
    }

    /// Get the secret bytes for HMAC operations.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Create secret from raw bytes (test-only, no file I/O).
    #[cfg(test)]
    #[must_use]
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn load_or_init_creates_new_secret() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("hmac.key");

        let secret = HmacSecret::load_or_init(&path).unwrap();
        assert_eq!(secret.as_bytes().len(), 32);
        assert!(path.exists());

        // Verify file is 32 bytes
        let bytes = fs::read(&path).unwrap();
        assert_eq!(bytes.len(), 32);
    }

    #[test]
    fn load_or_init_loads_existing() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("hmac.key");

        // Write known secret
        let known = [42u8; 32];
        fs::write(&path, known).unwrap();

        let secret = HmacSecret::load_or_init(&path).unwrap();
        assert_eq!(secret.as_bytes(), &known);
    }

    #[test]
    fn load_or_init_rejects_wrong_size() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("hmac.key");

        // Write wrong size
        fs::write(&path, [1, 2, 3]).unwrap();

        let result = HmacSecret::load_or_init(&path);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("32 bytes"));
    }

    #[cfg(unix)]
    #[test]
    fn write_sets_0600_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempdir().unwrap();
        let path = dir.path().join("hmac.key");

        let _secret = HmacSecret::load_or_init(&path).unwrap();

        let meta = fs::metadata(&path).unwrap();
        let mode = meta.permissions().mode();
        // Check only user bits (0o700 mask)
        assert_eq!(mode & 0o777, 0o600);
    }
}
