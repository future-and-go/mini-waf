use std::collections::HashMap;
use std::io::Read as _;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use parking_lot::RwLock;
use serde::Deserialize;
use tokio::sync::watch;
use tracing::{error, info, warn};

use super::client::CommunityClient;

/// Length of an Ed25519 signature in bytes.
const ED25519_SIGNATURE_LEN: usize = 64;

/// Length of an Ed25519 verifying key (public key) in bytes.
const ED25519_PUBKEY_LEN: usize = 32;

/// Maximum response body size for blocklist fetches (8 MiB).
const MAX_BLOCKLIST_RESPONSE_BYTES: usize = 8 * 1024 * 1024;

/// Maximum decompressed blocklist size (16 MiB).
const MAX_DECOMPRESSED_BYTES: u64 = 16 * 1024 * 1024;

/// Version response from `GET /api/v1/waf/blocklist/version`.
#[derive(Debug, Deserialize)]
struct BlocklistVersionResponse {
    version: u64,
}

/// Signed full blocklist response from `GET /api/v1/waf/blocklist/full`.
#[derive(Debug, Deserialize)]
struct BlocklistSignedResponse {
    version: u64,
    /// Optional key identifier returned by the server for key-rotation awareness.
    #[serde(default)]
    key_id: Option<String>,
    payload_hex: String,
    signature_hex: String,
}

/// Decoded (unverified) blocklist response from `GET /api/v1/waf/blocklist/decoded`.
#[derive(Debug, Deserialize)]
struct BlocklistDecodedResponse {
    version: u64,
    entries: Vec<BlocklistEntry>,
}

/// A single blocklist entry from the community server.
#[derive(Debug, Clone, Deserialize)]
pub struct BlocklistEntry {
    pub ip: String,
    pub reason: String,
    pub source: String,
}

/// Delta response from `GET /api/v1/waf/blocklist/delta?since_version=N`.
#[derive(Debug, Deserialize)]
struct DeltaResponse {
    from_version: i64,
    to_version: i64,
    added: Vec<DeltaAddedEntry>,
    removed: Vec<DeltaRemovedEntry>,
}

/// A newly added entry in a blocklist delta.
#[derive(Debug, Deserialize)]
struct DeltaAddedEntry {
    ip: String,
    scenario: String,
    action: Option<String>,
}

/// A removed entry in a blocklist delta.
#[derive(Debug, Deserialize)]
struct DeltaRemovedEntry {
    ip: String,
}

/// Deserialized entry from the signed payload (matches `WafConsensusEntry` shape).
#[derive(Debug, Deserialize)]
struct SignedBlocklistEntry {
    ip: IpAddr,
    scenario: String,
    action: String,
}

/// Community IP decision stored in the local cache.
#[derive(Debug, Clone)]
pub struct CommunityDecision {
    pub reason: String,
    pub source: String,
}

// ---- Public key discovery types ---------------------------------------------

/// Response from `GET /api/v1/keys/signing`.
#[derive(Debug, Deserialize)]
struct KeysResponse {
    keys: Vec<KeyInfo>,
}

/// A single key entry from the signing-keys discovery endpoint.
#[derive(Debug, Deserialize)]
struct KeyInfo {
    key_id: String,
    public_key_hex: String,
    #[serde(default)]
    _algorithm: String,
    status: String,
}

/// Parse a hex-encoded Ed25519 public key string into a `VerifyingKey`.
///
/// Returns `None` and logs an error if the key is malformed.
pub fn parse_public_key(hex_str: &str) -> Option<VerifyingKey> {
    let bytes = match hex::decode(hex_str) {
        Ok(b) => b,
        Err(e) => {
            error!("Community public_key is not valid hex: {e}");
            return None;
        }
    };
    if bytes.len() != ED25519_PUBKEY_LEN {
        error!(
            "Community public_key must be {} bytes, got {}",
            ED25519_PUBKEY_LEN,
            bytes.len()
        );
        return None;
    }
    let mut key_bytes = [0u8; ED25519_PUBKEY_LEN];
    key_bytes.copy_from_slice(&bytes);

    match VerifyingKey::from_bytes(&key_bytes) {
        Ok(vk) => Some(vk),
        Err(e) => {
            error!("Community public_key is not a valid Ed25519 key: {e}");
            None
        }
    }
}

/// Fetch signing public keys from the community server's key-discovery endpoint.
///
/// This is a standalone function (not a method on `CommunityBlocklistSync`) so
/// that it can be called during `init_community` before the sync object exists.
///
/// Returns a list of `(key_id, VerifyingKey)` pairs for all active keys.
pub async fn fetch_signing_keys_from_server(client: &CommunityClient) -> anyhow::Result<Vec<(String, VerifyingKey)>> {
    let url = format!("{}/api/v1/keys/signing", client.base_url);

    let resp = client
        .http
        .get(&url)
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("failed to fetch signing keys: {e}"))?;

    if !resp.status().is_success() {
        anyhow::bail!("signing keys endpoint returned {}", resp.status());
    }

    let body: KeysResponse = resp
        .json()
        .await
        .map_err(|e| anyhow::anyhow!("failed to parse signing keys response: {e}"))?;

    let mut keys = Vec::new();
    for key_info in &body.keys {
        if key_info.status != "active" {
            continue;
        }
        if let Some(vk) = parse_public_key(&key_info.public_key_hex) {
            keys.push((key_info.key_id.clone(), vk));
        }
    }
    Ok(keys)
}

/// Synchronises the community blocklist in the background.
///
/// On startup, performs a full pull of all blocked IPs.
/// Afterwards, periodically checks the version endpoint and only
/// re-fetches when the server version has changed.
///
/// When an Ed25519 `verify_key` is configured, uses the signed
/// `/blocklist/full` endpoint and cryptographically verifies the
/// payload before applying it.  Otherwise, falls back to the
/// unverified `/blocklist/decoded` endpoint (with a warning).
///
/// Uses `parking_lot::RwLock<HashMap>` for atomic map replacement:
/// a new map is built entirely, then swapped in a single write-lock,
/// so readers never see a partially-populated or empty state.
pub struct CommunityBlocklistSync {
    client: Arc<CommunityClient>,
    api_key: String,
    sync_interval_secs: u64,
    /// Ed25519 public key for signature verification.
    /// `None` means signature verification is disabled (fallback mode).
    verify_key: Option<VerifyingKey>,
    /// Blocked IPs from the community server (atomically swapped).
    blocked_ips: RwLock<HashMap<IpAddr, CommunityDecision>>,
    /// Current blocklist version from the server.
    current_version: AtomicU64,
}

impl CommunityBlocklistSync {
    pub fn new(
        client: Arc<CommunityClient>,
        api_key: String,
        sync_interval_secs: u64,
        verify_key: Option<VerifyingKey>,
    ) -> Self {
        if verify_key.is_some() {
            info!("Community blocklist signature verification enabled");
        } else {
            warn!(
                "Community blocklist signature verification DISABLED — \
                 set [community] public_key to enable it"
            );
        }
        Self {
            client,
            api_key,
            sync_interval_secs,
            verify_key,
            blocked_ips: RwLock::new(HashMap::new()),
            current_version: AtomicU64::new(0),
        }
    }

    /// Check if an IP is on the community blocklist.
    pub fn check_ip(&self, ip: &IpAddr) -> Option<CommunityDecision> {
        let map = self.blocked_ips.read();
        map.get(ip).cloned()
    }

    /// Return the number of blocked IPs in the cache.
    pub fn len(&self) -> usize {
        let map = self.blocked_ips.read();
        map.len()
    }

    /// Whether the blocklist cache is empty.
    pub fn is_empty(&self) -> bool {
        let map = self.blocked_ips.read();
        map.is_empty()
    }

    /// Background sync loop: full pull on startup, then periodic version checks.
    pub async fn run_sync_task(self: Arc<Self>, mut shutdown_rx: watch::Receiver<bool>) {
        info!(
            sync_interval_secs = self.sync_interval_secs,
            "Community blocklist sync task started"
        );

        // Full startup pull
        self.full_pull().await;

        let interval = Duration::from_secs(self.sync_interval_secs.max(10));

        loop {
            tokio::select! {
                () = tokio::time::sleep(interval) => {}
                result = shutdown_rx.changed() => {
                    if result.is_err() || *shutdown_rx.borrow() {
                        info!("Community blocklist sync task shutting down");
                        return;
                    }
                }
            }

            // Check if server has a newer version
            match self.fetch_version().await {
                Ok(server_version) => {
                    let local = self.current_version.load(Ordering::Relaxed);
                    if server_version > local {
                        info!(
                            local_version = local,
                            server_version, "Community blocklist version changed, updating"
                        );
                        // Try incremental delta first; fall back to full pull
                        match self.delta_pull().await {
                            Ok(true) => { /* delta applied successfully */ }
                            Ok(false) => {
                                info!("Delta unavailable, performing full pull");
                                self.full_pull().await;
                            }
                            Err(e) => {
                                warn!("Delta pull failed: {e:#}, falling back to full pull");
                                self.full_pull().await;
                            }
                        }
                    }
                }
                Err(e) => {
                    warn!("Failed to check community blocklist version: {e}");
                }
            }
        }
    }

    /// Attempt incremental delta pull.
    ///
    /// Returns `Ok(true)` if the delta was applied successfully,
    /// `Ok(false)` if the caller should fall back to a full pull.
    async fn delta_pull(&self) -> Result<bool, anyhow::Error> {
        let local_version = self.current_version.load(Ordering::Relaxed);
        if local_version == 0 {
            // Never pulled before — must do full pull
            return Ok(false);
        }

        let url = format!(
            "{}/api/v1/waf/blocklist/delta?since_version={}",
            self.client.base_url, local_version
        );
        let resp = self.client.http.get(&url).bearer_auth(&self.api_key).send().await?;

        if resp.status() == reqwest::StatusCode::GONE {
            info!("Delta not available (version too old), falling back to full pull");
            return Ok(false);
        }

        if !resp.status().is_success() {
            anyhow::bail!("delta pull returned {}", resp.status());
        }

        let body = read_response_body_limited(resp, MAX_BLOCKLIST_RESPONSE_BYTES)
            .await
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        let delta: DeltaResponse = serde_json::from_slice(&body)?;

        // Too many changes — fall back to full pull for atomicity
        if delta.added.len() + delta.removed.len() > 5000 {
            info!(
                added = delta.added.len(),
                removed = delta.removed.len(),
                "Delta too large, falling back to full pull"
            );
            return Ok(false);
        }

        // Apply delta to existing map
        let mut map = self.blocked_ips.write();
        for entry in &delta.removed {
            if let Ok(ip) = entry.ip.parse::<IpAddr>() {
                map.remove(&ip);
            }
        }
        for entry in &delta.added {
            if let Ok(ip) = entry.ip.parse::<IpAddr>() {
                map.insert(
                    ip,
                    CommunityDecision {
                        reason: entry.scenario.clone(),
                        source: format!("community-{}", entry.action.as_deref().unwrap_or("block")),
                    },
                );
            }
        }
        drop(map);

        #[allow(clippy::cast_sign_loss)]
        let new_version = delta.to_version as u64;
        self.current_version.store(new_version, Ordering::Relaxed);

        info!(
            from = delta.from_version,
            to = delta.to_version,
            added = delta.added.len(),
            removed = delta.removed.len(),
            "Community blocklist delta applied"
        );
        Ok(true)
    }

    /// Fetch the full blocklist from the community server and replace the cache.
    ///
    /// If a verify key is configured, uses the signed `/blocklist/full` endpoint
    /// and validates the Ed25519 signature before applying.  Otherwise, falls
    /// back to the unverified `/blocklist/decoded` endpoint.
    async fn full_pull(&self) {
        if let Some(ref vk) = self.verify_key {
            self.full_pull_verified(vk).await;
        } else {
            self.full_pull_decoded().await;
        }
    }

    /// Fetch the signed blocklist snapshot, verify the signature, decompress,
    /// and apply to the local cache.
    async fn full_pull_verified(&self, verify_key: &VerifyingKey) {
        let url = format!("{}/api/v1/waf/blocklist/full", self.client.base_url);

        let resp = match self.client.http.get(&url).bearer_auth(&self.api_key).send().await {
            Ok(r) => r,
            Err(e) => {
                warn!("Community blocklist signed pull failed: {e}");
                return;
            }
        };

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            warn!("Community blocklist signed pull returned {status}: {body}");
            return;
        }

        // Stream response body with size limit to prevent memory exhaustion
        let bytes = match read_response_body_limited(resp, MAX_BLOCKLIST_RESPONSE_BYTES).await {
            Ok(b) => b,
            Err(e) => {
                warn!("Community blocklist signed response rejected: {e}");
                return;
            }
        };

        let data: BlocklistSignedResponse = match serde_json::from_slice(&bytes) {
            Ok(d) => d,
            Err(e) => {
                warn!("Failed to parse community blocklist signed response: {e}");
                return;
            }
        };

        // Decode hex-encoded payload (zstd-compressed JSON)
        let payload = match hex::decode(&data.payload_hex) {
            Ok(p) => p,
            Err(e) => {
                warn!("Community blocklist payload_hex decode failed: {e}");
                return;
            }
        };

        // Decode hex-encoded signature
        let sig_bytes = match hex::decode(&data.signature_hex) {
            Ok(s) => s,
            Err(e) => {
                warn!("Community blocklist signature_hex decode failed: {e}");
                return;
            }
        };
        if sig_bytes.len() != ED25519_SIGNATURE_LEN {
            warn!(
                expected = ED25519_SIGNATURE_LEN,
                got = sig_bytes.len(),
                "Community blocklist signature has wrong length"
            );
            return;
        }

        // Reconstruct the Signature from bytes
        let mut sig_arr = [0u8; ED25519_SIGNATURE_LEN];
        sig_arr.copy_from_slice(&sig_bytes);
        let signature = Signature::from_bytes(&sig_arr);

        // Verify the Ed25519 signature over the compressed payload
        if let Err(e) = verify_key.verify(&payload, &signature) {
            // Include the server's key_id (if present) in the error message
            // so operators can diagnose key rotation issues.
            if let Some(ref server_key_id) = data.key_id {
                error!(
                    server_key_id = %server_key_id,
                    "Community blocklist SIGNATURE VERIFICATION FAILED: {e} — \
                     rejecting update. The server's key_id is '{server_key_id}'; \
                     check that [community] public_key matches or remove it to \
                     enable automatic key discovery."
                );
            } else {
                error!(
                    "Community blocklist SIGNATURE VERIFICATION FAILED: {e} — \
                     rejecting update (possible MITM or key mismatch)"
                );
            }
            return;
        }

        info!("Community blocklist signature verified successfully");

        // Decompress zstd payload with size limit
        let decompressed = match decompress_with_limit(&payload, MAX_DECOMPRESSED_BYTES) {
            Ok(d) => d,
            Err(e) => {
                warn!("Community blocklist decompression failed: {e}");
                return;
            }
        };

        // Parse the decompressed JSON as WafConsensusEntry array
        let entries: Vec<SignedBlocklistEntry> = match serde_json::from_slice(&decompressed) {
            Ok(e) => e,
            Err(e) => {
                warn!("Failed to parse community blocklist decompressed JSON: {e}");
                return;
            }
        };

        // Build new map, then atomically swap
        let mut new_map = HashMap::with_capacity(entries.len());
        let mut loaded = 0u64;
        for entry in &entries {
            new_map.insert(
                entry.ip,
                CommunityDecision {
                    reason: entry.scenario.clone(),
                    source: format!("community-{}", entry.action),
                },
            );
            loaded += 1;
        }

        // Atomic swap: single write-lock replaces entire map
        {
            let mut map = self.blocked_ips.write();
            *map = new_map;
        }
        self.current_version.store(data.version, Ordering::Relaxed);

        info!(
            version = data.version,
            loaded,
            total_entries = entries.len(),
            "Community blocklist loaded (signature verified)"
        );
    }

    /// Fallback: fetch the decoded (unverified) blocklist from the community server.
    async fn full_pull_decoded(&self) {
        let url = format!("{}/api/v1/waf/blocklist/decoded", self.client.base_url);

        let resp = match self.client.http.get(&url).bearer_auth(&self.api_key).send().await {
            Ok(r) => r,
            Err(e) => {
                warn!("Community blocklist full pull failed: {e}");
                return;
            }
        };

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            warn!("Community blocklist full pull returned {status}: {body}");
            return;
        }

        // Stream response body with size limit to prevent memory exhaustion
        let bytes = match read_response_body_limited(resp, MAX_BLOCKLIST_RESPONSE_BYTES).await {
            Ok(b) => b,
            Err(e) => {
                warn!("Community blocklist response rejected: {e}");
                return;
            }
        };

        let data: BlocklistDecodedResponse = match serde_json::from_slice(&bytes) {
            Ok(d) => d,
            Err(e) => {
                warn!("Failed to parse community blocklist: {e}");
                return;
            }
        };

        // Build new map off-thread, then atomically swap
        let mut new_map = HashMap::with_capacity(data.entries.len());
        let mut loaded = 0u64;
        for entry in &data.entries {
            if let Ok(ip) = entry.ip.parse::<IpAddr>() {
                new_map.insert(
                    ip,
                    CommunityDecision {
                        reason: entry.reason.clone(),
                        source: entry.source.clone(),
                    },
                );
                loaded += 1;
            }
        }

        // Atomic swap: single write-lock replaces entire map
        {
            let mut map = self.blocked_ips.write();
            *map = new_map;
        }
        self.current_version.store(data.version, Ordering::Relaxed);

        info!(
            version = data.version,
            loaded,
            total_entries = data.entries.len(),
            "Community blocklist loaded (UNVERIFIED — no public key configured)"
        );
    }

    /// Fetch just the version number from the community server.
    async fn fetch_version(&self) -> anyhow::Result<u64> {
        let url = format!("{}/api/v1/waf/blocklist/version", self.client.base_url);

        let resp = self
            .client
            .http
            .get(&url)
            .bearer_auth(&self.api_key)
            .send()
            .await
            .map_err(|e| anyhow::anyhow!("blocklist version request failed: {e}"))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("blocklist version returned {status}: {body}");
        }

        let data: BlocklistVersionResponse = resp
            .json()
            .await
            .map_err(|e| anyhow::anyhow!("failed to parse blocklist version: {e}"))?;
        Ok(data.version)
    }
}

/// Read an HTTP response body in chunks, aborting if the total size exceeds `max_bytes`.
///
/// This prevents a malicious or misbehaving server from forcing the WAF to
/// allocate unbounded memory.  The `Content-Length` header is checked first for
/// a fast-path rejection; then chunks are read incrementally so that even a
/// server that lies about (or omits) `Content-Length` cannot exceed the limit.
async fn read_response_body_limited(mut resp: reqwest::Response, max_bytes: usize) -> Result<bytes::Bytes, String> {
    // Fast-path: reject if Content-Length already exceeds the limit.
    if let Some(cl) = resp.content_length()
        && cl > max_bytes as u64
    {
        return Err(format!("Content-Length {cl} exceeds {max_bytes} byte limit"));
    }

    // Pre-allocate based on Content-Length hint (clamped to limit), or a small default.
    // After the check above, cl <= max_bytes, so the `as usize` cast is safe.
    #[allow(clippy::cast_possible_truncation)]
    let capacity = resp
        .content_length()
        .map_or(8192usize, |cl| (cl as usize).min(max_bytes));
    let mut body = Vec::with_capacity(capacity);

    loop {
        match resp.chunk().await {
            Ok(Some(chunk)) => {
                if body.len() + chunk.len() > max_bytes {
                    return Err(format!(
                        "response body exceeds {max_bytes} byte limit \
                         (read {} + {} chunk bytes)",
                        body.len(),
                        chunk.len(),
                    ));
                }
                body.extend_from_slice(&chunk);
            }
            Ok(None) => break,
            Err(e) => return Err(format!("failed to read response chunk: {e}")),
        }
    }

    Ok(bytes::Bytes::from(body))
}

/// Decompress zstd data with an upper bound on output size to prevent denial-of-service.
fn decompress_with_limit(data: &[u8], max_bytes: u64) -> Result<Vec<u8>, String> {
    let decoder = zstd::Decoder::new(data).map_err(|e| format!("zstd decoder init failed: {e}"))?;
    let mut buf = Vec::new();
    decoder
        .take(max_bytes + 1)
        .read_to_end(&mut buf)
        .map_err(|e| format!("zstd decompression failed: {e}"))?;
    if buf.len() as u64 > max_bytes {
        return Err(format!("decompressed blocklist exceeds {max_bytes} byte limit"));
    }
    Ok(buf)
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::items_after_statements,
    clippy::panic
)]
mod tests {
    use ed25519_dalek::{Signer, SigningKey};

    use super::*;

    /// Helper: generate a random Ed25519 signing key for tests.
    fn test_signing_key() -> SigningKey {
        SigningKey::generate(&mut rand::rngs::OsRng)
    }

    #[test]
    fn parse_valid_public_key() {
        let signing_key = test_signing_key();
        let verifying_key = signing_key.verifying_key();
        let hex_key = hex::encode(verifying_key.to_bytes());

        let parsed = parse_public_key(&hex_key);
        assert!(parsed.is_some());
        assert_eq!(parsed.unwrap().to_bytes(), verifying_key.to_bytes());
    }

    #[test]
    fn parse_invalid_hex_returns_none() {
        assert!(parse_public_key("not-hex!!").is_none());
    }

    #[test]
    fn parse_wrong_length_returns_none() {
        // 16 bytes instead of 32
        assert!(parse_public_key(&hex::encode([0u8; 16])).is_none());
    }

    #[test]
    fn verify_signed_payload_roundtrip() {
        let signing_key = test_signing_key();
        let verifying_key = signing_key.verifying_key();

        // Simulate what the community server does:
        // 1. Serialize entries to JSON
        let entries = serde_json::json!([
            {"ip": "1.2.3.4", "scenario": "brute_force", "confidence": 0.9,
             "reporters": 3, "action": "ban", "expires_at": "2026-12-31T00:00:00Z"}
        ]);
        let json_bytes = serde_json::to_vec(&entries).unwrap();

        // 2. Compress with zstd
        let compressed = zstd::encode_all(json_bytes.as_slice(), 3).unwrap();

        // 3. Sign the compressed data
        let signature = signing_key.sign(&compressed);

        // Hex-encode as the /full endpoint does
        let payload_hex = hex::encode(&compressed);
        let signature_hex = hex::encode(signature.to_bytes());

        // Now verify on the WAF side
        let payload = hex::decode(&payload_hex).unwrap();
        let sig_bytes = hex::decode(&signature_hex).unwrap();
        let mut sig_arr = [0u8; ED25519_SIGNATURE_LEN];
        sig_arr.copy_from_slice(&sig_bytes);
        let sig = Signature::from_bytes(&sig_arr);

        // Verify
        assert!(verifying_key.verify(&payload, &sig).is_ok());

        // Decompress
        let decompressed = zstd::decode_all(payload.as_slice()).unwrap();
        let parsed: Vec<SignedBlocklistEntry> = serde_json::from_slice(&decompressed).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].ip, "1.2.3.4".parse::<IpAddr>().unwrap());
        assert_eq!(parsed[0].scenario, "brute_force");
    }

    #[test]
    fn tampered_payload_rejected() {
        let signing_key = test_signing_key();
        let verifying_key = signing_key.verifying_key();

        let json_bytes = b"[]";
        let compressed = zstd::encode_all(json_bytes.as_slice(), 3).unwrap();
        let signature = signing_key.sign(&compressed);

        // Tamper with the compressed data
        let mut tampered = compressed;
        if let Some(last) = tampered.last_mut() {
            *last ^= 0xFF;
        }

        // Verification must fail
        assert!(verifying_key.verify(&tampered, &signature).is_err());
    }

    #[test]
    fn wrong_key_rejected() {
        let signing_key = test_signing_key();
        let wrong_key = test_signing_key();
        let wrong_verifying = wrong_key.verifying_key();

        let json_bytes = b"[]";
        let compressed = zstd::encode_all(json_bytes.as_slice(), 3).unwrap();
        let signature = signing_key.sign(&compressed);

        // Verification with wrong key must fail
        assert!(wrong_verifying.verify(&compressed, &signature).is_err());
    }
}
