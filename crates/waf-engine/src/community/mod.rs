pub mod blocklist;
pub mod checker;
pub mod client;
pub mod config;
pub mod enroll;
pub mod reporter;

pub use blocklist::CommunityBlocklistSync;
pub use checker::CommunityChecker;
pub use client::CommunityClient;
pub use config::CommunityConfig;
pub use reporter::{CommunityReporter, RequestInfo};

use std::sync::Arc;
use tokio::sync::watch;
use tracing::{error, info, warn};

/// All runtime components of the community threat intelligence integration.
pub struct CommunityComponents {
    /// HTTP client shared across all community operations
    pub client: Arc<CommunityClient>,
    /// Signal reporter (buffer + flush)
    pub reporter: Arc<CommunityReporter>,
    /// IP blocklist checker for the WAF pipeline
    pub checker: Arc<CommunityChecker>,
    /// Background sync task handle
    pub sync_handle: tokio::task::JoinHandle<()>,
    /// Background flush task handle
    pub flush_handle: tokio::task::JoinHandle<()>,
}

/// Initialise the community threat intelligence integration.
///
/// Performs machine enrollment if no `api_key` is configured, then starts
/// background tasks for signal reporting and blocklist syncing.
///
/// When no `public_key` is configured, automatically attempts to discover
/// the server's signing key via `GET /api/v1/keys/signing`.
///
/// Returns `None` when `config.enabled == false` or when enrollment fails.
pub async fn init_community(
    config: CommunityConfig,
    shutdown_rx: watch::Receiver<bool>,
) -> Option<CommunityComponents> {
    if !config.enabled {
        return None;
    }

    info!(
        server_url = %config.server_url,
        "Initialising community threat intelligence",
    );

    let client = match CommunityClient::new(&config.server_url) {
        Ok(c) => Arc::new(c),
        Err(e) => {
            warn!("Failed to create community HTTP client: {}", e);
            return None;
        }
    };

    // Enrollment: if no api_key is set, attempt auto-enrollment
    let (_machine_id, api_key) = match (&config.machine_id, &config.api_key) {
        (Some(mid), Some(key)) if !mid.is_empty() && !key.is_empty() => (mid.clone(), key.clone()),
        _ => {
            info!("No community API key found, attempting machine enrollment...");
            match enroll::enroll_machine(&client).await {
                Ok(resp) => {
                    info!(
                        machine_id = %resp.machine_id,
                        "Machine enrolled successfully. Save the API key to your config file."
                    );
                    if let Some(ref cred) = resp.enrollment_credential {
                        info!(
                            enrollment_credential = %cred,
                            "Enrollment credential (save this for re-enrollment)"
                        );
                    }
                    (resp.machine_id, resp.api_key)
                }
                Err(e) => {
                    warn!("Community machine enrollment failed: {}", e);
                    return None;
                }
            }
        }
    };

    // Parse optional Ed25519 public key for signature verification.
    //
    // Four cases:
    //   a) public_key present and valid      -> use verified `/blocklist/full` path
    //   b) public_key absent or empty        -> auto-discover from server, fallback to unsigned
    //   c) public_key present but invalid    -> REFUSE to initialise (fail-closed)
    //   d) auto-discovery succeeds           -> use discovered key for verification
    let verify_key = match config.public_key.as_deref().map(str::trim) {
        Some(pk) if !pk.is_empty() => {
            if let Some(vk) = blocklist::parse_public_key(pk) {
                info!("Using manually configured community public key for signature verification");
                Some(vk)
            } else {
                error!(
                    "Community blocklist initialisation REFUSED: public_key is set but invalid. \
                     Fix or remove [community] public_key to continue."
                );
                return None;
            }
        }
        _ => {
            // No public_key configured -- try auto-discovery from server
            info!(
                "No community public_key configured, attempting auto-discovery \
                 from server key endpoint..."
            );
            match blocklist::fetch_signing_keys_from_server(&client).await {
                Ok(keys) => {
                    if let Some((key_id, vk)) = keys.first() {
                        info!(
                            key_id = %key_id,
                            total_keys = keys.len(),
                            "Auto-discovered community signing key, \
                             signature verification enabled"
                        );
                        Some(*vk)
                    } else {
                        warn!(
                            "Community key discovery returned no active keys \
                             -- blocklist running WITHOUT signature verification"
                        );
                        None
                    }
                }
                Err(e) => {
                    warn!(
                        "Community key auto-discovery failed: {e} \
                         -- blocklist running WITHOUT signature verification. \
                         Set [community] public_key manually for MITM protection."
                    );
                    None
                }
            }
        }
    };

    // Create blocklist sync and checker
    let blocklist_sync = Arc::new(CommunityBlocklistSync::new(
        Arc::clone(&client),
        api_key.clone(),
        config.sync_interval_secs,
        verify_key,
    ));
    let checker = Arc::new(CommunityChecker::new(Arc::clone(&blocklist_sync)));

    // Create reporter
    let reporter = Arc::new(CommunityReporter::new(
        Arc::clone(&client),
        api_key,
        config.batch_size,
        config.flush_interval_secs,
    ));

    // Start background flush task
    let reporter_bg = Arc::clone(&reporter);
    let flush_shutdown = shutdown_rx.clone();
    let flush_handle = tokio::spawn(async move {
        reporter_bg.run_flush_task(flush_shutdown).await;
    });

    // Start background blocklist sync task
    let sync_bg = Arc::clone(&blocklist_sync);
    let sync_handle = tokio::spawn(async move {
        sync_bg.run_sync_task(shutdown_rx).await;
    });

    Some(CommunityComponents {
        client,
        reporter,
        checker,
        sync_handle,
        flush_handle,
    })
}
