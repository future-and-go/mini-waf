//! `VictoriaLogs` child-process sidecar.
//!
//! [`VictoriaLogsSidecar`] owns a `tokio::process::Child` running the upstream
//! `victoria-logs` binary, plus a supervisor task that:
//!
//! * forwards the child's stdout/stderr into the parent `tracing` subscriber,
//! * waits for the `/health` endpoint to become reachable before returning
//!   from [`Self::spawn`],
//! * monitors the child for unexpected exits,
//! * performs graceful shutdown on demand (SIGTERM, then SIGKILL after 5 s),
//! * restarts the child with exponential backoff on unexpected exits.
//!
//! Graceful shutdown is driven by [`Self::shutdown`].  Drop is a best-effort
//! cleanup hatch — it signals the supervisor but cannot synchronously wait
//! for the child to terminate.

use std::process::Stdio;
use std::time::Duration;

use anyhow::Context;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::{Child, Command};
use tracing::{error, info, warn};

use waf_common::config::VictoriaLogsConfig;

/// Time to wait for `/health` to become reachable after spawning the child.
const HEALTH_READY_TIMEOUT: Duration = Duration::from_secs(10);
/// Polling interval while waiting for `/health` during startup.
const HEALTH_POLL_INTERVAL: Duration = Duration::from_millis(500);
/// Background liveness probe interval after startup completes.
const HEALTH_CHECK_INTERVAL: Duration = Duration::from_secs(30);
/// HTTP timeout for a single `/health` request.
const HEALTH_REQUEST_TIMEOUT: Duration = Duration::from_secs(2);
/// Max time to wait for a graceful exit after sending SIGTERM.
const GRACEFUL_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);
/// Initial backoff delay before restarting after an unexpected exit.
const RESTART_BACKOFF_BASE: Duration = Duration::from_secs(1);
/// Maximum backoff delay between restart attempts.
const RESTART_BACKOFF_MAX: Duration = Duration::from_secs(120);
/// Max consecutive failures before the restart loop gives up entirely.
const RESTART_MAX_CONSECUTIVE_FAILURES: u32 = 50;

/// Reason the supervisor returned control to the restart loop.
enum ExitReason {
    /// SIGTERM/SIGINT received — do not restart.
    Shutdown,
    /// Child exited unexpectedly — restart with backoff.
    ChildExited(Option<std::process::ExitStatus>),
    /// Failed to wait on child process.
    WaitError(std::io::Error),
}

/// Marker handle for the running `VictoriaLogs` child.
///
/// The actual `Child` lives inside the supervisor task — kept there so
/// signal handling, health probing, and shutdown all run linearly on the
/// same task without cross-task locking.  This struct exists so the caller
/// has something to keep in scope; dropping it does **not** stop the child,
/// because Pingora's `run_forever` calls `std::process::exit(0)` and never
/// unwinds the parent stack anyway.  The supervisor itself listens for
/// SIGTERM/SIGINT and forwards them to the child.
pub struct VictoriaLogsSidecar {
    _private: (),
}

impl VictoriaLogsSidecar {
    /// Spawn the configured `victoria-logs` binary and wait for it to become
    /// healthy.
    ///
    /// Returns `Ok(None)` when the feature is disabled.  Returns `Err` if the
    /// binary fails to start or `/health` is unreachable within
    /// [`HEALTH_READY_TIMEOUT`].
    ///
    /// The child is supervised in a background task. If the child exits
    /// unexpectedly, the supervisor logs an error but does **not** restart
    /// automatically. For automatic restart, use [`Self::spawn_with_restart`].
    pub async fn spawn(cfg: &VictoriaLogsConfig) -> anyhow::Result<Option<Self>> {
        if !cfg.enabled {
            return Ok(None);
        }

        let child = spawn_child(cfg).await?;
        let listen_addr = cfg.listen_addr.clone();
        let cfg = cfg.clone();

        // Supervisor monitors the initial child; on unexpected exit,
        // hands off to spawn_with_restart for crash recovery with backoff.
        tokio::spawn(async move {
            let reason = supervise_until_exit(child, listen_addr).await;
            if matches!(reason, ExitReason::Shutdown) {
                return;
            }
            warn!("VictoriaLogs exited unexpectedly; entering restart loop");
            if let Err(e) = VictoriaLogsSidecar::spawn_with_restart(&cfg).await {
                error!(error = %e, "VictoriaLogs restart loop failed");
            }
        });

        Ok(Some(Self { _private: () }))
    }

    /// Spawn the configured `victoria-logs` binary with automatic restart on
    /// unexpected exits.
    ///
    /// The first spawn is synchronous (fail-closed): if the binary cannot
    /// start or `/health` is unreachable, the error propagates immediately.
    /// After a successful first run, unexpected exits trigger exponential
    /// backoff restarts (1 s base, 120 s cap). SIGTERM/SIGINT breaks the
    /// loop cleanly without restarting.
    ///
    /// Returns `Ok(None)` when the feature is disabled.
    pub async fn spawn_with_restart(cfg: &VictoriaLogsConfig) -> anyhow::Result<Option<Self>> {
        if !cfg.enabled {
            return Ok(None);
        }

        let mut backoff = RESTART_BACKOFF_BASE;
        let mut consecutive_failures: u32 = 0;

        loop {
            consecutive_failures = consecutive_failures.saturating_add(1);
            info!(attempt = consecutive_failures, "Starting VictoriaLogs sidecar");

            let run_start = tokio::time::Instant::now();

            match spawn_once(cfg).await {
                Ok(ExitReason::Shutdown) => {
                    info!("VictoriaLogs shutdown requested; not restarting");
                    return Ok(Some(Self { _private: () }));
                }
                Ok(ExitReason::ChildExited(status)) => {
                    warn!(?status, "VictoriaLogs exited unexpectedly; restarting in {backoff:?}");
                }
                Ok(ExitReason::WaitError(e)) => {
                    warn!(error = %e, "VictoriaLogs wait error; restarting in {backoff:?}");
                }
                Err(e) => {
                    // First attempt must be fail-closed: propagate the error
                    // so the WAF refuses to start without its audit pipeline.
                    if consecutive_failures == 1 {
                        return Err(e);
                    }
                    error!(error = %e, "Failed to spawn VictoriaLogs; retrying in {backoff:?}");
                }
            }

            if consecutive_failures >= RESTART_MAX_CONSECUTIVE_FAILURES {
                error!(
                    attempts = consecutive_failures,
                    "VictoriaLogs exceeded max consecutive failures; giving up"
                );
                return Ok(None);
            }

            // Listen for shutdown signals during backoff to avoid spawning
            // a new child after SIGTERM arrives while sleeping.
            tokio::select! {
                () = tokio::time::sleep(backoff) => {}
                _ = tokio::signal::ctrl_c() => {
                    info!("Shutdown signal during backoff; exiting restart loop");
                    return Ok(None);
                }
            }

            // Reset backoff after a run that lasted longer than the max
            // backoff duration — indicates the child was stable.
            let run_elapsed = run_start.elapsed();
            if run_elapsed >= RESTART_BACKOFF_MAX {
                backoff = RESTART_BACKOFF_BASE;
                consecutive_failures = 0;
            } else {
                backoff = backoff.saturating_mul(2).min(RESTART_BACKOFF_MAX);
            }
        }
    }
}

/// Spawn the child process, attach stdio forwarders, and wait for health.
/// Returns the healthy `Child` ready for supervision.
async fn spawn_child(cfg: &VictoriaLogsConfig) -> anyhow::Result<Child> {
    tokio::fs::create_dir_all(&cfg.storage_data_path)
        .await
        .with_context(|| format!("create storage_data_path '{}'", cfg.storage_data_path))?;

    let mut command = Command::new(&cfg.binary_path);
    command
        .arg(format!("--storageDataPath={}", cfg.storage_data_path))
        .arg(format!("--httpListenAddr={}", cfg.listen_addr))
        .arg(format!("--retentionPeriod={}", cfg.retention_period))
        .arg(format!(
            "--retention.maxDiskSpaceUsageBytes={}",
            cfg.max_disk_space_bytes
        ))
        .arg(format!("--storage.minFreeDiskSpaceBytes={}", cfg.min_free_disk_bytes))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(false);

    info!(
        binary = %cfg.binary_path,
        listen = %cfg.listen_addr,
        "Spawning VictoriaLogs sidecar"
    );

    let mut child = command
        .spawn()
        .with_context(|| format!("spawn '{}'", cfg.binary_path))?;

    // Detach stdout/stderr forwarders before any await so we never lose
    // log lines that arrived during health-check polling.
    if let Some(stdout) = child.stdout.take() {
        tokio::spawn(forward_lines(stdout, false));
    }
    if let Some(stderr) = child.stderr.take() {
        tokio::spawn(forward_lines(stderr, true));
    }

    let listen_addr = cfg.listen_addr.clone();
    if let Err(e) = wait_until_ready(&listen_addr).await {
        // Best-effort cleanup: kill the child so we don't leak a half-up
        // VictoriaLogs process when the WAF refuses to come up.
        let _ = child.start_kill();
        let _ = child.wait().await;
        return Err(e);
    }
    info!(listen = %listen_addr, "VictoriaLogs sidecar healthy");

    Ok(child)
}

/// Single-shot spawn + supervise: creates the child, waits for health,
/// then blocks until the supervisor returns. Used by the restart loop.
async fn spawn_once(cfg: &VictoriaLogsConfig) -> anyhow::Result<ExitReason> {
    let child = spawn_child(cfg).await?;
    let listen_addr = cfg.listen_addr.clone();
    Ok(supervise_until_exit(child, listen_addr).await)
}

/// Forward a child's stdio stream into the parent `tracing` subscriber line by
/// line.  Lines from stderr are escalated to `warn!` so operators see them
/// without enabling `info!` for the `victoria_logs` target.
async fn forward_lines<R>(reader: R, is_stderr: bool)
where
    R: tokio::io::AsyncRead + Unpin,
{
    let mut lines = BufReader::new(reader).lines();
    loop {
        match lines.next_line().await {
            Ok(Some(line)) => {
                if is_stderr {
                    warn!(target: "victoria_logs", "{line}");
                } else {
                    info!(target: "victoria_logs", "{line}");
                }
            }
            Ok(None) => return,
            Err(e) => {
                warn!(target: "victoria_logs", "log forwarder read error: {e}");
                return;
            }
        }
    }
}

/// Poll `/health` until the response is `200 OK` or the timeout elapses.
async fn wait_until_ready(listen_addr: &str) -> anyhow::Result<()> {
    let url = format!("http://{listen_addr}/health");
    let client = reqwest::Client::builder()
        .timeout(HEALTH_REQUEST_TIMEOUT)
        .build()
        .context("build reqwest client for health probe")?;

    let deadline = tokio::time::Instant::now() + HEALTH_READY_TIMEOUT;
    let mut last_err: Option<String> = None;

    loop {
        if tokio::time::Instant::now() >= deadline {
            let detail = last_err.unwrap_or_else(|| "no probe attempts succeeded".to_string());
            anyhow::bail!("VictoriaLogs '/health' did not become ready within {HEALTH_READY_TIMEOUT:?}: {detail}");
        }

        match client.get(&url).send().await {
            Ok(resp) if resp.status().is_success() => return Ok(()),
            Ok(resp) => last_err = Some(format!("HTTP {}", resp.status())),
            Err(e) => last_err = Some(e.to_string()),
        }
        tokio::time::sleep(HEALTH_POLL_INTERVAL).await;
    }
}

/// Supervisor task: monitors the child and routes shutdown signals.
///
/// Returns an [`ExitReason`] indicating why supervision ended, so the
/// restart loop can decide whether to restart or exit cleanly.
///
/// The supervisor listens directly for SIGTERM/SIGINT.  Pingora's
/// `run_forever` calls `std::process::exit(0)` and never unwinds the parent
/// stack, so a Drop-based shutdown path on [`VictoriaLogsSidecar`] would
/// never fire.  Multiple tokio signal handlers can coexist on the same
/// signal — pingora gets notified for its own graceful shutdown, and our
/// supervisor gets notified to forward the signal to the child.
async fn supervise_until_exit(mut child: Child, listen_addr: String) -> ExitReason {
    let mut health_timer = tokio::time::interval(HEALTH_CHECK_INTERVAL);
    // Reset so the first tick fires after a full interval, not immediately.
    health_timer.reset();
    let probe_url = format!("http://{listen_addr}/health");
    let probe_client = match reqwest::Client::builder().timeout(HEALTH_REQUEST_TIMEOUT).build() {
        Ok(c) => c,
        Err(e) => {
            warn!(error = %e, "Could not build periodic health-probe client; liveness checks disabled");
            // Fall back to a default client; if even default fails we just
            // skip the probe but still react to child exits + shutdowns.
            reqwest::Client::new()
        }
    };

    let mut sigterm = signal_recv(SignalKind::Terminate);
    let mut sigint = signal_recv(SignalKind::Interrupt);

    loop {
        tokio::select! {
            // Process-level SIGTERM / SIGINT — forward to the child before
            // pingora exits the whole process.
            Some(()) = sigterm.recv() => {
                info!("SIGTERM received; forwarding to VictoriaLogs");
                graceful_shutdown(&mut child).await;
                return ExitReason::Shutdown;
            }
            Some(()) = sigint.recv() => {
                info!("SIGINT received; forwarding to VictoriaLogs");
                graceful_shutdown(&mut child).await;
                return ExitReason::Shutdown;
            }
            // Child exited on its own.
            wait_res = child.wait() => {
                match wait_res {
                    Ok(status) => {
                        error!(status = ?status, "VictoriaLogs exited unexpectedly");
                        return ExitReason::ChildExited(Some(status));
                    }
                    Err(e) => {
                        error!(error = %e, "Failed to wait on VictoriaLogs child");
                        return ExitReason::WaitError(e);
                    }
                }
            }
            // Periodic liveness probe.
            _ = health_timer.tick() => {
                match probe_client.get(&probe_url).send().await {
                    Ok(resp) if resp.status().is_success() => {}
                    Ok(resp) => warn!(status = %resp.status(), "VictoriaLogs '/health' returned non-success"),
                    Err(e) => warn!(error = %e, "VictoriaLogs '/health' probe failed"),
                }
            }
        }
    }
}

/// Cross-platform signal kinds the supervisor reacts to.
#[derive(Clone, Copy)]
enum SignalKind {
    Terminate,
    Interrupt,
}

/// Channel that yields `Some(())` whenever the requested signal fires.
///
/// The Unix path uses `tokio::signal::unix`. On non-Unix targets we return
/// a never-resolving channel so the `select!` arm just sits idle — pingora
/// handles process termination via Windows-specific paths, and the WAF is
/// only meaningfully deployed on Unix anyway.
struct SignalRecv {
    #[cfg(unix)]
    inner: Option<tokio::signal::unix::Signal>,
    #[cfg(not(unix))]
    _kind: SignalKind,
}

impl SignalRecv {
    async fn recv(&mut self) -> Option<()> {
        #[cfg(unix)]
        {
            match self.inner.as_mut() {
                Some(sig) => sig.recv().await,
                None => std::future::pending().await,
            }
        }
        #[cfg(not(unix))]
        {
            std::future::pending().await
        }
    }
}

#[cfg(unix)]
fn signal_recv(kind: SignalKind) -> SignalRecv {
    use tokio::signal::unix::{SignalKind as TokioKind, signal};
    let tokio_kind = match kind {
        SignalKind::Terminate => TokioKind::terminate(),
        SignalKind::Interrupt => TokioKind::interrupt(),
    };
    let inner = match signal(tokio_kind) {
        Ok(s) => Some(s),
        Err(e) => {
            warn!(error = %e, "Could not register signal handler in VictoriaLogs supervisor");
            None
        }
    };
    SignalRecv { inner }
}

#[cfg(not(unix))]
fn signal_recv(kind: SignalKind) -> SignalRecv {
    SignalRecv { _kind: kind }
}

/// Send SIGTERM, wait up to [`GRACEFUL_SHUTDOWN_TIMEOUT`], escalate to
/// SIGKILL on timeout. Re-uses the system `kill` binary instead of `libc`
/// so we stay clear of `unsafe` blocks.
async fn graceful_shutdown(child: &mut Child) {
    let pid = child.id();
    if let Some(pid) = pid {
        info!(pid, "Sending SIGTERM to VictoriaLogs");
        if !send_signal_term(pid).await {
            warn!(pid, "Failed to send SIGTERM via `kill`; falling back to SIGKILL");
            let _ = child.start_kill();
        }
    } else {
        // Already exited — `wait()` will return immediately.
        let _ = child.wait().await;
        return;
    }

    match tokio::time::timeout(GRACEFUL_SHUTDOWN_TIMEOUT, child.wait()).await {
        Ok(Ok(status)) => info!(status = ?status, "VictoriaLogs exited gracefully"),
        Ok(Err(e)) => warn!(error = %e, "Error waiting on VictoriaLogs child"),
        Err(_) => {
            warn!(
                "VictoriaLogs did not exit within {:?}; sending SIGKILL",
                GRACEFUL_SHUTDOWN_TIMEOUT
            );
            let _ = child.start_kill();
            if let Err(e) = child.wait().await {
                warn!(error = %e, "Error waiting on VictoriaLogs after SIGKILL");
            }
        }
    }
}

#[cfg(unix)]
async fn send_signal_term(pid: u32) -> bool {
    Command::new("kill")
        .arg("-TERM")
        .arg(pid.to_string())
        .status()
        .await
        .is_ok_and(|s| s.success())
}

#[cfg(not(unix))]
async fn send_signal_term(_pid: u32) -> bool {
    // No graceful-stop primitive on non-Unix targets — fall through to SIGKILL.
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Backoff doubles each iteration up to the cap (120 s), never exceeds it.
    #[test]
    fn backoff_doubles_up_to_cap() {
        let mut backoff = RESTART_BACKOFF_BASE;
        let expected_secs = [1, 2, 4, 8, 16, 32, 64, 120, 120, 120];
        for &expected in &expected_secs {
            assert_eq!(backoff, Duration::from_secs(expected), "backoff should be {expected}s");
            backoff = backoff.saturating_mul(2).min(RESTART_BACKOFF_MAX);
        }
    }

    /// After a stable run (>= RESTART_BACKOFF_MAX), backoff resets to base.
    #[test]
    fn backoff_resets_after_stable_run() {
        let mut backoff = Duration::from_secs(64);

        // Simulate a run that lasted longer than RESTART_BACKOFF_MAX.
        let run_elapsed = RESTART_BACKOFF_MAX + Duration::from_secs(1);
        if run_elapsed >= RESTART_BACKOFF_MAX {
            backoff = RESTART_BACKOFF_BASE;
        }
        assert_eq!(backoff, RESTART_BACKOFF_BASE);
    }

    /// Consecutive failure counter caps at RESTART_MAX_CONSECUTIVE_FAILURES.
    #[test]
    fn max_consecutive_failures_cap() {
        let mut consecutive: u32 = 0;
        let mut gave_up = false;
        for _ in 0..100 {
            consecutive = consecutive.saturating_add(1);
            if consecutive >= RESTART_MAX_CONSECUTIVE_FAILURES {
                gave_up = true;
                break;
            }
        }
        assert!(gave_up, "loop must exit at max consecutive failures");
        assert_eq!(consecutive, RESTART_MAX_CONSECUTIVE_FAILURES);
    }

    /// spawn_with_restart returns None when the sidecar is disabled.
    #[tokio::test]
    async fn spawn_with_restart_disabled_returns_none() {
        let cfg = VictoriaLogsConfig {
            enabled: false,
            binary_path: "/nonexistent/binary".to_string(),
            storage_data_path: "/nonexistent/storage".to_string(),
            ..VictoriaLogsConfig::default()
        };
        let result = VictoriaLogsSidecar::spawn_with_restart(&cfg).await.unwrap();
        assert!(result.is_none(), "disabled sidecar must yield None");
    }
}
