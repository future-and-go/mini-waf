use std::time::{Duration, Instant};

use parking_lot::Mutex;
use tracing::info;

/// Internal state of the circuit breaker.
#[derive(Debug, Clone, Copy, PartialEq)]
enum CircuitState {
    /// Normal operation; tracks consecutive failure count.
    Closed { failure_count: u32 },
    /// Too many failures; all requests short-circuit until cooldown expires.
    Open { opened_at: Instant },
    /// Cooldown elapsed; exactly one probe request is allowed through.
    HalfOpen,
}

/// Circuit breaker for `CrowdSec` `AppSec` HTTP checks.
///
/// Tracks consecutive failures and opens the circuit after `threshold`
/// failures. After `reset_duration` elapses the circuit enters half-open
/// state to allow a single probe request.
pub struct AppSecCircuitBreaker {
    /// All mutable state inside one mutex to avoid TOCTOU races.
    state: Mutex<CircuitState>,
    /// Number of consecutive failures required to open the circuit.
    threshold: u32,
    /// How long the circuit stays open before transitioning to half-open.
    reset_duration: Duration,
}

impl AppSecCircuitBreaker {
    /// Create a new circuit breaker.
    ///
    /// `threshold` is clamped to a minimum of 1 (threshold=0 is ambiguous).
    pub fn new(threshold: u32, reset_secs: u64) -> Self {
        Self {
            state: Mutex::new(CircuitState::Closed { failure_count: 0 }),
            threshold: threshold.max(1),
            reset_duration: Duration::from_secs(reset_secs),
        }
    }

    /// Returns `true` if the request should proceed, `false` to short-circuit.
    ///
    /// When the circuit is `Open` and the cooldown has elapsed, transitions to
    /// `HalfOpen` and allows one probe request through.
    pub fn check_allow(&self) -> bool {
        let mut transitioned_half_open = false;
        let mut state = self.state.lock();
        let allowed = match *state {
            CircuitState::Closed { .. } => true,
            CircuitState::Open { opened_at } => {
                if opened_at.elapsed() >= self.reset_duration {
                    *state = CircuitState::HalfOpen;
                    transitioned_half_open = true;
                    true
                } else {
                    false
                }
            }
            CircuitState::HalfOpen => false,
        };
        drop(state);
        if transitioned_half_open {
            info!("AppSec circuit breaker transitioning to HalfOpen");
        }
        allowed
    }

    /// Record a successful request. Resets failure count / closes the circuit.
    pub fn on_success(&self) {
        let mut state = self.state.lock();
        let was_half_open = matches!(*state, CircuitState::HalfOpen);
        *state = CircuitState::Closed { failure_count: 0 };
        drop(state);
        if was_half_open {
            info!("AppSec circuit breaker closed after successful probe");
        }
    }

    /// Record a failed request. Increments failure count and may open the circuit.
    pub fn on_failure(&self) {
        let mut state = self.state.lock();
        let log_action = match *state {
            CircuitState::Closed { failure_count } => {
                let new_count = failure_count + 1;
                if new_count >= self.threshold {
                    *state = CircuitState::Open {
                        opened_at: Instant::now(),
                    };
                    Some(("opened", new_count))
                } else {
                    *state = CircuitState::Closed {
                        failure_count: new_count,
                    };
                    None
                }
            }
            CircuitState::HalfOpen => {
                *state = CircuitState::Open {
                    opened_at: Instant::now(),
                };
                Some(("reopened", 0))
            }
            CircuitState::Open { .. } => None,
        };
        drop(state);
        match log_action {
            Some(("opened", count)) => {
                info!(
                    threshold = self.threshold,
                    "AppSec circuit breaker OPENED after {count} consecutive failures",
                );
            }
            Some(("reopened", _)) => {
                info!("AppSec circuit breaker re-opened after failed probe");
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn starts_closed_and_allows_requests() {
        let cb = AppSecCircuitBreaker::new(3, 30);
        assert!(cb.check_allow());
    }

    #[test]
    fn n_consecutive_failures_open_circuit() {
        let cb = AppSecCircuitBreaker::new(3, 30);
        cb.on_failure();
        assert!(cb.check_allow(), "1 failure: still closed");
        cb.on_failure();
        assert!(cb.check_allow(), "2 failures: still closed");
        cb.on_failure();
        assert!(!cb.check_allow(), "3 failures: circuit should be open");
    }

    #[test]
    fn open_transitions_to_half_open_after_reset() {
        let cb = AppSecCircuitBreaker::new(1, 60);
        cb.on_failure();
        assert!(!cb.check_allow(), "circuit should be open with long reset");

        // Separate CB with 0s reset to test the HalfOpen transition.
        let cb2 = AppSecCircuitBreaker::new(1, 0);
        cb2.on_failure();
        thread::sleep(Duration::from_millis(1));
        assert!(cb2.check_allow(), "should transition to HalfOpen and allow probe");
    }

    #[test]
    fn half_open_success_closes_circuit() {
        let cb = AppSecCircuitBreaker::new(1, 0);
        cb.on_failure(); // open
        thread::sleep(Duration::from_millis(1));
        assert!(cb.check_allow()); // transitions to HalfOpen, allows probe
        cb.on_success(); // probe succeeded — close
        // Circuit is now closed; should allow freely.
        assert!(cb.check_allow());
        assert!(cb.check_allow());
    }

    #[test]
    fn half_open_failure_reopens_circuit() {
        let cb = AppSecCircuitBreaker::new(1, 0);
        cb.on_failure(); // open
        thread::sleep(Duration::from_millis(1));
        assert!(cb.check_allow()); // transitions to HalfOpen, allows probe
        cb.on_failure(); // probe failed — reopens circuit

        // Verify it went back to Open (and with 0s reset, immediately
        // transitions to HalfOpen on next check — still proves the
        // Open→HalfOpen→failure→Open round-trip).
        thread::sleep(Duration::from_millis(1));
        assert!(cb.check_allow()); // HalfOpen again after reopen expired
        // Now succeed to close it, proving the full cycle.
        cb.on_success();
        assert!(cb.check_allow(), "circuit should be closed after success");
    }

    #[test]
    fn success_resets_failure_count() {
        let cb = AppSecCircuitBreaker::new(3, 30);
        cb.on_failure();
        cb.on_failure();
        // 2 failures, then a success should reset count.
        cb.on_success();
        // Need 3 more failures to open, not just 1.
        cb.on_failure();
        assert!(cb.check_allow(), "failure count should have been reset");
    }

    #[test]
    fn threshold_zero_clamped_to_one() {
        let cb = AppSecCircuitBreaker::new(0, 30);
        // threshold clamped to 1, so a single failure opens.
        cb.on_failure();
        assert!(!cb.check_allow());
    }

    #[test]
    fn concurrent_access_is_safe() {
        use std::sync::Arc;
        let cb = Arc::new(AppSecCircuitBreaker::new(100, 30));
        let mut handles = Vec::new();
        for _ in 0..10 {
            let cb_clone = Arc::clone(&cb);
            handles.push(thread::spawn(move || {
                for _ in 0..50 {
                    cb_clone.on_failure();
                    let _ = cb_clone.check_allow();
                    cb_clone.on_success();
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        // No panic means thread-safe. Circuit should be closed since last ops were on_success.
        assert!(cb.check_allow());
    }
}
