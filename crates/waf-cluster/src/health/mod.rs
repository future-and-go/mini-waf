use std::collections::VecDeque;

use anyhow::Result;
use tracing::warn;

/// Phi-accrual failure detector (Cassandra-style).
///
/// Tracks heartbeat inter-arrival times and computes a suspicion level φ.
/// φ > `phi_suspect` → node may be failing.
/// φ > `phi_dead`    → node declared dead, trigger election if it was main.
pub struct PhiAccrualDetector {
    node_id: String,
    /// Ring buffer of heartbeat timestamps (Unix ms)
    window: VecDeque<u64>,
    max_window: usize,
    phi_suspect: f64,
    phi_dead: f64,
}

impl PhiAccrualDetector {
    pub fn new(node_id: String, phi_suspect: f64, phi_dead: f64) -> Self {
        Self {
            node_id,
            window: VecDeque::new(),
            max_window: 100,
            phi_suspect,
            phi_dead,
        }
    }

    /// Record a heartbeat arrival at `timestamp_ms`
    pub fn record_heartbeat(&mut self, timestamp_ms: u64) {
        if self.window.len() >= self.max_window {
            self.window.pop_front();
        }
        self.window.push_back(timestamp_ms);
    }

    /// Compute the phi suspicion value at `now_ms`.
    /// Returns 0.0 if insufficient data.
    pub fn phi(&self, now_ms: u64) -> f64 {
        if self.window.len() < 2 {
            return 0.0;
        }
        let last = self.window.back().copied().unwrap_or(0);
        let elapsed = now_ms.saturating_sub(last) as f64;

        let intervals: Vec<f64> = self
            .window
            .iter()
            .zip(self.window.iter().skip(1))
            .map(|(a, b)| b.saturating_sub(*a) as f64)
            .collect();

        if intervals.is_empty() {
            return 0.0;
        }

        let mean = intervals.iter().sum::<f64>() / intervals.len() as f64;
        if mean <= 0.0 {
            return f64::INFINITY;
        }

        // P(t > elapsed) ≈ exp(−elapsed / mean) for exponential distribution
        let prob = (-elapsed / mean).exp();
        if prob <= 0.0 {
            return f64::INFINITY;
        }
        -prob.log10()
    }

    /// Returns true when φ exceeds the suspect threshold.
    pub fn is_suspected(&self, now_ms: u64) -> bool {
        self.phi(now_ms) > self.phi_suspect
    }

    /// Returns true when φ exceeds the dead threshold, logging a warning.
    pub fn is_dead(&self, now_ms: u64) -> bool {
        let phi = self.phi(now_ms);
        if phi > self.phi_dead {
            warn!(node_id = %self.node_id, phi = phi, "Node declared dead by phi-accrual detector");
            true
        } else {
            false
        }
    }
}

/// Placeholder for the periodic health check task (full implementation in P3).
pub async fn run_health_check(_node_id: &str, _interval_secs: u64) -> Result<()> {
    Ok(())
}
