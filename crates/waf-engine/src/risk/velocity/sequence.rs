//! Transaction sequence FSM detector.
//!
//! Tracks Login→OTP→Withdrawal flow per actor. Flags:
//! - Out-of-order transitions (e.g., Withdrawal without Login)
//! - Impossible-fast transitions (e.g., Login→OTP in <1.5s)
//!
//! Emits +30 delta on violation. Sync-side only — fires when sequence
//! completes in a single request chain (FR-012 async handles cross-request).

use dashmap::DashMap;

use crate::risk::key::RiskKey;
use crate::risk::state::{Contributor, ContributorKind};

/// Risk delta for sequence violation.
pub const SEQUENCE_VIOLATION_DELTA: i16 = 30;

/// Minimum time between Login and OTP (milliseconds).
pub const MIN_LOGIN_TO_OTP_MS: i64 = 1500;

/// Minimum time between OTP and Withdrawal (milliseconds).
pub const MIN_OTP_TO_WITHDRAWAL_MS: i64 = 2000;

/// Transaction sequence states.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TxState {
    /// No transaction in progress.
    #[default]
    Idle,
    /// Login completed, awaiting OTP.
    LoggedIn { ts_ms: i64 },
    /// OTP verified, can proceed to withdrawal.
    OtpVerified { ts_ms: i64 },
}

/// Transaction endpoint roles.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TxEndpoint {
    Login,
    Otp,
    Withdrawal,
}

/// Sequence violation types.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SequenceViolation {
    /// OTP attempt without prior login.
    OtpWithoutLogin,
    /// Withdrawal attempt without OTP verification.
    WithdrawalWithoutOtp,
    /// Withdrawal attempt without login.
    WithdrawalWithoutLogin,
    /// Login→OTP transition too fast.
    LoginToOtpTooFast { elapsed_ms: i64 },
    /// OTP→Withdrawal transition too fast.
    OtpToWithdrawalTooFast { elapsed_ms: i64 },
}

/// Per-actor transaction state.
#[derive(Debug, Default)]
pub struct ActorTxState {
    state: TxState,
}

impl ActorTxState {
    /// Process a transaction endpoint and return any violation.
    #[allow(clippy::missing_const_for_fn)] // Mutates self.state
    pub fn transition(&mut self, endpoint: TxEndpoint, now_ms: i64) -> Option<SequenceViolation> {
        match (self.state, endpoint) {
            // Login: always valid, resets state
            (_, TxEndpoint::Login) => {
                self.state = TxState::LoggedIn { ts_ms: now_ms };
                None
            }

            // OTP: must be logged in
            (TxState::Idle, TxEndpoint::Otp) => Some(SequenceViolation::OtpWithoutLogin),
            (TxState::LoggedIn { ts_ms: login_ts }, TxEndpoint::Otp) => {
                let elapsed = now_ms.saturating_sub(login_ts);
                if elapsed < MIN_LOGIN_TO_OTP_MS {
                    self.state = TxState::Idle; // Reset on violation
                    Some(SequenceViolation::LoginToOtpTooFast { elapsed_ms: elapsed })
                } else {
                    self.state = TxState::OtpVerified { ts_ms: now_ms };
                    None
                }
            }
            (TxState::OtpVerified { .. }, TxEndpoint::Otp) => {
                // Re-OTP after OTP is OK (retry scenario)
                self.state = TxState::OtpVerified { ts_ms: now_ms };
                None
            }

            // Withdrawal: must have OTP verified
            (TxState::Idle, TxEndpoint::Withdrawal) => Some(SequenceViolation::WithdrawalWithoutLogin),
            (TxState::LoggedIn { .. }, TxEndpoint::Withdrawal) => {
                self.state = TxState::Idle; // Reset on violation
                Some(SequenceViolation::WithdrawalWithoutOtp)
            }
            (TxState::OtpVerified { ts_ms: otp_ts }, TxEndpoint::Withdrawal) => {
                let elapsed = now_ms.saturating_sub(otp_ts);
                self.state = TxState::Idle; // Withdrawal completes the flow
                if elapsed < MIN_OTP_TO_WITHDRAWAL_MS {
                    Some(SequenceViolation::OtpToWithdrawalTooFast { elapsed_ms: elapsed })
                } else {
                    None
                }
            }
        }
    }
}

/// Sequence FSM store: tracks transaction state per actor.
#[derive(Debug, Default)]
pub struct SequenceStore {
    actors: DashMap<RiskKey, ActorTxState>,
}

impl SequenceStore {
    #[must_use]
    pub fn new() -> Self {
        Self { actors: DashMap::new() }
    }

    /// Process a transaction endpoint for an actor.
    pub fn transition(&self, key: &RiskKey, endpoint: TxEndpoint, now_ms: i64) -> Option<SequenceViolation> {
        let mut entry = self.actors.entry(key.clone()).or_default();
        entry.transition(endpoint, now_ms)
    }

    /// Purge actors that have been idle (in Idle state).
    pub fn purge_idle(&self) -> usize {
        let mut purged = 0;
        self.actors.retain(|_, state| {
            if state.state == TxState::Idle {
                purged += 1;
                false
            } else {
                true
            }
        });
        purged
    }

    /// Number of tracked actors.
    #[must_use]
    pub fn len(&self) -> usize {
        self.actors.len()
    }

    /// Check if store is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.actors.is_empty()
    }
}

/// Evaluate sequence FSM and return a contributor if violation detected.
#[must_use]
pub fn evaluate(
    store: &SequenceStore,
    key: &RiskKey,
    endpoint: Option<TxEndpoint>,
    now_ms: i64,
) -> Option<Contributor> {
    let ep = endpoint?;
    store
        .transition(key, ep, now_ms)
        .map(|_violation| Contributor::new(ContributorKind::Anomaly, SEQUENCE_VIOLATION_DELTA, now_ms))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn make_key() -> RiskKey {
        RiskKey::from_ip(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)))
    }

    #[test]
    fn valid_sequence_no_violation() {
        let mut state = ActorTxState::default();
        let t0 = 10_000i64;

        // Login
        assert!(state.transition(TxEndpoint::Login, t0).is_none());

        // OTP after sufficient delay
        let t1 = t0 + MIN_LOGIN_TO_OTP_MS + 100;
        assert!(state.transition(TxEndpoint::Otp, t1).is_none());

        // Withdrawal after sufficient delay
        let t2 = t1 + MIN_OTP_TO_WITHDRAWAL_MS + 100;
        assert!(state.transition(TxEndpoint::Withdrawal, t2).is_none());
    }

    #[test]
    fn otp_without_login() {
        let mut state = ActorTxState::default();
        let result = state.transition(TxEndpoint::Otp, 10_000);
        assert_eq!(result, Some(SequenceViolation::OtpWithoutLogin));
    }

    #[test]
    fn withdrawal_without_otp() {
        let mut state = ActorTxState::default();
        state.transition(TxEndpoint::Login, 10_000);

        let result = state.transition(TxEndpoint::Withdrawal, 20_000);
        assert_eq!(result, Some(SequenceViolation::WithdrawalWithoutOtp));
    }

    #[test]
    fn withdrawal_without_login() {
        let mut state = ActorTxState::default();
        let result = state.transition(TxEndpoint::Withdrawal, 10_000);
        assert_eq!(result, Some(SequenceViolation::WithdrawalWithoutLogin));
    }

    #[test]
    fn login_to_otp_too_fast() {
        let mut state = ActorTxState::default();
        let t0 = 10_000i64;
        state.transition(TxEndpoint::Login, t0);

        // OTP too fast (only 500ms)
        let result = state.transition(TxEndpoint::Otp, t0 + 500);
        assert!(matches!(result, Some(SequenceViolation::LoginToOtpTooFast { .. })));
    }

    #[test]
    fn otp_to_withdrawal_too_fast() {
        let mut state = ActorTxState::default();
        let t0 = 10_000i64;
        state.transition(TxEndpoint::Login, t0);
        state.transition(TxEndpoint::Otp, t0 + MIN_LOGIN_TO_OTP_MS);

        // Withdrawal too fast (only 500ms after OTP)
        let t_withdraw = t0 + MIN_LOGIN_TO_OTP_MS + 500;
        let result = state.transition(TxEndpoint::Withdrawal, t_withdraw);
        assert!(matches!(result, Some(SequenceViolation::OtpToWithdrawalTooFast { .. })));
    }

    #[test]
    fn store_tracks_separate_actors() {
        let store = SequenceStore::new();
        let key1 = RiskKey::from_ip(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
        let key2 = RiskKey::from_ip(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)));
        let t0 = 10_000i64;

        // key1: logged in
        store.transition(&key1, TxEndpoint::Login, t0);

        // key2: OTP without login (violation)
        let result = store.transition(&key2, TxEndpoint::Otp, t0);
        assert_eq!(result, Some(SequenceViolation::OtpWithoutLogin));

        // key1: OTP should work (after delay)
        let result = store.transition(&key1, TxEndpoint::Otp, t0 + MIN_LOGIN_TO_OTP_MS);
        assert!(result.is_none());
    }

    #[test]
    fn evaluate_returns_contributor_on_violation() {
        let store = SequenceStore::new();
        let key = make_key();

        // OTP without login
        let result = evaluate(&store, &key, Some(TxEndpoint::Otp), 10_000);
        assert!(result.is_some());
        assert_eq!(result.unwrap().delta, SEQUENCE_VIOLATION_DELTA);
    }

    #[test]
    fn evaluate_no_endpoint_returns_none() {
        let store = SequenceStore::new();
        let key = make_key();
        assert!(evaluate(&store, &key, None, 10_000).is_none());
    }
}
