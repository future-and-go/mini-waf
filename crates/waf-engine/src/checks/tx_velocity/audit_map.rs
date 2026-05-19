//! FR-012 issue #60 — map tx-velocity breach signals to `security_events`.
//!
//! Only the three tx-flavoured `device_fp::Signal` variants produce audit
//! rows; the other nine `device_fp` signals are emitted elsewhere and we
//! intentionally ignore them here so the panel can filter by `TX-*`
//! `rule_id` without picking up unrelated detections.

use crate::device_fp::signal::Signal;

/// Stable `rule_id` constants — `&'static str` keeps the emitter alloc-free.
pub const RULE_ID_TX_SEQUENCE: &str = "TX-SEQ-001";
pub const RULE_ID_TX_WITHDRAW: &str = "TX-WITHDRAW-001";
pub const RULE_ID_TX_LIMIT: &str = "TX-LIMIT-001";

pub const RULE_NAME_TX_SEQUENCE: &str = "tx_sequence";
pub const RULE_NAME_TX_WITHDRAW: &str = "tx_withdraw";
pub const RULE_NAME_TX_LIMIT: &str = "tx_limit";

/// Map a device-fp signal to an audit triple. Returns `None` for non-tx
/// variants so the caller can `if let Some(...) = breach_to_audit(&sig)`
/// inside the broader signal loop.
#[must_use]
pub fn breach_to_audit(sig: &Signal) -> Option<(&'static str, &'static str, Option<String>)> {
    match sig {
        Signal::TxSequenceTooFast { from, to, interval_ms } => {
            let detail = serde_json::json!({
                "from": format!("{from:?}"),
                "to": format!("{to:?}"),
                "interval_ms": interval_ms,
            });
            Some((
                RULE_ID_TX_SEQUENCE,
                RULE_NAME_TX_SEQUENCE,
                serde_json::to_string(&detail).ok(),
            ))
        }
        Signal::WithdrawalVelocity { count, window_sec } => {
            let detail = serde_json::json!({
                "count": count,
                "window_sec": window_sec,
            });
            Some((
                RULE_ID_TX_WITHDRAW,
                RULE_NAME_TX_WITHDRAW,
                serde_json::to_string(&detail).ok(),
            ))
        }
        Signal::LimitChangeBurst { count, window_sec } => {
            let detail = serde_json::json!({
                "count": count,
                "window_sec": window_sec,
            });
            Some((
                RULE_ID_TX_LIMIT,
                RULE_NAME_TX_LIMIT,
                serde_json::to_string(&detail).ok(),
            ))
        }
        _ => None,
    }
}

/// Owned audit context — the recorder is sync but `tokio::spawn` moves data
/// into the worker. Holds owned strings so the closure has no borrow
/// dependencies on per-request state.
#[derive(Debug, Clone)]
pub struct OwnedAuditCtx {
    pub host_code: String,
    pub client_ip: String,
    pub method: String,
    pub path: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checks::tx_velocity::EndpointRole;

    #[test]
    fn tx_sequence_too_fast_maps_to_seq_001() {
        let sig = Signal::TxSequenceTooFast {
            from: EndpointRole::Login,
            to: EndpointRole::Deposit,
            interval_ms: 1500,
        };
        let (rule_id, name, detail) = breach_to_audit(&sig).expect("mapped");
        assert_eq!(rule_id, RULE_ID_TX_SEQUENCE);
        assert_eq!(name, RULE_NAME_TX_SEQUENCE);
        let detail = detail.expect("detail");
        assert!(detail.contains("\"interval_ms\":1500"), "got {detail}");
        assert!(detail.contains("Login"));
        assert!(detail.contains("Deposit"));
    }

    #[test]
    fn withdrawal_velocity_maps_to_withdraw_001() {
        let sig = Signal::WithdrawalVelocity {
            count: 12,
            window_sec: 60,
        };
        let (rule_id, name, detail) = breach_to_audit(&sig).expect("mapped");
        assert_eq!(rule_id, RULE_ID_TX_WITHDRAW);
        assert_eq!(name, RULE_NAME_TX_WITHDRAW);
        assert!(detail.unwrap().contains("\"count\":12"));
    }

    #[test]
    fn limit_change_burst_maps_to_limit_001() {
        let sig = Signal::LimitChangeBurst {
            count: 5,
            window_sec: 30,
        };
        let (rule_id, name, detail) = breach_to_audit(&sig).expect("mapped");
        assert_eq!(rule_id, RULE_ID_TX_LIMIT);
        assert_eq!(name, RULE_NAME_TX_LIMIT);
        assert!(detail.unwrap().contains("\"window_sec\":30"));
    }

    #[test]
    fn non_tx_signals_yield_none() {
        assert!(breach_to_audit(&Signal::MissingReferer).is_none());
        assert!(breach_to_audit(&Signal::IpHopping { distinct_ips: 7 }).is_none());
        assert!(breach_to_audit(&Signal::FpConflict { distinct_uas: 3 }).is_none());
    }
}
