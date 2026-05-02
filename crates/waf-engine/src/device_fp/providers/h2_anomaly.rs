//! HTTP/2 structural anomaly provider.
//!
//! Inspects captured h2 frames on the connection and emits one
//! `Signal::H2Anomaly` per distinct anomaly class. Checks are limited to
//! deterministic protocol violations (no heuristics):
//! - `WINDOW_UPDATE` increment == 0 → `ZeroWindowUpdate` (RFC 7540 §6.9)
//! - `PRIORITY` self-dependency (`stream_id == depends_on`) → `InvalidPriority` (§5.3.1)
//! - Pseudo-header order missing one of `:method` / `:scheme` /
//!   `:authority` / `:path` → `PseudoHeaderOrder` (§8.1.2.3)
//! - Empty SETTINGS when `expect_settings` is on → `BadSettings`

use crate::device_fp::providers::SignalProvider;
use crate::device_fp::signal::{H2AnomalyReason, Signal};
use crate::device_fp::types::DeviceCtx;

#[derive(Debug, Clone, Copy, Default)]
pub struct H2AnomalyProvider {
    /// When true, an h2 connection that produced zero SETTINGS payload
    /// is flagged as `BadSettings`. Off by default — empty captures may
    /// just mean the connection wasn't h2.
    pub expect_settings: bool,
}

impl H2AnomalyProvider {
    #[must_use]
    pub const fn new(expect_settings: bool) -> Self {
        Self { expect_settings }
    }
}

impl SignalProvider for H2AnomalyProvider {
    fn name(&self) -> &'static str {
        "h2_anomaly"
    }
    fn evaluate(&self, ctx: &DeviceCtx<'_>) -> Vec<Signal> {
        let mut out = Vec::new();
        ctx.conn.with_h2(|h2| {
            let any_h2_data = !h2.settings.is_empty()
                || !h2.window_updates.is_empty()
                || !h2.priority.is_empty()
                || h2.pseudo_header_order.is_some();

            if self.expect_settings && any_h2_data && h2.settings.is_empty() {
                out.push(Signal::H2Anomaly {
                    reason: H2AnomalyReason::BadSettings,
                });
            }
            if h2.window_updates.iter().any(|&(_, inc)| inc == 0) {
                out.push(Signal::H2Anomaly {
                    reason: H2AnomalyReason::ZeroWindowUpdate,
                });
            }
            if h2.priority.iter().any(|f| f.depends_on == f.stream_id) {
                out.push(Signal::H2Anomaly {
                    reason: H2AnomalyReason::InvalidPriority,
                });
            }
            if let Some(order) = h2.pseudo_header_order.as_ref() {
                let required = [":method", ":scheme", ":authority", ":path"];
                let missing = required.iter().any(|r| !order.iter().any(|h| h == r));
                if missing {
                    out.push(Signal::H2Anomaly {
                        reason: H2AnomalyReason::PseudoHeaderOrder,
                    });
                }
            }
        });
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device_fp::capture::ConnCtx;
    use crate::device_fp::capture::parsed::PriorityFrame;
    use crate::device_fp::types::FpKey;
    use std::net::{IpAddr, Ipv4Addr};

    fn ctx_with(conn: &ConnCtx, key: &FpKey) -> Vec<Signal> {
        let p = H2AnomalyProvider::new(true);
        let ctx = DeviceCtx::new(IpAddr::V4(Ipv4Addr::LOCALHOST), "ua", conn, key);
        p.evaluate(&ctx)
    }

    #[test]
    fn clean_h2_emits_nothing() {
        let conn = ConnCtx::new();
        conn.push_h2_settings(vec![(0x1, 4096)]);
        conn.push_h2_window_update(0, 65_535);
        conn.push_h2_priority(PriorityFrame {
            stream_id: 1,
            depends_on: 0,
            weight: 16,
            exclusive: false,
        });
        conn.set_h2_pseudo_order(vec![
            ":method".into(),
            ":authority".into(),
            ":scheme".into(),
            ":path".into(),
        ]);
        let key = FpKey::default();
        assert!(ctx_with(&conn, &key).is_empty());
    }

    #[test]
    fn flags_zero_window_update() {
        let conn = ConnCtx::new();
        conn.push_h2_settings(vec![(0x1, 4096)]);
        conn.push_h2_window_update(1, 0);
        let key = FpKey::default();
        let s = ctx_with(&conn, &key);
        assert!(s.iter().any(|x| matches!(
            x,
            Signal::H2Anomaly {
                reason: H2AnomalyReason::ZeroWindowUpdate
            }
        )));
    }

    #[test]
    fn flags_self_dependency_priority() {
        let conn = ConnCtx::new();
        conn.push_h2_settings(vec![(0x1, 4096)]);
        conn.push_h2_priority(PriorityFrame {
            stream_id: 3,
            depends_on: 3,
            weight: 16,
            exclusive: false,
        });
        let key = FpKey::default();
        let s = ctx_with(&conn, &key);
        assert!(s.iter().any(|x| matches!(
            x,
            Signal::H2Anomaly {
                reason: H2AnomalyReason::InvalidPriority
            }
        )));
    }

    #[test]
    fn flags_missing_pseudo_header() {
        let conn = ConnCtx::new();
        conn.push_h2_settings(vec![(0x1, 4096)]);
        conn.set_h2_pseudo_order(vec![":method".into(), ":path".into()]);
        let key = FpKey::default();
        let s = ctx_with(&conn, &key);
        assert!(s.iter().any(|x| matches!(
            x,
            Signal::H2Anomaly {
                reason: H2AnomalyReason::PseudoHeaderOrder
            }
        )));
    }

    #[test]
    fn flags_missing_settings_when_expected() {
        let conn = ConnCtx::new();
        // Some h2 activity but no SETTINGS frame.
        conn.push_h2_window_update(0, 1);
        let key = FpKey::default();
        let s = ctx_with(&conn, &key);
        assert!(s.iter().any(|x| matches!(
            x,
            Signal::H2Anomaly {
                reason: H2AnomalyReason::BadSettings
            }
        )));
    }

    #[test]
    fn empty_capture_no_signals() {
        let conn = ConnCtx::new();
        let key = FpKey::default();
        assert!(ctx_with(&conn, &key).is_empty());
    }
}
