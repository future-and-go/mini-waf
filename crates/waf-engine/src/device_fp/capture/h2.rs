// FR-010 phase-03 — real H2 frame inspector.
//
// Pingora's `H2FrameInspector` hook hands us already-parsed
// `H2FrameSnapshot` variants on stream 0 and the first request stream.
// This adapter extracts the fields the Akamai HTTP/2 fingerprint
// consumes and appends them to a per-connection `ConnCtx`.
//
// The hook auto-detaches after the first END_HEADERS, so the inspector
// only sees the early frame window — bounded work per connection.

use std::sync::Arc;

use pingora_core::protocols::inspector::{H2FrameInspector, H2FrameSnapshot};

use crate::device_fp::capture::conn_ctx::ConnCtx;
use crate::device_fp::capture::parsed::PriorityFrame;

/// Real h2 inspector: forwards parsed snapshots into a shared `ConnCtx`.
pub struct H2FrameTap {
    ctx: Arc<ConnCtx>,
}

impl H2FrameTap {
    #[must_use]
    pub const fn new(ctx: Arc<ConnCtx>) -> Self {
        Self { ctx }
    }
}

impl H2FrameInspector for H2FrameTap {
    fn on_frame(&self, frame: &H2FrameSnapshot<'_>) {
        match frame {
            H2FrameSnapshot::Settings(pairs) => {
                self.ctx.push_h2_settings(pairs.to_vec());
            }
            H2FrameSnapshot::WindowUpdate { stream_id, increment } => {
                self.ctx.push_h2_window_update(*stream_id, *increment);
            }
            H2FrameSnapshot::Priority {
                stream_id,
                depends_on,
                weight,
                exclusive,
            } => {
                self.ctx.push_h2_priority(PriorityFrame {
                    stream_id: *stream_id,
                    depends_on: *depends_on,
                    weight: *weight,
                    exclusive: *exclusive,
                });
            }
            H2FrameSnapshot::Headers {
                stream_id: _,
                pseudo_order,
                end_headers: _,
            } => {
                // Only the first observation is retained inside ConnCtx,
                // matching the Akamai fingerprint's "request pseudo order".
                let order: Vec<String> = pseudo_order.iter().map(|s| (*s).to_string()).collect();
                self.ctx.set_h2_pseudo_order(order);
            }
            // `H2FrameSnapshot` is `#[non_exhaustive]`; future variants
            // are silently ignored — they don't contribute to the
            // current Akamai fingerprint definition.
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn captures_full_akamai_field_set() {
        let ctx = Arc::new(ConnCtx::new());
        let insp = H2FrameTap::new(Arc::clone(&ctx));

        // Chrome-ish SETTINGS profile: HEADER_TABLE_SIZE, ENABLE_PUSH=0,
        // INITIAL_WINDOW_SIZE, MAX_HEADER_LIST_SIZE.
        insp.on_frame(&H2FrameSnapshot::Settings(&[
            (0x1, 65_536),
            (0x2, 0),
            (0x4, 6_291_456),
            (0x6, 262_144),
        ]));
        insp.on_frame(&H2FrameSnapshot::WindowUpdate {
            stream_id: 0,
            increment: 15_663_105,
        });
        insp.on_frame(&H2FrameSnapshot::Priority {
            stream_id: 3,
            depends_on: 0,
            weight: 200,
            exclusive: true,
        });
        insp.on_frame(&H2FrameSnapshot::Headers {
            stream_id: 1,
            pseudo_order: &[":method", ":authority", ":scheme", ":path"],
            end_headers: true,
        });

        let snap = ctx.snapshot();
        assert_eq!(snap.h2.settings.len(), 4);
        assert_eq!(snap.h2.settings.get(1).copied(), Some((0x2, 0)));
        assert_eq!(snap.h2.window_updates, vec![(0, 15_663_105)]);
        assert_eq!(snap.h2.priority.len(), 1);
        assert!(snap.h2.priority.first().is_some_and(|p| p.exclusive));
        assert_eq!(
            snap.h2.pseudo_header_order.unwrap(),
            vec![
                ":method".to_string(),
                ":authority".to_string(),
                ":scheme".to_string(),
                ":path".to_string()
            ]
        );
    }

    #[test]
    fn settings_append_across_frames() {
        let ctx = Arc::new(ConnCtx::new());
        let insp = H2FrameTap::new(Arc::clone(&ctx));
        insp.on_frame(&H2FrameSnapshot::Settings(&[(0x1, 4096)]));
        insp.on_frame(&H2FrameSnapshot::Settings(&[(0x3, 100)]));
        let snap = ctx.snapshot();
        assert_eq!(snap.h2.settings, vec![(0x1, 4096), (0x3, 100)]);
    }
}
