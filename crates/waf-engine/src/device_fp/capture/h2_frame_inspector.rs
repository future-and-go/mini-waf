// No-op HTTP/2 frame inspector — Phase 01 wiring stub.

use pingora_core::protocols::inspector::{H2FrameInspector, H2FrameSnapshot};

/// Discards every observed h2 frame snapshot. Default inspector when
/// FR-010 is disabled.
#[derive(Debug, Default)]
pub struct NoopH2FrameInspector;

impl H2FrameInspector for NoopH2FrameInspector {
    #[inline]
    fn on_frame(&self, _frame: &H2FrameSnapshot<'_>) {
        // intentional no-op
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pingora_core::protocols::inspector::H2FrameInspectorRef;
    use std::sync::Arc;

    #[test]
    fn instantiable_as_trait_object() {
        let _: H2FrameInspectorRef = Arc::new(NoopH2FrameInspector);
    }

    #[test]
    fn accepts_each_snapshot_variant() {
        let inspector = NoopH2FrameInspector;
        inspector.on_frame(&H2FrameSnapshot::Settings(&[(0x1, 4096)]));
        inspector.on_frame(&H2FrameSnapshot::WindowUpdate {
            stream_id: 0,
            increment: 65_535,
        });
        inspector.on_frame(&H2FrameSnapshot::Priority {
            stream_id: 1,
            depends_on: 0,
            weight: 16,
            exclusive: false,
        });
        inspector.on_frame(&H2FrameSnapshot::Headers {
            stream_id: 1,
            pseudo_order: &[":method", ":path", ":scheme", ":authority"],
            end_headers: true,
        });
    }
}
