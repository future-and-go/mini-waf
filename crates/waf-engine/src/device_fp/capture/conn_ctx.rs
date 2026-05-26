// FR-010 phase-03 — per-connection capture slot + registry.
//
// `ConnCtx` is the shared mutable slot the TLS / h2 inspectors write
// into during the early bytes of a connection. `ConnRegistry` keys
// those slots by a connection id so the HTTP request stage can fetch
// the right capture before evaluating the device-fingerprint pipeline.
//
// Slot lifetime is bounded by the connection: drop the registry entry
// when the connection terminates. Heavy work (hashing, store I/O)
// happens elsewhere — these methods only mutate small Vec/Option fields
// under a `parking_lot::Mutex`.

use std::sync::Arc;

use dashmap::DashMap;
use parking_lot::Mutex;

use crate::device_fp::capture::parsed::{H2Capture, ParsedClientHello, PriorityFrame, RawCapture};

/// Per-field cap on h2 frame entries retained in a `ConnCtx`. Akamai
/// fingerprinting only needs the first handful of frames; later frames carry
/// no additional signal but would let a peer grow the underlying `Vec`
/// without bound. Drop-newest once the cap is hit.
const MAX_H2_FRAME_ENTRIES: usize = 256;

/// Connection identifier handed in by the gateway. Opaque to this module —
/// pingora's `ConnectionDigest` or any monotonic counter works.
pub type ConnId = u64;

/// Shared, mutable per-connection context. Cloned cheaply via `Arc`.
#[derive(Debug, Default, Clone)]
pub struct ConnCtx {
    inner: Arc<Mutex<RawCapture>>,
}

impl ConnCtx {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Replace the captured `ClientHello`. Last write wins — typical
    /// connections only see one `ClientHello` per handshake.
    pub fn set_client_hello(&self, parsed: ParsedClientHello) {
        self.inner.lock().tls = Some(parsed);
    }

    /// Append a SETTINGS payload (vector of `(id, value)` in wire order).
    pub fn push_h2_settings(&self, pairs: Vec<(u16, u32)>) {
        let mut g = self.inner.lock();
        let remaining = MAX_H2_FRAME_ENTRIES.saturating_sub(g.h2.settings.len());
        if remaining == 0 {
            return;
        }
        g.h2.settings.extend(pairs.into_iter().take(remaining));
    }

    pub fn push_h2_window_update(&self, stream_id: u32, increment: u32) {
        let mut g = self.inner.lock();
        if g.h2.window_updates.len() >= MAX_H2_FRAME_ENTRIES {
            return;
        }
        g.h2.window_updates.push((stream_id, increment));
    }

    pub fn push_h2_priority(&self, frame: PriorityFrame) {
        let mut g = self.inner.lock();
        if g.h2.priority.len() >= MAX_H2_FRAME_ENTRIES {
            return;
        }
        g.h2.priority.push(frame);
    }

    /// Record the pseudo-header order observed on the first HEADERS frame
    /// of a request stream. Only the first observation is retained.
    pub fn set_h2_pseudo_order(&self, order: Vec<String>) {
        let mut g = self.inner.lock();
        if g.h2.pseudo_header_order.is_none() {
            g.h2.pseudo_header_order = Some(order);
        }
    }

    /// Cheap clone of the current capture. Vectors are small (handful of
    /// entries each) so allocation cost is negligible.
    #[must_use]
    pub fn snapshot(&self) -> RawCapture {
        self.inner.lock().clone()
    }

    /// Read-only view of the h2 capture without cloning. Holds the lock
    /// for the duration of `f`, so callers must keep `f` short.
    pub fn with_h2<R>(&self, f: impl FnOnce(&H2Capture) -> R) -> R {
        f(&self.inner.lock().h2)
    }
}

/// Connection-id keyed registry of capture slots. Dropping the registry
/// frees every slot; explicit `remove` is the connection-close hook.
#[derive(Debug, Default)]
pub struct ConnRegistry {
    slots: DashMap<ConnId, ConnCtx>,
}

impl ConnRegistry {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a fresh slot, returning a clone the inspectors will write
    /// into. Replacing an existing entry overwrites silently — caller
    /// owns ID allocation and is expected not to collide.
    pub fn insert(&self, id: ConnId) -> ConnCtx {
        let ctx = ConnCtx::new();
        self.slots.insert(id, ctx.clone());
        ctx
    }

    #[must_use]
    pub fn get(&self, id: ConnId) -> Option<ConnCtx> {
        self.slots.get(&id).map(|r| r.clone())
    }

    /// Connection-close hook. Removing the last `Arc` clone frees the
    /// inner buffers; outstanding inspector clones (held by pingora)
    /// keep the slot alive until they drop.
    pub fn remove(&self, id: ConnId) {
        self.slots.remove(&id);
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.slots.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.slots.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parsed_hello() -> ParsedClientHello {
        ParsedClientHello {
            legacy_version: 0x0303,
            cipher_suites: vec![0x1301, 0x1302],
            extensions: vec![0, 10, 13, 16],
            supported_groups: vec![29, 23],
            signature_algorithms: vec![0x0403, 0x0804],
            alpn: vec!["h2".into(), "http/1.1".into()],
            sni: Some("example.com".into()),
        }
    }

    #[test]
    fn round_trip_capture() {
        let ctx = ConnCtx::new();
        ctx.set_client_hello(parsed_hello());
        ctx.push_h2_settings(vec![(0x1, 4096), (0x3, 100)]);
        ctx.push_h2_window_update(0, 65_535);
        ctx.push_h2_priority(PriorityFrame {
            stream_id: 1,
            depends_on: 0,
            weight: 16,
            exclusive: false,
        });
        ctx.set_h2_pseudo_order(vec![
            ":method".into(),
            ":path".into(),
            ":scheme".into(),
            ":authority".into(),
        ]);

        let snap = ctx.snapshot();
        assert_eq!(snap.tls.as_ref().and_then(|t| t.sni.as_deref()), Some("example.com"));
        assert_eq!(snap.h2.settings.len(), 2);
        assert_eq!(snap.h2.window_updates, vec![(0, 65_535)]);
        assert_eq!(snap.h2.priority.len(), 1);
        assert_eq!(snap.h2.pseudo_header_order.as_ref().map(Vec::len), Some(4));
    }

    #[test]
    fn pseudo_order_first_write_wins() {
        let ctx = ConnCtx::new();
        ctx.set_h2_pseudo_order(vec![":method".into()]);
        ctx.set_h2_pseudo_order(vec![":path".into()]);
        let snap = ctx.snapshot();
        assert_eq!(
            snap.h2.pseudo_header_order.as_deref(),
            Some(&[":method".to_string()][..])
        );
    }

    #[test]
    fn shared_across_clones() {
        let a = ConnCtx::new();
        let b = a.clone();
        a.set_client_hello(parsed_hello());
        assert!(b.snapshot().tls.is_some());
    }

    #[test]
    fn registry_insert_get_remove() {
        let reg = ConnRegistry::new();
        let ctx = reg.insert(42);
        ctx.set_client_hello(parsed_hello());

        let fetched = reg.get(42).expect("present");
        assert!(fetched.snapshot().tls.is_some());
        assert_eq!(reg.len(), 1);

        reg.remove(42);
        assert!(reg.get(42).is_none());
        assert!(reg.is_empty());
    }

    #[test]
    fn registry_drop_frees_slots() {
        let reg = ConnRegistry::new();
        let ctx = reg.insert(1);
        drop(reg);
        // Held context still usable — inspector keeps writing until it drops.
        ctx.push_h2_window_update(0, 1);
        assert_eq!(ctx.snapshot().h2.window_updates.len(), 1);
    }

    #[test]
    fn settings_capped_at_max_entries() {
        let ctx = ConnCtx::new();
        // First batch fills past the cap in one call — extend must clamp.
        let total = MAX_H2_FRAME_ENTRIES + 50;
        let batch: Vec<(u16, u32)> = (0..total)
            .map(|i| {
                let v = u16::try_from(i).unwrap_or(u16::MAX);
                (v, u32::from(v))
            })
            .collect();
        ctx.push_h2_settings(batch);
        assert_eq!(ctx.snapshot().h2.settings.len(), MAX_H2_FRAME_ENTRIES);

        // Subsequent calls past the cap are no-ops.
        ctx.push_h2_settings(vec![(9999, 9999)]);
        let snap = ctx.snapshot();
        assert_eq!(snap.h2.settings.len(), MAX_H2_FRAME_ENTRIES);
        assert_ne!(snap.h2.settings.last(), Some(&(9999u16, 9999u32)));
    }

    #[test]
    fn window_updates_capped_at_max_entries() {
        let ctx = ConnCtx::new();
        for i in 0..(MAX_H2_FRAME_ENTRIES + 100) {
            ctx.push_h2_window_update(u32::try_from(i).unwrap_or(u32::MAX), 1);
        }
        let snap = ctx.snapshot();
        assert_eq!(snap.h2.window_updates.len(), MAX_H2_FRAME_ENTRIES);
        // First-write-wins: cap drops newest, so the final entry must be
        // from before the cap kicked in.
        assert_eq!(
            snap.h2.window_updates.last().map(|&(sid, _)| sid),
            Some(u32::try_from(MAX_H2_FRAME_ENTRIES - 1).unwrap_or(u32::MAX))
        );
    }

    #[test]
    fn priority_capped_at_max_entries() {
        let ctx = ConnCtx::new();
        for i in 0..(MAX_H2_FRAME_ENTRIES + 25) {
            ctx.push_h2_priority(PriorityFrame {
                stream_id: u32::try_from(i).unwrap_or(u32::MAX),
                depends_on: 0,
                weight: 16,
                exclusive: false,
            });
        }
        assert_eq!(ctx.snapshot().h2.priority.len(), MAX_H2_FRAME_ENTRIES);
    }

    #[test]
    fn settings_partial_fill_then_clamp() {
        let ctx = ConnCtx::new();
        // Fill MAX-2 entries first.
        let initial_n = MAX_H2_FRAME_ENTRIES - 2;
        let initial: Vec<(u16, u32)> = (0..initial_n)
            .map(|i| {
                let v = u16::try_from(i).unwrap_or(u16::MAX);
                (v, u32::from(v))
            })
            .collect();
        ctx.push_h2_settings(initial);
        assert_eq!(ctx.snapshot().h2.settings.len(), MAX_H2_FRAME_ENTRIES - 2);

        // Next call brings 10 — only 2 fit.
        ctx.push_h2_settings(vec![
            (1000, 0),
            (1001, 1),
            (1002, 2),
            (1003, 3),
            (1004, 4),
            (1005, 5),
            (1006, 6),
            (1007, 7),
            (1008, 8),
            (1009, 9),
        ]);
        let snap = ctx.snapshot();
        assert_eq!(snap.h2.settings.len(), MAX_H2_FRAME_ENTRIES);
        // The last two appended must be the first two of the batch (drop-newest).
        assert_eq!(snap.h2.settings.get(MAX_H2_FRAME_ENTRIES - 2), Some(&(1000u16, 0u32)));
        assert_eq!(snap.h2.settings.get(MAX_H2_FRAME_ENTRIES - 1), Some(&(1001u16, 1u32)));
    }
}
