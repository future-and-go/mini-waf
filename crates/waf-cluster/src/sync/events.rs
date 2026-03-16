use std::collections::VecDeque;

use tracing::debug;

use crate::protocol::{EventBatch, SecurityEvent};

/// Batches security events on the worker before forwarding to main.
///
/// Events accumulate in a bounded ring buffer. A full batch or timer flush
/// (both handled by the caller) triggers an `EventBatch` message.
pub struct EventBatcher {
    node_id: String,
    queue: VecDeque<SecurityEvent>,
    batch_size: usize,
}

impl EventBatcher {
    pub fn new(node_id: String, batch_size: usize) -> Self {
        Self {
            node_id,
            queue: VecDeque::new(),
            batch_size,
        }
    }

    /// Enqueue a security event
    pub fn push(&mut self, event: SecurityEvent) {
        self.queue.push_back(event);
    }

    /// Drain up to `batch_size` events and return an `EventBatch`, or `None`
    /// if the queue is empty.
    pub fn flush(&mut self) -> Option<EventBatch> {
        if self.queue.is_empty() {
            return None;
        }
        let count = self.queue.len().min(self.batch_size);
        let events: Vec<SecurityEvent> = self.queue.drain(..count).collect();
        debug!(
            node_id = %self.node_id,
            count = events.len(),
            "Flushing event batch"
        );
        Some(EventBatch {
            node_id: self.node_id.clone(),
            events,
        })
    }

    pub fn pending_count(&self) -> usize {
        self.queue.len()
    }
}
