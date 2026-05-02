// No-op ClientHello inspector — Phase 01 wiring stub.

use pingora_core::protocols::inspector::ClientHelloInspector;

/// Discards every `ClientHello` byte slice. Used to prove the trait wiring
/// compiles and to serve as the default inspector when FR-010 is disabled.
#[derive(Debug, Default)]
pub struct NoopClientHelloInspector;

impl ClientHelloInspector for NoopClientHelloInspector {
    #[inline]
    fn on_client_hello(&self, _raw: &[u8]) {
        // intentional no-op
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pingora_core::protocols::inspector::ClientHelloInspectorRef;
    use std::sync::Arc;

    #[test]
    fn instantiable_as_trait_object() {
        let _: ClientHelloInspectorRef = Arc::new(NoopClientHelloInspector);
    }

    #[test]
    fn accepts_arbitrary_bytes() {
        let inspector = NoopClientHelloInspector;
        inspector.on_client_hello(&[]);
        inspector.on_client_hello(&[0x16, 0x03, 0x01]);
    }
}
