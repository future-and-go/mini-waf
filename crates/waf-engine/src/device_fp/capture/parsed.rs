// FR-010 phase-03 — parsed capture data types.
//
// Owned, `Clone` snapshots of the fingerprint-relevant fields extracted
// from the raw TLS ClientHello and the early h2 frame window. Kept
// deliberately flat: phase-04 fingerprint providers concatenate / hash
// these fields directly without needing a second parse pass.

/// Parsed `ClientHello` subset consumed by JA3 / JA4 hashes.
///
/// GREASE values are filtered upstream by the fingerprint provider, not
/// here — keep the wire order intact for the JA3/JA4 contract.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ParsedClientHello {
    /// `legacy_version` from the `ClientHello` (e.g. 0x0303 for TLS 1.2).
    pub legacy_version: u16,
    /// Offered cipher suites in wire order.
    pub cipher_suites: Vec<u16>,
    /// Extension type IDs in wire order.
    pub extensions: Vec<u16>,
    /// `supported_groups` extension (10) — named curves in wire order.
    pub supported_groups: Vec<u16>,
    /// `signature_algorithms` extension (13).
    pub signature_algorithms: Vec<u16>,
    /// ALPN protocol IDs (e.g. "h2", "http/1.1") in wire order.
    pub alpn: Vec<String>,
    /// Server Name Indication, when present.
    pub sni: Option<String>,
}

/// Single PRIORITY frame snapshot retained for the Akamai h2 fingerprint.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PriorityFrame {
    pub stream_id: u32,
    pub depends_on: u32,
    pub weight: u8,
    pub exclusive: bool,
}

/// Captured early h2 frames in arrival order. Stops accumulating after
/// `END_HEADERS` on the first request stream (the inspector self-detaches).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct H2Capture {
    /// SETTINGS payload(s) — vector of (id, value) in wire order.
    pub settings: Vec<(u16, u32)>,
    /// `(stream_id, increment)` for `WINDOW_UPDATE` frames.
    pub window_updates: Vec<(u32, u32)>,
    /// PRIORITY frames in arrival order.
    pub priority: Vec<PriorityFrame>,
    /// Pseudo-header order on the first HEADERS frame for stream 1.
    pub pseudo_header_order: Option<Vec<String>>,
}

/// Owned snapshot of fingerprint-relevant capture for one connection.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RawCapture {
    pub tls: Option<ParsedClientHello>,
    pub h2: H2Capture,
}
