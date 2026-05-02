// FR-010 phase-03 — real ClientHello inspector + parser.
//
// Parses the TLS 1.x ClientHello handshake message handed to us by
// pingora's `ClientHelloInspector` hook. Hand-rolled, allocation-light:
// only the fields JA3 / JA4 hash consume are extracted; everything
// else is skipped without copying.
//
// Spec: RFC 5246 §7.4.1.2 (TLS 1.2), RFC 8446 §4.1.2 (TLS 1.3).
// Extensions: RFC 6066 (SNI = 0), RFC 8422 (supported_groups = 10),
// RFC 5246 (signature_algorithms = 13), RFC 7301 (ALPN = 16).
//
// Failure mode: malformed bytes return `Err(ParseError)`; the inspector
// stores nothing on parse failure rather than panicking. Adversarial
// peers must not crash the proxy.

use std::sync::Arc;

use pingora_core::protocols::inspector::ClientHelloInspector;

use crate::device_fp::capture::conn_ctx::ConnCtx;
use crate::device_fp::capture::parsed::ParsedClientHello;

/// Errors returned by [`parse_client_hello`]. All variants indicate a
/// malformed or truncated buffer; callers should drop the capture and
/// continue serving the connection (fail-open at fingerprint layer).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    UnexpectedEof,
    BadHandshakeType(u8),
    LengthMismatch,
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnexpectedEof => write!(f, "unexpected EOF parsing ClientHello"),
            Self::BadHandshakeType(t) => write!(f, "bad handshake type 0x{t:02x}"),
            Self::LengthMismatch => write!(f, "declared length does not fit buffer"),
        }
    }
}

impl std::error::Error for ParseError {}

/// Cursor-based reader over a borrowed byte slice. Returns `Err` instead
/// of panicking on short reads — adversarial inputs must be rejected.
/// All access is via `split_at_checked` / `split_first` so no panic
/// indexing reaches the hot path.
struct Reader<'a> {
    buf: &'a [u8],
}

impl<'a> Reader<'a> {
    const fn new(buf: &'a [u8]) -> Self {
        Self { buf }
    }

    const fn remaining(&self) -> usize {
        self.buf.len()
    }

    fn u8(&mut self) -> Result<u8, ParseError> {
        let (b, rest) = self.buf.split_first().ok_or(ParseError::UnexpectedEof)?;
        self.buf = rest;
        Ok(*b)
    }

    fn u16(&mut self) -> Result<u16, ParseError> {
        let s = self.take(2)?;
        let arr: [u8; 2] = s.try_into().map_err(|_| ParseError::UnexpectedEof)?;
        Ok(u16::from_be_bytes(arr))
    }

    fn u24(&mut self) -> Result<u32, ParseError> {
        let s = self.take(3)?;
        let arr: [u8; 3] = s.try_into().map_err(|_| ParseError::UnexpectedEof)?;
        Ok((u32::from(arr[0]) << 16) | (u32::from(arr[1]) << 8) | u32::from(arr[2]))
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], ParseError> {
        let (head, tail) = self.buf.split_at_checked(n).ok_or(ParseError::UnexpectedEof)?;
        self.buf = tail;
        Ok(head)
    }

    fn skip(&mut self, n: usize) -> Result<(), ParseError> {
        self.take(n).map(|_| ())
    }
}

/// Parse a `ClientHello` handshake message starting at the handshake type
/// byte (0x01). Returns the subset of fields the device-fingerprint
/// providers consume.
pub fn parse_client_hello(raw: &[u8]) -> Result<ParsedClientHello, ParseError> {
    let mut r = Reader::new(raw);

    let ht = r.u8()?;
    if ht != 0x01 {
        return Err(ParseError::BadHandshakeType(ht));
    }
    let body_len = r.u24()? as usize;
    if r.remaining() < body_len {
        return Err(ParseError::LengthMismatch);
    }

    let legacy_version = r.u16()?;
    r.skip(32)?; // random

    let sid_len = r.u8()? as usize;
    r.skip(sid_len)?;

    let cs_bytes = r.u16()? as usize;
    if !cs_bytes.is_multiple_of(2) {
        return Err(ParseError::LengthMismatch);
    }
    let cs_slice = r.take(cs_bytes)?;
    let cipher_suites: Vec<u16> = cs_slice
        .chunks_exact(2)
        .filter_map(|c| <[u8; 2]>::try_from(c).ok())
        .map(u16::from_be_bytes)
        .collect();

    let cm_len = r.u8()? as usize;
    r.skip(cm_len)?;

    // Extensions are optional in TLS 1.2 but mandatory in TLS 1.3 — treat
    // a buffer that ends here as "no extensions" and return what we have.
    if r.remaining() == 0 {
        return Ok(ParsedClientHello {
            legacy_version,
            cipher_suites,
            ..Default::default()
        });
    }

    let ext_total = r.u16()? as usize;
    let ext_slice = r.take(ext_total)?;
    let (extensions, supported_groups, signature_algorithms, alpn, sni) =
        parse_extensions(ext_slice)?;

    Ok(ParsedClientHello {
        legacy_version,
        cipher_suites,
        extensions,
        supported_groups,
        signature_algorithms,
        alpn,
        sni,
    })
}

type ExtensionFields = (Vec<u16>, Vec<u16>, Vec<u16>, Vec<String>, Option<String>);

fn parse_extensions(buf: &[u8]) -> Result<ExtensionFields, ParseError> {
    let mut r = Reader::new(buf);
    let mut extensions = Vec::new();
    let mut supported_groups = Vec::new();
    let mut signature_algorithms = Vec::new();
    let mut alpn = Vec::new();
    let mut sni = None;

    while r.remaining() > 0 {
        let ext_type = r.u16()?;
        let ext_len = r.u16()? as usize;
        let ext_data = r.take(ext_len)?;
        extensions.push(ext_type);

        match ext_type {
            0 => sni = parse_sni(ext_data)?,
            10 => supported_groups = parse_u16_list(ext_data)?,
            13 => signature_algorithms = parse_u16_list(ext_data)?,
            16 => alpn = parse_alpn(ext_data)?,
            _ => {}
        }
    }
    Ok((extensions, supported_groups, signature_algorithms, alpn, sni))
}

fn parse_u16_list(buf: &[u8]) -> Result<Vec<u16>, ParseError> {
    let mut r = Reader::new(buf);
    let len = r.u16()? as usize;
    if !len.is_multiple_of(2) {
        return Err(ParseError::LengthMismatch);
    }
    let s = r.take(len)?;
    Ok(s.chunks_exact(2)
        .filter_map(|c| <[u8; 2]>::try_from(c).ok())
        .map(u16::from_be_bytes)
        .collect())
}

fn parse_sni(buf: &[u8]) -> Result<Option<String>, ParseError> {
    // ServerNameList: u16 list_len, then entries: u8 name_type, u16 name_len, name.
    let mut r = Reader::new(buf);
    let _list_len = r.u16()?;
    while r.remaining() > 0 {
        let name_type = r.u8()?;
        let name_len = r.u16()? as usize;
        let name = r.take(name_len)?;
        if name_type == 0 {
            // host_name — first one wins, per RFC 6066 §3.
            return Ok(Some(String::from_utf8_lossy(name).into_owned()));
        }
    }
    Ok(None)
}

fn parse_alpn(buf: &[u8]) -> Result<Vec<String>, ParseError> {
    let mut r = Reader::new(buf);
    let _list_len = r.u16()?;
    let mut out = Vec::new();
    while r.remaining() > 0 {
        let n = r.u8()? as usize;
        let proto = r.take(n)?;
        out.push(String::from_utf8_lossy(proto).into_owned());
    }
    Ok(out)
}

/// Real `ClientHello` inspector: parses + writes into a shared `ConnCtx`.
///
/// One inspector instance per connection (cheap — just an `Arc<ConnCtx>`).
/// Pingora invokes `on_client_hello` synchronously during the handshake.
pub struct TlsCapture {
    ctx: Arc<ConnCtx>,
}

impl TlsCapture {
    #[must_use]
    pub const fn new(ctx: Arc<ConnCtx>) -> Self {
        Self { ctx }
    }
}

impl ClientHelloInspector for TlsCapture {
    fn on_client_hello(&self, raw: &[u8]) {
        if let Ok(parsed) = parse_client_hello(raw) {
            self.ctx.set_client_hello(parsed);
        }
        // Parse failures are intentionally swallowed — see module doc.
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::convert::TryFrom;

    fn u16_be(n: usize) -> [u8; 2] {
        u16::try_from(n).unwrap_or(u16::MAX).to_be_bytes()
    }

    fn u8_be(n: usize) -> u8 {
        u8::try_from(n).unwrap_or(u8::MAX)
    }

    /// Build a minimal `ClientHello` with the given cipher suites + extensions.
    fn build_client_hello(cipher_suites: &[u16], extensions: &[(u16, Vec<u8>)]) -> Vec<u8> {
        let mut body = Vec::with_capacity(128);
        body.extend_from_slice(&0x0303u16.to_be_bytes());
        body.extend_from_slice(&[0u8; 32]);
        body.push(0);

        let cs_bytes: Vec<u8> = cipher_suites.iter().flat_map(|c| c.to_be_bytes()).collect();
        body.extend_from_slice(&u16_be(cs_bytes.len()));
        body.extend_from_slice(&cs_bytes);

        body.push(1);
        body.push(0);

        let mut ext_buf = Vec::new();
        for (ty, data) in extensions {
            ext_buf.extend_from_slice(&ty.to_be_bytes());
            ext_buf.extend_from_slice(&u16_be(data.len()));
            ext_buf.extend_from_slice(data);
        }
        body.extend_from_slice(&u16_be(ext_buf.len()));
        body.extend_from_slice(&ext_buf);

        let mut msg = Vec::with_capacity(body.len() + 4);
        msg.push(0x01);
        let blen = u32::try_from(body.len()).unwrap_or(u32::MAX);
        msg.extend_from_slice(&[
            ((blen >> 16) & 0xff) as u8,
            ((blen >> 8) & 0xff) as u8,
            (blen & 0xff) as u8,
        ]);
        msg.extend_from_slice(&body);
        msg
    }

    fn ext_sni(host: &str) -> (u16, Vec<u8>) {
        let host = host.as_bytes();
        let entry_len = 1 + 2 + host.len();
        let mut data = Vec::with_capacity(2 + entry_len);
        data.extend_from_slice(&u16_be(entry_len));
        data.push(0);
        data.extend_from_slice(&u16_be(host.len()));
        data.extend_from_slice(host);
        (0, data)
    }

    fn ext_u16_list(ext_type: u16, items: &[u16]) -> (u16, Vec<u8>) {
        let inner: Vec<u8> = items.iter().flat_map(|c| c.to_be_bytes()).collect();
        let mut data = Vec::with_capacity(2 + inner.len());
        data.extend_from_slice(&u16_be(inner.len()));
        data.extend_from_slice(&inner);
        (ext_type, data)
    }

    fn ext_alpn(protos: &[&str]) -> (u16, Vec<u8>) {
        let mut inner = Vec::new();
        for p in protos {
            inner.push(u8_be(p.len()));
            inner.extend_from_slice(p.as_bytes());
        }
        let mut data = Vec::with_capacity(2 + inner.len());
        data.extend_from_slice(&u16_be(inner.len()));
        data.extend_from_slice(&inner);
        (16, data)
    }

    #[test]
    fn parses_minimal_hello_no_extensions() {
        let bytes = build_client_hello(&[0x1301, 0x1302], &[]);
        let parsed = parse_client_hello(&bytes).unwrap();
        assert_eq!(parsed.legacy_version, 0x0303);
        assert_eq!(parsed.cipher_suites, vec![0x1301, 0x1302]);
        assert!(parsed.extensions.is_empty());
        assert!(parsed.sni.is_none());
    }

    #[test]
    fn parses_full_extension_set() {
        let bytes = build_client_hello(
            &[0x1301, 0x1302, 0x1303],
            &[
                ext_sni("example.com"),
                ext_u16_list(10, &[29, 23, 24]),    // supported_groups
                ext_u16_list(13, &[0x0403, 0x0804]), // signature_algorithms
                ext_alpn(&["h2", "http/1.1"]),
            ],
        );
        let parsed = parse_client_hello(&bytes).unwrap();
        assert_eq!(parsed.cipher_suites.len(), 3);
        assert_eq!(parsed.extensions, vec![0, 10, 13, 16]);
        assert_eq!(parsed.supported_groups, vec![29, 23, 24]);
        assert_eq!(parsed.signature_algorithms, vec![0x0403, 0x0804]);
        assert_eq!(parsed.alpn, vec!["h2".to_string(), "http/1.1".to_string()]);
        assert_eq!(parsed.sni.as_deref(), Some("example.com"));
    }

    #[test]
    fn rejects_truncated_buffer() {
        let bytes = build_client_hello(&[0x1301], &[ext_sni("a.test")]);
        let cut = bytes.len().saturating_sub(5);
        let truncated = bytes.get(..cut).unwrap_or(&[]);
        assert!(parse_client_hello(truncated).is_err());
    }

    #[test]
    fn rejects_bad_handshake_type() {
        let mut bytes = build_client_hello(&[0x1301], &[]);
        if let Some(first) = bytes.first_mut() {
            *first = 0x02; // ServerHello
        }
        assert!(matches!(
            parse_client_hello(&bytes),
            Err(ParseError::BadHandshakeType(0x02))
        ));
    }

    #[test]
    fn rejects_odd_cipher_list_length() {
        let mut body = Vec::new();
        body.extend_from_slice(&0x0303u16.to_be_bytes());
        body.extend_from_slice(&[0u8; 32]);
        body.push(0); // sid len
        body.extend_from_slice(&3u16.to_be_bytes()); // odd
        body.extend_from_slice(&[0, 0, 0]);
        body.push(1);
        body.push(0);
        body.extend_from_slice(&0u16.to_be_bytes());

        let mut msg = vec![0x01];
        let blen = u32::try_from(body.len()).unwrap_or(u32::MAX);
        msg.extend_from_slice(&[
            ((blen >> 16) & 0xff) as u8,
            ((blen >> 8) & 0xff) as u8,
            (blen & 0xff) as u8,
        ]);
        msg.extend_from_slice(&body);
        assert!(matches!(parse_client_hello(&msg), Err(ParseError::LengthMismatch)));
    }

    #[test]
    fn inspector_writes_into_ctx() {
        let ctx = Arc::new(ConnCtx::new());
        let inspector = TlsCapture::new(Arc::clone(&ctx));
        let bytes = build_client_hello(&[0x1301], &[ext_sni("a.test")]);
        inspector.on_client_hello(&bytes);
        assert_eq!(ctx.snapshot().tls.unwrap().sni.as_deref(), Some("a.test"));
    }

    #[test]
    fn inspector_swallows_malformed_input() {
        let ctx = Arc::new(ConnCtx::new());
        let inspector = TlsCapture::new(Arc::clone(&ctx));
        inspector.on_client_hello(&[0x16, 0x03]); // junk
        assert!(ctx.snapshot().tls.is_none());
    }
}
