//! User-Agent Shannon entropy provider.
//!
//! Computes Shannon entropy on the byte distribution of the UA string and
//! emits `Signal::LowEntropyUa` when the value (×100) is below
//! `min_entropy_x100`. Caches the computed entropy in `DeviceCtx.derived`
//! so later providers can reuse it without recomputing.
//!
//! Empty UA → 0 entropy → emits if any positive threshold configured.

use crate::device_fp::providers::SignalProvider;
use crate::device_fp::signal::Signal;
use crate::device_fp::types::{DeviceCtx, DeviceDerived};

#[derive(Debug, Clone, Copy)]
pub struct UaEntropyProvider {
    pub min_entropy_x100: u16,
}

impl Default for UaEntropyProvider {
    fn default() -> Self {
        Self { min_entropy_x100: 250 }
    }
}

impl UaEntropyProvider {
    #[must_use]
    pub const fn new(min_entropy_x100: u16) -> Self {
        Self { min_entropy_x100 }
    }
}

impl SignalProvider for UaEntropyProvider {
    fn name(&self) -> &'static str {
        "ua_entropy"
    }
    fn evaluate(&self, ctx: &DeviceCtx<'_>) -> Vec<Signal> {
        let entropy_x100 = ctx.derived().and_then(|d| d.ua_entropy_x100).unwrap_or_else(|| {
            let v = shannon_entropy_x100(ctx.user_agent.as_bytes());
            ctx.set_derived(DeviceDerived {
                ua_entropy_x100: Some(v),
                ua_normalized: None,
            });
            v
        });
        if entropy_x100 < self.min_entropy_x100 {
            vec![Signal::LowEntropyUa { entropy_x100 }]
        } else {
            Vec::new()
        }
    }
}

/// Shannon entropy over the byte histogram, scaled by 100 and clamped to u16.
/// Returns 0 for empty input.
#[allow(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]
fn shannon_entropy_x100(bytes: &[u8]) -> u16 {
    if bytes.is_empty() {
        return 0;
    }
    let mut hist = [0u32; 256];
    for &b in bytes {
        // SAFETY-equivalent: `b as usize` is in 0..=255 → always within `hist`.
        if let Some(slot) = hist.get_mut(b as usize) {
            *slot += 1;
        }
    }
    let len = bytes.len() as f64;
    let mut h = 0.0_f64;
    for &c in &hist {
        if c == 0 {
            continue;
        }
        let p = f64::from(c) / len;
        h = p.mul_add(-p.log2(), h);
    }
    let scaled = (h * 100.0).round();
    if scaled <= 0.0 {
        0
    } else if scaled >= f64::from(u16::MAX) {
        u16::MAX
    } else {
        scaled as u16
    }
}

#[cfg(test)]
#[allow(clippy::indexing_slicing, clippy::trivially_copy_pass_by_ref)]
mod tests {
    use super::*;
    use crate::device_fp::capture::ConnCtx;
    use crate::device_fp::types::FpKey;
    use std::net::{IpAddr, Ipv4Addr};

    fn eval(provider: &UaEntropyProvider, ua: &str) -> Vec<Signal> {
        let conn = ConnCtx::new();
        let key = FpKey::default();
        let ctx = DeviceCtx::new(IpAddr::V4(Ipv4Addr::LOCALHOST), ua, &conn, &key);
        provider.evaluate(&ctx)
    }

    #[test]
    fn empty_ua_zero_entropy() {
        assert_eq!(shannon_entropy_x100(b""), 0);
    }

    #[test]
    fn uniform_8_bytes_three_bits() {
        // 8 distinct bytes → log2(8) = 3.0 → 300 (×100).
        assert_eq!(shannon_entropy_x100(b"01234567"), 300);
    }

    #[test]
    fn flags_low_entropy_string() {
        let p = UaEntropyProvider::new(200);
        let s = eval(&p, "aaaaaa");
        assert_eq!(s.len(), 1);
        assert!(matches!(s[0], Signal::LowEntropyUa { entropy_x100: 0 }));
    }

    #[test]
    fn passes_realistic_ua() {
        let p = UaEntropyProvider::new(300);
        let s = eval(
            &p,
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120 Safari/537.36",
        );
        assert!(s.is_empty(), "got {s:?}");
    }

    #[test]
    fn caches_in_derived() {
        let p = UaEntropyProvider::new(200);
        let conn = ConnCtx::new();
        let key = FpKey::default();
        let ctx = DeviceCtx::new(IpAddr::V4(Ipv4Addr::LOCALHOST), "abcdef", &conn, &key);
        let _ = p.evaluate(&ctx);
        assert!(ctx.derived().and_then(|d| d.ua_entropy_x100).is_some());
    }
}
