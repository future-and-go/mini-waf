//! Server response-header strategy (AC-16).
//!
//! Variants:
//! - [`ServerHeaderPolicy::Passthrough`] — leave the upstream `Server` byte-identical.
//!   This is the default and preserves AC-04 (header fidelity).
//! - [`ServerHeaderPolicy::Strip`] — remove `Server` entirely. We **never** substitute
//!   it with a WAF identifier (that would itself be a fingerprint leak).

use waf_common::HostConfig;

/// Strategy controlling the upstream `Server` response header.
#[derive(Debug, Clone, Copy)]
pub enum ServerHeaderPolicy {
    /// Leave `Server` untouched (default — preserves AC-04).
    Passthrough,
    /// Remove `Server` entirely.
    Strip,
}

impl ServerHeaderPolicy {
    /// Build the policy from a [`HostConfig`].
    #[must_use]
    pub const fn from_host_config(hc: &HostConfig) -> Self {
        if hc.strip_server_header {
            Self::Strip
        } else {
            Self::Passthrough
        }
    }

    /// Apply this policy to `resp`.
    pub fn apply(self, resp: &mut pingora_http::ResponseHeader) -> pingora_core::Result<()> {
        match self {
            Self::Passthrough => Ok(()),
            Self::Strip => {
                let _ = resp.remove_header("server");
                Ok(())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pingora_http::ResponseHeader;

    fn resp_with_server(value: &str) -> ResponseHeader {
        let mut r = ResponseHeader::build(200, None).expect("build");
        r.insert_header("server", value).expect("set server");
        r
    }

    #[test]
    fn passthrough_leaves_server_untouched() {
        let mut resp = resp_with_server("nginx/1.25.0");
        ServerHeaderPolicy::Passthrough.apply(&mut resp).expect("apply");
        assert_eq!(resp.headers.get("server").unwrap().as_bytes(), b"nginx/1.25.0");
    }

    #[test]
    fn strip_removes_server() {
        let mut resp = resp_with_server("nginx/1.25.0");
        ServerHeaderPolicy::Strip.apply(&mut resp).expect("apply");
        assert!(resp.headers.get("server").is_none());
    }

    #[test]
    fn from_host_config_default_passthrough() {
        let hc = HostConfig::default();
        assert!(!hc.strip_server_header, "default must be false");
        match ServerHeaderPolicy::from_host_config(&hc) {
            ServerHeaderPolicy::Passthrough => {}
            ServerHeaderPolicy::Strip => panic!("expected Passthrough"),
        }
    }

    #[test]
    fn from_host_config_strip_when_enabled() {
        let hc = HostConfig {
            strip_server_header: true,
            ..HostConfig::default()
        };
        match ServerHeaderPolicy::from_host_config(&hc) {
            ServerHeaderPolicy::Strip => {}
            ServerHeaderPolicy::Passthrough => panic!("expected Strip"),
        }
    }
}
