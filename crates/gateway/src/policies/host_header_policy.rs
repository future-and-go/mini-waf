//! Host header rewrite strategy (AC-25).
//!
//! Two variants:
//! - [`HostHeaderPolicy::Preserve`] — leave the request `Host` untouched
//!   so the upstream sees the original client Host. This is the transparent
//!   default and matches `HostConfig.preserve_host = true`.
//! - [`HostHeaderPolicy::Rewrite`] — replace `Host` with the configured
//!   upstream hostname. Used when the backend virtual-host is keyed off
//!   `remote_host` rather than the client-facing hostname.
//!
//! Selected once per request from `HostConfig` and applied as the last
//! request-side filter so `RequestForwardedHostFilter` has already captured
//! the original `Host`.

use waf_common::HostConfig;

/// Strategy controlling how the upstream `Host` header is set.
#[derive(Debug, Clone)]
pub enum HostHeaderPolicy {
    /// Leave the `Host` header untouched (transparent passthrough).
    Preserve,
    /// Replace `Host` with the contained value (typically `remote_host`).
    Rewrite(String),
}

impl HostHeaderPolicy {
    /// Build the policy from a [`HostConfig`].
    #[must_use]
    pub fn from_host_config(hc: &HostConfig) -> Self {
        if hc.preserve_host {
            Self::Preserve
        } else {
            Self::Rewrite(hc.remote_host.clone())
        }
    }

    /// Apply this policy to `req`.
    pub fn apply(&self, req: &mut pingora_http::RequestHeader) -> pingora_core::Result<()> {
        match self {
            Self::Preserve => Ok(()),
            Self::Rewrite(value) => req
                .insert_header("host", value.as_str())
                .map_err(|e| pingora_core::Error::because(pingora_core::ErrorType::InternalError, "host rewrite", e)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pingora_http::RequestHeader;
    use waf_common::HostConfig;

    fn make_req(host: &str) -> RequestHeader {
        let mut req = RequestHeader::build("GET", b"/", None).expect("build");
        req.insert_header("host", host).expect("set host");
        req
    }

    #[test]
    fn preserve_leaves_host_untouched() {
        let mut req = make_req("client.example.com");
        let policy = HostHeaderPolicy::Preserve;
        policy.apply(&mut req).expect("apply");
        let got = req.headers.get("host").expect("host header");
        assert_eq!(got.as_bytes(), b"client.example.com");
    }

    #[test]
    fn rewrite_replaces_host() {
        let mut req = make_req("client.example.com");
        let policy = HostHeaderPolicy::Rewrite("backend.internal".to_string());
        policy.apply(&mut req).expect("apply");
        let got = req.headers.get("host").expect("host header");
        assert_eq!(got.as_bytes(), b"backend.internal");
    }

    #[test]
    fn from_host_config_preserve_default() {
        let hc = HostConfig::default();
        assert!(hc.preserve_host, "default must be preserve");
        match HostHeaderPolicy::from_host_config(&hc) {
            HostHeaderPolicy::Preserve => {}
            HostHeaderPolicy::Rewrite(_) => panic!("expected Preserve"),
        }
    }

    #[test]
    fn from_host_config_rewrite_when_disabled() {
        let hc = HostConfig {
            preserve_host: false,
            remote_host: "upstream.local".into(),
            ..HostConfig::default()
        };
        match HostHeaderPolicy::from_host_config(&hc) {
            HostHeaderPolicy::Rewrite(v) => assert_eq!(v, "upstream.local"),
            HostHeaderPolicy::Preserve => panic!("expected Rewrite"),
        }
    }
}
