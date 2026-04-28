//! Location-header rewrite strategy (AC-18).
//!
//! Backends often emit redirects with their own internal hostname
//! (e.g. `Location: http://10.0.0.5:8080/x`). When such a redirect leaks
//! to the public client it both fingerprints internal infra and produces
//! broken navigation. This strategy rewrites the host (and scheme) when
//! the URL points at the configured `remote_host`.
//!
//! Out of scope:
//! - Relative URLs (`/path`) — passthrough unchanged.
//! - URLs whose host already matches the public `host_config.host` — passthrough.
//! - Malformed URLs — `tracing::warn!` and passthrough.

use waf_common::HostConfig;

/// Strategy that rewrites internal-host `Location` headers to the public host.
#[derive(Debug, Clone)]
pub struct LocationRewritePolicy {
    /// Internal host the backend emits (matched against URL host).
    pub internal_host: String,
    /// Public host to substitute in.
    pub public_host: String,
    /// `https` if the listener terminates TLS, else `http`.
    pub public_scheme: &'static str,
}

impl LocationRewritePolicy {
    /// Build the policy from a [`HostConfig`] and listener TLS state.
    #[must_use]
    pub fn from_host_config(hc: &HostConfig, is_tls: bool) -> Self {
        Self {
            internal_host: hc.remote_host.clone(),
            public_host: hc.host.clone(),
            public_scheme: if is_tls { "https" } else { "http" },
        }
    }

    /// Rewrite `value` if it points at `internal_host`. Returns `None`
    /// when the input should be left untouched (relative, public-host,
    /// or malformed).
    #[must_use]
    pub fn rewrite(&self, value: &str) -> Option<String> {
        let Ok(parsed) = url::Url::parse(value) else {
            if !value.starts_with('/') {
                tracing::warn!(location = %value, "malformed Location header — passthrough");
            }
            return None;
        };
        let host = parsed.host_str()?;
        if host.eq_ignore_ascii_case(&self.internal_host) {
            let mut rewritten = parsed.clone();
            rewritten.set_scheme(self.public_scheme).ok()?;
            rewritten.set_host(Some(&self.public_host)).ok()?;
            // Drop port — public host implies the default port for its scheme.
            let _ = rewritten.set_port(None);
            Some(rewritten.to_string())
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> LocationRewritePolicy {
        LocationRewritePolicy {
            internal_host: "backend".into(),
            public_host: "public.example.com".into(),
            public_scheme: "https",
        }
    }

    #[test]
    fn rewrites_absolute_internal() {
        let out = policy().rewrite("http://backend:8080/x?q=1").expect("rewrite");
        assert_eq!(out, "https://public.example.com/x?q=1");
    }

    #[test]
    fn passthrough_absolute_public() {
        assert!(policy().rewrite("https://public.example.com/x").is_none());
    }

    #[test]
    fn passthrough_relative() {
        assert!(policy().rewrite("/x?q=1").is_none());
    }

    #[test]
    fn passthrough_malformed() {
        assert!(policy().rewrite("ht!tp:/ /bad").is_none());
    }

    #[test]
    fn matches_host_case_insensitive() {
        let out = policy().rewrite("http://BACKEND/x").expect("rewrite");
        assert_eq!(out, "https://public.example.com/x");
    }
}
