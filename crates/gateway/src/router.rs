use dashmap::DashMap;
use std::collections::HashSet;
use std::sync::Arc;
use waf_common::HostConfig;

/// Routes incoming requests to the correct upstream based on Host header
pub struct HostRouter {
    /// key: "host:port" or just "host" (for default port)
    routes: DashMap<String, Arc<HostConfig>>,
}

impl Default for HostRouter {
    fn default() -> Self {
        Self { routes: DashMap::new() }
    }
}

impl HostRouter {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a host configuration.
    ///
    /// The host name is normalised to ASCII lowercase before insertion so
    /// that lookups remain case-insensitive (RFC 9110 §5.4 — host names are
    /// case-insensitive). Without this a client sending `Host: Example.COM`
    /// against a registered `example.com` would miss the route and the
    /// router would return 502, which an attacker can weaponise into a `DoS`
    /// by spraying random-case Host headers.
    pub fn register(&self, config: &Arc<HostConfig>) {
        let host_lc = config.host.to_ascii_lowercase();

        // Register by "host:port"
        let key = format!("{}:{}", host_lc, config.port);
        self.routes.insert(key, Arc::clone(config));

        // Also register by bare hostname for default ports (80/443)
        if config.port == 80 || config.port == 443 {
            self.routes.insert(host_lc, Arc::clone(config));
        }
    }

    /// Remove a host configuration.
    ///
    /// Case is normalised symmetrically with [`Self::register`] so that
    /// `unregister("Example.com", 80)` removes what `register` stored as
    /// `"example.com"`.
    pub fn unregister(&self, host: &str, port: u16) {
        let host_lc = host.to_ascii_lowercase();
        let key = format!("{host_lc}:{port}");
        self.routes.remove(&key);
        if port == 80 || port == 443 {
            self.routes.remove(&host_lc);
        }
    }

    /// Resolve a request to a host config using the Host header value.
    ///
    /// Lookup is case-insensitive — the incoming header is folded to
    /// ASCII lowercase to match the normalised keys produced by
    /// [`Self::register`].
    pub fn resolve(&self, host_header: &str) -> Option<Arc<HostConfig>> {
        let host_lc = host_header.to_ascii_lowercase();

        // Try exact match first
        if let Some(entry) = self.routes.get(&host_lc) {
            let cfg: Arc<HostConfig> = Arc::clone(&*entry);
            return Some(cfg);
        }

        // Try stripping default port if present
        if let Some(bare_host) = host_lc.split(':').next()
            && let Some(entry) = self.routes.get(bare_host)
        {
            let cfg: Arc<HostConfig> = Arc::clone(&*entry);
            return Some(cfg);
        }

        None
    }

    /// List all registered host configs (deduplicated by code)
    pub fn list(&self) -> Vec<Arc<HostConfig>> {
        let mut seen: HashSet<String> = HashSet::new();
        let mut result: Vec<Arc<HostConfig>> = Vec::new();

        for entry in &self.routes {
            let config: &Arc<HostConfig> = entry.value();
            let code = config.code.clone();
            if seen.insert(code) {
                result.push(Arc::clone(config));
            }
        }

        result
    }

    pub fn len(&self) -> usize {
        self.routes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.routes.is_empty()
    }
}
