//! FR-011 Phase 4 — exempt-path classification shared by the recorder and
//! `zero_depth` / `missing_referer` providers.
//!
//! Pure string match. Keeping the helper here (rather than in each provider)
//! means the recorder can pre-compute exemption flags onto every `Sample`,
//! so providers don't need the original path string at evaluation time.

/// Exact match against an entry-path list (e.g. `/`, `/login`, `/index`).
/// Used by `zero_depth` to suppress firing when the only observed path is
/// a legitimate entry point.
#[must_use]
pub fn is_entry_path(path: &str, exempt_paths: &[String]) -> bool {
    exempt_paths.iter().any(|p| p == path)
}

/// Union of exact-path match + prefix match. Used by `missing_referer`
/// (entry pages, static assets, APIs, healthchecks all legitimately lack
/// a Referer header).
#[must_use]
pub fn is_low_signal_path(path: &str, exempt_paths: &[String], exempt_prefixes: &[String]) -> bool {
    exempt_paths.iter().any(|p| p == path) || exempt_prefixes.iter().any(|p| path.starts_with(p))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| (*s).to_string()).collect()
    }

    #[test]
    fn entry_path_exact_match() {
        let paths = s(&["/", "/login", "/index"]);
        assert!(is_entry_path("/", &paths));
        assert!(is_entry_path("/login", &paths));
        assert!(!is_entry_path("/admin", &paths));
        // Exact only — no prefix matching.
        assert!(!is_entry_path("/login/extra", &paths));
    }

    #[test]
    fn low_signal_combines_exact_and_prefix() {
        let paths = s(&["/", "/health"]);
        let prefixes = s(&["/static/", "/api/"]);
        assert!(is_low_signal_path("/", &paths, &prefixes));
        assert!(is_low_signal_path("/health", &paths, &prefixes));
        assert!(is_low_signal_path("/static/css/app.css", &paths, &prefixes));
        assert!(is_low_signal_path("/api/users", &paths, &prefixes));
        assert!(!is_low_signal_path("/admin", &paths, &prefixes));
        // Prefix is strict — no implicit trailing-slash match.
        assert!(!is_low_signal_path("/static", &paths, &prefixes));
    }

    #[test]
    fn empty_lists_match_nothing() {
        let empty: Vec<String> = Vec::new();
        assert!(!is_entry_path("/", &empty));
        assert!(!is_low_signal_path("/anything", &empty, &empty));
    }
}
