//! Shared YAML config path resolution for admin-panel API modules.
//!
//! Admin-panel handlers (tier policies, `DDoS`, access lists, …) store their
//! YAML config under `<root>/configs/<name>.yaml`. `<root>` is the directory
//! two levels above the main TOML config file the server was started with
//! (e.g. `configs/default.toml` → root is `.`). When no main config file is
//! known (CLI subcommands, some integration tests), paths fall back to being
//! relative to the current working directory.

use std::path::{Path, PathBuf};

use crate::state::AppState;

/// Resolve `relative` against the project root inferred from the main config
/// path, or against the CWD when no main config is configured.
#[must_use]
pub fn resolve_under_root(state: &AppState, relative: &str) -> PathBuf {
    state.main_config_file.as_ref().map_or_else(
        || PathBuf::from(relative),
        |main| {
            let p = Path::new(main.as_str());
            let root = p.parent().and_then(Path::parent).unwrap_or_else(|| Path::new("."));
            root.join(relative)
        },
    )
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    /// Mirror of `resolve_under_root`'s `None` branch.
    #[test]
    fn relative_path_when_no_main_config() {
        let main: Option<String> = None;
        let got = main
            .as_ref()
            .map_or_else(|| PathBuf::from("configs/x.yaml"), |_| PathBuf::from("ignored"));
        assert_eq!(got, PathBuf::from("configs/x.yaml"));
    }

    /// Mirror of `resolve_under_root`'s `Some` branch:
    /// root is two levels above the main config file.
    #[test]
    fn root_is_two_levels_above_main_config() {
        let main = Path::new("/srv/waf/configs/default.toml");
        let root = main.parent().and_then(Path::parent).expect("two levels up");
        assert_eq!(root, Path::new("/srv/waf"));
        assert_eq!(
            root.join("configs/tier-policies.yaml"),
            Path::new("/srv/waf/configs/tier-policies.yaml"),
        );
    }
}
