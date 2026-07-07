//! Shared YAML config-file helpers for admin API modules.
//!
//! Every YAML-backed config endpoint resolves paths relative to the main
//! config file's root and persists changes with the same atomic
//! tmp-write-then-rename sequence. Defining the helpers once here means a
//! fix to root resolution or write atomicity lands everywhere at once.

use std::path::{Path, PathBuf};

use serde_json::Value;

use crate::error::ApiError;
use crate::state::AppState;

/// Resolve `relative` against the config root (two levels above the main
/// config file). Falls back to `relative` as a bare path when no main
/// config file is set.
pub fn resolve_path(state: &AppState, relative: &str) -> PathBuf {
    state.main_config_file.as_ref().map_or_else(
        || PathBuf::from(relative),
        |main| {
            let p = Path::new(main.as_str());
            let root = p.parent().and_then(|c| c.parent()).unwrap_or_else(|| Path::new("."));
            root.join(relative)
        },
    )
}

/// Read and parse a YAML file. `None` when the file is missing, unreadable,
/// or fails to parse — callers treat all three as "use defaults".
pub async fn read_yaml_opt(path: &Path) -> Option<Value> {
    let raw = tokio::fs::read_to_string(path).await.ok()?;
    serde_yaml::from_str::<Value>(&raw).ok()
}

/// Atomically persist pre-serialized YAML: create the parent directory,
/// write to `<stem>.yaml.tmp`, then rename over `path`.
pub async fn write_yaml_str(path: &Path, contents: &str) -> Result<(), ApiError> {
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .map_err(|e| ApiError::Internal(anyhow::anyhow!("mkdir: {e}")))?;
    }
    let tmp = path.with_extension("yaml.tmp");
    tokio::fs::write(&tmp, contents.as_bytes())
        .await
        .map_err(|e| ApiError::Internal(anyhow::anyhow!("write: {e}")))?;
    tokio::fs::rename(&tmp, path)
        .await
        .map_err(|e| ApiError::Internal(anyhow::anyhow!("rename: {e}")))?;
    Ok(())
}

/// Atomically persist pre-serialized TOML: create the parent directory,
/// write to `<stem>.toml.tmp`, then rename over `path`.
pub async fn write_toml_str(path: &Path, contents: &str) -> Result<(), ApiError> {
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .map_err(|e| ApiError::Internal(anyhow::anyhow!("mkdir: {e}")))?;
    }
    let tmp = path.with_extension("toml.tmp");
    tokio::fs::write(&tmp, contents.as_bytes())
        .await
        .map_err(|e| ApiError::Internal(anyhow::anyhow!("write: {e}")))?;
    tokio::fs::rename(&tmp, path)
        .await
        .map_err(|e| ApiError::Internal(anyhow::anyhow!("rename: {e}")))?;
    Ok(())
}

/// Serialize `value` to YAML and persist it atomically via [`write_yaml_str`].
pub async fn write_yaml(path: &Path, value: &Value) -> Result<(), ApiError> {
    let s = serde_yaml::to_string(value).map_err(|e| ApiError::Internal(anyhow::anyhow!("{e}")))?;
    write_yaml_str(path, &s).await
}
