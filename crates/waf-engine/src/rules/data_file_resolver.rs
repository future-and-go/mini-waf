//! Resolve a `pm_from_file` data-file reference to an absolute path with a
//! path-traversal guard.
//!
//! Rules YAML lives at e.g. `rules/owasp-crs/lfi.yaml` and references data
//! files relative to its own dir's `data/` subdirectory:
//! `value: lfi-os-files.data` → `rules/owasp-crs/data/lfi-os-files.data`.
//!
//! The resolver:
//!   1. Rejects values containing `..` or absolute paths up-front.
//!   2. Canonicalises the candidate path.
//!   3. Ensures the canonicalised path is inside `rules_root` (preventing
//!      symlink-escape attacks).

use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, anyhow, bail};

/// Resolve `value` (a filename like `lfi-os-files.data`) under the
/// `data/` subdir of `yaml_path`'s parent.
///
/// `rules_root` is the canonicalised root that the resolved path must remain
/// within. Returns the canonicalised absolute path on success.
pub fn resolve_data_path(yaml_path: &Path, value: &str, rules_root: &Path) -> Result<PathBuf> {
    let value_trimmed = value.trim();
    if value_trimmed.is_empty() {
        bail!("data file value must not be empty");
    }
    if value_trimmed.contains("..") {
        bail!("data file value must not contain '..': {value_trimmed}");
    }
    if Path::new(value_trimmed).is_absolute() {
        bail!("data file value must be a relative filename: {value_trimmed}");
    }

    let yaml_dir = yaml_path
        .parent()
        .ok_or_else(|| anyhow!("yaml path has no parent: {}", yaml_path.display()))?;

    let candidate = yaml_dir.join("data").join(value_trimmed);
    let canonical = candidate
        .canonicalize()
        .with_context(|| format!("data file not found: {}", candidate.display()))?;

    let root_canonical = rules_root
        .canonicalize()
        .with_context(|| format!("rules_root not canonicalisable: {}", rules_root.display()))?;

    if !canonical.starts_with(&root_canonical) {
        bail!(
            "data file resolves outside rules_root: {} (root: {})",
            canonical.display(),
            root_canonical.display()
        );
    }

    Ok(canonical)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn resolves_inside_data_subdir() {
        let root = tempdir().unwrap();
        let crs = root.path().join("owasp-crs");
        let data_dir = crs.join("data");
        fs::create_dir_all(&data_dir).unwrap();
        let data_file = data_dir.join("restricted-files.data");
        fs::write(&data_file, ".env\n.envrc\n").unwrap();
        let yaml = crs.join("lfi.yaml");
        fs::write(&yaml, "").unwrap();

        let got = resolve_data_path(&yaml, "restricted-files.data", root.path()).unwrap();
        assert_eq!(got, data_file.canonicalize().unwrap());
    }

    #[test]
    fn rejects_parent_dir_traversal() {
        let root = tempdir().unwrap();
        let crs = root.path().join("owasp-crs");
        fs::create_dir_all(crs.join("data")).unwrap();
        let yaml = crs.join("lfi.yaml");
        fs::write(&yaml, "").unwrap();

        let err = resolve_data_path(&yaml, "../../etc/passwd", root.path()).unwrap_err();
        assert!(err.to_string().contains(".."), "{err}");
    }

    #[test]
    fn rejects_absolute_path() {
        let root = tempdir().unwrap();
        let crs = root.path().join("owasp-crs");
        fs::create_dir_all(crs.join("data")).unwrap();
        let yaml = crs.join("lfi.yaml");
        fs::write(&yaml, "").unwrap();

        let err = resolve_data_path(&yaml, "/etc/passwd", root.path()).unwrap_err();
        assert!(err.to_string().contains("relative"), "{err}");
    }

    #[test]
    fn rejects_empty_value() {
        let root = tempdir().unwrap();
        let crs = root.path().join("owasp-crs");
        fs::create_dir_all(crs.join("data")).unwrap();
        let yaml = crs.join("lfi.yaml");
        fs::write(&yaml, "").unwrap();

        let err = resolve_data_path(&yaml, "   ", root.path()).unwrap_err();
        assert!(err.to_string().contains("empty"), "{err}");
    }

    #[test]
    fn rejects_missing_file() {
        let root = tempdir().unwrap();
        let crs = root.path().join("owasp-crs");
        fs::create_dir_all(crs.join("data")).unwrap();
        let yaml = crs.join("lfi.yaml");
        fs::write(&yaml, "").unwrap();

        let err = resolve_data_path(&yaml, "missing.data", root.path()).unwrap_err();
        assert!(err.to_string().contains("not found"), "{err}");
    }
}
