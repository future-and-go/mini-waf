//! Process-wide cache of pre-compiled Aho-Corasick automata loaded from
//! `pm_from_file` `.data` files.
//!
//! Build cost (case-insensitive AC over thousands of patterns) is paid once
//! per file. Subsequent rules referencing the same data file share the same
//! `Arc<AhoCorasick>` automaton. Cache entries are keyed by canonicalised
//! path + mtime + size, so re-loading after disk edits builds fresh.
//!
//! Defensive caps:
//!   * file size ≤ [`MAX_DATA_FILE_BYTES`] (10 MiB)
//!   * pattern count ≤ [`MAX_PATTERNS`] (100 000)
//!
//! Both caps make an OOM rule-loading attack into a structured `Err` rather
//! than a process kill.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::SystemTime;

use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};
use anyhow::{Context as _, Result, bail};
use parking_lot::Mutex;

/// 10 MiB cap on a single data file. Rejects malicious or accidental
/// gigabyte inputs at load time.
pub const MAX_DATA_FILE_BYTES: u64 = 10 * 1024 * 1024;

/// 100 000 pattern cap per file. Matches the upper bound CRS data files
/// stay well under (largest is ~5 000 lines).
pub const MAX_PATTERNS: usize = 100_000;

#[derive(Debug)]
struct CachedAc {
    mtime: SystemTime,
    size: u64,
    ac: Arc<AhoCorasick>,
}

/// Cache of compiled Aho-Corasick automata keyed by canonicalised path.
///
/// Thread-safe via `parking_lot::Mutex`. Cheap to clone (it's just an Arc
/// internally if the caller wraps it) — callers typically hold one per
/// rule-engine instance.
#[derive(Debug, Default)]
pub struct DataFileRegistry {
    cache: Mutex<HashMap<PathBuf, CachedAc>>,
    reloads: AtomicU64,
}

impl DataFileRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Return the cached automaton for `path`, building it on cache miss or
    /// when the file's `mtime` / `size` has changed.
    ///
    /// `path` MUST already be canonicalised by [`super::data_file_resolver`].
    pub fn load_or_get(&self, path: &Path) -> Result<Arc<AhoCorasick>> {
        let meta = fs::metadata(path).with_context(|| format!("stat {}", path.display()))?;
        let size = meta.len();
        if size > MAX_DATA_FILE_BYTES {
            bail!("data file too large: {size} bytes (cap {MAX_DATA_FILE_BYTES})");
        }
        let mtime = meta.modified().with_context(|| format!("mtime {}", path.display()))?;

        {
            let cache = self.cache.lock();
            if let Some(c) = cache.get(path)
                && c.mtime == mtime
                && c.size == size
            {
                return Ok(c.ac.clone());
            }
        }

        self.reloads.fetch_add(1, Ordering::Relaxed);

        let patterns = read_patterns(path)?;
        if patterns.len() > MAX_PATTERNS {
            bail!("too many patterns in {}: {}", path.display(), patterns.len());
        }
        if patterns.is_empty() {
            bail!("no patterns in data file: {}", path.display());
        }
        let ac = AhoCorasickBuilder::new()
            .ascii_case_insensitive(true)
            .match_kind(MatchKind::LeftmostFirst)
            .build(&patterns)
            .with_context(|| format!("build Aho-Corasick from {}", path.display()))?;
        let arc = Arc::new(ac);
        self.cache.lock().insert(
            path.to_owned(),
            CachedAc {
                mtime,
                size,
                ac: arc.clone(),
            },
        );
        Ok(arc)
    }

    /// Total number of cache-miss reloads since process start.
    pub fn reloads_total(&self) -> u64 {
        self.reloads.load(Ordering::Relaxed)
    }
}

/// Read a `.data` file as patterns: one per non-empty, non-comment line.
fn read_patterns(path: &Path) -> Result<Vec<String>> {
    let raw = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    Ok(raw
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(str::to_owned)
        .collect())
}

/// Build an Aho-Corasick automaton from an inline list of patterns
/// (`contains_any` operator's whitespace-separated value list).
///
/// Same builder settings as [`DataFileRegistry::load_or_get`] so the two
/// matchers behave identically (case-insensitive, leftmost-first).
pub fn build_inline_ac(patterns: &[String]) -> Result<Arc<AhoCorasick>> {
    if patterns.is_empty() {
        bail!("contains_any: empty pattern list");
    }
    if patterns.len() > MAX_PATTERNS {
        bail!("contains_any: too many patterns ({})", patterns.len());
    }
    let ac = AhoCorasickBuilder::new()
        .ascii_case_insensitive(true)
        .match_kind(MatchKind::LeftmostFirst)
        .build(patterns)
        .with_context(|| "build inline Aho-Corasick")?;
    Ok(Arc::new(ac))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use tempfile::tempdir;

    fn write_data(dir: &Path, name: &str, body: &str) -> PathBuf {
        let p = dir.join(name);
        fs::write(&p, body).unwrap();
        p.canonicalize().unwrap()
    }

    #[test]
    fn caches_by_canonical_path_and_returns_same_arc() {
        let dir = tempdir().unwrap();
        let p = write_data(dir.path(), "x.data", ".env\n.envrc\n");
        let reg = DataFileRegistry::new();
        let a = reg.load_or_get(&p).unwrap();
        let b = reg.load_or_get(&p).unwrap();
        assert!(Arc::ptr_eq(&a, &b), "cache must return the same Arc");
        assert!(a.is_match(".env"));
        assert!(a.is_match("path/to/.envrc"));
    }

    #[test]
    fn ignores_comments_and_blank_lines() {
        let dir = tempdir().unwrap();
        let p = write_data(dir.path(), "x.data", "# header\n\n.env\n   \n.foo\n");
        let reg = DataFileRegistry::new();
        let ac = reg.load_or_get(&p).unwrap();
        assert!(ac.is_match(".env"));
        assert!(ac.is_match(".foo"));
        assert!(!ac.is_match("# header"));
    }

    #[test]
    fn rejects_empty_pattern_list() {
        let dir = tempdir().unwrap();
        let p = write_data(dir.path(), "x.data", "# only comment\n\n");
        let reg = DataFileRegistry::new();
        let err = reg.load_or_get(&p).unwrap_err();
        assert!(err.to_string().contains("no patterns"), "{err}");
    }

    #[test]
    fn case_insensitive_match() {
        let dir = tempdir().unwrap();
        let p = write_data(dir.path(), "x.data", ".env\n");
        let reg = DataFileRegistry::new();
        let ac = reg.load_or_get(&p).unwrap();
        assert!(ac.is_match(".ENV"));
    }

    #[test]
    fn build_inline_ac_basic() {
        let ac = build_inline_ac(&["foo".into(), "bar".into()]).unwrap();
        assert!(ac.is_match("xfooy"));
        assert!(ac.is_match("BAR"));
        assert!(!ac.is_match("baz"));
    }

    #[test]
    fn build_inline_ac_rejects_empty() {
        let err = build_inline_ac(&[]).unwrap_err();
        assert!(err.to_string().contains("empty"));
    }
}
