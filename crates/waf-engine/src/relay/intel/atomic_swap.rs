//! FR-007 phase-04 — atomic file swap for intel feed refresh.
//!
//! Stream HTTP body bytes to `<target>.tmp`, fsync, then `rename(2)` over
//! `target`. POSIX rename is atomic — readers (mmdb open, Tor list load)
//! always see a consistent file. Windows rename semantics differ; this
//! module is documented and exercised on Linux/macOS only (production
//! target per CLAUDE.md).

use std::ops::RangeInclusive;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use futures_util::StreamExt;
use reqwest::Response;
use tokio::fs;
use tokio::io::AsyncWriteExt;

/// Inclusive byte range for sanity checks. Outside bounds → reject before
/// touching the filesystem.
pub type SizeBounds = RangeInclusive<u64>;

/// Stream `response` body to `target`, applying `bounds` sanity check.
///
/// On success: the file at `target` is the new payload. On any error
/// (network, size, fsync, rename): tmp file is removed if present and the
/// original `target` is left untouched.
pub async fn write_atomic(target: &Path, response: Response, bounds: &SizeBounds) -> Result<()> {
    if let Some(len) = response.content_length()
        && !bounds.contains(&len)
    {
        bail!(
            "content-length {len} outside bounds [{}..={}] for {}",
            bounds.start(),
            bounds.end(),
            target.display()
        );
    }

    let tmp = tmp_path_for(target);
    if let Some(parent) = target.parent() {
        fs::create_dir_all(parent)
            .await
            .with_context(|| format!("creating parent dir for {}", target.display()))?;
    }

    match stream_to_tmp(&tmp, response, bounds).await {
        Ok(()) => {
            fs::rename(&tmp, target)
                .await
                .with_context(|| format!("rename {} -> {}", tmp.display(), target.display()))?;
            Ok(())
        }
        Err(e) => {
            // Best-effort cleanup; ignore not-found.
            let _ = fs::remove_file(&tmp).await;
            Err(e)
        }
    }
}

fn tmp_path_for(target: &Path) -> PathBuf {
    let mut s = target.as_os_str().to_owned();
    s.push(".tmp");
    PathBuf::from(s)
}

async fn stream_to_tmp(tmp: &Path, response: Response, bounds: &SizeBounds) -> Result<()> {
    let mut file = fs::File::create(tmp)
        .await
        .with_context(|| format!("creating {}", tmp.display()))?;

    let mut written: u64 = 0;
    let max = *bounds.end();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.context("reading body chunk")?;
        written = written.saturating_add(chunk.len() as u64);
        if written > max {
            bail!("body exceeded max bound {max} bytes (streamed {written})");
        }
        file.write_all(&chunk)
            .await
            .with_context(|| format!("writing {}", tmp.display()))?;
    }

    if written < *bounds.start() {
        bail!(
            "body too small ({written} < {} bytes) for {}",
            bounds.start(),
            tmp.display()
        );
    }

    file.flush().await.context("flushing tmp")?;
    file.sync_all().await.context("fsync tmp")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn tmp_path_appends_suffix() {
        let p = PathBuf::from("/tmp/foo.mmdb");
        assert_eq!(tmp_path_for(&p), PathBuf::from("/tmp/foo.mmdb.tmp"));
    }
}
