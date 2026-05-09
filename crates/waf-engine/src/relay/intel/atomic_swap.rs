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
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, clippy::panic)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    use wiremock::matchers::method;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[test]
    fn tmp_path_appends_suffix() {
        let p = PathBuf::from("/tmp/foo.mmdb");
        assert_eq!(tmp_path_for(&p), PathBuf::from("/tmp/foo.mmdb.tmp"));
    }

    /// Build a reqwest::Client with no timeout for local tests.
    fn client() -> reqwest::Client {
        reqwest::Client::new()
    }

    #[tokio::test]
    async fn write_atomic_success_creates_file_with_content() {
        let server = MockServer::start().await;
        let body = vec![b'A'; 1024]; // 1 KiB
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(body.clone()))
            .mount(&server)
            .await;

        let tmp_dir = tempfile::tempdir().expect("tmp dir");
        let target = tmp_dir.path().join("out.dat");
        let bounds: SizeBounds = 512..=2048;

        let resp = client().get(server.uri()).send().await.expect("get");
        write_atomic(&target, resp, &bounds).await.expect("ok");

        assert!(target.exists());
        let content = std::fs::read(&target).expect("read");
        assert_eq!(content.len(), 1024);
    }

    #[tokio::test]
    async fn write_atomic_body_too_small_returns_error_and_no_file() {
        let server = MockServer::start().await;
        // Body = 10 bytes; lower bound = 100 bytes → should fail
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(vec![0u8; 10]))
            .mount(&server)
            .await;

        let tmp_dir = tempfile::tempdir().expect("tmp dir");
        let target = tmp_dir.path().join("out.dat");
        let bounds: SizeBounds = 100..=2048;

        let resp = client().get(server.uri()).send().await.expect("get");
        let result = write_atomic(&target, resp, &bounds).await;
        assert!(result.is_err(), "expected error for body too small");
        assert!(!target.exists(), "target should not exist on failure");
    }

    #[tokio::test]
    async fn write_atomic_content_length_too_large_rejects_before_download() {
        let server = MockServer::start().await;
        // Body exactly matches the declared content-length (200 bytes) but
        // the upper bound is 100 bytes → fast-path reject via content-length check.
        let body = vec![0u8; 200];
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(body))
            .mount(&server)
            .await;

        let tmp_dir = tempfile::tempdir().expect("tmp dir");
        let target = tmp_dir.path().join("out.dat");
        // Upper bound = 100, body = 200 → content-length (200) > 100 → fast-path reject
        let bounds: SizeBounds = 10..=100;

        let resp = client().get(server.uri()).send().await.expect("get");
        let result = write_atomic(&target, resp, &bounds).await;
        assert!(result.is_err(), "expected content-length fast-path rejection");
        // tmp file should be cleaned up or never created
        let tmp = tmp_dir.path().join("out.dat.tmp");
        assert!(!tmp.exists(), "tmp file should not exist after fast-path rejection");
    }

    #[tokio::test]
    async fn write_atomic_creates_parent_dirs_if_missing() {
        let server = MockServer::start().await;
        let body = vec![b'Z'; 512];
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(body))
            .mount(&server)
            .await;

        let tmp_dir = tempfile::tempdir().expect("tmp dir");
        // Target in a non-existent subdirectory
        let target = tmp_dir.path().join("sub").join("dir").join("out.dat");
        let bounds: SizeBounds = 1..=2048;

        let resp = client().get(server.uri()).send().await.expect("get");
        write_atomic(&target, resp, &bounds)
            .await
            .expect("should create parent dirs");
        assert!(target.exists());
    }
}
