//! FR-007 phase-07 — Intel feed refresh wiremock tests.
//!
//! Tests IpinfoLiteFeed, IptoasnFeed, and TorFeed for:
//! - 200 OK → RefreshOutcome::Updated (file written)
//! - 304 Not Modified (after first 200 with ETag) → second refresh returns NotModified
//! - 500 Internal Server Error → RefreshOutcome::Failed
//! - Body too small (below SizeBounds floor) → RefreshOutcome::Failed

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::doc_markdown,
    clippy::missing_const_for_fn,
    clippy::format_collect,
    clippy::string_extend_chars
)]

use std::sync::Arc;

use arc_swap::ArcSwap;
use tempfile::TempDir;
use url::Url;
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use waf_engine::relay::intel::{IntelProvider, IpinfoLiteFeed, IptoasnFeed, RefreshOutcome, TorFeed};
use waf_engine::relay::providers::tor_exit::TorSet;

fn build_client() -> reqwest::Client {
    reqwest::Client::builder().build().expect("reqwest client")
}

fn server_url(server: &MockServer, p: &str) -> Url {
    Url::parse(&format!("{}{p}", server.uri())).unwrap()
}

// ─── TorFeed ────────────────────────────────────────────────────────────────

/// Build a valid Tor list body of at least 10 KB (bounds floor).
fn tor_body_ok() -> Vec<u8> {
    // Real list is ~50KB text; pad to 11KB with valid IP lines.
    let mut body = String::with_capacity(12 * 1024);
    // ~200 IPs × ~14 bytes each ≈ 2.8KB; fill to >10KB with comments.
    for i in 0u32..300 {
        use std::fmt::Write as _;
        let _ = writeln!(body, "198.51.{}.{}", (i / 256) % 256, i % 256);
    }
    // Pad with comment lines to reach ≥10KB.
    while body.len() < 10 * 1024 + 1 {
        body.push_str("# padding comment\n");
    }
    body.into_bytes()
}

#[tokio::test]
async fn tor_feed_200_writes_file_and_returns_updated() {
    let server = MockServer::start().await;
    let tmp = TempDir::new().unwrap();
    let list_path = tmp.path().join("tor.txt");
    let body = tor_body_ok();

    Mock::given(method("GET"))
        .and(path("/tor.txt"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(body.clone()))
        .mount(&server)
        .await;

    let set = Arc::new(ArcSwap::from(Arc::new(TorSet::default())));
    let feed = TorFeed::new(
        Some(server_url(&server, "/tor.txt")),
        list_path.clone(),
        Arc::clone(&set),
        build_client(),
    );

    let outcome = feed.fetch_once().await.expect("fetch");
    assert!(
        matches!(outcome, RefreshOutcome::Updated),
        "expected Updated, got Failed"
    );
    assert!(list_path.exists(), "list file must be written on 200");
}

#[tokio::test]
async fn tor_feed_304_after_200_returns_not_modified() {
    let server = MockServer::start().await;
    let tmp = TempDir::new().unwrap();
    let list_path = tmp.path().join("tor.txt");
    let body = tor_body_ok();

    // First request: 200 + ETag.
    Mock::given(method("GET"))
        .and(path("/tor.txt"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_bytes(body)
                .append_header("ETag", "\"abc123\""),
        )
        .up_to_n_times(1)
        .mount(&server)
        .await;

    // Second request (with If-None-Match): 304.
    Mock::given(method("GET"))
        .and(path("/tor.txt"))
        .and(header("if-none-match", "\"abc123\""))
        .respond_with(ResponseTemplate::new(304))
        .mount(&server)
        .await;

    let set = Arc::new(ArcSwap::from(Arc::new(TorSet::default())));
    let feed = TorFeed::new(
        Some(server_url(&server, "/tor.txt")),
        list_path.clone(),
        Arc::clone(&set),
        build_client(),
    );

    let first = feed.fetch_once().await.expect("first");
    assert!(matches!(first, RefreshOutcome::Updated));

    let second = feed.fetch_once().await.expect("second");
    assert!(
        matches!(second, RefreshOutcome::NotModified),
        "expected NotModified on 304"
    );
}

#[tokio::test]
async fn tor_feed_500_returns_failed() {
    let server = MockServer::start().await;
    let tmp = TempDir::new().unwrap();
    let list_path = tmp.path().join("tor.txt");

    Mock::given(method("GET"))
        .and(path("/tor.txt"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&server)
        .await;

    let set = Arc::new(ArcSwap::from(Arc::new(TorSet::default())));
    let feed = TorFeed::new(Some(server_url(&server, "/tor.txt")), list_path, set, build_client());

    let outcome = feed.fetch_once().await.expect("fetch");
    assert!(matches!(outcome, RefreshOutcome::Failed(_)), "expected Failed on 500");
}

#[tokio::test]
async fn tor_feed_body_too_small_returns_failed() {
    let server = MockServer::start().await;
    let tmp = TempDir::new().unwrap();
    let list_path = tmp.path().join("tor.txt");

    // Body well below 10KB floor.
    Mock::given(method("GET"))
        .and(path("/tor.txt"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(b"tiny".to_vec()))
        .mount(&server)
        .await;

    let set = Arc::new(ArcSwap::from(Arc::new(TorSet::default())));
    let feed = TorFeed::new(Some(server_url(&server, "/tor.txt")), list_path, set, build_client());

    let outcome = feed.fetch_once().await.expect("fetch");
    assert!(
        matches!(outcome, RefreshOutcome::Failed(_)),
        "expected Failed for tiny body"
    );
}

#[tokio::test]
async fn tor_feed_200_updates_arc_swap_tor_set() {
    let server = MockServer::start().await;
    let tmp = TempDir::new().unwrap();
    let list_path = tmp.path().join("tor.txt");

    let mut body = String::from("203.0.113.99\n");
    while body.len() < 10 * 1024 + 1 {
        body.push_str("# padding\n");
    }

    Mock::given(method("GET"))
        .and(path("/tor.txt"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(body.into_bytes()))
        .mount(&server)
        .await;

    let set = Arc::new(ArcSwap::from(Arc::new(TorSet::default())));
    let feed = TorFeed::new(
        Some(server_url(&server, "/tor.txt")),
        list_path,
        Arc::clone(&set),
        build_client(),
    );

    feed.fetch_once().await.expect("fetch");
    let snap = set.load();
    assert!(
        snap.contains(&"203.0.113.99".parse().unwrap()),
        "ArcSwap must be updated after 200"
    );
}

// ─── IpinfoLiteFeed ──────────────────────────────────────────────────────────

/// Build a body ≥ 100KB (MMDB_BOUNDS floor).
fn mmdb_body_ok() -> Vec<u8> {
    vec![0u8; 101 * 1024]
}

#[tokio::test]
async fn ipinfo_feed_200_writes_file_and_returns_updated() {
    let server = MockServer::start().await;
    let tmp = TempDir::new().unwrap();
    let target = tmp.path().join("asn.mmdb");
    let body = mmdb_body_ok();

    Mock::given(method("GET"))
        .and(path("/asn.mmdb"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(body))
        .mount(&server)
        .await;

    let feed = IpinfoLiteFeed::new(Some(server_url(&server, "/asn.mmdb")), target.clone(), build_client());

    let outcome = feed.refresh().await.expect("refresh");
    assert!(matches!(outcome, RefreshOutcome::Updated));
    assert!(target.exists(), "file must be written on 200");
}

#[tokio::test]
async fn ipinfo_feed_304_returns_not_modified() {
    let server = MockServer::start().await;
    let tmp = TempDir::new().unwrap();
    let target = tmp.path().join("asn.mmdb");

    Mock::given(method("GET"))
        .and(path("/asn.mmdb"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_bytes(mmdb_body_ok())
                .append_header("ETag", "\"v1\""),
        )
        .up_to_n_times(1)
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/asn.mmdb"))
        .and(header("if-none-match", "\"v1\""))
        .respond_with(ResponseTemplate::new(304))
        .mount(&server)
        .await;

    let feed = IpinfoLiteFeed::new(Some(server_url(&server, "/asn.mmdb")), target, build_client());

    let first = feed.refresh().await.expect("first");
    assert!(matches!(first, RefreshOutcome::Updated));

    let second = feed.refresh().await.expect("second");
    assert!(matches!(second, RefreshOutcome::NotModified));
}

#[tokio::test]
async fn ipinfo_feed_500_returns_failed() {
    let server = MockServer::start().await;
    let tmp = TempDir::new().unwrap();

    Mock::given(method("GET"))
        .and(path("/asn.mmdb"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&server)
        .await;

    let feed = IpinfoLiteFeed::new(
        Some(server_url(&server, "/asn.mmdb")),
        tmp.path().join("asn.mmdb"),
        build_client(),
    );

    let outcome = feed.refresh().await.expect("refresh");
    assert!(matches!(outcome, RefreshOutcome::Failed(_)));
}

#[tokio::test]
async fn ipinfo_feed_body_below_floor_returns_failed() {
    let server = MockServer::start().await;
    let tmp = TempDir::new().unwrap();

    // Body below 100KB floor.
    Mock::given(method("GET"))
        .and(path("/asn.mmdb"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(vec![0u8; 50]))
        .mount(&server)
        .await;

    let feed = IpinfoLiteFeed::new(
        Some(server_url(&server, "/asn.mmdb")),
        tmp.path().join("asn.mmdb"),
        build_client(),
    );

    let outcome = feed.refresh().await.expect("refresh");
    assert!(
        matches!(outcome, RefreshOutcome::Failed(_)),
        "expected Failed for body below floor"
    );
}

// ─── IptoasnFeed (plain TSV) ─────────────────────────────────────────────────

/// Build a body ≥ 1 MiB (IPTOASN_BOUNDS floor = 1024 * 1024 bytes).
fn tsv_body_ok() -> Vec<u8> {
    vec![b'a'; 1024 * 1024 + 1]
}

#[tokio::test]
async fn iptoasn_feed_200_writes_file_and_returns_updated() {
    let server = MockServer::start().await;
    let tmp = TempDir::new().unwrap();
    let target = tmp.path().join("iptoasn.tsv");

    Mock::given(method("GET"))
        .and(path("/iptoasn.tsv"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(tsv_body_ok()))
        .mount(&server)
        .await;

    let feed = IptoasnFeed::new(
        Some(server_url(&server, "/iptoasn.tsv")),
        target.clone(),
        build_client(),
    );

    let outcome = feed.refresh().await.expect("refresh");
    assert!(matches!(outcome, RefreshOutcome::Updated));
    assert!(target.exists());
}

#[tokio::test]
async fn iptoasn_feed_304_returns_not_modified() {
    let server = MockServer::start().await;
    let tmp = TempDir::new().unwrap();
    let target = tmp.path().join("iptoasn.tsv");

    Mock::given(method("GET"))
        .and(path("/iptoasn.tsv"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_bytes(tsv_body_ok())
                .append_header("ETag", "\"tsv1\""),
        )
        .up_to_n_times(1)
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/iptoasn.tsv"))
        .and(header("if-none-match", "\"tsv1\""))
        .respond_with(ResponseTemplate::new(304))
        .mount(&server)
        .await;

    let feed = IptoasnFeed::new(Some(server_url(&server, "/iptoasn.tsv")), target, build_client());

    assert!(matches!(feed.refresh().await.expect("first"), RefreshOutcome::Updated));
    assert!(matches!(
        feed.refresh().await.expect("second"),
        RefreshOutcome::NotModified
    ));
}

#[tokio::test]
async fn iptoasn_feed_500_returns_failed() {
    let server = MockServer::start().await;
    let tmp = TempDir::new().unwrap();

    Mock::given(method("GET"))
        .and(path("/iptoasn.tsv"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&server)
        .await;

    let feed = IptoasnFeed::new(
        Some(server_url(&server, "/iptoasn.tsv")),
        tmp.path().join("iptoasn.tsv"),
        build_client(),
    );

    let outcome = feed.refresh().await.expect("refresh");
    assert!(matches!(outcome, RefreshOutcome::Failed(_)));
}

#[tokio::test]
async fn iptoasn_feed_body_below_floor_returns_failed() {
    let server = MockServer::start().await;
    let tmp = TempDir::new().unwrap();

    // Below 1MB floor.
    Mock::given(method("GET"))
        .and(path("/iptoasn.tsv"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(vec![b'a'; 100]))
        .mount(&server)
        .await;

    let feed = IptoasnFeed::new(
        Some(server_url(&server, "/iptoasn.tsv")),
        tmp.path().join("iptoasn.tsv"),
        build_client(),
    );

    let outcome = feed.refresh().await.expect("refresh");
    assert!(matches!(outcome, RefreshOutcome::Failed(_)));
}
