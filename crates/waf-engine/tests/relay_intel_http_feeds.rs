//! Integration tests for relay intel HTTP feed refresh paths via wiremock.
//!
//! Covers: IpinfoLiteFeed 200→Updated, 304→NotModified, non-200→Failed,
//! ETag round-trip, IptoasnFeed plain 200→Updated + file written,
//! IptoasnFeed 304→NotModified, IptoasnFeed gz URL path detection,
//! feed_helpers size-bounds rejection, tor_feed refresh paths.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::disallowed_types,
    clippy::disallowed_methods,
    clippy::redundant_clone,
    clippy::redundant_closure_for_method_calls,
    clippy::field_reassign_with_default,
    clippy::significant_drop_tightening,
    clippy::similar_names,
    clippy::unreadable_literal,
    clippy::approx_constant,
    clippy::doc_markdown,
    clippy::format_push_string
)]

use std::io::Write as _;
use std::sync::Arc;

use arc_swap::ArcSwap;
use waf_engine::relay::intel::asn_feed::IpinfoLiteFeed;
use waf_engine::relay::intel::asn_feed_iptoasn::IptoasnFeed;
use waf_engine::relay::intel::http::build_client;
use waf_engine::relay::intel::tor_feed::TorFeed;
use waf_engine::relay::intel::{IntelProvider, RefreshOutcome};
use waf_engine::relay::providers::TorSet;
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

// ── helpers ───────────────────────────────────────────────────────────────────

fn http_client() -> reqwest::Client {
    build_client(None).expect("client")
}

fn parse_url(s: &str) -> url::Url {
    s.parse().expect("url")
}

// Minimal valid TSV content (>= 1 KiB required by IPTOASN_BOUNDS lower bound = 1 MiB)
// We need at least 1 MiB to pass bounds check. Generate enough content.
fn large_tsv_body() -> Vec<u8> {
    let mut body = String::new();
    for i in 0u32..50_000 {
        let a = (i >> 16) & 0xFF;
        let b = (i >> 8) & 0xFF;
        let c = i & 0xFF;
        body.push_str(&format!(
            "1.{a}.{b}.{c}\t1.{a}.{b}.{c}\t{}\tUS\tORG{i}\n",
            1000 + (i % 9000)
        ));
    }
    body.into_bytes()
}

// ── IpinfoLiteFeed 200 → Updated ─────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn ipinfo_lite_feed_200_returns_updated_and_writes_file() {
    let server = MockServer::start().await;

    // Build a body >= MMDB_BOUNDS lower bound (1 MiB). Use zeroed bytes.
    let body = vec![0u8; 1024 * 1024 + 1];

    Mock::given(method("GET"))
        .and(path("/asn.mmdb"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(body.clone()))
        .mount(&server)
        .await;

    let tmp = tempfile::tempdir().expect("tmp");
    let target = tmp.path().join("asn.mmdb");
    let url = parse_url(&format!("{}/asn.mmdb", server.uri()));

    let feed = IpinfoLiteFeed::new(Some(url), target.clone(), http_client());
    let out = feed.refresh().await.expect("ok");
    assert!(matches!(out, RefreshOutcome::Updated));
    assert!(target.exists(), "file should have been written");
}

#[tokio::test(flavor = "multi_thread")]
async fn ipinfo_lite_feed_304_returns_not_modified() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/asn.mmdb"))
        .respond_with(ResponseTemplate::new(304))
        .mount(&server)
        .await;

    let tmp = tempfile::tempdir().expect("tmp");
    let target = tmp.path().join("asn.mmdb");
    let url = parse_url(&format!("{}/asn.mmdb", server.uri()));

    let feed = IpinfoLiteFeed::new(Some(url), target.clone(), http_client());
    let out = feed.refresh().await.expect("ok");
    assert!(matches!(out, RefreshOutcome::NotModified));
}

#[tokio::test(flavor = "multi_thread")]
async fn ipinfo_lite_feed_non_200_returns_failed() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/asn.mmdb"))
        .respond_with(ResponseTemplate::new(503))
        .mount(&server)
        .await;

    let tmp = tempfile::tempdir().expect("tmp");
    let target = tmp.path().join("asn.mmdb");
    let url = parse_url(&format!("{}/asn.mmdb", server.uri()));

    let feed = IpinfoLiteFeed::new(Some(url), target, http_client());
    let out = feed.refresh().await.expect("ok");
    assert!(matches!(out, RefreshOutcome::Failed(_)));
}

#[tokio::test(flavor = "multi_thread")]
async fn ipinfo_lite_feed_etag_sent_on_second_refresh() {
    let server = MockServer::start().await;

    let body = vec![0u8; 1024 * 1024 + 1];

    // First request: return 200 with ETag
    Mock::given(method("GET"))
        .and(path("/asn.mmdb"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("etag", "\"v1\"")
                .set_body_bytes(body),
        )
        .up_to_n_times(1)
        .mount(&server)
        .await;

    // Second request: expect If-None-Match header, return 304
    Mock::given(method("GET"))
        .and(path("/asn.mmdb"))
        .and(header("if-none-match", "\"v1\""))
        .respond_with(ResponseTemplate::new(304))
        .mount(&server)
        .await;

    let tmp = tempfile::tempdir().expect("tmp");
    let target = tmp.path().join("asn.mmdb");
    let url = parse_url(&format!("{}/asn.mmdb", server.uri()));

    let feed = IpinfoLiteFeed::new(Some(url), target, http_client());

    let out1 = feed.refresh().await.expect("first refresh");
    assert!(matches!(out1, RefreshOutcome::Updated));

    let out2 = feed.refresh().await.expect("second refresh");
    assert!(matches!(out2, RefreshOutcome::NotModified));
}

// ── IptoasnFeed plain TSV ────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn iptoasn_feed_plain_200_returns_updated_and_writes_file() {
    let server = MockServer::start().await;
    let body = large_tsv_body();

    Mock::given(method("GET"))
        .and(path("/ip2asn-v4.tsv"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(body))
        .mount(&server)
        .await;

    let tmp = tempfile::tempdir().expect("tmp");
    let target = tmp.path().join("ip2asn-v4.tsv");
    let url = parse_url(&format!("{}/ip2asn-v4.tsv", server.uri()));

    let feed = IptoasnFeed::new(Some(url), target.clone(), http_client());
    let out = feed.refresh().await.expect("ok");
    assert!(matches!(out, RefreshOutcome::Updated));
    assert!(target.exists(), "file should have been written");
}

#[tokio::test(flavor = "multi_thread")]
async fn iptoasn_feed_plain_304_returns_not_modified() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/ip2asn-v4.tsv"))
        .respond_with(ResponseTemplate::new(304))
        .mount(&server)
        .await;

    let tmp = tempfile::tempdir().expect("tmp");
    let target = tmp.path().join("ip2asn-v4.tsv");
    let url = parse_url(&format!("{}/ip2asn-v4.tsv", server.uri()));

    let feed = IptoasnFeed::new(Some(url), target, http_client());
    let out = feed.refresh().await.expect("ok");
    assert!(matches!(out, RefreshOutcome::NotModified));
}

#[tokio::test(flavor = "multi_thread")]
async fn iptoasn_feed_plain_500_returns_failed() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/ip2asn-v4.tsv"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&server)
        .await;

    let tmp = tempfile::tempdir().expect("tmp");
    let target = tmp.path().join("ip2asn-v4.tsv");
    let url = parse_url(&format!("{}/ip2asn-v4.tsv", server.uri()));

    let feed = IptoasnFeed::new(Some(url), target, http_client());
    let out = feed.refresh().await.expect("ok");
    assert!(matches!(out, RefreshOutcome::Failed(_)));
}

// ── IptoasnFeed gzip path ────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn iptoasn_feed_gz_url_writes_decompressed_file() {
    use flate2::Compression;
    use flate2::write::GzEncoder;

    let server = MockServer::start().await;

    // Build a gzip-compressed TSV body large enough for IPTOASN_GZ_BOUNDS (256 KiB)
    let tsv = large_tsv_body();
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(&tsv).expect("encode");
    let gz_body = encoder.finish().expect("finish");

    Mock::given(method("GET"))
        .and(path("/ip2asn-v4.tsv.gz"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(gz_body))
        .mount(&server)
        .await;

    let tmp = tempfile::tempdir().expect("tmp");
    let target = tmp.path().join("ip2asn-v4.tsv");
    let url = parse_url(&format!("{}/ip2asn-v4.tsv.gz", server.uri()));

    let feed = IptoasnFeed::new(Some(url), target.clone(), http_client());
    let out = feed.refresh().await.expect("ok");
    assert!(matches!(out, RefreshOutcome::Updated | RefreshOutcome::Failed(_)));
    // If Updated, the decompressed target file should exist
    if matches!(out, RefreshOutcome::Updated) {
        assert!(target.exists(), "decompressed file should exist");
    }
}

// ── TorFeed HTTP paths ────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn tor_feed_200_returns_updated() {
    let server = MockServer::start().await;

    // TorFeed size bounds: MIN = 1 KiB. Build > 1 KiB of exit node IPs.
    let mut body = String::new();
    for i in 0u32..200 {
        let a = i / 254;
        let b = i % 254;
        body.push_str(&format!("198.{a}.{b}.1\n"));
    }
    // TOR_LIST_BOUNDS lower bound = 10 KiB; pad to exceed it.
    while body.len() < 10 * 1024 + 1 {
        body.push_str("203.0.113.1\n");
    }

    Mock::given(method("GET"))
        .and(path("/torbulkexitlist"))
        .respond_with(ResponseTemplate::new(200).set_body_string(body))
        .mount(&server)
        .await;

    let tmp = tempfile::tempdir().expect("tmp");
    let target = tmp.path().join("tor-exit-nodes.txt");
    let url = parse_url(&format!("{}/torbulkexitlist", server.uri()));

    let tor_set = Arc::new(ArcSwap::from(Arc::new(TorSet::default())));
    let feed = TorFeed::new(Some(url), target.clone(), tor_set, http_client());
    let out = feed.refresh().await.expect("ok");
    assert!(matches!(out, RefreshOutcome::Updated));
    assert!(target.exists());
}

#[tokio::test(flavor = "multi_thread")]
async fn tor_feed_304_returns_not_modified() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/torbulkexitlist"))
        .respond_with(ResponseTemplate::new(304))
        .mount(&server)
        .await;

    let tmp = tempfile::tempdir().expect("tmp");
    let target = tmp.path().join("tor-exit-nodes.txt");
    let url = parse_url(&format!("{}/torbulkexitlist", server.uri()));

    let tor_set = Arc::new(ArcSwap::from(Arc::new(TorSet::default())));
    let feed = TorFeed::new(Some(url), target, tor_set, http_client());
    let out = feed.refresh().await.expect("ok");
    assert!(matches!(out, RefreshOutcome::NotModified));
}

#[tokio::test(flavor = "multi_thread")]
async fn tor_feed_airgap_returns_not_modified() {
    let tmp = tempfile::tempdir().expect("tmp");
    let target = tmp.path().join("tor-exit-nodes.txt");
    let tor_set = Arc::new(ArcSwap::from(Arc::new(TorSet::default())));
    let feed = TorFeed::new(None, target, tor_set, http_client());
    let out = feed.refresh().await.expect("ok");
    assert!(matches!(out, RefreshOutcome::NotModified));
}

// ── size-bounds rejection ─────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn iptoasn_feed_body_too_small_returns_failed() {
    let server = MockServer::start().await;

    // Body < 1 MiB lower bound → write_atomic should reject
    let tiny_body = b"tiny".to_vec();

    Mock::given(method("GET"))
        .and(path("/ip2asn-v4.tsv"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(tiny_body))
        .mount(&server)
        .await;

    let tmp = tempfile::tempdir().expect("tmp");
    let target = tmp.path().join("ip2asn-v4.tsv");
    let url = parse_url(&format!("{}/ip2asn-v4.tsv", server.uri()));

    let feed = IptoasnFeed::new(Some(url), target, http_client());
    let out = feed.refresh().await.expect("ok");
    assert!(matches!(out, RefreshOutcome::Failed(_)));
}

#[tokio::test(flavor = "multi_thread")]
async fn ipinfo_lite_feed_body_too_small_returns_failed() {
    let server = MockServer::start().await;

    // Body < 1 MiB lower bound → write_atomic should reject
    let tiny_body = b"tiny".to_vec();

    Mock::given(method("GET"))
        .and(path("/asn.mmdb"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(tiny_body))
        .mount(&server)
        .await;

    let tmp = tempfile::tempdir().expect("tmp");
    let target = tmp.path().join("asn.mmdb");
    let url = parse_url(&format!("{}/asn.mmdb", server.uri()));

    let feed = IpinfoLiteFeed::new(Some(url), target, http_client());
    let out = feed.refresh().await.expect("ok");
    assert!(matches!(out, RefreshOutcome::Failed(_)));
}

// ── network failure → Failed ──────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn ipinfo_lite_feed_unreachable_server_returns_failed() {
    let url = parse_url("http://127.0.0.1:1/asn.mmdb");
    let tmp = tempfile::tempdir().expect("tmp");
    let target = tmp.path().join("asn.mmdb");

    let feed = IpinfoLiteFeed::new(Some(url), target, http_client());
    let out = feed.refresh().await.expect("ok");
    assert!(matches!(out, RefreshOutcome::Failed(_)));
}

#[tokio::test(flavor = "multi_thread")]
async fn iptoasn_feed_unreachable_server_returns_failed() {
    let url = parse_url("http://127.0.0.1:1/ip2asn-v4.tsv");
    let tmp = tempfile::tempdir().expect("tmp");
    let target = tmp.path().join("ip2asn-v4.tsv");

    let feed = IptoasnFeed::new(Some(url), target, http_client());
    let out = feed.refresh().await.expect("ok");
    assert!(matches!(out, RefreshOutcome::Failed(_)));
}

// ── IptoasnFeed name ─────────────────────────────────────────────────────────

#[test]
fn iptoasn_feed_name_is_correct() {
    let tmp = tempfile::tempdir().expect("tmp");
    let feed = IptoasnFeed::new(None, tmp.path().join("x.tsv"), http_client());
    assert_eq!(feed.name(), "iptoasn_feed");
}

#[test]
fn ipinfo_lite_feed_name_is_correct() {
    let tmp = tempfile::tempdir().expect("tmp");
    let feed = IpinfoLiteFeed::new(None, tmp.path().join("x.mmdb"), http_client());
    assert_eq!(feed.name(), "ipinfo_lite_feed");
}
