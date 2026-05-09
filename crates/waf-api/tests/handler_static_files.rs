// Integration tests for embedded admin UI routes (/, /ui, /ui/, /ui/{path}).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::disallowed_types,
    clippy::disallowed_methods,
    clippy::undocumented_unsafe_blocks,
    clippy::doc_markdown,
    clippy::redundant_clone
)]

#[path = "common/mod.rs"]
mod common;

use common::{client, start_test_server, url_for};

fn no_redirect_client() -> reqwest::Client {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .expect("build client")
}

#[tokio::test(flavor = "multi_thread")]
async fn root_redirects_to_ui() {
    let s = start_test_server().await;
    let resp = no_redirect_client()
        .get(url_for(s.addr, "/"))
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), 308);
    let loc = resp.headers().get("location").expect("location header");
    assert_eq!(loc.to_str().unwrap(), "/ui/");
}

#[tokio::test(flavor = "multi_thread")]
async fn ui_no_slash_redirects() {
    let s = start_test_server().await;
    let resp = no_redirect_client()
        .get(url_for(s.addr, "/ui"))
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), 308);
    let loc = resp.headers().get("location").expect("location header");
    assert_eq!(loc.to_str().unwrap(), "/ui/");
}

#[tokio::test(flavor = "multi_thread")]
async fn ui_index_returns_200_or_404() {
    // The embedded admin panel may not be built in the test environment.
    // Either way, the handler must respond (not 5xx).
    let s = start_test_server().await;
    let resp = client().get(url_for(s.addr, "/ui/")).send().await.expect("send");
    let status = resp.status().as_u16();
    assert!(status == 200 || status == 404, "unexpected status for /ui/: {status}");
}

#[tokio::test(flavor = "multi_thread")]
async fn ui_unknown_path_falls_back_to_index_or_404() {
    let s = start_test_server().await;
    let resp = client()
        .get(url_for(s.addr, "/ui/some/spa/route"))
        .send()
        .await
        .expect("send");
    let status = resp.status().as_u16();
    assert!(
        status == 200 || status == 404,
        "unexpected status for SPA fallback: {status}"
    );
}
