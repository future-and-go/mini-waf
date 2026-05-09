//! Phase 07 — `RuleStore::reload_all` correctness with concurrent readers.

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
    clippy::missing_const_for_fn,
    clippy::items_after_statements,
    clippy::format_push_string,
    clippy::err_expect,
    clippy::needless_pass_by_value,
    clippy::needless_raw_string_hashes,
    unused_imports
)]

#[path = "common/mod.rs"]
mod common;

use std::sync::Arc;

use common::start_engine;
use waf_storage::models::{CreateHost, CreateIpRule, CreateUrlRule};

#[tokio::test(flavor = "multi_thread")]
async fn reload_all_loads_seeded_data() {
    let fx = start_engine().await;
    let host = fx
        .db
        .create_host(CreateHost {
            host: "seed.example.com".into(),
            port: 80,
            ssl: false,
            guard_status: true,
            remote_host: "127.0.0.1".into(),
            remote_port: 8080,
            remote_ip: None,
            cert_file: None,
            key_file: None,
            remarks: None,
            start_status: true,
            log_only_mode: false,
        })
        .await
        .expect("create host");

    for i in 0..16u8 {
        fx.db
            .create_block_ip(CreateIpRule {
                host_code: host.code.clone(),
                ip_cidr: format!("203.0.113.{i}/32"),
                remarks: None,
            })
            .await
            .expect("seed");
        fx.db
            .create_block_url(CreateUrlRule {
                host_code: host.code.clone(),
                url_pattern: format!("/admin/{i}"),
                match_type: "prefix".into(),
                remarks: None,
            })
            .await
            .expect("seed");
    }

    fx.engine.store.reload_all().await.expect("reload");

    // The store now matches every seeded IP and URL.
    for i in 0..16u8 {
        let ip: std::net::IpAddr = format!("203.0.113.{i}").parse().unwrap();
        assert!(fx.engine.store.block_ips.matches(&host.code, ip));
        let path = format!("/admin/{i}/page");
        assert!(fx.engine.store.block_urls.matches(&host.code, &path).is_some());
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn concurrent_reload_keeps_reader_consistent() {
    let fx = start_engine().await;
    let host = fx
        .db
        .create_host(CreateHost {
            host: "race.example.com".into(),
            port: 80,
            ssl: false,
            guard_status: true,
            remote_host: "127.0.0.1".into(),
            remote_port: 8080,
            remote_ip: None,
            cert_file: None,
            key_file: None,
            remarks: None,
            start_status: true,
            log_only_mode: false,
        })
        .await
        .expect("host");
    fx.db
        .create_block_ip(CreateIpRule {
            host_code: host.code.clone(),
            ip_cidr: "172.16.0.0/16".into(),
            remarks: None,
        })
        .await
        .expect("seed");
    fx.engine.store.reload_all().await.expect("initial");

    let store = Arc::clone(&fx.engine.store);
    let code = host.code.clone();
    let reader = tokio::spawn(async move {
        let probe: std::net::IpAddr = "172.16.5.5".parse().unwrap();
        for _ in 0..200 {
            // Reader must always see either pre-snapshot (true) or post-snapshot (true here).
            assert!(store.block_ips.matches(&code, probe));
            tokio::task::yield_now().await;
        }
    });

    for _ in 0..10 {
        fx.engine.store.reload_all().await.expect("reload");
    }
    reader.await.expect("reader");
}
