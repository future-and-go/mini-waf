#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::semicolon_if_nothing_returned
)]

use bytes::Bytes;
use criterion::{BenchmarkId, Criterion, black_box, criterion_group, criterion_main};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use waf_common::{DefenseConfig, HostConfig, RequestCtx};
use waf_engine::checks::{Check, SqlInjectionCheck};

fn make_host_config() -> Arc<HostConfig> {
    Arc::new(HostConfig {
        defense_config: DefenseConfig {
            sqli: true,
            ..DefenseConfig::default()
        },
        ..HostConfig::default()
    })
}

fn make_clean_ctx() -> RequestCtx {
    let mut headers = HashMap::new();
    headers.insert(
        "user-agent".to_string(),
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64)".to_string(),
    );
    headers.insert("accept".to_string(), "text/html,application/json".to_string());
    headers.insert("accept-language".to_string(), "en-US,en;q=0.9".to_string());
    headers.insert("accept-encoding".to_string(), "gzip, deflate, br".to_string());
    headers.insert("content-type".to_string(), "application/json".to_string());

    let body = r#"{"user":"alice","email":"alice@example.com","page":2,"limit":10}"#;

    RequestCtx {
        req_id: "bench-clean-001".to_string(),
        client_ip: "192.168.1.100".parse::<IpAddr>().unwrap(),
        client_port: 54321,
        method: "GET".to_string(),
        host: "api.example.com".to_string(),
        port: 443,
        path: "/api/v1/users".to_string(),
        query: "page=2&limit=10&sort=name".to_string(),
        headers,
        body_preview: Bytes::from(body),
        content_length: body.len() as u64,
        is_tls: true,
        host_config: make_host_config(),
        geo: None,
        tier: waf_common::tier::Tier::CatchAll,
        tier_policy: waf_common::RequestCtx::default_tier_policy(),
    }
}

fn malicious_corpus() -> Vec<(&'static str, RequestCtx)> {
    let host_cfg = make_host_config();

    vec![
        (
            "classic_tautology_url",
            make_ctx_query("id=1' OR '1'='1'--", "", &host_cfg),
        ),
        ("classic_comment_url", make_ctx_query("id=1;--", "", &host_cfg)),
        (
            "classic_stacked_url",
            make_ctx_query("id=1;DROP TABLE users;--", "", &host_cfg),
        ),
        ("blind_boolean_url", make_ctx_query("id=1 AND 1=1", "", &host_cfg)),
        (
            "blind_extraction_url",
            make_ctx_query("id=1 AND SUBSTRING(version(),1,1)='5'", "", &host_cfg),
        ),
        ("time_sleep_url", make_ctx_query("id=1 AND SLEEP(5)--", "", &host_cfg)),
        (
            "time_benchmark_url",
            make_ctx_query("id=1 AND BENCHMARK(1000000,SHA1('a'))--", "", &host_cfg),
        ),
        (
            "time_waitfor_url",
            make_ctx_query("id=1;WAITFOR DELAY '0:0:5'--", "", &host_cfg),
        ),
        (
            "time_pg_sleep_url",
            make_ctx_query("id=1;SELECT pg_sleep(5)--", "", &host_cfg),
        ),
        (
            "union_url",
            make_ctx_query("id=1 UNION SELECT 1,2,username,password FROM users--", "", &host_cfg),
        ),
        (
            "classic_tautology_header",
            make_ctx_header("X-Custom", "1' OR '1'='1'--", &host_cfg),
        ),
        (
            "union_header",
            make_ctx_header("X-Search", "1 UNION SELECT 1,2,3--", &host_cfg),
        ),
        (
            "classic_tautology_json",
            make_ctx_json(r#"{"id":"' OR '1'='1'"}"#, &host_cfg),
        ),
        (
            "union_json",
            make_ctx_json(r#"{"search":"1 UNION SELECT 1,2,3"}"#, &host_cfg),
        ),
    ]
}

fn make_ctx_query(query: &str, body: &str, cfg: &Arc<HostConfig>) -> RequestCtx {
    RequestCtx {
        req_id: "bench".to_string(),
        client_ip: "127.0.0.1".parse().unwrap(),
        client_port: 12345,
        method: "GET".to_string(),
        host: "example.com".to_string(),
        port: 80,
        path: "/api/test".to_string(),
        query: query.to_string(),
        headers: HashMap::new(),
        body_preview: Bytes::from(body.to_string()),
        content_length: body.len() as u64,
        is_tls: false,
        host_config: Arc::clone(cfg),
        geo: None,
        tier: waf_common::tier::Tier::CatchAll,
        tier_policy: waf_common::RequestCtx::default_tier_policy(),
    }
}

fn make_ctx_header(name: &str, value: &str, cfg: &Arc<HostConfig>) -> RequestCtx {
    let mut headers = HashMap::new();
    headers.insert(name.to_lowercase(), value.to_string());
    RequestCtx {
        req_id: "bench".to_string(),
        client_ip: "127.0.0.1".parse().unwrap(),
        client_port: 12345,
        method: "GET".to_string(),
        host: "example.com".to_string(),
        port: 80,
        path: "/".to_string(),
        query: String::new(),
        headers,
        body_preview: Bytes::new(),
        content_length: 0,
        is_tls: false,
        host_config: Arc::clone(cfg),
        geo: None,
        tier: waf_common::tier::Tier::CatchAll,
        tier_policy: waf_common::RequestCtx::default_tier_policy(),
    }
}

fn make_ctx_json(body: &str, cfg: &Arc<HostConfig>) -> RequestCtx {
    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "application/json".to_string());
    RequestCtx {
        req_id: "bench".to_string(),
        client_ip: "127.0.0.1".parse().unwrap(),
        client_port: 12345,
        method: "POST".to_string(),
        host: "example.com".to_string(),
        port: 80,
        path: "/api/data".to_string(),
        query: String::new(),
        headers,
        body_preview: Bytes::from(body.to_string()),
        content_length: body.len() as u64,
        is_tls: false,
        host_config: Arc::clone(cfg),
        geo: None,
        tier: waf_common::tier::Tier::CatchAll,
        tier_policy: waf_common::RequestCtx::default_tier_policy(),
    }
}

fn bench_clean(c: &mut Criterion) {
    let checker = SqlInjectionCheck::new();
    let ctx = make_clean_ctx();
    c.bench_function("sqli_check_clean", |b| {
        b.iter(|| black_box(checker.check(black_box(&ctx))))
    });
}

fn bench_malicious(c: &mut Criterion) {
    let checker = SqlInjectionCheck::new();
    let mut group = c.benchmark_group("sqli_check_malicious");
    for (name, ctx) in malicious_corpus() {
        group.bench_with_input(BenchmarkId::from_parameter(name), &ctx, |b, ctx| {
            b.iter(|| black_box(checker.check(black_box(ctx))))
        });
    }
    group.finish();
}

criterion_group!(benches, bench_clean, bench_malicious);
criterion_main!(benches);
