#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use bytes::Bytes;
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

fn make_ctx(query: &str, body: &str, headers: HashMap<String, String>) -> RequestCtx {
    RequestCtx {
        req_id: "test".to_string(),
        client_ip: "127.0.0.1".parse::<IpAddr>().unwrap(),
        client_port: 12345,
        method: "GET".to_string(),
        host: "example.com".to_string(),
        port: 80,
        path: "/".to_string(),
        query: query.to_string(),
        headers,
        body_preview: Bytes::from(body.to_string()),
        content_length: body.len() as u64,
        is_tls: false,
        host_config: make_host_config(),
        geo: None,
    }
}

fn json_headers() -> HashMap<String, String> {
    let mut h = HashMap::new();
    h.insert("content-type".to_string(), "application/json".to_string());
    h
}

fn custom_header(name: &str, value: &str) -> HashMap<String, String> {
    let mut h = HashMap::new();
    h.insert(name.to_lowercase(), value.to_string());
    h
}

// ═══════════════════════════════════════════════════════════════════════════════
// CLASSIC SQLi (tautology, comment, stacked) — URL param
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn classic_tautology_url_variant1() {
    let checker = SqlInjectionCheck::new();
    let ctx = make_ctx("id=1' OR '1'='1'--", "", HashMap::new());
    assert!(checker.check(&ctx).is_some(), "tautology ' OR '1'='1' in URL param");
}

#[test]
fn classic_tautology_url_variant2() {
    let checker = SqlInjectionCheck::new();
    let ctx = make_ctx("user=admin' OR '2'='2'--", "", HashMap::new());
    assert!(checker.check(&ctx).is_some(), "tautology ' OR '2'='2' in URL param");
}

#[test]
fn classic_comment_url_variant1() {
    let checker = SqlInjectionCheck::new();
    let ctx = make_ctx("id=1--SELECT password FROM users", "", HashMap::new());
    assert!(
        checker.check(&ctx).is_some(),
        "comment -- followed by SELECT in URL param"
    );
}

#[test]
fn classic_comment_url_variant2() {
    let checker = SqlInjectionCheck::new();
    let ctx = make_ctx("id=1/**/SELECT * FROM users", "", HashMap::new());
    assert!(
        checker.check(&ctx).is_some(),
        "block comment before SELECT in URL param"
    );
}

#[test]
fn classic_stacked_url_variant1() {
    let checker = SqlInjectionCheck::new();
    let ctx = make_ctx("id=1';DROP TABLE users;--", "", HashMap::new());
    assert!(checker.check(&ctx).is_some(), "stacked DROP TABLE in URL param");
}

#[test]
fn classic_stacked_url_variant2() {
    let checker = SqlInjectionCheck::new();
    let ctx = make_ctx("id=1';DELETE FROM sessions;--", "", HashMap::new());
    assert!(checker.check(&ctx).is_some(), "stacked DELETE FROM in URL param");
}

// ═══════════════════════════════════════════════════════════════════════════════
// CLASSIC SQLi — Header
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn classic_tautology_header_variant1() {
    let checker = SqlInjectionCheck::new();
    let ctx = make_ctx("", "", custom_header("x-custom", "1' OR '1'='1'--"));
    assert!(checker.check(&ctx).is_some(), "tautology in custom header");
}

#[test]
fn classic_tautology_header_variant2() {
    let checker = SqlInjectionCheck::new();
    let ctx = make_ctx("", "", custom_header("user-agent", "Mozilla' OR '1'='1'--"));
    assert!(checker.check(&ctx).is_some(), "tautology in User-Agent header");
}

#[test]
fn classic_stacked_header_variant1() {
    let checker = SqlInjectionCheck::new();
    let ctx = make_ctx("", "", custom_header("referer", "http://x.com';DROP TABLE users;--"));
    assert!(checker.check(&ctx).is_some(), "stacked query in Referer header");
}

#[test]
fn classic_stacked_header_variant2() {
    let checker = SqlInjectionCheck::new();
    let ctx = make_ctx(
        "",
        "",
        custom_header("x-forwarded-for", "127.0.0.1';DELETE FROM logs;--"),
    );
    assert!(checker.check(&ctx).is_some(), "stacked query in X-Forwarded-For header");
}

// ═══════════════════════════════════════════════════════════════════════════════
// CLASSIC SQLi — JSON body
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn classic_tautology_json_variant1() {
    let checker = SqlInjectionCheck::new();
    let ctx = make_ctx("", r#"{"username":"' OR '1'='1'"}"#, json_headers());
    assert!(checker.check(&ctx).is_some(), "tautology in JSON body");
}

#[test]
fn classic_tautology_json_variant2() {
    let checker = SqlInjectionCheck::new();
    let ctx = make_ctx("", r#"{"filter":"' OR 'x'='x'"}"#, json_headers());
    assert!(checker.check(&ctx).is_some(), "tautology variant in JSON body");
}

#[test]
fn classic_stacked_json_variant1() {
    let checker = SqlInjectionCheck::new();
    let ctx = make_ctx("", r#"{"id":"1';DROP TABLE users;--"}"#, json_headers());
    assert!(checker.check(&ctx).is_some(), "stacked query in JSON body");
}

#[test]
fn classic_stacked_json_variant2() {
    let checker = SqlInjectionCheck::new();
    let ctx = make_ctx("", r#"{"nested":{"value":"';DELETE FROM data;--"}}"#, json_headers());
    assert!(checker.check(&ctx).is_some(), "stacked query in nested JSON");
}

// ═══════════════════════════════════════════════════════════════════════════════
// BLIND SQLi (boolean, extraction, conditional) — URL param
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn blind_boolean_url_variant1() {
    let checker = SqlInjectionCheck::new();
    let ctx = make_ctx("id=1 AND 1=1", "", HashMap::new());
    assert!(checker.check(&ctx).is_some(), "boolean-based blind AND 1=1");
}

#[test]
fn blind_boolean_url_variant2() {
    let checker = SqlInjectionCheck::new();
    let ctx = make_ctx("id=1 AND 1=2", "", HashMap::new());
    assert!(checker.check(&ctx).is_some(), "boolean-based blind AND 1=2");
}

#[test]
fn blind_extraction_url_variant1() {
    let checker = SqlInjectionCheck::new();
    let ctx = make_ctx("id=1 AND SUBSTRING(version(),1,1)='5'", "", HashMap::new());
    assert!(checker.check(&ctx).is_some(), "extraction via SUBSTRING");
}

#[test]
fn blind_extraction_url_variant2() {
    let checker = SqlInjectionCheck::new();
    let ctx = make_ctx("id=1 AND ASCII(SUBSTR(user(),1,1))>64", "", HashMap::new());
    assert!(checker.check(&ctx).is_some(), "extraction via ASCII/SUBSTR");
}

// ═══════════════════════════════════════════════════════════════════════════════
// BLIND SQLi — Header
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn blind_boolean_header_variant1() {
    let checker = SqlInjectionCheck::new();
    let ctx = make_ctx("", "", custom_header("x-filter", "1 AND 1=1"));
    assert!(checker.check(&ctx).is_some(), "boolean blind in header");
}

#[test]
fn blind_boolean_header_variant2() {
    let checker = SqlInjectionCheck::new();
    let ctx = make_ctx("", "", custom_header("x-id", "test' AND '1'='1'"));
    assert!(checker.check(&ctx).is_some(), "string boolean blind in header");
}

#[test]
fn blind_extraction_header_variant1() {
    let checker = SqlInjectionCheck::new();
    let ctx = make_ctx(
        "",
        "",
        custom_header("user-agent", "1 AND SUBSTRING(@@version,1,1)='5'"),
    );
    assert!(checker.check(&ctx).is_some(), "extraction in User-Agent");
}

#[test]
fn blind_extraction_header_variant2() {
    let checker = SqlInjectionCheck::new();
    let ctx = make_ctx(
        "",
        "",
        custom_header("referer", "http://x.com?x=1 AND LENGTH(database())>0"),
    );
    assert!(checker.check(&ctx).is_some(), "extraction LENGTH in Referer");
}

// ═══════════════════════════════════════════════════════════════════════════════
// BLIND SQLi — JSON body
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn blind_boolean_json_variant1() {
    let checker = SqlInjectionCheck::new();
    let ctx = make_ctx("", r#"{"id":"1 AND 1=1"}"#, json_headers());
    assert!(checker.check(&ctx).is_some(), "boolean blind in JSON");
}

#[test]
fn blind_boolean_json_variant2() {
    let checker = SqlInjectionCheck::new();
    let ctx = make_ctx("", r#"{"filter":"' AND 'a'='a'"}"#, json_headers());
    assert!(checker.check(&ctx).is_some(), "string boolean blind in JSON");
}

#[test]
fn blind_extraction_json_variant1() {
    let checker = SqlInjectionCheck::new();
    let ctx = make_ctx("", r#"{"search":"1 AND SUBSTRING(user(),1,1)='r'"}"#, json_headers());
    assert!(checker.check(&ctx).is_some(), "extraction SUBSTRING in JSON");
}

#[test]
fn blind_extraction_json_variant2() {
    let checker = SqlInjectionCheck::new();
    let ctx = make_ctx("", r#"{"query":"1 AND LENGTH(database())>0"}"#, json_headers());
    assert!(checker.check(&ctx).is_some(), "extraction LENGTH in JSON");
}

// ═══════════════════════════════════════════════════════════════════════════════
// TIME-BASED SQLi (SLEEP, BENCHMARK, WAITFOR, pg_sleep) — URL param
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn time_sleep_url_variant1() {
    let checker = SqlInjectionCheck::new();
    let ctx = make_ctx("id=1 AND SLEEP(5)--", "", HashMap::new());
    assert!(checker.check(&ctx).is_some(), "SLEEP in URL param");
}

#[test]
fn time_sleep_url_variant2() {
    let checker = SqlInjectionCheck::new();
    let ctx = make_ctx("id=1' AND SLEEP(10)--", "", HashMap::new());
    assert!(checker.check(&ctx).is_some(), "quoted SLEEP in URL param");
}

#[test]
fn time_benchmark_url_variant1() {
    let checker = SqlInjectionCheck::new();
    let ctx = make_ctx("id=1 AND BENCHMARK(1000000,SHA1('a'))--", "", HashMap::new());
    assert!(checker.check(&ctx).is_some(), "BENCHMARK in URL param");
}

#[test]
fn time_benchmark_url_variant2() {
    let checker = SqlInjectionCheck::new();
    let ctx = make_ctx("id=1 AND BENCHMARK(5000000,MD5('test'))--", "", HashMap::new());
    assert!(checker.check(&ctx).is_some(), "BENCHMARK MD5 in URL param");
}

#[test]
fn time_waitfor_url_variant1() {
    let checker = SqlInjectionCheck::new();
    let ctx = make_ctx("id=1;WAITFOR DELAY('0:0:5')--", "", HashMap::new());
    assert!(checker.check(&ctx).is_some(), "WAITFOR DELAY with parens in URL param");
}

#[test]
fn time_waitfor_url_variant2() {
    let checker = SqlInjectionCheck::new();
    let ctx = make_ctx("id=1';waitfor delay('0:0:10')--", "", HashMap::new());
    assert!(checker.check(&ctx).is_some(), "quoted WAITFOR in URL param");
}

#[test]
fn time_pg_sleep_url_variant1() {
    let checker = SqlInjectionCheck::new();
    let ctx = make_ctx("id=1;SELECT pg_sleep(5)--", "", HashMap::new());
    assert!(checker.check(&ctx).is_some(), "pg_sleep in URL param");
}

#[test]
fn time_pg_sleep_url_variant2() {
    let checker = SqlInjectionCheck::new();
    let ctx = make_ctx("id=1' AND pg_sleep(10)--", "", HashMap::new());
    assert!(checker.check(&ctx).is_some(), "quoted pg_sleep in URL param");
}

// ═══════════════════════════════════════════════════════════════════════════════
// TIME-BASED SQLi — Header
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn time_sleep_header_variant1() {
    let checker = SqlInjectionCheck::new();
    let ctx = make_ctx("", "", custom_header("x-id", "1 AND SLEEP(5)--"));
    assert!(checker.check(&ctx).is_some(), "SLEEP in header");
}

#[test]
fn time_sleep_header_variant2() {
    let checker = SqlInjectionCheck::new();
    let ctx = make_ctx("", "", custom_header("user-agent", "Mozilla' AND SLEEP(5)--"));
    assert!(checker.check(&ctx).is_some(), "SLEEP in User-Agent");
}

#[test]
fn time_benchmark_header_variant1() {
    let checker = SqlInjectionCheck::new();
    let ctx = make_ctx(
        "",
        "",
        custom_header("referer", "http://x.com?1 AND BENCHMARK(1000000,SHA1('x'))"),
    );
    assert!(checker.check(&ctx).is_some(), "BENCHMARK in Referer");
}

#[test]
fn time_pg_sleep_header_variant1() {
    let checker = SqlInjectionCheck::new();
    let ctx = make_ctx("", "", custom_header("x-custom", "1;SELECT pg_sleep(5)--"));
    assert!(checker.check(&ctx).is_some(), "pg_sleep in header");
}

// ═══════════════════════════════════════════════════════════════════════════════
// TIME-BASED SQLi — JSON body
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn time_sleep_json_variant1() {
    let checker = SqlInjectionCheck::new();
    let ctx = make_ctx("", r#"{"id":"1 AND SLEEP(5)"}"#, json_headers());
    assert!(checker.check(&ctx).is_some(), "SLEEP in JSON body");
}

#[test]
fn time_sleep_json_variant2() {
    let checker = SqlInjectionCheck::new();
    let ctx = make_ctx("", r#"{"query":"' AND SLEEP(10)--"}"#, json_headers());
    assert!(checker.check(&ctx).is_some(), "quoted SLEEP in JSON");
}

#[test]
fn time_benchmark_json_variant1() {
    let checker = SqlInjectionCheck::new();
    let ctx = make_ctx("", r#"{"input":"1 AND BENCHMARK(1000000,SHA1('a'))"}"#, json_headers());
    assert!(checker.check(&ctx).is_some(), "BENCHMARK in JSON");
}

#[test]
fn time_waitfor_json_variant1() {
    let checker = SqlInjectionCheck::new();
    let ctx = make_ctx("", r#"{"cmd":"1;waitfor delay('0:0:5')--"}"#, json_headers());
    assert!(checker.check(&ctx).is_some(), "WAITFOR in JSON");
}

#[test]
fn time_pg_sleep_json_variant1() {
    let checker = SqlInjectionCheck::new();
    let ctx = make_ctx("", r#"{"val":"1;SELECT pg_sleep(5)--"}"#, json_headers());
    assert!(checker.check(&ctx).is_some(), "pg_sleep in JSON");
}

// ═══════════════════════════════════════════════════════════════════════════════
// UNION-BASED SQLi — URL param
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn union_url_variant1() {
    let checker = SqlInjectionCheck::new();
    let ctx = make_ctx("id=1 UNION SELECT 1,2,3--", "", HashMap::new());
    assert!(checker.check(&ctx).is_some(), "UNION SELECT in URL param");
}

#[test]
fn union_url_variant2() {
    let checker = SqlInjectionCheck::new();
    let ctx = make_ctx(
        "id=1 UNION/**/SELECT username,password FROM users--",
        "",
        HashMap::new(),
    );
    assert!(checker.check(&ctx).is_some(), "UNION comment SELECT in URL param");
}

#[test]
fn union_url_variant3() {
    let checker = SqlInjectionCheck::new();
    let ctx = make_ctx(
        "id=-1 UNION SELECT NULL,NULL,table_name FROM information_schema.tables--",
        "",
        HashMap::new(),
    );
    assert!(checker.check(&ctx).is_some(), "UNION info_schema in URL param");
}

// ═══════════════════════════════════════════════════════════════════════════════
// UNION-BASED SQLi — Header
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn union_header_variant1() {
    let checker = SqlInjectionCheck::new();
    let ctx = make_ctx("", "", custom_header("x-search", "1 UNION SELECT 1,2,3--"));
    assert!(checker.check(&ctx).is_some(), "UNION SELECT in header");
}

#[test]
fn union_header_variant2() {
    let checker = SqlInjectionCheck::new();
    let ctx = make_ctx("", "", custom_header("user-agent", "test' UNION SELECT 1,2,3--"));
    assert!(checker.check(&ctx).is_some(), "UNION in User-Agent");
}

#[test]
fn union_header_variant3() {
    let checker = SqlInjectionCheck::new();
    let ctx = make_ctx(
        "",
        "",
        custom_header("referer", "http://x.com?x=1 UNION/**/SELECT a,b FROM c--"),
    );
    assert!(checker.check(&ctx).is_some(), "UNION with comment in Referer");
}

// ═══════════════════════════════════════════════════════════════════════════════
// UNION-BASED SQLi — JSON body
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn union_json_variant1() {
    let checker = SqlInjectionCheck::new();
    let ctx = make_ctx("", r#"{"search":"1 UNION SELECT 1,2,3"}"#, json_headers());
    assert!(checker.check(&ctx).is_some(), "UNION SELECT in JSON");
}

#[test]
fn union_json_variant2() {
    let checker = SqlInjectionCheck::new();
    let ctx = make_ctx(
        "",
        r#"{"filter":"' UNION SELECT id,name FROM users--"}"#,
        json_headers(),
    );
    assert!(checker.check(&ctx).is_some(), "UNION SELECT in JSON");
}

#[test]
fn union_json_variant3() {
    let checker = SqlInjectionCheck::new();
    let ctx = make_ctx(
        "",
        r#"{"data":{"q":"-1 UNION SELECT column_name FROM information_schema.columns--"}}"#,
        json_headers(),
    );
    assert!(checker.check(&ctx).is_some(), "UNION nested JSON");
}

// ═══════════════════════════════════════════════════════════════════════════════
// CLEAN REQUEST NEGATIVES — must NOT trigger
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn clean_url_params() {
    let checker = SqlInjectionCheck::new();
    let ctx = make_ctx("name=alice&page=2&sort=created_at&order=desc", "", HashMap::new());
    assert!(checker.check(&ctx).is_none(), "clean URL params should pass");
}

#[test]
fn clean_json_body() {
    let checker = SqlInjectionCheck::new();
    let body = r#"{"username":"john_doe","email":"john@example.com","age":30,"active":true}"#;
    let ctx = make_ctx("", body, json_headers());
    assert!(checker.check(&ctx).is_none(), "clean JSON body should pass");
}

#[test]
fn clean_headers() {
    let checker = SqlInjectionCheck::new();
    let mut h = HashMap::new();
    h.insert(
        "user-agent".to_string(),
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64)".to_string(),
    );
    h.insert("accept".to_string(), "text/html,application/json".to_string());
    h.insert("x-request-id".to_string(), "abc123-def456".to_string());
    let ctx = make_ctx("", "", h);
    assert!(checker.check(&ctx).is_none(), "clean headers should pass");
}

#[test]
fn clean_complex_json() {
    let checker = SqlInjectionCheck::new();
    let body = r#"{
        "users": [
            {"id": 1, "name": "Alice", "roles": ["admin", "user"]},
            {"id": 2, "name": "Bob", "roles": ["user"]}
        ],
        "pagination": {"page": 1, "limit": 10, "total": 100},
        "filters": {"status": "active", "created_after": "2024-01-01"}
    }"#;
    let ctx = make_ctx("", body, json_headers());
    assert!(checker.check(&ctx).is_none(), "complex clean JSON should pass");
}

#[test]
fn clean_url_with_special_chars() {
    let checker = SqlInjectionCheck::new();
    let ctx = make_ctx("search=hello+world&tags=rust,waf&date=2024-01-01", "", HashMap::new());
    assert!(checker.check(&ctx).is_none(), "URL with special chars should pass");
}

// ═══════════════════════════════════════════════════════════════════════════════
// JWT/AUTHORIZATION NON-FALSE-POSITIVE TESTS
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn jwt_authorization_header_no_false_positive() {
    let checker = SqlInjectionCheck::new();
    let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
    let mut h = HashMap::new();
    h.insert("authorization".to_string(), format!("Bearer {jwt}"));
    let ctx = make_ctx("", "", h);
    assert!(
        checker.check(&ctx).is_none(),
        "JWT in Authorization should not false-positive"
    );
}

#[test]
fn jwt_x_token_header_no_false_positive() {
    let checker = SqlInjectionCheck::new();
    let jwt = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2V4YW1wbGUuY29tIiwiYXVkIjoiYXBpIn0.signature";
    let mut h = HashMap::new();
    h.insert("x-token".to_string(), jwt.to_string());
    let ctx = make_ctx("", "", h);
    assert!(
        checker.check(&ctx).is_none(),
        "JWT in X-Token should not false-positive"
    );
}

#[test]
fn base64_content_no_false_positive() {
    let checker = SqlInjectionCheck::new();
    let ctx = make_ctx("data=SGVsbG8gV29ybGQhIFRoaXMgaXMgYSB0ZXN0Lg==", "", HashMap::new());
    assert!(
        checker.check(&ctx).is_none(),
        "Base64 encoded data should not false-positive"
    );
}

// ═══════════════════════════════════════════════════════════════════════════════
// ENCODED EVASION DETECTION
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn url_encoded_union_select() {
    let checker = SqlInjectionCheck::new();
    let ctx = make_ctx("id=1%20UNION%20SELECT%201,2,3--", "", HashMap::new());
    assert!(checker.check(&ctx).is_some(), "URL-encoded UNION should be detected");
}

#[test]
fn double_encoded_sleep() {
    let checker = SqlInjectionCheck::new();
    let ctx = make_ctx("id=1%2520AND%2520SLEEP(5)", "", HashMap::new());
    assert!(checker.check(&ctx).is_some(), "Double-encoded SLEEP should be detected");
}

#[test]
fn plus_encoded_spaces() {
    let checker = SqlInjectionCheck::new();
    let ctx = make_ctx("id=1+UNION+SELECT+1,2,3--", "", HashMap::new());
    assert!(checker.check(&ctx).is_some(), "Plus-encoded spaces should be detected");
}
