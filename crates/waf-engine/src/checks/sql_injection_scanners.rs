//! SQL injection scanner helpers.
//!
//! Advanced scanning for JSON bodies and query parameters with path attribution.

use regex::RegexSet;
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::fmt::Write;
use waf_common::config::SqliScanConfig;

use super::url_decode_recursive;

/// Scan JSON body for `SQLi` patterns, returning (`json_path`, `pattern_index`) on first hit.
pub fn scan_json_body(body: &[u8], patterns: &RegexSet, json_parse_cap: usize) -> Option<(String, usize)> {
    if body.len() > json_parse_cap {
        return None;
    }
    let v: Value = serde_json::from_slice(body).ok()?;
    walk_json(&v, &mut String::from("body"), patterns)
}

/// Scan HTTP headers for `SQLi` patterns, respecting allowlist/denylist and cap.
pub fn scan_headers(
    headers: &HashMap<String, String>,
    cfg: &SqliScanConfig,
    patterns: &RegexSet,
) -> Option<(String, usize)> {
    if !cfg.scan_headers {
        return None;
    }

    let allowlist: Option<HashSet<String>> = (!cfg.header_allowlist.is_empty())
        .then(|| cfg.header_allowlist.iter().map(|s| s.to_ascii_lowercase()).collect());
    let denylist: HashSet<String> = cfg.header_denylist.iter().map(|s| s.to_ascii_lowercase()).collect();

    for (name, value) in headers {
        let key = name.to_ascii_lowercase();
        match &allowlist {
            Some(a) if !a.contains(&key) => continue,
            None if denylist.contains(&key) => continue,
            _ => {}
        }
        let slice = if value.len() > cfg.header_scan_cap {
            let boundary = value.floor_char_boundary(cfg.header_scan_cap);
            &value[..boundary]
        } else {
            value.as_str()
        };
        let decoded = url_decode_recursive(slice);
        let m = patterns.matches(&decoded);
        if let Some(idx) = m.iter().next() {
            return Some((format!("header.{key}"), idx));
        }
    }
    None
}

fn walk_json(v: &Value, path: &mut String, set: &RegexSet) -> Option<(String, usize)> {
    match v {
        Value::String(s) => {
            let decoded = url_decode_recursive(s);
            let m = set.matches(&decoded);
            m.iter().next().map(|idx| (path.clone(), idx))
        }
        Value::Object(map) => {
            for (k, child) in map {
                let restore = path.len();
                path.push('.');
                path.push_str(k);
                if let Some(hit) = walk_json(child, path, set) {
                    return Some(hit);
                }
                path.truncate(restore);
            }
            None
        }
        Value::Array(arr) => {
            for (i, child) in arr.iter().enumerate() {
                let restore = path.len();
                let _ = write!(path, "[{i}]");
                if let Some(hit) = walk_json(child, path, set) {
                    return Some(hit);
                }
                path.truncate(restore);
            }
            None
        }
        _ => None,
    }
}

/// Scan query parameters for `SQLi`, returning (`param_name`, `pattern_index`) on first hit.
pub fn scan_query_params(query: &str, patterns: &RegexSet) -> Option<(String, usize)> {
    for (k, v) in url::form_urlencoded::parse(query.as_bytes()) {
        let decoded = url_decode_recursive(&v);
        let m = patterns.matches(&decoded);
        if let Some(idx) = m.iter().next() {
            return Some((format!("query.{k}"), idx));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checks::sql_injection_patterns::SQLI_SET;

    const TEST_JSON_CAP: usize = 256 * 1024;

    #[test]
    fn json_nested_hit() {
        let body = br#"{"user":{"name":"' OR '1'='1'"}}"#;
        let result = scan_json_body(body, &SQLI_SET, TEST_JSON_CAP);
        assert!(result.is_some());
        let (path, _) = result.unwrap();
        assert_eq!(path, "body.user.name");
    }

    #[test]
    fn json_array_hit() {
        let body = br#"{"items":["safe","1 UNION SELECT 1,2"]}"#;
        let result = scan_json_body(body, &SQLI_SET, TEST_JSON_CAP);
        assert!(result.is_some());
        let (path, _) = result.unwrap();
        assert_eq!(path, "body.items[1]");
    }

    #[test]
    fn json_clean() {
        let body = br#"{"user":"alice","age":25}"#;
        let result = scan_json_body(body, &SQLI_SET, TEST_JSON_CAP);
        assert!(result.is_none());
    }

    #[test]
    fn json_malformed_returns_none() {
        let body = b"not valid json";
        let result = scan_json_body(body, &SQLI_SET, TEST_JSON_CAP);
        assert!(result.is_none());
    }

    #[test]
    fn json_oversize_returns_none() {
        let body = vec![b'{'; TEST_JSON_CAP + 1];
        let result = scan_json_body(&body, &SQLI_SET, TEST_JSON_CAP);
        assert!(result.is_none());
    }

    #[test]
    fn query_param_hit() {
        let query = "id=1+UNION+SELECT+1,2";
        let result = scan_query_params(query, &SQLI_SET);
        assert!(result.is_some());
        let (param, _) = result.unwrap();
        assert_eq!(param, "query.id");
    }

    #[test]
    fn query_param_clean() {
        let query = "name=alice&page=2";
        let result = scan_query_params(query, &SQLI_SET);
        assert!(result.is_none());
    }

    #[test]
    fn query_single_param() {
        let query = "q=SLEEP(5)";
        let result = scan_query_params(query, &SQLI_SET);
        assert!(result.is_some());
        let (param, _) = result.unwrap();
        assert_eq!(param, "query.q");
    }

    #[test]
    fn query_double_encoded_evasion() {
        let query = "id=1+AND+%2553%254C%2545%2545%2550%2528%2535%2529";
        let result = scan_query_params(query, &SQLI_SET);
        assert!(result.is_some(), "Should detect double-encoded SLEEP");
    }

    #[test]
    fn json_url_encoded_value() {
        let body = br#"{"cmd": "1 AND %53%4C%45%45%50%28%35%29"}"#;
        let result = scan_json_body(body, &SQLI_SET, TEST_JSON_CAP);
        assert!(result.is_some(), "Should detect URL-encoded SLEEP in JSON");
    }

    #[test]
    fn header_scan_with_denylist() {
        let cfg = SqliScanConfig::default();
        let mut headers = HashMap::new();
        headers.insert("user-agent".to_string(), "'; DROP TABLE users--".to_string());
        let result = scan_headers(&headers, &cfg, &SQLI_SET);
        assert!(result.is_some());
        let (loc, _) = result.unwrap();
        assert_eq!(loc, "header.user-agent");
    }

    #[test]
    fn header_scan_skips_denylist() {
        let cfg = SqliScanConfig::default();
        let mut headers = HashMap::new();
        headers.insert("content-type".to_string(), "'; DROP TABLE users--".to_string());
        let result = scan_headers(&headers, &cfg, &SQLI_SET);
        assert!(result.is_none(), "Should skip denylisted header");
    }

    #[test]
    fn header_scan_allowlist_overrides() {
        let cfg = SqliScanConfig {
            header_allowlist: vec!["x-custom".to_string()],
            ..Default::default()
        };
        let mut headers = HashMap::new();
        headers.insert("user-agent".to_string(), "'; DROP TABLE users--".to_string());
        headers.insert("x-custom".to_string(), "1 UNION SELECT 1".to_string());
        let result = scan_headers(&headers, &cfg, &SQLI_SET);
        assert!(result.is_some());
        let (loc, _) = result.unwrap();
        assert_eq!(loc, "header.x-custom");
    }

    #[test]
    fn header_scan_cap_truncates() {
        let cfg = SqliScanConfig {
            header_scan_cap: 10,
            ..Default::default()
        };
        let mut headers = HashMap::new();
        headers.insert("user-agent".to_string(), "safe_prefix_UNION SELECT 1,2".to_string());
        let result = scan_headers(&headers, &cfg, &SQLI_SET);
        assert!(result.is_none(), "Should not detect SQLi beyond cap");
    }
}
