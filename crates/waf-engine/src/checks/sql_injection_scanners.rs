//! SQL injection scanner helpers.
//!
//! Advanced scanning for JSON bodies and query parameters with path attribution.

use regex::RegexSet;
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::fmt::Write;
use waf_common::config::SqliScanConfig;

use super::url_decode_recursive;

/// Hard depth cap for `walk_json`. Defence-in-depth: serde_json's default
/// parser limit is 128 today, so any body deeper than that fails at parse
/// time before we walk; this guard ensures a future relaxation of that
/// limit cannot let an attacker drive the walker arbitrarily deep.
const MAX_JSON_DEPTH: usize = 128;

/// Scan JSON body for `SQLi` patterns, returning (`json_path`, `pattern_index`) on first hit.
pub fn scan_json_body(body: &[u8], patterns: &RegexSet, json_parse_cap: usize) -> Option<(String, usize)> {
    if body.len() > json_parse_cap {
        return None;
    }
    let v: Value = serde_json::from_slice(body).ok()?;
    walk_json(&v, "body", patterns)
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

/// Iterative DFS over a parsed `serde_json::Value` looking for `SQLi` hits.
///
/// Uses an explicit `Vec` stack instead of recursion so a deeply-nested body
/// cannot blow the call stack even if the body-abuse pre-check is disabled,
/// and respects [`MAX_JSON_DEPTH`] as an explicit defence-in-depth ceiling.
/// Children are pushed in reverse order so the pop order matches the natural
/// left-to-right / sorted-key traversal of the previous recursive form.
fn walk_json(root: &Value, root_path: &str, set: &RegexSet) -> Option<(String, usize)> {
    let mut stack: Vec<(&Value, String, usize)> = Vec::new();
    stack.push((root, root_path.to_owned(), 0));
    while let Some((node, path, depth)) = stack.pop() {
        if depth > MAX_JSON_DEPTH {
            return None;
        }
        match node {
            Value::String(s) => {
                let decoded = url_decode_recursive(s);
                if let Some(idx) = set.matches(&decoded).iter().next() {
                    return Some((path, idx));
                }
            }
            Value::Object(map) => {
                for (k, child) in map.iter().rev() {
                    let mut child_path = path.clone();
                    child_path.push('.');
                    child_path.push_str(k);
                    stack.push((child, child_path, depth + 1));
                }
            }
            Value::Array(arr) => {
                for (i, child) in arr.iter().enumerate().rev() {
                    let mut child_path = path.clone();
                    let _ = write!(child_path, "[{i}]");
                    stack.push((child, child_path, depth + 1));
                }
            }
            _ => {}
        }
    }
    None
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

/// Scan query parameters with libinjection fingerprinting.
///
/// Catches minimal error-injection probes like `'(` that contain no SQL keywords
/// and therefore evade keyword/regex-based patterns. Returns the parameter name
/// on the first hit.
pub fn scan_query_params_libinjection(query: &str) -> Option<String> {
    for (k, v) in url::form_urlencoded::parse(query.as_bytes()) {
        let decoded = url_decode_recursive(&v);
        if libinjectionrs::detect_sqli(decoded.as_bytes()).is_injection() {
            return Some(format!("query.{k}"));
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
    fn json_deep_nesting_iterative_walker_finds_hit() {
        // 100 layers of `{"a": ...}` wrapping a SQLi-bearing leaf string.
        // The recursive walker consumed one stack frame per layer; the
        // iterative replacement walks via a heap-allocated Vec instead.
        // This case is well under serde_json's default 128-deep parse limit.
        let mut body = String::new();
        for _ in 0..100 {
            body.push_str(r#"{"a":"#);
        }
        body.push_str(r#""' OR '1'='1'""#);
        for _ in 0..100 {
            body.push('}');
        }

        let result = scan_json_body(body.as_bytes(), &SQLI_SET, TEST_JSON_CAP);
        assert!(result.is_some(), "deep-nested SQLi must surface via iterative walker");
        let (path, _) = result.unwrap();
        assert!(path.starts_with("body.a.a.a"), "path={path}");
        assert!(path.ends_with(".a"), "path={path}");
    }

    #[test]
    fn json_beyond_serde_default_depth_returns_none() {
        // 200 layers exceeds serde_json's default RECURSION_LIMIT (128); the
        // parse fails and `scan_json_body` short-circuits to None before the
        // walker runs. Documents the outer guard that complements the
        // walker's own MAX_JSON_DEPTH ceiling.
        let mut body = String::new();
        for _ in 0..200 {
            body.push_str(r#"{"a":"#);
        }
        body.push_str(r#""hit""#);
        for _ in 0..200 {
            body.push('}');
        }
        let result = scan_json_body(body.as_bytes(), &SQLI_SET, TEST_JSON_CAP);
        assert!(result.is_none(), "serde_json parse must refuse 200-deep body");
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
