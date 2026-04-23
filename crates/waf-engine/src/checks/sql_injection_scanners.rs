//! SQL injection scanner helpers.
//!
//! Advanced scanning for JSON bodies and query parameters with path attribution.

use regex::RegexSet;
use serde_json::Value;
use std::fmt::Write;

use super::url_decode_recursive;

const JSON_PARSE_CAP: usize = 256 * 1024;

/// Scan JSON body for SQLi patterns, returning (json_path, pattern_index) on first hit.
pub fn scan_json_body(body: &[u8], patterns: &RegexSet) -> Option<(String, usize)> {
    if body.len() > JSON_PARSE_CAP {
        return None;
    }
    let v: Value = serde_json::from_slice(body).ok()?;
    walk_json(&v, &mut String::from("body"), patterns)
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

/// Scan query parameters for SQLi, returning (param_name, pattern_index) on first hit.
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

    #[test]
    fn json_nested_hit() {
        let body = br#"{"user":{"name":"' OR '1'='1'"}}"#;
        let result = scan_json_body(body, &SQLI_SET);
        assert!(result.is_some());
        let (path, _) = result.unwrap();
        assert_eq!(path, "body.user.name");
    }

    #[test]
    fn json_array_hit() {
        let body = br#"{"items":["safe","1 UNION SELECT 1,2"]}"#;
        let result = scan_json_body(body, &SQLI_SET);
        assert!(result.is_some());
        let (path, _) = result.unwrap();
        assert_eq!(path, "body.items[1]");
    }

    #[test]
    fn json_clean() {
        let body = br#"{"user":"alice","age":25}"#;
        let result = scan_json_body(body, &SQLI_SET);
        assert!(result.is_none());
    }

    #[test]
    fn json_malformed_returns_none() {
        let body = b"not valid json";
        let result = scan_json_body(body, &SQLI_SET);
        assert!(result.is_none());
    }

    #[test]
    fn json_oversize_returns_none() {
        let body = vec![b'{'; JSON_PARSE_CAP + 1];
        let result = scan_json_body(&body, &SQLI_SET);
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
        // Double-encoded: %2553%254C%2545%2545%2550%2528%25335%2529
        // → first decode: %53%4C%45%45%50%28%35%29 → second: SLEEP(5)
        let query = "id=1+AND+%2553%254C%2545%2545%2550%2528%2535%2529";
        let result = scan_query_params(query, &SQLI_SET);
        assert!(result.is_some(), "Should detect double-encoded SLEEP");
    }

    #[test]
    fn json_url_encoded_value() {
        // Single-encoded SLEEP(5) in JSON: %53%4C%45%45%50%28%35%29
        let body = br#"{"cmd": "1 AND %53%4C%45%45%50%28%35%29"}"#;
        let result = scan_json_body(body, &SQLI_SET);
        assert!(result.is_some(), "Should detect URL-encoded SLEEP in JSON");
    }
}
