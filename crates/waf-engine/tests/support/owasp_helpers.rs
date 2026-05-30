//! Shared helpers for OWASPCheck tests. Imported via
//! `#[path = "support/owasp_helpers.rs"] mod helpers;` in each test file.

#![allow(dead_code)]

use bytes::Bytes;
use std::collections::HashMap;
use std::sync::Arc;
use waf_common::{DefenseConfig, HostConfig, RequestCtx};

pub fn make_ctx() -> RequestCtx {
    let host_config = Arc::new(HostConfig {
        code: "test".into(),
        host: "example.com".into(),
        defense_config: DefenseConfig {
            owasp_set: true,
            ..DefenseConfig::default()
        },
        ..HostConfig::default()
    });
    RequestCtx {
        req_id: "t".into(),
        client_ip: "1.2.3.4".parse().unwrap(),
        client_port: 0,
        method: "GET".into(),
        host: "example.com".into(),
        port: 80,
        path: "/".into(),
        query: String::new(),
        headers: HashMap::new(),
        body_preview: Bytes::new(),
        content_length: 0,
        is_tls: false,
        host_config,
        geo: None,
        tier: waf_common::tier::Tier::CatchAll,
        tier_policy: waf_common::RequestCtx::default_tier_policy(),
        cookies: HashMap::new(),
        device_fp: None,
        tx_velocity_token: None,
    }
}

pub fn make_ctx_owasp_disabled() -> RequestCtx {
    let host_config = Arc::new(HostConfig {
        code: "t".into(),
        host: "h".into(),
        defense_config: DefenseConfig {
            owasp_set: false,
            ..DefenseConfig::default()
        },
        ..HostConfig::default()
    });
    RequestCtx {
        req_id: "t".into(),
        client_ip: "1.2.3.4".parse().unwrap(),
        client_port: 0,
        method: "GET".into(),
        host: "h".into(),
        port: 80,
        path: "/".into(),
        query: String::new(),
        headers: HashMap::new(),
        body_preview: Bytes::new(),
        content_length: 0,
        is_tls: false,
        host_config,
        geo: None,
        tier: waf_common::tier::Tier::CatchAll,
        tier_policy: waf_common::RequestCtx::default_tier_policy(),
        cookies: HashMap::new(),
        device_fp: None,
        tx_velocity_token: None,
    }
}
