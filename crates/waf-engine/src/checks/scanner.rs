use std::sync::LazyLock;

use regex::RegexSet;
use waf_common::{DetectionResult, Phase, RequestCtx};

use super::Check;

static SCANNER_UA_DESCS: &[&str] = &[
    "sqlmap (SQL injection scanner)",
    "Nmap (port scanner)",
    "Nikto (web scanner)",
    "Burp Suite (proxy/scanner)",
    "Acunetix (web scanner)",
    "Nessus (vulnerability scanner)",
    "Metasploit (exploitation framework)",
    "w3af (web application attack framework)",
    "DirBuster / dirbuster (directory brute-forcer)",
    "AppScan (IBM web scanner)",
    "WebInspect (HP web scanner)",
    "Paros Proxy",
    "OWASP ZAP",
    "gobuster (directory/DNS brute-forcer)",
    "ffuf (fast web fuzzer)",
    "wfuzz (web fuzzer)",
    "Nuclei (vulnerability scanner)",
    "dirb (web content scanner)",
    "Havij (automated SQL injection)",
    "Masscan (port scanner)",
    "zgrab (banner grabber)",
    "Netsparker (web scanner)",
    "Arachni (web scanner)",
    "OpenVAS (vulnerability scanner)",
    "Vega (web security scanner)",
    "Skipfish",
    "Wapiti (web app vulnerability scanner)",
    "Hydra (login brute-forcer)",
    "Medusa (login brute-forcer)",
    "headless Chrome / Puppeteer / Selenium",
    "PhantomJS",
    "Scrapy (web scraper)",
];

// SAFETY: All patterns are compile-time string literals. If any pattern fails
// to compile it is a code bug that must be caught in development, not at runtime.
static SCANNER_UA_SET: LazyLock<RegexSet> = LazyLock::new(|| {
    match RegexSet::new([
        r"(?i)\bsqlmap\b",
        r"(?i)\bnmap\b",
        r"(?i)\bnikto\b",
        r"(?i)\bburp\b|\bburpsuite\b",
        r"(?i)\bacunetix\b",
        r"(?i)\bnessus\b",
        r"(?i)\bmetasploit\b",
        r"(?i)\bw3af\b",
        r"(?i)\bdirbuster\b",
        r"(?i)\bappscan\b",
        r"(?i)\bwebinspect\b",
        r"(?i)\bparos\b",
        r"(?i)\b(OWASP[\s_-]?)?ZAP\b",
        r"(?i)\bgobuster\b",
        r"(?i)\bffuf\b",
        r"(?i)\bwfuzz\b",
        r"(?i)\bnuclei\b",
        r"(?i)\bdirb\b",
        r"(?i)\bhavij\b",
        r"(?i)\bmasscan\b",
        r"(?i)\bzgrab\b",
        r"(?i)\bnetsparker\b",
        r"(?i)\barachni\b",
        r"(?i)\bopenvas\b",
        r"(?i)\bvega\b",
        r"(?i)\bskipfish\b",
        r"(?i)\bwapiti\b",
        r"(?i)\bhydra\b",
        r"(?i)\bmedusa\b",
        r"(?i)(headlesschrome|headless chrome|puppeteer|selenium|webdriver)",
        r"(?i)\bphantomjs\b",
        r"(?i)\bscrapy\b",
    ]) {
        Ok(set) => set,
        Err(e) => {
            tracing::error!("BUG: scanner UA regex set failed to compile: {e}");
            RegexSet::empty()
        }
    }
});

/// Description text aligned with `SCRIPTED_CLIENT_UA_SET` patterns by index.
static SCRIPTED_CLIENT_UA_DESCS: &[&str] = &[
    "curl (non-browser HTTP client)",
    "Python Requests library",
    "Go HTTP client",
    "libwww-perl (Perl HTTP lib)",
    "wget (non-browser HTTP client)",
    "Apache HttpClient (Java)",
    "Node.js HTTP client",
];

/// Generic scripted-HTTP-client UAs. These are gated behind
/// `DefenseConfig.block_scripted_clients` because they are extremely
/// common in legitimate traffic (health checks, internal services, CI,
/// automation). Operators who run a strictly browser-only public site
/// can opt in to block them.
static SCRIPTED_CLIENT_UA_SET: LazyLock<RegexSet> = LazyLock::new(|| {
    match RegexSet::new([
        r"(?i)^curl/",
        r"(?i)^python-requests/",
        r"(?i)^go-http-client/",
        r"(?i)^libwww-perl/",
        r"(?i)^wget/",
        r"(?i)^apache-httpclient/",
        r"(?i)^node-fetch/|^axios/|^got\s|^undici",
    ]) {
        Ok(set) => set,
        Err(e) => {
            tracing::error!("BUG: scripted-client UA regex set failed to compile: {e}");
            RegexSet::empty()
        }
    }
});

/// Security scanner / automated tool detection checker (User-Agent based).
pub struct ScannerCheck;

impl ScannerCheck {
    pub const fn new() -> Self {
        Self
    }
}

impl Default for ScannerCheck {
    fn default() -> Self {
        Self::new()
    }
}

impl Check for ScannerCheck {
    fn check(&self, ctx: &RequestCtx) -> Option<DetectionResult> {
        if !ctx.host_config.defense_config.scan {
            return None;
        }

        let ua = ctx.headers.get("user-agent").map_or("", String::as_str);

        // Always check the real attack-tool list (sqlmap / nikto / nuclei /
        // headless browsers / etc.). These are unambiguously malicious so
        // they're never gated by config.
        let matches = SCANNER_UA_SET.matches(ua);
        if matches.matched_any() {
            let idx = matches.iter().next().unwrap_or(0);
            let desc = SCANNER_UA_DESCS.get(idx).copied().unwrap_or("scanner");
            return Some(DetectionResult {
                rule_id: Some(format!("SCAN-{:03}", idx + 1)),
                rule_name: "Scanner".to_string(),
                phase: Phase::Scanner,
                detail: format!("{desc} User-Agent detected"),
            });
        }

        // Optionally check generic scripted-client UAs (curl, python-requests,
        // go-http-client, …). Off by default — see DefenseConfig docs.
        if ctx.host_config.defense_config.block_scripted_clients {
            let matches = SCRIPTED_CLIENT_UA_SET.matches(ua);
            if matches.matched_any() {
                let idx = matches.iter().next().unwrap_or(0);
                let desc = SCRIPTED_CLIENT_UA_DESCS.get(idx).copied().unwrap_or("scripted-client");
                return Some(DetectionResult {
                    rule_id: Some(format!("SCRIPT-{:03}", idx + 1)),
                    rule_name: "Scripted Client".to_string(),
                    phase: Phase::Scanner,
                    detail: format!("{desc} User-Agent detected (block_scripted_clients=true)"),
                });
            }
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use std::collections::HashMap;
    use std::net::IpAddr;
    use std::sync::Arc;
    use waf_common::{DefenseConfig, HostConfig};

    fn make_ctx_with(ua: &str, block_scripted: bool) -> RequestCtx {
        let mut headers = HashMap::new();
        if !ua.is_empty() {
            headers.insert("user-agent".to_string(), ua.to_string());
        }
        RequestCtx {
            req_id: "test".to_string(),
            client_ip: "127.0.0.1".parse::<IpAddr>().unwrap(),
            client_port: 0,
            method: "GET".to_string(),
            host: "example.com".to_string(),
            port: 80,
            path: "/".to_string(),
            query: String::new(),
            headers,
            body_preview: Bytes::new(),
            content_length: 0,
            is_tls: false,
            host_config: Arc::new(HostConfig {
                defense_config: DefenseConfig {
                    scan: true,
                    block_scripted_clients: block_scripted,
                    ..DefenseConfig::default()
                },
                ..HostConfig::default()
            }),
            geo: None,
            tier: waf_common::tier::Tier::CatchAll,
            tier_policy: waf_common::RequestCtx::default_tier_policy(),
            cookies: std::collections::HashMap::new(),
        }
    }

    fn make_ctx(ua: &str) -> RequestCtx {
        // Default: block_scripted_clients=false (production default).
        make_ctx_with(ua, false)
    }

    #[test]
    fn detects_sqlmap() {
        let checker = ScannerCheck::new();
        let ctx = make_ctx("sqlmap/1.7.6#stable (https://sqlmap.org)");
        assert!(checker.check(&ctx).is_some());
    }

    #[test]
    fn detects_nikto() {
        let checker = ScannerCheck::new();
        let ctx = make_ctx("Nikto/2.1.5");
        assert!(checker.check(&ctx).is_some());
    }

    #[test]
    fn allows_regular_browser() {
        let checker = ScannerCheck::new();
        let ctx = make_ctx("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0");
        assert!(checker.check(&ctx).is_none());
    }

    #[test]
    fn allows_curl_by_default() {
        // curl is used for health checks, internal services, CI, etc. — never
        // block when block_scripted_clients is the default (false).
        let checker = ScannerCheck::new();
        let ctx = make_ctx("curl/8.5.0");
        assert!(checker.check(&ctx).is_none());
    }

    #[test]
    fn allows_python_requests_by_default() {
        let checker = ScannerCheck::new();
        let ctx = make_ctx("python-requests/2.28.0");
        assert!(checker.check(&ctx).is_none());
    }

    #[test]
    fn allows_go_http_client_by_default() {
        let checker = ScannerCheck::new();
        let ctx = make_ctx("Go-http-client/2.0");
        assert!(checker.check(&ctx).is_none());
    }

    #[test]
    fn blocks_curl_when_strict_mode_enabled() {
        // Operator opts in via DefenseConfig.block_scripted_clients=true
        // (e.g. browser-only public site). curl is then flagged.
        let checker = ScannerCheck::new();
        let ctx = make_ctx_with("curl/8.5.0", true);
        let result = checker.check(&ctx).expect("strict mode should block curl");
        assert_eq!(result.rule_name, "Scripted Client");
        assert!(result.detail.contains("curl"));
    }

    #[test]
    fn blocks_python_requests_when_strict_mode_enabled() {
        let checker = ScannerCheck::new();
        let ctx = make_ctx_with("python-requests/2.28.0", true);
        let result = checker.check(&ctx).expect("strict mode should block python-requests");
        assert_eq!(result.rule_name, "Scripted Client");
    }

    #[test]
    fn real_attack_tools_blocked_regardless_of_strict_mode() {
        // sqlmap is always blocked, never gated on block_scripted_clients.
        let checker = ScannerCheck::new();
        for strict in [false, true] {
            let ctx = make_ctx_with("sqlmap/1.7.6", strict);
            let result = checker.check(&ctx).unwrap_or_else(|| {
                panic!("sqlmap UA should always be blocked (strict={strict})");
            });
            assert_eq!(result.rule_name, "Scanner");
        }
    }
}
