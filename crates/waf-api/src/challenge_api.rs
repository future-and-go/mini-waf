//! Challenge engine config API — GET/PUT `/api/challenge/config`,
//! GET `/api/challenge/stats`, POST `/api/challenge/preview`.
//!
//! Config source: `configs/challenge.yaml`. The YAML root key is `challenge:`;
//! this layer strips/adds that wrapper so the frontend receives a flat
//! `ChallengeConfig` object.
//!
//! PUT routes require an admin JWT and are body-limited to 256 KiB by the
//! route layer in `server.rs`.

use std::path::Path;
use std::sync::Arc;

use axum::{
    Json,
    extract::State,
    http::{HeaderMap, header},
    response::IntoResponse,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::auth::{Claims, validate_admin_token};
use crate::config_paths::resolve_under_root;
use crate::error::{ApiError, ApiResult};
use crate::state::AppState;

/// Max body size for challenge PUT/preview requests (256 KiB).
pub const MAX_BODY_BYTES: usize = 256 * 1024;

// ─── Typed request models ────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChallengeBranding {
    pub title: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NonceStoreCfg {
    pub capacity: i64,
    pub gc_interval_secs: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChallengeConfig {
    pub enabled: bool,
    pub challenge_type: String,
    pub ttl_secs: i64,
    pub cookie_name: String,
    pub cookie_max_age: i64,
    pub same_site: String,
    pub http_only: bool,
    pub branding: ChallengeBranding,
    pub nonce_store: NonceStoreCfg,
}

#[derive(Debug, Deserialize)]
pub struct PreviewRequest {
    #[serde(default)]
    pub branding: Option<ChallengeBranding>,
}

// ─── Auth gate ───────────────────────────────────────────────────────────────

fn require_admin(headers: &HeaderMap, jwt_secret: &str) -> Result<Claims, ApiError> {
    let token = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or_else(|| ApiError::Unauthorized("missing bearer token".into()))?;
    validate_admin_token(token, jwt_secret).map_err(|e| ApiError::Unauthorized(e.to_string()))
}

// ─── Filesystem helpers ──────────────────────────────────────────────────────

async fn read_yaml_value(path: &Path) -> Value {
    let Ok(raw) = tokio::fs::read_to_string(path).await else {
        return Value::Null;
    };
    serde_yaml::from_str::<Value>(&raw).unwrap_or_else(|e| {
        tracing::warn!(path = %path.display(), error = %e, "challenge: YAML parse failed; falling back to defaults");
        Value::Null
    })
}

async fn write_yaml_value(path: &Path, value: &Value) -> Result<(), ApiError> {
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .map_err(|e| ApiError::Internal(anyhow::anyhow!("mkdir: {e}")))?;
    }
    let s = serde_yaml::to_string(value).map_err(|e| ApiError::Internal(anyhow::anyhow!("serialize: {e}")))?;
    let tmp = path.with_extension("yaml.tmp");
    tokio::fs::write(&tmp, s.as_bytes())
        .await
        .map_err(|e| ApiError::Internal(anyhow::anyhow!("write: {e}")))?;
    tokio::fs::rename(&tmp, path)
        .await
        .map_err(|e| ApiError::Internal(anyhow::anyhow!("rename: {e}")))?;
    Ok(())
}

// ─── Mapping helpers ─────────────────────────────────────────────────────────

fn default_branding() -> ChallengeBranding {
    ChallengeBranding {
        title: "Security Check".to_owned(),
        message: "Please wait while we verify your browser...".to_owned(),
    }
}

fn default_challenge_config() -> ChallengeConfig {
    ChallengeConfig {
        enabled: true,
        challenge_type: "js_challenge".to_owned(),
        ttl_secs: 300,
        cookie_name: "__waf_cc".to_owned(),
        cookie_max_age: 300,
        same_site: "Strict".to_owned(),
        http_only: false,
        branding: default_branding(),
        nonce_store: NonceStoreCfg {
            capacity: 100_000,
            gc_interval_secs: 60,
        },
    }
}

/// YAML `challenge.*` → flat FE `ChallengeConfig`.
fn yaml_to_fe(root: &Value) -> ChallengeConfig {
    let mut cfg = default_challenge_config();
    let Some(c) = root.get("challenge") else {
        return cfg;
    };
    if let Some(v) = c.get("enabled").and_then(Value::as_bool) {
        cfg.enabled = v;
    }
    if let Some(v) = c.get("type").and_then(Value::as_str) {
        v.clone_into(&mut cfg.challenge_type);
    }
    if let Some(token) = c.get("token") {
        if let Some(v) = token.get("ttl_secs").and_then(Value::as_i64) {
            cfg.ttl_secs = v;
        }
        if let Some(v) = token.get("cookie_name").and_then(Value::as_str) {
            v.clone_into(&mut cfg.cookie_name);
        }
        if let Some(v) = token.get("cookie_max_age").and_then(Value::as_i64) {
            cfg.cookie_max_age = v;
        }
        if let Some(v) = token.get("same_site").and_then(Value::as_str) {
            v.clone_into(&mut cfg.same_site);
        }
        if let Some(v) = token.get("http_only").and_then(Value::as_bool) {
            cfg.http_only = v;
        }
    }
    if let Some(b) = c.get("branding") {
        if let Some(v) = b.get("title").and_then(Value::as_str) {
            v.clone_into(&mut cfg.branding.title);
        }
        if let Some(v) = b.get("message").and_then(Value::as_str) {
            v.clone_into(&mut cfg.branding.message);
        }
    }
    if let Some(n) = c.get("nonce_store") {
        if let Some(v) = n.get("capacity").and_then(Value::as_i64) {
            cfg.nonce_store.capacity = v;
        }
        if let Some(v) = n.get("gc_interval_secs").and_then(Value::as_i64) {
            cfg.nonce_store.gc_interval_secs = v;
        }
    }
    cfg
}

/// Flat FE `ChallengeConfig` → YAML `challenge.*` wrapper.
fn fe_to_yaml(body: &ChallengeConfig) -> Value {
    json!({
        "challenge": {
            "enabled": body.enabled,
            "type": body.challenge_type,
            "token": {
                "ttl_secs": body.ttl_secs,
                "cookie_name": body.cookie_name,
                "cookie_max_age": body.cookie_max_age,
                "same_site": body.same_site,
                "http_only": body.http_only,
            },
            "branding": {
                "title": body.branding.title,
                "message": body.branding.message,
            },
            "nonce_store": {
                "capacity": body.nonce_store.capacity,
                "gc_interval_secs": body.nonce_store.gc_interval_secs,
            },
        }
    })
}

// ─── HTML escape (no new dependency) ─────────────────────────────────────────

/// Hand-rolled 5-char HTML escape: `&`, `<`, `>`, `"`, `'`.
/// Stored-XSS guard for `branding.title` and `branding.message` before they
/// land in the preview iframe template.
fn html_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#x27;"),
            _ => out.push(c),
        }
    }
    out
}

// ─── Handlers ────────────────────────────────────────────────────────────────

pub async fn get_challenge_config(State(state): State<Arc<AppState>>) -> ApiResult<Json<Value>> {
    let path = resolve_under_root(&state, "configs/challenge.yaml");
    let raw = read_yaml_value(&path).await;
    let cfg = if raw.is_null() {
        default_challenge_config()
    } else {
        yaml_to_fe(&raw)
    };
    Ok(Json(json!({ "success": true, "data": cfg })))
}

pub async fn put_challenge_config(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<ChallengeConfig>,
) -> ApiResult<Json<Value>> {
    require_admin(&headers, &state.jwt_secret)?;
    let path = resolve_under_root(&state, "configs/challenge.yaml");
    let yaml_val = fe_to_yaml(&body);
    write_yaml_value(&path, &yaml_val).await?;
    Ok(Json(json!({ "success": true, "data": body })))
}

pub async fn get_challenge_stats(_: State<Arc<AppState>>) -> ApiResult<Json<Value>> {
    // Hit-counters live in `waf_engine::challenge` and are not yet plumbed
    // through `AppState`. Returning zeros keeps the FE shape stable until
    // the wiring lands.
    Ok(Json(json!({
        "success": true,
        "data": { "issued": 0, "passed": 0, "failed": 0, "replays": 0 }
    })))
}

/// Returns raw HTML (the FE calls `resp.text()` directly). Title and message
/// are HTML-escaped before injection to prevent stored-XSS via crafted branding.
pub async fn challenge_preview(
    State(state): State<Arc<AppState>>,
    Json(body): Json<PreviewRequest>,
) -> impl IntoResponse {
    let path = resolve_under_root(&state, "configs/challenge.yaml");
    let raw = read_yaml_value(&path).await;
    let on_disk = yaml_to_fe(&raw);
    let (title_raw, msg_raw) = body.branding.as_ref().map_or_else(
        || (on_disk.branding.title.clone(), on_disk.branding.message.clone()),
        |b| (b.title.clone(), b.message.clone()),
    );
    let title = html_escape(&title_raw);
    let message = html_escape(&msg_raw);

    let html = format!(
        r#"<!DOCTYPE html><html><head><meta charset="utf-8"><title>{title}</title>
<style>body{{font-family:sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;background:#f5f5f5}}
.box{{background:#fff;padding:40px;border-radius:8px;box-shadow:0 2px 8px rgba(0,0,0,.15);text-align:center;max-width:400px}}
h1{{color:#1890ff;font-size:1.5rem}}p{{color:#555}}</style></head>
<body><div class="box"><h1>&#x1F512; {title}</h1><p>{message}</p></div></body></html>"#
    );
    ([(header::CONTENT_TYPE, "text/html; charset=utf-8")], html)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn default_config_has_known_shape() {
        let c = default_challenge_config();
        assert!(c.enabled);
        assert_eq!(c.challenge_type, "js_challenge");
        assert_eq!(c.cookie_name, "__waf_cc");
        assert_eq!(c.nonce_store.capacity, 100_000);
    }

    #[test]
    fn html_escape_handles_all_five_chars() {
        let raw = r#"<script>alert("\x'inj")</script>&"#;
        let out = html_escape(raw);
        assert!(!out.contains('<'));
        assert!(!out.contains('>'));
        assert!(!out.contains('"'));
        assert!(!out.contains('\''));
        assert!(out.contains("&lt;"));
        assert!(out.contains("&gt;"));
        assert!(out.contains("&amp;"));
        assert!(out.contains("&quot;"));
        assert!(out.contains("&#x27;"));
    }

    #[test]
    fn html_escape_keeps_unicode() {
        let raw = "🔒 Bảo mật";
        let out = html_escape(raw);
        assert!(out.contains("🔒"));
        assert!(out.contains("Bảo mật"));
    }

    #[test]
    fn yaml_to_fe_uses_defaults_when_missing_keys() {
        let cfg = yaml_to_fe(&json!({ "challenge": {} }));
        assert_eq!(cfg.cookie_name, "__waf_cc");
        assert_eq!(cfg.ttl_secs, 300);
    }

    #[test]
    fn fe_to_yaml_round_trips_via_yaml_to_fe() {
        let original = default_challenge_config();
        let yaml = fe_to_yaml(&original);
        let back = yaml_to_fe(&yaml);
        assert_eq!(back.enabled, original.enabled);
        assert_eq!(back.cookie_name, original.cookie_name);
        assert_eq!(back.branding.title, original.branding.title);
        assert_eq!(back.nonce_store.capacity, original.nonce_store.capacity);
    }
}
