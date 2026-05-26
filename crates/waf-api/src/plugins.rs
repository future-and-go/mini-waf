//! WASM Plugin API handlers

use std::sync::Arc;

use axum::extract::Multipart;
use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde_json::json;
use tracing::info;
use uuid::Uuid;
use waf_storage::models::CreateWasmPlugin;

use crate::state::AppState;

/// Maximum byte size accepted for the raw `.wasm` field on upload.
///
/// 16 MiB comfortably covers real WAF plugins (observed in-house plugins
/// run 50 KiB – 4 MiB after wasm-opt). Larger uploads are rejected so an
/// authenticated admin (or a compromised admin credential) cannot bloat the
/// `wasm_plugins.wasm_binary` bytea column or OOM the API process.
pub const MAX_WASM_BYTES: usize = 16 * 1024 * 1024;

/// Maximum allowed plugin name length and character set.
const MAX_NAME_LEN: usize = 64;

/// Maximum allowed length for free-form text fields (version / description /
/// author). 256 bytes is plenty for SemVer + a short description.
const MAX_TEXT_LEN: usize = 256;

/// Total per-request body limit applied to `POST /api/plugins`. The 64 KiB
/// headroom over [`MAX_WASM_BYTES`] absorbs the multipart envelope plus the
/// bounded text fields.
pub const MAX_TOTAL_BODY: usize = MAX_WASM_BYTES + 64 * 1024;

/// Validate a plugin name: non-empty, ≤ [`MAX_NAME_LEN`], only
/// `[A-Za-z0-9_-]`. Rejects path-traversal-style names (`..`, `/`),
/// whitespace, and Unicode oddities up front.
fn validate_plugin_name(name: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err("plugin name is required".to_string());
    }
    if name.len() > MAX_NAME_LEN {
        return Err(format!("plugin name exceeds {MAX_NAME_LEN} chars (got {})", name.len()));
    }
    if !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-') {
        return Err("plugin name must contain only [A-Za-z0-9_-]".to_string());
    }
    Ok(())
}

/// Cap a free-form text field at [`MAX_TEXT_LEN`].
fn validate_text_field(label: &str, value: &str) -> Result<(), String> {
    if value.len() > MAX_TEXT_LEN {
        return Err(format!("{label} exceeds {MAX_TEXT_LEN} chars (got {})", value.len()));
    }
    Ok(())
}

/// GET /api/plugins — list all plugins
pub async fn list_plugins(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    match state.db.list_wasm_plugins().await {
        Ok(rows) => {
            // Strip the binary from the listing response
            let list: Vec<serde_json::Value> = rows
                .iter()
                .map(|r| {
                    json!({
                        "id": r.id,
                        "name": r.name,
                        "version": r.version,
                        "description": r.description,
                        "author": r.author,
                        "enabled": r.enabled,
                        "config_json": r.config_json,
                        "created_at": r.created_at,
                        "updated_at": r.updated_at,
                        "wasm_size": r.wasm_binary.len(),
                    })
                })
                .collect();
            (StatusCode::OK, Json(json!({ "plugins": list }))).into_response()
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": e.to_string() })),
        )
            .into_response(),
    }
}

/// POST /api/plugins — upload a WASM plugin via multipart form
///
/// Form fields:
///   - `name`        (text)  plugin identifier
///   - `version`     (text, optional)
///   - `description` (text, optional)
///   - `author`      (text, optional)
///   - `file`        (binary) the .wasm file
pub async fn upload_plugin(State(state): State<Arc<AppState>>, mut multipart: Multipart) -> impl IntoResponse {
    let mut name = String::new();
    let mut version = None::<String>;
    let mut description = None::<String>;
    let mut author = None::<String>;
    let mut wasm_bytes = None::<Vec<u8>>;

    while let Ok(Some(field)) = multipart.next_field().await {
        match field.name() {
            Some("name") => {
                name = field.text().await.unwrap_or_default();
            }
            Some("version") => {
                version = Some(field.text().await.unwrap_or_default());
            }
            Some("description") => {
                description = Some(field.text().await.unwrap_or_default());
            }
            Some("author") => {
                author = Some(field.text().await.unwrap_or_default());
            }
            Some("file") => match field.bytes().await {
                Ok(b) => wasm_bytes = Some(b.to_vec()),
                Err(e) => {
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(json!({ "error": format!("failed to read file: {e}") })),
                    )
                        .into_response();
                }
            },
            _ => {}
        }
    }

    if let Err(msg) = validate_plugin_name(&name) {
        return (StatusCode::BAD_REQUEST, Json(json!({ "error": msg }))).into_response();
    }
    if let Some(v) = &version
        && let Err(msg) = validate_text_field("version", v)
    {
        return (StatusCode::BAD_REQUEST, Json(json!({ "error": msg }))).into_response();
    }
    if let Some(v) = &description
        && let Err(msg) = validate_text_field("description", v)
    {
        return (StatusCode::BAD_REQUEST, Json(json!({ "error": msg }))).into_response();
    }
    if let Some(v) = &author
        && let Err(msg) = validate_text_field("author", v)
    {
        return (StatusCode::BAD_REQUEST, Json(json!({ "error": msg }))).into_response();
    }

    let Some(bytes) = wasm_bytes else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "WASM file is required" })),
        )
            .into_response();
    };

    // Defense in depth: the router-level `DefaultBodyLimit::max(MAX_TOTAL_BODY)`
    // already rejects oversized requests before they reach this handler, but
    // a future router refactor that drops or widens that layer must not
    // silently lift the cap.
    if bytes.len() > MAX_WASM_BYTES {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": format!("WASM file exceeds {MAX_WASM_BYTES}-byte cap (got {})", bytes.len()),
            })),
        )
            .into_response();
    }

    // Validate WASM magic bytes (\0asm)
    if bytes.get(..4) != Some(b"\0asm".as_slice()) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "invalid WASM file (bad magic bytes)" })),
        )
            .into_response();
    }

    let req = CreateWasmPlugin {
        name: name.clone(),
        version: version.clone(),
        description: description.clone(),
        author: author.clone(),
        wasm_binary: bytes.clone(),
        enabled: Some(true),
        config_json: None,
    };

    // Persist to DB
    let row = match state.db.create_wasm_plugin(req).await {
        Ok(r) => r,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": e.to_string() })),
            )
                .into_response();
        }
    };

    // Load into the plugin manager
    if let Err(e) = state
        .plugin_manager
        .load(waf_engine::plugins::manager::LoadPluginParams {
            id: row.id,
            name: row.name.clone(),
            version: row.version.clone(),
            description: row.description.clone().unwrap_or_default(),
            author: row.author.clone().unwrap_or_default(),
            enabled: row.enabled,
            wasm_bytes: &bytes,
        })
        .await
    {
        // Plugin stored but failed to compile — surface the error
        tracing::warn!(plugin=%name, "WASM compile error: {e}");
    }

    info!(plugin = %name, "Plugin uploaded");
    (
        StatusCode::CREATED,
        Json(json!({
            "id": row.id,
            "name": row.name,
            "version": row.version,
            "enabled": row.enabled,
        })),
    )
        .into_response()
}

/// DELETE /api/plugins/:id — remove a plugin
pub async fn delete_plugin(State(state): State<Arc<AppState>>, Path(id): Path<Uuid>) -> impl IntoResponse {
    state.plugin_manager.unload(id).await;
    match state.db.delete_wasm_plugin(id).await {
        Ok(true) => (StatusCode::NO_CONTENT).into_response(),
        Ok(false) => (StatusCode::NOT_FOUND, Json(json!({ "error": "plugin not found" }))).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": e.to_string() })),
        )
            .into_response(),
    }
}

/// POST /api/plugins/:id/enable
pub async fn enable_plugin(State(state): State<Arc<AppState>>, Path(id): Path<Uuid>) -> impl IntoResponse {
    set_plugin_enabled(state, id, true).await
}

/// POST /api/plugins/:id/disable
pub async fn disable_plugin(State(state): State<Arc<AppState>>, Path(id): Path<Uuid>) -> impl IntoResponse {
    set_plugin_enabled(state, id, false).await
}

async fn set_plugin_enabled(state: Arc<AppState>, id: Uuid, enabled: bool) -> impl IntoResponse {
    state.plugin_manager.set_enabled(id, enabled).await;
    match state.db.set_wasm_plugin_enabled(id, enabled).await {
        Ok(true) => (StatusCode::OK, Json(json!({ "enabled": enabled }))).into_response(),
        Ok(false) => (StatusCode::NOT_FOUND, Json(json!({ "error": "plugin not found" }))).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": e.to_string() })),
        )
            .into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::{MAX_NAME_LEN, MAX_TEXT_LEN, validate_plugin_name, validate_text_field};

    #[test]
    fn plugin_name_accepts_alphanumeric_and_separators() {
        assert!(validate_plugin_name("my_plugin").is_ok());
        assert!(validate_plugin_name("MyPlugin-v2").is_ok());
        assert!(validate_plugin_name("waf_rate_limit_42").is_ok());
        assert!(validate_plugin_name("A").is_ok());
    }

    #[test]
    fn plugin_name_rejects_empty() {
        let err = validate_plugin_name("").unwrap_err();
        assert!(err.contains("required"), "msg = {err}");
    }

    #[test]
    fn plugin_name_rejects_path_traversal_characters() {
        assert!(validate_plugin_name("../etc/passwd").is_err());
        assert!(validate_plugin_name("plugin/../secret").is_err());
        assert!(validate_plugin_name("\\\\admin\\share").is_err());
    }

    #[test]
    fn plugin_name_rejects_whitespace_and_unicode() {
        assert!(validate_plugin_name("my plugin").is_err());
        assert!(validate_plugin_name("plugin\n").is_err());
        assert!(validate_plugin_name("plügin").is_err());
    }

    #[test]
    fn plugin_name_rejects_oversize() {
        let big = "a".repeat(MAX_NAME_LEN + 1);
        let err = validate_plugin_name(&big).unwrap_err();
        assert!(err.contains("exceeds"), "msg = {err}");
        assert!(err.contains(&MAX_NAME_LEN.to_string()), "msg = {err}");
    }

    #[test]
    fn plugin_name_boundary_max_length_accepted() {
        let exact = "a".repeat(MAX_NAME_LEN);
        assert!(validate_plugin_name(&exact).is_ok());
    }

    #[test]
    fn text_field_accepts_empty_and_short() {
        assert!(validate_text_field("version", "").is_ok());
        assert!(validate_text_field("version", "1.2.3-rc.4").is_ok());
        let exact = "x".repeat(MAX_TEXT_LEN);
        assert!(validate_text_field("description", &exact).is_ok());
    }

    #[test]
    fn text_field_rejects_oversize() {
        let big = "x".repeat(MAX_TEXT_LEN + 1);
        let err = validate_text_field("description", &big).unwrap_err();
        assert!(err.contains("description"), "msg = {err}");
        assert!(err.contains("exceeds"), "msg = {err}");
    }
}
