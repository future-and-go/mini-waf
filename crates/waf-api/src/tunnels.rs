//! Tunnel API handlers + WebSocket tunnel server endpoint.

use std::sync::Arc;

use axum::{
    Json,
    extract::{Path, Query, State, WebSocketUpgrade},
    http::StatusCode,
    response::IntoResponse,
};
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::{debug, info, warn};
use uuid::Uuid;
use waf_storage::models::CreateTunnel;

use crate::state::AppState;
use gateway::{TunnelConfig, TunnelConnection, generate_token, hash_token};

/// Closed set of transport protocols accepted on the tunnel API boundary.
///
/// Mirrors the `tunnels_protocol_check` CHECK constraint in migration 0017
/// so an invalid value is rejected with 400 before reaching the database.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum TunnelProtocol {
    Tcp,
    Udp,
    Ws,
    Quic,
    Http,
    Grpc,
}

impl TunnelProtocol {
    pub const fn as_db_str(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
            Self::Ws => "ws",
            Self::Quic => "quic",
            Self::Http => "http",
            Self::Grpc => "grpc",
        }
    }

    /// Parse a database/JSON string into the enum.
    ///
    /// `None` and the empty string default to TCP (matches the migration 0017
    /// column default); any other value off the closed set is a client error.
    pub fn parse_or_default(s: Option<&str>) -> Result<Self, String> {
        let raw = s.unwrap_or("tcp");
        match raw {
            "" | "tcp" => Ok(Self::Tcp),
            "udp" => Ok(Self::Udp),
            "ws" => Ok(Self::Ws),
            "quic" => Ok(Self::Quic),
            "http" => Ok(Self::Http),
            "grpc" => Ok(Self::Grpc),
            other => Err(format!(
                "protocol must be one of tcp|udp|ws|quic|http|grpc (got {other:?})"
            )),
        }
    }
}

// ─── REST handlers ─────────────────────────────────────────────────────────────

/// GET /api/tunnels
pub async fn list_tunnels(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    match state.db.list_tunnels().await {
        Ok(rows) => {
            let live = state.tunnel_registry.list_status().await;
            let list: Vec<serde_json::Value> = rows
                .iter()
                .map(|r| {
                    let status = live.iter().find(|s| s.id == r.id);
                    let connected = status.is_some_and(|s| s.connected);
                    json!({
                        "id": r.id,
                        "name": r.name,
                        "target_host": r.target_host,
                        "target_port": r.target_port,
                        "protocol": r.protocol,
                        "enabled": r.enabled,
                        "connected": connected,
                        "last_seen": r.last_seen,
                        "created_at": r.created_at,
                    })
                })
                .collect();
            // Envelope standardisation: canonical shape is `success/data/total`.
            // `tunnels` retained as a one-release deprecation alias.
            let total = list.len();
            let alias = list.clone();
            (
                StatusCode::OK,
                Json(json!({
                    "success": true,
                    "data": list,
                    "total": total,
                    "tunnels": alias,
                })),
            )
                .into_response()
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": e.to_string() })),
        )
            .into_response(),
    }
}

/// POST /api/tunnels — create a new tunnel
///
/// Request body: `{ "name": "...", "target_host": "...", "target_port": 8080 }`
/// Response includes the one-time-visible plain-text `token` field.
pub async fn create_tunnel(
    State(state): State<Arc<AppState>>,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    let Some(name) = body
        .get("name")
        .and_then(serde_json::Value::as_str)
        .map(ToString::to_string)
    else {
        return (StatusCode::BAD_REQUEST, Json(json!({ "error": "name is required" }))).into_response();
    };
    let Some(target_host) = body
        .get("target_host")
        .and_then(serde_json::Value::as_str)
        .map(ToString::to_string)
    else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "target_host is required" })),
        )
            .into_response();
    };
    #[allow(clippy::cast_possible_truncation)]
    let Some(target_port) = body
        .get("target_port")
        .and_then(serde_json::Value::as_i64)
        .filter(|&p| p > 0 && p < 65536)
        .map(|p| p as i32)
    else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "target_port must be 1-65535" })),
        )
            .into_response();
    };

    // Parse + validate protocol against the closed enum BEFORE allocating a
    // token; an invalid protocol is a client error, not a server one.
    let protocol_str = body.get("protocol").and_then(serde_json::Value::as_str);
    let protocol = match TunnelProtocol::parse_or_default(protocol_str) {
        Ok(p) => p,
        Err(msg) => {
            return (StatusCode::BAD_REQUEST, Json(json!({ "error": msg }))).into_response();
        }
    };

    let token = generate_token();
    let token_hash = hash_token(&token);

    let req = CreateTunnel {
        name: name.clone(),
        token: token.clone(),
        target_host: target_host.clone(),
        target_port,
        enabled: body.get("enabled").and_then(serde_json::Value::as_bool),
        protocol: Some(protocol.as_db_str().to_string()),
    };

    let row = match state.db.create_tunnel(&req, &token_hash).await {
        Ok(r) => r,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": e.to_string() })),
            )
                .into_response();
        }
    };

    // Register in the in-memory registry
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let reg_port = row.target_port as u16;
    state
        .tunnel_registry
        .register(TunnelConfig {
            id: row.id,
            name: row.name.clone(),
            token_hash,
            target_host: row.target_host.clone(),
            target_port: reg_port,
            enabled: row.enabled,
        })
        .await;

    info!(tunnel = %name, "Tunnel created");
    (
        StatusCode::CREATED,
        Json(json!({
            "id": row.id,
            "name": row.name,
            "target_host": row.target_host,
            "target_port": row.target_port,
            "protocol": row.protocol,
            "enabled": row.enabled,
            "token": token,   // shown once — client must save this
        })),
    )
        .into_response()
}

/// DELETE /api/tunnels/:id
pub async fn delete_tunnel(State(state): State<Arc<AppState>>, Path(id): Path<Uuid>) -> impl IntoResponse {
    state.tunnel_registry.unregister(id).await;
    match state.db.delete_tunnel(id).await {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => (StatusCode::NOT_FOUND, Json(json!({ "error": "tunnel not found" }))).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": e.to_string() })),
        )
            .into_response(),
    }
}

// ─── WebSocket tunnel endpoint ────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct TunnelConnectQuery {
    token: String,
}

/// GET /ws/tunnel — WebSocket endpoint for tunnel client connections.
///
/// The client must pass `?token=<plain-text-token>` in the query string.
/// After the WebSocket handshake the server sends `OK` on success or closes
/// the connection with a 4401 close code on auth failure.
pub async fn ws_tunnel(
    State(state): State<Arc<AppState>>,
    Query(q): Query<TunnelConnectQuery>,
    ws: WebSocketUpgrade,
) -> impl IntoResponse {
    let token_hash = hash_token(&q.token);
    let registry = state.tunnel_registry.clone();
    let db = state.db.clone();

    // Authenticate before upgrading
    let cfg = state.db.get_tunnel_by_token_hash(&token_hash).await;

    ws.on_upgrade(move |socket| async move {
        let cfg = match cfg {
            Ok(Some(c)) if c.enabled => c,
            _ => {
                warn!("Tunnel auth failed");
                return;
            }
        };

        // Register in live connections
        let (tx, mut rx) = tokio::sync::mpsc::channel::<String>(32);
        let tunnel_id = cfg.id;
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let target_port = cfg.target_port as u16;
        let conn = TunnelConnection::new(tunnel_id, cfg.name.clone(), cfg.target_host.clone(), target_port, tx);
        registry.connect(conn.clone()).await;
        let _ = db.update_tunnel_status(tunnel_id, "connected").await;

        let (mut ws_sink, mut ws_stream) = socket.split();

        // Send OK greeting
        let _ = ws_sink.send(axum::extract::ws::Message::Text("OK".into())).await;

        info!(tunnel = %cfg.name, "Tunnel WebSocket session started");

        loop {
            tokio::select! {
                // Outbound: messages from handlers to the tunnel client
                msg = rx.recv() => {
                    match msg {
                        Some(m) => {
                            if ws_sink.send(axum::extract::ws::Message::Text(m.into())).await.is_err() {
                                break;
                            }
                        }
                        None => break,
                    }
                }
                // Inbound: messages from the tunnel client
                frame = ws_stream.next() => {
                    match frame {
                        Some(Ok(axum::extract::ws::Message::Text(txt))) => {
                            debug!(tunnel = %cfg.name, msg = %txt, "Tunnel msg");
                            conn.touch().await;
                            if txt.starts_with("PONG") {
                                // keepalive — no action needed
                            }
                        }
                        Some(Ok(axum::extract::ws::Message::Close(_))) | None => break,
                        _ => {}
                    }
                }
            }
        }

        registry.disconnect(tunnel_id).await;
        let _ = db.update_tunnel_status(tunnel_id, "disconnected").await;
        info!(tunnel = %cfg.name, "Tunnel WebSocket session ended");
    })
}
