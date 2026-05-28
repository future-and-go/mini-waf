/// `WebSocket` handlers for real-time event/log streaming.
///
/// Endpoints:
///   GET /ws/events  — live security events
///   GET /ws/logs    — live access log stream
///
/// Authentication (in priority order):
///   1. `Authorization: Bearer <jwt>` header  (recommended)
///   2. `Sec-WebSocket-Protocol: bearer.<jwt>` header
///   3. `?token=<jwt>` query parameter  (deprecated — token may appear in logs)
///
/// Max 50 concurrent connections. Heartbeat ping every 30 s.
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use axum::{
    Json,
    extract::{
        Query, State,
        ws::{Message, WebSocket, WebSocketUpgrade},
    },
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use serde_json::json;
use tokio::time::interval;
use tracing::warn;

use crate::auth::validate_admin_token;
use crate::state::AppState;

#[derive(Deserialize)]
pub struct WsQuery {
    pub token: Option<String>,
}

const MAX_WS_CONNECTIONS: u32 = 50;

/// GET /ws/events — live security event stream
pub async fn ws_events(
    ws: WebSocketUpgrade,
    headers: HeaderMap,
    Query(params): Query<WsQuery>,
    State(state): State<Arc<AppState>>,
) -> Response {
    auth_and_upgrade(ws, &headers, params, state, "events").await
}

/// GET /ws/logs — live access log stream
pub async fn ws_logs(
    ws: WebSocketUpgrade,
    headers: HeaderMap,
    Query(params): Query<WsQuery>,
    State(state): State<Arc<AppState>>,
) -> Response {
    auth_and_upgrade(ws, &headers, params, state, "logs").await
}

/// Extract JWT token from headers or query parameter.
///
/// Priority:
///   1. `Authorization: Bearer <token>` header
///   2. `Sec-WebSocket-Protocol: bearer.<token>` header
///   3. `?token=<token>` query parameter (deprecated)
fn extract_ws_token(headers: &HeaderMap, params: &WsQuery) -> Option<String> {
    // 1. Authorization header (preferred)
    if let Some(auth) = headers.get("authorization")
        && let Ok(s) = auth.to_str()
        && let Some(token) = s.strip_prefix("Bearer ")
    {
        return Some(token.to_string());
    }

    // 2. Sec-WebSocket-Protocol header with "bearer." prefix
    if let Some(proto) = headers.get("sec-websocket-protocol")
        && let Ok(s) = proto.to_str()
    {
        // Protocol value may contain multiple comma-separated values
        for part in s.split(',') {
            let trimmed = part.trim();
            if let Some(token) = trimmed.strip_prefix("bearer.") {
                return Some(token.to_string());
            }
        }
    }

    // 3. Query parameter (deprecated — logs warning)
    if let Some(ref token) = params.token {
        warn!("WebSocket auth via query parameter is deprecated; use Authorization header instead");
        return Some(token.clone());
    }

    None
}

#[allow(clippy::unused_async)] // Axum handler signature requires async
async fn auth_and_upgrade(
    ws: WebSocketUpgrade,
    headers: &HeaderMap,
    params: WsQuery,
    state: Arc<AppState>,
    stream: &'static str,
) -> Response {
    // Extract JWT from headers or query parameter
    let Some(token) = extract_ws_token(headers, &params) else {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "token required — use Authorization header" })),
        )
            .into_response();
    };

    if validate_admin_token(&token, &state.jwt_secret).is_err() {
        return (StatusCode::UNAUTHORIZED, Json(json!({ "error": "invalid token" }))).into_response();
    }

    // Check connection limit
    let current = state.ws_connections.fetch_add(1, Ordering::Relaxed);
    if current >= MAX_WS_CONNECTIONS {
        state.ws_connections.fetch_sub(1, Ordering::Relaxed);
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({ "error": "max connections reached" })),
        )
            .into_response();
    }

    ws.on_upgrade(move |socket| handle_ws(socket, state, stream, token))
}

/// Returns `true` when the heartbeat tick must terminate the connection
/// because the bound JWT no longer satisfies the admin gate — expired,
/// revoked, signed with a now-rotated secret, or role demoted away from
/// `admin`. Pure helper extracted for unit-testing.
fn jwt_requires_close(token: &str, secret: &str) -> bool {
    validate_admin_token(token, secret).is_err()
}

async fn handle_ws(mut socket: WebSocket, state: Arc<AppState>, stream: &'static str, token: String) {
    // Subscribe to the Database's real-time event broadcast channel
    let mut rx = state.db.subscribe_events();
    let mut ping_interval = interval(Duration::from_secs(30));

    loop {
        tokio::select! {
            // Forward broadcast events to this client
            msg = rx.recv() => {
                match msg {
                    Ok(val) => {
                        let text = val.to_string();
                        // Forward all events for both /ws/logs and /ws/events
                        let _ = stream; // all event types forwarded by default
                        if socket.send(Message::Text(text.into())).await.is_err() {
                            break;
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                        // Skip lagged messages
                    }
                    Err(_) => break,
                }
            }

            // Heartbeat ping — also re-validates the bound JWT so an expired
            // or revoked token cannot keep streaming audit data for the rest
            // of the connection lifetime.
            _ = ping_interval.tick() => {
                if jwt_requires_close(&token, &state.jwt_secret) {
                    warn!(stream, "WS JWT no longer valid — closing socket");
                    let _ = socket.send(Message::Close(None)).await;
                    break;
                }
                if socket.send(Message::Ping(vec![].into())).await.is_err() {
                    break;
                }
            }

            // Handle incoming messages (pong, close, etc.)
            msg = socket.recv() => {
                match msg {
                    Some(Ok(Message::Close(_))) | None => break,
                    _ => {}
                }
            }
        }
    }

    state.ws_connections.fetch_sub(1, Ordering::Relaxed);
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::auth::generate_access_token;
    use uuid::Uuid;

    #[test]
    fn jwt_requires_close_true_for_garbage_token() {
        assert!(jwt_requires_close("not-a-jwt", "secret"));
    }

    #[test]
    fn jwt_requires_close_true_for_wrong_secret() {
        // A token signed with one secret must fail validation under another —
        // this is the path a rotated jwt_secret takes when a long-lived WS
        // session is still streaming.
        let token = generate_access_token(Uuid::new_v4(), "admin", "admin", "old-secret").expect("issue token");
        assert!(jwt_requires_close(&token, "new-secret"));
    }

    #[test]
    fn jwt_requires_close_false_for_fresh_admin_token() {
        // A token signed with the same secret, not yet expired, and carrying
        // the admin role must keep the heartbeat path open.
        let secret = "shared-secret";
        let token = generate_access_token(Uuid::new_v4(), "admin", "admin", secret).expect("issue token");
        assert!(!jwt_requires_close(&token, secret));
    }

    #[test]
    fn jwt_requires_close_true_for_non_admin_role() {
        // A valid JWT carrying a viewer / read-only role must NOT be allowed
        // to keep streaming — admin-only is the contract for /ws/events and
        // /ws/logs because both forward sensitive audit payloads.
        let secret = "shared-secret";
        let token = generate_access_token(Uuid::new_v4(), "carol", "viewer", secret).expect("issue token");
        assert!(jwt_requires_close(&token, secret));
    }
}
