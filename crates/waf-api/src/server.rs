use std::net::SocketAddr;
use std::sync::Arc;

use axum::{
    routing::{delete, get, post},
    Router,
};
use tower_http::cors::{Any, CorsLayer};
use tower_http::trace::TraceLayer;
use tracing::info;

use crate::handlers::*;
use crate::state::AppState;

/// Build the Axum router with all API routes
pub fn build_router(state: Arc<AppState>) -> Router {
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    Router::new()
        // Hosts
        .route("/api/hosts", get(list_hosts).post(create_host))
        .route("/api/hosts/:id", get(get_host).put(update_host).delete(delete_host))
        // Allow IPs
        .route("/api/allow-ips", get(list_allow_ips).post(create_allow_ip))
        .route("/api/allow-ips/:id", delete(delete_allow_ip))
        // Block IPs
        .route("/api/block-ips", get(list_block_ips).post(create_block_ip))
        .route("/api/block-ips/:id", delete(delete_block_ip))
        // Allow URLs
        .route("/api/allow-urls", get(list_allow_urls).post(create_allow_url))
        .route("/api/allow-urls/:id", delete(delete_allow_url))
        // Block URLs
        .route("/api/block-urls", get(list_block_urls).post(create_block_url))
        .route("/api/block-urls/:id", delete(delete_block_url))
        // Attack logs
        .route("/api/attack-logs", get(list_attack_logs))
        // System status
        .route("/api/status", get(get_status))
        // Rule reload
        .route("/api/reload", post(reload_rules))
        .layer(cors)
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

/// Start the management API server
pub async fn start_api_server(
    listen_addr: &str,
    state: Arc<AppState>,
) -> anyhow::Result<()> {
    let addr: SocketAddr = listen_addr.parse()?;
    let app = build_router(state);

    info!("Management API listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}
