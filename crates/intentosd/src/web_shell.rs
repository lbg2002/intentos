#![forbid(unsafe_code)]

//! Local loopback HTTP preview & JSON-RPC bridge (`127.0.0.1:8787`) so developers can test
//! IntentOS Shell interactively in browser or Preview pane alongside `ui.sock` and `intentosctl`.

use crate::core::IntentOsCore;
use axum::Router;
use axum::extract::{Path as AxumPath, State};
use axum::http::{StatusCode, header};
use axum::response::{Html, IntoResponse, Json, Response};
use axum::routing::{get, post};
use intentos_protocol::{UiRpcEnvelope, UiRpcResponse};
use std::net::SocketAddr;
use std::sync::Arc;

pub async fn start_web_shell_server(
    core: Arc<IntentOsCore>,
    addr: SocketAddr,
) -> anyhow::Result<()> {
    let app = Router::new()
        .route("/", get(index_handler))
        .route("/assets/{*path}", get(asset_handler))
        .route("/api/rpc", post(rpc_handler))
        .route("/healthz", get(health_handler))
        .with_state(core);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!(%addr, "IntentOS Web Shell listening");
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    Ok(())
}

async fn index_handler(State(core): State<Arc<IntentOsCore>>) -> impl IntoResponse {
    Html(crate::web_ui::render_index_html(&core.paths.repo_root))
}

async fn asset_handler(
    State(core): State<Arc<IntentOsCore>>,
    AxumPath(path): AxumPath<String>,
) -> Response {
    match crate::web_ui::load_static_asset(&core.paths.repo_root, &path) {
        Some((mime, bytes)) => ([(header::CONTENT_TYPE, mime)], bytes).into_response(),
        None => (StatusCode::NOT_FOUND, "Asset not found").into_response(),
    }
}

async fn health_handler(State(core): State<Arc<IntentOsCore>>) -> impl IntoResponse {
    Json(core.status())
}

async fn rpc_handler(
    State(core): State<Arc<IntentOsCore>>,
    Json(envelope): Json<UiRpcEnvelope>,
) -> Json<UiRpcResponse> {
    Json(
        core.handle_trusted_ui_rpc(envelope.id, envelope.request)
            .await,
    )
}
