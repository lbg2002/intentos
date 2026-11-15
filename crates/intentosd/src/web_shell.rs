#![forbid(unsafe_code)]

//! Local loopback HTTP preview, JSON-RPC bridge & SSE turn-event stream (`127.0.0.1:8787`)
//! so Web UI, GTK4, and developer tools can consume unified `AgentEvent` streams (`H10`).

use crate::backend_bridge::turn_checkpoint::{poll_turn_events, subscribe_turn_event_stream};
use crate::core::IntentOsCore;
use axum::Router;
use axum::extract::{Path as AxumPath, Query, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{Html, IntoResponse, Json, Response};
use axum::routing::{get, post};
use intentos_protocol::{AgentEvent, UiRpcEnvelope, UiRpcResponse};
use serde::Deserialize;
use serde_json::json;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::broadcast::error::RecvError;
use tokio_stream::wrappers::ReceiverStream;

#[derive(Debug, Deserialize)]
pub struct TurnEventsQuery {
    #[serde(default)]
    pub turn_id: String,
    #[serde(default)]
    pub since_seq: Option<u64>,
}

pub fn build_web_shell_router(core: Arc<IntentOsCore>) -> Router {
    Router::new()
        .route("/", get(index_handler))
        .route("/assets/{*path}", get(asset_handler))
        .route("/api/rpc", post(rpc_handler))
        .route("/api/turn-events", get(turn_events_sse_handler))
        .route("/healthz", get(health_handler))
        .with_state(core)
}

pub async fn start_web_shell_server(
    core: Arc<IntentOsCore>,
    addr: SocketAddr,
) -> anyhow::Result<()> {
    let app = build_web_shell_router(core);

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

fn encode_sse_agent_event(ev: &AgentEvent) -> Option<Event> {
    let payload = serde_json::to_string(ev).ok()?;
    Some(
        Event::default()
            .id(ev.seq.to_string())
            .event(ev.kind.event_name())
            .data(payload),
    )
}

async fn turn_events_sse_handler(
    headers: HeaderMap,
    Query(query): Query<TurnEventsQuery>,
) -> Response {
    let turn_id = query.turn_id.trim().to_string();
    if turn_id.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "ok": false, "error": "missing turn_id query parameter" })),
        )
            .into_response();
    }

    let header_since = headers
        .get("last-event-id")
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.trim().parse::<u64>().ok());
    let since_seq = query.since_seq.or(header_since).unwrap_or(0);

    let (tx, rx) = tokio::sync::mpsc::channel::<Result<Event, Infallible>>(128);
    tokio::spawn(async move {
        // Allow a short registration grace window when EventSource opens concurrently with POST /api/rpc.
        let mut sub_opt = subscribe_turn_event_stream(&turn_id, since_seq);
        if sub_opt.is_none() {
            for _ in 0..80 {
                tokio::time::sleep(Duration::from_millis(15)).await;
                sub_opt = subscribe_turn_event_stream(&turn_id, since_seq);
                if sub_opt.is_some() {
                    break;
                }
            }
        }

        let Some(mut sub) = sub_opt else {
            return;
        };

        let mut last_seq = since_seq;
        for ev in &sub.snapshot.events {
            if ev.seq > last_seq {
                last_seq = ev.seq;
                if let Some(sse_ev) = encode_sse_agent_event(ev)
                    && tx.send(Ok(sse_ev)).await.is_err()
                {
                    return;
                }
                if ev.kind.ends_turn_stream() {
                    return;
                }
            }
        }

        if sub.snapshot.done {
            return;
        }

        loop {
            match sub.rx.recv().await {
                Ok(ev) => {
                    if ev.seq <= last_seq {
                        continue;
                    }
                    last_seq = ev.seq;
                    let ends = ev.kind.ends_turn_stream();
                    if let Some(sse_ev) = encode_sse_agent_event(&ev)
                        && tx.send(Ok(sse_ev)).await.is_err()
                    {
                        return;
                    }
                    if ends {
                        return;
                    }
                }
                Err(RecvError::Lagged(_)) => {
                    let catchup = poll_turn_events(&json!({
                        "turn_id": turn_id,
                        "since_seq": last_seq,
                    }));
                    if let Some(arr) = catchup.get("events").and_then(|v| v.as_array()) {
                        for val in arr {
                            if let Ok(ev) = serde_json::from_value::<AgentEvent>(val.clone())
                                && ev.seq > last_seq
                            {
                                last_seq = ev.seq;
                                let ends = ev.kind.ends_turn_stream();
                                if let Some(sse_ev) = encode_sse_agent_event(&ev)
                                    && tx.send(Ok(sse_ev)).await.is_err()
                                {
                                    return;
                                }
                                if ends {
                                    return;
                                }
                            }
                        }
                    }
                    if catchup
                        .get("done")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false)
                    {
                        return;
                    }
                }
                Err(RecvError::Closed) => break,
            }
        }
    });

    Sse::new(ReceiverStream::new(rx))
        .keep_alive(KeepAlive::new().interval(Duration::from_secs(15)))
        .into_response()
}
