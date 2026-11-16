#![forbid(unsafe_code)]

//! Local loopback HTTP preview, JSON-RPC bridge & SSE turn-event stream (`127.0.0.1:8787`)
//! so Web UI, GTK4, and developer tools can consume unified `AgentEvent` streams (`H10`).

use crate::backend_bridge::turn_checkpoint::{poll_turn_events, subscribe_turn_event_stream};
use crate::core::IntentOsCore;
use axum::Router;
use axum::extract::Request;
use axum::extract::{Path as AxumPath, Query, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::middleware::{self, Next};
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
        .layer(middleware::from_fn(require_local_origin))
        .with_state(core)
}

// The HTTP bridge reaches trusted UI RPCs, including approvals. Loopback binding
// alone does not stop a hostile browser origin or DNS rebinding.
fn is_local_request(headers: &HeaderMap) -> bool {
    let Some(authority) = headers
        .get(header::HOST)
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.parse::<axum::http::uri::Authority>().ok())
    else {
        return false;
    };
    if authority.as_str().contains('@') {
        return false;
    }
    let host = authority
        .host()
        .trim_start_matches('[')
        .trim_end_matches(']');
    if !host.eq_ignore_ascii_case("localhost")
        && !host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback())
    {
        return false;
    }
    if headers
        .get("sec-fetch-site")
        .is_some_and(|v| v == "cross-site")
    {
        return false;
    }
    if let Some(origin) = headers.get(header::ORIGIN) {
        let Ok(origin) = origin.to_str() else {
            return false;
        };
        let Ok(origin_url) = reqwest::Url::parse(origin) else {
            return false;
        };
        let Ok(local_url) = reqwest::Url::parse(&format!("http://{authority}")) else {
            return false;
        };
        if origin_url.origin() != local_url.origin()
            || !origin_url.username().is_empty()
            || origin_url.password().is_some()
            || origin_url.path() != "/"
            || origin_url.query().is_some()
            || origin_url.fragment().is_some()
        {
            return false;
        }
    }
    true
}

async fn require_local_origin(request: Request, next: Next) -> Response {
    if !is_local_request(request.headers()) {
        return (StatusCode::FORBIDDEN, "Local same-origin requests required").into_response();
    }
    next.run(request).await
}

pub async fn start_web_shell_server(
    core: Arc<IntentOsCore>,
    addr: SocketAddr,
) -> anyhow::Result<()> {
    anyhow::ensure!(
        addr.ip().is_loopback(),
        "Web Shell must bind to a loopback address"
    );
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

#[cfg(test)]
mod local_origin_tests {
    use super::*;

    #[test]
    fn local_origin_rejects_cross_origin_and_rebinding() {
        for (host, origin, allowed) in [
            ("127.0.0.1:8787", None, true),
            ("localhost:8787", Some("http://localhost:8787"), true),
            ("[::1]:8787", Some("http://[::1]:8787"), true),
            ("evil.example:8787", None, false),
            ("127.0.0.1:8787", Some("https://evil.example"), false),
            ("127.0.0.1:8787", Some("http://127.0.0.1:9999"), false),
            ("127.0.0.1:8787", Some("http://localhost:8787"), false),
            ("127.0.0.1:8787", Some("null"), false),
            ("127.0.0.1:8787", Some("http://user@127.0.0.1:8787"), false),
        ] {
            let mut headers = HeaderMap::new();
            headers.insert(header::HOST, host.parse().unwrap());
            if let Some(origin) = origin {
                headers.insert(header::ORIGIN, origin.parse().unwrap());
            }
            assert_eq!(is_local_request(&headers), allowed, "{host} {origin:?}");
        }
        assert!(!is_local_request(&HeaderMap::new()));
        let mut headers = HeaderMap::new();
        headers.insert(header::HOST, "127.0.0.1:8787".parse().unwrap());
        headers.insert("sec-fetch-site", "cross-site".parse().unwrap());
        assert!(!is_local_request(&headers));
    }

    #[tokio::test]
    async fn web_router_guards_rpc_and_events_and_refuses_public_binding() {
        let tmp = tempfile::tempdir().unwrap();
        let repo = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
        let core = IntentOsCore::initialize(Some(tmp.path()), repo).unwrap();
        assert!(
            start_web_shell_server(core.clone(), "0.0.0.0:0".parse().unwrap())
                .await
                .is_err()
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(listener, build_web_shell_router(core))
                .await
                .unwrap();
        });
        let base = format!("http://{addr}");
        let client = reqwest::Client::new();
        assert_eq!(
            client
                .get(format!("{base}/healthz"))
                .send()
                .await
                .unwrap()
                .status(),
            StatusCode::OK
        );
        assert_eq!(
            client
                .get(format!("{base}/"))
                .header("Origin", &base)
                .send()
                .await
                .unwrap()
                .status(),
            StatusCode::OK
        );
        for path in ["/api/rpc", "/api/turn-events?turn_id=secret", "/healthz"] {
            let request = if path == "/api/rpc" {
                client.post(format!("{base}{path}")).json(&json!({}))
            } else {
                client.get(format!("{base}{path}"))
            };
            assert_eq!(
                request
                    .header("Origin", "https://evil.example")
                    .send()
                    .await
                    .unwrap()
                    .status(),
                StatusCode::FORBIDDEN
            );
        }
        assert_eq!(
            client
                .get(format!("{base}/healthz"))
                .header("Host", "evil.example")
                .send()
                .await
                .unwrap()
                .status(),
            StatusCode::FORBIDDEN
        );
        server.abort();
    }
}
