#![forbid(unsafe_code)]

//! Private UI Channel Unix Socket Server (`${XDG_RUNTIME_DIR}/intentos/ui.sock`, §10.5, §15.3).
//! Enforces `SO_PEERCRED` UID match and `/proc/<pid>/exe` verification before processing RPCs.

use crate::core::IntentOsCore;
use intentos_protocol::{UiRpcEnvelope, UiRpcResponse};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};

pub fn start_ui_socket_server(core: Arc<IntentOsCore>, sock_path: &Path) -> anyhow::Result<()> {
    if sock_path.exists() {
        let _ = std::fs::remove_file(sock_path);
    }
    if let Some(parent) = sock_path.parent() {
        std::fs::create_dir_all(parent)?;
        std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))?;
    }
    let listener = UnixListener::bind(sock_path)?;
    std::fs::set_permissions(sock_path, std::fs::Permissions::from_mode(0o600))?;

    let expected_uid = current_euid();
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            let core_ref = core.clone();
            tokio::spawn(async move {
                let _ = handle_ui_connection(core_ref, stream, expected_uid).await;
            });
        }
    });
    Ok(())
}

fn current_euid() -> u32 {
    std::fs::metadata("/proc/self")
        .map(|m| std::os::unix::fs::MetadataExt::uid(&m))
        .unwrap_or(1000)
}

async fn handle_ui_connection(
    core: Arc<IntentOsCore>,
    stream: UnixStream,
    expected_uid: u32,
) -> anyhow::Result<()> {
    // Verify peer credentials via SO_PEERCRED (§10.5)
    let cred = stream.peer_cred()?;
    if cred.uid() != expected_uid {
        tracing::warn!(
            peer_uid = cred.uid(),
            expected_uid,
            "rejected ui.sock connection from mismatched UID"
        );
        return Ok(());
    }
    // Reject connections from untrusted Node/Python worker binaries if a sandbox ever misconfigured mounts
    if let Some(pid) = cred.pid() {
        let cmdline = std::fs::read(format!("/proc/{}/cmdline", pid))
            .map(|b| String::from_utf8_lossy(&b).replace('\0', " "))
            .unwrap_or_default();
        if cmdline.contains("pi-adapter") || cmdline.contains("worker.js") {
            tracing::error!(%cmdline, "blocked Agent Worker cmdline from connecting to private ui.sock!");
            return Ok(());
        }
        if let Ok(exe_path) = std::fs::read_link(format!("/proc/{}/exe", pid)) {
            let exe_name = exe_path
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_default();
            if exe_name == "intentos-agent" || exe_path.to_string_lossy().contains("pi-adapter") {
                tracing::error!(?exe_path, "blocked Agent Worker from connecting to private ui.sock!");
                return Ok(());
            }
        }
    }

    let (read_half, mut write_half) = stream.into_split();
    let mut lines = BufReader::new(read_half).lines();
    while let Some(line) = lines.next_line().await? {
        if line.trim().is_empty() {
            continue;
        }
        let resp = match serde_json::from_str::<UiRpcEnvelope>(&line) {
            Ok(env) => core.handle_trusted_ui_rpc(env.id, env.request).await,
            Err(e) => UiRpcResponse {
                id: "invalid".into(),
                ok: false,
                result: None,
                error: Some(format!("JSON-RPC parse error: {}", e)),
            },
        };
        let encoded = serde_json::to_string(&resp)?;
        write_half.write_all(encoded.as_bytes()).await?;
        write_half.write_all(b"\n").await?;
        write_half.flush().await?;
    }
    Ok(())
}
