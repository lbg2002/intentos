#![forbid(unsafe_code)]

use clap::Parser;
use intentosd::core::IntentOsCore;
use intentosd::dbus_bridge::PublicDbusService;
use intentosd::ipc::start_ui_socket_server;
use intentosd::web_shell::start_web_shell_server;
use std::net::SocketAddr;
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(
    name = "intentosd",
    version,
    about = "IntentOS Trusted Rust Core Daemon"
)]
struct Args {
    /// Optional override base directory for isolated state/config/cache/run
    #[arg(long, env = "INTENTOS_BASE_DIR")]
    base_dir: Option<PathBuf>,

    /// Repository root containing `modules/builtin` and `agent/pi-adapter`
    #[arg(long, env = "INTENTOS_REPO_ROOT")]
    repo_root: Option<PathBuf>,

    /// Bind address for local interactive Web Shell (`0` port or `--no-web` to disable)
    #[arg(long, default_value = "127.0.0.1:8787")]
    web_listen: SocketAddr,

    #[arg(long, default_value_t = false)]
    no_web: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "intentosd=info".into()),
        )
        .init();

    let args = Args::parse();
    let repo_root = args.repo_root.unwrap_or_else(detect_repo_root);
    let core = IntentOsCore::initialize(args.base_dir.as_deref(), repo_root)?;

    // 1. Start Model Gateway Unix socket (`gateway.sock`) for zero-network Workers
    core.gateway
        .clone()
        .spawn_unix_socket_server(&core.paths.gateway_socket_path())?;

    // 2. Start Private UI Channel Unix socket (`ui.sock` with SO_PEERCRED verification)
    let ui_sock = core.paths.ui_socket_path();
    start_ui_socket_server(core.clone(), &ui_sock)?;
    tracing::info!(ui_socket = %ui_sock.display(), "Private UI channel listening");

    // 3. Start non-privileged Public D-Bus Service (`org.intentos.Core1`, §15.2)
    PublicDbusService::new(core.clone()).spawn_session_bus_listener();

    // 4. Start local interactive Web Shell server unless disabled
    if !args.no_web {
        start_web_shell_server(core.clone(), args.web_listen).await?;
    }

    let st = core.status();
    tracing::info!(
        capabilities = st.registered_capabilities,
        apps = st.indexed_apps,
        files = st.indexed_files,
        sites = st.indexed_sites,
        runtime = %st.runtime_mode,
        "intentosd ready"
    );

    tokio::signal::ctrl_c().await?;
    tracing::info!("shutting down intentosd");
    let _ = std::fs::remove_file(&ui_sock);
    let _ = std::fs::remove_file(core.paths.gateway_socket_path());
    Ok(())
}

fn detect_repo_root() -> PathBuf {
    if let Ok(cwd) = std::env::current_dir()
        && cwd.join("modules/builtin").exists()
    {
        return cwd;
    }
    PathBuf::from("/home/antigravity/intentos")
}
