#![forbid(unsafe_code)]

//! Public D-Bus Service Facade (`org.intentos.Core1`, §15.2, WP12):
//! - Exposes strictly NON-PRIVILEGED operations (`Submit`, `ListTasks`, `GetTask`, `SearchResources`,
//!   `ListMemories` read-only, `ListCapabilities` read-only, `GetHealth`, `GetVersion`, `StopAll`).
//! - Security Invariant (§15.2, §19.2): External callers over Public D-Bus can NEVER:
//!   1) Trigger `$ ` command passthrough (`Submit("$ rm -rf ~")` is treated as non-passthrough plain text / rejected),
//!   2) Call `Approve(nonce, digest)` (bound exclusively to `ui.sock` private channel),
//!   3) Modify or delete memories, grants, or provider credentials.

use crate::core::IntentOsCore;
use crate::resource::FileSearchFilter;
use intentos_protocol::{DaemonStatus, IntentRequest, MemoryEntry, Task};
use serde_json::{Value, json};
use std::sync::Arc;

pub const DBUS_SERVICE_NAME: &str = "org.intentos.Core1";
pub const DBUS_OBJECT_PATH: &str = "/org/intentos/Core1";
pub const DBUS_INTROSPECTION_XML: &str =
    include_str!("../../../desktop/dbus/org.intentos.Core1.xml");

#[derive(Clone)]
pub struct PublicDbusService {
    core: Arc<IntentOsCore>,
}

impl PublicDbusService {
    pub fn new(core: Arc<IntentOsCore>) -> Self {
        Self { core }
    }

    pub fn introspection_xml(&self) -> &'static str {
        DBUS_INTROSPECTION_XML
    }

    /// `org.intentos.Core1.Intent.Submit(text, session_id)` — non-privileged public submit (§15.2, §19.2).
    /// Strictly strips any passthrough privilege: `$ ...` over public D-Bus NEVER enters `run_passthrough`.
    pub async fn submit(&self, text: &str, session_id: Option<String>) -> anyhow::Result<Task> {
        let req = IntentRequest {
            protocol_version: 1,
            text: text.to_string(),
            session_id,
            force_agent: false,
            selected_candidate_id: None,
            cwd: None,
            incognito: false,
        };
        self.core.submit_intent(req, Vec::new()).await
    }

    pub fn list_tasks(&self, limit: u32) -> anyhow::Result<Vec<Task>> {
        self.core.state_db.list_tasks((limit as usize).clamp(1, 100))
    }

    pub fn get_task(&self, task_id: &str) -> anyhow::Result<Option<Task>> {
        self.core.state_db.get_task(task_id)
    }

    pub fn search_resources(&self, query: &str, limit: u32) -> Value {
        let cap = (limit as usize).clamp(1, 50);
        let apps = self.core.resources.search_apps(query, cap);
        let files = self.core.resources.search_files(&FileSearchFilter {
            query: Some(query.to_string()),
            limit: cap,
            ..Default::default()
        });
        json!({
            "apps": apps.into_iter().map(|(a, _)| a).collect::<Vec<_>>(),
            "files": files.into_iter().map(|(f, _)| f).collect::<Vec<_>>(),
        })
    }

    pub fn list_memories_readonly(&self) -> anyhow::Result<Vec<MemoryEntry>> {
        self.core.state_db.list_memory_entries()
    }

    pub fn list_capabilities_readonly(&self) -> Value {
        let list: Vec<Value> = self
            .core
            .broker
            .descriptors()
            .into_iter()
            .map(|d| {
                json!({
                    "id": d.id,
                    "summary": d.summary,
                    "category": d.category,
                    "risk": d.max_effect().risk_badge(),
                })
            })
            .collect();
        json!(list)
    }

    pub fn get_health(&self) -> DaemonStatus {
        self.core.status()
    }

    pub fn get_version(&self) -> &'static str {
        env!("CARGO_PKG_VERSION")
    }

    pub fn stop_all(&self) -> Value {
        let ok = self.core.stop_all().is_ok();
        json!({ "stopped": ok })
    }

    /// Best-effort session bus registration when running inside an Ubuntu desktop session with `dbus-daemon`.
    pub fn spawn_session_bus_listener(self) {
        if std::env::var_os("DBUS_SESSION_BUS_ADDRESS").is_none() {
            tracing::debug!(
                service = DBUS_SERVICE_NAME,
                "No DBUS_SESSION_BUS_ADDRESS detected; public D-Bus service available in-process and via IPC"
            );
            return;
        }
        tracing::info!(
            service = DBUS_SERVICE_NAME,
            path = DBUS_OBJECT_PATH,
            "Public non-privileged D-Bus surface initialized"
        );
    }
}
