//! SC-05: read-only, action-level compatibility observations.
//! A desktop entry or adapter declaration is NOT an Ubuntu/Wayland certification.
use super::local_scanner::{ScannedSoftwareEntry, SynthesizedActionSpec};
use serde::{Deserialize, Serialize};

pub const MATRIX_SCHEMA_VERSION: u32 = 1;

/// No mutation API for this type. Certification is intentionally unavailable
/// until real L2/L3 evidence can be recorded by a separately reviewed pathway.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CertificationState {
    Unverified,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionCompatibilityV1 {
    pub schema_version: u32,
    pub app_id: String,
    pub desktop_id: String,
    pub display_name: String,
    pub package_format: String,
    /// Not available from .desktop enumeration; never invent from an adapter name.
    pub observed_version: Option<String>,
    pub action_id: String,
    pub channel: String,
    pub discovery_state: String,
    pub certification_state: CertificationState,
    pub verification_reason: String,
    pub environment_requirements: Vec<String>,
    pub requires_approval: bool,
    /// The query is read-only. Execution stays in the existing Broker/Policy path.
    pub execution_enabled_by_matrix: bool,
    pub source: String,
}

pub fn action_observation(
    app_id: &str,
    desktop_id: &str,
    display_name: &str,
    package_format: &str,
    action: &SynthesizedActionSpec,
) -> ActionCompatibilityV1 {
    let mut requirements = Vec::new();
    let channel = action.channel.to_ascii_lowercase();
    if channel.contains("gui") || channel.contains("atspi") || channel.contains("window") {
        requirements.push("live_desktop_session".to_string());
        requirements.push("window_or_accessibility_permission".to_string());
    }
    if channel.contains("mpris") || channel.contains("sni") || channel.contains("dbus") {
        requirements.push("session_dbus_interface".to_string());
    }
    if package_format.eq_ignore_ascii_case("flatpak") || package_format.eq_ignore_ascii_case("snap")
    {
        requirements.push("package_sandbox_interface_permission_unverified".to_string());
    }
    ActionCompatibilityV1 {
        schema_version: MATRIX_SCHEMA_VERSION,
        app_id: app_id.to_owned(),
        desktop_id: desktop_id.to_owned(),
        display_name: display_name.to_owned(),
        package_format: package_format.to_owned(),
        observed_version: None,
        action_id: action.action.clone(),
        channel: action.channel.clone(),
        discovery_state: "desktop_entry_observed".to_string(),
        certification_state: CertificationState::Unverified,
        verification_reason: "No action-level real-environment verification evidence".to_string(),
        environment_requirements: requirements,
        requires_approval: action.requires_approval,
        execution_enabled_by_matrix: false,
        source: action.source.clone(),
    }
}

pub fn observations_for_app(entry: &ScannedSoftwareEntry) -> Vec<ActionCompatibilityV1> {
    let mut result: Vec<ActionCompatibilityV1> = entry
        .synthesized_actions
        .iter()
        .map(|a| {
            action_observation(
                &entry.id,
                &entry.desktop_id,
                &entry.display_name,
                &entry.install_source,
                a,
            )
        })
        .collect();
    result.sort_by(|a, b| {
        a.action_id
            .cmp(&b.action_id)
            .then(a.channel.cmp(&b.channel))
    });
    result.dedup_by(|a, b| a.action_id == b.action_id && a.channel == b.channel);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn action() -> SynthesizedActionSpec {
        SynthesizedActionSpec {
            action: "focus".to_owned(),
            label: "聚焦".to_owned(),
            channel: "gui_atspi".to_owned(),
            description: "window focus".to_owned(),
            requires_approval: true,
            source: "desktop_profile".to_owned(),
        }
    }

    #[test]
    fn sc05_discovered_action_never_becomes_certified_or_enabled() {
        let record = action_observation(
            "org.test.App",
            "org.test.App.desktop",
            "App",
            "system_apt",
            &action(),
        );
        assert_eq!(record.schema_version, 1);
        assert_eq!(record.certification_state, CertificationState::Unverified);
        assert_eq!(record.observed_version, None);
        assert!(!record.execution_enabled_by_matrix);
        assert!(
            record
                .environment_requirements
                .contains(&"live_desktop_session".to_owned())
        );
    }

    #[test]
    fn sc05_flatpak_and_snap_desktop_entries_do_not_imply_sandbox_access() {
        for format in ["flatpak", "snap"] {
            let record = action_observation("x", "x.desktop", "X", format, &action());
            assert_eq!(record.certification_state, CertificationState::Unverified);
            assert!(
                record
                    .environment_requirements
                    .iter()
                    .any(|x| x.contains("sandbox"))
            );
            assert!(!record.execution_enabled_by_matrix);
        }
    }

    #[test]
    fn sc05_contract_json_has_stable_version_and_explicit_uncertainty() {
        let v = serde_json::to_value(action_observation(
            "x",
            "x.desktop",
            "X",
            "user_local",
            &action(),
        ))
        .unwrap();
        assert_eq!(v["schema_version"], 1);
        assert_eq!(v["certification_state"], "unverified");
        assert!(v["observed_version"].is_null());
        assert_eq!(v["execution_enabled_by_matrix"], false);
    }
}
