//! SC-08 deferred explicit-argv pipeline draft, NOT an executor.
//! No shell string grammar, filesystem redirects or execution are enabled.
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

pub const SHELL_PLAN_DRAFT_VERSION: u32 = 1;
pub const MAX_DRAFT_STEPS: usize = 8;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PipelineDraftStep {
    pub step_id: String,
    pub program: String,
    #[serde(default)]
    pub argv: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShellPlanDraftV1 {
    pub version: u32,
    /// Explicit argv steps only. Operators are data, never passed to a shell.
    pub steps: Vec<PipelineDraftStep>,
    /// One pipe between adjacent steps, no conditionals in v1.
    #[serde(default)]
    pub operators: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DraftValidation {
    pub version: u32,
    /// There is intentionally no approved executor, even for valid drafts.
    pub executable: bool,
    pub steps: usize,
    pub status: String,
}

/// Validate a non-executable draft; caller must never pass it to bash -c.
/// Future execution requires frozen identities, scoped Broker/Policy grants,
/// L2 isolation and process-group recovery from SC-03/04.
pub fn validate_shell_plan_draft(
    draft: &ShellPlanDraftV1,
) -> Result<DraftValidation, &'static str> {
    if draft.version != SHELL_PLAN_DRAFT_VERSION {
        return Err("unsupported_plan_version");
    }
    if draft.steps.is_empty() || draft.steps.len() > MAX_DRAFT_STEPS {
        return Err("invalid_step_count");
    }
    if draft.operators.len() != draft.steps.len() - 1 {
        return Err("invalid_pipeline_arity");
    }
    if draft.operators.iter().any(|op| op != "pipe") {
        return Err("unsupported_syntax");
    }
    let mut ids = HashSet::new();
    for s in &draft.steps {
        if s.step_id.trim().is_empty() || !ids.insert(s.step_id.as_str()) {
            return Err("invalid_step_identity");
        }
        if s.program.trim().is_empty()
            || s.program.chars().any(|c| c.is_whitespace() || matches!(c, ';' | '|' | '&' | '<' | '>' | '`' | '$' | '\0'))
        {
            return Err("unsupported_syntax");
        }
        if s.argv.len() > 256 || s.argv.iter().any(|a| a.len() > 16384 || a.contains('\0')) {
            return Err("resource_limit");
        }
    }
    Ok(DraftValidation {
        version: SHELL_PLAN_DRAFT_VERSION,
        executable: false,
        steps: draft.steps.len(),
        status: "draft_only_requires_sc03_sc04_and_l2".to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn candidate() -> ShellPlanDraftV1 {
        ShellPlanDraftV1 {
            version: 1,
            steps: vec![
                PipelineDraftStep { step_id: "a".into(), program: "printf".into(), argv: vec!["hello".into()] },
                PipelineDraftStep { step_id: "b".into(), program: "wc".into(), argv: vec!["-c".into()] },
            ],
            operators: vec!["pipe".into()],
        }
    }

    #[test]
    fn sc08_valid_pipeline_is_still_not_executable() {
        let v = validate_shell_plan_draft(&candidate()).unwrap();
        assert!(!v.executable);
        assert_eq!(v.steps, 2);
    }

    #[test]
    fn sc08_rejects_conditional_and_shell_escape_as_unsupported_syntax() {
        let mut p = candidate();
        p.operators = vec!["&&".into()];
        assert_eq!(validate_shell_plan_draft(&p).unwrap_err(), "unsupported_syntax");
        p.operators = vec!["pipe".into()];
        p.steps[0].program = "bash -c".into();
        assert_eq!(validate_shell_plan_draft(&p).unwrap_err(), "unsupported_syntax");
        p.steps[0].program = "echo;id".into();
        assert_eq!(validate_shell_plan_draft(&p).unwrap_err(), "unsupported_syntax");
    }

    #[test]
    fn sc08_rejects_duplicate_step_ids_and_extra_redirection_fields() {
        let mut p = candidate();
        p.steps[1].step_id = "a".into();
        assert_eq!(validate_shell_plan_draft(&p).unwrap_err(), "invalid_step_identity");
        let raw = r#"{"version":1,"steps":[{"step_id":"a","program":"echo","argv":[],"redirect":"/tmp/file"}],"operators":[]}"#;
        assert!(serde_json::from_str::<ShellPlanDraftV1>(raw).is_err());
    }
}
