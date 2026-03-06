use serde::{Deserialize, Serialize};
use std::path::Path;

use crate::drift::DriftCheckResult;
use crate::policy::{PolicyResult, Severity};
use crate::rotate::RotateResult;

// ── Types ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize)]
pub struct NotificationConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
    #[serde(default)]
    pub webhook: Vec<WebhookConfig>,
}

impl Default for NotificationConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            timeout_ms: default_timeout_ms(),
            webhook: Vec::new(),
        }
    }
}

fn default_timeout_ms() -> u64 {
    2000
}

#[derive(Debug, Clone, Deserialize)]
pub struct WebhookConfig {
    pub name: String,
    pub url: String,
    #[serde(default)]
    pub events: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EventKind {
    DriftDetected,
    PolicyViolations,
    RotationFailure,
}

impl EventKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            EventKind::DriftDetected => "drift_detected",
            EventKind::PolicyViolations => "policy_violations",
            EventKind::RotationFailure => "rotation_failure",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct NotificationEvent {
    pub event: EventKind,
    pub timestamp: String,
    pub hostname: String,
    pub exit_code: i32,
    pub summary: String,
    pub details: serde_json::Value,
}

// ── Config loading (failure-safe by construction) ───────────────────

pub fn load_notification_config() -> NotificationConfig {
    load_notification_config_from_path(&crate::config::notifications_path())
}

pub fn load_notification_config_from_path(path: &Path) -> NotificationConfig {
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return NotificationConfig::default();
        }
        Err(e) => {
            eprintln!("warning: could not read notification config: {}", e);
            return NotificationConfig::default();
        }
    };

    match toml::from_str::<NotificationConfig>(&content) {
        Ok(config) => config,
        Err(e) => {
            eprintln!("warning: malformed notification config: {}", e);
            NotificationConfig::default()
        }
    }
}

// ── Dispatch (failure-isolated by construction) ─────────────────────

pub fn dispatch(event: &NotificationEvent) {
    let config = load_notification_config();
    dispatch_with_config(&config, event);
}

pub fn dispatch_with_config(config: &NotificationConfig, event: &NotificationEvent) {
    if !config.enabled {
        return;
    }

    let event_str = event.event.as_str();

    let payload = match serde_json::to_vec(event) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("warning: failed to serialize notification: {}", e);
            return;
        }
    };

    for hook in &config.webhook {
        // Empty events list = subscribe to all
        if !hook.events.is_empty() && !hook.events.iter().any(|e| e == event_str) {
            continue;
        }

        if let Err(e) = deliver_to_webhook(hook, &payload, config.timeout_ms) {
            eprintln!("warning: webhook '{}' delivery failed: {}", hook.name, e);
        }
    }
}

pub fn deliver_to_webhook(
    hook: &WebhookConfig,
    payload: &[u8],
    timeout_ms: u64,
) -> Result<(), String> {
    let agent = ureq::AgentBuilder::new()
        .timeout(std::time::Duration::from_millis(timeout_ms))
        .build();

    let resp = agent
        .post(&hook.url)
        .set("Content-Type", "application/json")
        .send_bytes(payload);

    match resp {
        Ok(r) if r.status() >= 200 && r.status() < 300 => Ok(()),
        Ok(r) => Err(format!("HTTP {}", r.status())),
        Err(e) => Err(e.to_string()),
    }
}

// ── Payload builders ────────────────────────────────────────────────

pub fn build_drift_event(exit_code: i32, results: &[DriftCheckResult]) -> NotificationEvent {
    let groups_checked = results.len();
    let groups_drifted = results.iter().filter(|r| r.drifted).count();

    let per_group: Vec<serde_json::Value> = results
        .iter()
        .map(|r| {
            serde_json::json!({
                "label": r.group_label,
                "group_id": r.group_id.to_string(),
                "status": r.status.to_string(),
            })
        })
        .collect();

    NotificationEvent {
        event: EventKind::DriftDetected,
        timestamp: now_iso8601(),
        hostname: hostname(),
        exit_code,
        summary: format!(
            "{} of {} group(s) drifted",
            groups_drifted, groups_checked
        ),
        details: serde_json::json!({
            "groups_checked": groups_checked,
            "groups_drifted": groups_drifted,
            "groups": per_group,
        }),
    }
}

pub fn build_audit_event(exit_code: i32, results: &[PolicyResult]) -> NotificationEvent {
    let violations = results
        .iter()
        .filter(|r| r.severity == Severity::Violation)
        .count();
    let warnings = results
        .iter()
        .filter(|r| r.severity == Severity::Warn)
        .count();

    let per_rule: Vec<serde_json::Value> = results
        .iter()
        .filter(|r| r.severity != Severity::Pass)
        .map(|r| {
            serde_json::json!({
                "rule_name": r.rule_name,
                "message": r.message,
                "affected_count": r.affected_references.len(),
                "affected_files": r.affected_references.iter()
                    .map(|a| a.file_path.as_str())
                    .collect::<Vec<_>>(),
            })
        })
        .collect();

    NotificationEvent {
        event: EventKind::PolicyViolations,
        timestamp: now_iso8601(),
        hostname: hostname(),
        exit_code,
        summary: format!(
            "{} violation(s), {} warning(s)",
            violations, warnings
        ),
        details: serde_json::json!({
            "violations": violations,
            "warnings": warnings,
            "rules": per_rule,
        }),
    }
}

pub fn build_rotate_event(
    exit_code: i32,
    group_label: &str,
    result: &RotateResult,
) -> NotificationEvent {
    let per_failure: Vec<serde_json::Value> = result
        .file_results
        .iter()
        .filter(|fr| !fr.success)
        .map(|fr| {
            serde_json::json!({
                "file_path": fr.file_path,
                "error": fr.error.as_deref().unwrap_or("unknown error"),
            })
        })
        .collect();

    NotificationEvent {
        event: EventKind::RotationFailure,
        timestamp: now_iso8601(),
        hostname: hostname(),
        exit_code,
        summary: format!(
            "rotation of '{}': {} succeeded, {} failed, {} skipped",
            group_label, result.succeeded, result.failed, result.skipped
        ),
        details: serde_json::json!({
            "group_label": group_label,
            "total_members": result.total_members,
            "succeeded": result.succeeded,
            "failed": result.failed,
            "skipped": result.skipped,
            "failures": per_failure,
        }),
    }
}

// ── Helpers ─────────────────────────────────────────────────────────

fn hostname() -> String {
    std::process::Command::new("hostname")
        .output()
        .ok()
        .and_then(|o| {
            if o.status.success() {
                String::from_utf8(o.stdout).ok().map(|s| s.trim().to_string())
            } else {
                None
            }
        })
        .unwrap_or_else(|| "unknown".to_string())
}

fn now_iso8601() -> String {
    chrono::Utc::now().to_rfc3339()
}
