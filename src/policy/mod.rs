use regex::Regex;
use serde::Deserialize;
use std::collections::HashSet;
use thiserror::Error;

use crate::config;
use crate::index::db;
use crate::index::db::DbError;
use crate::index::models::{ScanStatus, SecretReference};

// ── Error type ──────────────────────────────────────────────────────

#[derive(Error, Debug)]
pub enum PolicyError {
    #[error("failed to read policies file: {0}")]
    ReadError(#[from] std::io::Error),
    #[error("failed to parse policies file: {0}")]
    ParseError(#[from] toml::de::Error),
    #[error("database error: {0}")]
    DbError(#[from] DbError),
    #[error("invalid pattern: {0}")]
    InvalidPattern(String),
    #[error("invalid config: {0}")]
    InvalidConfig(String),
    #[error("git binary not found")]
    GitNotFound,
}

// ── Types ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize)]
pub struct PolicyFile {
    #[serde(default)]
    pub policy: Vec<PolicyDef>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PolicyDef {
    pub name: String,
    #[serde(rename = "match", deserialize_with = "deserialize_match")]
    pub match_patterns: Vec<String>,
    pub max_age_days: Option<u64>,
    pub warn_at_days: Option<u64>,
    pub require_vault: Option<bool>,
    pub max_references: Option<usize>,
    pub no_git: Option<bool>,
}

fn deserialize_match<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum StringOrVec {
        Single(String),
        Multiple(Vec<String>),
    }

    match StringOrVec::deserialize(deserializer)? {
        StringOrVec::Single(s) => Ok(vec![s]),
        StringOrVec::Multiple(v) => Ok(v),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Severity {
    Pass,
    Warn,
    Violation,
}

#[derive(Debug, Clone)]
pub struct PolicyResult {
    pub rule_name: String,
    pub severity: Severity,
    pub message: String,
    pub affected_references: Vec<AffectedRef>,
}

#[derive(Debug, Clone)]
pub struct AffectedRef {
    pub identity_key: String,
    pub display_label: String,
    pub file_path: String,
}

// ── Loading ─────────────────────────────────────────────────────────

pub fn load_policies() -> Result<Vec<PolicyDef>, PolicyError> {
    let path = config::policies_path();
    let content = match std::fs::read_to_string(&path) {
        Ok(c) => c,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(PolicyError::ReadError(e)),
    };

    let file: PolicyFile = toml::from_str(&content)?;

    // Validate warn_at_days <= max_age_days when both are set
    for p in &file.policy {
        if let (Some(warn), Some(max)) = (p.warn_at_days, p.max_age_days) {
            if warn > max {
                return Err(PolicyError::InvalidConfig(format!(
                    "policy '{}': warn_at_days ({}) must be <= max_age_days ({})",
                    p.name, warn, max
                )));
            }
        }
    }

    Ok(file.policy)
}

// ── Evaluation ──────────────────────────────────────────────────────

pub fn evaluate_policies(
    conn: &rusqlite::Connection,
    policies: &[PolicyDef],
) -> Result<Vec<PolicyResult>, PolicyError> {
    let all_refs = db::list_references(conn)?;

    // Filter to Present refs only (per feedback #10)
    let refs: Vec<&SecretReference> = all_refs
        .iter()
        .filter(|r| r.scan_status == ScanStatus::Present)
        .collect();

    let mut results = Vec::new();

    for policy in policies {
        // Compile patterns
        let is_wildcard = policy.match_patterns.iter().any(|p| p == "*");
        let compiled: Vec<Regex> = policy
            .match_patterns
            .iter()
            .filter(|p| *p != "*")
            .map(|p| glob_to_regex(p))
            .collect::<Result<Vec<_>, _>>()?;

        if let Some(max) = policy.max_references {
            results.push(eval_max_references(policy, &compiled, is_wildcard, &refs, max));
        }

        if policy.no_git == Some(true) {
            results.push(eval_no_git(policy, &compiled, is_wildcard, &refs)?);
        }

        if policy.max_age_days.is_some() || policy.warn_at_days.is_some() {
            results.push(eval_max_age(
                policy,
                &compiled,
                is_wildcard,
                &refs,
                policy.max_age_days,
                policy.warn_at_days,
            ));
        }

        if policy.require_vault == Some(true) {
            results.push(eval_require_vault(policy, &compiled, is_wildcard, &refs));
        }
    }

    Ok(results)
}

// ── Pattern matching ────────────────────────────────────────────────

pub fn glob_to_regex(pattern: &str) -> Result<Regex, PolicyError> {
    let mut regex_str = String::from("^");
    for ch in pattern.chars() {
        match ch {
            '*' => regex_str.push_str(".*"),
            '?' => regex_str.push('.'),
            '.' | '+' | '(' | ')' | '[' | ']' | '{' | '}' | '|' | '^' | '$' | '\\' => {
                regex_str.push('\\');
                regex_str.push(ch);
            }
            _ => regex_str.push(ch),
        }
    }
    regex_str.push('$');
    Regex::new(&regex_str).map_err(|e| PolicyError::InvalidPattern(e.to_string()))
}

pub fn matches_rule(
    compiled_patterns: &[Regex],
    is_wildcard: bool,
    reference: &SecretReference,
) -> bool {
    // Wildcard matches ALL refs unconditionally, including provider_pattern=None
    if is_wildcard {
        return true;
    }

    // Non-wildcard: match against provider_pattern only (not display_label)
    // Refs with provider_pattern=None do not match non-wildcard patterns
    match &reference.provider_pattern {
        Some(provider) => compiled_patterns.iter().any(|re| re.is_match(provider)),
        None => false,
    }
}

// ── Rule evaluators ─────────────────────────────────────────────────

fn eval_max_references(
    rule: &PolicyDef,
    patterns: &[Regex],
    is_wildcard: bool,
    refs: &[&SecretReference],
    max: usize,
) -> PolicyResult {
    let matching: Vec<&SecretReference> = refs
        .iter()
        .filter(|r| matches_rule(patterns, is_wildcard, r))
        .copied()
        .collect();

    // Dedupe by (file_path, fingerprint) per feedback #2
    let mut seen = HashSet::new();
    let deduped: Vec<&SecretReference> = matching
        .iter()
        .filter(|r| seen.insert((r.file_path.as_str(), r.fingerprint.as_str())))
        .copied()
        .collect();

    let count = deduped.len();

    if count > max {
        PolicyResult {
            rule_name: rule.name.clone(),
            severity: Severity::Violation,
            message: format!(
                "found {} unique references (max {})",
                count, max
            ),
            affected_references: deduped
                .iter()
                .map(|r| AffectedRef {
                    identity_key: r.identity_key.clone(),
                    display_label: r.display_label.clone(),
                    file_path: r.file_path.clone(),
                })
                .collect(),
        }
    } else {
        PolicyResult {
            rule_name: rule.name.clone(),
            severity: Severity::Pass,
            message: format!("found {} unique references (max {})", count, max),
            affected_references: Vec::new(),
        }
    }
}

fn eval_no_git(
    rule: &PolicyDef,
    patterns: &[Regex],
    is_wildcard: bool,
    refs: &[&SecretReference],
) -> Result<PolicyResult, PolicyError> {
    let matching: Vec<&SecretReference> = refs
        .iter()
        .filter(|r| matches_rule(patterns, is_wildcard, r))
        .copied()
        .collect();

    let mut violations = Vec::new();

    for r in &matching {
        let path = std::path::Path::new(&r.file_path);
        let parent = match path.parent() {
            Some(p) if p.exists() => p,
            // Parent doesn't exist or file is at root → skip (not a violation)
            _ => continue,
        };

        // Find the git repo root
        let repo_root = std::process::Command::new("git")
            .args(["-C", &parent.to_string_lossy(), "rev-parse", "--show-toplevel"])
            .output();

        let output = match repo_root {
            Ok(o) => o,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(PolicyError::GitNotFound);
            }
            Err(_) => continue, // other errors → skip
        };

        if !output.status.success() {
            // Not inside a git repo → skip (not a violation)
            continue;
        }

        // Check if file is tracked
        let tracked = std::process::Command::new("git")
            .args([
                "-C",
                &parent.to_string_lossy(),
                "ls-files",
                "--error-unmatch",
                &r.file_path,
            ])
            .output();

        match tracked {
            Ok(o) if o.status.success() => {
                violations.push(AffectedRef {
                    identity_key: r.identity_key.clone(),
                    display_label: r.display_label.clone(),
                    file_path: r.file_path.clone(),
                });
            }
            Ok(_) => {} // not tracked → pass
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(PolicyError::GitNotFound);
            }
            Err(_) => continue,
        }
    }

    if violations.is_empty() {
        Ok(PolicyResult {
            rule_name: rule.name.clone(),
            severity: Severity::Pass,
            message: "no tracked files found".to_string(),
            affected_references: Vec::new(),
        })
    } else {
        Ok(PolicyResult {
            rule_name: rule.name.clone(),
            severity: Severity::Violation,
            message: format!(
                "{} secret(s) found in git-tracked files",
                violations.len()
            ),
            affected_references: violations,
        })
    }
}

fn eval_max_age(
    rule: &PolicyDef,
    patterns: &[Regex],
    is_wildcard: bool,
    refs: &[&SecretReference],
    max_days: Option<u64>,
    warn_days: Option<u64>,
) -> PolicyResult {
    let matching: Vec<&SecretReference> = refs
        .iter()
        .filter(|r| matches_rule(patterns, is_wildcard, r))
        .copied()
        .collect();

    let now = chrono::Utc::now();
    let mut worst_severity = Severity::Pass;
    let mut affected = Vec::new();
    let mut message_parts = Vec::new();

    for r in &matching {
        let age = now.signed_duration_since(r.last_changed);
        let age_days = age.num_days() as u64;

        if let Some(max) = max_days {
            if age_days > max {
                if worst_severity != Severity::Violation {
                    worst_severity = Severity::Violation;
                }
                affected.push(AffectedRef {
                    identity_key: r.identity_key.clone(),
                    display_label: r.display_label.clone(),
                    file_path: r.file_path.clone(),
                });
                continue;
            }
        }

        if let Some(warn) = warn_days {
            if age_days > warn {
                if worst_severity == Severity::Pass {
                    worst_severity = Severity::Warn;
                }
                affected.push(AffectedRef {
                    identity_key: r.identity_key.clone(),
                    display_label: r.display_label.clone(),
                    file_path: r.file_path.clone(),
                });
            }
        }
    }

    match worst_severity {
        Severity::Violation => {
            message_parts.push(format!(
                "secrets exceed max age of {} days",
                max_days.unwrap()
            ));
        }
        Severity::Warn => {
            message_parts.push(format!(
                "secrets approaching max age (warn at {} days)",
                warn_days.unwrap()
            ));
        }
        Severity::Pass => {
            message_parts.push("all secrets within age limits".to_string());
        }
    }

    PolicyResult {
        rule_name: rule.name.clone(),
        severity: worst_severity,
        message: message_parts.join("; "),
        affected_references: affected,
    }
}

fn eval_require_vault(
    rule: &PolicyDef,
    _patterns: &[Regex],
    _is_wildcard: bool,
    _refs: &[&SecretReference],
) -> PolicyResult {
    PolicyResult {
        rule_name: rule.name.clone(),
        severity: Severity::Warn,
        message: "require_vault is not yet implemented — treating as warning".to_string(),
        affected_references: Vec::new(),
    }
}
