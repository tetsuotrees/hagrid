use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

/// How a secret was located within a file.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum LocationKind {
    JsonPath,
    EnvVar,
    TomlKey,
    ShellExport,
    RawLine,
}

impl std::fmt::Display for LocationKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::JsonPath => write!(f, "json_path"),
            Self::EnvVar => write!(f, "env_var"),
            Self::TomlKey => write!(f, "toml_key"),
            Self::ShellExport => write!(f, "shell_export"),
            Self::RawLine => write!(f, "raw_line"),
        }
    }
}

impl LocationKind {
    pub fn from_str_loose(s: &str) -> Self {
        match s {
            "json_path" => Self::JsonPath,
            "env_var" => Self::EnvVar,
            "toml_key" => Self::TomlKey,
            "shell_export" => Self::ShellExport,
            _ => Self::RawLine,
        }
    }
}

/// Location within a file where a secret was found.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Location {
    pub kind: LocationKind,
    pub discriminator: String,
    pub line_number: Option<u32>,
}

/// Scan status of a reference.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ScanStatus {
    Present,
    Removed,
    Error,
}

impl std::fmt::Display for ScanStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Present => write!(f, "present"),
            Self::Removed => write!(f, "removed"),
            Self::Error => write!(f, "error"),
        }
    }
}

impl ScanStatus {
    pub fn from_str_loose(s: &str) -> Self {
        match s {
            "present" => Self::Present,
            "removed" => Self::Removed,
            _ => Self::Error,
        }
    }
}

/// A single discovered secret reference. Never contains the secret value.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretReference {
    pub identity_key: String,
    pub file_path: String,
    pub location: Location,
    pub provider_pattern: Option<String>,
    pub fingerprint: String,
    pub display_label: String,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub last_changed: DateTime<Utc>,
    pub scan_status: ScanStatus,
}

/// Why a grouping was suggested.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum SuggestionReason {
    ExactFingerprint,
    StructuralMatch,
    ProviderMatch,
    AgentProposal,
}

impl std::fmt::Display for SuggestionReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ExactFingerprint => write!(f, "exact_fingerprint"),
            Self::StructuralMatch => write!(f, "structural_match"),
            Self::ProviderMatch => write!(f, "provider_match"),
            Self::AgentProposal => write!(f, "agent_proposal"),
        }
    }
}

impl SuggestionReason {
    pub fn from_str_loose(s: &str) -> Self {
        match s {
            "exact_fingerprint" => Self::ExactFingerprint,
            "structural_match" => Self::StructuralMatch,
            "provider_match" => Self::ProviderMatch,
            _ => Self::AgentProposal,
        }
    }
}

/// Status of a suggestion.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum SuggestionStatus {
    Pending,
    Accepted,
    Rejected,
}

impl std::fmt::Display for SuggestionStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pending => write!(f, "pending"),
            Self::Accepted => write!(f, "accepted"),
            Self::Rejected => write!(f, "rejected"),
        }
    }
}

impl SuggestionStatus {
    pub fn from_str_loose(s: &str) -> Self {
        match s {
            "pending" => Self::Pending,
            "accepted" => Self::Accepted,
            _ => Self::Rejected,
        }
    }
}

/// A grouping suggestion awaiting user review.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Suggestion {
    pub suggestion_id: Uuid,
    pub reason: SuggestionReason,
    pub confidence: f64,
    pub reference_ids: Vec<String>,
    pub proposed_label: Option<String>,
    pub metadata: HashMap<String, String>,
    pub created_at: DateTime<Utc>,
    pub status: SuggestionStatus,
}

/// Status of a confirmed group.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum GroupStatus {
    Synced,
    Drifted,
    Stale,
    Degraded,
    Empty,
    Unknown,
}

impl std::fmt::Display for GroupStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Synced => write!(f, "synced"),
            Self::Drifted => write!(f, "drifted"),
            Self::Stale => write!(f, "stale"),
            Self::Degraded => write!(f, "degraded"),
            Self::Empty => write!(f, "empty"),
            Self::Unknown => write!(f, "unknown"),
        }
    }
}

impl GroupStatus {
    pub fn from_str_loose(s: &str) -> Self {
        match s {
            "synced" => Self::Synced,
            "drifted" => Self::Drifted,
            "stale" => Self::Stale,
            "degraded" => Self::Degraded,
            "empty" => Self::Empty,
            _ => Self::Unknown,
        }
    }
}

/// A user-confirmed group of related secret references.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretGroup {
    pub group_id: Uuid,
    pub label: String,
    pub members: Vec<String>,
    pub status: GroupStatus,
    pub created_at: DateTime<Utc>,
    pub confirmed_at: DateTime<Utc>,
}

/// A drift event recorded when group members diverge.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DriftEvent {
    pub group_id: Uuid,
    pub detected_at: DateTime<Utc>,
    pub member_fingerprints: HashMap<String, String>,
    pub resolved: bool,
    pub resolved_at: Option<DateTime<Utc>>,
}

/// Raw finding from a scanner before it becomes a SecretReference.
#[derive(Debug, Clone)]
pub struct RawFinding {
    pub file_path: String,
    pub location: Location,
    pub provider_pattern: Option<String>,
    pub display_label: String,
    pub secret_value: String,
}
