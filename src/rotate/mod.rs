use std::collections::HashMap;
use std::path::Path;

use serde::Serialize;
use thiserror::Error;

use crate::index::db;
use crate::index::fingerprint::{self, DerivedKeys};
use crate::index::models::*;
use crate::scan::engine::{self, ScanDepth};
use crate::scan::patterns::CompiledPattern;

// ── Error type ──────────────────────────────────────────────────────

#[derive(Error, Debug)]
pub enum RotateError {
    #[error("group not found: {0}")]
    GroupNotFound(String),
    #[error("group has no present members")]
    NoMembers,
    #[error("reference not found: {0}")]
    ReferenceNotFound(String),
    #[error("could not extract current value from {0}: {1}")]
    ValueExtraction(String, String),
    #[error("fingerprint mismatch for {0}: file may have changed since last scan")]
    FingerprintMismatch(String),
    #[error("stale line reference in {0}: {1}")]
    StaleLineReference(String, String),
    #[error("value not found in file {0}")]
    ValueNotFound(String),
    #[error("mixed location kinds in {0}: run `hagrid scan` to consolidate references")]
    MixedLocationKinds(String),
    #[error("file write failed for {0}: {1}")]
    WriteFailed(String, String),
    #[error("verification failed for {0}: {1}")]
    VerificationFailed(String, String),
    #[error("database error: {0}")]
    DbError(#[from] db::DbError),
    #[error("io error: {0}")]
    IoError(#[from] std::io::Error),
}

// ── Types ───────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct MemberInfo {
    pub identity_key: String,
    pub file_path: String,
    pub location: Location,
    pub fingerprint: String,
    pub display_label: String,
    pub scan_status: ScanStatus,
}

#[derive(Debug, Clone, Serialize)]
pub struct RotateInfoReport {
    pub group_label: String,
    pub group_id: String,
    pub group_status: String,
    pub member_count: usize,
    pub unique_fingerprints: usize,
    pub drifted: bool,
    pub members: Vec<RotateInfoMember>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RotateInfoMember {
    pub identity_key: String,
    pub file_path: String,
    pub location_kind: String,
    pub discriminator: String,
    pub line_number: Option<u32>,
    pub fingerprint: String,
    pub display_label: String,
    pub scan_status: String,
}

#[derive(Debug)]
pub struct FileRotateResult {
    pub file_path: String,
    pub identity_key: String,
    pub success: bool,
    pub error: Option<String>,
    pub backed_up: bool,
    pub verified: bool,
}

#[derive(Debug)]
pub struct RotateResult {
    pub total_members: usize,
    pub succeeded: usize,
    pub failed: usize,
    pub skipped: usize,
    pub file_results: Vec<FileRotateResult>,
}

fn push_success_result(result: &mut RotateResult, member: &MemberInfo, backed_up: bool) {
    result.file_results.push(FileRotateResult {
        file_path: member.file_path.clone(),
        identity_key: member.identity_key.clone(),
        success: true,
        error: None,
        backed_up,
        verified: true,
    });
    result.succeeded += 1;
}

fn push_failure_result(
    result: &mut RotateResult,
    member: &MemberInfo,
    error: String,
    backed_up: bool,
) {
    result.file_results.push(FileRotateResult {
        file_path: member.file_path.clone(),
        identity_key: member.identity_key.clone(),
        success: false,
        error: Some(error),
        backed_up,
        verified: false,
    });
    result.failed += 1;
}

fn rollback_file(file_path: &Path, original_content: &str) -> Result<(), RotateError> {
    atomic_write(file_path, original_content, false).map(|_| ())
}

fn scan_fingerprints_by_identity(
    findings: &[crate::index::models::RawFinding],
    keys: &DerivedKeys,
) -> HashMap<String, String> {
    findings
        .iter()
        .map(|finding| {
            let identity = fingerprint::compute_identity(
                &keys.identity_key,
                &finding.file_path,
                &finding.location.kind,
                &finding.location.discriminator,
                "file",
            );
            let fingerprint =
                fingerprint::compute_fingerprint(&keys.fingerprint_key, &finding.secret_value);
            (identity, fingerprint)
        })
        .collect()
}

fn verify_members_against_findings(
    file_path: &str,
    members: &[&MemberInfo],
    expected_fingerprint: &str,
    findings: &[crate::index::models::RawFinding],
    keys: &DerivedKeys,
) -> Result<(), RotateError> {
    let scanned = scan_fingerprints_by_identity(findings, keys);

    for member in members {
        match scanned.get(&member.identity_key) {
            Some(fingerprint) if fingerprint == expected_fingerprint => {}
            Some(_) => {
                return Err(RotateError::VerificationFailed(
                    file_path.to_string(),
                    format!(
                        "fingerprint mismatch after write for {}",
                        member.location.discriminator
                    ),
                ));
            }
            None => {
                return Err(RotateError::VerificationFailed(
                    file_path.to_string(),
                    format!(
                        "rotated reference not found after write for {}",
                        member.location.discriminator
                    ),
                ));
            }
        }
    }

    Ok(())
}

fn verify_members_in_file(
    file_path: &str,
    members: &[&MemberInfo],
    expected_fingerprint: &str,
    keys: &DerivedKeys,
    patterns: &[CompiledPattern],
) -> Result<(), RotateError> {
    let findings = engine::scan_single_file(Path::new(file_path), patterns, ScanDepth::Standard)
        .map_err(|e| RotateError::VerificationFailed(file_path.to_string(), e))?;
    verify_members_against_findings(file_path, members, expected_fingerprint, &findings, keys)
}

// ── Gathering info ──────────────────────────────────────────────────

pub fn gather_rotate_info(
    conn: &rusqlite::Connection,
    group_label: &str,
) -> Result<(SecretGroup, Vec<MemberInfo>), RotateError> {
    let group = match db::get_group_by_label(conn, group_label)? {
        Some(g) => g,
        None => return Err(RotateError::GroupNotFound(group_label.to_string())),
    };

    let member_keys = db::get_group_members(conn, &group.group_id.to_string())?;
    let mut members = Vec::new();

    for key in &member_keys {
        match db::get_reference(conn, key)? {
            Some(r) => members.push(MemberInfo {
                identity_key: r.identity_key,
                file_path: r.file_path,
                location: r.location,
                fingerprint: r.fingerprint,
                display_label: r.display_label,
                scan_status: r.scan_status,
            }),
            None => {
                return Err(RotateError::ReferenceNotFound(key.clone()));
            }
        }
    }

    Ok((group, members))
}

pub fn build_info_report(group: &SecretGroup, members: &[MemberInfo]) -> RotateInfoReport {
    let present: Vec<&MemberInfo> = members
        .iter()
        .filter(|m| m.scan_status == ScanStatus::Present)
        .collect();

    let unique_fps: std::collections::HashSet<&str> =
        present.iter().map(|m| m.fingerprint.as_str()).collect();

    RotateInfoReport {
        group_label: group.label.clone(),
        group_id: group.group_id.to_string(),
        group_status: group.status.to_string(),
        member_count: members.len(),
        unique_fingerprints: unique_fps.len(),
        drifted: unique_fps.len() > 1,
        members: members
            .iter()
            .map(|m| RotateInfoMember {
                identity_key: m.identity_key.clone(),
                file_path: m.file_path.clone(),
                location_kind: m.location.kind.to_string(),
                discriminator: m.location.discriminator.clone(),
                line_number: m.location.line_number,
                fingerprint: m.fingerprint.clone(),
                display_label: m.display_label.clone(),
                scan_status: m.scan_status.to_string(),
            })
            .collect(),
    }
}

// ── Value extraction ────────────────────────────────────────────────

pub fn find_current_value(
    member: &MemberInfo,
    keys: &DerivedKeys,
    patterns: &[CompiledPattern],
) -> Result<String, RotateError> {
    let path = Path::new(&member.file_path);
    if !path.exists() {
        return Err(RotateError::ValueExtraction(
            member.file_path.clone(),
            "file does not exist".to_string(),
        ));
    }

    let findings = engine::scan_single_file(path, patterns, ScanDepth::Standard)
        .map_err(|e| RotateError::ValueExtraction(member.file_path.clone(), e))?;

    // Match by computed identity_key against ALL findings (not just RawLine)
    for f in &findings {
        let computed_id = fingerprint::compute_identity(
            &keys.identity_key,
            &f.file_path,
            &f.location.kind,
            &f.location.discriminator,
            "file",
        );

        if computed_id == member.identity_key {
            // Verify fingerprint matches what's in the DB
            let computed_fp =
                fingerprint::compute_fingerprint(&keys.fingerprint_key, &f.secret_value);
            if computed_fp != member.fingerprint {
                return Err(RotateError::FingerprintMismatch(member.file_path.clone()));
            }
            return Ok(f.secret_value.clone());
        }
    }

    // No identity match — handle stale RawLine case
    if member.location.kind == LocationKind::RawLine {
        // Check if the fingerprint still exists in any finding (line shifted)
        for f in &findings {
            let fp = fingerprint::compute_fingerprint(&keys.fingerprint_key, &f.secret_value);
            if fp == member.fingerprint {
                return Err(RotateError::StaleLineReference(
                    member.file_path.clone(),
                    "line number shifted — run `hagrid scan` to refresh before retrying"
                        .to_string(),
                ));
            }
        }
    }

    Err(RotateError::ValueExtraction(
        member.file_path.clone(),
        "value not found in file".to_string(),
    ))
}

// ── Format-aware replacement ────────────────────────────────────────

/// A single replacement to apply within a file.
pub struct Replacement<'a> {
    pub member: &'a MemberInfo,
    pub old_value: String,
    pub new_value: String,
}

/// Apply all replacements to file content, returning modified content.
/// For JSON/TOML files, uses path-aware structured mutation.
/// For EnvVar/ShellExport/RawLine, uses line-targeted replacement.
pub fn replace_in_file(
    content: &str,
    replacements: &[Replacement<'_>],
) -> Result<String, RotateError> {
    if replacements.is_empty() {
        return Ok(content.to_string());
    }

    // Check for mixed location kinds (e.g., RawLine + EnvVar in same file)
    let kinds: std::collections::HashSet<&LocationKind> = replacements
        .iter()
        .map(|r| &r.member.location.kind)
        .collect();
    let has_rawline = kinds.contains(&LocationKind::RawLine);
    let has_structural = kinds.iter().any(|k| **k != LocationKind::RawLine);
    if has_rawline && has_structural {
        return Err(RotateError::MixedLocationKinds(
            replacements[0].member.file_path.clone(),
        ));
    }

    // Dispatch by location kind of the first replacement
    let kind = &replacements[0].member.location.kind;

    match kind {
        LocationKind::JsonPath => replace_json_path_aware(content, replacements),
        LocationKind::TomlKey => replace_toml_path_aware(content, replacements),
        LocationKind::EnvVar | LocationKind::ShellExport | LocationKind::RawLine => {
            replace_line_targeted(content, replacements)
        }
    }
}

/// JSON: parse → navigate to each discriminator path → verify → mutate → serialize.
fn replace_json_path_aware(
    content: &str,
    replacements: &[Replacement<'_>],
) -> Result<String, RotateError> {
    let mut doc: serde_json::Value = serde_json::from_str(content).map_err(|e| {
        RotateError::ValueNotFound(format!(
            "failed to parse JSON in {}: {}",
            replacements[0].member.file_path, e
        ))
    })?;

    for rep in replacements {
        let path = &rep.member.location.discriminator;
        let target = doc.pointer_mut(path).ok_or_else(|| {
            RotateError::ValueNotFound(format!(
                "{}: JSON path '{}' not found",
                rep.member.file_path, path
            ))
        })?;

        match target.as_str() {
            Some(v) if v == rep.old_value => {
                *target = serde_json::Value::String(rep.new_value.clone());
            }
            Some(v) => {
                return Err(RotateError::ValueNotFound(format!(
                    "{}: value at '{}' is '{}...', expected '{}...'",
                    rep.member.file_path,
                    path,
                    &v[..v.len().min(8)],
                    &rep.old_value[..rep.old_value.len().min(8)],
                )));
            }
            None => {
                return Err(RotateError::ValueNotFound(format!(
                    "{}: value at '{}' is not a string",
                    rep.member.file_path, path
                )));
            }
        }
    }

    let mut result = serde_json::to_string_pretty(&doc).map_err(|e| {
        RotateError::WriteFailed(replacements[0].member.file_path.clone(), e.to_string())
    })?;
    // Ensure trailing newline
    if !result.ends_with('\n') {
        result.push('\n');
    }
    Ok(result)
}

/// TOML: parse → navigate dotted path → verify → mutate → serialize.
fn replace_toml_path_aware(
    content: &str,
    replacements: &[Replacement<'_>],
) -> Result<String, RotateError> {
    let mut doc: toml::Value = toml::from_str(content).map_err(|e| {
        RotateError::ValueNotFound(format!(
            "failed to parse TOML in {}: {}",
            replacements[0].member.file_path, e
        ))
    })?;

    for rep in replacements {
        let path = &rep.member.location.discriminator;
        let target = navigate_toml_mut(&mut doc, path).ok_or_else(|| {
            RotateError::ValueNotFound(format!(
                "{}: TOML key '{}' not found",
                rep.member.file_path, path
            ))
        })?;

        match target.as_str() {
            Some(v) if v == rep.old_value => {
                *target = toml::Value::String(rep.new_value.clone());
            }
            Some(v) => {
                return Err(RotateError::ValueNotFound(format!(
                    "{}: value at '{}' is '{}...', expected '{}...'",
                    rep.member.file_path,
                    path,
                    &v[..v.len().min(8)],
                    &rep.old_value[..rep.old_value.len().min(8)],
                )));
            }
            None => {
                return Err(RotateError::ValueNotFound(format!(
                    "{}: value at '{}' is not a string",
                    rep.member.file_path, path
                )));
            }
        }
    }

    let mut result = toml::to_string_pretty(&doc).map_err(|e| {
        RotateError::WriteFailed(replacements[0].member.file_path.clone(), e.to_string())
    })?;
    if !result.ends_with('\n') {
        result.push('\n');
    }
    Ok(result)
}

/// Navigate a TOML value by dotted path (e.g., "database.password").
fn navigate_toml_mut<'a>(doc: &'a mut toml::Value, path: &str) -> Option<&'a mut toml::Value> {
    let parts: Vec<&str> = path.split('.').collect();
    let mut current = doc;

    for (i, part) in parts.iter().enumerate() {
        // Handle array indexing: key[0]
        if let Some(bracket_pos) = part.find('[') {
            let key = &part[..bracket_pos];
            let idx_str = part[bracket_pos + 1..].trim_end_matches(']');
            let idx: usize = idx_str.parse().ok()?;

            current = current.as_table_mut()?.get_mut(key)?;
            current = current.as_array_mut()?.get_mut(idx)?;
        } else if i == 0 && parts.len() == 1 {
            // Simple top-level key
            current = current.as_table_mut()?.get_mut(*part)?;
        } else {
            current = current.as_table_mut()?.get_mut(*part)?;
        }
    }

    Some(current)
}

/// Line-targeted replacement for EnvVar, ShellExport, and RawLine.
fn replace_line_targeted(
    content: &str,
    replacements: &[Replacement<'_>],
) -> Result<String, RotateError> {
    let mut lines: Vec<String> = content.lines().map(String::from).collect();
    // Track whether original content ended with newline
    let ends_with_newline = content.ends_with('\n');

    for rep in replacements {
        let line_num = rep.member.location.line_number.ok_or_else(|| {
            RotateError::ValueNotFound(format!(
                "{}: no line number for {} replacement",
                rep.member.file_path, rep.member.location.kind
            ))
        })?;

        let idx = (line_num as usize).saturating_sub(1);
        if idx >= lines.len() {
            return Err(RotateError::ValueNotFound(format!(
                "{}: line {} does not exist (file has {} lines)",
                rep.member.file_path,
                line_num,
                lines.len()
            )));
        }

        let line = &lines[idx];

        // Format-aware validation
        match rep.member.location.kind {
            LocationKind::EnvVar | LocationKind::ShellExport => {
                // Verify discriminator (key name) appears on line
                let disc = &rep.member.location.discriminator;
                if !line.contains(&format!("{}=", disc)) {
                    return Err(RotateError::ValueNotFound(format!(
                        "{}: line {} does not contain '{}='",
                        rep.member.file_path, line_num, disc
                    )));
                }
            }
            _ => {}
        }

        // Replace old_value with new_value on the target line
        if !line.contains(&rep.old_value) {
            return Err(RotateError::ValueNotFound(format!(
                "{}: line {} does not contain the expected value",
                rep.member.file_path, line_num
            )));
        }

        lines[idx] = line.replacen(&rep.old_value, &rep.new_value, 1);
    }

    let mut result = lines.join("\n");
    if ends_with_newline {
        result.push('\n');
    }
    Ok(result)
}

// ── Atomic write ────────────────────────────────────────────────────

pub fn atomic_write(file_path: &Path, content: &str, backup: bool) -> Result<bool, RotateError> {
    let mut backed_up = false;

    if backup {
        let base_bak = file_path.with_extension("bak");
        let bak_path = if base_bak.exists() {
            // Timestamped backup to avoid collision, with a counter for same-second retries.
            let ts = chrono::Utc::now().format("%Y%m%d%H%M%S");
            let mut counter = 0;
            let mut candidate = file_path.with_extension(format!("bak.{}", ts));
            while candidate.exists() {
                counter += 1;
                candidate = file_path.with_extension(format!("bak.{}.{}", ts, counter));
            }
            candidate
        } else {
            base_bak
        };
        std::fs::copy(file_path, &bak_path).map_err(|e| {
            RotateError::WriteFailed(
                file_path.display().to_string(),
                format!("backup failed: {}", e),
            )
        })?;
        backed_up = true;
    }

    // Get original permissions
    let metadata = std::fs::metadata(file_path)
        .map_err(|e| RotateError::WriteFailed(file_path.display().to_string(), e.to_string()))?;

    let tmp_path = file_path.with_extension("hagrid-tmp");

    // Write temp file
    std::fs::write(&tmp_path, content)
        .map_err(|e| RotateError::WriteFailed(file_path.display().to_string(), e.to_string()))?;

    // Preserve permissions
    std::fs::set_permissions(&tmp_path, metadata.permissions()).map_err(|e| {
        let _ = std::fs::remove_file(&tmp_path);
        RotateError::WriteFailed(file_path.display().to_string(), e.to_string())
    })?;

    // Atomic rename
    std::fs::rename(&tmp_path, file_path).map_err(|e| {
        RotateError::WriteFailed(
            file_path.display().to_string(),
            format!(
                "rename failed (temp file left at {}): {}",
                tmp_path.display(),
                e
            ),
        )
    })?;

    Ok(backed_up)
}

// ── Verification ────────────────────────────────────────────────────

pub fn verify_rotation(
    file_path: &str,
    identity_key: &str,
    expected_fingerprint: &str,
    keys: &DerivedKeys,
    patterns: &[CompiledPattern],
) -> Result<(), RotateError> {
    let findings = engine::scan_single_file(Path::new(file_path), patterns, ScanDepth::Standard)
        .map_err(|e| RotateError::VerificationFailed(file_path.to_string(), e))?;
    let member = MemberInfo {
        identity_key: identity_key.to_string(),
        file_path: file_path.to_string(),
        location: Location {
            kind: LocationKind::RawLine,
            discriminator: identity_key.to_string(),
            line_number: None,
        },
        fingerprint: expected_fingerprint.to_string(),
        display_label: String::new(),
        scan_status: ScanStatus::Present,
    };
    verify_members_against_findings(file_path, &[&member], expected_fingerprint, &findings, keys)
}

// ── Execute rotation ────────────────────────────────────────────────

pub fn execute_rotation(
    conn: &rusqlite::Connection,
    members: &[MemberInfo],
    new_value: &str,
    keys: &DerivedKeys,
    patterns: &[CompiledPattern],
    backup: bool,
) -> RotateResult {
    let expected_fp = fingerprint::compute_fingerprint(&keys.fingerprint_key, new_value);

    let present: Vec<&MemberInfo> = members
        .iter()
        .filter(|m| m.scan_status == ScanStatus::Present)
        .collect();

    let mut result = RotateResult {
        total_members: present.len(),
        succeeded: 0,
        failed: 0,
        skipped: 0,
        file_results: Vec::new(),
    };

    // Group members by file_path for per-file transactions
    let mut by_file: HashMap<&str, Vec<&MemberInfo>> = HashMap::new();
    for m in &present {
        by_file.entry(m.file_path.as_str()).or_default().push(m);
    }

    for (file_path, file_members) in &by_file {
        // Phase 1: extract current values for all members in this file
        let mut replacements = Vec::new();
        let mut extraction_failures = Vec::new();

        for member in file_members {
            match find_current_value(member, keys, patterns) {
                Ok(old_value) => {
                    replacements.push(Replacement {
                        member,
                        old_value,
                        new_value: new_value.to_string(),
                    });
                }
                Err(e) => {
                    extraction_failures.push((member, e));
                }
            }
        }

        if !extraction_failures.is_empty() {
            let root_cause = extraction_failures[0].1.to_string();
            for member in file_members {
                let error = extraction_failures
                    .iter()
                    .find(|(failed_member, _)| failed_member.identity_key == member.identity_key)
                    .map(|(_, err)| format!("per-file transaction aborted: {}", err))
                    .unwrap_or_else(|| {
                        format!(
                            "per-file transaction aborted because another reference in this file failed preflight: {}",
                            root_cause
                        )
                    });
                push_failure_result(&mut result, member, error, false);
            }
            continue;
        }

        // Phase 2: read file content once and apply all replacements
        let content = match std::fs::read_to_string(file_path) {
            Ok(c) => c,
            Err(e) => {
                for rep in &replacements {
                    push_failure_result(
                        &mut result,
                        rep.member,
                        format!("failed to read file: {}", e),
                        false,
                    );
                }
                continue;
            }
        };

        let modified = match replace_in_file(&content, &replacements) {
            Ok(m) => m,
            Err(e) => {
                for rep in &replacements {
                    push_failure_result(&mut result, rep.member, e.to_string(), false);
                }
                continue;
            }
        };

        // Phase 3: atomic write (single write per file)
        let path = Path::new(file_path);
        let backed_up = match atomic_write(path, &modified, backup) {
            Ok(b) => b,
            Err(e) => {
                for rep in &replacements {
                    push_failure_result(&mut result, rep.member, e.to_string(), false);
                }
                continue;
            }
        };

        // Phase 4: verify the committed file as a single transaction.
        if let Err(err) =
            verify_members_in_file(file_path, file_members, &expected_fp, keys, patterns)
        {
            let error = match rollback_file(path, &content) {
                Ok(()) => format!("{}; file restored", err),
                Err(rollback_err) => format!("{}; rollback failed: {}", err, rollback_err),
            };
            for rep in &replacements {
                push_failure_result(&mut result, rep.member, error.clone(), backed_up);
            }
            continue;
        }

        // Phase 5: persist the new fingerprints atomically in the index.
        let db_update = (|| -> Result<(), RotateError> {
            conn.execute_batch("BEGIN IMMEDIATE TRANSACTION")
                .map_err(db::DbError::from)?;

            for rep in &replacements {
                let now = chrono::Utc::now();
                let updated_ref = SecretReference {
                    identity_key: rep.member.identity_key.clone(),
                    file_path: rep.member.file_path.clone(),
                    location: rep.member.location.clone(),
                    provider_pattern: None, // preserve existing via upsert
                    fingerprint: expected_fp.clone(),
                    display_label: rep.member.display_label.clone(),
                    first_seen: now,
                    last_seen: now,
                    last_changed: now,
                    scan_status: ScanStatus::Present,
                };
                db::upsert_reference(conn, &updated_ref)?;
            }

            conn.execute_batch("COMMIT").map_err(db::DbError::from)?;
            Ok(())
        })();

        if let Err(err) = db_update {
            let _ = conn.execute_batch("ROLLBACK");
            let error = match rollback_file(path, &content) {
                Ok(()) => format!("database update failed: {}; file restored", err),
                Err(rollback_err) => format!(
                    "database update failed: {}; rollback failed: {}",
                    err, rollback_err
                ),
            };
            for rep in &replacements {
                push_failure_result(&mut result, rep.member, error.clone(), backed_up);
            }
            continue;
        }

        for rep in &replacements {
            push_success_result(&mut result, rep.member, backed_up);
        }
    }

    result
}
