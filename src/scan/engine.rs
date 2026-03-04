use chrono::Utc;
use std::path::Path;
use tracing::{info, warn};

use crate::config::Config;
use crate::index::fingerprint;
use crate::index::models::*;
use crate::scan::entropy;
use crate::scan::parsers;
use crate::scan::patterns::{self, CompiledPattern};
use crate::scan::walker;

/// Scan depth level.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanDepth {
    Lite,
    Standard,
}

/// Result of a scan operation.
#[derive(Debug)]
pub struct ScanResult {
    pub findings: Vec<RawFinding>,
    pub files_scanned: usize,
    pub files_skipped: usize,
    pub errors: Vec<String>,
}

/// Run a scan with the given configuration.
pub fn scan(
    config: &Config,
    depth: ScanDepth,
    path_override: Option<&Path>,
) -> ScanResult {
    let mut result = ScanResult {
        findings: Vec::new(),
        files_scanned: 0,
        files_skipped: 0,
        errors: Vec::new(),
    };

    // Load patterns
    let patterns = match patterns::load_patterns(
        Some(&crate::config::patterns_path()),
    ) {
        Ok(p) => p,
        Err(e) => {
            warn!("failed to load user patterns, using defaults: {}", e);
            patterns::load_default_patterns().unwrap_or_default()
        }
    };

    // Walk files
    let files = walker::walk_files(config, path_override);
    info!("found {} files to scan", files.len());

    for file_path in &files {
        match scan_file(file_path, &patterns, depth) {
            Ok(findings) => {
                result.files_scanned += 1;
                result.findings.extend(findings);
            }
            Err(e) => {
                result.files_skipped += 1;
                let msg = format!("{}: {}", file_path.display(), e);
                warn!("{}", msg);
                result.errors.push(msg);
            }
        }
    }

    // Deduplicate findings by (file_path, discriminator)
    dedup_findings(&mut result.findings);

    info!(
        "scan complete: {} files scanned, {} skipped, {} findings",
        result.files_scanned,
        result.files_skipped,
        result.findings.len()
    );

    result
}

/// Convert raw findings to SecretReferences with fingerprints and identity keys.
pub fn findings_to_references(
    findings: &[RawFinding],
    identity_key: &[u8],
    fingerprint_key: &[u8],
) -> Vec<SecretReference> {
    let now = Utc::now();

    findings
        .iter()
        .map(|f| {
            let fp = fingerprint::compute_fingerprint(fingerprint_key, &f.secret_value);
            let id = fingerprint::compute_identity(
                identity_key,
                &f.file_path,
                &f.location.kind,
                &f.location.discriminator,
                "file",
            );

            SecretReference {
                identity_key: id,
                file_path: f.file_path.clone(),
                location: f.location.clone(),
                provider_pattern: f.provider_pattern.clone(),
                fingerprint: fp,
                display_label: f.display_label.clone(),
                first_seen: now,
                last_seen: now,
                last_changed: now,
                scan_status: ScanStatus::Present,
            }
        })
        .collect()
}

fn scan_file(
    path: &Path,
    patterns: &[CompiledPattern],
    depth: ScanDepth,
) -> Result<Vec<RawFinding>, String> {
    let content = std::fs::read_to_string(path).map_err(|e| e.to_string())?;

    let path_str = path
        .canonicalize()
        .unwrap_or_else(|_| path.to_path_buf())
        .to_string_lossy()
        .to_string();

    let mut findings = Vec::new();

    // Phase 1: Pattern matching (both Lite and Standard)
    findings.extend(scan_with_patterns(&path_str, &content, patterns));

    // Phase 2: Structural parsing (Standard only)
    if depth == ScanDepth::Standard {
        findings.extend(scan_with_parsers(&path_str, &content, patterns));
    }

    Ok(findings)
}

/// Scan file content with regex patterns.
fn scan_with_patterns(
    path_str: &str,
    content: &str,
    patterns: &[CompiledPattern],
) -> Vec<RawFinding> {
    let mut findings = Vec::new();

    for (line_num, line) in content.lines().enumerate() {
        let matches = patterns::scan_line(patterns, line, (line_num + 1) as u32, Some(content));

        for m in matches {
            findings.push(RawFinding {
                file_path: path_str.to_string(),
                location: Location {
                    kind: LocationKind::RawLine,
                    discriminator: format!("line:{}", m.line_number),
                    line_number: Some(m.line_number),
                },
                provider_pattern: Some(m.pattern_name),
                display_label: m.display,
                secret_value: m.matched_value,
            });
        }
    }

    findings
}

/// Scan file content using structural parsers, then check extracted values against patterns.
fn scan_with_parsers(
    path_str: &str,
    content: &str,
    patterns: &[CompiledPattern],
) -> Vec<RawFinding> {
    let mut findings = Vec::new();

    let kvs = parsers::parse_file(path_str, content);

    for kv in kvs {
        // Check if value matches any known pattern
        let mut matched = false;
        for pattern in patterns {
            if pattern.regex.is_match(&kv.value) {
                // Check entropy if required
                if let Some(min_entropy) = pattern.entropy_min {
                    if entropy::shannon_entropy(&kv.value) < min_entropy {
                        continue;
                    }
                }
                findings.push(RawFinding {
                    file_path: path_str.to_string(),
                    location: kv.location.clone(),
                    provider_pattern: Some(pattern.name.clone()),
                    display_label: format!("{} ({})", pattern.display, kv.key_path),
                    secret_value: kv.value.clone(),
                });
                matched = true;
                break;
            }
        }

        // If no pattern match, check for high-entropy values
        if !matched && entropy::is_high_entropy(&kv.value, None) {
            // Only flag if the key name suggests it's a secret
            if key_name_suggests_secret(&kv.key_path) {
                findings.push(RawFinding {
                    file_path: path_str.to_string(),
                    location: kv.location.clone(),
                    provider_pattern: None,
                    display_label: format!("High-entropy value ({})", kv.key_path),
                    secret_value: kv.value.clone(),
                });
            }
        }
    }

    findings
}

/// Check if a key name suggests it holds a secret value.
fn key_name_suggests_secret(key: &str) -> bool {
    let lower = key.to_lowercase();
    let secret_indicators = [
        "key", "secret", "token", "password", "passwd", "credential",
        "auth", "api_key", "apikey", "private", "access_key",
    ];

    secret_indicators.iter().any(|ind| lower.contains(ind))
}

/// Deduplicate findings: if the same value appears at the same location via both
/// pattern matching and structural parsing, keep the one with richer location info.
fn dedup_findings(findings: &mut Vec<RawFinding>) {
    findings.sort_by(|a, b| {
        a.file_path
            .cmp(&b.file_path)
            .then(a.secret_value.cmp(&b.secret_value))
    });

    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    findings.retain(|f| {
        // Key: file_path + discriminator + value
        let key = format!("{}|{}|{}", f.file_path, f.location.discriminator, f.secret_value);
        seen.insert(key)
    });
}
