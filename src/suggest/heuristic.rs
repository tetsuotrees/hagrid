use std::collections::HashMap;

use chrono::Utc;
use uuid::Uuid;

use crate::index::db;
use crate::index::models::*;

/// Generate heuristic suggestions based on structural and provider matching.
pub fn suggest_heuristic_matches(conn: &rusqlite::Connection) -> Result<Vec<Suggestion>, db::DbError> {
    let refs = db::list_references(conn)?;
    let mut suggestions = Vec::new();

    let present_refs: Vec<&SecretReference> = refs
        .iter()
        .filter(|r| r.scan_status == ScanStatus::Present)
        .collect();

    // Strategy 1: Same provider pattern + different files = potential group
    suggestions.extend(suggest_by_provider(conn, &present_refs)?);

    // Strategy 2: Same key path across similar config files
    suggestions.extend(suggest_by_key_path(conn, &present_refs)?);

    Ok(suggestions)
}

/// Suggest grouping references with the same provider pattern across different files.
fn suggest_by_provider(
    conn: &rusqlite::Connection,
    refs: &[&SecretReference],
) -> Result<Vec<Suggestion>, db::DbError> {
    let mut suggestions = Vec::new();

    // Group by provider pattern
    let mut by_provider: HashMap<String, Vec<&SecretReference>> = HashMap::new();
    for r in refs {
        if let Some(ref provider) = r.provider_pattern {
            by_provider.entry(provider.clone()).or_default().push(r);
        }
    }

    for (provider, group) in &by_provider {
        if group.len() < 2 {
            continue;
        }

        // Only suggest if they're in different files (same file = different secrets)
        let unique_files: std::collections::HashSet<&str> =
            group.iter().map(|r| r.file_path.as_str()).collect();
        if unique_files.len() < 2 {
            continue;
        }

        // Skip if they already have the same fingerprint (exact match handles this)
        let unique_fps: std::collections::HashSet<&str> =
            group.iter().map(|r| r.fingerprint.as_str()).collect();
        if unique_fps.len() == 1 {
            continue;
        }

        let ref_ids: Vec<String> = group.iter().map(|r| r.identity_key.clone()).collect();

        if db::suggestion_exists(conn, &SuggestionReason::ProviderMatch, &ref_ids)? {
            continue;
        }

        let mut metadata = HashMap::new();
        metadata.insert("provider".to_string(), provider.clone());
        metadata.insert(
            "note".to_string(),
            "Same provider pattern found in different files — may be the same logical secret".to_string(),
        );

        suggestions.push(Suggestion {
            suggestion_id: Uuid::new_v4(),
            reason: SuggestionReason::ProviderMatch,
            confidence: 0.6,
            reference_ids: ref_ids,
            proposed_label: Some(provider.replace('_', "-")),
            metadata,
            created_at: Utc::now(),
            status: SuggestionStatus::Pending,
        });
    }

    Ok(suggestions)
}

/// Suggest grouping references with the same key path pattern across similar config files.
fn suggest_by_key_path(
    conn: &rusqlite::Connection,
    refs: &[&SecretReference],
) -> Result<Vec<Suggestion>, db::DbError> {
    let mut suggestions = Vec::new();

    // Group by discriminator (key path within file)
    let mut by_key: HashMap<String, Vec<&SecretReference>> = HashMap::new();
    for r in refs {
        // Normalize the discriminator to just the key name
        let key = normalize_key_name(&r.location.discriminator);
        if !key.is_empty() {
            by_key.entry(key).or_default().push(r);
        }
    }

    for (key, group) in &by_key {
        if group.len() < 2 {
            continue;
        }

        // Only if in different files
        let unique_files: std::collections::HashSet<&str> =
            group.iter().map(|r| r.file_path.as_str()).collect();
        if unique_files.len() < 2 {
            continue;
        }

        // Skip if exact fingerprint match (handled by exact suggestions)
        let unique_fps: std::collections::HashSet<&str> =
            group.iter().map(|r| r.fingerprint.as_str()).collect();
        if unique_fps.len() == 1 {
            continue;
        }

        let ref_ids: Vec<String> = group.iter().map(|r| r.identity_key.clone()).collect();

        if db::suggestion_exists(conn, &SuggestionReason::StructuralMatch, &ref_ids)? {
            continue;
        }

        let mut metadata = HashMap::new();
        metadata.insert("key_name".to_string(), key.clone());
        metadata.insert(
            "note".to_string(),
            "Same key name found in different config files — may be the same logical secret".to_string(),
        );

        suggestions.push(Suggestion {
            suggestion_id: Uuid::new_v4(),
            reason: SuggestionReason::StructuralMatch,
            confidence: 0.5,
            reference_ids: ref_ids,
            proposed_label: Some(key.replace('_', "-").to_lowercase()),
            metadata,
            created_at: Utc::now(),
            status: SuggestionStatus::Pending,
        });
    }

    Ok(suggestions)
}

/// Extract just the final key name from a discriminator path.
fn normalize_key_name(discriminator: &str) -> String {
    // Handle JSON pointers: /path/to/key → key
    if discriminator.starts_with('/') {
        return discriminator
            .rsplit('/')
            .next()
            .unwrap_or("")
            .to_string();
    }

    // Handle TOML paths: path.to.key → key
    if discriminator.contains('.') {
        return discriminator
            .rsplit('.')
            .next()
            .unwrap_or("")
            .to_string();
    }

    // Handle line references: line:N → skip (not useful for grouping)
    if discriminator.starts_with("line:") {
        return String::new();
    }

    // Plain key name
    discriminator.to_string()
}
