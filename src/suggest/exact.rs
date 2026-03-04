use std::collections::HashMap;

use chrono::Utc;
use uuid::Uuid;

use crate::index::db;
use crate::index::models::*;

/// Generate suggestions for references that share the exact same fingerprint.
pub fn suggest_exact_matches(conn: &rusqlite::Connection) -> Result<Vec<Suggestion>, db::DbError> {
    let refs = db::list_references(conn)?;
    let mut suggestions = Vec::new();

    // Group references by fingerprint
    let mut by_fingerprint: HashMap<String, Vec<&SecretReference>> = HashMap::new();
    for r in &refs {
        if r.scan_status != ScanStatus::Present {
            continue;
        }
        by_fingerprint
            .entry(r.fingerprint.clone())
            .or_default()
            .push(r);
    }

    // Create suggestions for fingerprints shared by 2+ references
    for group in by_fingerprint.values() {
        if group.len() < 2 {
            continue;
        }

        let ref_ids: Vec<String> = group.iter().map(|r| r.identity_key.clone()).collect();

        // Check if this suggestion already exists
        if db::suggestion_exists(conn, &SuggestionReason::ExactFingerprint, &ref_ids)? {
            continue;
        }

        // Check if all refs are already in the same group
        if all_in_same_group(conn, &ref_ids)? {
            continue;
        }

        // Generate a proposed label from the provider pattern
        let proposed_label = group
            .iter()
            .find_map(|r| r.provider_pattern.as_ref())
            .map(|p| p.replace('_', "-"));

        let mut metadata = HashMap::new();
        metadata.insert(
            "files".to_string(),
            group
                .iter()
                .map(|r| r.file_path.clone())
                .collect::<Vec<_>>()
                .join(", "),
        );

        suggestions.push(Suggestion {
            suggestion_id: Uuid::new_v4(),
            reason: SuggestionReason::ExactFingerprint,
            confidence: 1.0,
            reference_ids: ref_ids,
            proposed_label,
            metadata,
            created_at: Utc::now(),
            status: SuggestionStatus::Pending,
        });
    }

    Ok(suggestions)
}

/// Check if all references are already members of the same group.
fn all_in_same_group(conn: &rusqlite::Connection, ref_ids: &[String]) -> Result<bool, db::DbError> {
    let groups = db::list_groups(conn)?;
    for group in &groups {
        if ref_ids.iter().all(|id| group.members.contains(id)) {
            return Ok(true);
        }
    }
    Ok(false)
}
