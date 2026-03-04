use std::collections::HashMap;

use chrono::Utc;

use crate::config::Config;
use crate::index::db;
use crate::index::models::*;

/// Result of checking a single group for drift.
#[derive(Debug)]
pub struct DriftCheckResult {
    pub group_label: String,
    pub group_id: uuid::Uuid,
    pub status: GroupStatus,
    pub member_fingerprints: HashMap<String, String>,
    pub drifted: bool,
    pub removed_members: Vec<String>,
    pub pruned_members: Vec<String>,
}

/// Check all groups for drift, with auto-pruning of long-removed members.
pub fn check_all_drift(
    conn: &rusqlite::Connection,
    config: &Config,
) -> Result<Vec<DriftCheckResult>, db::DbError> {
    let groups = db::list_groups(conn)?;
    let mut results = Vec::new();

    for group in groups {
        let result = check_group_drift(conn, &group, config)?;
        results.push(result);
    }

    Ok(results)
}

/// Check a single group for drift and auto-prune stale removed members.
pub fn check_group_drift(
    conn: &rusqlite::Connection,
    group: &SecretGroup,
    config: &Config,
) -> Result<DriftCheckResult, db::DbError> {
    let mut member_fps: HashMap<String, String> = HashMap::new();
    let mut removed_members = Vec::new();
    let mut pruned_members = Vec::new();
    let mut present_fps: Vec<String> = Vec::new();
    let prune_threshold = config.groups.auto_prune_after_scans;

    for member_id in &group.members {
        if let Some(reference) = db::get_reference(conn, member_id)? {
            match reference.scan_status {
                ScanStatus::Present => {
                    member_fps.insert(member_id.clone(), reference.fingerprint.clone());
                    present_fps.push(reference.fingerprint.clone());
                }
                ScanStatus::Removed => {
                    // Check if this member should be auto-pruned
                    let removed_count =
                        db::get_removed_scan_count(conn, member_id).unwrap_or(0);
                    if prune_threshold > 0 && removed_count >= prune_threshold {
                        db::remove_group_member(conn, member_id)?;
                        pruned_members.push(member_id.clone());
                    } else {
                        removed_members.push(member_id.clone());
                    }
                }
                ScanStatus::Error => {
                    // Skip errored members
                }
            }
        }
    }

    // Determine group status
    let status = if present_fps.is_empty()
        && !removed_members.is_empty()
    {
        GroupStatus::Empty
    } else if present_fps.is_empty()
        && removed_members.is_empty()
        && !pruned_members.is_empty()
    {
        // All members were pruned
        GroupStatus::Empty
    } else if !removed_members.is_empty() {
        GroupStatus::Degraded
    } else if present_fps.is_empty() {
        GroupStatus::Unknown
    } else {
        let unique_fps: std::collections::HashSet<&String> = present_fps.iter().collect();
        if unique_fps.len() == 1 {
            GroupStatus::Synced
        } else {
            GroupStatus::Drifted
        }
    };

    let drifted = status == GroupStatus::Drifted;

    // Update group status in DB
    db::update_group_status(conn, &group.group_id, &status)?;

    // Record drift event if drifted
    if drifted {
        let event = DriftEvent {
            group_id: group.group_id,
            detected_at: Utc::now(),
            member_fingerprints: member_fps.clone(),
            resolved: false,
            resolved_at: None,
        };
        db::insert_drift_event(conn, &event)?;
    }

    Ok(DriftCheckResult {
        group_label: group.label.clone(),
        group_id: group.group_id,
        status,
        member_fingerprints: member_fps,
        drifted,
        removed_members,
        pruned_members,
    })
}
