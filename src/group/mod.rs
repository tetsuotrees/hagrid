use chrono::Utc;
use uuid::Uuid;

use crate::index::db;
use crate::index::models::*;

/// Create a new group from a label and reference IDs.
pub fn create_group(
    conn: &rusqlite::Connection,
    label: &str,
    ref_ids: &[String],
) -> Result<SecretGroup, GroupError> {
    // Validate label
    if label.starts_with("ref:") {
        return Err(GroupError::InvalidLabel(
            "group label must not start with 'ref:'".to_string(),
        ));
    }

    if label.is_empty() {
        return Err(GroupError::InvalidLabel("group label cannot be empty".to_string()));
    }

    // Check label uniqueness
    if db::get_group_by_label(conn, label)?.is_some() {
        return Err(GroupError::LabelExists(label.to_string()));
    }

    // Validate all reference IDs exist
    for ref_id in ref_ids {
        if db::get_reference(conn, ref_id)?.is_none() {
            return Err(GroupError::ReferenceNotFound(ref_id.clone()));
        }
    }

    if ref_ids.is_empty() {
        return Err(GroupError::EmptyGroup);
    }

    let now = Utc::now();
    let group = SecretGroup {
        group_id: Uuid::new_v4(),
        label: label.to_string(),
        members: ref_ids.to_vec(),
        status: GroupStatus::Unknown,
        created_at: now,
        confirmed_at: now,
    };

    db::create_group(conn, &group)?;

    Ok(group)
}

/// Remove a reference from its group.
pub fn ungroup_reference(
    conn: &rusqlite::Connection,
    identity_key: &str,
) -> Result<Option<String>, GroupError> {
    let group_id = db::remove_group_member(conn, identity_key)?;
    Ok(group_id)
}

/// Add a reference to an existing group.
pub fn add_to_group(
    conn: &rusqlite::Connection,
    label: &str,
    identity_key: &str,
) -> Result<(), GroupError> {
    let group = db::get_group_by_label(conn, label)?
        .ok_or_else(|| GroupError::GroupNotFound(label.to_string()))?;

    if db::get_reference(conn, identity_key)?.is_none() {
        return Err(GroupError::ReferenceNotFound(identity_key.to_string()));
    }

    db::add_group_member(conn, &group.group_id, identity_key)?;

    Ok(())
}

#[derive(Debug, thiserror::Error)]
pub enum GroupError {
    #[error("group label already exists: {0}")]
    LabelExists(String),
    #[error("invalid group label: {0}")]
    InvalidLabel(String),
    #[error("reference not found: {0}")]
    ReferenceNotFound(String),
    #[error("group not found: {0}")]
    GroupNotFound(String),
    #[error("cannot create empty group")]
    EmptyGroup,
    #[error("database error: {0}")]
    DbError(#[from] db::DbError),
}
