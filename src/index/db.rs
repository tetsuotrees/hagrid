use chrono::Utc;
use rusqlite::{params, Connection};
use std::collections::HashMap;
use std::path::Path;
use thiserror::Error;
use uuid::Uuid;

use crate::index::models::*;

#[derive(Error, Debug)]
pub enum DbError {
    #[error("database error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("database not initialized — run `hagrid init` first")]
    NotInitialized,
    #[error("failed to set encryption key")]
    EncryptionFailed,
}

/// Open an encrypted SQLCipher database.
pub fn open_db(path: &Path, db_key: &[u8]) -> Result<Connection, DbError> {
    let conn = Connection::open(path)?;

    // Set the encryption key as a hex string
    let hex_key = db_key.iter().map(|b| format!("{:02x}", b)).collect::<String>();
    conn.pragma_update(None, "key", format!("x'{}'", hex_key))?;

    // Verify the key works by trying a simple query
    conn.execute_batch("SELECT count(*) FROM sqlite_master;")
        .map_err(|_| DbError::EncryptionFailed)?;

    Ok(conn)
}

/// Run database migrations.
pub fn migrate(conn: &Connection) -> Result<(), DbError> {
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS secret_references (
            identity_key TEXT PRIMARY KEY,
            file_path TEXT NOT NULL,
            location_kind TEXT NOT NULL,
            location_discriminator TEXT NOT NULL,
            location_line_number INTEGER,
            provider_pattern TEXT,
            fingerprint TEXT NOT NULL,
            display_label TEXT NOT NULL,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            last_changed TEXT NOT NULL,
            scan_status TEXT NOT NULL DEFAULT 'present',
            removed_scan_count INTEGER NOT NULL DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS secret_groups (
            group_id TEXT PRIMARY KEY,
            label TEXT NOT NULL UNIQUE,
            status TEXT NOT NULL DEFAULT 'unknown',
            created_at TEXT NOT NULL,
            confirmed_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS group_members (
            group_id TEXT NOT NULL,
            identity_key TEXT NOT NULL,
            PRIMARY KEY (group_id, identity_key),
            FOREIGN KEY (group_id) REFERENCES secret_groups(group_id),
            FOREIGN KEY (identity_key) REFERENCES secret_references(identity_key)
        );

        CREATE TABLE IF NOT EXISTS suggestions (
            suggestion_id TEXT PRIMARY KEY,
            reason TEXT NOT NULL,
            confidence REAL NOT NULL,
            proposed_label TEXT,
            metadata_json TEXT NOT NULL DEFAULT '{}',
            created_at TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending'
        );

        CREATE TABLE IF NOT EXISTS suggestion_refs (
            suggestion_id TEXT NOT NULL,
            identity_key TEXT NOT NULL,
            PRIMARY KEY (suggestion_id, identity_key),
            FOREIGN KEY (suggestion_id) REFERENCES suggestions(suggestion_id)
        );

        CREATE TABLE IF NOT EXISTS drift_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            group_id TEXT NOT NULL,
            detected_at TEXT NOT NULL,
            member_fingerprints_json TEXT NOT NULL,
            resolved INTEGER NOT NULL DEFAULT 0,
            resolved_at TEXT,
            FOREIGN KEY (group_id) REFERENCES secret_groups(group_id)
        );

        CREATE INDEX IF NOT EXISTS idx_refs_fingerprint ON secret_references(fingerprint);
        CREATE INDEX IF NOT EXISTS idx_refs_file_path ON secret_references(file_path);
        CREATE INDEX IF NOT EXISTS idx_refs_scan_status ON secret_references(scan_status);
        CREATE INDEX IF NOT EXISTS idx_suggestions_status ON suggestions(status);
        CREATE INDEX IF NOT EXISTS idx_drift_group ON drift_events(group_id);
        ",
    )?;
    Ok(())
}

// --- Secret References ---

pub fn upsert_reference(conn: &Connection, r: &SecretReference) -> Result<(), DbError> {
    conn.execute(
        "INSERT INTO secret_references (
            identity_key, file_path, location_kind, location_discriminator,
            location_line_number, provider_pattern, fingerprint, display_label,
            first_seen, last_seen, last_changed, scan_status, removed_scan_count
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, 0)
        ON CONFLICT(identity_key) DO UPDATE SET
            fingerprint = CASE
                WHEN excluded.fingerprint != secret_references.fingerprint
                THEN excluded.fingerprint
                ELSE secret_references.fingerprint
            END,
            last_seen = excluded.last_seen,
            last_changed = CASE
                WHEN excluded.fingerprint != secret_references.fingerprint
                THEN excluded.last_changed
                ELSE secret_references.last_changed
            END,
            scan_status = excluded.scan_status,
            removed_scan_count = 0,
            display_label = excluded.display_label,
            location_line_number = excluded.location_line_number
        ",
        params![
            r.identity_key,
            r.file_path,
            r.location.kind.to_string(),
            r.location.discriminator,
            r.location.line_number,
            r.provider_pattern,
            r.fingerprint,
            r.display_label,
            r.first_seen.to_rfc3339(),
            r.last_seen.to_rfc3339(),
            r.last_changed.to_rfc3339(),
            r.scan_status.to_string(),
        ],
    )?;
    Ok(())
}

pub fn get_reference(conn: &Connection, identity_key: &str) -> Result<Option<SecretReference>, DbError> {
    let mut stmt = conn.prepare(
        "SELECT identity_key, file_path, location_kind, location_discriminator,
                location_line_number, provider_pattern, fingerprint, display_label,
                first_seen, last_seen, last_changed, scan_status
         FROM secret_references WHERE identity_key = ?1",
    )?;

    let result = stmt.query_row(params![identity_key], |row| {
        Ok(SecretReference {
            identity_key: row.get(0)?,
            file_path: row.get(1)?,
            location: Location {
                kind: LocationKind::from_str_loose(&row.get::<_, String>(2)?),
                discriminator: row.get(3)?,
                line_number: row.get(4)?,
            },
            provider_pattern: row.get(5)?,
            fingerprint: row.get(6)?,
            display_label: row.get(7)?,
            first_seen: chrono::DateTime::parse_from_rfc3339(&row.get::<_, String>(8)?)
                .unwrap_or_default()
                .with_timezone(&Utc),
            last_seen: chrono::DateTime::parse_from_rfc3339(&row.get::<_, String>(9)?)
                .unwrap_or_default()
                .with_timezone(&Utc),
            last_changed: chrono::DateTime::parse_from_rfc3339(&row.get::<_, String>(10)?)
                .unwrap_or_default()
                .with_timezone(&Utc),
            scan_status: ScanStatus::from_str_loose(&row.get::<_, String>(11)?),
        })
    });

    match result {
        Ok(r) => Ok(Some(r)),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
        Err(e) => Err(e.into()),
    }
}

pub fn list_references(conn: &Connection) -> Result<Vec<SecretReference>, DbError> {
    let mut stmt = conn.prepare(
        "SELECT identity_key, file_path, location_kind, location_discriminator,
                location_line_number, provider_pattern, fingerprint, display_label,
                first_seen, last_seen, last_changed, scan_status
         FROM secret_references ORDER BY file_path, location_discriminator",
    )?;

    let refs = stmt
        .query_map([], |row| {
            Ok(SecretReference {
                identity_key: row.get(0)?,
                file_path: row.get(1)?,
                location: Location {
                    kind: LocationKind::from_str_loose(&row.get::<_, String>(2)?),
                    discriminator: row.get(3)?,
                    line_number: row.get(4)?,
                },
                provider_pattern: row.get(5)?,
                fingerprint: row.get(6)?,
                display_label: row.get(7)?,
                first_seen: chrono::DateTime::parse_from_rfc3339(&row.get::<_, String>(8)?)
                    .unwrap_or_default()
                    .with_timezone(&Utc),
                last_seen: chrono::DateTime::parse_from_rfc3339(&row.get::<_, String>(9)?)
                    .unwrap_or_default()
                    .with_timezone(&Utc),
                last_changed: chrono::DateTime::parse_from_rfc3339(&row.get::<_, String>(10)?)
                    .unwrap_or_default()
                    .with_timezone(&Utc),
                scan_status: ScanStatus::from_str_loose(&row.get::<_, String>(11)?),
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;

    Ok(refs)
}

/// Mark references not seen in the current scan as Removed.
/// Takes identity keys that WERE seen in this scan.
/// For newly-removed refs, sets status to 'removed' and increments removed_scan_count.
/// For already-removed refs that remain unseen, increments removed_scan_count.
pub fn mark_unseen_as_removed(conn: &Connection, seen_keys: &[String]) -> Result<u64, DbError> {
    if seen_keys.is_empty() {
        // Mark all present references as removed
        let count = conn.execute(
            "UPDATE secret_references SET scan_status = 'removed',
             removed_scan_count = removed_scan_count + 1
             WHERE scan_status = 'present'",
            [],
        )?;
        // Also increment counter for already-removed refs
        conn.execute(
            "UPDATE secret_references SET removed_scan_count = removed_scan_count + 1
             WHERE scan_status = 'removed'",
            [],
        )?;
        return Ok(count as u64);
    }

    // Build a comma-separated list of placeholders
    let placeholders: Vec<String> = seen_keys.iter().enumerate().map(|(i, _)| format!("?{}", i + 1)).collect();
    let placeholders_str = placeholders.join(", ");

    // Mark present refs as removed
    let sql = format!(
        "UPDATE secret_references SET scan_status = 'removed',
         removed_scan_count = removed_scan_count + 1
         WHERE scan_status = 'present' AND identity_key NOT IN ({})",
        placeholders_str
    );
    let params: Vec<&dyn rusqlite::types::ToSql> = seen_keys.iter().map(|k| k as &dyn rusqlite::types::ToSql).collect();
    let count = conn.execute(&sql, params.as_slice())?;

    // Increment counter for already-removed refs that remain unseen
    let sql2 = format!(
        "UPDATE secret_references SET removed_scan_count = removed_scan_count + 1
         WHERE scan_status = 'removed' AND identity_key NOT IN ({})",
        placeholders_str
    );
    conn.execute(&sql2, params.as_slice())?;

    Ok(count as u64)
}

pub fn delete_reference(conn: &Connection, identity_key: &str) -> Result<bool, DbError> {
    // Remove from any groups first
    conn.execute(
        "DELETE FROM group_members WHERE identity_key = ?1",
        params![identity_key],
    )?;
    // Remove from suggestions
    conn.execute(
        "DELETE FROM suggestion_refs WHERE identity_key = ?1",
        params![identity_key],
    )?;
    let count = conn.execute(
        "DELETE FROM secret_references WHERE identity_key = ?1",
        params![identity_key],
    )?;
    Ok(count > 0)
}

// --- Secret Groups ---

pub fn create_group(conn: &Connection, group: &SecretGroup) -> Result<(), DbError> {
    conn.execute(
        "INSERT INTO secret_groups (group_id, label, status, created_at, confirmed_at)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            group.group_id.to_string(),
            group.label,
            group.status.to_string(),
            group.created_at.to_rfc3339(),
            group.confirmed_at.to_rfc3339(),
        ],
    )?;

    for member in &group.members {
        conn.execute(
            "INSERT OR IGNORE INTO group_members (group_id, identity_key) VALUES (?1, ?2)",
            params![group.group_id.to_string(), member],
        )?;
    }

    Ok(())
}

pub fn get_group_by_label(conn: &Connection, label: &str) -> Result<Option<SecretGroup>, DbError> {
    let mut stmt = conn.prepare(
        "SELECT group_id, label, status, created_at, confirmed_at
         FROM secret_groups WHERE label = ?1",
    )?;

    let result = stmt.query_row(params![label], |row| {
        let group_id_str: String = row.get(0)?;
        Ok((
            group_id_str,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, String>(3)?,
            row.get::<_, String>(4)?,
        ))
    });

    match result {
        Ok((group_id_str, label, status, created_at, confirmed_at)) => {
            let members = get_group_members(conn, &group_id_str)?;
            Ok(Some(SecretGroup {
                group_id: Uuid::parse_str(&group_id_str).unwrap_or_else(|_| Uuid::new_v4()),
                label,
                members,
                status: GroupStatus::from_str_loose(&status),
                created_at: chrono::DateTime::parse_from_rfc3339(&created_at)
                    .unwrap_or_default()
                    .with_timezone(&Utc),
                confirmed_at: chrono::DateTime::parse_from_rfc3339(&confirmed_at)
                    .unwrap_or_default()
                    .with_timezone(&Utc),
            }))
        }
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
        Err(e) => Err(e.into()),
    }
}

pub fn get_group_by_id(conn: &Connection, group_id: &str) -> Result<Option<SecretGroup>, DbError> {
    let mut stmt = conn.prepare(
        "SELECT group_id, label, status, created_at, confirmed_at
         FROM secret_groups WHERE group_id = ?1",
    )?;

    let result = stmt.query_row(params![group_id], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, String>(3)?,
            row.get::<_, String>(4)?,
        ))
    });

    match result {
        Ok((gid, label, status, created_at, confirmed_at)) => {
            let members = get_group_members(conn, &gid)?;
            Ok(Some(SecretGroup {
                group_id: Uuid::parse_str(&gid).unwrap_or_else(|_| Uuid::new_v4()),
                label,
                members,
                status: GroupStatus::from_str_loose(&status),
                created_at: chrono::DateTime::parse_from_rfc3339(&created_at)
                    .unwrap_or_default()
                    .with_timezone(&Utc),
                confirmed_at: chrono::DateTime::parse_from_rfc3339(&confirmed_at)
                    .unwrap_or_default()
                    .with_timezone(&Utc),
            }))
        }
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
        Err(e) => Err(e.into()),
    }
}

fn get_group_members(conn: &Connection, group_id: &str) -> Result<Vec<String>, DbError> {
    let mut stmt = conn.prepare(
        "SELECT identity_key FROM group_members WHERE group_id = ?1",
    )?;
    let members = stmt
        .query_map(params![group_id], |row| row.get(0))?
        .collect::<Result<Vec<String>, _>>()?;
    Ok(members)
}

pub fn list_groups(conn: &Connection) -> Result<Vec<SecretGroup>, DbError> {
    let mut stmt = conn.prepare(
        "SELECT group_id, label, status, created_at, confirmed_at
         FROM secret_groups ORDER BY label",
    )?;

    let groups = stmt
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;

    let mut result = Vec::new();
    for (gid, label, status, created_at, confirmed_at) in groups {
        let members = get_group_members(conn, &gid)?;
        result.push(SecretGroup {
            group_id: Uuid::parse_str(&gid).unwrap_or_else(|_| Uuid::new_v4()),
            label,
            members,
            status: GroupStatus::from_str_loose(&status),
            created_at: chrono::DateTime::parse_from_rfc3339(&created_at)
                .unwrap_or_default()
                .with_timezone(&Utc),
            confirmed_at: chrono::DateTime::parse_from_rfc3339(&confirmed_at)
                .unwrap_or_default()
                .with_timezone(&Utc),
        });
    }

    Ok(result)
}

pub fn update_group_status(conn: &Connection, group_id: &Uuid, status: &GroupStatus) -> Result<(), DbError> {
    conn.execute(
        "UPDATE secret_groups SET status = ?1 WHERE group_id = ?2",
        params![status.to_string(), group_id.to_string()],
    )?;
    Ok(())
}

pub fn add_group_member(conn: &Connection, group_id: &Uuid, identity_key: &str) -> Result<(), DbError> {
    conn.execute(
        "INSERT OR IGNORE INTO group_members (group_id, identity_key) VALUES (?1, ?2)",
        params![group_id.to_string(), identity_key],
    )?;
    Ok(())
}

pub fn remove_group_member(conn: &Connection, identity_key: &str) -> Result<Option<String>, DbError> {
    // Find which group this ref belongs to
    let mut stmt = conn.prepare(
        "SELECT group_id FROM group_members WHERE identity_key = ?1",
    )?;
    let group_id: Option<String> = stmt
        .query_row(params![identity_key], |row| row.get(0))
        .ok();

    conn.execute(
        "DELETE FROM group_members WHERE identity_key = ?1",
        params![identity_key],
    )?;

    Ok(group_id)
}

pub fn delete_group(conn: &Connection, label: &str) -> Result<bool, DbError> {
    // Get group_id first
    let mut stmt = conn.prepare("SELECT group_id FROM secret_groups WHERE label = ?1")?;
    let group_id: Option<String> = stmt.query_row(params![label], |row| row.get(0)).ok();

    if let Some(gid) = group_id {
        conn.execute("DELETE FROM group_members WHERE group_id = ?1", params![gid])?;
        conn.execute("DELETE FROM drift_events WHERE group_id = ?1", params![gid])?;
        conn.execute("DELETE FROM secret_groups WHERE group_id = ?1", params![gid])?;
        Ok(true)
    } else {
        Ok(false)
    }
}

// --- Suggestions ---

pub fn insert_suggestion(conn: &Connection, s: &Suggestion) -> Result<(), DbError> {
    let metadata_json = serde_json::to_string(&s.metadata).unwrap_or_else(|_| "{}".to_string());

    conn.execute(
        "INSERT INTO suggestions (suggestion_id, reason, confidence, proposed_label, metadata_json, created_at, status)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            s.suggestion_id.to_string(),
            s.reason.to_string(),
            s.confidence,
            s.proposed_label,
            metadata_json,
            s.created_at.to_rfc3339(),
            s.status.to_string(),
        ],
    )?;

    for ref_id in &s.reference_ids {
        conn.execute(
            "INSERT OR IGNORE INTO suggestion_refs (suggestion_id, identity_key) VALUES (?1, ?2)",
            params![s.suggestion_id.to_string(), ref_id],
        )?;
    }

    Ok(())
}

pub fn list_suggestions(conn: &Connection, status: Option<&SuggestionStatus>) -> Result<Vec<Suggestion>, DbError> {
    let sql = match status {
        Some(_) => "SELECT suggestion_id, reason, confidence, proposed_label, metadata_json, created_at, status
                     FROM suggestions WHERE status = ?1 ORDER BY confidence DESC",
        None => "SELECT suggestion_id, reason, confidence, proposed_label, metadata_json, created_at, status
                 FROM suggestions ORDER BY confidence DESC",
    };

    let mut stmt = conn.prepare(sql)?;

    let rows = if let Some(st) = status {
        stmt.query_map(params![st.to_string()], map_suggestion)?
            .collect::<Result<Vec<_>, _>>()?
    } else {
        stmt.query_map([], map_suggestion)?
            .collect::<Result<Vec<_>, _>>()?
    };

    let mut result = Vec::new();
    for (sid, reason, confidence, proposed_label, metadata_json, created_at, status) in rows {
        let ref_ids = get_suggestion_refs(conn, &sid)?;
        let metadata: HashMap<String, String> =
            serde_json::from_str(&metadata_json).unwrap_or_default();
        result.push(Suggestion {
            suggestion_id: Uuid::parse_str(&sid).unwrap_or_else(|_| Uuid::new_v4()),
            reason: SuggestionReason::from_str_loose(&reason),
            confidence,
            reference_ids: ref_ids,
            proposed_label,
            metadata,
            created_at: chrono::DateTime::parse_from_rfc3339(&created_at)
                .unwrap_or_default()
                .with_timezone(&Utc),
            status: SuggestionStatus::from_str_loose(&status),
        });
    }

    Ok(result)
}

type SuggestionRow = (String, String, f64, Option<String>, String, String, String);

fn map_suggestion(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<SuggestionRow> {
    Ok((
        row.get(0)?,
        row.get(1)?,
        row.get(2)?,
        row.get(3)?,
        row.get(4)?,
        row.get(5)?,
        row.get(6)?,
    ))
}

fn get_suggestion_refs(conn: &Connection, suggestion_id: &str) -> Result<Vec<String>, DbError> {
    let mut stmt = conn.prepare(
        "SELECT identity_key FROM suggestion_refs WHERE suggestion_id = ?1",
    )?;
    let refs = stmt
        .query_map(params![suggestion_id], |row| row.get(0))?
        .collect::<Result<Vec<String>, _>>()?;
    Ok(refs)
}

pub fn update_suggestion_status(
    conn: &Connection,
    suggestion_id: &Uuid,
    status: &SuggestionStatus,
) -> Result<(), DbError> {
    conn.execute(
        "UPDATE suggestions SET status = ?1 WHERE suggestion_id = ?2",
        params![status.to_string(), suggestion_id.to_string()],
    )?;
    Ok(())
}

/// Check if a suggestion with the same reason and reference set already exists.
pub fn suggestion_exists(
    conn: &Connection,
    reason: &SuggestionReason,
    reference_ids: &[String],
) -> Result<bool, DbError> {
    let mut sorted = reference_ids.to_vec();
    sorted.sort();
    let ref_key = sorted.join(",");

    let mut stmt = conn.prepare(
        "SELECT s.suggestion_id FROM suggestions s
         WHERE s.reason = ?1 AND s.status = 'pending'",
    )?;

    let candidates: Vec<String> = stmt
        .query_map(params![reason.to_string()], |row| row.get(0))?
        .collect::<Result<Vec<_>, _>>()?;

    for sid in candidates {
        let refs = get_suggestion_refs(conn, &sid)?;
        let mut refs_sorted = refs;
        refs_sorted.sort();
        if refs_sorted.join(",") == ref_key {
            return Ok(true);
        }
    }

    Ok(false)
}

// --- Drift Events ---

pub fn insert_drift_event(conn: &Connection, event: &DriftEvent) -> Result<(), DbError> {
    let fps_json = serde_json::to_string(&event.member_fingerprints).unwrap_or_else(|_| "{}".to_string());
    conn.execute(
        "INSERT INTO drift_events (group_id, detected_at, member_fingerprints_json, resolved, resolved_at)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            event.group_id.to_string(),
            event.detected_at.to_rfc3339(),
            fps_json,
            event.resolved as i32,
            event.resolved_at.map(|dt| dt.to_rfc3339()),
        ],
    )?;
    Ok(())
}

pub fn list_drift_events(conn: &Connection, group_id: Option<&Uuid>) -> Result<Vec<DriftEvent>, DbError> {
    let sql = match group_id {
        Some(_) => "SELECT group_id, detected_at, member_fingerprints_json, resolved, resolved_at
                     FROM drift_events WHERE group_id = ?1 ORDER BY detected_at DESC",
        None => "SELECT group_id, detected_at, member_fingerprints_json, resolved, resolved_at
                 FROM drift_events ORDER BY detected_at DESC",
    };

    let mut stmt = conn.prepare(sql)?;

    let rows: Vec<(String, String, String, bool, Option<String>)> = if let Some(gid) = group_id {
        stmt.query_map(params![gid.to_string()], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?))
        })?
        .collect::<Result<Vec<_>, _>>()?
    } else {
        stmt.query_map([], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?))
        })?
        .collect::<Result<Vec<_>, _>>()?
    };

    let mut result = Vec::new();
    for (gid, detected_at, fps_json, resolved, resolved_at) in rows {
        let member_fingerprints: HashMap<String, String> =
            serde_json::from_str(&fps_json).unwrap_or_default();
        result.push(DriftEvent {
            group_id: Uuid::parse_str(&gid).unwrap_or_else(|_| Uuid::new_v4()),
            detected_at: chrono::DateTime::parse_from_rfc3339(&detected_at)
                .unwrap_or_default()
                .with_timezone(&Utc),
            member_fingerprints,
            resolved,
            resolved_at: resolved_at.and_then(|dt| {
                chrono::DateTime::parse_from_rfc3339(&dt)
                    .ok()
                    .map(|d| d.with_timezone(&Utc))
            }),
        });
    }

    Ok(result)
}

// --- Stats ---

pub fn count_references(conn: &Connection) -> Result<usize, DbError> {
    let count: i64 = conn.query_row(
        "SELECT COUNT(*) FROM secret_references WHERE scan_status = 'present'",
        [],
        |row| row.get(0),
    )?;
    Ok(count as usize)
}

pub fn count_groups(conn: &Connection) -> Result<usize, DbError> {
    let count: i64 = conn.query_row("SELECT COUNT(*) FROM secret_groups", [], |row| row.get(0))?;
    Ok(count as usize)
}

pub fn count_pending_suggestions(conn: &Connection) -> Result<usize, DbError> {
    let count: i64 = conn.query_row(
        "SELECT COUNT(*) FROM suggestions WHERE status = 'pending'",
        [],
        |row| row.get(0),
    )?;
    Ok(count as usize)
}

pub fn count_unresolved_drift(conn: &Connection) -> Result<usize, DbError> {
    let count: i64 = conn.query_row(
        "SELECT COUNT(*) FROM drift_events WHERE resolved = 0",
        [],
        |row| row.get(0),
    )?;
    Ok(count as usize)
}

pub fn count_ungrouped_references(conn: &Connection) -> Result<usize, DbError> {
    let count: i64 = conn.query_row(
        "SELECT COUNT(*) FROM secret_references
         WHERE scan_status = 'present'
         AND identity_key NOT IN (SELECT identity_key FROM group_members)",
        [],
        |row| row.get(0),
    )?;
    Ok(count as usize)
}

/// Get the removed_scan_count for a reference.
pub fn get_removed_scan_count(conn: &Connection, identity_key: &str) -> Result<u32, DbError> {
    let count: i64 = conn.query_row(
        "SELECT removed_scan_count FROM secret_references WHERE identity_key = ?1",
        params![identity_key],
        |row| row.get(0),
    )?;
    Ok(count as u32)
}
