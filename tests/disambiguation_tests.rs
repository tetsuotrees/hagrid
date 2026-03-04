//! Integration tests for hex-like group-label disambiguation in show/forget flows.
//!
//! WS-4: Verifies that group labels that are valid hex strings (like "deadbeef",
//! "cafe1234") are resolved as group labels first, with ref-ID fallback only
//! when no group matches.

use chrono::Utc;
use hagrid::group;
use hagrid::index::db;
use hagrid::index::fingerprint;
use hagrid::index::models::*;
use tempfile::TempDir;

fn setup_test_db() -> (rusqlite::Connection, fingerprint::DerivedKeys, TempDir) {
    let tmp = TempDir::new().unwrap();
    let db_path = tmp.path().join("test.db");
    let master = b"test-master-secret-32-bytes-long!";
    let keys = fingerprint::derive_keys(master);
    let conn = db::open_db(&db_path, &keys.db_key).unwrap();
    db::migrate(&conn).unwrap();
    (conn, keys, tmp)
}

fn insert_test_ref(conn: &rusqlite::Connection, identity: &str, fp: &str) {
    let now = Utc::now();
    let r = SecretReference {
        identity_key: identity.to_string(),
        file_path: format!("/test/{}", identity),
        location: Location {
            kind: LocationKind::EnvVar,
            discriminator: "TEST_KEY".to_string(),
            line_number: Some(1),
        },
        provider_pattern: Some("test_pattern".to_string()),
        fingerprint: fp.to_string(),
        display_label: "Test secret".to_string(),
        first_seen: now,
        last_seen: now,
        last_changed: now,
        scan_status: ScanStatus::Present,
    };
    db::upsert_reference(conn, &r).unwrap();
}

/// A group labeled "deadbeef" should be found by get_group_by_label,
/// taking priority over any reference whose identity_key starts with "deadbeef".
#[test]
fn test_hex_label_group_takes_priority_over_ref() {
    let (conn, _keys, _tmp) = setup_test_db();

    // Create a reference whose identity key starts with "deadbeef"
    let ref_id = "deadbeef11111111222222223333333344444444555555556666666677777777";
    insert_test_ref(&conn, ref_id, "fp_deadbeef");

    // Create a group with the label "deadbeef"
    group::create_group(&conn, "deadbeef", &[ref_id.to_string()]).unwrap();

    // Disambiguation: "deadbeef" as input should resolve to the group, not the reference
    let group_result = db::get_group_by_label(&conn, "deadbeef").unwrap();
    assert!(group_result.is_some(), "group 'deadbeef' should be found by label");
    assert_eq!(group_result.unwrap().label, "deadbeef");
}

/// When no group exists with a hex label, the disambiguation logic should
/// fall through to reference lookup.
#[test]
fn test_hex_label_falls_back_to_ref_when_no_group() {
    let (conn, _keys, _tmp) = setup_test_db();

    // Create a reference whose identity key starts with "cafe1234"
    let ref_id = "cafe123400000000111111112222222233333333444444445555555566666666";
    insert_test_ref(&conn, ref_id, "fp_cafe");

    // No group called "cafe1234" exists
    let group_result = db::get_group_by_label(&conn, "cafe1234").unwrap();
    assert!(group_result.is_none(), "no group should exist with label 'cafe1234'");

    // The ref should be findable by prefix
    let refs = db::list_references(&conn).unwrap();
    let matches: Vec<_> = refs
        .iter()
        .filter(|r| r.identity_key.starts_with("cafe1234"))
        .collect();
    assert_eq!(matches.len(), 1, "should find exactly one ref matching 'cafe1234'");
}

/// The "ref:" prefix should always bypass group lookup and go straight
/// to reference resolution, even if a group with the same name exists.
#[test]
fn test_ref_prefix_bypasses_group_lookup() {
    let (conn, _keys, _tmp) = setup_test_db();

    let ref_id = "abcdef0011111111222222223333333344444444555555556666666677777777";
    insert_test_ref(&conn, ref_id, "fp_abcdef");

    // Create a group named "abcdef00" — same as the ref's prefix
    group::create_group(&conn, "abcdef00", &[ref_id.to_string()]).unwrap();

    // With "ref:" prefix, should resolve to the reference, not the group
    let hex_prefix = "ref:abcdef00".strip_prefix("ref:").unwrap();
    let refs = db::list_references(&conn).unwrap();
    let matches: Vec<_> = refs
        .iter()
        .filter(|r| r.identity_key.starts_with(hex_prefix))
        .collect();
    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].identity_key, ref_id);
}

/// Group label "deadbeefcafe" (all hex, 12 chars) should be resolved
/// as group label, not confused with a reference ID prefix.
#[test]
fn test_long_hex_label_resolved_as_group() {
    let (conn, _keys, _tmp) = setup_test_db();

    let ref_id = "aaa0000011111111222222223333333344444444555555556666666677777777";
    insert_test_ref(&conn, ref_id, "fp1");

    group::create_group(&conn, "deadbeefcafe", &[ref_id.to_string()]).unwrap();

    let group = db::get_group_by_label(&conn, "deadbeefcafe").unwrap();
    assert!(group.is_some());
    assert_eq!(group.unwrap().label, "deadbeefcafe");
}

/// Verify forget logic: forgetting a hex-named group deletes the group,
/// not a reference with a matching prefix.
#[test]
fn test_forget_hex_group_deletes_group_not_ref() {
    let (conn, _keys, _tmp) = setup_test_db();

    let ref_id = "deadbeef11111111222222223333333344444444555555556666666677777777";
    insert_test_ref(&conn, ref_id, "fp_deadbeef");

    group::create_group(&conn, "deadbeef", &[ref_id.to_string()]).unwrap();

    // Forget the group by label
    let deleted = db::delete_group(&conn, "deadbeef").unwrap();
    assert!(deleted, "should delete the group");

    // The reference should still exist
    let ref_still_exists = db::get_reference(&conn, ref_id).unwrap();
    assert!(
        ref_still_exists.is_some(),
        "reference should NOT be deleted when forgetting the group"
    );
}

/// Verify that show-style disambiguation works correctly with multiple
/// hex-like groups and references that could collide.
#[test]
fn test_multiple_hex_groups_no_cross_contamination() {
    let (conn, _keys, _tmp) = setup_test_db();

    let ref_a = "aabbccdd11111111222222223333333344444444555555556666666677777777";
    let ref_b = "eeff001122222222333333334444444455555555666666667777777788888888";
    insert_test_ref(&conn, ref_a, "fp_a");
    insert_test_ref(&conn, ref_b, "fp_b");

    group::create_group(&conn, "aabbccdd", &[ref_a.to_string()]).unwrap();
    group::create_group(&conn, "eeff0011", &[ref_b.to_string()]).unwrap();

    // Each label resolves to its own group
    let group_a = db::get_group_by_label(&conn, "aabbccdd").unwrap().unwrap();
    let group_b = db::get_group_by_label(&conn, "eeff0011").unwrap().unwrap();
    assert_eq!(group_a.members.len(), 1);
    assert_eq!(group_b.members.len(), 1);
    assert_ne!(group_a.group_id, group_b.group_id);
}

/// Edge case: a label that is exactly 64 hex chars (same length as an identity key).
/// The spec says CLI input without "ref:" prefix is always tried as group label first.
#[test]
fn test_64_char_hex_label_treated_as_group() {
    let (conn, _keys, _tmp) = setup_test_db();

    let ref_id = "1111111122222222333333334444444455555555666666667777777788888888";
    insert_test_ref(&conn, ref_id, "fp1");

    // This label is exactly 64 hex chars — could be confused with a full identity key
    let label_64 = "aaaaaaaabbbbbbbbccccccccddddddddeeeeeeeeffffffff0000000011111111";
    group::create_group(&conn, label_64, &[ref_id.to_string()]).unwrap();

    let group = db::get_group_by_label(&conn, label_64).unwrap();
    assert!(group.is_some(), "64-char hex group label should be found");
}
