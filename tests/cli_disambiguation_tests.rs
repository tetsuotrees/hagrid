//! CLI-level disambiguation tests for resolve_target() and handler wiring.
//!
//! WS-5: Tests the extracted `resolve_target()` helper and verifies that
//! `show::run_with_conn()` and `forget::run_with_conn()` correctly use it.

use chrono::Utc;
use hagrid::cli::{self, TargetResolution};
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

// ========================================================================
// Helper-level tests for resolve_target()
// ========================================================================

/// ref: prefix bypasses group lookup, resolves to reference.
#[test]
fn resolve_target_ref_prefix_bypasses_group() {
    let (conn, _keys, _tmp) = setup_test_db();

    let ref_id = "deadbeef11111111222222223333333344444444555555556666666677777777";
    insert_test_ref(&conn, ref_id, "fp1");

    // Create a group with the same prefix as a label
    group::create_group(&conn, "deadbeef", &[ref_id.to_string()]).unwrap();

    // ref: prefix should resolve to the reference, not the group
    let result = cli::resolve_target(&conn, "ref:deadbeef").unwrap();
    assert_eq!(result, TargetResolution::Reference(ref_id.to_string()));
}

/// Bare hex input resolves to group when group exists with that label.
#[test]
fn resolve_target_bare_hex_resolves_to_group() {
    let (conn, _keys, _tmp) = setup_test_db();

    let ref_id = "deadbeef11111111222222223333333344444444555555556666666677777777";
    insert_test_ref(&conn, ref_id, "fp1");

    group::create_group(&conn, "deadbeef", &[ref_id.to_string()]).unwrap();

    // Bare "deadbeef" should resolve to the group, not the reference
    let result = cli::resolve_target(&conn, "deadbeef").unwrap();
    assert_eq!(result, TargetResolution::Group("deadbeef".to_string()));
}

/// Bare hex input falls back to reference when no group matches.
#[test]
fn resolve_target_bare_hex_falls_back_to_ref() {
    let (conn, _keys, _tmp) = setup_test_db();

    let ref_id = "cafe123411111111222222223333333344444444555555556666666677777777";
    insert_test_ref(&conn, ref_id, "fp1");

    // No group called "cafe1234"
    let result = cli::resolve_target(&conn, "cafe1234").unwrap();
    assert_eq!(result, TargetResolution::Reference(ref_id.to_string()));
}

/// Non-hex input that isn't a group label -> error.
#[test]
fn resolve_target_non_hex_no_group_is_error() {
    let (conn, _keys, _tmp) = setup_test_db();

    let result = cli::resolve_target(&conn, "my-group");
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("not found"));
}

/// Ambiguous reference prefix (multiple matches) -> error.
#[test]
fn resolve_target_ambiguous_ref_prefix_is_error() {
    let (conn, _keys, _tmp) = setup_test_db();

    // Two refs sharing the same 8-char prefix
    let ref_a = "aabbccdd11111111222222223333333344444444555555556666666677777777";
    let ref_b = "aabbccdd22222222333333334444444455555555666666667777777788888888";
    insert_test_ref(&conn, ref_a, "fp_a");
    insert_test_ref(&conn, ref_b, "fp_b");

    // No group "aabbccdd", so falls to ref lookup — ambiguous
    let result = cli::resolve_target(&conn, "aabbccdd");
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("ambiguous"));
}

// ========================================================================
// Handler-level wiring tests
// ========================================================================

/// show::run_with_conn resolves "deadbeef" to the group when group exists.
#[test]
fn show_handler_resolves_to_group() {
    let (conn, _keys, _tmp) = setup_test_db();

    let ref_id = "deadbeef11111111222222223333333344444444555555556666666677777777";
    insert_test_ref(&conn, ref_id, "fp1");
    group::create_group(&conn, "deadbeef", &[ref_id.to_string()]).unwrap();

    // run_with_conn should succeed (exit 0) and resolve to the group
    let exit_code = cli::show::run_with_conn(&conn, "deadbeef", true);
    assert_eq!(exit_code, 0);
}

/// forget::run_with_conn with "ref:..." resolves to reference and deletes it.
#[test]
fn forget_handler_resolves_ref_prefix_and_deletes() {
    let (conn, _keys, _tmp) = setup_test_db();

    let ref_id = "deadbeef00111111222222223333333344444444555555556666666677777777";
    insert_test_ref(&conn, ref_id, "fp1");

    // Verify the ref exists before
    assert!(db::get_reference(&conn, ref_id).unwrap().is_some());

    let exit_code = cli::forget::run_with_conn(&conn, "ref:deadbeef00");
    assert_eq!(exit_code, 0);

    // Verify the ref was deleted
    assert!(db::get_reference(&conn, ref_id).unwrap().is_none());
}
