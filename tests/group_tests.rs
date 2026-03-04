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

#[test]
fn test_create_group() {
    let (conn, _keys, _tmp) = setup_test_db();

    insert_test_ref(&conn, "aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111", "fp1");
    insert_test_ref(&conn, "bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222", "fp1");

    let g = group::create_group(
        &conn,
        "test-group",
        &[
            "aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111".to_string(),
            "bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222".to_string(),
        ],
    ).unwrap();

    assert_eq!(g.label, "test-group");
    assert_eq!(g.members.len(), 2);
}

#[test]
fn test_group_label_ref_prefix_rejected() {
    let (conn, _keys, _tmp) = setup_test_db();

    insert_test_ref(&conn, "aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111", "fp1");

    let result = group::create_group(
        &conn,
        "ref:bad-label",
        &["aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111".to_string()],
    );

    assert!(result.is_err(), "group label starting with ref: should be rejected");
}

#[test]
fn test_group_duplicate_label_rejected() {
    let (conn, _keys, _tmp) = setup_test_db();

    insert_test_ref(&conn, "aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111", "fp1");
    insert_test_ref(&conn, "bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222", "fp1");

    group::create_group(
        &conn,
        "my-group",
        &["aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111".to_string()],
    ).unwrap();

    let result = group::create_group(
        &conn,
        "my-group",
        &["bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222".to_string()],
    );

    assert!(result.is_err(), "duplicate group label should be rejected");
}

#[test]
fn test_ungroup_reference() {
    let (conn, _keys, _tmp) = setup_test_db();

    insert_test_ref(&conn, "aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111", "fp1");
    insert_test_ref(&conn, "bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222", "fp1");

    group::create_group(
        &conn,
        "test-group",
        &[
            "aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111".to_string(),
            "bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222".to_string(),
        ],
    ).unwrap();

    let result = group::ungroup_reference(
        &conn,
        "aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111",
    ).unwrap();

    assert!(result.is_some(), "should return the group ID");

    // Verify the group now has one member
    let g = db::get_group_by_label(&conn, "test-group").unwrap().unwrap();
    assert_eq!(g.members.len(), 1);
}

#[test]
fn test_empty_group_rejected() {
    let (conn, _keys, _tmp) = setup_test_db();

    let result = group::create_group(&conn, "empty-group", &[]);
    assert!(result.is_err(), "empty group should be rejected");
}
