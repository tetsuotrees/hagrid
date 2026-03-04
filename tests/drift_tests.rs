use chrono::Utc;
use hagrid::config::Config;
use hagrid::drift;
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

fn insert_test_ref(conn: &rusqlite::Connection, identity: &str, fp: &str, status: ScanStatus) {
    let now = Utc::now();
    let r = SecretReference {
        identity_key: identity.to_string(),
        file_path: format!("/test/{}", identity),
        location: Location {
            kind: LocationKind::EnvVar,
            discriminator: "KEY".to_string(),
            line_number: Some(1),
        },
        provider_pattern: None,
        fingerprint: fp.to_string(),
        display_label: "Test".to_string(),
        first_seen: now,
        last_seen: now,
        last_changed: now,
        scan_status: status,
    };
    db::upsert_reference(conn, &r).unwrap();
}

#[test]
fn test_drift_synced_group() {
    let (conn, _keys, _tmp) = setup_test_db();
    let config = Config::default();

    let fp = "a".repeat(64);
    insert_test_ref(&conn, &"a".repeat(64), &fp, ScanStatus::Present);
    insert_test_ref(&conn, &"b".repeat(64), &fp, ScanStatus::Present);

    group::create_group(
        &conn,
        "synced-group",
        &["a".repeat(64), "b".repeat(64)],
    ).unwrap();

    let results = drift::check_all_drift(&conn, &config).unwrap();
    assert_eq!(results.len(), 1);
    assert!(!results[0].drifted, "group with same fingerprints should not be drifted");
    assert_eq!(results[0].status, GroupStatus::Synced);
}

#[test]
fn test_drift_drifted_group() {
    let (conn, _keys, _tmp) = setup_test_db();
    let config = Config::default();

    insert_test_ref(&conn, &"a".repeat(64), &"1".repeat(64), ScanStatus::Present);
    insert_test_ref(&conn, &"b".repeat(64), &"2".repeat(64), ScanStatus::Present);

    group::create_group(
        &conn,
        "drifted-group",
        &["a".repeat(64), "b".repeat(64)],
    ).unwrap();

    let results = drift::check_all_drift(&conn, &config).unwrap();
    assert_eq!(results.len(), 1);
    assert!(results[0].drifted, "group with different fingerprints should be drifted");
    assert_eq!(results[0].status, GroupStatus::Drifted);
}

#[test]
fn test_drift_degraded_group() {
    let (conn, _keys, _tmp) = setup_test_db();
    let config = Config::default();

    let fp = "c".repeat(64);
    insert_test_ref(&conn, &"a".repeat(64), &fp, ScanStatus::Present);
    insert_test_ref(&conn, &"b".repeat(64), &fp, ScanStatus::Removed);

    group::create_group(
        &conn,
        "degraded-group",
        &["a".repeat(64), "b".repeat(64)],
    ).unwrap();

    let results = drift::check_all_drift(&conn, &config).unwrap();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].status, GroupStatus::Degraded);
    assert!(!results[0].removed_members.is_empty());
}

#[test]
fn test_drift_empty_group() {
    let (conn, _keys, _tmp) = setup_test_db();
    let config = Config::default();

    let fp = "d".repeat(64);
    insert_test_ref(&conn, &"a".repeat(64), &fp, ScanStatus::Removed);
    insert_test_ref(&conn, &"b".repeat(64), &fp, ScanStatus::Removed);

    group::create_group(
        &conn,
        "empty-group",
        &["a".repeat(64), "b".repeat(64)],
    ).unwrap();

    let results = drift::check_all_drift(&conn, &config).unwrap();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].status, GroupStatus::Empty);
}

#[test]
fn test_auto_prune_after_threshold() {
    let (conn, _keys, _tmp) = setup_test_db();
    let mut config = Config::default();
    config.groups.auto_prune_after_scans = 2; // prune after 2 scans removed

    let fp = "e".repeat(64);
    let id_a = "a".repeat(64);
    let id_b = "b".repeat(64);

    insert_test_ref(&conn, &id_a, &fp, ScanStatus::Present);
    insert_test_ref(&conn, &id_b, &fp, ScanStatus::Present);

    group::create_group(
        &conn,
        "prune-group",
        &[id_a.clone(), id_b.clone()],
    ).unwrap();

    // Simulate member B being removed for 2 scans
    // First mark as removed (removed_scan_count = 1)
    let seen = vec![id_a.clone()];
    db::mark_unseen_as_removed(&conn, &seen).unwrap();
    // Second time (removed_scan_count = 2)
    db::mark_unseen_as_removed(&conn, &seen).unwrap();

    let results = drift::check_all_drift(&conn, &config).unwrap();
    assert_eq!(results.len(), 1);

    // Member B should have been auto-pruned (removed_scan_count >= 2)
    assert!(
        !results[0].pruned_members.is_empty(),
        "should have pruned member B after 2 removed scans"
    );
    assert!(
        results[0].pruned_members.contains(&id_b),
        "pruned member should be B"
    );

    // Group should now have only 1 member
    let group = db::get_group_by_label(&conn, "prune-group").unwrap().unwrap();
    assert_eq!(group.members.len(), 1);
    assert!(group.members.contains(&id_a));
}
