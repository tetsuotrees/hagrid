use chrono::Utc;
use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyEventState, KeyModifiers};
use hagrid::index::db;
use hagrid::index::fingerprint;
use hagrid::index::models::*;
use hagrid::tui::app::{App, DetailInfo, ListSection, View};
use hagrid::tui::input::{handle_key, KeyAction};
use tempfile::TempDir;
use uuid::Uuid;

fn setup_test_db() -> (rusqlite::Connection, fingerprint::DerivedKeys, TempDir) {
    let tmp = TempDir::new().unwrap();
    let db_path = tmp.path().join("test.db");
    let master = b"test-master-secret-32-bytes-long!";
    let keys = fingerprint::derive_keys(master);
    let conn = db::open_db(&db_path, &keys.db_key).unwrap();
    db::migrate(&conn).unwrap();
    (conn, keys, tmp)
}

fn insert_test_ref(
    conn: &rusqlite::Connection,
    identity: &str,
    fp: &str,
    file_path: &str,
    discriminator: &str,
    provider: Option<&str>,
) {
    let now = Utc::now();
    let r = SecretReference {
        identity_key: identity.to_string(),
        file_path: file_path.to_string(),
        location: Location {
            kind: LocationKind::EnvVar,
            discriminator: discriminator.to_string(),
            line_number: Some(1),
        },
        provider_pattern: provider.map(|s| s.to_string()),
        fingerprint: fp.to_string(),
        display_label: format!("{} in {}", discriminator, file_path),
        first_seen: now,
        last_seen: now,
        last_changed: now,
        scan_status: ScanStatus::Present,
    };
    db::upsert_reference(conn, &r).unwrap();
}

fn insert_test_group(
    conn: &rusqlite::Connection,
    label: &str,
    members: &[&str],
    status: GroupStatus,
) {
    let now = Utc::now();
    let group = SecretGroup {
        group_id: Uuid::new_v4(),
        label: label.to_string(),
        members: members.iter().map(|s| s.to_string()).collect(),
        status,
        created_at: now,
        confirmed_at: now,
    };
    db::create_group(conn, &group).unwrap();
}

fn key(code: KeyCode) -> KeyEvent {
    KeyEvent {
        code,
        modifiers: KeyModifiers::empty(),
        kind: KeyEventKind::Press,
        state: KeyEventState::empty(),
    }
}

// --- Empty state tests ---

#[test]
fn test_tui_empty_database() {
    let (conn, _keys, _tmp) = setup_test_db();
    let mut app = App::new();
    app.load(&conn);

    assert_eq!(app.summary.total_refs, 0);
    assert_eq!(app.summary.groups, 0);
    assert_eq!(app.summary.ungrouped, 0);
    assert_eq!(app.summary.pending_suggestions, 0);
    assert_eq!(app.summary.unresolved_drift, 0);
    assert!(app.group_items.is_empty());
    assert!(app.ungrouped_items.is_empty());
    assert!(app.error.is_none());
}

#[test]
fn test_tui_empty_state_navigation_safe() {
    let (conn, _keys, _tmp) = setup_test_db();
    let mut app = App::new();
    app.load(&conn);

    // Navigate in empty state should not panic
    app.move_down();
    app.move_up();
    app.toggle_section();
    app.move_down();
    app.move_up();

    assert_eq!(app.group_index, 0);
    assert_eq!(app.ungrouped_index, 0);
}

#[test]
fn test_tui_empty_enter_detail_noop() {
    let (conn, _keys, _tmp) = setup_test_db();
    let mut app = App::new();
    app.load(&conn);

    app.enter_detail(&conn);
    // Should stay in list view since there's nothing to select
    assert_eq!(app.view, View::List);
    assert!(app.detail.is_none());
}

// --- Data loading tests ---

#[test]
fn test_tui_loads_references() {
    let (conn, _keys, _tmp) = setup_test_db();

    insert_test_ref(
        &conn,
        "aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111",
        "fp_a",
        "/home/user/.env",
        "OPENAI_API_KEY",
        Some("openai"),
    );
    insert_test_ref(
        &conn,
        "bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222",
        "fp_b",
        "/home/user/config.json",
        "$.api.key",
        None,
    );

    let mut app = App::new();
    app.load(&conn);

    assert_eq!(app.summary.total_refs, 2);
    assert_eq!(app.summary.ungrouped, 2);
    assert_eq!(app.ungrouped_items.len(), 2);
    assert!(app.group_items.is_empty());
}

#[test]
fn test_tui_loads_groups_and_ungrouped() {
    let (conn, _keys, _tmp) = setup_test_db();

    let id_a = "aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111";
    let id_b = "bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222";
    let id_c = "cccc3333cccc3333cccc3333cccc3333cccc3333cccc3333cccc3333cccc3333";

    insert_test_ref(&conn, id_a, "fp_a", "/app/.env", "API_KEY", Some("stripe"));
    insert_test_ref(&conn, id_b, "fp_a", "/deploy/.env", "API_KEY", Some("stripe"));
    insert_test_ref(&conn, id_c, "fp_c", "/other/.env", "DB_PASS", None);

    insert_test_group(&conn, "stripe-keys", &[id_a, id_b], GroupStatus::Synced);

    let mut app = App::new();
    app.load(&conn);

    assert_eq!(app.summary.total_refs, 3);
    assert_eq!(app.summary.groups, 1);
    assert_eq!(app.summary.ungrouped, 1);
    assert_eq!(app.group_items.len(), 1);
    assert_eq!(app.ungrouped_items.len(), 1);
}

// --- Navigation / state transition tests ---

#[test]
fn test_tui_navigate_groups() {
    let (conn, _keys, _tmp) = setup_test_db();

    let id_a = "aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111";
    let id_b = "bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222";
    let id_c = "cccc3333cccc3333cccc3333cccc3333cccc3333cccc3333cccc3333cccc3333";
    let id_d = "dddd4444dddd4444dddd4444dddd4444dddd4444dddd4444dddd4444dddd4444";

    insert_test_ref(&conn, id_a, "fp1", "/a", "K1", None);
    insert_test_ref(&conn, id_b, "fp1", "/b", "K2", None);
    insert_test_ref(&conn, id_c, "fp2", "/c", "K3", None);
    insert_test_ref(&conn, id_d, "fp2", "/d", "K4", None);

    insert_test_group(&conn, "alpha", &[id_a, id_b], GroupStatus::Synced);
    insert_test_group(&conn, "beta", &[id_c, id_d], GroupStatus::Drifted);

    let mut app = App::new();
    app.load(&conn);

    assert_eq!(app.group_items.len(), 2);
    assert_eq!(app.group_index, 0);

    let action = handle_key(&mut app, key(KeyCode::Char('j')));
    assert_eq!(action, KeyAction::Redraw);
    assert_eq!(app.group_index, 1);

    // Can't go past end
    handle_key(&mut app, key(KeyCode::Char('j')));
    assert_eq!(app.group_index, 1);

    let action = handle_key(&mut app, key(KeyCode::Char('k')));
    assert_eq!(action, KeyAction::Redraw);
    assert_eq!(app.group_index, 0);
}

#[test]
fn test_tui_tab_between_sections() {
    let (conn, _keys, _tmp) = setup_test_db();

    let id_a = "aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111";
    let id_b = "bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222";
    let id_c = "cccc3333cccc3333cccc3333cccc3333cccc3333cccc3333cccc3333cccc3333";

    insert_test_ref(&conn, id_a, "fp1", "/a", "K1", None);
    insert_test_ref(&conn, id_b, "fp1", "/b", "K2", None);
    insert_test_ref(&conn, id_c, "fp_c", "/c", "K3", None);

    insert_test_group(&conn, "grouped", &[id_a, id_b], GroupStatus::Synced);

    let mut app = App::new();
    app.load(&conn);

    assert_eq!(app.section, ListSection::Groups);
    assert_eq!(app.active_items().len(), 1); // 1 group

    handle_key(&mut app, key(KeyCode::Tab));
    assert_eq!(app.section, ListSection::Ungrouped);
    assert_eq!(app.active_items().len(), 1); // 1 ungrouped ref

    handle_key(&mut app, key(KeyCode::Tab));
    assert_eq!(app.section, ListSection::Groups);
}

// --- Detail selection tests ---

#[test]
fn test_tui_enter_group_detail() {
    let (conn, _keys, _tmp) = setup_test_db();

    let id_a = "aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111";
    let id_b = "bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222";

    insert_test_ref(&conn, id_a, "fp1", "/app/.env", "API_KEY", Some("stripe"));
    insert_test_ref(&conn, id_b, "fp1", "/deploy/.env", "API_KEY", Some("stripe"));

    insert_test_group(&conn, "stripe-keys", &[id_a, id_b], GroupStatus::Synced);

    let mut app = App::new();
    app.load(&conn);

    // Enter detail for the group
    app.enter_detail(&conn);
    assert_eq!(app.view, View::Detail);

    match &app.detail {
        Some(DetailInfo::Group {
            label,
            status,
            member_count,
            members,
            ..
        }) => {
            assert_eq!(label, "stripe-keys");
            assert_eq!(*status, GroupStatus::Synced);
            assert_eq!(*member_count, 2);
            assert_eq!(members.len(), 2);
        }
        other => panic!("expected Group detail, got {:?}", other),
    }
}

#[test]
fn test_tui_enter_reference_detail() {
    let (conn, _keys, _tmp) = setup_test_db();

    let id_a = "aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111";

    insert_test_ref(&conn, id_a, "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890", "/home/user/.env", "OPENAI_API_KEY", Some("openai"));

    let mut app = App::new();
    app.load(&conn);

    // Switch to ungrouped and enter detail
    app.toggle_section();
    app.enter_detail(&conn);
    assert_eq!(app.view, View::Detail);

    match &app.detail {
        Some(DetailInfo::Reference {
            file_path,
            discriminator,
            provider,
            fingerprint_prefix,
            ..
        }) => {
            assert_eq!(file_path, "/home/user/.env");
            assert_eq!(discriminator, "OPENAI_API_KEY");
            assert_eq!(provider.as_deref(), Some("openai"));
            // Fingerprint should be truncated
            assert!(fingerprint_prefix.ends_with("..."));
            assert!(fingerprint_prefix.len() < 20);
        }
        other => panic!("expected Reference detail, got {:?}", other),
    }
}

#[test]
fn test_tui_back_from_detail() {
    let (conn, _keys, _tmp) = setup_test_db();

    let id_a = "aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111";
    insert_test_ref(&conn, id_a, "fp1", "/a", "K", None);

    let mut app = App::new();
    app.load(&conn);
    app.toggle_section();
    app.enter_detail(&conn);
    assert_eq!(app.view, View::Detail);

    // Backspace goes back
    let action = handle_key(&mut app, key(KeyCode::Backspace));
    assert_eq!(action, KeyAction::Redraw);
    assert_eq!(app.view, View::List);
    assert!(app.detail.is_none());
}

// --- Refresh test ---

#[test]
fn test_tui_refresh_reloads_data() {
    let (conn, _keys, _tmp) = setup_test_db();

    let mut app = App::new();
    app.load(&conn);
    assert_eq!(app.summary.total_refs, 0);

    // Insert data after initial load
    insert_test_ref(
        &conn,
        "aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111",
        "fp1",
        "/a",
        "K",
        None,
    );

    // Refresh
    let action = handle_key(&mut app, key(KeyCode::Char('r')));
    assert_eq!(action, KeyAction::Refresh);

    // Simulate what the event loop does on Refresh
    app.load(&conn);
    assert_eq!(app.summary.total_refs, 1);
    assert_eq!(app.ungrouped_items.len(), 1);
}

// --- Security: no secret values rendered ---

#[test]
fn test_tui_no_secret_values_in_list_items() {
    let (conn, _keys, _tmp) = setup_test_db();

    insert_test_ref(
        &conn,
        "aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111",
        "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
        "/home/user/.env",
        "OPENAI_API_KEY",
        Some("openai"),
    );

    let mut app = App::new();
    app.load(&conn);

    // Check ungrouped items contain only metadata
    for item in &app.ungrouped_items {
        if let hagrid::tui::app::ListItem::Reference {
            display_id,
            file_path,
            discriminator,
            identity_key,
            ..
        } = item
        {
            // display_id should be a ref: prefix, not a value
            assert!(display_id.starts_with("ref:"));
            // file_path is metadata, not a secret
            assert!(file_path.contains('/'));
            // discriminator is a key name, not a value
            assert!(!discriminator.is_empty());
            // identity_key is a hash, not a secret value
            assert_eq!(identity_key.len(), 64);
        }
    }
}

#[test]
fn test_tui_no_secret_values_in_detail() {
    let (conn, _keys, _tmp) = setup_test_db();

    insert_test_ref(
        &conn,
        "aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111",
        "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
        "/home/user/.env",
        "STRIPE_SECRET_KEY",
        Some("stripe"),
    );

    let mut app = App::new();
    app.load(&conn);
    app.toggle_section();
    app.enter_detail(&conn);

    match &app.detail {
        Some(DetailInfo::Reference {
            fingerprint_prefix, ..
        }) => {
            // Fingerprint is truncated - only shows first 12 chars + "..."
            assert!(fingerprint_prefix.ends_with("..."));
            assert_eq!(fingerprint_prefix.len(), 15); // "abcdef123456..."
        }
        other => panic!("expected Reference detail, got {:?}", other),
    }
}

#[test]
fn test_tui_group_detail_no_secret_values() {
    let (conn, _keys, _tmp) = setup_test_db();

    let id_a = "aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111";
    let id_b = "bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222";

    insert_test_ref(&conn, id_a, "fp1", "/a/.env", "KEY", None);
    insert_test_ref(&conn, id_b, "fp1", "/b/.env", "KEY", None);

    insert_test_group(&conn, "test-group", &[id_a, id_b], GroupStatus::Synced);

    let mut app = App::new();
    app.load(&conn);
    app.enter_detail(&conn);

    match &app.detail {
        Some(DetailInfo::Group { members, .. }) => {
            for m in members {
                // Members should have display IDs (ref:...), not secret values
                assert!(m.display_id.starts_with("ref:"));
                // File paths are metadata
                assert!(m.file_path.contains('/'));
            }
        }
        other => panic!("expected Group detail, got {:?}", other),
    }
}

// --- Removed references should not appear in ungrouped list ---

#[test]
fn test_tui_removed_refs_not_in_ungrouped() {
    let (conn, _keys, _tmp) = setup_test_db();

    let now = Utc::now();
    let r = SecretReference {
        identity_key: "aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111"
            .to_string(),
        file_path: "/old/.env".to_string(),
        location: Location {
            kind: LocationKind::EnvVar,
            discriminator: "OLD_KEY".to_string(),
            line_number: Some(1),
        },
        provider_pattern: None,
        fingerprint: "fp_old".to_string(),
        display_label: "Old key".to_string(),
        first_seen: now,
        last_seen: now,
        last_changed: now,
        scan_status: ScanStatus::Removed,
    };
    db::upsert_reference(&conn, &r).unwrap();

    let mut app = App::new();
    app.load(&conn);

    // Removed refs should not appear in the ungrouped list
    assert!(app.ungrouped_items.is_empty());
    // count_references only counts Present refs
    assert_eq!(app.summary.total_refs, 0);
}

// --- Quit behavior ---

#[test]
fn test_tui_quit_from_list() {
    let mut app = App::new();
    let action = handle_key(&mut app, key(KeyCode::Char('q')));
    assert_eq!(action, KeyAction::Quit);
    assert!(app.should_quit);
}

#[test]
fn test_tui_quit_from_detail() {
    let mut app = App::new();
    app.view = View::Detail;
    let action = handle_key(&mut app, key(KeyCode::Char('q')));
    assert_eq!(action, KeyAction::Quit);
    assert!(app.should_quit);
}
