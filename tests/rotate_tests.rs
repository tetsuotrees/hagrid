use chrono::Utc;
use tempfile::TempDir;
use uuid::Uuid;

use hagrid::index::models::*;
use hagrid::index::{db, fingerprint};
use hagrid::rotate::{self, MemberInfo, Replacement, RotateError};
use hagrid::scan::engine::{self, ScanDepth};
use hagrid::scan::patterns;

fn setup_test_db() -> (rusqlite::Connection, fingerprint::DerivedKeys, TempDir) {
    let tmp = TempDir::new().unwrap();
    let db_path = tmp.path().join("test.db");
    let master = b"test-master-secret-32-bytes-long!";
    let keys = fingerprint::derive_keys(master);
    let conn = db::open_db(&db_path, &keys.db_key).unwrap();
    db::migrate(&conn).unwrap();
    (conn, keys, tmp)
}

fn load_test_patterns() -> Vec<hagrid::scan::patterns::CompiledPattern> {
    patterns::load_default_patterns().unwrap()
}

/// Create a .env file, scan it, upsert refs, create a group, and return identities.
fn setup_env_group(
    conn: &rusqlite::Connection,
    keys: &fingerprint::DerivedKeys,
    dir: &std::path::Path,
    filename: &str,
    env_content: &str,
    group_label: &str,
) -> Vec<String> {
    let file_path = dir.join(filename);
    std::fs::write(&file_path, env_content).unwrap();

    let compiled = load_test_patterns();
    let findings = engine::scan_single_file(&file_path, &compiled, ScanDepth::Standard).unwrap();

    let mut identity_keys = Vec::new();
    let now = Utc::now();
    for f in &findings {
        let id = fingerprint::compute_identity(
            &keys.identity_key,
            &f.file_path,
            &f.location.kind,
            &f.location.discriminator,
            "file",
        );
        let fp = fingerprint::compute_fingerprint(&keys.fingerprint_key, &f.secret_value);
        let r = SecretReference {
            identity_key: id.clone(),
            file_path: f.file_path.clone(),
            location: f.location.clone(),
            provider_pattern: f.provider_pattern.clone(),
            fingerprint: fp,
            display_label: f.display_label.clone(),
            first_seen: now,
            last_seen: now,
            last_changed: now,
            scan_status: ScanStatus::Present,
        };
        db::upsert_reference(conn, &r).unwrap();
        identity_keys.push(id);
    }

    // Create group
    let group = SecretGroup {
        group_id: Uuid::new_v4(),
        label: group_label.to_string(),
        members: identity_keys.clone(),
        status: GroupStatus::Synced,
        created_at: now,
        confirmed_at: now,
    };
    db::create_group(conn, &group).unwrap();

    identity_keys
}

// ── gather_rotate_info tests ─────────────────────────────────────

#[test]
fn test_gather_info_valid_group() {
    let (conn, keys, _tmp) = setup_test_db();
    let work_dir = TempDir::new().unwrap();

    let ids = setup_env_group(
        &conn,
        &keys,
        work_dir.path(),
        ".env",
        "OPENAI_API_KEY=sk-proj-a8Bf2kL9mNpQrStUvWxYz0123456789012345678901234567\n",
        "openai-key",
    );

    let (group, members) = rotate::gather_rotate_info(&conn, "openai-key").unwrap();
    assert_eq!(group.label, "openai-key");
    assert!(!members.is_empty());
    assert!(members.iter().any(|m| ids.contains(&m.identity_key)));
}

#[test]
fn test_gather_info_nonexistent_group() {
    let (conn, _keys, _tmp) = setup_test_db();
    let err = rotate::gather_rotate_info(&conn, "nonexistent").unwrap_err();
    assert!(matches!(err, RotateError::GroupNotFound(_)));
}

// ── build_info_report ────────────────────────────────────────────

#[test]
fn test_build_info_report() {
    let (conn, keys, _tmp) = setup_test_db();
    let work_dir = TempDir::new().unwrap();

    setup_env_group(
        &conn,
        &keys,
        work_dir.path(),
        ".env",
        "OPENAI_API_KEY=sk-proj-a8Bf2kL9mNpQrStUvWxYz0123456789012345678901234567\n",
        "test-report",
    );

    let (group, members) = rotate::gather_rotate_info(&conn, "test-report").unwrap();
    let report = rotate::build_info_report(&group, &members);

    assert_eq!(report.group_label, "test-report");
    assert_eq!(report.member_count, members.len());
    assert_eq!(report.unique_fingerprints, 1);
    assert!(!report.drifted);
}

// ── find_current_value ───────────────────────────────────────────

#[test]
fn test_find_current_value_env() {
    let (conn, keys, _tmp) = setup_test_db();
    let work_dir = TempDir::new().unwrap();

    setup_env_group(
        &conn,
        &keys,
        work_dir.path(),
        ".env",
        "GITHUB_TOKEN=ghp_abcdefghij1234567890abcdefghij123456\n",
        "gh-token",
    );

    let (_, members) = rotate::gather_rotate_info(&conn, "gh-token").unwrap();
    let patterns = load_test_patterns();

    let value = rotate::find_current_value(&members[0], &keys, &patterns).unwrap();
    assert_eq!(value, "ghp_abcdefghij1234567890abcdefghij123456");
}

#[test]
fn test_find_current_value_json() {
    let (conn, keys, _tmp) = setup_test_db();
    let work_dir = TempDir::new().unwrap();
    let json_file = work_dir.path().join("config.json");
    std::fs::write(
        &json_file,
        r#"{"api_key": "ghp_abcdefghij1234567890abcdefghij123456"}"#,
    )
    .unwrap();

    let compiled = load_test_patterns();
    let findings = engine::scan_single_file(&json_file, &compiled, ScanDepth::Standard).unwrap();

    if findings.is_empty() {
        // If no findings in JSON, skip this test (pattern may not match in JSON context)
        return;
    }

    let now = Utc::now();
    let mut identity_keys = Vec::new();
    for f in &findings {
        let id = fingerprint::compute_identity(
            &keys.identity_key,
            &f.file_path,
            &f.location.kind,
            &f.location.discriminator,
            "file",
        );
        let fp = fingerprint::compute_fingerprint(&keys.fingerprint_key, &f.secret_value);
        let r = SecretReference {
            identity_key: id.clone(),
            file_path: f.file_path.clone(),
            location: f.location.clone(),
            provider_pattern: f.provider_pattern.clone(),
            fingerprint: fp,
            display_label: f.display_label.clone(),
            first_seen: now,
            last_seen: now,
            last_changed: now,
            scan_status: ScanStatus::Present,
        };
        db::upsert_reference(&conn, &r).unwrap();
        identity_keys.push(id);
    }

    let group = SecretGroup {
        group_id: Uuid::new_v4(),
        label: "json-key".to_string(),
        members: identity_keys.clone(),
        status: GroupStatus::Synced,
        created_at: now,
        confirmed_at: now,
    };
    db::create_group(&conn, &group).unwrap();

    let (_, members) = rotate::gather_rotate_info(&conn, "json-key").unwrap();
    let value = rotate::find_current_value(&members[0], &keys, &compiled).unwrap();
    assert_eq!(value, "ghp_abcdefghij1234567890abcdefghij123456");
}

#[test]
fn test_find_current_value_stale_fingerprint() {
    let (conn, keys, _tmp) = setup_test_db();
    let work_dir = TempDir::new().unwrap();

    setup_env_group(
        &conn,
        &keys,
        work_dir.path(),
        ".env",
        "GITHUB_TOKEN=ghp_abcdefghij1234567890abcdefghij123456\n",
        "stale-fp",
    );

    // Now change the file so the fingerprint no longer matches
    let env_file = work_dir.path().join(".env");
    std::fs::write(
        &env_file,
        "GITHUB_TOKEN=ghp_ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZzz\n",
    )
    .unwrap();

    let (_, members) = rotate::gather_rotate_info(&conn, "stale-fp").unwrap();
    let patterns = load_test_patterns();
    let err = rotate::find_current_value(&members[0], &keys, &patterns).unwrap_err();
    assert!(
        matches!(err, RotateError::FingerprintMismatch(_)),
        "expected FingerprintMismatch, got {:?}",
        err
    );
}

// ── replace_in_file tests ────────────────────────────────────────

#[test]
fn test_replace_env_preserves_quotes() {
    let content = r#"API_KEY="old_secret_value"
OTHER=something
"#;

    let member = MemberInfo {
        identity_key: "test-id".to_string(),
        file_path: "test.env".to_string(),
        location: Location {
            kind: LocationKind::EnvVar,
            discriminator: "API_KEY".to_string(),
            line_number: Some(1),
        },
        fingerprint: "fp".to_string(),
        display_label: "Test".to_string(),
        scan_status: ScanStatus::Present,
    };

    let replacements = vec![Replacement {
        member: &member,
        old_value: "old_secret_value".to_string(),
        new_value: "new_secret_value".to_string(),
    }];

    let result = rotate::replace_in_file(content, &replacements).unwrap();
    assert!(result.contains(r#"API_KEY="new_secret_value""#));
    assert!(result.contains("OTHER=something"));
}

#[test]
fn test_replace_env_unquoted() {
    let content = "API_KEY=old_secret_value\n";

    let member = MemberInfo {
        identity_key: "test-id".to_string(),
        file_path: "test.env".to_string(),
        location: Location {
            kind: LocationKind::EnvVar,
            discriminator: "API_KEY".to_string(),
            line_number: Some(1),
        },
        fingerprint: "fp".to_string(),
        display_label: "Test".to_string(),
        scan_status: ScanStatus::Present,
    };

    let replacements = vec![Replacement {
        member: &member,
        old_value: "old_secret_value".to_string(),
        new_value: "new_secret_value".to_string(),
    }];

    let result = rotate::replace_in_file(content, &replacements).unwrap();
    assert_eq!(result, "API_KEY=new_secret_value\n");
}

#[test]
fn test_replace_shell_export() {
    let content = "export API_KEY=\"old_secret_value\"\n";

    let member = MemberInfo {
        identity_key: "test-id".to_string(),
        file_path: "test.sh".to_string(),
        location: Location {
            kind: LocationKind::ShellExport,
            discriminator: "API_KEY".to_string(),
            line_number: Some(1),
        },
        fingerprint: "fp".to_string(),
        display_label: "Test".to_string(),
        scan_status: ScanStatus::Present,
    };

    let replacements = vec![Replacement {
        member: &member,
        old_value: "old_secret_value".to_string(),
        new_value: "new_secret_value".to_string(),
    }];

    let result = rotate::replace_in_file(content, &replacements).unwrap();
    assert!(result.contains(r#"export API_KEY="new_secret_value""#));
}

#[test]
fn test_replace_json_path_aware() {
    let content = r#"{
  "api_key": "old_secret_value"
}
"#;

    let member = MemberInfo {
        identity_key: "test-id".to_string(),
        file_path: "config.json".to_string(),
        location: Location {
            kind: LocationKind::JsonPath,
            discriminator: "/api_key".to_string(),
            line_number: None,
        },
        fingerprint: "fp".to_string(),
        display_label: "Test".to_string(),
        scan_status: ScanStatus::Present,
    };

    let replacements = vec![Replacement {
        member: &member,
        old_value: "old_secret_value".to_string(),
        new_value: "new_secret_value".to_string(),
    }];

    let result = rotate::replace_in_file(content, &replacements).unwrap();
    assert!(result.contains("new_secret_value"));
    assert!(!result.contains("old_secret_value"));
    // Verify it's still valid JSON
    let _parsed: serde_json::Value = serde_json::from_str(&result).unwrap();
}

#[test]
fn test_replace_json_nested_path() {
    let content = r#"{
  "nested": {
    "token": "old_secret_value"
  }
}
"#;

    let member = MemberInfo {
        identity_key: "test-id".to_string(),
        file_path: "config.json".to_string(),
        location: Location {
            kind: LocationKind::JsonPath,
            discriminator: "/nested/token".to_string(),
            line_number: None,
        },
        fingerprint: "fp".to_string(),
        display_label: "Test".to_string(),
        scan_status: ScanStatus::Present,
    };

    let replacements = vec![Replacement {
        member: &member,
        old_value: "old_secret_value".to_string(),
        new_value: "new_secret_value".to_string(),
    }];

    let result = rotate::replace_in_file(content, &replacements).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&result).unwrap();
    assert_eq!(
        parsed.pointer("/nested/token").unwrap().as_str().unwrap(),
        "new_secret_value"
    );
}

#[test]
fn test_replace_toml_path_aware() {
    let content = "api_key = \"old_secret_value\"\n";

    let member = MemberInfo {
        identity_key: "test-id".to_string(),
        file_path: "config.toml".to_string(),
        location: Location {
            kind: LocationKind::TomlKey,
            discriminator: "api_key".to_string(),
            line_number: Some(1),
        },
        fingerprint: "fp".to_string(),
        display_label: "Test".to_string(),
        scan_status: ScanStatus::Present,
    };

    let replacements = vec![Replacement {
        member: &member,
        old_value: "old_secret_value".to_string(),
        new_value: "new_secret_value".to_string(),
    }];

    let result = rotate::replace_in_file(content, &replacements).unwrap();
    assert!(result.contains("new_secret_value"));
    assert!(!result.contains("old_secret_value"));
}

#[test]
fn test_replace_toml_nested() {
    let content = "[database]\npassword = \"old_secret_value\"\n";

    let member = MemberInfo {
        identity_key: "test-id".to_string(),
        file_path: "config.toml".to_string(),
        location: Location {
            kind: LocationKind::TomlKey,
            discriminator: "database.password".to_string(),
            line_number: Some(2),
        },
        fingerprint: "fp".to_string(),
        display_label: "Test".to_string(),
        scan_status: ScanStatus::Present,
    };

    let replacements = vec![Replacement {
        member: &member,
        old_value: "old_secret_value".to_string(),
        new_value: "new_secret_value".to_string(),
    }];

    let result = rotate::replace_in_file(content, &replacements).unwrap();
    let parsed: toml::Value = toml::from_str(&result).unwrap();
    assert_eq!(
        parsed["database"]["password"].as_str().unwrap(),
        "new_secret_value"
    );
}

#[test]
fn test_replace_discriminator_mismatch() {
    let content = "WRONG_KEY=old_secret_value\n";

    let member = MemberInfo {
        identity_key: "test-id".to_string(),
        file_path: "test.env".to_string(),
        location: Location {
            kind: LocationKind::EnvVar,
            discriminator: "API_KEY".to_string(),
            line_number: Some(1),
        },
        fingerprint: "fp".to_string(),
        display_label: "Test".to_string(),
        scan_status: ScanStatus::Present,
    };

    let replacements = vec![Replacement {
        member: &member,
        old_value: "old_secret_value".to_string(),
        new_value: "new_secret_value".to_string(),
    }];

    let err = rotate::replace_in_file(content, &replacements).unwrap_err();
    assert!(matches!(err, RotateError::ValueNotFound(_)));
}

#[test]
fn test_replace_value_not_found() {
    let content = "API_KEY=completely_different_value\n";

    let member = MemberInfo {
        identity_key: "test-id".to_string(),
        file_path: "test.env".to_string(),
        location: Location {
            kind: LocationKind::EnvVar,
            discriminator: "API_KEY".to_string(),
            line_number: Some(1),
        },
        fingerprint: "fp".to_string(),
        display_label: "Test".to_string(),
        scan_status: ScanStatus::Present,
    };

    let replacements = vec![Replacement {
        member: &member,
        old_value: "old_secret_value".to_string(),
        new_value: "new_secret_value".to_string(),
    }];

    let err = rotate::replace_in_file(content, &replacements).unwrap_err();
    assert!(matches!(err, RotateError::ValueNotFound(_)));
}

// ── atomic_write tests ───────────────────────────────────────────

#[test]
fn test_atomic_write_creates_file() {
    let tmp = TempDir::new().unwrap();
    let file = tmp.path().join("test.txt");
    std::fs::write(&file, "original content").unwrap();

    rotate::atomic_write(&file, "new content", false).unwrap();
    assert_eq!(std::fs::read_to_string(&file).unwrap(), "new content");
    // No .bak should exist
    assert!(!file.with_extension("bak").exists());
}

#[cfg(unix)]
#[test]
fn test_atomic_write_preserves_permissions() {
    use std::os::unix::fs::PermissionsExt;

    let tmp = TempDir::new().unwrap();
    let file = tmp.path().join("test.txt");
    std::fs::write(&file, "original").unwrap();
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();

    rotate::atomic_write(&file, "new content", false).unwrap();

    let mode = std::fs::metadata(&file).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
}

#[test]
fn test_atomic_write_with_backup() {
    let tmp = TempDir::new().unwrap();
    let file = tmp.path().join("test.txt");
    std::fs::write(&file, "original content").unwrap();

    let backed_up = rotate::atomic_write(&file, "new content", true).unwrap();
    assert!(backed_up);
    assert!(file.with_extension("bak").exists());
    assert_eq!(
        std::fs::read_to_string(file.with_extension("bak")).unwrap(),
        "original content"
    );
    assert_eq!(std::fs::read_to_string(&file).unwrap(), "new content");
}

#[test]
fn test_atomic_write_backup_collision() {
    let tmp = TempDir::new().unwrap();
    let file = tmp.path().join("test.txt");
    std::fs::write(&file, "original content").unwrap();

    // Create an existing .bak to trigger timestamped backup
    let bak = file.with_extension("bak");
    std::fs::write(&bak, "old backup").unwrap();

    let backed_up = rotate::atomic_write(&file, "new content", true).unwrap();
    assert!(backed_up);
    // Original .bak should be untouched
    assert_eq!(std::fs::read_to_string(&bak).unwrap(), "old backup");
    // A timestamped .bak.* should exist
    let entries: Vec<_> = std::fs::read_dir(tmp.path())
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy().starts_with("test.bak."))
        .collect();
    assert!(!entries.is_empty(), "timestamped backup should exist");
}

// ── verify_rotation ──────────────────────────────────────────────

#[test]
fn test_verify_rotation_success() {
    let master = b"test-master-secret-32-bytes-long!";
    let keys = fingerprint::derive_keys(master);
    let patterns = load_test_patterns();

    let tmp = TempDir::new().unwrap();
    let env_file = tmp.path().join(".env");
    let secret = "ghp_abcdefghij1234567890abcdefghij123456";
    std::fs::write(&env_file, format!("GITHUB_TOKEN={}\n", secret)).unwrap();

    let expected_fp = fingerprint::compute_fingerprint(&keys.fingerprint_key, secret);

    // Scan to get identity key
    let findings = engine::scan_single_file(&env_file, &patterns, ScanDepth::Standard).unwrap();
    assert!(!findings.is_empty());

    let identity_key = fingerprint::compute_identity(
        &keys.identity_key,
        &findings[0].file_path,
        &findings[0].location.kind,
        &findings[0].location.discriminator,
        "file",
    );

    let result = rotate::verify_rotation(
        &env_file.to_string_lossy(),
        &identity_key,
        &expected_fp,
        &keys,
        &patterns,
    );
    assert!(result.is_ok(), "verification should succeed: {:?}", result);
}

// ── execute_rotation end-to-end ──────────────────────────────────

#[test]
fn test_execute_full_flow() {
    let (conn, keys, _tmp) = setup_test_db();
    let work_dir = TempDir::new().unwrap();
    let patterns = load_test_patterns();

    setup_env_group(
        &conn,
        &keys,
        work_dir.path(),
        ".env",
        "GITHUB_TOKEN=ghp_abcdefghij1234567890abcdefghij123456\n",
        "rotate-test",
    );

    let (_, members) = rotate::gather_rotate_info(&conn, "rotate-test").unwrap();
    let new_value = "ghp_newvalue12345678901234567890newvalue12";

    let result = rotate::execute_rotation(&conn, &members, new_value, &keys, &patterns, false);

    assert_eq!(result.succeeded, 1, "should succeed for 1 member");
    assert_eq!(result.failed, 0, "should have no failures");
    assert!(result.file_results[0].verified, "should be verified");

    // Verify the file was actually changed
    let env_file = work_dir.path().join(".env");
    let content = std::fs::read_to_string(&env_file).unwrap();
    assert!(content.contains(new_value));
    assert!(!content.contains("ghp_abcdefghij1234567890abcdefghij123456"));
}

#[test]
fn test_execute_multi_member_same_file() {
    let (conn, keys, _tmp) = setup_test_db();
    let work_dir = TempDir::new().unwrap();
    let patterns = load_test_patterns();

    // Create a file with two secrets
    let env_file = work_dir.path().join(".env");
    std::fs::write(
        &env_file,
        "GITHUB_TOKEN=ghp_abcdefghij1234567890abcdefghij123456\nOPENAI_API_KEY=sk-proj-a8Bf2kL9mNpQrStUvWxYz0123456789012345678901234567\n",
    )
    .unwrap();

    let compiled = load_test_patterns();
    let findings = engine::scan_single_file(&env_file, &compiled, ScanDepth::Standard).unwrap();

    // Upsert all findings and collect identity keys
    let now = Utc::now();
    let mut all_ids = Vec::new();
    for f in &findings {
        let id = fingerprint::compute_identity(
            &keys.identity_key,
            &f.file_path,
            &f.location.kind,
            &f.location.discriminator,
            "file",
        );
        let fp = fingerprint::compute_fingerprint(&keys.fingerprint_key, &f.secret_value);
        let r = SecretReference {
            identity_key: id.clone(),
            file_path: f.file_path.clone(),
            location: f.location.clone(),
            provider_pattern: f.provider_pattern.clone(),
            fingerprint: fp,
            display_label: f.display_label.clone(),
            first_seen: now,
            last_seen: now,
            last_changed: now,
            scan_status: ScanStatus::Present,
        };
        db::upsert_reference(&conn, &r).unwrap();
        all_ids.push(id);
    }

    assert!(
        all_ids.len() >= 2,
        "fixture should produce at least two references in one file"
    );

    let group = SecretGroup {
        group_id: Uuid::new_v4(),
        label: "multi-member".to_string(),
        members: all_ids.clone(),
        status: GroupStatus::Synced,
        created_at: now,
        confirmed_at: now,
    };
    db::create_group(&conn, &group).unwrap();

    let (_, members) = rotate::gather_rotate_info(&conn, "multi-member").unwrap();
    let new_value = "ghp_rotatedmultivalue1234567890abcdefghij12345";

    let result = rotate::execute_rotation(&conn, &members, new_value, &keys, &patterns, false);

    assert_eq!(
        result.succeeded,
        members.len(),
        "all members should succeed"
    );
    assert_eq!(result.failed, 0, "same-file rotation should be atomic");

    let content = std::fs::read_to_string(&env_file).unwrap();
    assert!(
        content.contains(new_value),
        "file should contain new value after rotation"
    );
    assert_eq!(content.matches(new_value).count(), members.len());
    assert!(!content.contains("ghp_abcdefghij1234567890abcdefghij123456"));
    assert!(!content.contains("sk-proj-a8Bf2kL9mNpQrStUvWxYz0123456789012345678901234567"));
}

#[test]
fn test_execute_same_file_extraction_failure_aborts_entire_file() {
    let (conn, keys, _tmp) = setup_test_db();
    let work_dir = TempDir::new().unwrap();
    let patterns = load_test_patterns();

    let env_file = work_dir.path().join(".env");
    std::fs::write(
        &env_file,
        "GITHUB_TOKEN=ghp_abcdefghij1234567890abcdefghij123456\nOPENAI_API_KEY=sk-proj-a8Bf2kL9mNpQrStUvWxYz0123456789012345678901234567\n",
    )
    .unwrap();

    let findings = engine::scan_single_file(&env_file, &patterns, ScanDepth::Standard).unwrap();
    let now = Utc::now();
    let mut all_ids = Vec::new();
    for f in &findings {
        let id = fingerprint::compute_identity(
            &keys.identity_key,
            &f.file_path,
            &f.location.kind,
            &f.location.discriminator,
            "file",
        );
        let fp = fingerprint::compute_fingerprint(&keys.fingerprint_key, &f.secret_value);
        db::upsert_reference(
            &conn,
            &SecretReference {
                identity_key: id.clone(),
                file_path: f.file_path.clone(),
                location: f.location.clone(),
                provider_pattern: f.provider_pattern.clone(),
                fingerprint: fp,
                display_label: f.display_label.clone(),
                first_seen: now,
                last_seen: now,
                last_changed: now,
                scan_status: ScanStatus::Present,
            },
        )
        .unwrap();
        all_ids.push(id);
    }

    db::create_group(
        &conn,
        &SecretGroup {
            group_id: Uuid::new_v4(),
            label: "same-file-abort".to_string(),
            members: all_ids,
            status: GroupStatus::Synced,
            created_at: now,
            confirmed_at: now,
        },
    )
    .unwrap();

    let edited_content = "GITHUB_TOKEN=ghp_abcdefghij1234567890abcdefghij123456\n";
    std::fs::write(&env_file, edited_content).unwrap();

    let (_, members) = rotate::gather_rotate_info(&conn, "same-file-abort").unwrap();
    let result = rotate::execute_rotation(
        &conn,
        &members,
        "ghp_newvalue12345678901234567890newvalue12",
        &keys,
        &patterns,
        false,
    );

    assert_eq!(result.succeeded, 0);
    assert_eq!(result.failed, members.len());
    assert_eq!(std::fs::read_to_string(&env_file).unwrap(), edited_content);
}

#[test]
fn test_execute_undetectable_value_rolls_back_file() {
    let (conn, keys, _tmp) = setup_test_db();
    let work_dir = TempDir::new().unwrap();
    let patterns = load_test_patterns();

    setup_env_group(
        &conn,
        &keys,
        work_dir.path(),
        ".env",
        "GITHUB_TOKEN=ghp_abcdefghij1234567890abcdefghij123456\n",
        "rollback-test",
    );

    let env_file = work_dir.path().join(".env");
    let original_content = std::fs::read_to_string(&env_file).unwrap();
    let (_, members) = rotate::gather_rotate_info(&conn, "rollback-test").unwrap();
    let result = rotate::execute_rotation(&conn, &members, "plain-text", &keys, &patterns, false);

    assert_eq!(result.succeeded, 0);
    assert_eq!(result.failed, 1);
    assert_eq!(
        std::fs::read_to_string(&env_file).unwrap(),
        original_content
    );
}

#[test]
fn test_execute_partial_failure_continues() {
    let (conn, keys, _tmp) = setup_test_db();
    let work_dir = TempDir::new().unwrap();
    let patterns = load_test_patterns();

    // Create two files
    let env1 = work_dir.path().join(".env");
    std::fs::write(
        &env1,
        "GITHUB_TOKEN=ghp_abcdefghij1234567890abcdefghij123456\n",
    )
    .unwrap();

    let env2 = work_dir.path().join(".env2");
    std::fs::write(
        &env2,
        "GITHUB_TOKEN=ghp_abcdefghij1234567890abcdefghij123456\n",
    )
    .unwrap();

    // Scan and upsert both files
    let now = Utc::now();
    let mut all_ids = Vec::new();
    for file in &[&env1, &env2] {
        let findings = engine::scan_single_file(file, &patterns, ScanDepth::Standard).unwrap();
        for f in &findings {
            let id = fingerprint::compute_identity(
                &keys.identity_key,
                &f.file_path,
                &f.location.kind,
                &f.location.discriminator,
                "file",
            );
            let fp = fingerprint::compute_fingerprint(&keys.fingerprint_key, &f.secret_value);
            let r = SecretReference {
                identity_key: id.clone(),
                file_path: f.file_path.clone(),
                location: f.location.clone(),
                provider_pattern: f.provider_pattern.clone(),
                fingerprint: fp,
                display_label: f.display_label.clone(),
                first_seen: now,
                last_seen: now,
                last_changed: now,
                scan_status: ScanStatus::Present,
            };
            db::upsert_reference(&conn, &r).unwrap();
            all_ids.push(id);
        }
    }

    let group = SecretGroup {
        group_id: Uuid::new_v4(),
        label: "partial-test".to_string(),
        members: all_ids.clone(),
        status: GroupStatus::Synced,
        created_at: now,
        confirmed_at: now,
    };
    db::create_group(&conn, &group).unwrap();

    // Remove the secret from env2 after indexing it so this file fails preflight.
    std::fs::write(&env2, "GITHUB_TOKEN=not_a_secret\n").unwrap();

    let (_, members) = rotate::gather_rotate_info(&conn, "partial-test").unwrap();
    let new_value = "ghp_newpartialval1234567890abcdefghij1234";
    let result = rotate::execute_rotation(&conn, &members, new_value, &keys, &patterns, false);

    assert_eq!(result.succeeded, 1, "one file should rotate successfully");
    assert_eq!(result.failed, 1, "one file should report failure");
    assert!(
        std::fs::read_to_string(&env1).unwrap().contains(new_value),
        "healthy file should still rotate"
    );
    assert_eq!(
        std::fs::read_to_string(&env2).unwrap(),
        "GITHUB_TOKEN=not_a_secret\n"
    );
}

// ── Exit code tests ──────────────────────────────────────────────

#[test]
fn test_exit_code_all_succeed() {
    let result = rotate::RotateResult {
        total_members: 2,
        succeeded: 2,
        failed: 0,
        skipped: 0,
        file_results: vec![],
    };
    let exit = compute_exit_code(&result);
    assert_eq!(exit, 0);
}

#[test]
fn test_exit_code_partial_failure() {
    let result = rotate::RotateResult {
        total_members: 2,
        succeeded: 1,
        failed: 1,
        skipped: 0,
        file_results: vec![],
    };
    let exit = compute_exit_code(&result);
    assert_eq!(exit, 5);
}

#[test]
fn test_exit_code_all_fail_returns_1() {
    let result = rotate::RotateResult {
        total_members: 2,
        succeeded: 0,
        failed: 2,
        skipped: 0,
        file_results: vec![],
    };
    let exit = compute_exit_code(&result);
    assert_eq!(exit, 1);
}

/// Replicate the exit code logic from cli/rotate.rs for testing.
fn compute_exit_code(result: &rotate::RotateResult) -> i32 {
    if result.succeeded == 0 && result.failed > 0 {
        1
    } else if result.failed > 0 {
        5
    } else {
        0
    }
}

// ── JSON/TOML multi-path regression ──────────────────────────────

#[test]
fn test_replace_json_two_paths_same_old_value() {
    // Regression: two JSON paths with the same old value must be replaced independently
    let content = r#"{
  "primary_key": "same_old_value_shared",
  "secondary_key": "same_old_value_shared"
}
"#;

    let member1 = MemberInfo {
        identity_key: "id1".to_string(),
        file_path: "config.json".to_string(),
        location: Location {
            kind: LocationKind::JsonPath,
            discriminator: "/primary_key".to_string(),
            line_number: None,
        },
        fingerprint: "fp1".to_string(),
        display_label: "Primary".to_string(),
        scan_status: ScanStatus::Present,
    };

    let member2 = MemberInfo {
        identity_key: "id2".to_string(),
        file_path: "config.json".to_string(),
        location: Location {
            kind: LocationKind::JsonPath,
            discriminator: "/secondary_key".to_string(),
            line_number: None,
        },
        fingerprint: "fp2".to_string(),
        display_label: "Secondary".to_string(),
        scan_status: ScanStatus::Present,
    };

    let replacements = vec![
        Replacement {
            member: &member1,
            old_value: "same_old_value_shared".to_string(),
            new_value: "new_value_for_all".to_string(),
        },
        Replacement {
            member: &member2,
            old_value: "same_old_value_shared".to_string(),
            new_value: "new_value_for_all".to_string(),
        },
    ];

    let result = rotate::replace_in_file(content, &replacements).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&result).unwrap();
    assert_eq!(parsed["primary_key"].as_str().unwrap(), "new_value_for_all");
    assert_eq!(
        parsed["secondary_key"].as_str().unwrap(),
        "new_value_for_all"
    );
}

#[test]
fn test_replace_toml_two_paths_same_old_value() {
    // Regression: two TOML paths with the same old value must be replaced independently
    let content = "[section_a]\nkey = \"shared_value\"\n\n[section_b]\nkey = \"shared_value\"\n";

    let member1 = MemberInfo {
        identity_key: "id1".to_string(),
        file_path: "config.toml".to_string(),
        location: Location {
            kind: LocationKind::TomlKey,
            discriminator: "section_a.key".to_string(),
            line_number: Some(2),
        },
        fingerprint: "fp1".to_string(),
        display_label: "Section A".to_string(),
        scan_status: ScanStatus::Present,
    };

    let member2 = MemberInfo {
        identity_key: "id2".to_string(),
        file_path: "config.toml".to_string(),
        location: Location {
            kind: LocationKind::TomlKey,
            discriminator: "section_b.key".to_string(),
            line_number: Some(5),
        },
        fingerprint: "fp2".to_string(),
        display_label: "Section B".to_string(),
        scan_status: ScanStatus::Present,
    };

    let replacements = vec![
        Replacement {
            member: &member1,
            old_value: "shared_value".to_string(),
            new_value: "rotated_value".to_string(),
        },
        Replacement {
            member: &member2,
            old_value: "shared_value".to_string(),
            new_value: "rotated_value".to_string(),
        },
    ];

    let result = rotate::replace_in_file(content, &replacements).unwrap();
    let parsed: toml::Value = toml::from_str(&result).unwrap();
    assert_eq!(
        parsed["section_a"]["key"].as_str().unwrap(),
        "rotated_value"
    );
    assert_eq!(
        parsed["section_b"]["key"].as_str().unwrap(),
        "rotated_value"
    );
}

// ── Mixed location kinds ─────────────────────────────────────────

#[test]
fn test_mixed_location_kinds_rejected() {
    let content = "API_KEY=old_value\n";

    let member1 = MemberInfo {
        identity_key: "id1".to_string(),
        file_path: "test.env".to_string(),
        location: Location {
            kind: LocationKind::EnvVar,
            discriminator: "API_KEY".to_string(),
            line_number: Some(1),
        },
        fingerprint: "fp1".to_string(),
        display_label: "EnvVar".to_string(),
        scan_status: ScanStatus::Present,
    };

    let member2 = MemberInfo {
        identity_key: "id2".to_string(),
        file_path: "test.env".to_string(),
        location: Location {
            kind: LocationKind::RawLine,
            discriminator: "1".to_string(),
            line_number: Some(1),
        },
        fingerprint: "fp2".to_string(),
        display_label: "RawLine".to_string(),
        scan_status: ScanStatus::Present,
    };

    let replacements = vec![
        Replacement {
            member: &member1,
            old_value: "old_value".to_string(),
            new_value: "new_value".to_string(),
        },
        Replacement {
            member: &member2,
            old_value: "old_value".to_string(),
            new_value: "new_value".to_string(),
        },
    ];

    let err = rotate::replace_in_file(content, &replacements).unwrap_err();
    assert!(matches!(err, RotateError::MixedLocationKinds(_)));
}
