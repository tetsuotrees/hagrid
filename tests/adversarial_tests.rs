use hagrid::config::{self, Config};
use hagrid::index::db;
use hagrid::index::fingerprint;
use hagrid::scan::engine::{self, ScanDepth};
use hagrid::scan::entropy;
use std::path::PathBuf;
use tempfile::TempDir;

fn fixtures_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

// --- False Positive Tests ---

#[test]
fn test_uuid_not_flagged_as_secret() {
    // UUIDs have high entropy but are not secrets
    let is_secret = entropy::is_high_entropy("550e8400-e29b-41d4-a716-446655440000", None);
    assert!(!is_secret, "UUID should not be flagged as high-entropy secret");
}

#[test]
fn test_base64_image_not_flagged() {
    let is_secret = entropy::is_high_entropy(
        "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAA",
        None,
    );
    assert!(!is_secret, "base64 image data should not be flagged");
}

#[test]
fn test_short_strings_not_flagged() {
    assert!(!entropy::is_high_entropy("abc123", None));
    assert!(!entropy::is_high_entropy("password", None));
    assert!(!entropy::is_high_entropy("12345", None));
}

// --- Permission Tests ---

#[test]
fn test_unreadable_file_gracefully_skipped() {
    let tmp = TempDir::new().unwrap();
    let file = tmp.path().join("secret.env");
    std::fs::write(&file, "SECRET=sk-proj-test12345678901234567890123456789012345678").unwrap();

    // Make unreadable (will only work on Unix)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o000);
        std::fs::set_permissions(&file, perms).unwrap();
    }

    let config = Config::default();
    let result = engine::scan(&config, ScanDepth::Standard, Some(tmp.path()));

    // Should not panic or crash
    // Skipped files reported as errors
    #[cfg(unix)]
    {
        assert!(result.files_skipped > 0 || result.files_scanned == 0);
        // Restore permissions for cleanup
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o644);
        std::fs::set_permissions(&file, perms).unwrap();
    }
}

// --- Symlink Tests ---

#[test]
fn test_symlink_loop_detected_without_hang() {
    let tmp = TempDir::new().unwrap();

    // Create a symlink loop: a -> b -> a
    let dir_a = tmp.path().join("a");
    let dir_b = tmp.path().join("b");
    std::fs::create_dir(&dir_a).unwrap();

    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(&dir_a, &dir_b).unwrap();
        std::os::unix::fs::symlink(&dir_b, dir_a.join("loop")).unwrap();
    }

    // Write a secret in dir_a
    std::fs::write(dir_a.join("secret.env"), "KEY=sk-proj-test12345678901234567890123456789012345678").unwrap();

    let mut config = Config::default();
    config.scan.follow_symlinks = false; // default: don't follow symlinks

    let result = engine::scan(&config, ScanDepth::Standard, Some(tmp.path()));

    // Should complete without hanging
    assert!(result.files_scanned >= 1, "should scan at least the non-symlink file");
}

// --- Idempotency Tests ---

#[test]
fn test_scan_idempotent_references() {
    let tmp = TempDir::new().unwrap();
    let db_path = tmp.path().join("test.db");
    let master = b"test-master-secret-32-bytes-long!";
    let keys = fingerprint::derive_keys(master);
    let conn = db::open_db(&db_path, &keys.db_key).unwrap();
    db::migrate(&conn).unwrap();

    let config = Config::default();

    // Scan twice
    let result1 = engine::scan(&config, ScanDepth::Standard, Some(&fixtures_path()));
    let refs1 = engine::findings_to_references(
        &result1.findings,
        &keys.identity_key,
        &keys.fingerprint_key,
    );

    for r in &refs1 {
        db::upsert_reference(&conn, r).unwrap();
    }

    let result2 = engine::scan(&config, ScanDepth::Standard, Some(&fixtures_path()));
    let refs2 = engine::findings_to_references(
        &result2.findings,
        &keys.identity_key,
        &keys.fingerprint_key,
    );

    for r in &refs2 {
        db::upsert_reference(&conn, r).unwrap();
    }

    // Should have the same references with same identity keys
    let all_refs = db::list_references(&conn).unwrap();
    let identity_keys: Vec<&str> = all_refs.iter().map(|r| r.identity_key.as_str()).collect();

    // No duplicates
    let unique: std::collections::HashSet<&str> = identity_keys.iter().copied().collect();
    assert_eq!(
        identity_keys.len(),
        unique.len(),
        "should not have duplicate identity keys after re-scan"
    );
}

// --- Hard Exclusion Tests ---

#[test]
fn test_hard_exclusion_of_hagrid_db() {
    let hagrid_dir = config::hagrid_dir();

    // Create the files so canonicalize can resolve them
    std::fs::create_dir_all(hagrid_dir.join("logs")).ok();
    std::fs::write(hagrid_dir.join("hagrid.db"), b"").ok();
    std::fs::write(hagrid_dir.join("backup.tmp"), b"").ok();
    std::fs::write(hagrid_dir.join("old.bak"), b"").ok();

    assert!(config::is_hard_excluded(&hagrid_dir.join("hagrid.db")));
    assert!(config::is_hard_excluded(&hagrid_dir.join("backup.tmp")));
    assert!(config::is_hard_excluded(&hagrid_dir.join("old.bak")));
    assert!(config::is_hard_excluded(&hagrid_dir.join("logs/something.log")));

    // Clean up test files (leave dir since it may have real data)
    std::fs::remove_file(hagrid_dir.join("backup.tmp")).ok();
    std::fs::remove_file(hagrid_dir.join("old.bak")).ok();
}

#[test]
fn test_hard_exclusion_allows_config() {
    let hagrid_dir = config::hagrid_dir();

    // Config should NOT be excluded
    assert!(!config::is_hard_excluded(&hagrid_dir.join("config.toml")));
    assert!(!config::is_hard_excluded(&hagrid_dir.join("patterns.toml")));

    // Paths outside ~/.hagrid/ should never be excluded
    assert!(!config::is_hard_excluded(std::path::Path::new("/tmp/hagrid.db")));
}

// --- DB Encryption Tests ---

#[test]
fn test_db_encrypted_at_rest() {
    let tmp = TempDir::new().unwrap();
    let db_path = tmp.path().join("encrypted.db");
    let master = b"test-master-secret-32-bytes-long!";
    let keys = fingerprint::derive_keys(master);

    // Create and populate DB
    let conn = db::open_db(&db_path, &keys.db_key).unwrap();
    db::migrate(&conn).unwrap();
    drop(conn);

    // Try to open with wrong key — should fail
    let wrong_master = b"wrong-master-secret-32-bytes-ugh!";
    let wrong_keys = fingerprint::derive_keys(wrong_master);
    let result = db::open_db(&db_path, &wrong_keys.db_key);
    assert!(result.is_err(), "opening with wrong key should fail");

    // Verify the file is not readable as plain SQLite
    let raw = std::fs::read(&db_path).unwrap();
    let header = &raw[..16.min(raw.len())];
    assert_ne!(
        header,
        b"SQLite format 3\0",
        "encrypted DB should not have plain SQLite header"
    );
}

// --- Edge Case: Empty File ---

#[test]
fn test_empty_file_handled() {
    let tmp = TempDir::new().unwrap();
    std::fs::write(tmp.path().join("empty.env"), "").unwrap();

    let config = Config::default();
    let result = engine::scan(&config, ScanDepth::Standard, Some(tmp.path()));

    // Should not crash, should find nothing
    assert_eq!(result.files_scanned, 1);
    assert!(result.findings.is_empty());
}

// --- Edge Case: Binary File ---

#[test]
fn test_binary_file_skipped() {
    let tmp = TempDir::new().unwrap();
    std::fs::write(tmp.path().join("image.png"), [0x89, 0x50, 0x4E, 0x47]).unwrap();

    let config = Config::default();
    let result = engine::scan(&config, ScanDepth::Standard, Some(tmp.path()));

    // Binary files should be skipped
    let png_findings: Vec<_> = result
        .findings
        .iter()
        .filter(|f| f.file_path.ends_with(".png"))
        .collect();
    assert!(png_findings.is_empty(), "should not scan binary files");
}
