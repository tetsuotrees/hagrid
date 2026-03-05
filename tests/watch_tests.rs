use std::path::PathBuf;

use tempfile::TempDir;

use hagrid::config::Config;
use hagrid::index::{db, fingerprint};
use hagrid::scan::engine::{self, ScanDepth};
use hagrid::scan::patterns;
use hagrid::watch;

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

// ── process_file_change tests ─────────────────────────────────────

#[test]
fn test_watch_detects_new_file() {
    let (conn, keys, _tmp) = setup_test_db();
    let config = Config::default();
    let patterns = load_test_patterns();

    // Create a temp file with a secret
    let watch_dir = TempDir::new().unwrap();
    let env_file = watch_dir.path().join(".env");
    std::fs::write(
        &env_file,
        "OPENAI_API_KEY=sk-proj-a8Bf2kL9mNpQrStUvWxYz0123456789012345678901234567\n",
    )
    .unwrap();

    let result = watch::process_file_change(&env_file, &conn, &keys, &patterns, &config);

    assert!(result.findings_count > 0, "should find at least one secret");
    assert!(result.upserted > 0, "should upsert findings into DB");
    assert!(result.errors.is_empty(), "should have no errors");
}

#[test]
fn test_watch_idempotent_events() {
    let (conn, keys, _tmp) = setup_test_db();
    let config = Config::default();
    let patterns = load_test_patterns();

    let watch_dir = TempDir::new().unwrap();
    let env_file = watch_dir.path().join(".env");
    std::fs::write(
        &env_file,
        "GITHUB_TOKEN=ghp_abcdefghij1234567890abcdefghij123456\n",
    )
    .unwrap();

    // Process same file twice — should be idempotent
    let r1 = watch::process_file_change(&env_file, &conn, &keys, &patterns, &config);
    let r2 = watch::process_file_change(&env_file, &conn, &keys, &patterns, &config);

    assert_eq!(
        r1.findings_count, r2.findings_count,
        "repeated events should produce same finding count"
    );
    assert_eq!(
        r1.upserted, r2.upserted,
        "repeated events should upsert same count (upsert is idempotent)"
    );

    // DB should still have exactly the same references
    let refs = db::list_references(&conn).unwrap();
    let github_refs: Vec<_> = refs
        .iter()
        .filter(|r| r.display_label.contains("GitHub") || r.display_label.contains("github"))
        .collect();
    assert!(
        !github_refs.is_empty(),
        "DB should contain the GitHub token reference"
    );
}

#[test]
fn test_watch_deleted_file_noop() {
    let (conn, keys, _tmp) = setup_test_db();
    let config = Config::default();
    let patterns = load_test_patterns();

    // Process a non-existent file — should be a no-op
    let fake_path = PathBuf::from("/tmp/definitely-does-not-exist-hagrid-test.env");
    let result = watch::process_file_change(&fake_path, &conn, &keys, &patterns, &config);

    assert_eq!(result.findings_count, 0);
    assert_eq!(result.upserted, 0);
    assert!(result.errors.is_empty());
}

#[test]
fn test_watch_no_roots_returns_error() {
    let (conn, keys, _tmp) = setup_test_db();
    let mut config = Config::default();

    // Point roots at a path that does not exist.
    let non_existent = std::env::temp_dir().join("hagrid-watch-missing-root");
    if non_existent.exists() {
        let _ = std::fs::remove_file(&non_existent);
    }
    config.scan.roots = vec![non_existent.to_string_lossy().to_string()];

    let exit = watch::run_watch(&conn, &keys, &config);
    assert_eq!(exit, 1, "watch should fail when no scan roots exist");
}

#[test]
fn test_watch_binary_file_skipped() {
    let (conn, keys, _tmp) = setup_test_db();
    let config = Config::default();
    let patterns = load_test_patterns();

    let watch_dir = TempDir::new().unwrap();
    let bin_file = watch_dir.path().join("image.png");
    std::fs::write(&bin_file, b"fake png content with OPENAI_API_KEY=sk-proj-test1234").unwrap();

    let result = watch::process_file_change(&bin_file, &conn, &keys, &patterns, &config);

    assert_eq!(result.findings_count, 0, "binary files should be skipped");
    assert_eq!(result.upserted, 0);
}

#[test]
fn test_watch_excluded_dir_skipped() {
    let (conn, keys, _tmp) = setup_test_db();
    let config = Config::default();
    let patterns = load_test_patterns();

    // Create a file inside node_modules (excluded dir)
    let watch_dir = TempDir::new().unwrap();
    let nm_dir = watch_dir.path().join("node_modules").join("some-pkg");
    std::fs::create_dir_all(&nm_dir).unwrap();
    let env_file = nm_dir.join(".env");
    std::fs::write(
        &env_file,
        "OPENAI_API_KEY=sk-proj-a8Bf2kL9mNpQrStUvWxYz0123456789012345678901234567\n",
    )
    .unwrap();

    let result = watch::process_file_change(&env_file, &conn, &keys, &patterns, &config);

    assert_eq!(
        result.findings_count, 0,
        "files in excluded dirs should be skipped"
    );
}

#[test]
fn test_watch_permission_denied_handled() {
    let (conn, keys, _tmp) = setup_test_db();
    let config = Config::default();
    let patterns = load_test_patterns();

    let watch_dir = TempDir::new().unwrap();
    let env_file = watch_dir.path().join(".env");
    std::fs::write(
        &env_file,
        "OPENAI_API_KEY=sk-proj-a8Bf2kL9mNpQrStUvWxYz0123456789012345678901234567\n",
    )
    .unwrap();

    // Make file unreadable
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&env_file, std::fs::Permissions::from_mode(0o000)).unwrap();
    }

    let result = watch::process_file_change(&env_file, &conn, &keys, &patterns, &config);

    // Should handle gracefully — either skip or report error, but not panic
    // On macOS running as root or with SIP, permissions might not apply the same way,
    // so we just verify it doesn't panic.
    assert!(
        result.findings_count == 0 || !result.errors.is_empty(),
        "unreadable file should produce no findings or an error"
    );

    // Restore permissions for cleanup
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&env_file, std::fs::Permissions::from_mode(0o644));
    }
}

#[test]
fn test_watch_upsert_only_no_removal() {
    let (conn, keys, _tmp) = setup_test_db();
    let config = Config::default();
    let patterns = load_test_patterns();

    let watch_dir = TempDir::new().unwrap();

    // First, create and process a file
    let env_file = watch_dir.path().join(".env");
    std::fs::write(
        &env_file,
        "GITHUB_TOKEN=ghp_abcdefghij1234567890abcdefghij123456\n",
    )
    .unwrap();
    watch::process_file_change(&env_file, &conn, &keys, &patterns, &config);

    let refs_before = db::list_references(&conn).unwrap();
    let present_before = refs_before
        .iter()
        .filter(|r| r.scan_status == hagrid::index::models::ScanStatus::Present)
        .count();
    assert!(present_before > 0, "should have at least one present ref");

    // Now process a DIFFERENT file — the first file's refs should NOT be marked removed
    let env_file2 = watch_dir.path().join(".env2");
    std::fs::write(
        &env_file2,
        "OPENAI_API_KEY=sk-proj-a8Bf2kL9mNpQrStUvWxYz0123456789012345678901234567\n",
    )
    .unwrap();
    watch::process_file_change(&env_file2, &conn, &keys, &patterns, &config);

    let refs_after = db::list_references(&conn).unwrap();
    let present_after = refs_after
        .iter()
        .filter(|r| r.scan_status == hagrid::index::models::ScanStatus::Present)
        .count();

    // Present count should only grow (upsert-only, no removals)
    assert!(
        present_after >= present_before,
        "watch mode should not remove refs: before={} after={}",
        present_before,
        present_after
    );
}

// ── D-1 dedup regression tests ────────────────────────────────────

#[test]
fn test_d1_dedup_standard_coalesces_rawline_and_structural() {
    // In Standard depth, a secret in a .env file should produce a single
    // finding (structural EnvVar), not both a RawLine and an EnvVar.
    let config = Config::default();

    let tmp = TempDir::new().unwrap();
    let env_file = tmp.path().join("simple.env");
    std::fs::write(
        &env_file,
        "OPENAI_API_KEY=sk-proj-a8Bf2kL9mNpQrStUvWxYz0123456789012345678901234567\n",
    )
    .unwrap();

    let result = engine::scan(&config, ScanDepth::Standard, Some(tmp.path()));

    // Should find the OpenAI key
    let openai: Vec<_> = result
        .findings
        .iter()
        .filter(|f| f.secret_value.starts_with("sk-proj-"))
        .collect();

    assert!(
        !openai.is_empty(),
        "should find the OpenAI key"
    );

    // D-1 fix: there should be exactly 1 finding for this secret value,
    // NOT 2 (one RawLine + one EnvVar). The structural finding should survive.
    assert_eq!(
        openai.len(),
        1,
        "D-1: should coalesce RawLine + EnvVar into 1 finding, got {}",
        openai.len()
    );

    // The surviving finding should be the structural one (EnvVar), not RawLine
    assert_ne!(
        openai[0].location.kind,
        hagrid::index::models::LocationKind::RawLine,
        "D-1: structural finding should survive over RawLine"
    );
}

#[test]
fn test_d1_dedup_lite_unaffected() {
    // Lite depth only does pattern matching (no structural parsing),
    // so findings should all be RawLine — no dedup needed.
    let config = Config::default();

    let tmp = TempDir::new().unwrap();
    let env_file = tmp.path().join("simple.env");
    std::fs::write(
        &env_file,
        "OPENAI_API_KEY=sk-proj-a8Bf2kL9mNpQrStUvWxYz0123456789012345678901234567\n",
    )
    .unwrap();

    let result = engine::scan(&config, ScanDepth::Lite, Some(tmp.path()));

    let openai: Vec<_> = result
        .findings
        .iter()
        .filter(|f| f.secret_value.starts_with("sk-proj-"))
        .collect();

    assert_eq!(
        openai.len(),
        1,
        "Lite should produce exactly 1 RawLine finding"
    );
    assert_eq!(
        openai[0].location.kind,
        hagrid::index::models::LocationKind::RawLine,
    );
}

#[test]
fn test_d1_standard_lte_lite_or_equal_after_dedup() {
    // After D-1 fix, standard findings may be <= lite findings for structured
    // files (where structural replaces RawLine). But standard should still
    // find secrets in files that only lite would find via pattern matching.
    let config = Config::default();
    let fixtures = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");

    let lite = engine::scan(&config, ScanDepth::Lite, Some(&fixtures));
    let standard = engine::scan(&config, ScanDepth::Standard, Some(&fixtures));

    // Standard should still find secrets
    assert!(!standard.findings.is_empty(), "standard should find secrets");

    // After D-1, standard findings can be fewer than lite in structured files
    // (because RawLine duplicates are removed). The relationship is no longer
    // guaranteed to be >=, so we just verify both modes work.
    assert!(!lite.findings.is_empty(), "lite should find secrets");
}

#[test]
fn test_watch_scan_single_file_consistent_with_full_scan() {
    let patterns = load_test_patterns();

    let tmp = TempDir::new().unwrap();
    let env_file = tmp.path().join("simple.env");
    std::fs::write(
        &env_file,
        "GITHUB_TOKEN=ghp_abcdefghij1234567890abcdefghij123456\nOPENAI_API_KEY=sk-proj-a8Bf2kL9mNpQrStUvWxYz0123456789012345678901234567\n",
    )
    .unwrap();

    // scan_single_file should return the same findings as a full scan of the same file
    let single = engine::scan_single_file(&env_file, &patterns, ScanDepth::Standard).unwrap();

    let config = Config::default();
    let full = engine::scan(&config, ScanDepth::Standard, Some(tmp.path()));

    assert_eq!(
        single.len(),
        full.findings.len(),
        "scan_single_file and full scan should produce same findings for same file"
    );
}

// ── Symlink safety ────────────────────────────────────────────────

#[cfg(unix)]
#[test]
fn test_watch_symlink_loop_handled() {
    let (conn, keys, _tmp) = setup_test_db();
    let config = Config::default();
    let patterns = load_test_patterns();

    let watch_dir = TempDir::new().unwrap();

    // Create a symlink loop: link_a -> link_b -> link_a
    let link_a = watch_dir.path().join("link_a");
    let link_b = watch_dir.path().join("link_b");
    std::os::unix::fs::symlink(&link_b, &link_a).unwrap();
    std::os::unix::fs::symlink(&link_a, &link_b).unwrap();

    // Processing a symlink loop should not panic or hang
    let result = watch::process_file_change(&link_a, &conn, &keys, &patterns, &config);

    // The symlink doesn't point to a real file, so it should be treated as deleted/non-existent
    assert_eq!(result.findings_count, 0);
}
