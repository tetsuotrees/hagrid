use hagrid::index::db;
use hagrid::index::fingerprint;
use hagrid::index::models::*;
use hagrid::scan::engine::{self, ScanDepth};
use hagrid::suggest;
use std::path::PathBuf;
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

fn fixtures_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

#[test]
fn test_exact_fingerprint_suggestions() {
    let (conn, keys, _tmp) = setup_test_db();
    let config = hagrid::config::Config::default();

    // Scan fixtures
    let result = engine::scan(&config, ScanDepth::Standard, Some(&fixtures_path()));
    let refs = engine::findings_to_references(
        &result.findings,
        &keys.identity_key,
        &keys.fingerprint_key,
    );

    // Insert refs into DB
    for r in &refs {
        db::upsert_reference(&conn, r).unwrap();
    }

    // Generate suggestions
    let suggestions = suggest::generate_suggestions(&conn, ScanDepth::Standard).unwrap();

    // Should have exact fingerprint match suggestions for shared secrets
    let exact: Vec<_> = suggestions
        .iter()
        .filter(|s| s.reason == SuggestionReason::ExactFingerprint)
        .collect();

    // The same OpenAI key appears in multiple fixture files
    assert!(
        !exact.is_empty(),
        "should find exact fingerprint match suggestions for shared secrets"
    );

    // All exact matches should have confidence 1.0
    for s in &exact {
        assert_eq!(s.confidence, 1.0);
        assert!(s.reference_ids.len() >= 2);
    }
}

#[test]
fn test_suggestion_deduplication() {
    let (conn, keys, _tmp) = setup_test_db();
    let config = hagrid::config::Config::default();

    let result = engine::scan(&config, ScanDepth::Standard, Some(&fixtures_path()));
    let refs = engine::findings_to_references(
        &result.findings,
        &keys.identity_key,
        &keys.fingerprint_key,
    );

    for r in &refs {
        db::upsert_reference(&conn, r).unwrap();
    }

    // Generate suggestions twice
    let _suggestions1 = suggest::generate_suggestions(&conn, ScanDepth::Standard).unwrap();
    let suggestions2 = suggest::generate_suggestions(&conn, ScanDepth::Standard).unwrap();

    // Second run should not create duplicate suggestions
    assert!(
        suggestions2.is_empty(),
        "second suggestion run should not create duplicates, found {}",
        suggestions2.len()
    );
}
