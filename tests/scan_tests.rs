use std::path::PathBuf;

use hagrid::config::Config;
use hagrid::index::fingerprint;
use hagrid::scan::engine::{self, ScanDepth};

fn fixtures_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

#[test]
fn test_scan_finds_secrets_in_env_file() {
    let config = Config::default();
    let result = engine::scan(&config, ScanDepth::Standard, Some(&fixtures_path()));

    assert!(result.files_scanned > 0);
    assert!(!result.findings.is_empty(), "should find secrets in fixtures");

    // Should find at least the OpenAI key and GitHub token from simple.env
    let openai_findings: Vec<_> = result
        .findings
        .iter()
        .filter(|f| f.secret_value.starts_with("sk-proj-"))
        .collect();
    assert!(!openai_findings.is_empty(), "should find OpenAI API key");

    let github_findings: Vec<_> = result
        .findings
        .iter()
        .filter(|f| f.secret_value.starts_with("ghp_"))
        .collect();
    assert!(!github_findings.is_empty(), "should find GitHub token");
}

#[test]
fn test_scan_finds_secrets_in_json() {
    let config = Config::default();
    let result = engine::scan(&config, ScanDepth::Standard, Some(&fixtures_path()));

    // Should find the OpenAI key in config.json with JSON pointer
    let json_findings: Vec<_> = result
        .findings
        .iter()
        .filter(|f| f.file_path.ends_with("config.json"))
        .collect();
    assert!(!json_findings.is_empty(), "should find secrets in config.json");
}

#[test]
fn test_scan_finds_secrets_in_toml() {
    let config = Config::default();
    let result = engine::scan(&config, ScanDepth::Standard, Some(&fixtures_path()));

    let toml_findings: Vec<_> = result
        .findings
        .iter()
        .filter(|f| f.file_path.ends_with("config.toml"))
        .collect();
    assert!(!toml_findings.is_empty(), "should find secrets in config.toml");
}

#[test]
fn test_scan_finds_secrets_in_shell_rc() {
    let config = Config::default();
    let result = engine::scan(&config, ScanDepth::Standard, Some(&fixtures_path()));

    let shell_findings: Vec<_> = result
        .findings
        .iter()
        .filter(|f| f.file_path.ends_with("bashrc_sample"))
        .collect();
    assert!(!shell_findings.is_empty(), "should find secrets in bashrc_sample");
}

#[test]
fn test_scan_lite_vs_standard() {
    let config = Config::default();

    let lite = engine::scan(&config, ScanDepth::Lite, Some(&fixtures_path()));
    let standard = engine::scan(&config, ScanDepth::Standard, Some(&fixtures_path()));

    // Standard should find at least as many as Lite (includes structural parsing)
    assert!(
        standard.findings.len() >= lite.findings.len(),
        "standard should find >= lite findings: {} vs {}",
        standard.findings.len(),
        lite.findings.len()
    );
}

#[test]
fn test_scan_is_idempotent() {
    let config = Config::default();

    let result1 = engine::scan(&config, ScanDepth::Standard, Some(&fixtures_path()));
    let result2 = engine::scan(&config, ScanDepth::Standard, Some(&fixtures_path()));

    assert_eq!(
        result1.findings.len(),
        result2.findings.len(),
        "idempotent: same number of findings"
    );
}

#[test]
fn test_scan_converts_to_references() {
    let config = Config::default();
    let result = engine::scan(&config, ScanDepth::Standard, Some(&fixtures_path()));

    let master = b"test-master-secret-32-bytes-long!";
    let keys = fingerprint::derive_keys(master);

    let refs = engine::findings_to_references(
        &result.findings,
        &keys.identity_key,
        &keys.fingerprint_key,
    );

    assert_eq!(refs.len(), result.findings.len());

    // All references should have non-empty identity keys and fingerprints
    for r in &refs {
        assert!(!r.identity_key.is_empty());
        assert_eq!(r.identity_key.len(), 64); // HMAC-SHA256 hex
        assert!(!r.fingerprint.is_empty());
        assert_eq!(r.fingerprint.len(), 64);
    }
}
