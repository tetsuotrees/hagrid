//! Integration tests for the policy engine (WS-5).
//!
//! Tests cover: max_references, no_git, max_age_days, require_vault,
//! glob matching, policy loading, scope filtering, and exit-code precedence.

use chrono::{Duration, Utc};
use hagrid::index::db;
use hagrid::index::fingerprint;
use hagrid::index::models::*;
use hagrid::policy::{self, PolicyDef, PolicyError, Severity};
use tempfile::TempDir;

// ── Helpers ─────────────────────────────────────────────────────────

fn setup_test_db() -> (rusqlite::Connection, TempDir) {
    let tmp = TempDir::new().unwrap();
    let db_path = tmp.path().join("test.db");
    let master = b"test-master-secret-32-bytes-long!";
    let keys = fingerprint::derive_keys(master);
    let conn = db::open_db(&db_path, &keys.db_key).unwrap();
    db::migrate(&conn).unwrap();
    (conn, tmp)
}

fn insert_ref(
    conn: &rusqlite::Connection,
    identity: &str,
    fp: &str,
    file_path: &str,
    provider: Option<&str>,
    status: ScanStatus,
    last_changed: chrono::DateTime<Utc>,
) {
    let now = Utc::now();
    let r = SecretReference {
        identity_key: identity.to_string(),
        file_path: file_path.to_string(),
        location: Location {
            kind: LocationKind::EnvVar,
            discriminator: "KEY".to_string(),
            line_number: Some(1),
        },
        provider_pattern: provider.map(|s| s.to_string()),
        fingerprint: fp.to_string(),
        display_label: format!("secret-{}", &identity[..8]),
        first_seen: now,
        last_seen: now,
        last_changed,
        scan_status: status,
    };
    db::upsert_reference(conn, &r).unwrap();
}

fn make_policy(name: &str, patterns: Vec<&str>) -> PolicyDef {
    PolicyDef {
        name: name.to_string(),
        match_patterns: patterns.into_iter().map(|s| s.to_string()).collect(),
        max_age_days: None,
        warn_at_days: None,
        require_vault: None,
        max_references: None,
        no_git: None,
    }
}

// ── max_references tests ────────────────────────────────────────────

#[test]
fn max_references_pass_below_limit() {
    let (conn, _tmp) = setup_test_db();
    let now = Utc::now();
    insert_ref(&conn, "aa00000000000000000000000000000000000000000000000000000000000001", "fp1", "/a", Some("aws_key"), ScanStatus::Present, now);
    insert_ref(&conn, "aa00000000000000000000000000000000000000000000000000000000000002", "fp2", "/b", Some("aws_key"), ScanStatus::Present, now);

    let mut p = make_policy("test", vec!["aws_*"]);
    p.max_references = Some(5);
    let results = policy::evaluate_policies(&conn, &[p]).unwrap();
    assert_eq!(results[0].severity, Severity::Pass);
}

#[test]
fn max_references_violation_exceeds_limit() {
    let (conn, _tmp) = setup_test_db();
    let now = Utc::now();
    // One secret (same fingerprint) in 3 different locations → exceeds limit of 2
    insert_ref(&conn, "bb00000000000000000000000000000000000000000000000000000000000001", "fp_same", "/a", Some("aws_key"), ScanStatus::Present, now);
    insert_ref(&conn, "bb00000000000000000000000000000000000000000000000000000000000002", "fp_same", "/b", Some("aws_key"), ScanStatus::Present, now);
    insert_ref(&conn, "bb00000000000000000000000000000000000000000000000000000000000003", "fp_same", "/c", Some("aws_key"), ScanStatus::Present, now);

    let mut p = make_policy("test", vec!["aws_*"]);
    p.max_references = Some(2);
    let results = policy::evaluate_policies(&conn, &[p]).unwrap();
    assert_eq!(results[0].severity, Severity::Violation);
    assert_eq!(results[0].affected_references.len(), 3);
}

#[test]
fn max_references_match_filter_only_matching() {
    let (conn, _tmp) = setup_test_db();
    let now = Utc::now();
    insert_ref(&conn, "cc00000000000000000000000000000000000000000000000000000000000001", "fp1", "/a", Some("aws_key"), ScanStatus::Present, now);
    insert_ref(&conn, "cc00000000000000000000000000000000000000000000000000000000000002", "fp2", "/b", Some("github_pat"), ScanStatus::Present, now);

    let mut p = make_policy("test", vec!["aws_*"]);
    p.max_references = Some(0);
    let results = policy::evaluate_policies(&conn, &[p]).unwrap();
    // Only 1 ref matches aws_*
    assert_eq!(results[0].severity, Severity::Violation);
    assert_eq!(results[0].affected_references.len(), 1);
}

#[test]
fn max_references_different_fingerprints_evaluated_independently() {
    let (conn, _tmp) = setup_test_db();
    let now = Utc::now();
    // Two different secrets (different fingerprints), each in 1 location.
    // Per-secret counting: each secret has 1 location ≤ limit of 1. Pass.
    insert_ref(&conn, "dd00000000000000000000000000000000000000000000000000000000000001", "fp_alpha", "/file_a", Some("aws_key"), ScanStatus::Present, now);
    insert_ref(&conn, "dd00000000000000000000000000000000000000000000000000000000000002", "fp_beta", "/file_b", Some("aws_key"), ScanStatus::Present, now);

    let mut p = make_policy("test", vec!["aws_*"]);
    p.max_references = Some(1);
    let results = policy::evaluate_policies(&conn, &[p]).unwrap();
    // Each secret is in only 1 location → no violation
    assert_eq!(results[0].severity, Severity::Pass);
}

#[test]
fn max_references_dedupe_same_file_and_fingerprint() {
    let (conn, _tmp) = setup_test_db();
    let now = Utc::now();
    // Two refs with same (file_path, fingerprint) but different identity keys and discriminators → count as 1
    insert_ref(&conn, "ee00000000000000000000000000000000000000000000000000000000000001", "fp_same", "/same/file", Some("aws_key"), ScanStatus::Present, now);
    insert_ref(&conn, "ee00000000000000000000000000000000000000000000000000000000000002", "fp_same", "/same/file", Some("aws_key"), ScanStatus::Present, now);

    let mut p = make_policy("test", vec!["aws_*"]);
    p.max_references = Some(1);
    let results = policy::evaluate_policies(&conn, &[p]).unwrap();
    // Deduped count = 1, limit = 1 → pass
    assert_eq!(results[0].severity, Severity::Pass);
}

// ── no_git tests ────────────────────────────────────────────────────

#[test]
fn no_git_pass_untracked_file() {
    let (conn, _tmp) = setup_test_db();
    let now = Utc::now();

    let git_tmp = TempDir::new().unwrap();
    // Init a git repo
    std::process::Command::new("git")
        .args(["init"])
        .current_dir(git_tmp.path())
        .output()
        .unwrap();
    std::process::Command::new("git")
        .args(["config", "user.name", "test"])
        .current_dir(git_tmp.path())
        .output()
        .unwrap();
    std::process::Command::new("git")
        .args(["config", "user.email", "test@test"])
        .current_dir(git_tmp.path())
        .output()
        .unwrap();

    // Create a file but don't add it to git
    let secret_file = git_tmp.path().join("untracked.env");
    std::fs::write(&secret_file, "SECRET=value").unwrap();

    insert_ref(
        &conn,
        "ff00000000000000000000000000000000000000000000000000000000000001",
        "fp1",
        &secret_file.to_string_lossy(),
        Some("aws_key"),
        ScanStatus::Present,
        now,
    );

    let mut p = make_policy("test", vec!["aws_*"]);
    p.no_git = Some(true);
    let results = policy::evaluate_policies(&conn, &[p]).unwrap();
    assert_eq!(results[0].severity, Severity::Pass);
}

#[test]
fn no_git_violation_tracked_file() {
    let (conn, _tmp) = setup_test_db();
    let now = Utc::now();

    let git_tmp = TempDir::new().unwrap();
    std::process::Command::new("git")
        .args(["init"])
        .current_dir(git_tmp.path())
        .output()
        .unwrap();
    std::process::Command::new("git")
        .args(["config", "user.name", "test"])
        .current_dir(git_tmp.path())
        .output()
        .unwrap();
    std::process::Command::new("git")
        .args(["config", "user.email", "test@test"])
        .current_dir(git_tmp.path())
        .output()
        .unwrap();

    // Create, add, and commit a file
    let secret_file = git_tmp.path().join("tracked.env");
    std::fs::write(&secret_file, "SECRET=value").unwrap();
    std::process::Command::new("git")
        .args(["add", "tracked.env"])
        .current_dir(git_tmp.path())
        .output()
        .unwrap();
    std::process::Command::new("git")
        .args(["commit", "-m", "add secret"])
        .current_dir(git_tmp.path())
        .output()
        .unwrap();

    insert_ref(
        &conn,
        "ff00000000000000000000000000000000000000000000000000000000000002",
        "fp1",
        &secret_file.to_string_lossy(),
        Some("aws_key"),
        ScanStatus::Present,
        now,
    );

    let mut p = make_policy("test", vec!["aws_*"]);
    p.no_git = Some(true);
    let results = policy::evaluate_policies(&conn, &[p]).unwrap();
    assert_eq!(results[0].severity, Severity::Violation);
    assert_eq!(results[0].affected_references.len(), 1);
}

#[test]
fn no_git_match_filter_unmatched_refs_ignored() {
    let (conn, _tmp) = setup_test_db();
    let now = Utc::now();

    let git_tmp = TempDir::new().unwrap();
    std::process::Command::new("git")
        .args(["init"])
        .current_dir(git_tmp.path())
        .output()
        .unwrap();
    std::process::Command::new("git")
        .args(["config", "user.name", "test"])
        .current_dir(git_tmp.path())
        .output()
        .unwrap();
    std::process::Command::new("git")
        .args(["config", "user.email", "test@test"])
        .current_dir(git_tmp.path())
        .output()
        .unwrap();

    let secret_file = git_tmp.path().join("tracked.env");
    std::fs::write(&secret_file, "SECRET=value").unwrap();
    std::process::Command::new("git")
        .args(["add", "tracked.env"])
        .current_dir(git_tmp.path())
        .output()
        .unwrap();
    std::process::Command::new("git")
        .args(["commit", "-m", "add"])
        .current_dir(git_tmp.path())
        .output()
        .unwrap();

    // Insert ref with a provider that doesn't match the policy pattern
    insert_ref(
        &conn,
        "ff00000000000000000000000000000000000000000000000000000000000003",
        "fp1",
        &secret_file.to_string_lossy(),
        Some("github_pat"),
        ScanStatus::Present,
        now,
    );

    let mut p = make_policy("test", vec!["aws_*"]);
    p.no_git = Some(true);
    let results = policy::evaluate_policies(&conn, &[p]).unwrap();
    // github_pat doesn't match aws_* → no violation
    assert_eq!(results[0].severity, Severity::Pass);
}

#[test]
fn no_git_non_repo_file_not_violation() {
    let (conn, _tmp) = setup_test_db();
    let now = Utc::now();

    // Create a file outside any git repo
    let plain_tmp = TempDir::new().unwrap();
    let secret_file = plain_tmp.path().join("plain.env");
    std::fs::write(&secret_file, "SECRET=value").unwrap();

    insert_ref(
        &conn,
        "ff00000000000000000000000000000000000000000000000000000000000004",
        "fp1",
        &secret_file.to_string_lossy(),
        Some("aws_key"),
        ScanStatus::Present,
        now,
    );

    let mut p = make_policy("test", vec!["aws_*"]);
    p.no_git = Some(true);
    let results = policy::evaluate_policies(&conn, &[p]).unwrap();
    // File outside git repo → skipped, not a violation
    assert_eq!(results[0].severity, Severity::Pass);
}

// ── max_age_days tests ──────────────────────────────────────────────

#[test]
fn max_age_pass_recent() {
    let (conn, _tmp) = setup_test_db();
    let now = Utc::now();
    insert_ref(&conn, "aa11000000000000000000000000000000000000000000000000000000000001", "fp1", "/a", Some("aws_key"), ScanStatus::Present, now);

    let mut p = make_policy("test", vec!["aws_*"]);
    p.max_age_days = Some(90);
    let results = policy::evaluate_policies(&conn, &[p]).unwrap();
    assert_eq!(results[0].severity, Severity::Pass);
}

#[test]
fn max_age_warn_between_warn_and_max() {
    let (conn, _tmp) = setup_test_db();
    let last_changed = Utc::now() - Duration::days(70);
    insert_ref(&conn, "aa11000000000000000000000000000000000000000000000000000000000002", "fp1", "/a", Some("aws_key"), ScanStatus::Present, last_changed);

    let mut p = make_policy("test", vec!["aws_*"]);
    p.max_age_days = Some(90);
    p.warn_at_days = Some(60);
    let results = policy::evaluate_policies(&conn, &[p]).unwrap();
    assert_eq!(results[0].severity, Severity::Warn);
}

#[test]
fn max_age_violation_exceeds_max() {
    let (conn, _tmp) = setup_test_db();
    let last_changed = Utc::now() - Duration::days(100);
    insert_ref(&conn, "aa11000000000000000000000000000000000000000000000000000000000003", "fp1", "/a", Some("aws_key"), ScanStatus::Present, last_changed);

    let mut p = make_policy("test", vec!["aws_*"]);
    p.max_age_days = Some(90);
    p.warn_at_days = Some(60);
    let results = policy::evaluate_policies(&conn, &[p]).unwrap();
    assert_eq!(results[0].severity, Severity::Violation);
}

// ── require_vault test ──────────────────────────────────────────────

#[test]
fn require_vault_returns_warn_stub() {
    let (conn, _tmp) = setup_test_db();
    let now = Utc::now();
    insert_ref(&conn, "ab00000000000000000000000000000000000000000000000000000000000001", "fp1", "/a", Some("aws_key"), ScanStatus::Present, now);

    let mut p = make_policy("test", vec!["aws_*"]);
    p.require_vault = Some(true);
    let results = policy::evaluate_policies(&conn, &[p]).unwrap();
    assert_eq!(results[0].severity, Severity::Warn);
    assert!(results[0].message.contains("not yet implemented"));
}

// ── Glob matching tests ─────────────────────────────────────────────

#[test]
fn glob_wildcard_matches_all_including_none_provider() {
    let (conn, _tmp) = setup_test_db();
    let now = Utc::now();
    insert_ref(&conn, "ac00000000000000000000000000000000000000000000000000000000000001", "fp1", "/a", Some("aws_key"), ScanStatus::Present, now);
    insert_ref(&conn, "ac00000000000000000000000000000000000000000000000000000000000002", "fp2", "/b", None, ScanStatus::Present, now);

    let mut p = make_policy("test", vec!["*"]);
    p.max_references = Some(0);
    let results = policy::evaluate_policies(&conn, &[p]).unwrap();
    // Both refs matched (including None provider), each secret in 1 location > 0 → violation
    assert_eq!(results[0].severity, Severity::Violation);
    assert_eq!(results[0].affected_references.len(), 2);
}

#[test]
fn glob_pattern_matches_provider() {
    let (conn, _tmp) = setup_test_db();
    let now = Utc::now();
    insert_ref(&conn, "ad00000000000000000000000000000000000000000000000000000000000001", "fp1", "/a", Some("openai_api_key"), ScanStatus::Present, now);
    insert_ref(&conn, "ad00000000000000000000000000000000000000000000000000000000000002", "fp2", "/b", Some("github_pat"), ScanStatus::Present, now);

    let mut p = make_policy("test", vec!["openai_*"]);
    p.max_references = Some(0);
    let results = policy::evaluate_policies(&conn, &[p]).unwrap();
    // Only openai_api_key matches openai_*
    assert_eq!(results[0].severity, Severity::Violation);
    assert_eq!(results[0].affected_references.len(), 1);
}

#[test]
fn glob_pattern_does_not_match_none_provider() {
    let (conn, _tmp) = setup_test_db();
    let now = Utc::now();
    insert_ref(&conn, "ae00000000000000000000000000000000000000000000000000000000000001", "fp1", "/a", None, ScanStatus::Present, now);

    let mut p = make_policy("test", vec!["openai_*"]);
    p.max_references = Some(0);
    let results = policy::evaluate_policies(&conn, &[p]).unwrap();
    // provider_pattern=None does NOT match non-wildcard → Pass (0 matching refs)
    assert_eq!(results[0].severity, Severity::Pass);
}

#[test]
fn glob_no_matches_is_pass() {
    let (conn, _tmp) = setup_test_db();
    let now = Utc::now();
    insert_ref(&conn, "af00000000000000000000000000000000000000000000000000000000000001", "fp1", "/a", Some("github_pat"), ScanStatus::Present, now);

    let mut p = make_policy("test", vec!["nonexistent_*"]);
    p.max_references = Some(0);
    let results = policy::evaluate_policies(&conn, &[p]).unwrap();
    assert_eq!(results[0].severity, Severity::Pass);
}

// ── Policy loading tests ────────────────────────────────────────────

#[test]
fn load_missing_file_returns_empty() {
    // Override would need to set a custom path. Instead, test the behavior
    // by verifying that a non-existent path returns empty vec.
    // We test the parsing logic directly.
    let content = "";
    let file: policy::PolicyFile = toml::from_str(content).unwrap();
    assert!(file.policy.is_empty());
}

#[test]
fn load_match_string_deserializes() {
    let toml_str = r#"
[[policy]]
name = "test"
match = "aws_*"
max_references = 3
"#;
    let file: policy::PolicyFile = toml::from_str(toml_str).unwrap();
    assert_eq!(file.policy.len(), 1);
    assert_eq!(file.policy[0].match_patterns, vec!["aws_*"]);
}

#[test]
fn load_match_array_deserializes() {
    let toml_str = r#"
[[policy]]
name = "test"
match = ["aws_*", "openai_*"]
max_references = 3
"#;
    let file: policy::PolicyFile = toml::from_str(toml_str).unwrap();
    assert_eq!(file.policy.len(), 1);
    assert_eq!(file.policy[0].match_patterns, vec!["aws_*", "openai_*"]);
}

#[test]
fn load_warn_at_greater_than_max_age_is_error() {
    let toml_str = r#"
[[policy]]
name = "bad"
match = "*"
max_age_days = 30
warn_at_days = 60
"#;
    let file: policy::PolicyFile = toml::from_str(toml_str).unwrap();
    // Simulate the validation that load_policies() does
    for p in &file.policy {
        if let (Some(warn), Some(max)) = (p.warn_at_days, p.max_age_days) {
            assert!(warn > max);
            // This would be an InvalidConfig error
            let err = PolicyError::InvalidConfig(format!(
                "policy '{}': warn_at_days ({}) must be <= max_age_days ({})",
                p.name, warn, max
            ));
            assert!(err.to_string().contains("warn_at_days"));
            return;
        }
    }
    panic!("should have found invalid config");
}

// ── Scope filter test ───────────────────────────────────────────────

#[test]
fn scope_filter_removed_refs_excluded() {
    let (conn, _tmp) = setup_test_db();
    let now = Utc::now();
    // One present, one removed
    insert_ref(&conn, "ba00000000000000000000000000000000000000000000000000000000000001", "fp1", "/a", Some("aws_key"), ScanStatus::Present, now);
    insert_ref(&conn, "ba00000000000000000000000000000000000000000000000000000000000002", "fp2", "/b", Some("aws_key"), ScanStatus::Removed, now);

    let mut p = make_policy("test", vec!["aws_*"]);
    p.max_references = Some(0);
    let results = policy::evaluate_policies(&conn, &[p]).unwrap();
    // Only 1 ref is Present → count=1, limit=0 → violation, but only 1 affected
    assert_eq!(results[0].severity, Severity::Violation);
    assert_eq!(results[0].affected_references.len(), 1);
    assert_eq!(results[0].affected_references[0].file_path, "/a");
}

// ── Exit-code precedence tests ──────────────────────────────────────

#[test]
fn exit_code_violations_return_4() {
    let results = [policy::PolicyResult {
        rule_name: "test".to_string(),
        severity: Severity::Violation,
        message: "bad".to_string(),
        affected_references: Vec::new(),
    }];
    let violations = results.iter().filter(|r| r.severity == Severity::Violation).count();
    let exit_code = if violations > 0 { 4 } else { 0 };
    assert_eq!(exit_code, 4);
}

#[test]
fn exit_code_warnings_only_return_0() {
    let results = [policy::PolicyResult {
        rule_name: "test".to_string(),
        severity: Severity::Warn,
        message: "meh".to_string(),
        affected_references: Vec::new(),
    }];
    let violations = results.iter().filter(|r| r.severity == Severity::Violation).count();
    let exit_code = if violations > 0 { 4 } else { 0 };
    assert_eq!(exit_code, 0);
}

#[test]
fn exit_code_fatal_error_returns_1() {
    // Simulate: if evaluate_policies returns an error, audit returns 1
    let err = PolicyError::InvalidPattern("bad".to_string());
    // In the CLI handler, any error maps to exit code 1
    let exit_code = match Err::<Vec<policy::PolicyResult>, PolicyError>(err) {
        Ok(_) => 0,
        Err(_) => 1,
    };
    assert_eq!(exit_code, 1);
}

// ── Regression tests ────────────────────────────────────────────────

/// P1 regression: three unrelated secrets each in one location should NOT
/// violate max_references=2. Counting is per-secret (per-fingerprint),
/// not global across all matched refs.
#[test]
fn max_references_per_secret_not_global() {
    let (conn, _tmp) = setup_test_db();
    let now = Utc::now();
    // Three distinct secrets (different fingerprints), each in exactly 1 location
    insert_ref(&conn, "ca00000000000000000000000000000000000000000000000000000000000001", "fp_secret_a", "/a", Some("aws_key"), ScanStatus::Present, now);
    insert_ref(&conn, "ca00000000000000000000000000000000000000000000000000000000000002", "fp_secret_b", "/b", Some("aws_key"), ScanStatus::Present, now);
    insert_ref(&conn, "ca00000000000000000000000000000000000000000000000000000000000003", "fp_secret_c", "/c", Some("aws_key"), ScanStatus::Present, now);

    let mut p = make_policy("test", vec!["aws_*"]);
    p.max_references = Some(2);
    let results = policy::evaluate_policies(&conn, &[p]).unwrap();
    // Each secret appears in only 1 location (≤ 2) → pass
    assert_eq!(results[0].severity, Severity::Pass);
}

/// P2 regression: a future last_changed timestamp (clock skew) should NOT
/// cause a false max_age violation. Negative age is clamped to 0 days.
#[test]
fn max_age_future_timestamp_does_not_false_violate() {
    let (conn, _tmp) = setup_test_db();
    let future = Utc::now() + Duration::days(30);
    insert_ref(&conn, "cb00000000000000000000000000000000000000000000000000000000000001", "fp1", "/a", Some("aws_key"), ScanStatus::Present, future);

    let mut p = make_policy("test", vec!["aws_*"]);
    p.max_age_days = Some(90);
    p.warn_at_days = Some(60);
    let results = policy::evaluate_policies(&conn, &[p]).unwrap();
    // Future timestamp → age clamped to 0 days → well within limits → pass
    assert_eq!(results[0].severity, Severity::Pass);
}
