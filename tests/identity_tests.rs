use hagrid::index::fingerprint;
use hagrid::index::models::LocationKind;

#[test]
fn test_identity_deterministic_across_calls() {
    let key = b"test-identity-key-here-32-bytes!";

    let id1 = fingerprint::compute_identity(
        key,
        "/Users/test/.env",
        &LocationKind::EnvVar,
        "OPENAI_API_KEY",
        "file",
    );
    let id2 = fingerprint::compute_identity(
        key,
        "/Users/test/.env",
        &LocationKind::EnvVar,
        "OPENAI_API_KEY",
        "file",
    );

    assert_eq!(id1, id2, "identity should be deterministic");
}

#[test]
fn test_identity_different_for_different_paths() {
    let key = b"test-identity-key-here-32-bytes!";

    let id1 = fingerprint::compute_identity(
        key,
        "/Users/test/.env",
        &LocationKind::EnvVar,
        "OPENAI_API_KEY",
        "file",
    );
    let id2 = fingerprint::compute_identity(
        key,
        "/Users/test/other/.env",
        &LocationKind::EnvVar,
        "OPENAI_API_KEY",
        "file",
    );

    assert_ne!(id1, id2, "different paths should produce different identities");
}

#[test]
fn test_identity_different_for_same_file_different_discriminator() {
    let key = b"test-identity-key-here-32-bytes!";

    let id1 = fingerprint::compute_identity(
        key,
        "/config.json",
        &LocationKind::JsonPath,
        "/production/api_key",
        "file",
    );
    let id2 = fingerprint::compute_identity(
        key,
        "/config.json",
        &LocationKind::JsonPath,
        "/staging/api_key",
        "file",
    );

    assert_ne!(id1, id2, "different discriminators should produce different identities");
}

#[test]
fn test_duplicate_keys_fixture_produces_distinct_references() {
    // Simulates the duplicate_keys.json case: same key name at different JSON pointers
    let key = b"test-identity-key-here-32-bytes!";

    let id_prod = fingerprint::compute_identity(
        key,
        "/tests/fixtures/duplicate_keys.json",
        &LocationKind::JsonPath,
        "/production/api_key",
        "file",
    );
    let id_staging = fingerprint::compute_identity(
        key,
        "/tests/fixtures/duplicate_keys.json",
        &LocationKind::JsonPath,
        "/staging/api_key",
        "file",
    );

    assert_ne!(id_prod, id_staging, "same key name at different JSON pointers should be distinct");
}

#[test]
fn test_display_id_collision_handling() {
    // Create two keys that share a prefix
    let key = b"test-identity-key-here-32-bytes!";

    // These will have different identity keys
    let id1 = fingerprint::compute_identity(
        key,
        "/file1.json",
        &LocationKind::JsonPath,
        "/key",
        "file",
    );
    let id2 = fingerprint::compute_identity(
        key,
        "/file2.json",
        &LocationKind::JsonPath,
        "/key",
        "file",
    );

    let all_keys = vec![id1.as_str(), id2.as_str()];

    let display1 = fingerprint::display_id(&id1, &all_keys);
    let display2 = fingerprint::display_id(&id2, &all_keys);

    // Display IDs should start with "ref:"
    assert!(display1.starts_with("ref:"));
    assert!(display2.starts_with("ref:"));

    // Display IDs should be different
    assert_ne!(display1, display2, "display IDs should be unique");
}
