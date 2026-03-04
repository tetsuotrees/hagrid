use hagrid::index::fingerprint;

#[test]
fn test_fingerprint_keyed_and_installation_specific() {
    let key1 = b"installation-one-key-is-32-bytes!";
    let key2 = b"installation-two-key-is-32-bytes!";

    let fp1 = fingerprint::compute_fingerprint(key1, "sk-proj-abc123");
    let fp2 = fingerprint::compute_fingerprint(key2, "sk-proj-abc123");

    // Same value, different keys → different fingerprints
    assert_ne!(fp1, fp2, "different installation keys should produce different fingerprints");
}

#[test]
fn test_fingerprint_full_digest_stored() {
    let key = b"test-fingerprint-key-here-32byte!";
    let fp = fingerprint::compute_fingerprint(key, "some-secret-value");

    assert_eq!(fp.len(), 64, "fingerprint should be full 64-char hex digest");
    assert!(fp.chars().all(|c| c.is_ascii_hexdigit()), "should be valid hex");
}

#[test]
fn test_fingerprint_truncated_for_display() {
    let key = b"test-fingerprint-key-here-32byte!";
    let fp = fingerprint::compute_fingerprint(key, "some-secret-value");

    let display = &fp[..16];
    assert_eq!(display.len(), 16, "display truncation should be 16 chars");
}

#[test]
fn test_hkdf_derivation_deterministic() {
    let master = b"deterministic-master-secret-key!!";
    let keys1 = fingerprint::derive_keys(master);
    let keys2 = fingerprint::derive_keys(master);

    assert_eq!(keys1.identity_key, keys2.identity_key);
    assert_eq!(keys1.fingerprint_key, keys2.fingerprint_key);
    assert_eq!(keys1.db_key, keys2.db_key);
}

#[test]
fn test_hkdf_derivation_unique_per_purpose() {
    let master = b"deterministic-master-secret-key!!";
    let keys = fingerprint::derive_keys(master);

    assert_ne!(keys.identity_key, keys.fingerprint_key);
    assert_ne!(keys.fingerprint_key, keys.db_key);
    assert_ne!(keys.identity_key, keys.db_key);
}
