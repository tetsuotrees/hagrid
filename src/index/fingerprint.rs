use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::Zeroize;

use crate::index::models::LocationKind;

type HmacSha256 = Hmac<Sha256>;

const IDENTITY_INFO: &[u8] = b"hagrid-identity-v1";
const FINGERPRINT_INFO: &[u8] = b"hagrid-fingerprint-v1";
const DB_INFO: &[u8] = b"hagrid-db-v1";

/// Derived keys from the master secret.
pub struct DerivedKeys {
    pub identity_key: Vec<u8>,
    pub fingerprint_key: Vec<u8>,
    pub db_key: Vec<u8>,
}

impl Drop for DerivedKeys {
    fn drop(&mut self) {
        self.identity_key.zeroize();
        self.fingerprint_key.zeroize();
        self.db_key.zeroize();
    }
}

/// Derive all keys from the master secret using HKDF-SHA256.
pub fn derive_keys(master_secret: &[u8]) -> DerivedKeys {
    let hk = Hkdf::<Sha256>::new(None, master_secret);

    let mut identity_key = vec![0u8; 32];
    hk.expand(IDENTITY_INFO, &mut identity_key)
        .expect("HKDF expand should not fail with 32-byte output");

    let mut fingerprint_key = vec![0u8; 32];
    hk.expand(FINGERPRINT_INFO, &mut fingerprint_key)
        .expect("HKDF expand should not fail with 32-byte output");

    let mut db_key = vec![0u8; 32];
    hk.expand(DB_INFO, &mut db_key)
        .expect("HKDF expand should not fail with 32-byte output");

    DerivedKeys {
        identity_key,
        fingerprint_key,
        db_key,
    }
}

/// Compute the HMAC-SHA256 fingerprint of a secret value.
/// Returns the full 64-char hex digest.
pub fn compute_fingerprint(fingerprint_key: &[u8], secret_value: &str) -> String {
    let mut mac =
        HmacSha256::new_from_slice(fingerprint_key).expect("HMAC can take key of any size");
    mac.update(secret_value.as_bytes());
    let result = mac.finalize();
    hex::encode(result.into_bytes())
}

/// Compute the deterministic identity key for a reference.
/// identity = HMAC-SHA256(identity_key, normalized_path | location_kind | discriminator | source_kind)
pub fn compute_identity(
    identity_key: &[u8],
    normalized_path: &str,
    location_kind: &LocationKind,
    discriminator: &str,
    source_kind: &str,
) -> String {
    let message = format!(
        "{}|{}|{}|{}",
        normalized_path, location_kind, discriminator, source_kind
    );
    let mut mac =
        HmacSha256::new_from_slice(identity_key).expect("HMAC can take key of any size");
    mac.update(message.as_bytes());
    let result = mac.finalize();
    hex::encode(result.into_bytes())
}

/// Compute a display ID from a full identity key hex string.
/// Starts with 6 chars, extends by 2 on collision.
pub fn display_id(identity_key: &str, all_keys: &[&str]) -> String {
    let mut len = 6;
    loop {
        let prefix = &identity_key[..len.min(identity_key.len())];

        // Check if any other key shares this prefix
        let collisions = all_keys
            .iter()
            .any(|k| {
                *k != identity_key
                    && k.len() >= len.min(k.len())
                    && identity_key.len() >= len
                    && k[..len.min(k.len())] == identity_key[..len.min(identity_key.len())]
            });

        if !collisions || len >= identity_key.len() {
            return format!("ref:{}", prefix);
        }
        len += 2;
    }
}

/// Resolve a display ID prefix to a full identity key.
/// Returns Ok(key) if exactly one match, Err with candidates if ambiguous.
pub fn resolve_display_id<'a>(
    prefix: &str,
    all_keys: &[&'a str],
) -> Result<&'a str, Vec<&'a str>> {
    // Strip "ref:" prefix if present
    let hex_prefix = prefix.strip_prefix("ref:").unwrap_or(prefix);

    let matches: Vec<&str> = all_keys
        .iter()
        .filter(|k| k.starts_with(hex_prefix))
        .copied()
        .collect();

    match matches.len() {
        1 => Ok(matches[0]),
        0 => Err(vec![]),
        _ => Err(matches),
    }
}

/// Hex encoding helper (we use this instead of pulling in the hex crate).
mod hex {
    pub fn encode(bytes: impl AsRef<[u8]>) -> String {
        bytes
            .as_ref()
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_keys_deterministic() {
        let master = b"test-master-secret-32-bytes-long!";
        let keys1 = derive_keys(master);
        let keys2 = derive_keys(master);
        assert_eq!(keys1.identity_key, keys2.identity_key);
        assert_eq!(keys1.fingerprint_key, keys2.fingerprint_key);
        assert_eq!(keys1.db_key, keys2.db_key);
    }

    #[test]
    fn test_derive_keys_different() {
        let master = b"test-master-secret-32-bytes-long!";
        let keys = derive_keys(master);
        assert_ne!(keys.identity_key, keys.fingerprint_key);
        assert_ne!(keys.fingerprint_key, keys.db_key);
        assert_ne!(keys.identity_key, keys.db_key);
    }

    #[test]
    fn test_fingerprint_deterministic() {
        let key = b"test-fingerprint-key-here-32byte!";
        let fp1 = compute_fingerprint(key, "sk-proj-abc123");
        let fp2 = compute_fingerprint(key, "sk-proj-abc123");
        assert_eq!(fp1, fp2);
        assert_eq!(fp1.len(), 64); // full hex digest
    }

    #[test]
    fn test_fingerprint_different_values() {
        let key = b"test-fingerprint-key-here-32byte!";
        let fp1 = compute_fingerprint(key, "sk-proj-abc123");
        let fp2 = compute_fingerprint(key, "sk-proj-xyz789");
        assert_ne!(fp1, fp2);
    }

    #[test]
    fn test_identity_deterministic() {
        let key = b"test-identity-key-here-32-bytes!";
        let id1 = compute_identity(key, "/home/user/.env", &LocationKind::EnvVar, "OPENAI_API_KEY", "file");
        let id2 = compute_identity(key, "/home/user/.env", &LocationKind::EnvVar, "OPENAI_API_KEY", "file");
        assert_eq!(id1, id2);
    }

    #[test]
    fn test_identity_different_discriminator() {
        let key = b"test-identity-key-here-32-bytes!";
        let id1 = compute_identity(key, "/config.json", &LocationKind::JsonPath, "/api/key", "file");
        let id2 = compute_identity(key, "/config.json", &LocationKind::JsonPath, "/db/key", "file");
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_display_id_no_collision() {
        let key = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";
        let all = vec![key, "ffffff1234567890abcdef1234567890abcdef1234567890abcdef1234567890"];
        assert_eq!(display_id(key, &all), "ref:abcdef");
    }

    #[test]
    fn test_resolve_display_id() {
        let keys = vec![
            "abcdef1234567890",
            "abcdef5678901234",
            "ffffff1234567890",
        ];
        // Ambiguous
        assert!(resolve_display_id("ref:abcdef", &keys).is_err());
        // Unique
        assert_eq!(resolve_display_id("ref:ffffff", &keys).unwrap(), "ffffff1234567890");
        // No match
        assert!(resolve_display_id("ref:000000", &keys).is_err());
    }
}
