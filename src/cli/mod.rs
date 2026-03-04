pub mod drift;
pub mod export;
pub mod forget;
pub mod group;
pub mod init;
pub mod list;
pub mod scan;
pub mod show;
pub mod status;
pub mod suggest;
pub mod ungroup;

use crate::config;
use crate::index::{db, fingerprint};
use crate::keychain;

/// Open the database with derived keys. Returns (Connection, DerivedKeys).
pub fn open_db() -> Result<(rusqlite::Connection, fingerprint::DerivedKeys), String> {
    let db_path = config::db_path();
    if !db_path.exists() {
        return Err("database not found — run `hagrid init` first".to_string());
    }

    let master_secret =
        keychain::retrieve_master_secret().map_err(|e| e.to_string())?;

    let keys = fingerprint::derive_keys(&master_secret);
    let conn = db::open_db(&db_path, &keys.db_key).map_err(|e| e.to_string())?;

    Ok((conn, keys))
}

/// Resolve a target that could be a ref ID or full identity key.
pub fn resolve_ref_id(
    conn: &rusqlite::Connection,
    input: &str,
) -> Result<String, String> {
    // If it's a full-length hex key, use directly
    if input.len() == 64 && input.chars().all(|c| c.is_ascii_hexdigit()) {
        return Ok(input.to_string());
    }

    // Strip ref: prefix
    let hex_prefix = input.strip_prefix("ref:").unwrap_or(input);

    // Find all matching references
    let refs = db::list_references(conn).map_err(|e| e.to_string())?;
    let matches: Vec<&str> = refs
        .iter()
        .map(|r| r.identity_key.as_str())
        .filter(|k| k.starts_with(hex_prefix))
        .collect();

    match matches.len() {
        0 => Err(format!("no reference found matching '{}'", input)),
        1 => Ok(matches[0].to_string()),
        _ => {
            let display: Vec<String> = matches.iter().map(|k| format!("ref:{}", &k[..6.min(k.len())])).collect();
            Err(format!(
                "ambiguous id {} — matches {}. Use a longer prefix or full identity key.",
                input,
                display.join(", ")
            ))
        }
    }
}
