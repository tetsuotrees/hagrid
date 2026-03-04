use security_framework::passwords::{delete_generic_password, get_generic_password, set_generic_password};
use thiserror::Error;

const SERVICE_NAME: &str = "hagrid";
const ACCOUNT_NAME: &str = "master-secret";

#[derive(Error, Debug)]
pub enum KeychainError {
    #[error("failed to store master secret in Keychain: {0}")]
    Store(String),
    #[error("failed to retrieve master secret from Keychain: {0}")]
    Retrieve(String),
    #[error("failed to delete master secret from Keychain: {0}")]
    Delete(String),
    #[error("master secret not found in Keychain — run `hagrid init` first")]
    NotFound,
}

/// Store the master secret in macOS Keychain.
pub fn store_master_secret(secret: &[u8]) -> Result<(), KeychainError> {
    // Try deleting first to handle update case
    let _ = delete_generic_password(SERVICE_NAME, ACCOUNT_NAME);
    set_generic_password(SERVICE_NAME, ACCOUNT_NAME, secret)
        .map_err(|e| KeychainError::Store(e.to_string()))
}

/// Retrieve the master secret from macOS Keychain.
pub fn retrieve_master_secret() -> Result<Vec<u8>, KeychainError> {
    match get_generic_password(SERVICE_NAME, ACCOUNT_NAME) {
        Ok(data) => Ok(data.to_vec()),
        Err(e) => {
            let msg = e.to_string();
            if msg.contains("item not found") || msg.contains("-25300") {
                Err(KeychainError::NotFound)
            } else {
                Err(KeychainError::Retrieve(msg))
            }
        }
    }
}

/// Delete the master secret from macOS Keychain.
pub fn delete_master_secret() -> Result<(), KeychainError> {
    delete_generic_password(SERVICE_NAME, ACCOUNT_NAME)
        .map_err(|e| KeychainError::Delete(e.to_string()))
}

/// Check if a master secret exists in Keychain.
pub fn master_secret_exists() -> bool {
    get_generic_password(SERVICE_NAME, ACCOUNT_NAME).is_ok()
}
