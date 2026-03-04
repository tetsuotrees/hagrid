use colored::Colorize;
use rand::RngCore;

use crate::config;
use crate::index::{db, fingerprint};
use crate::keychain;

pub fn run() -> i32 {
    let hagrid_dir = config::hagrid_dir();

    // Create ~/.hagrid/ directory
    if let Err(e) = std::fs::create_dir_all(&hagrid_dir) {
        eprintln!("{} failed to create {}: {}", "error:".red().bold(), hagrid_dir.display(), e);
        return 1;
    }

    // Check if already initialized
    if keychain::master_secret_exists() && config::db_path().exists() {
        println!("{} Hagrid is already initialized at {}", "note:".yellow().bold(), hagrid_dir.display());
        println!("  To reinitialize, delete {} and remove the Keychain entry first.", hagrid_dir.display());
        return 0;
    }

    // Generate master secret (32 random bytes)
    let mut master_secret = vec![0u8; 32];
    rand::thread_rng().fill_bytes(&mut master_secret);

    // Store in Keychain
    if let Err(e) = keychain::store_master_secret(&master_secret) {
        eprintln!("{} {}", "error:".red().bold(), e);
        return 1;
    }

    // Derive keys
    let keys = fingerprint::derive_keys(&master_secret);

    // Create encrypted database
    let db_path = config::db_path();
    match db::open_db(&db_path, &keys.db_key) {
        Ok(conn) => {
            if let Err(e) = db::migrate(&conn) {
                eprintln!("{} failed to initialize database: {}", "error:".red().bold(), e);
                return 1;
            }
        }
        Err(e) => {
            eprintln!("{} failed to create database: {}", "error:".red().bold(), e);
            return 1;
        }
    }

    // Write default config
    if !config::config_path().exists() {
        if let Err(e) = config::write_default_config() {
            eprintln!("{} failed to write default config: {}", "warning:".yellow().bold(), e);
        }
    }

    // Zero out master secret from stack
    use zeroize::Zeroize;
    master_secret.zeroize();

    println!("{} Hagrid initialized successfully", "ok:".green().bold());
    println!("  Data directory: {}", hagrid_dir.display());
    println!("  Master secret stored in macOS Keychain (service: hagrid)");
    println!("  Config: {}", config::config_path().display());
    println!();
    println!("Next steps:");
    println!("  hagrid scan          # Scan for secrets");
    println!("  hagrid suggest       # Review grouping suggestions");

    0
}
