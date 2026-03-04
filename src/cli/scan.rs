use colored::Colorize;
use std::path::Path;

use crate::config;
use crate::index::db;
use crate::scan::engine::{self, ScanDepth};
use crate::suggest;

pub fn run(depth: &str, path: Option<&str>, json: bool) -> i32 {
    let scan_depth = match depth {
        "lite" => ScanDepth::Lite,
        "standard" => ScanDepth::Standard,
        _ => {
            eprintln!("{} invalid depth '{}' — use 'lite' or 'standard'", "error:".red().bold(), depth);
            return 2;
        }
    };

    let (conn, keys) = match super::open_db() {
        Ok(v) => v,
        Err(e) => {
            eprintln!("{} {}", "error:".red().bold(), e);
            return 1;
        }
    };

    let cfg = match config::load_config() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{} {}", "error:".red().bold(), e);
            return 1;
        }
    };

    let path_override = path.map(Path::new);

    // Run scan
    let result = engine::scan(
        &cfg,
        scan_depth,
        path_override,
    );

    // Convert findings to references
    let references = engine::findings_to_references(
        &result.findings,
        &keys.identity_key,
        &keys.fingerprint_key,
    );

    // Track which identity keys we saw
    let seen_keys: Vec<String> = references.iter().map(|r| r.identity_key.clone()).collect();

    // Track fatal DB errors — exit 1 if any occur
    let mut db_errors = false;

    // Upsert references into DB
    let mut new_count = 0;
    let mut updated_count = 0;
    for reference in &references {
        let existing = db::get_reference(&conn, &reference.identity_key);
        match existing {
            Ok(Some(_)) => updated_count += 1,
            Ok(None) => new_count += 1,
            Err(e) => {
                eprintln!("{} failed to check reference: {}", "error:".red().bold(), e);
                db_errors = true;
            }
        }
        if let Err(e) = db::upsert_reference(&conn, reference) {
            eprintln!("{} failed to store reference: {}", "error:".red().bold(), e);
            db_errors = true;
        }
    }

    // Mark references not seen in this scan as Removed
    let removed = match db::mark_unseen_as_removed(&conn, &seen_keys) {
        Ok(n) => n,
        Err(e) => {
            eprintln!("{} failed to mark removed references: {}", "error:".red().bold(), e);
            db_errors = true;
            0
        }
    };

    // Generate suggestions
    let suggestions = match suggest::generate_suggestions(&conn, scan_depth) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("{} failed to generate suggestions: {}", "error:".red().bold(), e);
            db_errors = true;
            Vec::new()
        }
    };

    if json {
        let output = serde_json::json!({
            "files_scanned": result.files_scanned,
            "files_skipped": result.files_skipped,
            "findings": references.len(),
            "new": new_count,
            "updated": updated_count,
            "removed": removed,
            "suggestions_generated": suggestions.len(),
            "errors": result.errors,
            "db_errors": db_errors,
        });
        println!("{}", serde_json::to_string_pretty(&output).unwrap());
    } else {
        println!("{} Scan complete", "ok:".green().bold());
        println!("  Files scanned: {}", result.files_scanned);
        if result.files_skipped > 0 {
            println!("  Files skipped: {} (see warnings above)", result.files_skipped);
        }
        println!("  Secrets found: {} ({} new, {} updated)", references.len(), new_count, updated_count);
        if removed > 0 {
            println!("  Removed: {}", removed);
        }
        if !suggestions.is_empty() {
            println!("  New suggestions: {} — run `hagrid suggest` to review", suggestions.len());
        }
    }

    // Print file-level errors to stderr
    for err in &result.errors {
        eprintln!("{} {}", "warning:".yellow().bold(), err);
    }

    // Fatal errors (exit 1) take priority per spec
    if db_errors { 1 } else { 0 }
}
