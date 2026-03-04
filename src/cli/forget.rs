use colored::Colorize;

use crate::index::db;

pub fn run(target: &str) -> i32 {
    let (conn, _keys) = match super::open_db() {
        Ok(v) => v,
        Err(e) => {
            eprintln!("{} {}", "error:".red().bold(), e);
            return 1;
        }
    };

    // Spec: if starts with "ref:", treat as reference; otherwise group label first.
    if target.starts_with("ref:") {
        return forget_reference(&conn, target);
    }

    // Try as group label first
    if try_forget_group(&conn, target) {
        return 0;
    }

    // Fall back to reference ID if it looks like hex
    if target.chars().all(|c| c.is_ascii_hexdigit()) && target.len() >= 6 {
        return forget_reference(&conn, target);
    }

    eprintln!("{} '{}' not found as reference or group", "error:".red().bold(), target);
    1
}

fn forget_reference(conn: &rusqlite::Connection, target: &str) -> i32 {
    match super::resolve_ref_id(conn, target) {
        Ok(identity_key) => match db::delete_reference(conn, &identity_key) {
            Ok(true) => {
                println!("{} Reference forgotten", "ok:".green().bold());
                0
            }
            Ok(false) => {
                eprintln!("{} reference not found", "error:".red().bold());
                1
            }
            Err(e) => {
                eprintln!("{} {}", "error:".red().bold(), e);
                1
            }
        },
        Err(e) => {
            eprintln!("{} {}", "error:".red().bold(), e);
            1
        }
    }
}

fn try_forget_group(conn: &rusqlite::Connection, label: &str) -> bool {
    match db::delete_group(conn, label) {
        Ok(true) => {
            println!("{} Group '{}' forgotten", "ok:".green().bold(), label);
            true
        }
        Ok(false) => false,
        Err(e) => {
            eprintln!("{} {}", "error:".red().bold(), e);
            false
        }
    }
}
