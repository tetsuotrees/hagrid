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

    run_with_conn(&conn, target)
}

pub fn run_with_conn(conn: &rusqlite::Connection, target: &str) -> i32 {
    match super::resolve_target(conn, target) {
        Ok(super::TargetResolution::Group(label)) => forget_group(conn, &label),
        Ok(super::TargetResolution::Reference(identity_key)) => {
            forget_reference_by_key(conn, &identity_key)
        }
        Err(e) => {
            eprintln!("{} {}", "error:".red().bold(), e);
            1
        }
    }
}

fn forget_reference_by_key(conn: &rusqlite::Connection, identity_key: &str) -> i32 {
    match db::delete_reference(conn, identity_key) {
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
    }
}

fn forget_group(conn: &rusqlite::Connection, label: &str) -> i32 {
    match db::delete_group(conn, label) {
        Ok(true) => {
            println!("{} Group '{}' forgotten", "ok:".green().bold(), label);
            0
        }
        Ok(false) => {
            eprintln!("{} group '{}' not found", "error:".red().bold(), label);
            1
        }
        Err(e) => {
            eprintln!("{} {}", "error:".red().bold(), e);
            1
        }
    }
}
