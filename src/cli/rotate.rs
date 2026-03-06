use colored::Colorize;
use std::io::{self, Write};
use zeroize::Zeroizing;

use crate::index::models::ScanStatus;
use crate::rotate;
use crate::scan::patterns;

pub fn run(group_label: &str, backup: bool) -> i32 {
    let (conn, keys) = match super::open_db() {
        Ok(v) => v,
        Err(e) => {
            eprintln!("{} {}", "error:".red().bold(), e);
            return 1;
        }
    };

    // Gather group info
    let (_group, members) = match rotate::gather_rotate_info(&conn, group_label) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("{} {}", "error:".red().bold(), e);
            return 1;
        }
    };

    let report = rotate::build_info_report(&_group, &members);
    println!("Group: {}", report.group_label.bold());
    println!(
        "Status: {} ({} members, {} unique fingerprints{})",
        report.group_status,
        report.member_count,
        report.unique_fingerprints,
        if report.drifted { ", DRIFTED" } else { "" }
    );

    // Filter to present members
    let present: Vec<&rotate::MemberInfo> = members
        .iter()
        .filter(|m| m.scan_status == ScanStatus::Present)
        .collect();

    if present.is_empty() {
        eprintln!("{} no present members to rotate", "error:".red().bold());
        return 1;
    }

    println!();
    println!("Files to modify ({}):", present.len());
    for m in &present {
        println!(
            "  {} [{}] {}",
            m.display_label, m.location.discriminator, m.file_path
        );
    }
    println!();

    // Prompt for new secret value
    let new_value = match read_new_value() {
        Some(v) => v,
        None => {
            eprintln!("{} cancelled", "error:".red().bold());
            return 1;
        }
    };

    // Confirm
    println!();
    print!(
        "Proceed with rotation of {} references? [y/N] ",
        present.len()
    );
    io::stdout().flush().unwrap();

    let mut confirm = String::new();
    io::stdin().read_line(&mut confirm).unwrap();
    if !confirm.trim().eq_ignore_ascii_case("y") {
        println!("Cancelled.");
        return 0;
    }

    // Load patterns and execute
    let compiled = match patterns::load_default_patterns() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("{} failed to load patterns: {}", "error:".red().bold(), e);
            return 1;
        }
    };

    println!();
    println!("Rotating...");
    let result = rotate::execute_rotation(&conn, &members, &new_value, &keys, &compiled, backup);

    // Display results
    println!();
    for fr in &result.file_results {
        if fr.success {
            let backup_note = if fr.backed_up { " (backed up)" } else { "" };
            println!(
                "  {} {}{} {}",
                "+".green(),
                fr.file_path,
                backup_note,
                if fr.verified { "verified" } else { "" }
            );
        } else {
            println!(
                "  {} {} — {}",
                "x".red(),
                fr.file_path,
                fr.error.as_deref().unwrap_or("unknown error")
            );
        }
    }

    println!();
    println!(
        "Result: {} succeeded, {} failed, {} skipped (of {} total)",
        result.succeeded, result.failed, result.skipped, result.total_members
    );

    // Exit code precedence: 1 (all fail/fatal) > 5 (partial) > 0 (all ok)
    let exit_code = if result.succeeded == 0 && result.failed > 0 {
        1
    } else if result.failed > 0 {
        5
    } else {
        0
    };

    if result.failed > 0 {
        let event = crate::notify::build_rotate_event(exit_code, group_label, &result);
        crate::notify::dispatch(&event);
    }

    exit_code
}

/// Read a new secret value with confirmation. Returns None if cancelled or mismatched.
fn read_new_value() -> Option<Zeroizing<String>> {
    let value1 = Zeroizing::new(
        rpassword::prompt_password_stderr("Enter new secret value: ")
            .map_err(|e| eprintln!("{} {}", "error:".red().bold(), e))
            .ok()?,
    );

    if value1.is_empty() {
        eprintln!("{} value cannot be empty", "error:".red().bold());
        return None;
    }

    let value2 = Zeroizing::new(
        rpassword::prompt_password_stderr("Confirm new secret value: ")
            .map_err(|e| eprintln!("{} {}", "error:".red().bold(), e))
            .ok()?,
    );

    if *value1 != *value2 {
        eprintln!("{} values do not match", "error:".red().bold());
        return None;
    }

    Some(value1)
}
