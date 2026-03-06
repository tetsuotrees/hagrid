use colored::Colorize;

use crate::index::fingerprint;
use crate::index::models::ScanStatus;
use crate::rotate;

pub fn run(group_label: &str, json: bool) -> i32 {
    let (conn, _keys) = match super::open_db() {
        Ok(v) => v,
        Err(e) => {
            eprintln!("{} {}", "error:".red().bold(), e);
            return 1;
        }
    };

    let (group, members) = match rotate::gather_rotate_info(&conn, group_label) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("{} {}", "error:".red().bold(), e);
            return 1;
        }
    };

    let report = rotate::build_info_report(&group, &members);

    if json {
        println!("{}", serde_json::to_string_pretty(&report).unwrap());
    } else {
        println!("Group: {}", report.group_label);
        println!("Status: {}", report.group_status);
        println!(
            "Members: {} ({} unique fingerprints{})",
            report.member_count,
            report.unique_fingerprints,
            if report.drifted { ", DRIFTED" } else { "" }
        );
        println!();

        let all_keys: Vec<&str> = members.iter().map(|m| m.identity_key.as_str()).collect();

        for m in &members {
            let status_indicator = match m.scan_status {
                ScanStatus::Present => "+".green(),
                ScanStatus::Removed => "-".red(),
                ScanStatus::Error => "!".yellow(),
            };
            let ref_id = fingerprint::display_id(&m.identity_key, &all_keys);
            println!(
                "  {} {} {} [{}] {}",
                status_indicator, ref_id, m.display_label, m.location.discriminator, m.file_path
            );
            println!(
                "    fingerprint: {}...",
                &m.fingerprint[..m.fingerprint.len().min(16)]
            );
        }
    }

    0
}
