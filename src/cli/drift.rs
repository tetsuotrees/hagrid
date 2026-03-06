use colored::Colorize;

use crate::config;
use crate::drift;
use crate::index::db;
use crate::index::fingerprint;
use crate::index::models::GroupStatus;

pub fn run(json: bool) -> i32 {
    let (conn, _keys) = match super::open_db() {
        Ok(v) => v,
        Err(e) => {
            eprintln!("{} {}", "error:".red().bold(), e);
            return 1;
        }
    };

    let cfg = config::load_config().unwrap_or_default();

    let results = match drift::check_all_drift(&conn, &cfg) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("{} {}", "error:".red().bold(), e);
            return 1;
        }
    };

    let any_drifted = results.iter().any(|r| r.drifted);

    if json {
        let output = serde_json::json!({
            "drift_detected": any_drifted,
            "groups": results.iter().map(|r| {
                serde_json::json!({
                    "label": r.group_label,
                    "group_id": r.group_id.to_string(),
                    "status": r.status.to_string(),
                    "drifted": r.drifted,
                    "member_fingerprints": r.member_fingerprints,
                    "removed_members": r.removed_members,
                    "pruned_members": r.pruned_members,
                })
            }).collect::<Vec<_>>(),
        });
        println!("{}", serde_json::to_string_pretty(&output).unwrap());
    } else {
        if results.is_empty() {
            println!("No groups to check for drift.");
            return 0;
        }

        let refs = db::list_references(&conn).unwrap_or_default();
        let all_keys: Vec<&str> = refs.iter().map(|r| r.identity_key.as_str()).collect();

        for result in &results {
            let status_display = match result.status {
                GroupStatus::Synced => "synced".green().to_string(),
                GroupStatus::Drifted => "DRIFTED".red().bold().to_string(),
                GroupStatus::Degraded => "degraded".yellow().to_string(),
                GroupStatus::Empty => "empty".dimmed().to_string(),
                _ => result.status.to_string(),
            };

            println!("{} [{}]", result.group_label.bold(), status_display);

            if result.drifted {
                println!("  Members have different fingerprints:");
                for (member_id, fp) in &result.member_fingerprints {
                    let display_id = fingerprint::display_id(member_id, &all_keys);
                    if let Some(r) = refs.iter().find(|r| r.identity_key == *member_id) {
                        println!(
                            "    {} {} fp:{}",
                            display_id.dimmed(),
                            r.file_path,
                            &fp[..16]
                        );
                    }
                }
            }

            if !result.removed_members.is_empty() {
                println!("  Removed members:");
                for member_id in &result.removed_members {
                    let display_id = fingerprint::display_id(member_id, &all_keys);
                    println!("    {} {}", display_id.dimmed(), "[REMOVED]".red());
                }
            }

            if !result.pruned_members.is_empty() {
                println!("  Auto-pruned members (exceeded removal threshold):");
                for member_id in &result.pruned_members {
                    let display_id = fingerprint::display_id(member_id, &all_keys);
                    println!("    {} {}", display_id.dimmed(), "[PRUNED]".yellow());
                }
            }
        }
    }

    let exit_code = if any_drifted { 3 } else { 0 };

    if any_drifted {
        let event = crate::notify::build_drift_event(exit_code, &results);
        crate::notify::dispatch(&event);
    }

    exit_code
}
