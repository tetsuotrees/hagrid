use colored::Colorize;

use crate::index::db;
use crate::index::fingerprint;
use crate::index::models::ScanStatus;

pub fn run(ungrouped: bool, json: bool) -> i32 {
    let (conn, _keys) = match super::open_db() {
        Ok(v) => v,
        Err(e) => {
            eprintln!("{} {}", "error:".red().bold(), e);
            return 1;
        }
    };

    let refs = match db::list_references(&conn) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("{} {}", "error:".red().bold(), e);
            return 1;
        }
    };

    let groups = match db::list_groups(&conn) {
        Ok(g) => g,
        Err(e) => {
            eprintln!("{} {}", "error:".red().bold(), e);
            return 1;
        }
    };

    // Collect all identity keys for display ID generation
    let all_keys: Vec<&str> = refs.iter().map(|r| r.identity_key.as_str()).collect();

    if json {
        if ungrouped {
            let grouped_ids: std::collections::HashSet<&str> = groups
                .iter()
                .flat_map(|g| g.members.iter().map(|m| m.as_str()))
                .collect();

            let ungrouped_refs: Vec<_> = refs
                .iter()
                .filter(|r| r.scan_status == ScanStatus::Present && !grouped_ids.contains(r.identity_key.as_str()))
                .collect();

            let output = serde_json::json!({
                "ungrouped_references": ungrouped_refs.iter().map(|r| {
                    serde_json::json!({
                        "identity_key": r.identity_key,
                        "file_path": r.file_path,
                        "location": {
                            "kind": r.location.kind.to_string(),
                            "discriminator": r.location.discriminator,
                            "line_number": r.location.line_number,
                        },
                        "provider_pattern": r.provider_pattern,
                        "display_label": r.display_label,
                        "fingerprint": &r.fingerprint[..16],
                        "first_seen": r.first_seen.to_rfc3339(),
                        "last_seen": r.last_seen.to_rfc3339(),
                    })
                }).collect::<Vec<_>>(),
            });
            println!("{}", serde_json::to_string_pretty(&output).unwrap());
        } else {
            let output = serde_json::json!({
                "groups": groups.iter().map(|g| {
                    serde_json::json!({
                        "group_id": g.group_id.to_string(),
                        "label": g.label,
                        "status": g.status.to_string(),
                        "member_count": g.members.len(),
                        "members": g.members,
                    })
                }).collect::<Vec<_>>(),
                "references": refs.iter().filter(|r| r.scan_status == ScanStatus::Present).map(|r| {
                    serde_json::json!({
                        "identity_key": r.identity_key,
                        "file_path": r.file_path,
                        "display_label": r.display_label,
                        "fingerprint": &r.fingerprint[..16],
                    })
                }).collect::<Vec<_>>(),
            });
            println!("{}", serde_json::to_string_pretty(&output).unwrap());
        }
    } else {
        let grouped_ids: std::collections::HashSet<&str> = groups
            .iter()
            .flat_map(|g| g.members.iter().map(|m| m.as_str()))
            .collect();

        if !ungrouped && !groups.is_empty() {
            println!("{}", "Groups:".bold());
            for group in &groups {
                let status_display = match group.status {
                    crate::index::models::GroupStatus::Synced => "synced".green().to_string(),
                    crate::index::models::GroupStatus::Drifted => "DRIFTED".red().to_string(),
                    crate::index::models::GroupStatus::Degraded => "degraded".yellow().to_string(),
                    crate::index::models::GroupStatus::Empty => "empty".dimmed().to_string(),
                    _ => group.status.to_string(),
                };
                println!(
                    "  {} [{}] ({} members)",
                    group.label.bold(),
                    status_display,
                    group.members.len()
                );
            }
            println!();
        }

        let ungrouped_refs: Vec<_> = refs
            .iter()
            .filter(|r| r.scan_status == ScanStatus::Present && !grouped_ids.contains(r.identity_key.as_str()))
            .collect();

        if !ungrouped_refs.is_empty() {
            if ungrouped {
                println!("{}", "Ungrouped references:".bold());
            } else {
                println!("{}", "Ungrouped:".bold());
            }
            for r in &ungrouped_refs {
                let display_id = fingerprint::display_id(&r.identity_key, &all_keys);
                println!(
                    "  {} {} at {}:{}",
                    display_id.dimmed(),
                    r.display_label,
                    r.file_path,
                    r.location
                        .line_number
                        .map(|n| n.to_string())
                        .unwrap_or_else(|| r.location.discriminator.clone()),
                );
            }
        } else if ungrouped {
            println!("No ungrouped references.");
        }
    }

    0
}
