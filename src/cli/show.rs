use colored::Colorize;

use crate::index::db;
use crate::index::fingerprint;

pub fn run(target: &str, json: bool) -> i32 {
    let (conn, _keys) = match super::open_db() {
        Ok(v) => v,
        Err(e) => {
            eprintln!("{} {}", "error:".red().bold(), e);
            return 1;
        }
    };

    // Spec disambiguation: if input starts with "ref:", treat as reference ID;
    // otherwise treat as group label. If group not found and input looks like
    // a hex prefix, fall back to reference lookup.
    if target.starts_with("ref:") {
        show_reference(&conn, target, json)
    } else {
        match db::get_group_by_label(&conn, target) {
            Ok(Some(_)) => show_group(&conn, target, json),
            Ok(None) => {
                // Not a group — try as reference ID if it looks like hex
                if target.chars().all(|c| c.is_ascii_hexdigit()) && target.len() >= 6 {
                    show_reference(&conn, target, json)
                } else {
                    eprintln!("{} '{}' not found as group label or reference", "error:".red().bold(), target);
                    1
                }
            }
            Err(e) => {
                eprintln!("{} {}", "error:".red().bold(), e);
                1
            }
        }
    }
}

fn show_reference(conn: &rusqlite::Connection, target: &str, json: bool) -> i32 {
    let identity_key = match super::resolve_ref_id(conn, target) {
        Ok(k) => k,
        Err(e) => {
            eprintln!("{} {}", "error:".red().bold(), e);
            return 2;
        }
    };

    let reference = match db::get_reference(conn, &identity_key) {
        Ok(Some(r)) => r,
        Ok(None) => {
            eprintln!("{} reference not found", "error:".red().bold());
            return 1;
        }
        Err(e) => {
            eprintln!("{} {}", "error:".red().bold(), e);
            return 1;
        }
    };

    if json {
        let output = serde_json::json!({
            "identity_key": reference.identity_key,
            "file_path": reference.file_path,
            "location": {
                "kind": reference.location.kind.to_string(),
                "discriminator": reference.location.discriminator,
                "line_number": reference.location.line_number,
            },
            "provider_pattern": reference.provider_pattern,
            "fingerprint": reference.fingerprint,
            "display_label": reference.display_label,
            "first_seen": reference.first_seen.to_rfc3339(),
            "last_seen": reference.last_seen.to_rfc3339(),
            "last_changed": reference.last_changed.to_rfc3339(),
            "scan_status": reference.scan_status.to_string(),
        });
        println!("{}", serde_json::to_string_pretty(&output).unwrap());
    } else {
        let refs = db::list_references(conn).unwrap_or_default();
        let all_keys: Vec<&str> = refs.iter().map(|r| r.identity_key.as_str()).collect();
        let display_id = fingerprint::display_id(&reference.identity_key, &all_keys);

        println!("{} {}", "Reference:".bold(), display_id);
        println!("  Label:        {}", reference.display_label);
        println!("  File:         {}", reference.file_path);
        println!("  Location:     {} ({})", reference.location.discriminator, reference.location.kind);
        if let Some(line) = reference.location.line_number {
            println!("  Line:         {}", line);
        }
        if let Some(ref provider) = reference.provider_pattern {
            println!("  Provider:     {}", provider);
        }
        println!("  Fingerprint:  {}", &reference.fingerprint[..16]);
        println!("  Status:       {}", reference.scan_status);
        println!("  First seen:   {}", reference.first_seen.format("%Y-%m-%d %H:%M:%S"));
        println!("  Last seen:    {}", reference.last_seen.format("%Y-%m-%d %H:%M:%S"));
        println!("  Last changed: {}", reference.last_changed.format("%Y-%m-%d %H:%M:%S"));
    }

    0
}

fn show_group(conn: &rusqlite::Connection, label: &str, json: bool) -> i32 {
    let group = match db::get_group_by_label(conn, label) {
        Ok(Some(g)) => g,
        Ok(None) => {
            eprintln!("{} group '{}' not found", "error:".red().bold(), label);
            return 1;
        }
        Err(e) => {
            eprintln!("{} {}", "error:".red().bold(), e);
            return 1;
        }
    };

    // Load member details
    let mut members = Vec::new();
    for member_id in &group.members {
        if let Ok(Some(reference)) = db::get_reference(conn, member_id) {
            members.push(reference);
        }
    }

    if json {
        let output = serde_json::json!({
            "group_id": group.group_id.to_string(),
            "label": group.label,
            "status": group.status.to_string(),
            "created_at": group.created_at.to_rfc3339(),
            "confirmed_at": group.confirmed_at.to_rfc3339(),
            "members": members.iter().map(|r| {
                serde_json::json!({
                    "identity_key": r.identity_key,
                    "file_path": r.file_path,
                    "location": {
                        "kind": r.location.kind.to_string(),
                        "discriminator": r.location.discriminator,
                        "line_number": r.location.line_number,
                    },
                    "fingerprint": r.fingerprint,
                    "display_label": r.display_label,
                    "scan_status": r.scan_status.to_string(),
                })
            }).collect::<Vec<_>>(),
        });
        println!("{}", serde_json::to_string_pretty(&output).unwrap());
    } else {
        let refs = db::list_references(conn).unwrap_or_default();
        let all_keys: Vec<&str> = refs.iter().map(|r| r.identity_key.as_str()).collect();

        let status_display = match group.status {
            crate::index::models::GroupStatus::Synced => "synced".green().to_string(),
            crate::index::models::GroupStatus::Drifted => "DRIFTED".red().to_string(),
            crate::index::models::GroupStatus::Degraded => "degraded".yellow().to_string(),
            crate::index::models::GroupStatus::Empty => "empty".dimmed().to_string(),
            _ => group.status.to_string(),
        };

        println!("{} {} [{}]", "Group:".bold(), group.label, status_display);
        println!("  Members ({}):", members.len());
        for member in &members {
            let display_id = fingerprint::display_id(&member.identity_key, &all_keys);
            let status = match member.scan_status {
                crate::index::models::ScanStatus::Present => "".to_string(),
                crate::index::models::ScanStatus::Removed => " [REMOVED]".red().to_string(),
                crate::index::models::ScanStatus::Error => " [ERROR]".red().to_string(),
            };
            println!(
                "    {} {} at {}{}",
                display_id.dimmed(),
                member.display_label,
                member.file_path,
                status,
            );
            println!("      Fingerprint: {}", &member.fingerprint[..16]);
        }
    }

    0
}
