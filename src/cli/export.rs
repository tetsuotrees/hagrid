use colored::Colorize;

use crate::index::db;

pub fn run(format: &str) -> i32 {
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

    match format {
        "json" => {
            let output = serde_json::json!({
                "references": refs.iter().map(|r| {
                    serde_json::json!({
                        "identity_key": r.identity_key,
                        "file_path": r.file_path,
                        "location": {
                            "kind": r.location.kind.to_string(),
                            "discriminator": r.location.discriminator,
                            "line_number": r.location.line_number,
                        },
                        "provider_pattern": r.provider_pattern,
                        "fingerprint": r.fingerprint,
                        "display_label": r.display_label,
                        "first_seen": r.first_seen.to_rfc3339(),
                        "last_seen": r.last_seen.to_rfc3339(),
                        "last_changed": r.last_changed.to_rfc3339(),
                        "scan_status": r.scan_status.to_string(),
                    })
                }).collect::<Vec<_>>(),
                "groups": groups.iter().map(|g| {
                    serde_json::json!({
                        "group_id": g.group_id.to_string(),
                        "label": g.label,
                        "status": g.status.to_string(),
                        "members": g.members,
                        "created_at": g.created_at.to_rfc3339(),
                        "confirmed_at": g.confirmed_at.to_rfc3339(),
                    })
                }).collect::<Vec<_>>(),
            });
            println!("{}", serde_json::to_string_pretty(&output).unwrap());
        }
        "csv" => {
            println!("identity_key,file_path,location_kind,discriminator,line_number,provider,display_label,fingerprint,scan_status");
            for r in &refs {
                println!(
                    "{},{},{},{},{},{},{},{},{}",
                    r.identity_key,
                    r.file_path,
                    r.location.kind,
                    r.location.discriminator,
                    r.location.line_number.map(|n| n.to_string()).unwrap_or_default(),
                    r.provider_pattern.as_deref().unwrap_or(""),
                    r.display_label,
                    &r.fingerprint[..16],
                    r.scan_status,
                );
            }
        }
        _ => {
            eprintln!("{} invalid format '{}' — use 'json' or 'csv'", "error:".red().bold(), format);
            return 2;
        }
    }

    0
}
