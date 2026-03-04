use colored::Colorize;

use crate::index::db;

pub fn run(json: bool) -> i32 {
    let (conn, _keys) = match super::open_db() {
        Ok(v) => v,
        Err(e) => {
            eprintln!("{} {}", "error:".red().bold(), e);
            return 1;
        }
    };

    let ref_count = db::count_references(&conn).unwrap_or(0);
    let group_count = db::count_groups(&conn).unwrap_or(0);
    let ungrouped = db::count_ungrouped_references(&conn).unwrap_or(0);
    let pending_suggestions = db::count_pending_suggestions(&conn).unwrap_or(0);
    let unresolved_drift = db::count_unresolved_drift(&conn).unwrap_or(0);

    if json {
        let output = serde_json::json!({
            "references": ref_count,
            "groups": group_count,
            "ungrouped": ungrouped,
            "pending_suggestions": pending_suggestions,
            "unresolved_drift": unresolved_drift,
        });
        println!("{}", serde_json::to_string_pretty(&output).unwrap());
    } else {
        println!("{}", "Hagrid Status".bold());
        println!("  Tracked secrets: {}", ref_count);
        println!("  Groups: {}", group_count);
        println!("  Ungrouped: {}", ungrouped);

        if pending_suggestions > 0 {
            println!(
                "  Pending suggestions: {} — run `hagrid suggest --review`",
                pending_suggestions.to_string().yellow()
            );
        }

        if unresolved_drift > 0 {
            println!(
                "  {} — run `hagrid drift` for details",
                format!("Drift detected: {}", unresolved_drift).red()
            );
        } else if group_count > 0 {
            println!("  Drift: {}", "none".green());
        }
    }

    0
}
