use colored::Colorize;

pub fn run(label: &str, ref_ids: &[String]) -> i32 {
    let (conn, _keys) = match super::open_db() {
        Ok(v) => v,
        Err(e) => {
            eprintln!("{} {}", "error:".red().bold(), e);
            return 1;
        }
    };

    // Resolve all ref IDs
    let mut resolved_ids = Vec::new();
    for ref_id in ref_ids {
        match super::resolve_ref_id(&conn, ref_id) {
            Ok(id) => resolved_ids.push(id),
            Err(e) => {
                eprintln!("{} {}", "error:".red().bold(), e);
                return 2;
            }
        }
    }

    match crate::group::create_group(&conn, label, &resolved_ids) {
        Ok(group) => {
            println!(
                "{} Created group '{}' with {} members",
                "ok:".green().bold(),
                group.label,
                group.members.len()
            );
            0
        }
        Err(e) => {
            eprintln!("{} {}", "error:".red().bold(), e);
            1
        }
    }
}
