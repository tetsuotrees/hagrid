use colored::Colorize;

pub fn run(ref_id: &str) -> i32 {
    let (conn, _keys) = match super::open_db() {
        Ok(v) => v,
        Err(e) => {
            eprintln!("{} {}", "error:".red().bold(), e);
            return 1;
        }
    };

    let identity_key = match super::resolve_ref_id(&conn, ref_id) {
        Ok(k) => k,
        Err(e) => {
            eprintln!("{} {}", "error:".red().bold(), e);
            return 2;
        }
    };

    match crate::group::ungroup_reference(&conn, &identity_key) {
        Ok(Some(_group_id)) => {
            println!("{} Reference removed from group", "ok:".green().bold());
            0
        }
        Ok(None) => {
            println!("Reference was not in any group.");
            0
        }
        Err(e) => {
            eprintln!("{} {}", "error:".red().bold(), e);
            1
        }
    }
}
