use colored::Colorize;

use crate::config;
use crate::watch;

pub fn run() -> i32 {
    let (conn, keys) = match super::open_db() {
        Ok(v) => v,
        Err(e) => {
            eprintln!("{} {}", "error:".red().bold(), e);
            return 1;
        }
    };

    let cfg = match config::load_config() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{} {}", "error:".red().bold(), e);
            return 1;
        }
    };

    watch::run_watch(&conn, &keys, &cfg)
}
