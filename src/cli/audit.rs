use colored::Colorize;

use crate::policy;

pub fn run(json: bool) -> i32 {
    let (conn, _keys) = match super::open_db() {
        Ok(v) => v,
        Err(e) => {
            eprintln!("{} {}", "error:".red().bold(), e);
            return 1;
        }
    };

    let policies = match policy::load_policies() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("{} {}", "error:".red().bold(), e);
            return 1;
        }
    };

    if policies.is_empty() {
        if json {
            println!(r#"{{"violations":0,"warnings":0,"results":[]}}"#);
        } else {
            println!("No policies defined in {}.", crate::config::policies_path().display());
        }
        return 0;
    }

    let results = match policy::evaluate_policies(&conn, &policies) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("{} {}", "error:".red().bold(), e);
            return 1;
        }
    };

    let violations = results.iter().filter(|r| r.severity == policy::Severity::Violation).count();
    let warnings = results.iter().filter(|r| r.severity == policy::Severity::Warn).count();

    if json {
        let json_results: Vec<serde_json::Value> = results.iter().map(|r| {
            serde_json::json!({
                "rule_name": r.rule_name,
                "severity": match r.severity {
                    policy::Severity::Pass => "pass",
                    policy::Severity::Warn => "warning",
                    policy::Severity::Violation => "violation",
                },
                "message": r.message,
                "affected_references": r.affected_references.iter().map(|a| {
                    serde_json::json!({
                        "identity_key": a.identity_key,
                        "display_label": a.display_label,
                        "file_path": a.file_path,
                    })
                }).collect::<Vec<_>>(),
            })
        }).collect();

        let output = serde_json::json!({
            "violations": violations,
            "warnings": warnings,
            "results": json_results,
        });
        println!("{}", serde_json::to_string_pretty(&output).unwrap());
    } else {
        for r in &results {
            match r.severity {
                policy::Severity::Pass => continue,
                policy::Severity::Warn => {
                    println!("{} {} — {}", "[WARNING]".yellow().bold(), r.rule_name, r.message);
                }
                policy::Severity::Violation => {
                    println!("{} {} — {}", "[VIOLATION]".red().bold(), r.rule_name, r.message);
                }
            }
            for a in &r.affected_references {
                println!("    {} at {}", a.display_label, a.file_path);
            }
        }

        if violations == 0 && warnings == 0 {
            println!("All policies pass.");
        }
    }

    if violations > 0 { 4 } else { 0 }
}
