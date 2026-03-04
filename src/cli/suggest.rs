use colored::Colorize;
use std::io::{self, Write};

use crate::index::db;
use crate::index::fingerprint;
use crate::index::models::*;

pub fn run(review: bool, json: bool) -> i32 {
    if review && json {
        eprintln!("{} cannot combine --review (interactive) with --json", "error:".red().bold());
        return 2;
    }

    let (conn, _keys) = match super::open_db() {
        Ok(v) => v,
        Err(e) => {
            eprintln!("{} {}", "error:".red().bold(), e);
            return 1;
        }
    };

    let suggestions = match db::list_suggestions(&conn, Some(&SuggestionStatus::Pending)) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("{} {}", "error:".red().bold(), e);
            return 1;
        }
    };

    if suggestions.is_empty() {
        if json {
            println!("{}", serde_json::json!({"suggestions": []}));
        } else {
            println!("No pending suggestions.");
        }
        return 0;
    }

    if json {
        let output = serde_json::json!({
            "suggestions": suggestions.iter().map(|s| {
                serde_json::json!({
                    "suggestion_id": s.suggestion_id.to_string(),
                    "reason": s.reason.to_string(),
                    "confidence": s.confidence,
                    "reference_ids": s.reference_ids,
                    "proposed_label": s.proposed_label,
                    "metadata": s.metadata,
                })
            }).collect::<Vec<_>>(),
        });
        println!("{}", serde_json::to_string_pretty(&output).unwrap());
        return 0;
    }

    // Load refs for display
    let refs = db::list_references(&conn).unwrap_or_default();
    let all_keys: Vec<&str> = refs.iter().map(|r| r.identity_key.as_str()).collect();

    if review {
        // Interactive review
        for suggestion in &suggestions {
            println!();
            print_suggestion(suggestion, &refs, &all_keys);

            print!("  [a]ccept / [r]eject / [s]kip? ");
            io::stdout().flush().unwrap();

            let mut input = String::new();
            io::stdin().read_line(&mut input).unwrap();
            let choice = input.trim().to_lowercase();

            match choice.as_str() {
                "a" | "accept" => {
                    // Accept: create group
                    let label = suggestion
                        .proposed_label
                        .clone()
                        .unwrap_or_else(|| format!("group-{}", &suggestion.suggestion_id.to_string()[..8]));

                    match crate::group::create_group(&conn, &label, &suggestion.reference_ids) {
                        Ok(group) => {
                            if let Err(e) = db::update_suggestion_status(
                                &conn,
                                &suggestion.suggestion_id,
                                &SuggestionStatus::Accepted,
                            ) {
                                eprintln!("{} failed to update suggestion: {}", "warning:".yellow().bold(), e);
                            }
                            println!("  {} Created group '{}'", "ok:".green().bold(), group.label);
                        }
                        Err(e) => {
                            eprintln!("  {} {}", "error:".red().bold(), e);
                        }
                    }
                }
                "r" | "reject" => {
                    if let Err(e) = db::update_suggestion_status(
                        &conn,
                        &suggestion.suggestion_id,
                        &SuggestionStatus::Rejected,
                    ) {
                        eprintln!("{} {}", "warning:".yellow().bold(), e);
                    }
                    println!("  Rejected.");
                }
                _ => {
                    println!("  Skipped.");
                }
            }
        }
    } else {
        // Non-interactive: just list
        println!("{} ({} pending)", "Suggestions".bold(), suggestions.len());
        for suggestion in &suggestions {
            println!();
            print_suggestion(suggestion, &refs, &all_keys);
        }
        println!();
        println!("Run `hagrid suggest --review` to accept or reject.");
    }

    0
}

fn print_suggestion(
    suggestion: &Suggestion,
    refs: &[SecretReference],
    all_keys: &[&str],
) {
    let reason = match suggestion.reason {
        SuggestionReason::ExactFingerprint => "exact fingerprint match".green().to_string(),
        SuggestionReason::StructuralMatch => "structural match".yellow().to_string(),
        SuggestionReason::ProviderMatch => "provider match".yellow().to_string(),
        SuggestionReason::AgentProposal => "agent proposal".dimmed().to_string(),
    };

    println!(
        "  Suggestion: {} (confidence: {:.0}%)",
        reason,
        suggestion.confidence * 100.0
    );

    if let Some(ref label) = suggestion.proposed_label {
        println!("  Proposed label: {}", label.bold());
    }

    println!("  References:");
    for ref_id in &suggestion.reference_ids {
        let display_id = fingerprint::display_id(ref_id, all_keys);
        if let Some(r) = refs.iter().find(|r| r.identity_key == *ref_id) {
            println!(
                "    {} {} at {}",
                display_id.dimmed(),
                r.display_label,
                r.file_path,
            );
        } else {
            println!("    {} (reference not found)", display_id.dimmed());
        }
    }
}
