#![allow(dead_code)]

use clap::{Parser, Subcommand};
use std::process;
use tracing_subscriber::EnvFilter;

mod cli;
mod config;
mod drift;
mod group;
mod index;
mod keychain;
mod notify;
mod policy;
mod rotate;
mod scan;
mod suggest;
mod tui;
mod watch;

#[derive(Parser)]
#[command(
    name = "hagrid",
    about = "Keeper of Keys — local-first secret lifecycle management",
    version
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Setup: generate master secret, create ~/.hagrid/, configure scope
    Init,

    /// Scan for secrets
    Scan {
        /// Scan depth: lite or standard
        #[arg(long, default_value = "standard")]
        depth: String,

        /// Override scan roots with a specific path
        #[arg(long)]
        path: Option<String>,

        /// Output as JSON
        #[arg(long)]
        json: bool,
    },

    /// Overview: secrets, groups, drift, suggestions
    Status {
        /// Output as JSON
        #[arg(long)]
        json: bool,
    },

    /// List secrets and groups
    List {
        /// Show only ungrouped references
        #[arg(long)]
        ungrouped: bool,

        /// Output as JSON
        #[arg(long)]
        json: bool,
    },

    /// Show details for a group or reference
    Show {
        /// Group label or reference ID (ref:xxxxx)
        target: String,

        /// Output as JSON
        #[arg(long)]
        json: bool,
    },

    /// Show or review grouping suggestions
    Suggest {
        /// Interactively review suggestions
        #[arg(long)]
        review: bool,

        /// Output as JSON
        #[arg(long)]
        json: bool,
    },

    /// Create a group from references
    Group {
        /// Group label
        label: String,

        /// Reference IDs to include
        #[arg(required = true)]
        refs: Vec<String>,
    },

    /// Remove a reference from its group
    Ungroup {
        /// Reference ID (ref:xxxxx or full identity key)
        ref_id: String,
    },

    /// Check groups for value drift
    Drift {
        /// Output as JSON
        #[arg(long)]
        json: bool,
    },

    /// Remove a reference or group from tracking
    Forget {
        /// Reference ID or group label
        target: String,
    },

    /// Export index data
    Export {
        /// Output format: json or csv
        #[arg(long, default_value = "json")]
        format: String,
    },

    /// Evaluate policy rules and report violations
    Audit {
        /// Output as JSON
        #[arg(long)]
        json: bool,
    },

    /// Show rotation info for a group
    RotateInfo {
        /// Group label
        group_label: String,

        /// Output as JSON
        #[arg(long)]
        json: bool,
    },

    /// Rotate a secret across all group members
    Rotate {
        /// Group label
        group_label: String,

        /// Create .bak backup of each modified file
        #[arg(long)]
        backup: bool,
    },

    /// Watch for file changes and re-scan automatically
    Watch,

    /// Launch interactive terminal UI for browsing inventory
    Tui,
}

fn main() {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("warn")),
        )
        .with_target(false)
        .init();

    let cli = Cli::parse();

    let exit_code = match cli.command {
        Commands::Init => cli::init::run(),
        Commands::Scan { depth, path, json } => cli::scan::run(&depth, path.as_deref(), json),
        Commands::Status { json } => cli::status::run(json),
        Commands::List { ungrouped, json } => cli::list::run(ungrouped, json),
        Commands::Show { target, json } => cli::show::run(&target, json),
        Commands::Suggest { review, json } => cli::suggest::run(review, json),
        Commands::Group { label, refs } => cli::group::run(&label, &refs),
        Commands::Ungroup { ref_id } => cli::ungroup::run(&ref_id),
        Commands::Drift { json } => cli::drift::run(json),
        Commands::Forget { target } => cli::forget::run(&target),
        Commands::Export { format } => cli::export::run(&format),
        Commands::Audit { json } => cli::audit::run(json),
        Commands::RotateInfo { group_label, json } => cli::rotate_info::run(&group_label, json),
        Commands::Rotate {
            group_label,
            backup,
        } => cli::rotate::run(&group_label, backup),
        Commands::Watch => cli::watch::run(),
        Commands::Tui => tui::run(),
    };

    process::exit(exit_code);
}
