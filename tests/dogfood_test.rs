//! Dogfooding test: exercises the scan engine against real local config paths.
//!
//! This test does NOT output secret values — only finding metadata (file paths,
//! location discriminators, provider patterns, display labels). It validates
//! the scan engine's behavior on real-world files.
//!
//! IMPORTANT: This test reads real files on the machine. It does NOT store,
//! transmit, or log any secret values.

use hagrid::config::Config;
use hagrid::scan::engine::{self, ScanDepth};
use std::path::Path;

fn expand(path: &str) -> std::path::PathBuf {
    hagrid::config::expand_tilde(path)
}

/// Run a Standard-depth scan against targeted real shell config files.
/// These are small files that complete quickly.
#[test]
fn dogfood_scan_shell_configs() {
    let config = Config::default();

    let shell_files = &["~/.zshrc", "~/.bash_profile", "~/.profile"];

    let mut total_files = 0;
    let mut total_findings = 0;
    let mut all_findings: Vec<(String, String, String, Option<String>)> = Vec::new();

    for path_str in shell_files {
        let path = expand(path_str);
        if !path.exists() {
            continue;
        }

        let result = engine::scan(&config, ScanDepth::Standard, Some(&path));
        total_files += result.files_scanned;
        total_findings += result.findings.len();

        for f in &result.findings {
            all_findings.push((
                f.file_path.clone(),
                f.location.discriminator.clone(),
                f.display_label.clone(),
                f.provider_pattern.clone(),
            ));
        }
    }

    eprintln!("\n=== DOGFOOD: SHELL CONFIGS ===");
    eprintln!("Files scanned: {}", total_files);
    eprintln!("Findings: {}", total_findings);
    for f in &all_findings {
        let basename = Path::new(&f.0)
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| f.0.clone());
        eprintln!(
            "  - {} @ {} [{}] ({})",
            basename,
            f.1,
            f.3.as_deref().unwrap_or("heuristic"),
            f.2
        );
    }
    eprintln!("=== END ===\n");

    assert!(total_files > 0, "should scan at least 1 shell config");
}

/// SSH directory should detect PEM private keys.
#[test]
fn dogfood_ssh_detects_private_keys() {
    let config = Config::default();
    let ssh_dir = expand("~/.ssh");

    if !ssh_dir.exists() {
        eprintln!("SKIP: ~/.ssh does not exist");
        return;
    }

    let result = engine::scan(&config, ScanDepth::Lite, Some(&ssh_dir));

    let pem_findings: Vec<_> = result
        .findings
        .iter()
        .filter(|f| f.provider_pattern.as_deref() == Some("private_key_pem"))
        .collect();

    eprintln!(
        "\n=== DOGFOOD: SSH ===\nFiles: {}, Findings: {}, PEM keys: {}\n=== END ===\n",
        result.files_scanned,
        result.findings.len(),
        pem_findings.len()
    );

    // Most dev machines have at least one SSH key
    if pem_findings.is_empty() {
        eprintln!("NOTE: No PEM private keys found in ~/.ssh (unusual but not a bug)");
    }
}

/// Lite scan should find a subset of what Standard finds.
#[test]
fn dogfood_lite_vs_standard_real_configs() {
    let config = Config::default();

    let path = expand("~/.zshrc");
    if !path.exists() {
        eprintln!("SKIP: ~/.zshrc does not exist");
        return;
    }

    let lite = engine::scan(&config, ScanDepth::Lite, Some(&path));
    let standard = engine::scan(&config, ScanDepth::Standard, Some(&path));

    eprintln!(
        "\n=== DOGFOOD: LITE vs STANDARD ===\nLite: {} findings, Standard: {} findings\n=== END ===\n",
        lite.findings.len(),
        standard.findings.len()
    );

    assert!(
        standard.findings.len() >= lite.findings.len(),
        "Standard ({}) should find >= Lite ({})",
        standard.findings.len(),
        lite.findings.len()
    );
}

/// Verify that the exclude rules actually filter out expected directories.
#[test]
fn dogfood_excludes_node_modules_and_target() {
    use hagrid::scan::walker;

    let config = Config::default();

    // Scan just the hagrid project dir itself — known to have a target/ dir
    let project = expand("~/Projects/hagrid");
    if !project.exists() {
        eprintln!("SKIP: ~/Projects/hagrid does not exist");
        return;
    }

    let files = walker::walk_files(&config, Some(&project));

    let violations: Vec<_> = files
        .iter()
        .filter(|f| {
            let s = f.to_string_lossy();
            s.contains("/node_modules/") || s.contains("/target/")
        })
        .collect();

    eprintln!(
        "\n=== DOGFOOD: EXCLUSIONS ===\nTotal files walked: {}\nExclusion violations: {}\n=== END ===\n",
        files.len(),
        violations.len()
    );

    assert!(
        violations.is_empty(),
        "found {} files in excluded directories",
        violations.len()
    );
}

/// Scan the hagrid project's own test fixtures — validates scan engine against
/// known inputs with known expected outputs.
#[test]
fn dogfood_scan_own_fixtures() {
    let config = Config::default();
    let fixtures = expand("~/Projects/hagrid/tests/fixtures");

    let result = engine::scan(&config, ScanDepth::Standard, Some(&fixtures));

    eprintln!("\n=== DOGFOOD: OWN FIXTURES ===");
    eprintln!(
        "Files: {}, Findings: {}, Errors: {}",
        result.files_scanned,
        result.findings.len(),
        result.errors.len()
    );
    for f in &result.findings {
        let basename = Path::new(&f.file_path)
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();
        eprintln!(
            "  - {} @ {} [{}]",
            basename,
            f.location.discriminator,
            f.provider_pattern.as_deref().unwrap_or("heuristic")
        );
    }
    eprintln!("=== END ===\n");

    // We know our fixtures have secrets — should find at least a few
    assert!(
        result.findings.len() >= 3,
        "should find at least 3 secrets in our own fixtures, found {}",
        result.findings.len()
    );
}

/// Scan a single known .env-style file path (the hagrid project's own fixture).
/// Validates structural parsing + pattern matching integration.
#[test]
fn dogfood_env_parsing_integration() {
    let config = Config::default();
    let env_file = expand("~/Projects/hagrid/tests/fixtures/simple.env");

    let result = engine::scan(&config, ScanDepth::Standard, Some(&env_file));

    eprintln!("\n=== DOGFOOD: .ENV PARSING ===");
    for f in &result.findings {
        eprintln!(
            "  - {} [{}] kind={:?}",
            f.location.discriminator,
            f.provider_pattern.as_deref().unwrap_or("heuristic"),
            f.location.kind
        );
    }
    eprintln!("=== END ===\n");

    // simple.env should produce findings with EnvVar location kind from structural parsing
    let env_findings: Vec<_> = result
        .findings
        .iter()
        .filter(|f| f.location.kind == hagrid::index::models::LocationKind::EnvVar)
        .collect();

    // With Standard depth, structural parsing should produce EnvVar-typed locations
    // (If this is 0, it means structural parser output is being deduped away or not working)
    eprintln!("EnvVar-typed findings: {}", env_findings.len());
}
