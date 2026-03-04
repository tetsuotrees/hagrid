use ignore::overrides::OverrideBuilder;
use ignore::WalkBuilder;
use std::path::{Path, PathBuf};
use tracing::warn;

use crate::config::{self, Config};

/// Walk files in the configured scan roots, respecting exclusions.
pub fn walk_files(config: &Config, path_override: Option<&Path>) -> Vec<PathBuf> {
    let mut files = Vec::new();

    let roots: Vec<PathBuf> = if let Some(path) = path_override {
        vec![path.to_path_buf()]
    } else {
        config
            .scan
            .roots
            .iter()
            .map(|r| config::expand_tilde(r))
            .collect()
    };

    let max_size = config.scan.max_file_size_mb * 1024 * 1024;

    for root in &roots {
        if !root.exists() {
            continue;
        }

        if root.is_file() {
            // Single file root
            if should_include_file(root, max_size, config) {
                files.push(root.clone());
            }
            continue;
        }

        let mut builder = WalkBuilder::new(root);
        builder
            .hidden(false) // don't skip hidden files (we want .env, .zshrc, etc.)
            .follow_links(config.scan.follow_symlinks)
            .max_depth(Some(20)); // prevent unbounded recursion

        // Add exclude directory overrides
        let mut override_builder = OverrideBuilder::new(root);
        for dir in &config.scan.exclude_dirs {
            let pattern = format!("!{}/**", dir);
            if let Err(e) = override_builder.add(&pattern) {
                warn!("invalid exclude pattern '{}': {}", dir, e);
            }
        }
        for glob in &config.scan.exclude_globs {
            let pattern = format!("!{}", glob);
            if let Err(e) = override_builder.add(&pattern) {
                warn!("invalid exclude glob '{}': {}", glob, e);
            }
        }

        if let Ok(overrides) = override_builder.build() {
            builder.overrides(overrides);
        }

        for entry in builder.build() {
            match entry {
                Ok(entry) => {
                    let path = entry.path();

                    // Skip directories
                    if path.is_dir() {
                        continue;
                    }

                    // Check hard exclusions
                    if config::is_hard_excluded(path) {
                        continue;
                    }

                    // Check if excluded directory
                    if is_in_excluded_dir(path, &config.scan.exclude_dirs) {
                        continue;
                    }

                    if should_include_file(path, max_size, config) {
                        files.push(path.to_path_buf());
                    }
                }
                Err(e) => {
                    warn!("error walking {}: {}", root.display(), e);
                }
            }
        }
    }

    files.sort();
    files.dedup();
    files
}

fn should_include_file(path: &Path, max_size: u64, config: &Config) -> bool {
    // Check file size
    if let Ok(metadata) = std::fs::metadata(path) {
        if metadata.len() > max_size {
            return false;
        }
    }

    // Check exclude globs by extension
    if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
        for glob in &config.scan.exclude_globs {
            if let Some(glob_ext) = glob.strip_prefix("*.") {
                if ext == glob_ext {
                    return false;
                }
            }
        }
    }

    // Check if binary
    if is_likely_binary(path) {
        return false;
    }

    true
}

fn is_in_excluded_dir(path: &Path, exclude_dirs: &[String]) -> bool {
    for component in path.components() {
        if let std::path::Component::Normal(name) = component {
            let name_str = name.to_string_lossy();
            for excluded in exclude_dirs {
                // Handle paths like ".git/objects"
                if excluded.contains('/') {
                    let path_str = path.to_string_lossy();
                    if path_str.contains(excluded) {
                        return true;
                    }
                } else if name_str == *excluded {
                    return true;
                }
            }
        }
    }
    false
}

fn is_likely_binary(path: &Path) -> bool {
    let binary_extensions = [
        "exe", "dll", "so", "dylib", "o", "a", "lib",
        "png", "jpg", "jpeg", "gif", "bmp", "ico", "svg",
        "mp3", "mp4", "avi", "mov", "wav", "flac",
        "zip", "tar", "gz", "bz2", "xz", "7z", "rar",
        "pdf", "doc", "docx", "xls", "xlsx",
        "wasm", "pyc", "pyo", "class",
        "db", "sqlite", "sqlite3",
    ];

    if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
        return binary_extensions.contains(&ext.to_lowercase().as_str());
    }

    false
}
