use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use notify::{self, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use tracing::{debug, info, warn};

use crate::config::{self, Config};
use crate::index::db;
use crate::index::fingerprint::DerivedKeys;
use crate::scan::engine::{self, ScanDepth};
use crate::scan::patterns::{self, CompiledPattern};
use crate::scan::walker;

/// Debounce window: coalesce rapid events into a single re-scan per file.
const DEBOUNCE_MS: u64 = 500;

/// Result of processing a single file change.
#[derive(Debug)]
pub struct FileChangeResult {
    pub file_path: String,
    pub findings_count: usize,
    pub upserted: usize,
    pub errors: Vec<String>,
}

/// Process a single file change: scan the file and upsert findings into DB.
///
/// This is the testable core of the watch engine. It does NOT call
/// `mark_unseen_as_removed` — watch mode is upsert-only to avoid
/// flapping when files are temporarily locked or being written.
pub fn process_file_change(
    file_path: &Path,
    conn: &rusqlite::Connection,
    keys: &DerivedKeys,
    patterns: &[CompiledPattern],
    config: &Config,
) -> FileChangeResult {
    let path_str = file_path
        .canonicalize()
        .unwrap_or_else(|_| file_path.to_path_buf())
        .to_string_lossy()
        .to_string();

    let mut result = FileChangeResult {
        file_path: path_str.clone(),
        findings_count: 0,
        upserted: 0,
        errors: Vec::new(),
    };

    // Check if file still exists (may have been deleted)
    if !file_path.exists() {
        debug!("file no longer exists, skipping: {}", path_str);
        return result;
    }

    // Apply walker filters: skip binary, oversized, excluded files
    let max_size = config.scan.max_file_size_mb * 1024 * 1024;
    if !walker::should_include_file(file_path, max_size, config) {
        debug!("file excluded by filters: {}", path_str);
        return result;
    }
    if config::is_hard_excluded(file_path) {
        debug!("file hard-excluded: {}", path_str);
        return result;
    }
    if walker::is_in_excluded_dir(file_path, &config.scan.exclude_dirs) {
        debug!("file in excluded directory: {}", path_str);
        return result;
    }

    // Scan the single file at Standard depth
    let scan_result = engine::scan_single_file(file_path, patterns, ScanDepth::Standard);
    let findings = match scan_result {
        Ok(f) => f,
        Err(e) => {
            let msg = format!("{}: {}", path_str, e);
            warn!("{}", msg);
            result.errors.push(msg);
            return result;
        }
    };

    result.findings_count = findings.len();

    // Convert to references and upsert
    let references = engine::findings_to_references(
        &findings,
        &keys.identity_key,
        &keys.fingerprint_key,
    );

    for reference in &references {
        if let Err(e) = db::upsert_reference(conn, reference) {
            let msg = format!("failed to store reference: {}", e);
            warn!("{}", msg);
            result.errors.push(msg);
        } else {
            result.upserted += 1;
        }
    }

    result
}

/// Run the watch loop. Blocks until interrupted.
///
/// Returns exit code: 0 on clean shutdown, 1 on fatal setup error.
pub fn run_watch(
    conn: &rusqlite::Connection,
    keys: &DerivedKeys,
    config: &Config,
) -> i32 {
    // Load patterns
    let patterns = match patterns::load_patterns(Some(&config::patterns_path())) {
        Ok(p) => p,
        Err(e) => {
            warn!("failed to load user patterns, using defaults: {}", e);
            patterns::load_default_patterns().unwrap_or_default()
        }
    };

    // Resolve watch roots
    let roots: Vec<PathBuf> = config
        .scan
        .roots
        .iter()
        .map(|r| config::expand_tilde(r))
        .filter(|r| r.exists())
        .collect();

    if roots.is_empty() {
        eprintln!("error: no scan roots exist, nothing to watch");
        return 1;
    }

    // Set up notify watcher
    let (tx, rx) = mpsc::channel();

    let mut watcher: RecommendedWatcher = match notify::recommended_watcher(move |res| {
        if let Ok(event) = res {
            let _ = tx.send(event);
        }
    }) {
        Ok(w) => w,
        Err(e) => {
            eprintln!("error: failed to create file watcher: {}", e);
            return 1;
        }
    };

    // Watch all roots recursively
    let mut watched_roots = 0usize;
    for root in &roots {
        if root.is_dir() {
            if let Err(e) = watcher.watch(root, RecursiveMode::Recursive) {
                eprintln!("warning: cannot watch {}: {}", root.display(), e);
            } else {
                eprintln!("watching: {}", root.display());
                watched_roots += 1;
            }
        } else if root.is_file() {
            if let Err(e) = watcher.watch(root, RecursiveMode::NonRecursive) {
                eprintln!("warning: cannot watch {}: {}", root.display(), e);
            } else {
                eprintln!("watching: {}", root.display());
                watched_roots += 1;
            }
        }
    }

    if watched_roots == 0 {
        eprintln!("error: failed to watch any scan roots");
        return 1;
    }

    eprintln!("hagrid watch: listening for file changes (ctrl-c to stop)");

    // Event loop with debouncing
    let debounce = Duration::from_millis(DEBOUNCE_MS);
    let mut pending: HashSet<PathBuf> = HashSet::new();
    let mut last_event = Instant::now();

    loop {
        match rx.recv_timeout(debounce) {
            Ok(event) => {
                // Only process Create/Modify events (not Remove — upsert-only)
                match event.kind {
                    EventKind::Create(_) | EventKind::Modify(_) => {
                        for path in event.paths {
                            if path.is_file() {
                                pending.insert(path);
                            }
                        }
                        last_event = Instant::now();
                    }
                    _ => {}
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                // Debounce window elapsed — process pending files
                if !pending.is_empty() && last_event.elapsed() >= debounce {
                    let batch: Vec<PathBuf> = pending.drain().collect();
                    for file_path in &batch {
                        let result =
                            process_file_change(file_path, conn, keys, &patterns, config);
                        if result.findings_count > 0 {
                            eprintln!(
                                "  {} — {} finding(s), {} upserted",
                                result.file_path, result.findings_count, result.upserted
                            );
                        }
                        for err in &result.errors {
                            eprintln!("  error: {}", err);
                        }
                    }
                }
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                info!("watch channel disconnected, shutting down");
                break;
            }
        }
    }

    0
}
