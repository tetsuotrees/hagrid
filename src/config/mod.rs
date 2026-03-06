use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("failed to read config file: {0}")]
    ReadError(#[from] std::io::Error),
    #[error("failed to parse config file: {0}")]
    ParseError(#[from] toml::de::Error),
}

/// Top-level configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    #[serde(default = "default_scan")]
    pub scan: ScanConfig,
    #[serde(default)]
    pub display: DisplayConfig,
    #[serde(default)]
    pub groups: GroupConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanConfig {
    #[serde(default = "default_roots")]
    pub roots: Vec<String>,
    #[serde(default = "default_exclude_dirs")]
    pub exclude_dirs: Vec<String>,
    #[serde(default = "default_exclude_globs")]
    pub exclude_globs: Vec<String>,
    #[serde(default = "default_max_file_size_mb")]
    pub max_file_size_mb: u64,
    #[serde(default)]
    pub follow_symlinks: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[derive(Default)]
pub struct DisplayConfig {
    #[serde(default)]
    pub show_prefix: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupConfig {
    #[serde(default = "default_auto_prune_after_scans")]
    pub auto_prune_after_scans: u32,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            scan: default_scan(),
            display: DisplayConfig::default(),
            groups: GroupConfig::default(),
        }
    }
}


impl Default for GroupConfig {
    fn default() -> Self {
        Self {
            auto_prune_after_scans: default_auto_prune_after_scans(),
        }
    }
}

fn default_scan() -> ScanConfig {
    ScanConfig {
        roots: default_roots(),
        exclude_dirs: default_exclude_dirs(),
        exclude_globs: default_exclude_globs(),
        max_file_size_mb: default_max_file_size_mb(),
        follow_symlinks: false,
    }
}

fn default_roots() -> Vec<String> {
    vec![
        "~/.config".into(),
        "~/.env".into(),
        "~/.zshrc".into(),
        "~/.bashrc".into(),
        "~/.bash_profile".into(),
        "~/.profile".into(),
        "~/.ssh".into(),
        "~/.aws".into(),
        "~/.docker".into(),
        "~/.openclaw".into(),
        "~/.hagrid".into(),
        "~/projects".into(),
    ]
}

fn default_exclude_dirs() -> Vec<String> {
    vec![
        "node_modules".into(),
        ".git/objects".into(),
        "target".into(),
        "__pycache__".into(),
        "venv".into(),
        ".venv".into(),
        "dist".into(),
        "build".into(),
        "vendor".into(),
    ]
}

fn default_exclude_globs() -> Vec<String> {
    vec![
        "*.pyc".into(),
        "*.wasm".into(),
        "*.so".into(),
        "*.dylib".into(),
        "*.png".into(),
        "*.jpg".into(),
        "*.mp4".into(),
    ]
}

fn default_max_file_size_mb() -> u64 {
    10
}

fn default_auto_prune_after_scans() -> u32 {
    3
}

/// Check if a path is hard-excluded (Hagrid's own data files).
/// Enforced after path canonicalization per spec.
pub fn is_hard_excluded(path: &Path) -> bool {
    // Canonicalize the path; fall back to the original if canonicalization fails
    let canonical = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
    let path_str = canonical.to_string_lossy();

    // Resolve the actual hagrid directory
    let hagrid = hagrid_dir();
    let hagrid_canonical = hagrid
        .canonicalize()
        .unwrap_or_else(|_| hagrid.clone());
    let hagrid_str = hagrid_canonical.to_string_lossy();

    // Only apply hard-exclusion rules to paths inside ~/.hagrid/
    if !path_str.starts_with(hagrid_str.as_ref()) {
        return false;
    }

    // Relative path within ~/.hagrid/
    let relative = &path_str[hagrid_str.len()..];
    // Strip leading separator
    let relative = relative.strip_prefix('/').unwrap_or(relative);

    // Hard-excluded patterns (relative to ~/.hagrid/):
    // - hagrid.db (the encrypted database)
    // - logs/* (log directory)
    // - *.tmp (temporary files)
    // - *.bak (backup files)
    if relative == "hagrid.db" {
        return true;
    }
    if relative.starts_with("logs/") || relative == "logs" {
        return true;
    }
    if relative.ends_with(".tmp") {
        return true;
    }
    if relative.ends_with(".bak") {
        return true;
    }

    false
}

/// Expand ~ to home directory in a path string.
pub fn expand_tilde(path: &str) -> PathBuf {
    if let Some(rest) = path.strip_prefix("~/") {
        if let Some(home) = dirs::home_dir() {
            return home.join(rest);
        }
    } else if path == "~" {
        if let Some(home) = dirs::home_dir() {
            return home;
        }
    }
    PathBuf::from(path)
}

/// Get the hagrid data directory (~/.hagrid/).
pub fn hagrid_dir() -> PathBuf {
    dirs::home_dir()
        .expect("could not determine home directory")
        .join(".hagrid")
}

/// Get the database path.
pub fn db_path() -> PathBuf {
    hagrid_dir().join("hagrid.db")
}

/// Get the config file path.
pub fn config_path() -> PathBuf {
    hagrid_dir().join("config.toml")
}

/// Get the patterns file path.
pub fn patterns_path() -> PathBuf {
    hagrid_dir().join("patterns.toml")
}

/// Get the policies file path.
pub fn policies_path() -> PathBuf {
    hagrid_dir().join("policies.toml")
}

/// Get the notifications config file path.
pub fn notifications_path() -> PathBuf {
    hagrid_dir().join("notifications.toml")
}

/// Load config from disk, falling back to defaults.
pub fn load_config() -> Result<Config, ConfigError> {
    let path = config_path();
    if path.exists() {
        let content = std::fs::read_to_string(&path)?;
        let config: Config = toml::from_str(&content)?;
        Ok(config)
    } else {
        Ok(Config::default())
    }
}

/// Write default config to disk.
pub fn write_default_config() -> Result<(), ConfigError> {
    let config = Config::default();
    let content = toml::to_string_pretty(&config).expect("config serialization should not fail");
    std::fs::write(config_path(), content)?;
    Ok(())
}
