pub mod dotenv;
pub mod json;
pub mod shell;
pub mod toml_parser;

use crate::index::models::Location;

/// A key-value pair extracted from a structured file.
#[derive(Debug, Clone)]
pub struct ExtractedKV {
    pub key_path: String,
    pub value: String,
    pub location: Location,
}

/// Determine which parser to use based on file extension/name.
pub fn parse_file(path: &str, content: &str) -> Vec<ExtractedKV> {
    let lower = path.to_lowercase();

    if lower.ends_with(".json") {
        json::parse(content)
    } else if lower.ends_with(".toml") {
        toml_parser::parse(content)
    } else if lower.ends_with(".env")
        || lower.contains(".env.")
        || lower.ends_with("/.env")
    {
        dotenv::parse(content)
    } else if lower.ends_with(".zshrc")
        || lower.ends_with(".bashrc")
        || lower.ends_with(".bash_profile")
        || lower.ends_with(".profile")
        || lower.ends_with(".zprofile")
        || lower.ends_with(".zshenv")
    {
        shell::parse(content)
    } else {
        // Try dotenv format as fallback for unknown files
        let results = dotenv::parse(content);
        if !results.is_empty() {
            return results;
        }
        // No structural parsing — will rely on pattern matching
        Vec::new()
    }
}
