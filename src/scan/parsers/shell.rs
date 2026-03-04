use crate::index::models::{Location, LocationKind};
use crate::scan::parsers::ExtractedKV;
use regex::Regex;

/// Parse shell rc files for `export KEY=VALUE` and `KEY=VALUE` patterns.
pub fn parse(content: &str) -> Vec<ExtractedKV> {
    let mut results = Vec::new();

    let export_re = Regex::new(r#"^\s*export\s+([A-Za-z_][A-Za-z0-9_]*)=(.+)"#).unwrap();
    let assign_re = Regex::new(r#"^\s*([A-Za-z_][A-Za-z0-9_]*)=(.+)"#).unwrap();

    for (i, line) in content.lines().enumerate() {
        let trimmed = line.trim();

        // Skip comments and empty lines
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        // Try export first, then plain assignment
        let captures = export_re
            .captures(trimmed)
            .or_else(|| assign_re.captures(trimmed));

        if let Some(caps) = captures {
            let key = caps.get(1).unwrap().as_str();
            let raw_value = caps.get(2).unwrap().as_str().trim();

            // Strip quotes and inline comments
            let value = strip_value(raw_value);

            if !value.is_empty() {
                results.push(ExtractedKV {
                    key_path: key.to_string(),
                    value: value.to_string(),
                    location: Location {
                        kind: LocationKind::ShellExport,
                        discriminator: key.to_string(),
                        line_number: Some(i as u32 + 1),
                    },
                });
            }
        }
    }

    results
}

/// Strip quotes and trailing inline comments from a shell value.
fn strip_value(s: &str) -> &str {
    let s = s.trim();

    // Strip surrounding quotes
    if ((s.starts_with('"') && s.ends_with('"')) || (s.starts_with('\'') && s.ends_with('\'')))
        && s.len() >= 2 {
            return &s[1..s.len() - 1];
        }

    // Strip inline comment (unquoted)
    if let Some(comment_pos) = s.find(" #") {
        return s[..comment_pos].trim();
    }

    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_export() {
        let content = r#"
# My config
export OPENAI_API_KEY="sk-proj-abc123456789"
export PATH="/usr/bin:$PATH"
GITHUB_TOKEN=ghp_abcdefghij1234567890abcdefghij123456
"#;
        let results = parse(content);
        assert_eq!(results.len(), 3);
        assert_eq!(results[0].key_path, "OPENAI_API_KEY");
        assert_eq!(results[0].value, "sk-proj-abc123456789");
        assert_eq!(results[2].key_path, "GITHUB_TOKEN");
    }

    #[test]
    fn test_strip_inline_comment() {
        let content = "API_KEY=abc123 # my key\n";
        let results = parse(content);
        assert_eq!(results[0].value, "abc123");
    }
}
