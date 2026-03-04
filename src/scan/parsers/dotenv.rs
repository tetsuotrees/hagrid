use crate::index::models::{Location, LocationKind};
use crate::scan::parsers::ExtractedKV;

/// Parse .env file content (KEY=VALUE lines, # comments).
pub fn parse(content: &str) -> Vec<ExtractedKV> {
    let mut results = Vec::new();

    for (i, line) in content.lines().enumerate() {
        let trimmed = line.trim();

        // Skip empty lines and comments
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        // Find the first = sign
        if let Some(eq_pos) = trimmed.find('=') {
            let key = trimmed[..eq_pos].trim();
            let value = trimmed[eq_pos + 1..].trim();

            // Skip if key is empty
            if key.is_empty() {
                continue;
            }

            // Strip surrounding quotes from value
            let value = strip_quotes(value);

            if !value.is_empty() {
                results.push(ExtractedKV {
                    key_path: key.to_string(),
                    value: value.to_string(),
                    location: Location {
                        kind: LocationKind::EnvVar,
                        discriminator: key.to_string(),
                        line_number: Some(i as u32 + 1),
                    },
                });
            }
        }
    }

    results
}

/// Strip surrounding single or double quotes from a value.
fn strip_quotes(s: &str) -> &str {
    if ((s.starts_with('"') && s.ends_with('"')) || (s.starts_with('\'') && s.ends_with('\'')))
        && s.len() >= 2 {
            return &s[1..s.len() - 1];
        }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_dotenv() {
        let content = r#"# Comment
OPENAI_API_KEY=sk-proj-abc123456789
DATABASE_URL="postgres://user:pass@localhost/db"
EMPTY=
"#;
        let results = parse(content);
        assert_eq!(results.len(), 2); // EMPTY is skipped
        assert_eq!(results[0].key_path, "OPENAI_API_KEY");
        assert_eq!(results[0].value, "sk-proj-abc123456789");
        assert_eq!(results[1].key_path, "DATABASE_URL");
        assert_eq!(results[1].value, "postgres://user:pass@localhost/db");
    }

    #[test]
    fn test_parse_single_quotes() {
        let content = "KEY='value123'\n";
        let results = parse(content);
        assert_eq!(results[0].value, "value123");
    }
}
