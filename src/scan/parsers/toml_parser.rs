use crate::index::models::{Location, LocationKind};
use crate::scan::parsers::ExtractedKV;
use toml::Value;

/// Parse TOML content and extract all string values with their dotted paths.
pub fn parse(content: &str) -> Vec<ExtractedKV> {
    let Ok(value) = content.parse::<Value>() else {
        return Vec::new();
    };

    let mut results = Vec::new();
    walk_value(&value, "", content, &mut results);
    results
}

fn walk_value(value: &Value, path: &str, original: &str, results: &mut Vec<ExtractedKV>) {
    match value {
        Value::String(s) => {
            if !s.is_empty() {
                let line_number = find_line_for_key(original, path, s);
                results.push(ExtractedKV {
                    key_path: path.to_string(),
                    value: s.clone(),
                    location: Location {
                        kind: LocationKind::TomlKey,
                        discriminator: path.to_string(),
                        line_number,
                    },
                });
            }
        }
        Value::Table(table) => {
            for (key, val) in table {
                let new_path = if path.is_empty() {
                    key.clone()
                } else {
                    format!("{}.{}", path, key)
                };
                walk_value(val, &new_path, original, results);
            }
        }
        Value::Array(arr) => {
            for (i, val) in arr.iter().enumerate() {
                let new_path = format!("{}[{}]", path, i);
                walk_value(val, &new_path, original, results);
            }
        }
        _ => {}
    }
}

fn find_line_for_key(original: &str, _path: &str, value: &str) -> Option<u32> {
    // Try to find the value in the original content
    let search = format!("\"{}\"", value);
    if let Some(pos) = original.find(&search) {
        return Some(original[..pos].matches('\n').count() as u32 + 1);
    }
    if let Some(pos) = original.find(value) {
        return Some(original[..pos].matches('\n').count() as u32 + 1);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_toml() {
        let content = r#"
api_key = "sk-proj-abc123"

[database]
password = "secret123"
"#;
        let results = parse(content);
        assert_eq!(results.len(), 2);
        // TOML sorts keys alphabetically
        let paths: Vec<&str> = results.iter().map(|r| r.key_path.as_str()).collect();
        assert!(paths.contains(&"api_key"));
        assert!(paths.contains(&"database.password"));
    }

    #[test]
    fn test_parse_invalid_toml() {
        let results = parse("not [valid toml");
        assert!(results.is_empty());
    }
}
