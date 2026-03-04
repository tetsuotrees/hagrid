use crate::index::models::{Location, LocationKind};
use crate::scan::parsers::ExtractedKV;
use serde_json::Value;

/// Parse JSON content and extract all string values with their JSON pointer paths.
pub fn parse(content: &str) -> Vec<ExtractedKV> {
    let Ok(value) = serde_json::from_str::<Value>(content) else {
        return Vec::new();
    };

    let mut results = Vec::new();
    walk_value(&value, "", content, &mut results);
    results
}

fn walk_value(value: &Value, pointer: &str, original: &str, results: &mut Vec<ExtractedKV>) {
    match value {
        Value::String(s) => {
            if !s.is_empty() {
                let line_number = find_line_for_pointer(original, pointer, s);
                results.push(ExtractedKV {
                    key_path: pointer.to_string(),
                    value: s.clone(),
                    location: Location {
                        kind: LocationKind::JsonPath,
                        discriminator: pointer.to_string(),
                        line_number,
                    },
                });
            }
        }
        Value::Object(map) => {
            for (key, val) in map {
                let new_pointer = format!("{}/{}", pointer, escape_json_pointer(key));
                walk_value(val, &new_pointer, original, results);
            }
        }
        Value::Array(arr) => {
            for (i, val) in arr.iter().enumerate() {
                let new_pointer = format!("{}/{}", pointer, i);
                walk_value(val, &new_pointer, original, results);
            }
        }
        _ => {}
    }
}

/// Escape special characters in JSON pointer segment per RFC 6901.
fn escape_json_pointer(segment: &str) -> String {
    segment.replace('~', "~0").replace('/', "~1")
}

/// Try to find the line number for a value in the original JSON text.
fn find_line_for_pointer(original: &str, _pointer: &str, value: &str) -> Option<u32> {
    // Simple heuristic: find the string value in the original text
    // This won't be perfect for duplicated values but is good enough for display
    if let Some(pos) = original.find(&format!("\"{}\"", value.replace('"', "\\\""))) {
        let line = original[..pos].matches('\n').count() as u32 + 1;
        return Some(line);
    }
    // Fallback: search for the raw value
    if let Some(pos) = original.find(value) {
        let line = original[..pos].matches('\n').count() as u32 + 1;
        return Some(line);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_json() {
        let content = r#"{
            "api_key": "sk-proj-abc123456789012345678901234567890123456789",
            "nested": {
                "token": "ghp_abcdefghij1234567890abcdefghij123456"
            }
        }"#;

        let results = parse(content);
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].key_path, "/api_key");
        assert_eq!(results[1].key_path, "/nested/token");
    }

    #[test]
    fn test_parse_array_json() {
        let content = r#"{"keys": ["key1", "key2"]}"#;
        let results = parse(content);
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].key_path, "/keys/0");
        assert_eq!(results[1].key_path, "/keys/1");
    }

    #[test]
    fn test_parse_invalid_json() {
        let results = parse("not json at all");
        assert!(results.is_empty());
    }
}
