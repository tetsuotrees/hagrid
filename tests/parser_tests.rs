use hagrid::index::models::LocationKind;
use hagrid::scan::parsers;

#[test]
fn test_json_parser_extracts_all_strings() {
    let content = r#"{
        "level1": "value1",
        "nested": {
            "level2": "value2",
            "deep": {
                "level3": "value3"
            }
        },
        "array": ["item1", "item2"],
        "number": 42,
        "bool": true,
        "null_val": null
    }"#;

    let results = parsers::json::parse(content);

    // Should extract 5 strings (not numbers, bools, or nulls)
    assert_eq!(results.len(), 5);

    let paths: Vec<&str> = results.iter().map(|r| r.key_path.as_str()).collect();
    assert!(paths.contains(&"/level1"));
    assert!(paths.contains(&"/nested/level2"));
    assert!(paths.contains(&"/nested/deep/level3"));
    assert!(paths.contains(&"/array/0"));
    assert!(paths.contains(&"/array/1"));

    // All should have JsonPath location kind
    for r in &results {
        assert_eq!(r.location.kind, LocationKind::JsonPath);
    }
}

#[test]
fn test_toml_parser_extracts_all_strings() {
    let content = r#"
name = "my-app"

[api]
key = "secret123"

[database]
host = "localhost"
port = 5432
"#;

    let results = parsers::toml_parser::parse(content);

    // Should extract strings only (not integers)
    let paths: Vec<&str> = results.iter().map(|r| r.key_path.as_str()).collect();
    assert!(paths.contains(&"name"));
    assert!(paths.contains(&"api.key"));
    assert!(paths.contains(&"database.host"));
    // port = 5432 is an integer, should not be extracted
    assert!(!paths.iter().any(|p| p.contains("port")));
}

#[test]
fn test_dotenv_parser_handles_edge_cases() {
    let content = r#"
# Comment line
KEY1=value1
KEY2="quoted value"
KEY3='single quoted'
KEY4=
KEY5=value with spaces
EMPTY_QUOTED=""

# Another comment
KEY6=value#not-a-comment
"#;

    let results = parsers::dotenv::parse(content);

    let kv: std::collections::HashMap<&str, &str> = results
        .iter()
        .map(|r| (r.key_path.as_str(), r.value.as_str()))
        .collect();

    assert_eq!(kv.get("KEY1"), Some(&"value1"));
    assert_eq!(kv.get("KEY2"), Some(&"quoted value"));
    assert_eq!(kv.get("KEY3"), Some(&"single quoted"));
    // KEY4 is empty, should be skipped
    assert!(!kv.contains_key("KEY4"));
    assert!(kv.contains_key("KEY5"));
}

#[test]
fn test_shell_parser_handles_export() {
    let content = r#"
export VAR1="value1"
export VAR2='value2'
VAR3=value3
export PATH="/usr/bin:$PATH"
"#;

    let results = parsers::shell::parse(content);
    assert_eq!(results.len(), 4);

    for r in &results {
        assert_eq!(r.location.kind, LocationKind::ShellExport);
        assert!(r.location.line_number.is_some());
    }
}

#[test]
fn test_file_dispatch_by_extension() {
    // .env files
    let env_results = parsers::parse_file("test.env", "KEY=value\n");
    assert!(!env_results.is_empty());

    // .json files
    let json_results = parsers::parse_file("config.json", r#"{"key": "value"}"#);
    assert!(!json_results.is_empty());

    // .toml files
    let toml_results = parsers::parse_file("config.toml", "key = \"value\"\n");
    assert!(!toml_results.is_empty());

    // Shell rc files
    let shell_results = parsers::parse_file("/home/user/.bashrc", "export KEY=value\n");
    assert!(!shell_results.is_empty());
}
