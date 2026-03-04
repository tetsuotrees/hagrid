use regex::Regex;
use serde::Deserialize;
use std::path::Path;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum PatternError {
    #[error("failed to read patterns file: {0}")]
    ReadError(#[from] std::io::Error),
    #[error("failed to parse patterns file: {0}")]
    ParseError(#[from] toml::de::Error),
    #[error("invalid regex in pattern '{name}': {source}")]
    InvalidRegex {
        name: String,
        source: regex::Error,
    },
}

/// A pattern definition from TOML.
#[derive(Debug, Clone, Deserialize)]
pub struct PatternDef {
    pub name: String,
    pub provider: String,
    pub display: String,
    pub regex: String,
    pub entropy_min: Option<f64>,
    pub context_regex: Option<String>,
}

/// A compiled pattern ready for matching.
#[derive(Debug, Clone)]
pub struct CompiledPattern {
    pub name: String,
    pub provider: String,
    pub display: String,
    pub regex: Regex,
    pub entropy_min: Option<f64>,
    pub context_regex: Option<Regex>,
}

/// Collection of patterns from a TOML file.
#[derive(Debug, Deserialize)]
struct PatternFile {
    pattern: Vec<PatternDef>,
}

/// A match found by a pattern.
#[derive(Debug, Clone)]
pub struct PatternMatch {
    pub pattern_name: String,
    pub provider: String,
    pub display: String,
    pub matched_value: String,
    pub line_number: u32,
    pub start_offset: usize,
    pub end_offset: usize,
}

/// Load and compile the default embedded patterns.
pub fn load_default_patterns() -> Result<Vec<CompiledPattern>, PatternError> {
    let default_toml = include_str!("../../patterns/default.toml");
    compile_patterns_from_toml(default_toml)
}

/// Load and compile user patterns from a file, merged with defaults.
pub fn load_patterns(user_patterns_path: Option<&Path>) -> Result<Vec<CompiledPattern>, PatternError> {
    let mut patterns = load_default_patterns()?;

    if let Some(path) = user_patterns_path {
        if path.exists() {
            let content = std::fs::read_to_string(path)?;
            let user_patterns = compile_patterns_from_toml(&content)?;
            // User patterns override defaults with the same name
            for up in user_patterns {
                if let Some(pos) = patterns.iter().position(|p| p.name == up.name) {
                    patterns[pos] = up;
                } else {
                    patterns.push(up);
                }
            }
        }
    }

    Ok(patterns)
}

fn compile_patterns_from_toml(toml_str: &str) -> Result<Vec<CompiledPattern>, PatternError> {
    let file: PatternFile = toml::from_str(toml_str)?;
    let mut compiled = Vec::new();

    for def in file.pattern {
        let regex = Regex::new(&def.regex).map_err(|e| PatternError::InvalidRegex {
            name: def.name.clone(),
            source: e,
        })?;

        let context_regex = match &def.context_regex {
            Some(cr) => Some(Regex::new(cr).map_err(|e| PatternError::InvalidRegex {
                name: format!("{}.context", def.name),
                source: e,
            })?),
            None => None,
        };

        compiled.push(CompiledPattern {
            name: def.name,
            provider: def.provider,
            display: def.display,
            regex,
            entropy_min: def.entropy_min,
            context_regex,
        });
    }

    Ok(compiled)
}

/// Scan a line of text against all patterns. Returns all matches.
pub fn scan_line(
    patterns: &[CompiledPattern],
    line: &str,
    line_number: u32,
    full_content: Option<&str>,
) -> Vec<PatternMatch> {
    let mut matches = Vec::new();

    for pattern in patterns {
        // If pattern has a context_regex, check if the context matches
        // either on this line or in the full content
        if let Some(ref ctx) = pattern.context_regex {
            let context_matches = ctx.is_match(line)
                || full_content.is_some_and(|c| ctx.is_match(c));
            if !context_matches {
                continue;
            }
        }

        for m in pattern.regex.find_iter(line) {
            let value = m.as_str().to_string();

            // Check entropy minimum if specified
            if let Some(min_entropy) = pattern.entropy_min {
                if crate::scan::entropy::shannon_entropy(&value) < min_entropy {
                    continue;
                }
            }

            matches.push(PatternMatch {
                pattern_name: pattern.name.clone(),
                provider: pattern.provider.clone(),
                display: pattern.display.clone(),
                matched_value: value,
                line_number,
                start_offset: m.start(),
                end_offset: m.end(),
            });
        }
    }

    matches
}
