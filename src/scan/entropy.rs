use std::collections::HashMap;

const DEFAULT_ENTROPY_THRESHOLD: f64 = 4.5;
const MIN_STRING_LENGTH: usize = 16;

/// Compute Shannon entropy of a string in bits per character.
pub fn shannon_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }

    let mut freq: HashMap<char, usize> = HashMap::new();
    let len = s.len() as f64;

    for c in s.chars() {
        *freq.entry(c).or_insert(0) += 1;
    }

    let mut entropy = 0.0;
    for &count in freq.values() {
        let p = count as f64 / len;
        if p > 0.0 {
            entropy -= p * p.log2();
        }
    }

    entropy
}

/// Check if a string looks like a high-entropy secret.
pub fn is_high_entropy(s: &str, threshold: Option<f64>) -> bool {
    let threshold = threshold.unwrap_or(DEFAULT_ENTROPY_THRESHOLD);

    if s.len() < MIN_STRING_LENGTH {
        return false;
    }

    // Skip known non-secret high-entropy strings
    if is_known_non_secret(s) {
        return false;
    }

    shannon_entropy(s) >= threshold
}

/// Heuristic: skip strings that look like non-secrets despite high entropy.
fn is_known_non_secret(s: &str) -> bool {
    // UUIDs: 8-4-4-4-12 hex pattern
    if s.len() == 36 && s.chars().filter(|&c| c == '-').count() == 4 {
        let parts: Vec<&str> = s.split('-').collect();
        if parts.len() == 5
            && parts[0].len() == 8
            && parts[1].len() == 4
            && parts[2].len() == 4
            && parts[3].len() == 4
            && parts[4].len() == 12
            && parts.iter().all(|p| p.chars().all(|c| c.is_ascii_hexdigit()))
        {
            return true;
        }
    }

    // Common hashes in lock files (sha256, sha512 hex)
    if (s.len() == 64 || s.len() == 128) && s.chars().all(|c| c.is_ascii_hexdigit()) {
        // Could be a hash — we'll still catch these via context_regex patterns
        // but skip them in raw entropy scanning
        return false; // Actually, let pattern matching handle these
    }

    // Base64 image data (starts with common image MIME type indicators)
    if s.starts_with("iVBOR") || s.starts_with("/9j/") || s.starts_with("R0lGOD") {
        return true;
    }

    // Very long strings (>500 chars) are likely encoded data, not secrets
    if s.len() > 500 {
        return true;
    }

    false
}

/// Extract high-entropy strings from a line.
/// Returns (value, start_offset, end_offset) tuples.
pub fn find_high_entropy_strings(
    line: &str,
    threshold: Option<f64>,
) -> Vec<(String, usize, usize)> {
    let mut results = Vec::new();

    // Split on whitespace and common delimiters to find token-like strings
    let delimiters = &[' ', '\t', '"', '\'', '=', ':', ',', ';', '(', ')', '{', '}', '[', ']'];

    let mut start = 0;
    for (i, c) in line.char_indices() {
        if delimiters.contains(&c) || i == line.len() - 1 {
            let end = if delimiters.contains(&c) { i } else { i + 1 };
            if end > start {
                let token = &line[start..end];
                if is_high_entropy(token, threshold) {
                    results.push((token.to_string(), start, end));
                }
            }
            start = i + 1;
        }
    }

    results
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_entropy_low_for_simple_strings() {
        assert!(shannon_entropy("aaaaaaaaaa") < 1.0);
        assert!(shannon_entropy("abababababab") < 2.0);
    }

    #[test]
    fn test_entropy_high_for_random_strings() {
        // Typical API key-like string
        assert!(shannon_entropy("sk-proj-a8Bf2kL9mNpQrStUvWxYz012345678901234567890") > 4.0);
    }

    #[test]
    fn test_skip_short_strings() {
        assert!(!is_high_entropy("abc", None));
        assert!(!is_high_entropy("short", None));
    }

    #[test]
    fn test_skip_uuid() {
        assert!(is_known_non_secret("550e8400-e29b-41d4-a716-446655440000"));
    }

    #[test]
    fn test_skip_base64_image() {
        assert!(is_known_non_secret("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAA"));
    }
}
