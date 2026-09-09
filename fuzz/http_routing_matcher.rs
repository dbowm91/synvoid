#![no_main]

//! Fuzz target for request-target normalization + routing matcher.
//!
//! Feeds arbitrary bytes (as a URL path) through the canonical WAF
//! normalizer and a fixed routing table (`synvoid_proxy::location_matcher`).
//! Verifies adversarial paths never panic either consumer and that matching
//! on the normalized target is total. Strict bounds: non-UTF8 skipped,
//! inputs over 2 KiB skipped, fuzzed patterns capped at 128 chars. No
//! network access, no filesystem mutation.

use libfuzzer_sys::fuzz_target;
use synvoid_proxy::location_matcher::{LocationMatch, LocationMatcher};
use synvoid_waf::attack_detection::normalizer::InputNormalizer;

fn fixed_table() -> LocationMatcher {
    LocationMatcher::new(vec![
        "= /login".to_string(),
        "/admin".to_string(),
        "/api".to_string(),
        "~ \\.jpg$".to_string(),
    ])
}

fuzz_target!(|data: &[u8]| {
    if data.is_empty() || data.len() > 2048 {
        return;
    }
    let path = match std::str::from_utf8(data) {
        Ok(s) => s,
        Err(_) => return,
    };
    // Control characters would never arrive as a decoded target; skip rather
    // than testing transport decoding here (covered by framing targets).
    if path.chars().any(|c| c == '\0') {
        return;
    }
    let normalizer = InputNormalizer::new();
    let normalized = normalizer.normalize(path);
    let table = fixed_table();
    let _ = table.match_uri(path);
    let _ = table.match_uri(normalized.as_str());
    // Fuzzed route patterns must also be total (complexity-gated inside).
    if path.len() <= 128 {
        if let Some(rule) = LocationMatch::new(path.to_string(), 0) {
            let _ = rule.matches(path);
            let _ = rule.matches(normalized.as_str());
        }
    }
});

#[cfg(test)]
mod tests {
    #[test]
    fn test_fuzz_target_compiles() {}
}
