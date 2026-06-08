#![no_main]

//! Fuzz target for WAF attack detection.
//!
//! Constructs synthetic HTTP requests from fuzzed byte data (method,
//! path, query) and passes them through [`AttackDetector::check_request`]
//! to verify that pattern matching does not panic on adversarial input.

use std::net::IpAddr;

use http::Method;
use libfuzzer_sys::fuzz_target;
use synvoid::waf::attack_detection::{AttackDetectionConfig, AttackDetector};

fuzz_target!(|data: &[u8]| {
    if data.len() < 3 {
        return;
    }

    let method = match data[0] % 4 {
        0 => Method::GET,
        1 => Method::POST,
        2 => Method::PUT,
        _ => Method::DELETE,
    };

    let path = String::from_utf8_lossy(&data[1..]).to_string();
    let query = if data.len() > 2 {
        Some(String::from_utf8_lossy(&data[2..]).to_string())
    } else {
        None
    };

    let config = AttackDetectionConfig::default();
    let detector = AttackDetector::new(config);

    let _ = detector.check_request(
        "127.0.0.1".parse::<IpAddr>().unwrap(),
        &method,
        &path,
        query.as_deref(),
        &http::HeaderMap::new(),
        None,
    );
});

#[cfg(test)]
mod tests {
    #[test]
    fn test_fuzz_target_compiles() {
        assert!(true);
    }
}
