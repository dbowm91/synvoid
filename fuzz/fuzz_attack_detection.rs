#![no_main]

use http::Method;
use libfuzzer_sys::fuzz_target;
use maluwaf::waf::attack_detection::{AttackDetectionConfig, AttackDetector};

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
