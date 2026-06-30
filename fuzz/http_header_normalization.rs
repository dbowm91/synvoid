#![no_main]

use libfuzzer_sys::fuzz_target;
use synvoid_waf::attack_detection::normalizer::InputNormalizer;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let normalizer = InputNormalizer::new();
        let _ = normalizer.normalize(s);
    }
});

#[cfg(test)]
mod tests {
    #[test]
    fn test_fuzz_target_compiles() {
        assert!(true);
    }
}
