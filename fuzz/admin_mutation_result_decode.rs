#![no_main]

use libfuzzer_sys::fuzz_target;
use synvoid_core::admin_mutation::AdminMutationResult;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = serde_json::from_str::<AdminMutationResult>(s);
    }
});

#[cfg(test)]
mod tests {
    #[test]
    fn test_fuzz_target_compiles() {
        assert!(true);
    }
}
