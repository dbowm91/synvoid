#![no_main]

use libfuzzer_sys::fuzz_target;
use synvoid_core::block_store::BlocklistSnapshotChunk;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = serde_json::from_str::<BlocklistSnapshotChunk>(s);
    }
});

#[cfg(test)]
mod tests {
    #[test]
    fn test_fuzz_target_compiles() {
        assert!(true);
    }
}
