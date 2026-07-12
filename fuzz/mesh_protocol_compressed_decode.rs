#![no_main]

use libfuzzer_sys::fuzz_target;
use synvoid_mesh::mesh::MeshMessage;

fuzz_target!(|data: &[u8]| {
    let _ = MeshMessage::decode_compressed(data);
});

#[cfg(test)]
mod tests {
    #[test]
    fn test_fuzz_target_compiles() {
        // Fuzz target compile check; no-op assertion needed.
    }
}
