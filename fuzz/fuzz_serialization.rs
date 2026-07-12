#![no_main]

//! Fuzz target for serialization roundtrips.
//!
//! Feeds arbitrary byte slices into postcard deserialization for common
//! types (String, Vec\<u8\>, HashMap, integers) and verifies that
//! serialize/deserialize roundtrips do not panic on malformed input.

use libfuzzer_sys::fuzz_target;
use synvoid::serialization::{deserialize, serialize};

fuzz_target!(|data: &[u8]| {
    // Test postcard deserialization with various message types
    // These should all handle malformed input gracefully

    // Test deserializing as String
    let _ = deserialize::<String>(data);

    // Test deserializing as Vec<u8>
    let _ = deserialize::<Vec<u8>>(data);

    // Test deserializing as Option<String>
    let _ = deserialize::<Option<String>>(data);

    // Test deserializing as std::collections::HashMap<String, String>
    let _ = deserialize::<std::collections::HashMap<String, String>>(data);

    // Test deserializing as u64
    let _ = deserialize::<u64>(data);

    // Test deserializing as i64
    let _ = deserialize::<i64>(data);

    // Test roundtrip with valid data
    if let Ok(original) = deserialize::<String>(data) {
        if let Ok(serialized) = serialize(&original) {
            let _ = deserialize::<String>(&serialized);
        }
    }

    // Test with Vec<u8> roundtrip
    if let Ok(original) = deserialize::<Vec<u8>>(data) {
        if let Ok(serialized) = serialize(&original) {
            let _ = deserialize::<Vec<u8>>(&serialized);
        }
    }
});

#[cfg(test)]
mod tests {
    #[test]
    fn test_fuzz_target_compiles() {
        // Fuzz target compile check; no-op assertion needed.
    }
}
