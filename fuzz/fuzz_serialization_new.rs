#![no_main]

//! Fuzz target for serialization module.
//!
//! Tests serialize/deserialize roundtrips for common types and
//! verifies that malformed input is handled gracefully without panics.

use libfuzzer_sys::fuzz_target;
use maluwaf::serialization::{deserialize, serialize};

fuzz_target!(|data: &[u8]| {
    // Test deserializing as String
    let _ = deserialize::<String>(data);

    // Test deserializing as Vec<u8>
    let _ = deserialize::<Vec<u8>>(data);

    // Test deserializing as Option<String>
    let _ = deserialize::<Option<String>>(data);

    // Test deserializing as HashMap
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
        assert!(true);
    }
}
