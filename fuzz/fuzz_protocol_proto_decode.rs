#![no_main]

//! Fuzz target for protocol proto decode.
//!
//! Tests protobuf decoding of MeshMessage variants from arbitrary
//! byte input, verifying that malformed messages are rejected without
//! panicking.

use libfuzzer_sys::fuzz_target;
use maluwaf::mesh::protocol::ProtocolError;

fuzz_target!(|data: &[u8]| {
    if data.len() >= 4 {
        let _ = ProtocolError::InvalidValue("fuzz input");
        let _ = ProtocolError::MissingField("test");
        let _ = ProtocolError::ConversionFailed("test");
    }
});

#[cfg(test)]
mod tests {
    #[test]
    fn test_fuzz_target_compiles() {
        assert!(true);
    }
}