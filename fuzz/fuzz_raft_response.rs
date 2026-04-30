#![no_main]

//! Fuzz target for RaftResponse message decoding.
//!
//! Tests protobuf decoding of MeshMessage::Raft variants from arbitrary
//! byte input, verifying that malformed messages are rejected without
//! panicking.

use libfuzzer_sys::fuzz_target;
use maluwaf::mesh::protocol::MeshMessage;

fuzz_target!(|data: &[u8]| {
    let _ = MeshMessage::decode(data);
});
