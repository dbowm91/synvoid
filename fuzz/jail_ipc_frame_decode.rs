#![no_main]

//! Fuzz target for the sandbox jail IPC frame decoder.
//!
//! Feeds arbitrary bytes through the length-delimited frame reader and the
//! request/response envelope validators (`synvoid_ipc::jail_protocol`).
//! Verifies malformed frames yield typed errors (never panic, never
//! unbounded allocation: the length prefix is validated against
//! `JAIL_MAX_FRAME_BYTES` before any payload allocation). Strict bounds:
//! inputs over 64 KiB skipped. No child processes spawned, no network, no
//! filesystem mutation.

use libfuzzer_sys::fuzz_target;
use synvoid_ipc::jail_protocol::{
    decode_request, decode_response, read_frame, JAIL_MAX_FRAME_BYTES,
};

fuzz_target!(|data: &[u8]| {
    if data.is_empty() || data.len() > 65536 {
        return;
    }
    // Full-frame read path (length prefix + payload).
    let mut cursor = std::io::Cursor::new(data);
    match read_frame(&mut cursor, JAIL_MAX_FRAME_BYTES) {
        Ok(synvoid_ipc::jail_protocol::FrameRead::Frame(payload)) => {
            let _ = decode_request(&payload);
            let _ = decode_response(&payload);
        }
        Ok(synvoid_ipc::jail_protocol::FrameRead::CleanEof) => {}
        Err(_) => {}
    }
    // Raw-payload decode path (frame already delimited upstream).
    let payload = if data.len() > 4 { &data[4..] } else { data };
    let _ = decode_request(payload);
    let _ = decode_response(payload);
    // Truncation path: every prefix length must also be total.
    if data.len() > 8 {
        let half = &data[..data.len() / 2];
        let mut cursor = std::io::Cursor::new(half);
        let _ = read_frame(&mut cursor, JAIL_MAX_FRAME_BYTES);
    }
});

#[cfg(test)]
mod tests {
    #[test]
    fn test_fuzz_target_compiles() {}
}
