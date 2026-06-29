#![no_main]

//! Fuzz target for DNS message decoding.
//!
//! Feeds arbitrary bytes to [`parse_dns_message`] to verify that the
//! hickory-proto based DNS parser handles malformed, truncated, and
//! adversarial wire-format input without panicking.

use libfuzzer_sys::fuzz_target;
use synvoid::dns::wire::parse_dns_message;

fuzz_target!(|data: &[u8]| {
    let _ = parse_dns_message(data);
});
