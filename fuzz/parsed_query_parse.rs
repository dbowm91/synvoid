#![no_main]

//! Fuzz target for canonical DNS query parsing.
//!
//! Feeds arbitrary bytes to [`ParsedDnsQuery::parse`] to verify that the
//! canonical parser handles malformed, truncated, and adversarial
//! wire-format input without panicking.

use libfuzzer_sys::fuzz_target;
use synvoid::dns::parsed_query::ParsedDnsQuery;

fuzz_target!(|data: &[u8]| {
    let _ = ParsedDnsQuery::parse(data);
});
