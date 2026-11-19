#![no_main]

//! Fuzz target for the TSIG RR parser.
//!
//! The audit (D12) found `parse_tsig_from_query` did not follow the RR layout,
//! skipped CLASS but not TTL/RDLENGTH, and could read `query[pos]` with
//! `pos == len`. The function is reachable before any ACL check on AXFR/IXFR,
//! so a panic here is a pre-authentication remote panic once transfers are
//! enabled. This target runs it at several `qd_end` values, including one
//! taken from the input itself.

use libfuzzer_sys::fuzz_target;
use synvoid::dns::tsig::parse_tsig_from_query;

fuzz_target!(|data: &[u8]| {
    let split = data.last().map(|byte| *byte as usize).unwrap_or(0);
    for qd_end in [0, 12, split.min(data.len()), data.len()] {
        let _ = parse_tsig_from_query(data, qd_end);
    }
});
