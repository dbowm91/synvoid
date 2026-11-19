#![no_main]

//! Fuzz target for EDNS option parsing.
//!
//! The audit (D3/D15/D16) found the option loop bounded by an attacker-declared
//! RDLENGTH and an entry guard one byte short of the OPT fixed header. This
//! target drives both the canonical query parse (which derives the OPT offset
//! from the header counts) and the EDNS walkers directly at offsets that need
//! not be real question boundaries, so a bounds regression is a crash rather
//! than a corpus mutation that happens to be well-framed.

use libfuzzer_sys::fuzz_target;
use synvoid::dns::edns::{additional_section_start, parse_query_edns};
use synvoid::dns::parsed_query::ParsedDnsQuery;

fuzz_target!(|data: &[u8]| {
    // Full path: header counts decide where the OPT record is.
    let _ = ParsedDnsQuery::parse(data);

    // Parser-level path: every offset is hostile, including past the end.
    for start in [0usize, 12, data.len() / 2, data.len()] {
        let _ = additional_section_start(data, start, 1, 1);
        let _ = parse_query_edns(data, start, u16::MAX);
        let _ = parse_query_edns(data, start, 1);
    }
});
