//! Shared test support infrastructure for synvoid-dns integration tests.
//!
//! This module provides common helpers extracted from duplicated test
//! fixture code across the `tests/` directory.  Import with:
//!
//! ```ignore
//! mod support;
//! use support::*;
//! ```
//!
//! # Module overview
//!
//! | Module | Contents |
//! |--------|----------|
//! | [`query`] | DNS wire-format query builders (standard, AXFR, IXFR, NOTIFY, UPDATE, EDNS DO-bit) |
//! | [`zone`] | Zone construction helpers (`build_test_zone`, `zone_with_soa`, `zone_with_records`) |
//! | [`context`] | Test context setup (`setup`, `make_ctx`, `ephemeral_port`, `make_config`) |
//! | [`response`] | Response wire-format parsers (`response_rcode`, `skip_wire_name`, etc.) |
//!
//! # Design principles
//!
//! - **Explicit returns** — every function returns a value; no global state is mutated.
//! - **Defaults documented** — each helper's default parameters and override points are noted.
//! - **No production secrets** — all values are test-only (hardcoded IPs, test serials).
//! - **Ephemeral ports** — use `context::ephemeral_port()` for listeners.
//!
//! # When to add new helpers
//!
//! A helper belongs here when:
//! 1. It appears in 2+ test files with near-identical code, **or**
//! 2. It is a building block that multiple future tests will need.
//!
//! If a helper is only used in a single test file, keep it local to
//! that file.  Extract here when the second usage appears.

pub mod context;
pub mod query;
pub mod response;
pub mod zone;

// Re-export the most commonly used items at crate level for convenience.
pub use context::{ephemeral_port, make_config, make_ctx, setup};
pub use query::{
    build_axfr_query, build_ixfr_query, build_notify_query, build_query, build_query_with_do_bit,
    build_rr, build_update_add_record, build_update_header, build_zone_question, encode_qname,
};
pub use response::{
    is_authoritative, is_recursion_available, is_response, parse_answer_types, response_ancount,
    response_arcount, response_flags, response_nscount, response_rcode, skip_name, skip_wire_name,
};
pub use zone::{build_test_zone, update_soa_value, zone_with_records, zone_with_soa};
