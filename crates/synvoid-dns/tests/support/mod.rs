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
//! | [`context`] | Test context setup (`setup`, `make_ctx`, `make_config`) |
//! | [`response`] | Response wire-format parsers (`response_rcode`, `skip_wire_name`, etc.) |
//! | [`runtime_config`] | DNS-owned runtime config fixtures (`AuthoritativeRuntimeBuilder`, `recursive_runtime`, `dns_runtime`, `start_bound_dns_server`) — Phases 126-128; `DnsServer::new` accepts no persistence DTO |
//!
//! # Design principles
//!
//! - **Explicit returns** — every function returns a value; no global state is mutated.
//! - **Defaults documented** — each helper's default parameters and override points are noted.
//! - **No production secrets** — all values are test-only (hardcoded IPs, test serials).
//! - **No predicted ports for listeners** (Phase 131) — a test that starts a
//!   listener uses `runtime_config::start_bound_dns_server`, which lets the
//!   server perform the real bind and retries on a lost race. The old
//!   `ephemeral_port` helpers were removed because they released the port
//!   before the bind, which is the TOCTOU race behind the intermittently red
//!   DNS conformance lane (Phase 130 F-3).
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
pub mod runtime_config;
pub mod zone;

// Re-export the most commonly used items at crate level for convenience.
// Not all re-exports are used by every test file — that's expected.
#[allow(unused_imports)]
pub use context::{make_config, make_ctx, setup};
#[allow(unused_imports)]
pub use query::{
    build_axfr_query, build_ixfr_query, build_notify_query, build_query, build_query_with_do_bit,
    build_rr, build_update_add_record, build_update_header, build_zone_question, encode_qname,
};
#[allow(unused_imports)]
pub use response::{
    is_authoritative, is_recursion_available, is_response, parse_answer_types, response_ancount,
    response_arcount, response_flags, response_nscount, response_rcode, skip_name, skip_wire_name,
};
#[allow(unused_imports)]
pub use runtime_config::{
    authoritative_runtime, circuit_breaker_runtime, disabled_doh, disabled_doq, disabled_dot,
    dns_runtime, dns_runtime_on, dnssec_enabled_runtime, dnssec_runtime, doh_on, doq_on, dot_on,
    recursive_cache_runtime, recursive_disabled, recursive_runtime, recursive_runtime_on,
    recursive_with_acl, recursive_with_upstreams, start_bound_dns_server, tsig_key, zone_spec,
    AuthoritativeRuntimeBuilder, BoundServer, UNBOUND_TEST_PORT,
};
#[allow(unused_imports)]
pub use zone::{build_test_zone, update_soa_value, zone_with_records, zone_with_soa};
