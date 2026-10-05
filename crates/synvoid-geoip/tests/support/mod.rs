//! Test-only support for the `synvoid-geoip` evidence suites.
//!
//! `mmdb` builds a real MaxMind database image in memory so the provider tests
//! can distinguish a covered address from an uncovered one. Nothing here is
//! part of the library surface.

pub mod mmdb;
