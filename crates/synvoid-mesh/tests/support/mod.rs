//! Shared support code for the mesh integration test binaries.
//!
//! Each binary that needs a two-node world declares `mod support;` so the
//! identity and PKI setup exists exactly once.

pub mod fixture;
