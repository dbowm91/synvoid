//! # synvoid-testkit
//!
//! Shared test utilities for cross-crate use in the SynVoid workspace.
//!
//! ## Purpose
//!
//! This crate provides lightweight test helpers that are consumed by **two or
//! more** workspace crates, avoiding duplication of boilerplate across test
//! suites. It deliberately depends only on `synvoid-core` and `synvoid-config`
//! so that pulling it into a test harness does not drag in the full server
//! dependency tree.
//!
//! ## What belongs here
//!
//! - Generic ephemeral TCP/UDP server fixtures (not domain-specific).
//! - Temporary certificate/key material shared across TLS-related crates.
//! - Test tracing/logging initialization.
//! - Generic temporary-directory lifecycle helpers.
//! - Deterministic test clocks or readiness primitives.
//! - Shared process-cleanup wrappers.
//! - Small assertion macros used in multiple crates.
//!
//! ## What does **not** belong here
//!
//! - DNS query builders → `synvoid-dns` tests.
//! - Mesh routing fixtures → `synvoid-mesh` tests.
//! - WAF corpora or rule fixtures → `synvoid-waf` tests.
//! - IPC-specific endpoints → `synvoid-ipc` tests.
//! - Anything that depends on more than `synvoid-core` or `synvoid-config`.
//!
//! ## Current status
//!
//! As of Milestone E, this crate has **no active consumers** across the
//! workspace. The helpers below are retained for potential future use but
//! should be removed if no consumer materialises. Any new addition must
//! demonstrate cross-crate value and include both unit tests and API-level
//! doc comments.
//!
//! See `README.md` for the full boundary policy.

pub mod assertions;
pub mod config_fixtures;
pub mod request_fixtures;
