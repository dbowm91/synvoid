//! SynVoid core types and shared abstractions.
//!
//! This crate provides dependency-light shared types that are used across
//! multiple SynVoid subsystems. It intentionally avoids heavy dependencies
//! like tokio, hyper, axum, rustls, openraft, wasmtime, yara-x, rusqlite, quinn.

pub mod drain;
pub mod error;
pub mod ids;
pub mod metrics;
pub mod request;
pub mod routing;
pub mod time;
pub mod url;
pub mod verdict;
