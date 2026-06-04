//! SynVoid tarpit Markov chain generator and configuration.
//!
//! This crate provides the pure Markov chain text generation logic
//! and tarpit configuration types, independent of HTTP handling.

pub mod config;
pub mod generator;

pub use config::TarpitConfig;
pub use generator::MarkovChain;
