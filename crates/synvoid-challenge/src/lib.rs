//! SynVoid challenge types and pure challenge logic.
//!
//! This crate provides challenge type definitions, configuration structs,
//! and pure verification logic that doesn't depend on HTTP rendering.

pub mod css;
pub mod honeypot;
pub mod manager_pow;
pub mod pow;
pub mod types;

pub use types::{ChallengePriority, ChallengeResult, ChallengeType};
