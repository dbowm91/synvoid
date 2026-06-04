//! SynVoid WAF engine - attack detection, normalization, and pattern matching.
//!
//! This crate provides the core WAF attack detection logic independent of
//! HTTP server, supervisor, worker, mesh, DNS, and admin subsystems.

pub mod attack_detection;
pub mod bot;
pub mod request_sanitization;
