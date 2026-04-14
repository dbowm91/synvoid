//! Session management module
//!
//! Provides generic session management with support for different
//! KEM algorithms and automatic key rotation for forward secrecy.

pub mod manager;

pub use manager::{Session, SessionConfig, SessionError, SessionManager};
