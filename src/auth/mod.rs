//! Compatibility facade for `synvoid-auth`.
//!
//! Canonical authentication/session/CSRF/lockout implementation lives in
//! the `synvoid-auth` crate. New code should import `synvoid_auth` directly;
//! this root path remains for transitional API compatibility.
//! See `architecture/root_module_ledger.md`.

pub use synvoid_auth::*;
