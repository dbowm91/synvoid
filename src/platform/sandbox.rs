//! Compatibility facade for `synvoid-platform` sandbox backends.
//!
//! Canonical owner (Phase 29): `synvoid-platform::sandbox` — Landlock
//! (Linux), Capsicum (FreeBSD), Pledge (OpenBSD), Job Objects (Windows),
//! Seatbelt (macOS behind `macos-sandbox`). This root module is a pure
//! re-export facade so existing `crate::platform::sandbox::` paths keep
//! compiling; new code must import `synvoid_platform::sandbox` directly.
//!
//! The jail runtime (`synvoid-jail-runtime`) enforces isolation via
//! `synvoid-platform` without importing root paths.

pub use synvoid_platform::sandbox::*;
