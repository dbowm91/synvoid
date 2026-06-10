// HTTP/3 server implementation lives in the synvoid-http3 crate.
// This module re-exports the public API for root-crate consumers.

pub use synvoid_http3::{Http3Server, Http3WafBackend};
