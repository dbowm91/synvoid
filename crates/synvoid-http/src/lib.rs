//! SynVoid HTTP server utilities.
//!
//! Provides HTTP/1.1 and HTTP/2 server pipeline components, body helpers,
//! header helpers, and response construction primitives.

pub mod early_parse;
pub mod headers;
pub mod listener;
pub mod response_builder;
pub mod runtime;
pub mod validation_helpers;

pub use response_builder::{
    bad_gateway_bytes, error_body, error_response_bytes, fallback_error_boxed,
    fallback_error_bytes, fallback_error_full, reason_phrase,
};
