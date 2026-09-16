//! Root compatibility shim - canonical implementation is in synvoid-http
//! (`streaming_waf_body`; Phase 34 moved it out of the generic transport
//! layer `synvoid-http-client`).
pub use synvoid_http::streaming_waf_body::{
    StreamingWafBody, StreamingWafDecision, StreamingWafScanner,
};
