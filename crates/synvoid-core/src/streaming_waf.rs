//! Streaming WAF scanner trait and decision type.
//!
//! This module defines the minimal trait needed for streaming body WAF scanning.
//! It lives in `synvoid-core` so both `synvoid-waf` (for `WafAccess`) and
//! `synvoid-http-client` (for `StreamingWafBody`) can depend on it without
//! creating circular dependencies.

/// Decision returned by a streaming WAF scanner after inspecting a body chunk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StreamingWafDecision {
    /// Chunk is clean; continue processing.
    Continue,
    /// Chunk triggered a block. Contains HTTP status code and error message.
    Block(u16, String),
}

/// Streaming WAF scanner that inspects body chunks as they arrive.
///
/// This trait is object-safe and can be used as `Box<dyn StreamingWafScanner>`.
pub trait StreamingWafScanner: Send + Sync {
    /// Inspect a body chunk and return a WAF decision.
    fn scan_chunk(&mut self, chunk: &[u8]) -> StreamingWafDecision;
}

impl<T: StreamingWafScanner + ?Sized> StreamingWafScanner for Box<T> {
    fn scan_chunk(&mut self, chunk: &[u8]) -> StreamingWafDecision {
        (**self).scan_chunk(chunk)
    }
}
