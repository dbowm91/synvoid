use std::collections::VecDeque;
use std::sync::Arc;

use bytes::Bytes;
use parking_lot::RwLock;

use crate::waf::attack_detection::{AttackDetectionResult, AttackDetector};

const DEFAULT_CHUNK_SIZE: usize = 4096;
const DEFAULT_MAX_BUFFERED_CHUNKS: usize = 64;

#[derive(Debug, Clone)]
pub enum StreamingWafDecision {
    Continue,
    Block(u16, String),
    NeedMore,
}

pub struct StreamingWafCore {
    inner: Arc<AttackDetector>,
    chunk_size: usize,
    max_buffered_chunks: usize,
    state: RwLock<StreamingState>,
}

struct StreamingState {
    pending_chunks: VecDeque<Bytes>,
    current_input: Option<String>,
    chunks_processed: usize,
    last_result: Option<AttackDetectionResult>,
    bytes_seen: usize,
}

impl StreamingWafCore {
    pub fn new(inner: Arc<AttackDetector>) -> Self {
        Self {
            inner,
            chunk_size: DEFAULT_CHUNK_SIZE,
            max_buffered_chunks: DEFAULT_MAX_BUFFERED_CHUNKS,
            state: RwLock::new(StreamingState {
                pending_chunks: VecDeque::new(),
                current_input: None,
                chunks_processed: 0,
                last_result: None,
                bytes_seen: 0,
            }),
        }
    }

    pub fn with_config(
        inner: Arc<AttackDetector>,
        chunk_size: usize,
        max_buffered_chunks: usize,
    ) -> Self {
        Self {
            inner,
            chunk_size,
            max_buffered_chunks,
            state: RwLock::new(StreamingState {
                pending_chunks: VecDeque::new(),
                current_input: None,
                chunks_processed: 0,
                last_result: None,
                bytes_seen: 0,
            }),
        }
    }

    pub fn scan_chunk(&self, chunk: &[u8]) -> StreamingWafDecision {
        let mut state = self.state.write();

        if state.pending_chunks.len() >= self.max_buffered_chunks {
            return StreamingWafDecision::Block(
                413,
                "Request body too large: buffer overflow".to_string(),
            );
        }

        state.bytes_seen += chunk.len();

        let chunk_bytes = Bytes::copy_from_slice(chunk);
        state.pending_chunks.push_back(chunk_bytes);
        state.chunks_processed += 1;

        let current_input = Self::assemble_input(&state.pending_chunks);
        state.current_input = Some(current_input.clone());

        if let Some(result) = self.inner.check_body_only_via_normalized(&current_input) {
            state.last_result = Some(result.clone());
            return StreamingWafDecision::Block(
                result.get_block_status().unwrap_or(403),
                format!("Attack detected: {:?}", result.attack_type),
            );
        }

        StreamingWafDecision::Continue
    }

    pub fn scan_chunk_utf8(&self, chunk: &[u8]) -> StreamingWafDecision {
        let mut state = self.state.write();

        if state.pending_chunks.len() >= self.max_buffered_chunks {
            return StreamingWafDecision::Block(
                413,
                "Request body too large: buffer overflow".to_string(),
            );
        }

        state.bytes_seen += chunk.len();

        if let Ok(s) = std::str::from_utf8(chunk) {
            if let Some(ref mut current) = state.current_input {
                current.push_str(s);
            } else {
                state.current_input = Some(s.to_string());
            }
        } else {
            return StreamingWafDecision::Block(400, "Invalid UTF-8 in request body".to_string());
        }

        state.chunks_processed += 1;

        if let Some(ref current_input) = state.current_input {
            if let Some(result) = self.inner.check_body_only_via_normalized(current_input) {
                state.last_result = Some(result.clone());
                return StreamingWafDecision::Block(
                    result.get_block_status().unwrap_or(403),
                    format!("Attack detected: {:?}", result.attack_type),
                );
            }
        }

        StreamingWafDecision::Continue
    }

    fn assemble_input(chunks: &VecDeque<Bytes>) -> String {
        let mut result = String::with_capacity(chunks.iter().map(|c| c.len()).sum());
        for chunk in chunks {
            if let Ok(s) = std::str::from_utf8(chunk) {
                result.push_str(s);
            }
        }
        result
    }

    pub fn finalize(&self) -> Option<AttackDetectionResult> {
        let state = self.state.read();
        state.last_result.clone()
    }

    pub fn bytes_seen(&self) -> usize {
        self.state.read().bytes_seen
    }

    pub fn chunks_processed(&self) -> usize {
        self.state.read().chunks_processed
    }

    pub fn pending_chunks_count(&self) -> usize {
        self.state.read().pending_chunks.len()
    }

    pub fn reset(&self) {
        let mut state = self.state.write();
        state.pending_chunks.clear();
        state.current_input = None;
        state.chunks_processed = 0;
        state.last_result = None;
        state.bytes_seen = 0;
    }
}

impl AttackDetectionResult {
    pub fn get_block_status(&self) -> Option<u16> {
        Some(match self.attack_type {
            crate::waf::attack_detection::AttackType::Sqli => 403,
            crate::waf::attack_detection::AttackType::Xss => 403,
            crate::waf::attack_detection::AttackType::PathTraversal => 403,
            _ => 403,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_streaming_waf_basic() {
        use crate::waf::attack_detection::AttackDetectionConfig;

        let config = AttackDetectionConfig::default();
        let detector = AttackDetector::new(config);
        let streaming = StreamingWafCore::new(Arc::new(detector));

        let result = streaming.scan_chunk(b"hello world");
        assert!(matches!(result, StreamingWafDecision::Continue));
    }

    #[test]
    fn test_streaming_waf_block() {
        use crate::waf::attack_detection::AttackDetectionConfig;

        let config = AttackDetectionConfig::default();
        let detector = AttackDetector::new(config);
        let streaming = StreamingWafCore::new(Arc::new(detector));

        let result = streaming.scan_chunk(b"1' OR '1'='1");
        assert!(matches!(result, StreamingWafDecision::Block(..)));
    }

    #[test]
    fn test_streaming_waf_buffer_overflow() {
        use crate::waf::attack_detection::AttackDetectionConfig;

        let config = AttackDetectionConfig::default();
        let detector = AttackDetector::new(config);
        let streaming = StreamingWafCore::with_config(Arc::new(detector), 1024, 2);

        streaming.scan_chunk(b"chunk1");
        streaming.scan_chunk(b"chunk2");
        let result = streaming.scan_chunk(b"chunk3");
        assert!(matches!(result, StreamingWafDecision::Block(413, _)));
    }

    #[test]
    fn test_streaming_waf_reset() {
        use crate::waf::attack_detection::AttackDetectionConfig;

        let config = AttackDetectionConfig::default();
        let detector = AttackDetector::new(config);
        let streaming = StreamingWafCore::new(Arc::new(detector));

        streaming.scan_chunk(b"test");
        assert_eq!(streaming.chunks_processed(), 1);

        streaming.reset();
        assert_eq!(streaming.chunks_processed(), 0);
    }
}
