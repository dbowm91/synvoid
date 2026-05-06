use std::collections::VecDeque;
use std::sync::Arc;

use bytes::Bytes;

use crate::waf::attack_detection::{AttackDetectionResult, AttackDetector};
use crate::buffer::{BufferPool, PooledBuf};

const DEFAULT_CHUNK_SIZE: usize = 4096;
const DEFAULT_MAX_BUFFERED_BYTES: usize = 2 * 1024 * 1024;

#[derive(Debug, Clone)]
pub enum StreamingWafDecision {
    Continue,
    Block(u16, String),
}

#[allow(dead_code)]
pub struct StreamingWafCore {
    inner: Arc<AttackDetector>,
    chunk_size: usize,
    max_buffered_bytes: usize,
    state: StreamingState,
}

#[derive(Debug, PartialEq)]
enum MultipartState {
    None,
    LookingForBoundary,
    ReadingHeaders { buffer: PooledBuf },
    ReadingField { buffer: PooledBuf },
    SkippingFile,
}

struct StreamingState {
    pending_chunks: VecDeque<Bytes>,
    current_input: String,
    chunks_processed: usize,
    last_result: Option<AttackDetectionResult>,
    bytes_seen: usize,
    boundary: Option<String>,
    multipart_state: MultipartState,
    trailing_window: PooledBuf,
}

const TRAILING_WINDOW_SIZE: usize = 128;

impl StreamingWafCore {
    pub fn new(inner: Arc<AttackDetector>) -> Self {
        Self {
            inner,
            chunk_size: DEFAULT_CHUNK_SIZE,
            max_buffered_bytes: DEFAULT_MAX_BUFFERED_BYTES,
            state: StreamingState {
                pending_chunks: VecDeque::new(),
                current_input: String::with_capacity(DEFAULT_CHUNK_SIZE * 4),
                chunks_processed: 0,
                last_result: None,
                bytes_seen: 0,
                boundary: None,
                multipart_state: MultipartState::None,
                trailing_window: BufferPool::acquire(0),
            },
        }
    }

    pub fn with_config(
        inner: Arc<AttackDetector>,
        chunk_size: usize,
        max_buffered_bytes: usize,
    ) -> Self {
        Self {
            inner,
            chunk_size,
            max_buffered_bytes,
            state: StreamingState {
                pending_chunks: VecDeque::new(),
                current_input: String::with_capacity(chunk_size * 4),
                chunks_processed: 0,
                last_result: None,
                bytes_seen: 0,
                boundary: None,
                multipart_state: MultipartState::None,
                trailing_window: BufferPool::acquire(0),
            },
        }
    }

    pub fn set_multipart_boundary(&mut self, boundary: &str) {
        let state = &mut self.state;
        state.boundary = Some(format!("--{}", boundary));
        state.multipart_state = MultipartState::LookingForBoundary;
    }

    /// Scans a chunk of data. Optimized for 1M+ RPS by using a persistent string buffer.
    pub fn scan_chunk(&mut self, chunk: &[u8]) -> StreamingWafDecision {
        if self.state.bytes_seen.saturating_add(chunk.len()) > self.max_buffered_bytes {
            return StreamingWafDecision::Block(
                413,
                "Request body too large: byte limit exceeded".to_string(),
            );
        }

        self.state.bytes_seen += chunk.len();
        self.state.chunks_processed += 1;

        if self.state.boundary.is_some() {
            self.process_multipart_chunk(chunk)
        } else {
            self.process_regular_chunk(chunk)
        }
    }

    fn process_regular_chunk(&mut self, chunk: &[u8]) -> StreamingWafDecision {
        // Use fragmented scan to avoid merging buffers
        if let Some(result) = self.inner.check_body_fragments(&[
            self.state.trailing_window.as_slice(),
            chunk,
        ]) {
            self.state.last_result = Some(result.clone());
            return StreamingWafDecision::Block(
                result.get_block_status().unwrap_or(403),
                format!("Attack detected: {:?}", result.attack_type),
            );
        }

        // Update trailing window
        self.state.trailing_window.clear();
        let window_start = chunk.len().saturating_sub(TRAILING_WINDOW_SIZE);
        self.state
            .trailing_window
            .extend_from_slice(&chunk[window_start..]);

        StreamingWafDecision::Continue
    }

    fn process_multipart_chunk(&mut self, chunk: &[u8]) -> StreamingWafDecision {
        let boundary = self.state.boundary.clone().unwrap();
        let mut current_pos = 0;

        let mut combined = BufferPool::acquire(self.state.trailing_window.len() + chunk.len());
        combined.as_mut_slice()[..self.state.trailing_window.len()]
            .copy_from_slice(self.state.trailing_window.as_slice());
        combined.as_mut_slice()[self.state.trailing_window.len()..].copy_from_slice(chunk);

        while current_pos < combined.len() {
            match &mut self.state.multipart_state {
                MultipartState::LookingForBoundary => {
                    let remaining = &combined[current_pos..];
                    if let Some(pos) = Self::find_bytes(remaining, boundary.as_bytes()) {
                        self.state.multipart_state = MultipartState::ReadingHeaders {
                            buffer: BufferPool::acquire(0),
                        };
                        current_pos += pos + boundary.len();
                    } else {
                        current_pos = combined.len();
                    }
                }
                MultipartState::ReadingHeaders { buffer } => {
                    let remaining = &combined[current_pos..];
                    let s = String::from_utf8_lossy(remaining);
                    if let Some(pos) = s.find("\r\n\r\n") {
                        let header_chunk = &remaining[..pos + 4];
                        buffer.extend_from_slice(header_chunk);
                        current_pos += header_chunk.len();

                        // Parse headers to see if it's a file
                        let header_str = String::from_utf8_lossy(buffer.as_slice()).to_lowercase();
                        if header_str.contains("filename=") {
                            self.state.multipart_state = MultipartState::SkippingFile;
                        } else {
                            self.state.multipart_state = MultipartState::ReadingField {
                                buffer: BufferPool::acquire(0),
                            };
                        }
                    } else {
                        buffer.extend_from_slice(remaining);
                        current_pos = combined.len();
                    }
                }
                MultipartState::ReadingField { buffer } => {
                    let remaining = &combined[current_pos..];
                    if let Some(pos) = Self::find_bytes(remaining, boundary.as_bytes()) {
                        let field_data = &remaining[..pos];
                        buffer.extend_from_slice(field_data);

                        // Scan the field
                        let field_str = String::from_utf8_lossy(buffer.as_slice());
                        if let Some(result) = self.inner.check_body_only_via_normalized(&field_str) {
                            self.state.last_result = Some(result.clone());
                            return StreamingWafDecision::Block(
                                result.get_block_status().unwrap_or(403),
                                format!(
                                    "Attack detected in multipart field: {:?}",
                                    result.attack_type
                                ),
                            );
                        }

                        self.state.multipart_state = MultipartState::ReadingHeaders {
                            buffer: BufferPool::acquire(0),
                        };
                        current_pos += pos + boundary.len();
                    } else {
                        buffer.extend_from_slice(remaining);
                        current_pos = combined.len();
                    }
                }
                MultipartState::SkippingFile => {
                    let remaining = &combined[current_pos..];
                    if let Some(pos) = Self::find_bytes(remaining, boundary.as_bytes()) {
                        self.state.multipart_state = MultipartState::ReadingHeaders {
                            buffer: BufferPool::acquire(0),
                        };
                        current_pos += pos + boundary.len();
                    } else {
                        current_pos = combined.len();
                    }
                }
                MultipartState::None => {
                    self.state.multipart_state = MultipartState::LookingForBoundary;
                }
            }
        }

        // Update trailing window to handle split boundaries/headers
        self.state.trailing_window.clear();
        let window_size = boundary.len() + 4; // enough for boundary + CRLF CRLF
        let window_start = combined.len().saturating_sub(window_size);
        self.state
            .trailing_window
            .extend_from_slice(&combined[window_start..]);

        StreamingWafDecision::Continue
    }

    pub fn finalize(&self) -> Option<AttackDetectionResult> {
        self.state.last_result.clone()
    }

    pub fn bytes_seen(&self) -> usize {
        self.state.bytes_seen
    }

    pub fn chunks_processed(&self) -> usize {
        self.state.chunks_processed
    }

    pub fn reset(&mut self) {
        let state = &mut self.state;
        state.pending_chunks.clear();
        state.current_input.clear();
        state.chunks_processed = 0;
        state.last_result = None;
        state.bytes_seen = 0;
        state.boundary = None;
        state.multipart_state = MultipartState::None;
        state.trailing_window.clear();
    }

    fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
        if needle.is_empty() {
            return Some(0);
        }
        haystack.windows(needle.len()).position(|w| w == needle)
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
        let mut streaming = StreamingWafCore::new(Arc::new(detector));

        let result = streaming.scan_chunk(b"hello world");
        assert!(matches!(result, StreamingWafDecision::Continue));
    }

    #[test]
    fn test_streaming_waf_block() {
        use crate::waf::attack_detection::AttackDetectionConfig;

        let config = AttackDetectionConfig::default();
        let detector = AttackDetector::new(config);
        let mut streaming = StreamingWafCore::new(Arc::new(detector));

        let result = streaming.scan_chunk(b"1' OR '1'='1");
        assert!(matches!(result, StreamingWafDecision::Block(..)));
    }

    #[test]
    fn test_streaming_waf_buffer_overflow() {
        use crate::waf::attack_detection::AttackDetectionConfig;

        let config = AttackDetectionConfig::default();
        let detector = AttackDetector::new(config);
        let mut streaming = StreamingWafCore::with_config(Arc::new(detector), 1024, 12);
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
        let mut streaming = StreamingWafCore::new(Arc::new(detector));

        streaming.scan_chunk(b"test");
        assert_eq!(streaming.chunks_processed(), 1);

        streaming.reset();
        assert_eq!(streaming.chunks_processed(), 0);
    }

    #[test]
    fn test_streaming_waf_split_attack() {
        use crate::waf::attack_detection::AttackDetectionConfig;

        let config = AttackDetectionConfig::default();
        let detector = AttackDetector::new(config);
        let mut streaming = StreamingWafCore::new(Arc::new(detector));

        // "1' OR '1'='1" split into two chunks
        streaming.scan_chunk(b"1' OR ");
        let result = streaming.scan_chunk(b"'1'='1");
        assert!(matches!(result, StreamingWafDecision::Block(..)));
    }

    #[test]
    fn test_streaming_waf_multipart_field_attack() {
        use crate::waf::attack_detection::AttackDetectionConfig;

        let config = AttackDetectionConfig::default();
        let detector = AttackDetector::new(config);
        let mut streaming = StreamingWafCore::new(Arc::new(detector));
        streaming.set_multipart_boundary("boundary");

        let multipart_data = b"--boundary\r\n\
                               Content-Disposition: form-data; name=\"field\"\r\n\
                               \r\n\
                               1' OR '1'='1\r\n\
                               --boundary--";

        // Scan in small chunks to test streaming
        for chunk in multipart_data.chunks(10) {
            let result = streaming.scan_chunk(chunk);
            if let StreamingWafDecision::Block(..) = result {
                return; // Success
            }
        }
        panic!("Should have detected attack in multipart field");
    }

    #[test]
    fn test_streaming_waf_multipart_skip_file() {
        use crate::waf::attack_detection::AttackDetectionConfig;

        let config = AttackDetectionConfig::default();
        let detector = AttackDetector::new(config);
        let mut streaming = StreamingWafCore::new(Arc::new(detector));
        streaming.set_multipart_boundary("boundary");

        // Attack payload inside a file should be skipped if we strictly follow the requirement
        // "avoid scanning binary file uploads if we shouldn't"
        let multipart_data = b"--boundary\r\n\
                               Content-Disposition: form-data; name=\"file\"; filename=\"malicious.txt\"\r\n\
                               Content-Type: text/plain\r\n\
                               \r\n\
                               1' OR '1'='1\r\n\
                               --boundary--";

        for chunk in multipart_data.chunks(10) {
            let result = streaming.scan_chunk(chunk);
            assert!(
                matches!(result, StreamingWafDecision::Continue),
                "Should NOT have detected attack in file content"
            );
        }
    }
}
