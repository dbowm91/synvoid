use std::sync::Arc;

use bytes::Bytes;

use crate::buffer::{BufferPool, PooledBuf};
use crate::waf::attack_detection::{AttackDetectionResult, AttackDetector};

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
    ReadingHeaders,
    ReadingField,
    SkippingFile,
}

struct StreamingState {
    chunks_processed: usize,
    last_result: Option<AttackDetectionResult>,
    bytes_seen: usize,
    boundary: Option<String>,
    multipart_state: MultipartState,
    trailing_window: PooledBuf,
    multipart_header_buffer: PooledBuf,
    multipart_field_buffer: PooledBuf,
    field_trailing_window: PooledBuf,
}

const TRAILING_WINDOW_SIZE: usize = 512;

impl StreamingWafCore {
    pub fn new(inner: Arc<AttackDetector>) -> Self {
        Self {
            inner,
            chunk_size: DEFAULT_CHUNK_SIZE,
            max_buffered_bytes: DEFAULT_MAX_BUFFERED_BYTES,
            state: StreamingState {
                chunks_processed: 0,
                last_result: None,
                bytes_seen: 0,
                boundary: None,
                multipart_state: MultipartState::None,
                trailing_window: BufferPool::acquire(0),
                multipart_header_buffer: BufferPool::acquire(0),
                multipart_field_buffer: BufferPool::acquire(0),
                field_trailing_window: BufferPool::acquire(0),
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
                chunks_processed: 0,
                last_result: None,
                bytes_seen: 0,
                boundary: None,
                multipart_state: MultipartState::None,
                trailing_window: BufferPool::acquire(0),
                multipart_header_buffer: BufferPool::acquire(0),
                multipart_field_buffer: BufferPool::acquire(0),
                field_trailing_window: BufferPool::acquire(0),
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
        if let Some(result) = self
            .inner
            .check_body_fragments(&[self.state.trailing_window.as_slice(), chunk])
        {
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
        let boundary_str = self.state.boundary.as_ref().unwrap().clone();
        let boundary = boundary_str.as_bytes();
        let trailing_slice = self.state.trailing_window.as_slice();
        let combined_view = [trailing_slice, chunk];
        let total_len = combined_view[0].len() + combined_view[1].len();
        let mut current_pos = 0;

        while current_pos < total_len {
            match self.state.multipart_state {
                MultipartState::LookingForBoundary => {
                    if let Some(pos) =
                        Self::find_in_fragments(&combined_view, current_pos, boundary)
                    {
                        self.state.multipart_state = MultipartState::ReadingHeaders;
                        self.state.multipart_header_buffer.clear();
                        current_pos = pos + boundary.len();
                    } else {
                        current_pos = total_len;
                    }
                }
                MultipartState::ReadingHeaders => {
                    if let Some(pos) =
                        Self::find_in_fragments(&combined_view, current_pos, b"\r\n\r\n")
                    {
                        let header_len = (pos + 4) - current_pos;
                        Self::copy_from_fragments(
                            &mut self.state.multipart_header_buffer,
                            &combined_view,
                            current_pos,
                            header_len,
                        );
                        current_pos = pos + 4;

                        // Parse headers to see if it's a file
                        let header_str =
                            String::from_utf8_lossy(self.state.multipart_header_buffer.as_slice())
                                .to_lowercase();
                        if header_str.contains("filename=") {
                            self.state.multipart_state = MultipartState::SkippingFile;
                        } else {
                            self.state.multipart_state = MultipartState::ReadingField;
                            self.state.multipart_field_buffer.clear();
                            self.state.field_trailing_window.clear();
                        }
                    } else {
                        Self::copy_from_fragments(
                            &mut self.state.multipart_header_buffer,
                            &combined_view,
                            current_pos,
                            total_len - current_pos,
                        );
                        current_pos = total_len;
                    }
                }
                MultipartState::ReadingField => {
                    if let Some(pos) =
                        Self::find_in_fragments(&combined_view, current_pos, boundary)
                    {
                        let field_len = pos - current_pos;
                        let mut field_fragment = BufferPool::acquire(field_len);
                        Self::copy_from_fragments(
                            &mut field_fragment,
                            &combined_view,
                            current_pos,
                            field_len,
                        );

                        // Scan combined fragments: [trailing, current_fragment]
                        if let Some(result) = self.inner.check_body_fragments(&[
                            self.state.field_trailing_window.as_slice(),
                            field_fragment.as_slice(),
                        ]) {
                            self.state.last_result = Some(result.clone());
                            return StreamingWafDecision::Block(
                                result.get_block_status().unwrap_or(403),
                                format!(
                                    "Attack detected in multipart field: {:?}",
                                    result.attack_type
                                ),
                            );
                        }

                        self.state.multipart_state = MultipartState::ReadingHeaders;
                        self.state.multipart_header_buffer.clear();
                        self.state.field_trailing_window.clear();
                        current_pos = pos + boundary.len();
                    } else {
                        // Boundary not found, scan what we have and keep trailing window
                        let fragment_len = total_len - current_pos;
                        let mut field_fragment = BufferPool::acquire(fragment_len);
                        Self::copy_from_fragments(
                            &mut field_fragment,
                            &combined_view,
                            current_pos,
                            fragment_len,
                        );

                        if let Some(result) = self.inner.check_body_fragments(&[
                            self.state.field_trailing_window.as_slice(),
                            field_fragment.as_slice(),
                        ]) {
                            self.state.last_result = Some(result.clone());
                            return StreamingWafDecision::Block(
                                result.get_block_status().unwrap_or(403),
                                format!(
                                    "Attack detected in multipart field fragment: {:?}",
                                    result.attack_type
                                ),
                            );
                        }

                        // Update field trailing window
                        self.state.field_trailing_window.clear();
                        let window_start =
                            field_fragment.len().saturating_sub(TRAILING_WINDOW_SIZE);
                        self.state
                            .field_trailing_window
                            .extend_from_slice(&field_fragment[window_start..]);

                        current_pos = total_len;
                    }
                }
                MultipartState::SkippingFile => {
                    if let Some(pos) =
                        Self::find_in_fragments(&combined_view, current_pos, boundary)
                    {
                        self.state.multipart_state = MultipartState::ReadingHeaders;
                        self.state.multipart_header_buffer.clear();
                        current_pos = pos + boundary.len();
                    } else {
                        current_pos = total_len;
                    }
                }
                MultipartState::None => {
                    self.state.multipart_state = MultipartState::LookingForBoundary;
                }
            }
        }

        let window_size = boundary.len() + 4; // enough for boundary + CRLF CRLF
        let window_start = total_len.saturating_sub(window_size);
        let window_len = total_len - window_start;

        // Perform the copy while combined_view is still valid
        let mut temp_buf = BufferPool::acquire(window_len);
        Self::copy_from_fragments(&mut temp_buf, &combined_view, window_start, window_len);

        // Update trailing window
        self.state.trailing_window.clear();
        self.state
            .trailing_window
            .extend_from_slice(temp_buf.as_slice());

        StreamingWafDecision::Continue
    }

    fn find_in_fragments(fragments: &[&[u8]; 2], start_pos: usize, needle: &[u8]) -> Option<usize> {
        let frag0_len = fragments[0].len();
        let total_len = frag0_len + fragments[1].len();

        if needle.is_empty() {
            return Some(start_pos);
        }
        if start_pos + needle.len() > total_len {
            return None;
        }

        for i in start_pos..=(total_len - needle.len()) {
            let mut matched = true;
            for (j, &nb) in needle.iter().enumerate() {
                let pos = i + j;
                let b = if pos < frag0_len {
                    fragments[0][pos]
                } else {
                    fragments[1][pos - frag0_len]
                };
                if b != nb {
                    matched = false;
                    break;
                }
            }
            if matched {
                return Some(i);
            }
        }
        None
    }

    fn copy_from_fragments(
        dest: &mut PooledBuf,
        fragments: &[&[u8]; 2],
        start_pos: usize,
        len: usize,
    ) {
        let frag0_len = fragments[0].len();
        let end_pos = start_pos + len;

        if start_pos < frag0_len {
            let take = (frag0_len - start_pos).min(len);
            dest.extend_from_slice(&fragments[0][start_pos..start_pos + take]);
            if len > take {
                let remaining = len - take;
                dest.extend_from_slice(&fragments[1][..remaining]);
            }
        } else {
            dest.extend_from_slice(&fragments[1][start_pos - frag0_len..end_pos - frag0_len]);
        }
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
        state.chunks_processed = 0;
        state.last_result = None;
        state.bytes_seen = 0;
        state.boundary = None;
        state.multipart_state = MultipartState::None;
        state.trailing_window.clear();
        state.multipart_header_buffer.clear();
        state.multipart_field_buffer.clear();
        state.field_trailing_window.clear();
    }
}

impl AttackDetectionResult {
    pub fn get_block_status(&self) -> Option<u16> {
        Some(match self.attack_type {
            crate::waf::attack_detection::AttackType::Sqli => 403,
            crate::waf::attack_detection::AttackType::Xss => 403,
            crate::waf::attack_detection::AttackType::PathTraversal => 403,
            crate::waf::attack_detection::AttackType::Smuggling => 403,
            crate::waf::attack_detection::AttackType::CmdInjection => 403,
            crate::waf::attack_detection::AttackType::Rce => 403,
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
