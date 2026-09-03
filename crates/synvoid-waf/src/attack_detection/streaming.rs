use std::sync::Arc;

use crate::attack_detection::{AttackDetectionResult, AttackDetector};
use synvoid_utils::buffer::pool::{BufferPool, PooledBuf};

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

        let max_old = TRAILING_WINDOW_SIZE.saturating_sub(chunk.len());
        let take = self.state.trailing_window.len().min(max_old);
        let old_start = self.state.trailing_window.len() - take;
        let previous_content = self.state.trailing_window[old_start..].to_vec();

        self.state.trailing_window.clear();
        self.state
            .trailing_window
            .extend_from_slice(&previous_content);
        self.state.trailing_window.extend_from_slice(
            &chunk[chunk
                .len()
                .saturating_sub(TRAILING_WINDOW_SIZE.saturating_sub(previous_content.len()))..],
        );

        StreamingWafDecision::Continue
    }

    fn process_multipart_chunk(&mut self, chunk: &[u8]) -> StreamingWafDecision {
        let Some(boundary_str) = self.state.boundary.as_ref().cloned() else {
            tracing::error!("Multipart processing without boundary; continuing without block");
            return StreamingWafDecision::Continue;
        };
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
                        // Scan preamble bytes before first boundary (H06)
                        let preamble_len = pos.saturating_sub(current_pos);
                        if preamble_len > 0 {
                            let mut preamble = BufferPool::acquire(preamble_len);
                            Self::copy_from_fragments(
                                &mut preamble,
                                &combined_view,
                                current_pos,
                                preamble_len,
                            );
                            if let Some(result) = self.inner.check_body_fragments(&[
                                self.state.trailing_window.as_slice(),
                                preamble.as_slice(),
                            ]) {
                                self.state.last_result = Some(result.clone());
                                return StreamingWafDecision::Block(
                                    result.get_block_status().unwrap_or(403),
                                    format!(
                                        "Attack detected in multipart preamble: {:?}",
                                        result.attack_type
                                    ),
                                );
                            }
                        }
                        self.state.multipart_state = MultipartState::ReadingHeaders;
                        self.state.multipart_header_buffer.clear();
                        current_pos = pos + boundary.len();
                    } else {
                        // No boundary found — scan preamble as regular content (H06)
                        let preamble_len = total_len - current_pos;
                        if preamble_len > 0 {
                            let mut preamble = BufferPool::acquire(preamble_len);
                            Self::copy_from_fragments(
                                &mut preamble,
                                &combined_view,
                                current_pos,
                                preamble_len,
                            );
                            if let Some(result) = self.inner.check_body_fragments(&[
                                self.state.trailing_window.as_slice(),
                                preamble.as_slice(),
                            ]) {
                                self.state.last_result = Some(result.clone());
                                return StreamingWafDecision::Block(
                                    result.get_block_status().unwrap_or(403),
                                    format!(
                                        "Attack detected in multipart preamble: {:?}",
                                        result.attack_type
                                    ),
                                );
                            }
                        }
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

                        let previous_window = self.state.field_trailing_window.as_slice();
                        let keep_from_previous =
                            TRAILING_WINDOW_SIZE.saturating_sub(field_fragment.len());
                        let previous_start =
                            previous_window.len().saturating_sub(keep_from_previous);
                        let mut trailing_window = BufferPool::acquire(TRAILING_WINDOW_SIZE);
                        trailing_window.extend_from_slice(&previous_window[previous_start..]);
                        trailing_window.extend_from_slice(field_fragment.as_slice());
                        if trailing_window.len() > TRAILING_WINDOW_SIZE {
                            let overflow = trailing_window.len() - TRAILING_WINDOW_SIZE;
                            let tail = trailing_window.as_slice()[overflow..].to_vec();
                            trailing_window.clear();
                            trailing_window.extend_from_slice(&tail);
                        }
                        self.state.field_trailing_window = trailing_window;

                        current_pos = total_len;
                    }
                }
                MultipartState::SkippingFile => {
                    if let Some(pos) =
                        Self::find_in_fragments(&combined_view, current_pos, boundary)
                    {
                        // Scan file content before next boundary (H01)
                        let file_len = pos.saturating_sub(current_pos);
                        if file_len > 0 {
                            let mut file_fragment = BufferPool::acquire(file_len);
                            Self::copy_from_fragments(
                                &mut file_fragment,
                                &combined_view,
                                current_pos,
                                file_len,
                            );
                            if let Some(result) = self.inner.check_body_fragments(&[
                                self.state.trailing_window.as_slice(),
                                file_fragment.as_slice(),
                            ]) {
                                self.state.last_result = Some(result.clone());
                                return StreamingWafDecision::Block(
                                    result.get_block_status().unwrap_or(403),
                                    format!(
                                        "Attack detected in multipart file: {:?}",
                                        result.attack_type
                                    ),
                                );
                            }
                        }
                        self.state.multipart_state = MultipartState::ReadingHeaders;
                        self.state.multipart_header_buffer.clear();
                        current_pos = pos + boundary.len();
                    } else {
                        // No boundary — scan file chunk incrementally (H01)
                        let file_len = total_len - current_pos;
                        if file_len > 0 {
                            let mut file_fragment = BufferPool::acquire(file_len);
                            Self::copy_from_fragments(
                                &mut file_fragment,
                                &combined_view,
                                current_pos,
                                file_len,
                            );
                            if let Some(result) = self.inner.check_body_fragments(&[
                                self.state.trailing_window.as_slice(),
                                file_fragment.as_slice(),
                            ]) {
                                self.state.last_result = Some(result.clone());
                                return StreamingWafDecision::Block(
                                    result.get_block_status().unwrap_or(403),
                                    format!(
                                        "Attack detected in multipart file: {:?}",
                                        result.attack_type
                                    ),
                                );
                            }
                        }
                        current_pos = total_len;
                    }
                }
                MultipartState::None => {
                    self.state.multipart_state = MultipartState::LookingForBoundary;
                }
            }
        }

        let window_size = boundary.len() + 4;
        let window_start = total_len.saturating_sub(window_size);
        let window_len = total_len - window_start;

        let mut temp_buf = BufferPool::acquire(window_len);
        Self::copy_from_fragments(&mut temp_buf, &combined_view, window_start, window_len);

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

    pub fn finalize(&mut self) -> Option<AttackDetectionResult> {
        if self.state.last_result.is_some() {
            return self.state.last_result.clone();
        }

        if !self.state.trailing_window.is_empty() {
            if let Some(result) = self
                .inner
                .check_body_fragments(&[self.state.trailing_window.as_slice()])
            {
                self.state.last_result = Some(result.clone());
                return Some(result);
            }
        }

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
    /// Block status for an already-detected attack. Currently always 403;
    /// kept as `Option` for call-site compat (`unwrap_or(403)`).
    pub fn get_block_status(&self) -> Option<u16> {
        Some(403)
    }
}

impl synvoid_core::streaming_waf::StreamingWafScanner for StreamingWafCore {
    fn scan_chunk(&mut self, chunk: &[u8]) -> synvoid_core::streaming_waf::StreamingWafDecision {
        match StreamingWafCore::scan_chunk(self, chunk) {
            StreamingWafDecision::Continue => {
                synvoid_core::streaming_waf::StreamingWafDecision::Continue
            }
            StreamingWafDecision::Block(status, reason) => {
                synvoid_core::streaming_waf::StreamingWafDecision::Block(status, reason)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_streaming_waf_basic() {
        use crate::attack_detection::AttackDetectionConfig;

        let config = AttackDetectionConfig::default();
        let detector = AttackDetector::new(config);
        let mut streaming = StreamingWafCore::new(Arc::new(detector));

        let result = streaming.scan_chunk(b"hello world");
        assert!(matches!(result, StreamingWafDecision::Continue));
    }

    #[test]
    fn test_streaming_waf_block() {
        use crate::attack_detection::AttackDetectionConfig;

        let config = AttackDetectionConfig::default();
        let detector = AttackDetector::new(config);
        let mut streaming = StreamingWafCore::new(Arc::new(detector));

        let result = streaming.scan_chunk(b"1' OR '1'='1");
        assert!(matches!(result, StreamingWafDecision::Block(..)));
    }

    #[test]
    fn test_streaming_waf_buffer_overflow() {
        use crate::attack_detection::AttackDetectionConfig;

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
        use crate::attack_detection::AttackDetectionConfig;

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
        use crate::attack_detection::AttackDetectionConfig;

        let config = AttackDetectionConfig::default();
        let detector = AttackDetector::new(config);
        let mut streaming = StreamingWafCore::new(Arc::new(detector));

        streaming.scan_chunk(b"<script>");
        let result = streaming.scan_chunk(b"alert(1)</script>");
        assert!(matches!(result, StreamingWafDecision::Block(..)));
    }
}
