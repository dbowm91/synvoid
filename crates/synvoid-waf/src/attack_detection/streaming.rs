use std::sync::Arc;

use crate::attack_detection::{AttackDetectionResult, AttackDetector};
use synvoid_utils::buffer::pool::{BufferPool, PooledBuf};

const DEFAULT_CHUNK_SIZE: usize = 4096;
pub(crate) const DEFAULT_MAX_BUFFERED_BYTES: usize = 2 * 1024 * 1024;

const SNIFF_CAP: usize = 512;
const MAX_BOUNDARY_TOKEN_LEN: usize = 128;

const TEXT_PART_MARKERS: &[&str] = &[
    "text/",
    "json",
    "xml",
    "svg",
    "javascript",
    "ecmascript",
    "urlencoded",
    "+xml",
    "csv",
    "yaml",
    "rtf",
];

const BINARY_PART_MARKERS: &[&str] = &[
    "image/",
    "video/",
    "audio/",
    "font/",
    "model/",
    "octet-stream",
    "pdf",
    "zip",
    "gzip",
    "x-tar",
    "x-7z",
    "x-rar",
    "x-xz",
    "x-bzip2",
    "wasm",
    "msword",
    "vnd.",
    "ogg",
    "mp4",
    "mpeg",
    "quicktime",
    "x-msvideo",
    "x-shockwave",
    "x-msdos",
    "x-executable",
    "x-object",
    "x-sharedlib",
    "x-archive",
];

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
    sniff_done: bool,
    sniff_buf: PooledBuf,
    file_part_is_text: bool,
    value_region_start: Option<usize>,
    log_only: bool,
    log_only_allowed: bool,
    trailing_window: PooledBuf,
    multipart_header_buffer: PooledBuf,
    multipart_field_buffer: PooledBuf,
    field_trailing_window: PooledBuf,
}

const TRAILING_WINDOW_SIZE: usize = 512;

impl StreamingWafCore {
    pub fn new(inner: Arc<AttackDetector>) -> Self {
        let max_buffered_bytes = inner.max_body_scan_bytes();
        Self {
            inner,
            chunk_size: DEFAULT_CHUNK_SIZE,
            max_buffered_bytes,
            state: StreamingState {
                chunks_processed: 0,
                last_result: None,
                bytes_seen: 0,
                boundary: None,
                multipart_state: MultipartState::None,
                sniff_done: false,
                sniff_buf: BufferPool::acquire(0),
                file_part_is_text: true,
                value_region_start: None,
                log_only: false,
                log_only_allowed: false,
                trailing_window: BufferPool::acquire(0),
                multipart_header_buffer: BufferPool::acquire(0),
                multipart_field_buffer: BufferPool::acquire(0),
                field_trailing_window: BufferPool::acquire(0),
            },
        }
    }

    /// Construct a scanner whose byte cap is the caller's resolved request
    /// body limit. Used by the application body policy so the scanner and the
    /// buffered path cannot disagree about the cap.
    pub fn with_body_limit(inner: Arc<AttackDetector>, max_buffered_bytes: usize) -> Self {
        Self::with_config(inner, DEFAULT_CHUNK_SIZE, max_buffered_bytes)
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
                sniff_done: false,
                sniff_buf: BufferPool::acquire(0),
                file_part_is_text: true,
                value_region_start: None,
                log_only: false,
                log_only_allowed: false,
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

    pub fn set_log_only(&mut self, log_only: bool) {
        self.state.log_only = log_only;
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

        if self.state.log_only_allowed {
            return StreamingWafDecision::Continue;
        }

        if self.state.boundary.is_none() && !self.state.sniff_done {
            let decision = self.resolve_sniff(chunk);
            return self.apply_log_only(decision);
        }

        let decision = if self.state.boundary.is_some() {
            self.process_multipart_chunk(chunk)
        } else {
            self.process_regular_chunk(chunk)
        };
        self.apply_log_only(decision)
    }

    fn apply_log_only(&mut self, decision: StreamingWafDecision) -> StreamingWafDecision {
        match decision {
            StreamingWafDecision::Block(413, _) => decision,
            StreamingWafDecision::Block(status, reason) if self.state.log_only => {
                self.state.last_result = None;
                self.state.log_only_allowed = true;
                tracing::warn!(
                    status = status,
                    reason = %reason,
                    "attack-pattern match allowed by per-path log-only policy"
                );
                StreamingWafDecision::Continue
            }
            _ => decision,
        }
    }

    fn resolve_sniff(&mut self, chunk: &[u8]) -> StreamingWafDecision {
        let room = SNIFF_CAP.saturating_sub(self.state.sniff_buf.len());
        let take = room.min(chunk.len());
        self.state.sniff_buf.extend_from_slice(&chunk[..take]);

        enum SniffDecision {
            Wait,
            NotMultipart,
            MultipartBoundary,
        }

        let decision = {
            let buf = self.state.sniff_buf.as_slice();
            match Self::first_line_end(buf) {
                Some(pos) => {
                    if Self::head_is_boundary(&buf[..pos]) {
                        SniffDecision::MultipartBoundary
                    } else {
                        SniffDecision::NotMultipart
                    }
                }
                None => {
                    let plausible = buf.is_empty()
                        || buf == b"-"
                        || (buf.starts_with(b"--") && buf.len() < SNIFF_CAP);
                    if plausible {
                        SniffDecision::Wait
                    } else {
                        SniffDecision::NotMultipart
                    }
                }
            }
        };

        match decision {
            SniffDecision::Wait => StreamingWafDecision::Continue,
            SniffDecision::NotMultipart => {
                self.state.sniff_done = true;
                self.scan_stashed_as_regular(chunk, take)
            }
            SniffDecision::MultipartBoundary => {
                let token = {
                    let buf = self.state.sniff_buf.as_slice();
                    let pos = Self::first_line_end(buf).unwrap_or(0);
                    String::from_utf8_lossy(&buf[2..pos]).into_owned()
                };
                self.state.sniff_done = true;
                self.state.boundary = Some(format!("--{token}"));
                self.state.multipart_state = MultipartState::LookingForBoundary;
                let stashed = std::mem::replace(&mut self.state.sniff_buf, BufferPool::acquire(0));
                let first = self.process_multipart_chunk(stashed.as_slice());
                if matches!(first, StreamingWafDecision::Block(..)) {
                    return first;
                }
                if take < chunk.len() {
                    return self.process_multipart_chunk(&chunk[take..]);
                }
                first
            }
        }
    }

    fn first_line_end(buf: &[u8]) -> Option<usize> {
        let mut i = 0;
        while i + 1 < buf.len() {
            if buf[i] == b'\r' && buf[i + 1] == b'\n' {
                return Some(i);
            }
            i += 1;
        }
        None
    }

    fn head_is_boundary(line: &[u8]) -> bool {
        line.len() >= 3
            && line[0] == b'-'
            && line[1] == b'-'
            && Self::valid_boundary_token(&line[2..])
    }

    fn scan_stashed_as_regular(&mut self, chunk: &[u8], take: usize) -> StreamingWafDecision {
        let stashed = std::mem::replace(&mut self.state.sniff_buf, BufferPool::acquire(0));
        let first = self.process_regular_chunk(stashed.as_slice());
        if matches!(first, StreamingWafDecision::Block(..)) {
            return first;
        }
        if take < chunk.len() {
            return self.process_regular_chunk(&chunk[take..]);
        }
        first
    }

    fn valid_boundary_token(raw: &[u8]) -> bool {
        if raw.is_empty() || raw.len() > MAX_BOUNDARY_TOKEN_LEN {
            return false;
        }
        raw.iter().all(|b| {
            matches!(
                b,
                b'A'..=b'Z'
                    | b'a'..=b'z'
                    | b'0'..=b'9'
                    | b'\''
                    | b'('
                    | b')'
                    | b'+'
                    | b'_'
                    | b','
                    | b'-'
                    | b'.'
                    | b'/'
                    | b':'
                    | b'='
                    | b'?'
            )
        })
    }

    fn header_param_value(headers: &str, param: &str) -> Option<String> {
        let needle = format!("{param}=\"");
        let mut start = 0;
        while let Some(pos) = headers[start..].find(&needle) {
            let abs_pos = start + pos;
            let prev_ok = abs_pos == 0 || {
                let prev = headers.as_bytes()[abs_pos - 1];
                !prev.is_ascii_alphanumeric() && prev != b'-' && prev != b'_'
            };
            if prev_ok {
                let val_start = abs_pos + needle.len();
                if let Some(end) = headers[val_start..].find('"') {
                    return Some(headers[val_start..val_start + end].to_string());
                }
                return None;
            }
            start = abs_pos + 1;
        }
        None
    }

    fn part_content_is_text(header_str: &str) -> bool {
        let mut content_type = None;
        for line in header_str.split("\r\n") {
            if let Some(value) = line.strip_prefix("content-type:") {
                content_type = Some(value.trim());
                break;
            }
        }
        let content_type = match content_type {
            Some(ct) => ct,
            None => return true,
        };
        if TEXT_PART_MARKERS
            .iter()
            .any(|marker| content_type.contains(marker))
        {
            return true;
        }
        if BINARY_PART_MARKERS
            .iter()
            .any(|marker| content_type.contains(marker))
        {
            return false;
        }
        true
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

        // Phase 54: `resize(0)` empties the window; `clear()` only zeroizes
        // in place and would make the extends below accumulate unboundedly.
        self.state.trailing_window.resize(0);
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
        self.state.value_region_start = None;

        while current_pos < total_len {
            match self.state.multipart_state {
                MultipartState::LookingForBoundary => {
                    if let Some(pos) =
                        Self::find_in_fragments(&combined_view, current_pos, boundary)
                    {
                        // Scan preamble bytes before first boundary (H06)
                        let preamble_len = pos.saturating_sub(current_pos);
                        if preamble_len > 0 {
                            // Phase 54: `acquire(N)` yields N logical bytes;
                            // empty before filling via `copy_from_fragments`
                            // (which appends) to avoid a zero prefix.
                            let mut preamble = BufferPool::acquire(preamble_len);
                            preamble.resize(0);
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
                        self.state.multipart_header_buffer.resize(0);
                        current_pos = pos + boundary.len();
                    } else {
                        // No boundary found — scan preamble as regular content (H06)
                        let preamble_len = total_len - current_pos;
                        if preamble_len > 0 {
                            // Phase 54: empty before filling (see above).
                            let mut preamble = BufferPool::acquire(preamble_len);
                            preamble.resize(0);
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
                        self.state.value_region_start = Some(current_pos);

                        let header_str =
                            String::from_utf8_lossy(self.state.multipart_header_buffer.as_slice())
                                .to_lowercase();
                        if header_str.contains("filename=\"") {
                            self.state.multipart_state = MultipartState::SkippingFile;
                            self.state.file_part_is_text = Self::part_content_is_text(&header_str);
                            if let Some(filename) =
                                Self::header_param_value(&header_str, "filename")
                            {
                                if let Some(result) =
                                    self.inner.check_body_fragments(&[filename.as_bytes()])
                                {
                                    self.state.last_result = Some(result.clone());
                                    return StreamingWafDecision::Block(
                                        result.get_block_status().unwrap_or(403),
                                        format!(
                                            "Attack detected in multipart filename: {:?}",
                                            result.attack_type
                                        ),
                                    );
                                }
                            }
                        } else {
                            self.state.multipart_state = MultipartState::ReadingField;
                            // Phase 54: empty (not zeroize) before reuse.
                            self.state.multipart_field_buffer.resize(0);
                            self.state.field_trailing_window.resize(0);
                            if let Some(name) = Self::header_param_value(&header_str, "name") {
                                if let Some(result) =
                                    self.inner.check_body_fragments(&[name.as_bytes()])
                                {
                                    self.state.last_result = Some(result.clone());
                                    return StreamingWafDecision::Block(
                                        result.get_block_status().unwrap_or(403),
                                        format!(
                                            "Attack detected in multipart field name: {:?}",
                                            result.attack_type
                                        ),
                                    );
                                }
                            }
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
                        // Phase 54: empty before filling (see above).
                        let mut field_fragment = BufferPool::acquire(field_len);
                        field_fragment.resize(0);
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
                        self.state.multipart_header_buffer.resize(0);
                        self.state.field_trailing_window.resize(0);
                        current_pos = pos + boundary.len();
                    } else {
                        let fragment_len = total_len - current_pos;
                        // Phase 54: empty before filling (see above).
                        let mut field_fragment = BufferPool::acquire(fragment_len);
                        field_fragment.resize(0);
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
                        // Phase 54: the window holds only real trailing bytes —
                        // empty before filling so no zero-filled prefix lands
                        // in the scanned content.
                        let mut trailing_window = BufferPool::acquire(TRAILING_WINDOW_SIZE);
                        trailing_window.resize(0);
                        trailing_window.extend_from_slice(&previous_window[previous_start..]);
                        trailing_window.extend_from_slice(field_fragment.as_slice());
                        if trailing_window.len() > TRAILING_WINDOW_SIZE {
                            let overflow = trailing_window.len() - TRAILING_WINDOW_SIZE;
                            let tail = trailing_window.as_slice()[overflow..].to_vec();
                            trailing_window.resize(0);
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
                        if file_len > 0 && self.state.file_part_is_text {
                            // Phase 54: empty before filling (see above).
                            let mut file_fragment = BufferPool::acquire(file_len);
                            file_fragment.resize(0);
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
                        self.state.multipart_header_buffer.resize(0);
                        current_pos = pos + boundary.len();
                    } else {
                        // No boundary — scan file chunk incrementally (H01)
                        let file_len = total_len - current_pos;
                        if file_len > 0 && self.state.file_part_is_text {
                            // Phase 54: empty before filling (see above).
                            let mut file_fragment = BufferPool::acquire(file_len);
                            file_fragment.resize(0);
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
        let mut window_start = total_len.saturating_sub(window_size);
        if matches!(
            self.state.multipart_state,
            MultipartState::ReadingField | MultipartState::SkippingFile
        ) {
            window_start = window_start.max(self.state.value_region_start.unwrap_or(0));
        }
        let window_len = total_len - window_start;

        let mut temp_buf = BufferPool::acquire(window_len);
        // Phase 54: empty before filling (see above).
        temp_buf.resize(0);
        Self::copy_from_fragments(&mut temp_buf, &combined_view, window_start, window_len);

        self.state.trailing_window.resize(0);
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
        state.sniff_done = false;
        state.sniff_buf.resize(0);
        state.file_part_is_text = true;
        state.value_region_start = None;
        state.log_only_allowed = false;
        // Phase 54: `reset` must empty the windows (`clear()` only zeroizes
        // in place and keeps length).
        state.trailing_window.resize(0);
        state.multipart_header_buffer.resize(0);
        state.multipart_field_buffer.resize(0);
        state.field_trailing_window.resize(0);
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

    /// Phase 54: adversarial split patterns — attacks fragmented at every
    /// byte position across chunk boundaries must still be caught, and the
    /// trailing window must contain only real trailing bytes (no zero
    /// prefix, no unbounded growth).
    #[test]
    fn test_streaming_cross_chunk_split_patterns() {
        use crate::attack_detection::AttackDetectionConfig;

        let payloads: &[&[u8]] = &[
            b"1' OR '1'='1",
            b"<script>alert(1)</script>",
            b"../../etc/passwd",
            b"{{7*7}}",
            b"1 UNION SELECT password FROM users",
        ];
        for payload in payloads {
            // Split at every position, including 1-byte chunks. A prefix
            // fragment may already match on its own (correct); what matters
            // is that the complete payload is always caught regardless of
            // where the split falls.
            for split in 1..payload.len() {
                let config = AttackDetectionConfig::default();
                let detector = AttackDetector::new(config);
                let mut streaming = StreamingWafCore::new(Arc::new(detector));
                let first = streaming.scan_chunk(&payload[..split]);
                if matches!(first, StreamingWafDecision::Block(..)) {
                    continue;
                }
                let second = streaming.scan_chunk(&payload[split..]);
                assert!(
                    matches!(second, StreamingWafDecision::Block(..)),
                    "split attack must be caught across chunks: {payload:?} @ {split}"
                );
            }
        }
    }

    /// Phase 54: the trailing window stays bounded and prefix-free over many
    /// benign chunks (the old clear-then-append pattern grew it unboundedly).
    #[test]
    fn test_streaming_window_stays_bounded() {
        use crate::attack_detection::AttackDetectionConfig;

        let config = AttackDetectionConfig::default();
        let detector = AttackDetector::new(config);
        let mut streaming = StreamingWafCore::new(Arc::new(detector));

        let chunk = vec![b'a'; 512];
        for _ in 0..32 {
            let result = streaming.scan_chunk(&chunk);
            assert!(matches!(result, StreamingWafDecision::Continue));
        }
        assert!(
            streaming.state.trailing_window.len() <= super::TRAILING_WINDOW_SIZE,
            "trailing window must stay bounded"
        );
        assert!(
            streaming
                .state
                .trailing_window
                .as_slice()
                .iter()
                .all(|b| *b == b'a'),
            "trailing window must contain only real trailing bytes"
        );
    }

    fn multipart_streaming() -> StreamingWafCore {
        use crate::attack_detection::AttackDetectionConfig;

        let config = AttackDetectionConfig::default();
        let detector = AttackDetector::new(config);
        StreamingWafCore::new(Arc::new(detector))
    }

    type MultipartPart<'a> = (&'a str, Option<&'a str>, Option<&'a str>, &'a [u8]);

    fn multipart_body(boundary: &str, parts: &[MultipartPart<'_>]) -> Vec<u8> {
        let mut body = Vec::new();
        for (name, filename, content_type, value) in parts {
            body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
            match filename {
                Some(fname) => {
                    body.extend_from_slice(
                        format!("Content-Disposition: form-data; name=\"{name}\"; filename=\"{fname}\"\r\n")
                            .as_bytes(),
                    );
                    if let Some(ct) = content_type {
                        body.extend_from_slice(format!("Content-Type: {ct}\r\n").as_bytes());
                    }
                }
                None => {
                    body.extend_from_slice(
                        format!("Content-Disposition: form-data; name=\"{name}\"\r\n").as_bytes(),
                    );
                }
            }
            body.extend_from_slice(b"\r\n");
            body.extend_from_slice(value);
            body.extend_from_slice(b"\r\n");
        }
        body.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
        body
    }

    #[test]
    fn test_multipart_framing_alone_passes() {
        let mut streaming = multipart_streaming();
        let body = multipart_body(
            "TESTBOUNDARY123",
            &[
                ("csrf_token", None, None, b"abcdef0123456789"),
                ("title", None, None, b"A benign post"),
                ("body", None, None, b"Just some ordinary text."),
                ("tags", None, None, b"test"),
            ],
        );
        let result = streaming.scan_chunk(&body);
        assert!(
            matches!(result, StreamingWafDecision::Continue),
            "benign multipart framing must not match body patterns: {result:?}"
        );
    }

    #[test]
    fn test_multipart_binary_file_bytes_skipped() {
        let mut streaming = multipart_streaming();
        let mut binary = vec![0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a];
        binary.extend_from_slice(b"\x24\x7b\x7d\x7d\x23\x7b\x25\x7dname=\x25\x3e");
        binary.extend_from_slice(&[0xff, 0xd8, 0x00, 0x10, 0x4a, 0x46]);
        let body = multipart_body(
            "TESTBOUNDARY123",
            &[
                ("csrf_token", None, None, b"abcdef0123456789"),
                ("image", Some("photo.png"), Some("image/png"), &binary),
            ],
        );
        let result = streaming.scan_chunk(&body);
        assert!(
            matches!(result, StreamingWafDecision::Continue),
            "binary file bytes must not match text patterns: {result:?}"
        );
    }

    #[test]
    fn test_multipart_text_file_still_scanned() {
        let mut streaming = multipart_streaming();
        let body = multipart_body(
            "TESTBOUNDARY123",
            &[(
                "image",
                Some("evil.svg"),
                Some("image/svg+xml"),
                b"<svg><script>alert(1)</script></svg>",
            )],
        );
        let result = streaming.scan_chunk(&body);
        assert!(
            matches!(result, StreamingWafDecision::Block(..)),
            "text file parts must still be scanned: {result:?}"
        );
    }

    #[test]
    fn test_multipart_field_value_still_scanned() {
        let mut streaming = multipart_streaming();
        let body = multipart_body(
            "TESTBOUNDARY123",
            &[("body", None, None, b"hello {{7*7}} world")],
        );
        let result = streaming.scan_chunk(&body);
        assert!(
            matches!(result, StreamingWafDecision::Block(..)),
            "text field values must still be scanned: {result:?}"
        );
    }

    #[test]
    fn test_multipart_filename_scanned() {
        let mut streaming = multipart_streaming();
        let body = multipart_body(
            "TESTBOUNDARY123",
            &[(
                "image",
                Some("../../etc/passwd"),
                Some("image/png"),
                b"fake-bytes",
            )],
        );
        let result = streaming.scan_chunk(&body);
        assert!(
            matches!(result, StreamingWafDecision::Block(..)),
            "filenames must still be scanned: {result:?}"
        );
    }

    #[test]
    fn test_multipart_evil_field_name_blocked() {
        let mut streaming = multipart_streaming();
        let body = multipart_body(
            "TESTBOUNDARY123",
            &[("{{7*7}}", None, None, b"benign value")],
        );
        let result = streaming.scan_chunk(&body);
        assert!(
            matches!(result, StreamingWafDecision::Block(..)),
            "attacker-controlled field names must still be scanned: {result:?}"
        );
    }

    #[test]
    fn test_multipart_split_chunks_pass() {
        let body = multipart_body(
            "TESTBOUNDARY123",
            &[
                ("csrf_token", None, None, b"abcdef0123456789"),
                ("title", None, None, b"A benign post"),
                ("body", None, None, b"Just some ordinary text."),
            ],
        );
        for split in [1, 2, 3, 7, 13, 29, 64] {
            let mut streaming = multipart_streaming();
            let mut pos = 0;
            let mut blocked = false;
            while pos < body.len() {
                let end = (pos + split).min(body.len());
                if matches!(
                    streaming.scan_chunk(&body[pos..end]),
                    StreamingWafDecision::Block(..)
                ) {
                    blocked = true;
                    break;
                }
                pos = end;
            }
            assert!(!blocked, "benign multipart must pass at split {split}");
        }
    }

    #[test]
    fn test_sniff_fallback_scans_non_multipart() {
        let mut streaming = multipart_streaming();
        let result = streaming.scan_chunk(b"just some plain text");
        assert!(
            matches!(result, StreamingWafDecision::Continue),
            "benign non-multipart bodies pass: {result:?}"
        );
        let mut streaming = multipart_streaming();
        let result = streaming.scan_chunk(b"-- not multipart at all\r\nmore text");
        assert!(
            matches!(result, StreamingWafDecision::Block(..)),
            "rejected sniff input still gets a regular scan: {result:?}"
        );
    }

    #[test]
    fn test_sniff_deferred_first_line() {
        let mut streaming = multipart_streaming();
        let first = streaming.scan_chunk(b"--TESTBOUND");
        assert!(matches!(first, StreamingWafDecision::Continue));
        let body = multipart_body("TESTBOUNDARY123", &[("a", None, None, b"b")]);
        let rest_start = b"--TESTBOUND".len();
        let second = streaming.scan_chunk(&body[rest_start..]);
        assert!(
            matches!(second, StreamingWafDecision::Continue),
            "split boundary head must still parse: {second:?}"
        );
    }

    #[test]
    fn test_multipart_split_after_headers_passes() {
        let body = multipart_body(
            "TESTBOUNDARY123",
            &[
                ("csrf_token", None, None, b"abcdef0123456789"),
                ("title", None, None, b"A benign post"),
                ("body", None, None, b"Just some ordinary text."),
            ],
        );
        let raw = String::from_utf8_lossy(&body);
        let mut offsets = Vec::new();
        let mut search_from = 0;
        while let Some(rel) = raw[search_from..].find("\r\n\r\n") {
            let header_end = search_from + rel + 4;
            for k in 0..=48 {
                if header_end + k < body.len() {
                    offsets.push(header_end + k);
                }
            }
            search_from = header_end;
        }
        assert!(!offsets.is_empty());
        for split in offsets {
            let mut streaming = multipart_streaming();
            let first = streaming.scan_chunk(&body[..split]);
            assert!(
                matches!(first, StreamingWafDecision::Continue),
                "head must pass at split {split}: {first:?}"
            );
            let second = streaming.scan_chunk(&body[split..]);
            assert!(
                matches!(second, StreamingWafDecision::Continue),
                "framing bytes must never be scanned as values (split {split}): {second:?}"
            );
        }
    }

    #[test]
    fn test_log_only_allows_attack_body() {
        let mut streaming = multipart_streaming();
        streaming.set_log_only(true);
        let body = multipart_body(
            "TESTBOUNDARY123",
            &[
                ("title", None, None, b"look at this {{7*7}} page=2"),
                (
                    "image",
                    Some("photo.png"),
                    Some("image/png"),
                    b"\x89PNG\r\n${evil} name=",
                ),
            ],
        );
        let result = streaming.scan_chunk(&body);
        assert!(
            matches!(result, StreamingWafDecision::Continue),
            "log-only must allow attack-pattern bodies: {result:?}"
        );
        assert!(streaming.state.log_only_allowed);
        let again = streaming.scan_chunk(b"{{7*7}} ${evil}");
        assert!(
            matches!(again, StreamingWafDecision::Continue),
            "log-only skips further scans after first downgrade: {again:?}"
        );
    }

    #[test]
    fn test_log_only_keeps_size_limit() {
        let mut streaming = multipart_streaming();
        streaming.set_log_only(true);
        streaming.max_buffered_bytes = 12;
        streaming.scan_chunk(b"chunk1");
        streaming.scan_chunk(b"chunk2");
        let result = streaming.scan_chunk(b"chunk3");
        assert!(
            matches!(result, StreamingWafDecision::Block(413, _)),
            "log-only must keep the byte-limit block: {result:?}"
        );
    }

    #[test]
    fn test_log_only_off_blocks() {
        let mut streaming = multipart_streaming();
        let body = multipart_body(
            "TESTBOUNDARY123",
            &[("body", None, None, b"hello {{7*7}} world")],
        );
        let result = streaming.scan_chunk(&body);
        assert!(matches!(result, StreamingWafDecision::Block(..)));
    }

    #[test]
    fn test_multipart_value_attack_after_header_split_blocked() {
        let body = multipart_body(
            "TESTBOUNDARY123",
            &[
                ("csrf_token", None, None, b"abcdef0123456789"),
                ("body", None, None, b"prefix {{7*7}} suffix"),
            ],
        );
        let raw = String::from_utf8_lossy(&body);
        let header_end = raw.find("\r\n\r\n").unwrap() + 4;
        let split = header_end + 3;
        let mut streaming = multipart_streaming();
        let first = streaming.scan_chunk(&body[..split]);
        assert!(matches!(first, StreamingWafDecision::Continue));
        let second = streaming.scan_chunk(&body[split..]);
        assert!(
            matches!(second, StreamingWafDecision::Block(..)),
            "value attacks must still be caught across header splits: {second:?}"
        );
    }

    fn big_benign_body(size: usize) -> Vec<u8> {
        let boundary = "TESTBOUNDARY123";
        let mut body = multipart_body(boundary, &[("f", None, None, b"")]);
        body.truncate(body.len() - format!("--{boundary}--\r\n").len());
        let fill = vec![b'a'; size];
        body.extend_from_slice(&fill);
        body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
        body
    }

    fn scan_all(streaming: &mut StreamingWafCore, body: &[u8]) -> StreamingWafDecision {
        let mut off = 0;
        let mut verdict = StreamingWafDecision::Continue;
        while off < body.len() {
            let end = (off + 16384).min(body.len());
            verdict = streaming.scan_chunk(&body[off..end]);
            if matches!(verdict, StreamingWafDecision::Block(..)) {
                break;
            }
            off = end;
        }
        verdict
    }

    #[test]
    fn test_body_cap_follows_detector_config() {
        let mut streaming = multipart_streaming();
        let body = big_benign_body(3 * 1024 * 1024);
        let result = scan_all(&mut streaming, &body);
        assert!(
            matches!(result, StreamingWafDecision::Continue),
            "default 10MB cap must admit a 3MB benign body: {result:?}"
        );
    }

    #[test]
    fn test_body_cap_respects_small_config() {
        use crate::attack_detection::{AttackDetectionConfig, AttackDetector};

        let config = AttackDetectionConfig {
            max_request_body_size: Some(100),
            ..Default::default()
        };
        let mut streaming = StreamingWafCore::new(std::sync::Arc::new(AttackDetector::new(config)));
        let body = big_benign_body(1024);
        let result = scan_all(&mut streaming, &body);
        assert!(
            matches!(result, StreamingWafDecision::Block(413, _)),
            "configured cap must still bound the scan: {result:?}"
        );
    }

    #[test]
    fn test_body_cap_none_falls_back_to_default() {
        use crate::attack_detection::{AttackDetectionConfig, AttackDetector};

        let config = AttackDetectionConfig {
            max_request_body_size: None,
            ..Default::default()
        };
        let mut streaming = StreamingWafCore::new(std::sync::Arc::new(AttackDetector::new(config)));
        let body = big_benign_body(3 * 1024 * 1024);
        let result = scan_all(&mut streaming, &body);
        assert!(
            matches!(result, StreamingWafDecision::Block(413, _)),
            "unset cap must fall back to the built-in bound: {result:?}"
        );
    }
}
