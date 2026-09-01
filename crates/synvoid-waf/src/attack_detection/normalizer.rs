use std::borrow::Cow;
use std::cell::RefCell;
use std::sync::{Arc, OnceLock};
use synvoid_utils::buffer::pool::{BufferPool, PooledBuf};
use unicode_normalization::UnicodeNormalization;

const MAX_OUTPUT_RATIO: usize = 100;

use bitflags::bitflags;

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
    pub struct NormalizationFlags: u32 {
        const NONE = 0;
        const NULL_BYTE = 1 << 0;
        const ZERO_WIDTH = 1 << 1;
        const HOMOGLYPH = 1 << 2;
        const DOUBLE_ENCODING = 1 << 3;
        const INVALID_UTF8 = 1 << 4;
        const UNICODE_NORMALIZED = 1 << 5;
        const OVERLONG = 1 << 6;
        const OUTPUT_LIMIT = 1 << 7;
    }
}

thread_local! {
    static NORMALIZE_BUFFER: RefCell<String> = RefCell::new(String::with_capacity(4096));
    static NORMALIZE_CHARS: RefCell<Vec<char>> = RefCell::new(Vec::with_capacity(4096));
    static FRAGMENT_MERGE_BUFFER: RefCell<Vec<u8>> = RefCell::new(Vec::with_capacity(8192));
    static NORMALIZATION_FLAGS: RefCell<NormalizationFlags> = const { RefCell::new(NormalizationFlags::NONE) };
}

#[inline]
fn hex_char_to_nibble(c: char) -> Option<u8> {
    match c {
        '0'..='9' => Some(c as u8 - b'0'),
        'a'..='f' => Some(c as u8 - b'a' + 10),
        'A'..='F' => Some(c as u8 - b'A' + 10),
        _ => None,
    }
}

#[inline]
fn hex_chars_to_u32(chars: &[char]) -> Option<u32> {
    if chars.len() > 8 {
        return None;
    }
    let mut result = 0u32;
    for &c in chars {
        result = result << 4 | hex_char_to_nibble(c)? as u32;
    }
    Some(result)
}

#[inline]
fn hex_chars_to_u8(chars: &[char]) -> Option<u8> {
    if chars.len() < 2 {
        return None;
    }
    let high = hex_char_to_nibble(chars[0])?;
    let low = hex_char_to_nibble(chars[1])?;
    Some((high << 4) | low)
}

#[derive(Clone)]
pub struct InputNormalizer {
    max_decode_passes: usize,
}

impl Default for InputNormalizer {
    fn default() -> Self {
        Self {
            max_decode_passes: 10,
        }
    }
}

impl InputNormalizer {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn normalize<'a>(&self, input: &'a str) -> NormalizedInput<'a> {
        NORMALIZE_BUFFER.with(|buf_cell| {
            NORMALIZE_CHARS.with(|chars_cell| {
                NORMALIZATION_FLAGS.with(|flags_cell| {
                    *flags_cell.borrow_mut() = NormalizationFlags::NONE;
                    let mut buffer = buf_cell.borrow_mut();
                    let mut chars = chars_cell.borrow_mut();
                    let mut ni = self.normalize_internal(input, &mut buffer, &mut chars);
                    ni.flags = *flags_cell.borrow();
                    ni
                })
            })
        })
    }

    pub fn normalize_fragments(&self, fragments: &[&[u8]]) -> NormalizedInput<'static> {
        FRAGMENT_MERGE_BUFFER.with(|merge_cell| {
            let mut merge_buf = merge_cell.borrow_mut();
            merge_buf.clear();
            for frag in fragments {
                merge_buf.extend_from_slice(frag);
            }

            let input_str = String::from_utf8_lossy(&merge_buf);
            let has_invalid_utf8 = matches!(input_str, Cow::Owned(_));

            NORMALIZE_BUFFER.with(|buf_cell| {
                NORMALIZE_CHARS.with(|chars_cell| {
                    NORMALIZATION_FLAGS.with(|flags_cell| {
                        *flags_cell.borrow_mut() = if has_invalid_utf8 {
                            NormalizationFlags::INVALID_UTF8
                        } else {
                            NormalizationFlags::NONE
                        };
                        let mut buffer = buf_cell.borrow_mut();
                        let mut chars = chars_cell.borrow_mut();
                        let ni = self.normalize_internal(&input_str, &mut buffer, &mut chars);
                        let normalized_data = match ni.normalized {
                            NormalizedData::Borrowed(s) => {
                                let mut pooled = BufferPool::acquire(s.len());
                                pooled.extend_from_slice(s.as_bytes());
                                NormalizedData::pooled(pooled)
                            }
                            NormalizedData::Pooled { buf, lossy } => {
                                NormalizedData::Pooled { buf, lossy }
                            }
                            NormalizedData::Owned(o) => NormalizedData::Owned(o),
                        };
                        NormalizedInput {
                            normalized: normalized_data,
                            passes: ni.passes,
                            flags: *flags_cell.borrow(),
                        }
                    })
                })
            })
        })
    }

    fn normalize_internal<'a>(
        &self,
        input: &'a str,
        buffer: &mut String,
        chars: &mut Vec<char>,
    ) -> NormalizedInput<'a> {
        buffer.clear();
        chars.clear();

        let mut total_passes = 0;
        let max_output = input.len().saturating_mul(MAX_OUTPUT_RATIO);
        let mut output_limited = false;

        buffer.push_str(input);

        for _ in 0..self.max_decode_passes {
            let prev_len = buffer.len();
            let prev_content = buffer.clone();
            chars.clear();
            chars.extend(buffer.chars());
            buffer.clear();
            let decoded_len = self.decode_single_pass_with_chars(buffer, chars);

            if decoded_len == prev_len && buffer.as_str() == prev_content {
                break;
            }

            total_passes += 1;

            if decoded_len > max_output {
                *buffer = prev_content;
                output_limited = true;
                break;
            }
        }

        if total_passes > 1 {
            NORMALIZATION_FLAGS.with(|f| {
                let mut flags = f.borrow_mut();
                *flags |= NormalizationFlags::DOUBLE_ENCODING;
            });
        }

        chars.clear();
        chars.extend(buffer.chars());
        buffer.clear();
        self.apply_normalizations_with_chars(buffer, chars);

        if buffer.len() > max_output {
            buffer.clear();
            buffer.push_str(input);
            output_limited = true;
        } else {
            // NFKC normalization can create new percent-encoding sequences
            // (e.g., %b2 → ² → NFKC → 2, forming %02 with preceding literal).
            // Run one additional decode pass to handle them.
            let post_norm = buffer.clone();
            chars.clear();
            chars.extend(post_norm.chars());
            buffer.clear();
            self.decode_single_pass_with_chars(buffer, chars);

            if buffer.len() > max_output {
                *buffer = post_norm;
                output_limited = true;
            }
        }

        if output_limited {
            NORMALIZATION_FLAGS.with(|f| f.borrow_mut().insert(NormalizationFlags::OUTPUT_LIMIT));
        }

        let normalized = if buffer.as_str() == input {
            NormalizedData::Borrowed(input)
        } else {
            let mut pooled = BufferPool::acquire(buffer.len());
            pooled.as_mut_slice().copy_from_slice(buffer.as_bytes());
            NormalizedData::pooled(pooled)
        };

        NormalizedInput {
            normalized,
            passes: total_passes,
            flags: NormalizationFlags::NONE, // Will be set by caller
        }
    }

    fn decode_single_pass_with_chars(&self, input: &mut String, chars: &mut [char]) -> usize {
        let mut i = 0;
        while i < chars.len() {
            match chars[i] {
                '%' => {
                    if i + 5 < chars.len() && chars[i + 1] == 'u' {
                        if let Some(code_point) = hex_chars_to_u32(&chars[i + 2..i + 6]) {
                            if code_point == 0 {
                                NORMALIZATION_FLAGS
                                    .with(|f| f.borrow_mut().insert(NormalizationFlags::NULL_BYTE));
                            } else {
                                if let Some(ch) = char::from_u32(code_point) {
                                    input.push(ch);
                                }
                            }
                            i += 6;
                            continue;
                        }
                    }
                    if i + 2 < chars.len() {
                        if let Some(byte) = hex_chars_to_u8(&chars[i + 1..i + 3]) {
                            if byte == 0 {
                                NORMALIZATION_FLAGS
                                    .with(|f| f.borrow_mut().insert(NormalizationFlags::NULL_BYTE));
                            } else if (0xC0..=0xFD).contains(&byte) {
                                // Potential overlong UTF-8 start byte.
                                // Try to decode the full overlong sequence and map
                                // to the intended ASCII character if the decoded
                                // codepoint falls in the ASCII range (0x00-0x7F).
                                let (decoded_char, bytes_consumed) =
                                    Self::decode_overlong_sequence(chars, i, byte);
                                if let Some(ch) = decoded_char {
                                    input.push(ch);
                                } else {
                                    input.push(byte as char);
                                }
                                i += bytes_consumed;
                                continue;
                            } else {
                                input.push(byte as char);
                            }
                            i += 3;
                            continue;
                        }
                    }
                    input.push('%');
                    i += 1;
                }
                '+' => {
                    input.push(' ');
                    i += 1;
                }
                '\\' => {
                    if i + 1 < chars.len() {
                        match chars[i + 1] {
                            'x' | 'X' => {
                                if i + 3 < chars.len() {
                                    if let Some(byte) = hex_chars_to_u8(&chars[i + 2..i + 4]) {
                                        if byte == 0 {
                                            NORMALIZATION_FLAGS.with(|f| {
                                                f.borrow_mut().insert(NormalizationFlags::NULL_BYTE)
                                            });
                                        } else {
                                            input.push(byte as char);
                                        }
                                        i += 4;
                                        continue;
                                    }
                                }
                                input.push_str("\\x");
                                i += 2;
                                continue;
                            }
                            'u' | 'U' => {
                                if i + 5 < chars.len() {
                                    if let Some(code_point) = hex_chars_to_u32(&chars[i + 2..i + 6])
                                    {
                                        if code_point == 0 {
                                            NORMALIZATION_FLAGS.with(|f| {
                                                f.borrow_mut().insert(NormalizationFlags::NULL_BYTE)
                                            });
                                        } else {
                                            if let Some(ch) = char::from_u32(code_point) {
                                                input.push(ch);
                                            }
                                        }
                                        i += 6;
                                        continue;
                                    }
                                }
                                input.push_str("\\u");
                                i += 2;
                                continue;
                            }
                            'n' => {
                                input.push('\n');
                                i += 2;
                                continue;
                            }
                            'r' => {
                                input.push('\r');
                                i += 2;
                                continue;
                            }
                            't' => {
                                input.push('\t');
                                i += 2;
                                continue;
                            }
                            '0'..='7' => {
                                let mut octal = String::new();
                                let mut j = i + 1;
                                while j < chars.len()
                                    && j < i + 4
                                    && chars[j] >= '0'
                                    && chars[j] <= '7'
                                {
                                    octal.push(chars[j]);
                                    j += 1;
                                }
                                if !octal.is_empty() {
                                    if let Ok(byte) = u8::from_str_radix(&octal, 8) {
                                        if byte == 0 {
                                            NORMALIZATION_FLAGS.with(|f| {
                                                f.borrow_mut().insert(NormalizationFlags::NULL_BYTE)
                                            });
                                        } else {
                                            input.push(byte as char);
                                        }
                                        i = j;
                                        continue;
                                    }
                                }
                            }
                            _ => {}
                        }
                    }
                    input.push('\\');
                    i += 1;
                }
                '&' => {
                    let mut entity_chars = String::new();
                    let mut found_semicolon = false;
                    let mut j = i + 1;

                    for _ in 0..10 {
                        if j >= chars.len() {
                            break;
                        }
                        if chars[j] == ';' {
                            found_semicolon = true;
                            j += 1;
                            break;
                        }
                        entity_chars.push(chars[j]);
                        j += 1;
                    }

                    if found_semicolon {
                        if let Some(ch) = self.decode_html_entity_simple(&entity_chars) {
                            if ch == '\0' {
                                NORMALIZATION_FLAGS
                                    .with(|f| f.borrow_mut().insert(NormalizationFlags::NULL_BYTE));
                            } else {
                                input.push(ch);
                            }
                            i = j;
                            continue;
                        }
                    }

                    input.push('&');
                    input.push_str(&entity_chars);
                    if found_semicolon {
                        input.push(';');
                    }
                    i = j;
                }
                '\0' => {
                    NORMALIZATION_FLAGS
                        .with(|f| f.borrow_mut().insert(NormalizationFlags::NULL_BYTE));
                    i += 1;
                }
                c => {
                    input.push(c);
                    i += 1;
                }
            }
        }

        input.len()
    }

    /// Decode an overlong UTF-8 percent-encoded sequence starting at position `start`.
    ///
    /// Overlong encodings use extra bytes to represent codepoints that should fit
    /// in fewer bytes. For example, `>` (U+003E) can be overlong-encoded as `%C0%BE`
    /// instead of the canonical `%3E`. The function also detects non-ASCII overlongs
    /// (e.g. a 3-byte encoding of `é` which canonically fits in 2 bytes) and flags
    /// `NormalizationFlags::OVERLONG` only when the decoded codepoint is below the
    /// minimal value for the byte length.
    ///
    /// Returns `(decoded_char, total_chars_consumed)` where `total_chars_consumed`
    /// includes the initial `%XX` at `start`. If the sequence is not a valid
    /// multi-byte UTF-8 encoding, returns `(None, 3)` (consumes only the initial
    /// percent-encoded byte).
    fn decode_overlong_sequence(
        chars: &[char],
        start: usize,
        first_byte: u8,
    ) -> (Option<char>, usize) {
        // Determine the expected number of bytes from the start byte.
        let expected_bytes = if first_byte & 0xE0 == 0xC0 {
            2
        } else if first_byte & 0xF0 == 0xE0 {
            3
        } else if first_byte & 0xF8 == 0xF0 {
            4
        } else {
            // 0xF8-0xFD are not valid UTF-8 start bytes at all.
            return (None, 3);
        };

        let mut bytes = vec![first_byte];
        let mut pos = start + 3; // skip the initial %XX

        for _ in 1..expected_bytes {
            // Expect '%' followed by two hex digits.
            if pos + 2 >= chars.len() {
                return (None, 3);
            }
            if chars[pos] != '%' {
                return (None, 3);
            }
            if let Some(byte) = hex_chars_to_u8(&chars[pos + 1..pos + 3]) {
                if byte & 0xC0 != 0x80 {
                    // Not a continuation byte.
                    return (None, 3);
                }
                bytes.push(byte);
                pos += 3;
            } else {
                return (None, 3);
            }
        }

        // Decode the codepoint from the multi-byte sequence.
        let codepoint = match bytes.len() {
            2 => ((bytes[0] & 0x1F) as u32) << 6 | (bytes[1] & 0x3F) as u32,
            3 => {
                ((bytes[0] & 0x0F) as u32) << 12
                    | ((bytes[1] & 0x3F) as u32) << 6
                    | (bytes[2] & 0x3F) as u32
            }
            4 => {
                ((bytes[0] & 0x07) as u32) << 18
                    | ((bytes[1] & 0x3F) as u32) << 12
                    | ((bytes[2] & 0x3F) as u32) << 6
                    | (bytes[3] & 0x3F) as u32
            }
            _ => return (None, 3),
        };

        // Flag overlong only when the codepoint could have been encoded with
        // fewer bytes than were used. Minimal byte lengths per RFC 3629:
        //  2 bytes => U+0080 minimum, 3 bytes => U+0800, 4 bytes => U+10000.
        let is_overlong = match bytes.len() {
            2 => codepoint < 0x80,
            3 => codepoint < 0x800,
            4 => codepoint < 0x10000,
            _ => false,
        };
        if is_overlong {
            NORMALIZATION_FLAGS.with(|f| {
                f.borrow_mut().insert(NormalizationFlags::OVERLONG);
            });
        }
        (char::from_u32(codepoint), pos - start)
    }

    fn decode_html_entity_simple(&self, entity: &str) -> Option<char> {
        if let Some(rest) = entity.strip_prefix('#') {
            if rest.starts_with('x') || rest.starts_with('X') {
                let hex = &rest[1..];
                if let Ok(code) = u32::from_str_radix(hex, 16) {
                    return char::from_u32(code);
                }
            } else if let Ok(code) = rest.parse::<u32>() {
                return char::from_u32(code);
            }
            return None;
        }

        Some(match entity {
            "lt" => '<',
            "gt" => '>',
            "amp" => '&',
            "quot" => '"',
            "apos" => '\'',
            "nbsp" => '\u{00a0}',
            "copy" => '\u{00a9}',
            "reg" => '\u{00ae}',
            "trade" => '\u{2122}',
            "hellip" => '\u{2026}',
            "ndash" => '\u{2013}',
            "mdash" => '\u{2014}',
            "lsquo" => '\u{2018}',
            "rsquo" => '\u{2019}',
            "ldquo" => '\u{201C}',
            "rdquo" => '\u{201D}',
            "bullet" => '\u{2022}',
            "prime" => '\u{2032}',
            "Prime" => '\u{2033}',
            "oline" => '\u{203E}',
            "frasl" => '\u{2044}',
            "euro" => '\u{20AC}',
            "prod" => '\u{220F}',
            "sum" => '\u{2211}',
            "radic" => '\u{221A}',
            "infin" => '\u{221E}',
            "approx" => '\u{2248}',
            "ne" => '\u{2260}',
            "le" => '\u{2264}',
            "ge" => '\u{2265}',
            "times" => '\u{00D7}',
            "divide" => '\u{00F7}',
            "circ" => '\u{02C6}',
            "tilde" => '\u{02DC}',
            "colon" => ':',
            "Tab" => '\t',
            "NewLine" => '\n',
            _ => return None,
        })
    }

    fn apply_normalizations_with_chars(&self, input: &mut String, chars: &mut [char]) {
        for c in chars.iter() {
            if matches!(c,
                '\u{200B}' | '\u{200C}' | '\u{200D}' | '\u{200E}' | '\u{200F}' |
                '\u{FEFF}' | '\u{2060}' | '\u{2061}' | '\u{2062}' | '\u{2063}' |
                '\u{2064}' | '\u{206A}' | '\u{206B}' | '\u{206C}' | '\u{206D}' |
                '\u{206E}' | '\u{206F}' | '\u{034F}' | '\u{180E}' |
                '\u{FE00}'..='\u{FE0F}' | '\u{E0100}'..='\u{E01EF}'
            ) {
                NORMALIZATION_FLAGS.with(|f| f.borrow_mut().insert(NormalizationFlags::ZERO_WIDTH));
                continue;
            }

            if *c == '\0' {
                NORMALIZATION_FLAGS.with(|f| f.borrow_mut().insert(NormalizationFlags::NULL_BYTE));
                continue;
            }

            let normalized = match c {
                '\u{0430}' => Some('a'),
                '\u{0410}' => Some('A'),
                '\u{0435}' => Some('e'),
                '\u{0415}' => Some('E'),
                '\u{043E}' => Some('o'),
                '\u{041E}' => Some('O'),
                '\u{0440}' => Some('p'),
                '\u{0420}' => Some('P'),
                '\u{0441}' => Some('c'),
                '\u{0421}' => Some('C'),
                '\u{0443}' => Some('y'),
                '\u{0423}' => Some('Y'),
                '\u{0445}' => Some('x'),
                '\u{0425}' => Some('X'),
                '\u{0456}' => Some('i'),
                '\u{0406}' => Some('I'),
                '\u{0458}' => Some('j'),
                '\u{0408}' => Some('J'),
                '\u{04BB}' => Some('h'),
                '\u{04B2}' => Some('H'),
                '\u{0432}' => Some('v'),
                '\u{0412}' => Some('V'),
                '\u{043C}' => Some('m'),
                '\u{041C}' => Some('M'),
                '\u{043D}' => Some('n'),
                '\u{041D}' => Some('N'),
                '\u{043A}' => Some('k'),
                '\u{041A}' => Some('K'),
                '\u{0442}' => Some('t'),
                '\u{0422}' => Some('T'),
                '\u{2010}' | '\u{2011}' | '\u{2012}' | '\u{2013}' | '\u{2014}' | '\u{2015}' => {
                    Some('-')
                }
                '\u{2018}' | '\u{2019}' | '\u{201A}' | '\u{201B}' => Some('\''),
                '\u{201C}' | '\u{201D}' | '\u{201E}' | '\u{201F}' => Some('"'),
                '\u{00A0}' => Some(' '),
                '\u{2028}' | '\u{2029}' => Some(' '),
                '\u{FF01}' => Some('!'),
                '\u{FF02}' => Some('"'),
                '\u{FF03}' => Some('#'),
                '\u{FF04}' => Some('$'),
                '\u{FF05}' => Some('%'),
                '\u{FF06}' => Some('&'),
                '\u{FF07}' => Some('\''),
                '\u{FF08}' => Some('('),
                '\u{FF09}' => Some(')'),
                '\u{FF0A}' => Some('*'),
                '\u{FF0B}' => Some('+'),
                '\u{FF0C}' => Some(','),
                '\u{FF0D}' => Some('-'),
                '\u{FF0E}' => Some('.'),
                '\u{FF0F}' => Some('/'),
                '\u{FF10}'..='\u{FF19}' => {
                    let offset = *c as u32 - 0xFF10;
                    char::from_u32(0x30 + offset)
                }
                '\u{FF1A}' => Some(':'),
                '\u{FF1B}' => Some(';'),
                '\u{FF1C}' => Some('<'),
                '\u{FF1D}' => Some('='),
                '\u{FF1E}' => Some('>'),
                '\u{FF1F}' => Some('?'),
                '\u{FF20}' => Some('@'),
                '\u{FF21}'..='\u{FF3A}' => {
                    let offset = *c as u32 - 0xFF21;
                    char::from_u32(0x41 + offset)
                }
                '\u{FF3B}' => Some('['),
                '\u{FF3C}' => Some('\\'),
                '\u{FF3D}' => Some(']'),
                '\u{FF3E}' => Some('^'),
                '\u{FF3F}' => Some('_'),
                '\u{FF40}' => Some('`'),
                '\u{FF41}'..='\u{FF5A}' => {
                    let offset = *c as u32 - 0xFF41;
                    char::from_u32(0x61 + offset)
                }
                '\u{FF5B}' => Some('{'),
                '\u{FF5C}' => Some('|'),
                '\u{FF5D}' => Some('}'),
                '\u{FF5E}' => Some('~'),
                '\u{03B1}' => Some('a'),
                '\u{0391}' => Some('A'),
                '\u{03C4}' => Some('t'),
                '\u{03A4}' => Some('T'),
                '\u{03BF}' => Some('o'),
                '\u{039F}' => Some('O'),
                '\u{03B9}' => Some('i'),
                '\u{0399}' => Some('I'),
                '\u{03BD}' => Some('v'),
                '\u{039D}' => Some('N'),
                _ => Some(*c),
            };

            if let Some(n) = normalized {
                if n != *c {
                    NORMALIZATION_FLAGS
                        .with(|f| f.borrow_mut().insert(NormalizationFlags::HOMOGLYPH));
                }
                if n.is_whitespace() {
                    input.push(' ');
                } else if n.is_ascii() {
                    input.push(n);
                } else {
                    NORMALIZATION_FLAGS.with(|f| {
                        f.borrow_mut()
                            .insert(NormalizationFlags::UNICODE_NORMALIZED)
                    });
                    let nfkc: Cow<'_, str> = n.nfkc().collect();
                    input.push_str(&nfkc);
                }
            }
        }
    }
}

#[derive(Debug)]
pub enum NormalizedData<'a> {
    Borrowed(&'a str),
    Owned(String),
    Pooled {
        buf: PooledBuf,
        lossy: OnceLock<String>,
    },
}

impl<'a> Clone for NormalizedData<'a> {
    fn clone(&self) -> Self {
        match self {
            Self::Borrowed(s) => Self::Borrowed(s),
            Self::Owned(s) => Self::Owned(s.clone()),
            Self::Pooled { buf, lossy } => {
                let mut new_buf = BufferPool::acquire(buf.len());
                new_buf.extend_from_slice(buf.as_slice());
                let new_lossy = OnceLock::new();
                if let Some(value) = lossy.get() {
                    let _ = new_lossy.set(value.clone());
                }
                Self::Pooled {
                    buf: new_buf,
                    lossy: new_lossy,
                }
            }
        }
    }
}

impl<'a> Default for NormalizedData<'a> {
    fn default() -> Self {
        Self::Borrowed("")
    }
}

impl<'a> NormalizedData<'a> {
    fn pooled(buf: PooledBuf) -> Self {
        Self::Pooled {
            buf,
            lossy: OnceLock::new(),
        }
    }

    pub fn as_str(&self) -> &str {
        match self {
            Self::Borrowed(s) => s,
            Self::Owned(ref s) => s.as_str(),
            Self::Pooled { buf, lossy } => {
                std::str::from_utf8(buf.as_slice()).unwrap_or_else(|_| {
                    lossy
                        .get_or_init(|| String::from_utf8_lossy(buf.as_slice()).into_owned())
                        .as_str()
                })
            }
        }
    }
}

impl<'a> std::fmt::Display for NormalizedData<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

#[derive(Debug, Clone, Default)]
pub struct NormalizedInput<'a> {
    pub normalized: NormalizedData<'a>,
    pub passes: usize,
    pub flags: NormalizationFlags,
}

impl<'a> std::fmt::Display for NormalizedInput<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.normalized)
    }
}

impl<'a> AsRef<str> for NormalizedInput<'a> {
    fn as_ref(&self) -> &str {
        self.normalized.as_str()
    }
}

impl<'a> NormalizedInput<'a> {
    pub fn as_str(&self) -> &str {
        self.normalized.as_str()
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.normalized.as_str().as_bytes()
    }

    pub fn into_owned(self) -> NormalizedInput<'static> {
        let normalized = match self.normalized {
            NormalizedData::Borrowed(s) => NormalizedData::Owned(s.to_string()),
            NormalizedData::Owned(s) => NormalizedData::Owned(s),
            NormalizedData::Pooled { buf, lossy } => NormalizedData::Pooled { buf, lossy },
        };
        NormalizedInput {
            normalized,
            passes: self.passes,
            flags: self.flags,
        }
    }
}

impl<'a> NormalizedInputs<'a> {
    pub fn into_owned(self) -> NormalizedInputs<'static> {
        NormalizedInputs {
            path: self.path.map(|p| p.into_owned()),
            path_raw: self.path_raw.map(|p| Cow::Owned(p.into_owned())),
            query_string: self.query_string.map(|qs| qs.into_owned()),
            query_string_raw: self.query_string_raw.map(|qs| Cow::Owned(qs.into_owned())),
            headers: self
                .headers
                .into_iter()
                .map(|(k, v)| (k, v.into_owned()))
                .collect(),
            headers_raw: self
                .headers_raw
                .into_iter()
                .map(|(k, v)| (k, Cow::Owned(v.into_owned())))
                .collect(),
            body: self.body, // body is already static
            body_raw: self.body_raw,
            body_bytes: self.body_bytes.map(|b| Cow::Owned(b.into_owned())),
        }
    }

    pub fn all_values(&self) -> impl Iterator<Item = &str> {
        let mut values = Vec::new();
        if let Some(ref p) = self.path {
            values.push(p.as_str());
        }
        if let Some(ref qs) = self.query_string {
            values.push(qs.as_str());
        }
        for (_, v) in &self.headers {
            values.push(v.as_str());
        }
        if let Some(ref b) = self.body {
            values.push(b.as_str());
        }
        values.into_iter()
    }

    pub fn all_raw_values(&self) -> impl Iterator<Item = &str> {
        let mut values = Vec::new();
        if let Some(ref p) = self.path_raw {
            values.push(p.as_ref());
        }
        if let Some(ref qs) = self.query_string_raw {
            values.push(qs.as_ref());
        }
        for (_, v) in &self.headers_raw {
            values.push(v.as_ref());
        }
        if let Some(ref b) = self.body_raw {
            values.push(b.as_ref());
        }
        values.into_iter()
    }
}

pub struct NormalizedInputs<'a> {
    pub path: Option<NormalizedInput<'a>>,
    pub path_raw: Option<Cow<'a, str>>,
    pub query_string: Option<NormalizedInput<'a>>,
    pub query_string_raw: Option<Cow<'a, str>>,
    pub headers: Vec<(Arc<str>, NormalizedInput<'a>)>,
    pub headers_raw: Vec<(Arc<str>, Cow<'a, str>)>,
    pub body: Option<NormalizedInput<'static>>,
    pub body_raw: Option<Cow<'static, str>>,
    pub body_bytes: Option<Cow<'a, [u8]>>,
}

impl<'a> NormalizedInputs<'a> {
    pub fn normalize_all(
        normalizer: &InputNormalizer,
        path: Option<&'a str>,
        query_string: Option<&'a str>,
        headers: &'a http::HeaderMap,
        body: Option<&'a [u8]>,
    ) -> Self {
        let path_norm = path.map(|p| normalizer.normalize(p));
        let path_raw = path.map(Cow::Borrowed);

        let query_string_norm = query_string.map(|qs| normalizer.normalize(qs));
        let query_string_raw = query_string.map(Cow::Borrowed);

        let mut normalized_headers = Vec::new();
        let mut raw_headers = Vec::new();
        for (name, value) in headers.iter() {
            if let Ok(value_str) = value.to_str() {
                let name_arc: Arc<str> = name.as_str().into();
                normalized_headers.push((name_arc.clone(), normalizer.normalize(value_str)));
                raw_headers.push((name_arc, Cow::Borrowed(value_str)));
            }
        }

        let body_raw = body.map(|b| String::from_utf8_lossy(b).into_owned().into());
        let body_norm = body_raw.as_ref().map(|s: &Cow<'static, str>| {
            let ni = normalizer.normalize(s.as_ref());
            let normalized_data = match ni.normalized {
                NormalizedData::Borrowed(s) => {
                    let mut pooled = BufferPool::acquire(s.len());
                    pooled.clear();
                    pooled.extend_from_slice(s.as_bytes());
                    NormalizedData::pooled(pooled)
                }
                NormalizedData::Pooled { buf, lossy } => NormalizedData::Pooled { buf, lossy },
                NormalizedData::Owned(o) => NormalizedData::Owned(o),
            };
            NormalizedInput {
                normalized: normalized_data,
                passes: ni.passes,
                flags: ni.flags,
            }
        });

        Self {
            path: path_norm,
            path_raw,
            query_string: query_string_norm,
            query_string_raw,
            headers: normalized_headers,
            headers_raw: raw_headers,
            body: body_norm,
            body_raw,
            body_bytes: body.map(Cow::Borrowed),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_overlong_gt_decoded() {
        // %C0%BE is overlong UTF-8 for U+003E ('>')
        let normalizer = InputNormalizer::new();
        let result = normalizer.normalize("/path/%C0%BEtest%C0%BE");
        assert_eq!(result.as_str(), "/path/>test>");
        assert!(result.flags.contains(NormalizationFlags::OVERLONG));
    }

    #[test]
    fn test_overlong_lt_decoded() {
        // %C0%BC is overlong UTF-8 for U+003C ('<')
        let normalizer = InputNormalizer::new();
        let result = normalizer.normalize("%C0%BCscript%C0%BC");
        assert_eq!(result.as_str(), "<script<");
        assert!(result.flags.contains(NormalizationFlags::OVERLONG));
    }

    #[test]
    fn test_overlong_slash_decoded() {
        // %C0%AF is overlong UTF-8 for U+002F ('/')
        let normalizer = InputNormalizer::new();
        let result = normalizer.normalize("a%C0%AFb");
        assert_eq!(result.as_str(), "a/b");
        assert!(result.flags.contains(NormalizationFlags::OVERLONG));
    }

    #[test]
    fn test_overlong_paren_decoded() {
        // %C0%A8 is overlong UTF-8 for U+0028 ('(')
        let normalizer = InputNormalizer::new();
        let result = normalizer.normalize("alert%C0%A81%C0%A9");
        assert_eq!(result.as_str(), "alert(1)");
        assert!(result.flags.contains(NormalizationFlags::OVERLONG));
    }

    #[test]
    fn test_full_xss_overlong_payload() {
        // The actual corpus fixture payload
        let normalizer = InputNormalizer::new();
        let result = normalizer
            .normalize("/profile/%C0%AE%C0%AE%C0%BCscript%C0%BEalert(1)%C0%BC/script%C0%BE");
        // After overlong decoding: /profile/>> <script> alert(1) < /script >
        // Note: %C0%AE maps to '>' (U+003E)
        assert!(result.as_str().contains("<script>"));
        assert!(result.as_str().contains("</script>"));
        assert!(result.flags.contains(NormalizationFlags::OVERLONG));
    }

    #[test]
    fn test_canonical_percent_encoding_still_works() {
        // %3C is the canonical encoding for '<' — should still work
        let normalizer = InputNormalizer::new();
        let result = normalizer.normalize("%3Cscript%3Ealert(1)%3C/script%3E");
        assert_eq!(result.as_str(), "<script>alert(1)</script>");
        assert!(!result.flags.contains(NormalizationFlags::OVERLONG));
    }

    #[test]
    fn test_benign_unicode_preserved() {
        // Normal UTF-8 characters should not be affected
        let normalizer = InputNormalizer::new();
        let result = normalizer.normalize("/café/naïve/日本語");
        assert_eq!(result.as_str(), "/café/naïve/日本語");
        assert!(!result.flags.contains(NormalizationFlags::OVERLONG));
    }

    #[test]
    fn test_benign_percent_encoded_unicode() {
        // %C3%A9 is the canonical UTF-8 for 'é' — should decode normally
        let normalizer = InputNormalizer::new();
        let result = normalizer.normalize("/caf%C3%A9");
        assert_eq!(result.as_str(), "/café");
        assert!(!result.flags.contains(NormalizationFlags::OVERLONG));
    }

    #[test]
    fn test_malformed_non_attack_overlong() {
        // %C1%A9 is overlong UTF-8 for U+0069 ('i')
        // This is overlong but maps to an ASCII character
        let normalizer = InputNormalizer::new();
        let result = normalizer.normalize("%C1%A9");
        assert_eq!(result.as_str(), "i");
        assert!(result.flags.contains(NormalizationFlags::OVERLONG));
    }

    #[test]
    fn test_bare_continuation_byte_not_overlong() {
        // %80 is a bare continuation byte — not a valid overlong sequence
        let normalizer = InputNormalizer::new();
        let result = normalizer.normalize("test%80test");
        // Should be treated as char U+0080 (control char), not decoded as overlong
        assert!(result.as_str().contains('\u{0080}'));
    }

    #[test]
    fn test_overlong_three_byte() {
        // %E0%80%AE is a 3-byte overlong for U+002E ('.')
        // (This is a 3-byte encoding of a codepoint that fits in 1 byte)
        let normalizer = InputNormalizer::new();
        let result = normalizer.normalize("a%E0%80%AEb");
        assert_eq!(result.as_str(), "a.b");
        assert!(result.flags.contains(NormalizationFlags::OVERLONG));
    }

    #[test]
    fn test_overlong_idempotency() {
        // Double-encoded overlong: %25C0%25BE should decode to %C0%BE on first pass,
        // then to '>' on second pass
        let normalizer = InputNormalizer::new();
        let result = normalizer.normalize("%25C0%25BE");
        assert_eq!(result.as_str(), ">");
        assert!(result.flags.contains(NormalizationFlags::OVERLONG));
    }

    #[test]
    fn test_null_byte_still_detected_with_overlong() {
        // %C0%80 is overlong UTF-8 for U+0000 (null byte)
        let normalizer = InputNormalizer::new();
        let result = normalizer.normalize("test%C0%80end");
        // Should detect null byte AND overlong
        assert!(result.flags.contains(NormalizationFlags::NULL_BYTE));
        assert!(result.flags.contains(NormalizationFlags::OVERLONG));
    }

    #[test]
    fn test_double_encoding_with_overlong() {
        // %253C is double-encoded '<': first pass → %3C, second pass → <
        let normalizer = InputNormalizer::new();
        let result = normalizer.normalize("%253Cscript%253E");
        assert_eq!(result.as_str(), "<script>");
        assert!(result.flags.contains(NormalizationFlags::DOUBLE_ENCODING));
    }

    #[test]
    fn test_normalization_bounded_depth() {
        // Ensure repeated decoding terminates
        let normalizer = InputNormalizer::new();
        // 10 levels of encoding: %252525252525252525253C
        let input = "%252525252525252525253C";
        let result = normalizer.normalize(input);
        // Should terminate and produce some decoded result
        assert!(!result.as_str().is_empty());
    }
}
