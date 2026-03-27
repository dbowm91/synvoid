use unicode_normalization::UnicodeNormalization;

const MAX_OUTPUT_RATIO: usize = 100;

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

    pub fn normalize(&self, input: &str) -> NormalizedInput {
        let mut buffer = String::with_capacity(input.len());
        let mut passes = 0;
        let max_output = input.len().saturating_mul(MAX_OUTPUT_RATIO);

        buffer.push_str(input);

        for _ in 0..self.max_decode_passes {
            let prev_len = buffer.len();
            let decoded = self.decode_single_pass_inplace(&mut buffer);
            if decoded == prev_len {
                break;
            }
            if decoded > max_output {
                break;
            }
            passes += 1;
        }

        self.apply_normalizations_inplace(&mut buffer);

        NormalizedInput {
            normalized: buffer,
            passes,
        }
    }

    fn decode_single_pass_inplace(&self, input: &mut String) -> usize {
        let chars: Vec<char> = input.chars().collect();
        input.clear();

        let mut i = 0;
        while i < chars.len() {
            match chars[i] {
                '%' => {
                    if i + 2 < chars.len() {
                        let hex: String = chars[i + 1..=i + 2].iter().collect();
                        if let Ok(byte) = u8::from_str_radix(&hex, 16) {
                            if byte != 0 {
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
                                    let hex: String = chars[i + 2..=i + 3].iter().collect();
                                    if let Ok(byte) = u8::from_str_radix(&hex, 16) {
                                        if byte != 0 {
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
                                    let hex: String = chars[i + 2..=i + 5].iter().collect();
                                    if let Ok(code_point) = u32::from_str_radix(&hex, 16) {
                                        if code_point != 0 {
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
                            '0' => {
                                i += 2;
                                continue;
                            }
                            '1'..='7' => {
                                if i + 3 < chars.len()
                                    && chars[i + 2].is_ascii_digit()
                                    && chars[i + 3].is_ascii_digit()
                                {
                                    let octal: String = chars[i + 1..=i + 3].iter().collect();
                                    if let Ok(byte) = u8::from_str_radix(&octal, 8) {
                                        if byte != 0 {
                                            input.push(byte as char);
                                        }
                                        i += 4;
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
                            if ch != '\0' {
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

    fn decode_html_entity_simple(&self, entity: &str) -> Option<char> {
        if let Some(rest) = entity.strip_prefix('#') {
            if rest.starts_with('x') || rest.starts_with('X') {
                let hex = &rest[1..];
                if let Ok(code) = u32::from_str_radix(hex, 16) {
                    return char::from_u32(code);
                }
            } else if let Ok(code) = u32::from_str_radix(rest, 10) {
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

    fn apply_normalizations_inplace(&self, input: &mut String) {
        let chars: Vec<char> = input.chars().collect();
        input.clear();

        for c in chars {
            if matches!(c,
                '\u{200B}' | '\u{200C}' | '\u{200D}' | '\u{200E}' | '\u{200F}' |
                '\u{FEFF}' | '\u{2060}' | '\u{2061}' | '\u{2062}' | '\u{2063}' |
                '\u{2064}' | '\u{206A}' | '\u{206B}' | '\u{206C}' | '\u{206D}' |
                '\u{206E}' | '\u{206F}' | '\u{034F}' | '\u{180E}' |
                '\u{FE00}'..='\u{FE0F}' | '\u{E0100}'..='\u{E01EF}' | '\0'
            ) {
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
                '\u{0432}' => Some('B'),
                '\u{0412}' => Some('B'),
                '\u{043C}' => Some('M'),
                '\u{041C}' => Some('M'),
                '\u{043D}' => Some('H'),
                '\u{041D}' => Some('H'),
                '\u{043A}' => Some('K'),
                '\u{041A}' => Some('K'),
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
                    let offset = c as u32 - 0xFF10;
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
                    let offset = c as u32 - 0xFF21;
                    char::from_u32(0x41 + offset)
                }
                '\u{FF3B}' => Some('['),
                '\u{FF3C}' => Some('\\'),
                '\u{FF3D}' => Some(']'),
                '\u{FF3E}' => Some('^'),
                '\u{FF3F}' => Some('_'),
                '\u{FF40}' => Some('`'),
                '\u{FF41}'..='\u{FF5A}' => {
                    let offset = c as u32 - 0xFF41;
                    char::from_u32(0x61 + offset)
                }
                '\u{FF5B}' => Some('{'),
                '\u{FF5C}' => Some('|'),
                '\u{FF5D}' => Some('}'),
                '\u{FF5E}' => Some('~'),
                _ => Some(c),
            };

            if let Some(n) = normalized {
                if n.is_whitespace() {
                    input.push(' ');
                } else {
                    let nfc: String = n.nfkc().collect();
                    input.push_str(&nfc);
                }
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct NormalizedInput {
    pub normalized: String,
    pub passes: usize,
}

impl std::fmt::Display for NormalizedInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.normalized)
    }
}

impl AsRef<str> for NormalizedInput {
    fn as_ref(&self) -> &str {
        &self.normalized
    }
}

impl NormalizedInput {
    pub fn as_str(&self) -> &str {
        &self.normalized
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.normalized.as_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_url_decode() {
        let normalizer = InputNormalizer::new();
        let result = normalizer.normalize("%3Cscript%3E");
        assert_eq!(result.normalized, "<script>");
    }

    #[test]
    fn test_double_url_decode() {
        let normalizer = InputNormalizer::new();
        let result = normalizer.normalize("%253Cscript%253E");
        assert_eq!(result.normalized, "<script>");
    }

    #[test]
    fn test_unicode_decode() {
        let normalizer = InputNormalizer::new();
        let result = normalizer.normalize("\\u003Cscript\\u003E");
        assert_eq!(result.normalized, "<script>");
    }

    #[test]
    fn test_zero_width_removal() {
        let normalizer = InputNormalizer::new();
        let result = normalizer.normalize("hel\u{200B}lo");
        assert_eq!(result.normalized, "hello");
    }

    #[test]
    fn test_homoglyph_normalize() {
        let normalizer = InputNormalizer::new();
        let result = normalizer.normalize("\u{0430}dmin");
        assert_eq!(result.normalized, "admin");
    }

    #[test]
    fn test_html_entity_decode() {
        let normalizer = InputNormalizer::new();
        let result = normalizer.normalize("&#60;script&#62;");
        assert_eq!(result.normalized, "<script>");
    }

    #[test]
    fn test_null_byte_removal() {
        let normalizer = InputNormalizer::new();
        let result = normalizer.normalize("hel\u{0000}lo");
        assert_eq!(result.normalized, "hello");
    }

    #[test]
    fn test_fullwidth_normalize() {
        let normalizer = InputNormalizer::new();
        let result = normalizer.normalize("\u{FF01}\u{FF02}");
        assert_eq!(result.normalized, "!\"");
    }

    #[test]
    fn test_url_encoded_null_byte() {
        let normalizer = InputNormalizer::new();
        let result = normalizer.normalize("../../../etc/passwd%00.jpg");
        assert_eq!(result.normalized, "../../../etc/passwd.jpg");
    }

    #[test]
    fn test_hex_encoded_null_byte() {
        let normalizer = InputNormalizer::new();
        let result = normalizer.normalize("../../../etc/passwd\\x00.jpg");
        assert_eq!(result.normalized, "../../../etc/passwd.jpg");
    }

    #[test]
    fn test_unicode_encoded_null_byte() {
        let normalizer = InputNormalizer::new();
        let result = normalizer.normalize("../../../etc/passwd\\u0000.jpg");
        assert_eq!(result.normalized, "../../../etc/passwd.jpg");
    }

    #[test]
    fn test_html_entity_null_byte() {
        let normalizer = InputNormalizer::new();
        let result = normalizer.normalize("test&#0;value");
        assert_eq!(result.normalized, "testvalue");
    }

    #[test]
    fn test_html_entity_hex_null_byte() {
        let normalizer = InputNormalizer::new();
        let result = normalizer.normalize("test&#x00;value");
        assert_eq!(result.normalized, "testvalue");
    }

    #[test]
    fn test_multiple_null_bytes() {
        let normalizer = InputNormalizer::new();
        let result = normalizer.normalize("a\\x00b%00c\\u0000d&#0;e");
        assert_eq!(result.normalized, "abcde");
    }
}
