use unicode_normalization::UnicodeNormalization;

pub struct InputNormalizer {
    max_decode_passes: usize,
}

impl Default for InputNormalizer {
    fn default() -> Self {
        Self {
            max_decode_passes: 5,
        }
    }
}

impl InputNormalizer {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn normalize(&self, input: &str) -> NormalizedInput {
        let mut result = input.to_string();
        let mut passes = 0;

        loop {
            let decoded = self.decode_single_pass(&result);
            if decoded == result || passes >= self.max_decode_passes {
                break;
            }
            result = decoded;
            passes += 1;
        }

        result = self.normalize_unicode(&result);
        result = self.remove_zero_width_chars(&result);
        result = self.normalize_homoglyphs(&result);
        result = self.remove_null_bytes(&result);
        result = self.normalize_whitespace(&result);

        NormalizedInput {
            original: input.to_string(),
            normalized: result,
            passes,
        }
    }

    fn decode_single_pass(&self, input: &str) -> String {
        let mut result = String::with_capacity(input.len());
        let mut chars = input.chars().peekable();

        while let Some(c) = chars.next() {
            match c {
                '%' => {
                    let hex: String = chars.by_ref().take(2).collect();
                    if hex.len() == 2 {
                        if let Ok(byte) = u8::from_str_radix(&hex, 16) {
                            if byte == 0 {
                                continue;
                            }
                            result.push(byte as char);
                            continue;
                        }
                    }
                    result.push('%');
                    result.push_str(&hex);
                }
                '+' => result.push(' '),
                '\\' => {
                    if let Some(&next) = chars.peek() {
                        match next {
                            'x' | 'X' => {
                                chars.next();
                                let hex: String = chars.by_ref().take(2).collect();
                                if hex.len() == 2 {
                                    if let Ok(byte) = u8::from_str_radix(&hex, 16) {
                                        if byte == 0 {
                                            continue;
                                        }
                                        result.push(byte as char);
                                        continue;
                                    }
                                }
                                result.push_str("\\x");
                                result.push_str(&hex);
                            }
                            'u' | 'U' => {
                                chars.next();
                                let hex: String = chars.by_ref().take(4).collect();
                                if hex.len() == 4 {
                                    if let Ok(code_point) = u32::from_str_radix(&hex, 16) {
                                        if code_point == 0 {
                                            continue;
                                        }
                                        if let Some(ch) = char::from_u32(code_point) {
                                            result.push(ch);
                                            continue;
                                        }
                                    }
                                }
                                result.push_str("\\u");
                                result.push_str(&hex);
                            }
                            '0'..='7' => {
                                let octal: String = chars.by_ref().take(3).collect();
                                if let Ok(byte) = u8::from_str_radix(&octal, 8) {
                                    if byte == 0 {
                                        continue;
                                    }
                                    result.push(byte as char);
                                    continue;
                                }
                                result.push('\\');
                                result.push_str(&octal);
                            }
                            'n' => {
                                chars.next();
                                result.push('\n');
                            }
                            'r' => {
                                chars.next();
                                result.push('\r');
                            }
                            't' => {
                                chars.next();
                                result.push('\t');
                            }
                            '0' => {
                                chars.next();
                                continue;
                            }
                            _ => {
                                result.push(c);
                            }
                        }
                    } else {
                        result.push(c);
                    }
                }
                '&' => {
                    let mut entity_chars = String::new();
                    let mut found_semicolon = false;
                    let mut consumed = 0;

                    for _ in 0..10 {
                        if let Some(&next) = chars.peek() {
                            if next == ';' {
                                found_semicolon = true;
                                chars.next();
                                consumed += 1;
                                break;
                            }
                            entity_chars.push(next);
                            chars.next();
                            consumed += 1;
                        } else {
                            break;
                        }
                    }

                    if found_semicolon {
                        if let Some(ch) = self.decode_html_entity_simple(&entity_chars) {
                            if ch == '\0' {
                                continue;
                            }
                            result.push(ch);
                            continue;
                        }
                    }

                    result.push('&');
                    result.push_str(&entity_chars);
                    if found_semicolon {
                        result.push(';');
                    }
                }
                '\0' => continue,
                _ => result.push(c),
            }
        }

        result
    }

    fn decode_html_entity_simple(&self, entity: &str) -> Option<char> {
        if entity.starts_with('#') {
            let rest = &entity[1..];
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
            _ => return None,
        })
    }

    fn normalize_unicode(&self, input: &str) -> String {
        input.nfkc().collect()
    }

    fn remove_zero_width_chars(&self, input: &str) -> String {
        input
            .chars()
            .filter(|c| {
                !matches!(
                    c,
                    '\u{200B}' | '\u{200C}' | '\u{200D}' | '\u{200E}' | '\u{200F}' |
                    '\u{FEFF}' | '\u{2060}' | '\u{2061}' | '\u{2062}' | '\u{2063}' |
                    '\u{2064}' | '\u{206A}' | '\u{206B}' | '\u{206C}' | '\u{206D}' |
                    '\u{206E}' | '\u{206F}' | '\u{034F}' | '\u{180E}' | '\u{FE00}'..
                    '\u{FE0F}' | '\u{E0100}'..='\u{E01EF}'
                )
            })
            .collect()
    }

    fn normalize_homoglyphs(&self, input: &str) -> String {
        input
            .chars()
            .map(|c| match c {
                '\u{0430}' => 'a',
                '\u{0410}' => 'A',
                '\u{0435}' => 'e',
                '\u{0415}' => 'E',
                '\u{043E}' => 'o',
                '\u{041E}' => 'O',
                '\u{0440}' => 'p',
                '\u{0420}' => 'P',
                '\u{0441}' => 'c',
                '\u{0421}' => 'C',
                '\u{0443}' => 'y',
                '\u{0423}' => 'Y',
                '\u{0445}' => 'x',
                '\u{0425}' => 'X',
                '\u{0456}' => 'i',
                '\u{0406}' => 'I',
                '\u{0458}' => 'j',
                '\u{0408}' => 'J',
                '\u{04BB}' => 'h',
                '\u{04B2}' => 'H',
                '\u{0432}' => 'B',
                '\u{0412}' => 'B',
                '\u{043C}' => 'M',
                '\u{041C}' => 'M',
                '\u{043D}' => 'H',
                '\u{041D}' => 'H',
                '\u{043A}' => 'K',
                '\u{041A}' => 'K',
                '\u{FE00}'..='\u{FE0F}' => c,
                '\u{2010}' | '\u{2011}' | '\u{2012}' | '\u{2013}' | '\u{2014}' | '\u{2015}' => '-',
                '\u{2018}' | '\u{2019}' | '\u{201A}' | '\u{201B}' => '\'',
                '\u{201C}' | '\u{201D}' | '\u{201E}' | '\u{201F}' => '"',
                '\u{00A0}' => ' ',
                '\u{2028}' | '\u{2029}' => ' ',
                '\u{FF01}' => '!',
                '\u{FF02}' => '"',
                '\u{FF03}' => '#',
                '\u{FF04}' => '$',
                '\u{FF05}' => '%',
                '\u{FF06}' => '&',
                '\u{FF07}' => '\'',
                '\u{FF08}' => '(',
                '\u{FF09}' => ')',
                '\u{FF0A}' => '*',
                '\u{FF0B}' => '+',
                '\u{FF0C}' => ',',
                '\u{FF0D}' => '-',
                '\u{FF0E}' => '.',
                '\u{FF0F}' => '/',
                '\u{FF10}'..='\u{FF19}' => {
                    let offset = c as u32 - 0xFF10;
                    char::from_u32(0x30 + offset).unwrap_or(c)
                }
                '\u{FF1A}' => ':',
                '\u{FF1B}' => ';',
                '\u{FF1C}' => '<',
                '\u{FF1D}' => '=',
                '\u{FF1E}' => '>',
                '\u{FF1F}' => '?',
                '\u{FF20}' => '@',
                '\u{FF21}'..='\u{FF3A}' => {
                    let offset = c as u32 - 0xFF21;
                    char::from_u32(0x41 + offset).unwrap_or(c)
                }
                '\u{FF3B}' => '[',
                '\u{FF3C}' => '\\',
                '\u{FF3D}' => ']',
                '\u{FF3E}' => '^',
                '\u{FF3F}' => '_',
                '\u{FF40}' => '`',
                '\u{FF41}'..='\u{FF5A}' => {
                    let offset = c as u32 - 0xFF41;
                    char::from_u32(0x61 + offset).unwrap_or(c)
                }
                '\u{FF5B}' => '{',
                '\u{FF5C}' => '|',
                '\u{FF5D}' => '}',
                '\u{FF5E}' => '~',
                _ => c,
            })
            .collect()
    }

    fn remove_null_bytes(&self, input: &str) -> String {
        input.replace('\0', "")
    }

    fn normalize_whitespace(&self, input: &str) -> String {
        input
            .chars()
            .map(|c| if c.is_whitespace() { ' ' } else { c })
            .collect()
    }
}

#[derive(Debug, Clone)]
pub struct NormalizedInput {
    pub original: String,
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
