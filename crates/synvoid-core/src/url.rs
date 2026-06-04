/// Decode percent-encoded URL strings.
pub fn urlencoding_decode(input: &str) -> String {
    let mut result = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();

    while let Some(c) = chars.next() {
        if c == '%' {
            let hex: String = chars.by_ref().take(2).collect();
            if hex.len() == 2 {
                if let Ok(byte) = u8::from_str_radix(&hex, 16) {
                    if byte.is_ascii() {
                        result.push(byte as char);
                        continue;
                    } else {
                        result.push('%');
                        result.push_str(&hex);
                        continue;
                    }
                }
            }
            result.push('%');
            result.push_str(&hex);
        } else if c == '+' {
            result.push(' ');
        } else {
            result.push(c);
        }
    }

    result
}

#[allow(clippy::result_unit_err)]
pub fn urlencoding_decode_result(input: &str) -> Result<String, ()> {
    Ok(urlencoding_decode(input))
}

pub fn url_decode_all(input: &str) -> String {
    let mut result = input.to_string();

    for _ in 0..10 {
        let decoded = urlencoding_decode(&result);
        if decoded == result {
            break;
        }
        result = decoded;
    }

    result
}

/// Result of regex complexity analysis.
pub struct RegexComplexityResult {
    pub safe: bool,
    pub reason: String,
}

impl RegexComplexityResult {
    pub fn safe() -> Self {
        Self {
            safe: true,
            reason: String::new(),
        }
    }

    pub fn unsafe_(reason: String) -> Self {
        Self {
            safe: false,
            reason,
        }
    }
}

const REGEX_SIZE_LIMIT: usize = 1000;
const REGEX_MAX_QUANTIFIERS: usize = 20;
const REGEX_MAX_GROUPS: usize = 10;

pub fn check_regex_complexity(pattern: &str) -> RegexComplexityResult {
    if pattern.len() > REGEX_SIZE_LIMIT {
        return RegexComplexityResult::unsafe_(format!(
            "Pattern too long ({} bytes, max {})",
            pattern.len(),
            REGEX_SIZE_LIMIT
        ));
    }

    let nested_quantifiers = [
        (r"(.*)+", "nested .*"),
        (r"(.+)+", "nested .+"),
        (r"([^]]*)+", "nested [^]]*"),
        (r"([^]]*)*", "nested [^]]**"),
    ];

    for (pat, desc) in &nested_quantifiers {
        if pattern.contains(pat) {
            return RegexComplexityResult::unsafe_(format!(
                "ReDoS risk: nested quantifiers ({})",
                desc
            ));
        }
    }

    let quant_count = pattern.chars().filter(|c| *c == '+' || *c == '*').count();
    if quant_count > REGEX_MAX_QUANTIFIERS {
        return RegexComplexityResult::unsafe_(format!(
            "Too many quantifiers ({} > {}), may cause catastrophic backtracking",
            quant_count, REGEX_MAX_QUANTIFIERS
        ));
    }

    let group_count = pattern.matches('(').count();
    if group_count > REGEX_MAX_GROUPS {
        return RegexComplexityResult::unsafe_(format!(
            "Too many capture groups ({} > {})",
            group_count, REGEX_MAX_GROUPS
        ));
    }

    let dangerous_lookarounds = [r"(?=", r"(?!", r"(?<=", r"(?<!"];
    for da in &dangerous_lookarounds {
        if pattern.contains(da) {
            let count = pattern.matches(da).count();
            if count > 5 {
                return RegexComplexityResult::unsafe_(format!(
                    "Many lookarounds ({}), potential performance issue",
                    count
                ));
            }
        }
    }

    RegexComplexityResult::safe()
}

pub fn default_true() -> bool {
    true
}
