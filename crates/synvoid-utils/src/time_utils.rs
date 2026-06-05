const DURATION_SUFFIXES: &[(&str, &str, u64)] = &[
    ("seconds", "s", 1),
    ("minutes", "m", 60),
    ("hours", "h", 3600),
    ("days", "d", 86400),
];

const DURATION_SUFFIX_SHORT: &[(char, u64)] = &[('s', 1), ('m', 60), ('h', 3600), ('d', 86400)];

pub fn parse_duration(s: &str) -> Option<u64> {
    let s = s.trim();

    if s.is_empty() {
        return None;
    }

    if s.eq_ignore_ascii_case("never")
        || s.eq_ignore_ascii_case("permanent")
        || s.eq_ignore_ascii_case("0")
    {
        return Some(0);
    }

    if let Ok(num) = s.parse::<u64>() {
        return Some(num);
    }

    if s.len() < 2 {
        return None;
    }

    // Handle millisecond suffixes before all other suffix matching to prevent
    // "ms" from being misinterpreted as "m" (last char 's') and "milliseconds"
    // from matching "seconds". Both convert to seconds by integer-dividing by
    // 1000. Sub-second precision is truncated since the return type is u64.
    if let Some(stripped) = s.strip_suffix("ms") {
        let value = stripped.parse::<u64>().ok()?;
        return Some(value / 1000);
    }
    if s.len() > 12 && s[s.len() - 12..].eq_ignore_ascii_case("milliseconds") {
        let value = s[..s.len() - 12].parse::<u64>().ok()?;
        return Some(value / 1000);
    }

    for (long_suffix, _short_suffix, multiplier) in DURATION_SUFFIXES {
        let suffix_len = long_suffix.len();
        if s.len() > suffix_len && s[s.len() - suffix_len..].eq_ignore_ascii_case(long_suffix) {
            let value = s[..s.len() - suffix_len].parse::<u64>().ok()?;
            return value.checked_mul(*multiplier);
        }
    }

    let last_char = s.chars().last()?;
    for (short_suffix, multiplier) in DURATION_SUFFIX_SHORT {
        if last_char.eq_ignore_ascii_case(short_suffix) {
            let value = s[..s.len() - 1].parse::<u64>().ok()?;
            return value.checked_mul(*multiplier);
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_duration() {
        assert_eq!(parse_duration("30s"), Some(30));
        assert_eq!(parse_duration("5m"), Some(300));
        assert_eq!(parse_duration("2h"), Some(7200));
        assert_eq!(parse_duration("1d"), Some(86400));
        assert_eq!(parse_duration("100ms"), Some(0));
        assert_eq!(parse_duration("1500ms"), Some(1));
        assert_eq!(parse_duration("never"), Some(0));
        assert_eq!(parse_duration("permanent"), Some(0));
        assert_eq!(parse_duration("0"), Some(0));
        assert_eq!(parse_duration("60"), Some(60));
        assert_eq!(parse_duration(""), None);
        assert_eq!(parse_duration("x"), None);
    }
}
