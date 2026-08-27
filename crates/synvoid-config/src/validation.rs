#[derive(Debug, Clone)]
pub struct ConfigValidationError {
    pub field: String,
    pub message: String,
}

impl std::fmt::Display for ConfigValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.field, self.message)
    }
}

impl std::error::Error for ConfigValidationError {}

pub fn parse_size_string(s: &str) -> Result<usize, String> {
    let s = s.trim().to_uppercase();
    let (multiplier, num_str) = if s.ends_with("GB") {
        (1024 * 1024 * 1024, &s[..s.len() - 2])
    } else if s.ends_with("MB") {
        (1024 * 1024, &s[..s.len() - 2])
    } else if s.ends_with("KB") {
        (1024, &s[..s.len() - 2])
    } else if s.ends_with("B") {
        (1, &s[..s.len() - 1])
    } else {
        (1, s.as_str())
    };
    let num: usize = num_str.trim().parse().map_err(|_| "Invalid number")?;
    num.checked_mul(multiplier)
        .ok_or_else(|| format!("size overflow: {}", s))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_size_overflow_gb() {
        let max = format!("{}GB", usize::MAX / (1024 * 1024 * 1024) + 1);
        assert!(parse_size_string(&max).is_err());
    }

    #[test]
    fn test_parse_size_overflow_mb() {
        let max = format!("{}MB", usize::MAX / (1024 * 1024) + 1);
        assert!(parse_size_string(&max).is_err());
    }

    #[test]
    fn test_parse_size_overflow_kb() {
        let max = format!("{}KB", usize::MAX / 1024 + 1);
        assert!(parse_size_string(&max).is_err());
    }

    #[test]
    fn test_parse_size_valid() {
        assert_eq!(parse_size_string("10GB").unwrap(), 10 * 1024 * 1024 * 1024);
        assert_eq!(parse_size_string("500MB").unwrap(), 500 * 1024 * 1024);
        assert_eq!(parse_size_string("1024KB").unwrap(), 1024 * 1024);
        assert_eq!(parse_size_string("100B").unwrap(), 100);
        assert_eq!(parse_size_string("100").unwrap(), 100);
    }

    #[test]
    fn test_parse_size_invalid() {
        assert!(parse_size_string("abc").is_err());
        assert!(parse_size_string("").is_err());
    }
}
