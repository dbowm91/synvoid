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
    Ok(num * multiplier)
}
