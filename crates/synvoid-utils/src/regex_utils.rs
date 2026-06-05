const REGEX_SIZE_LIMIT: usize = 1024;
const REGEX_MAX_QUANTIFIERS: usize = 10;
const REGEX_MAX_GROUPS: usize = 20;

#[derive(Debug, Clone)]
pub struct RegexComplexityResult {
    pub safe: bool,
    pub reason: Option<String>,
}

impl RegexComplexityResult {
    pub fn safe() -> Self {
        Self {
            safe: true,
            reason: None,
        }
    }

    pub fn unsafe_(reason: impl Into<String>) -> Self {
        Self {
            safe: false,
            reason: Some(reason.into()),
        }
    }
}

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
