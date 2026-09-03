use parking_lot::RwLock;
use regex::Regex;
use std::collections::HashSet;
use std::sync::Arc;

use synvoid_utils::check_regex_complexity;

pub struct EndpointBlocker {
    blocked_patterns: Vec<Regex>,
    invalid_patterns: Vec<String>,
    block_methods: HashSet<String>,
    block_response_code: u16,
    block_page_html: Option<String>,
}

#[derive(Clone)]
pub struct EndpointBlockerManager {
    inner: Arc<RwLock<EndpointBlocker>>,
}

#[derive(Debug, Clone)]
pub struct RegexValidationResult {
    pub valid: Vec<String>,
    pub invalid: Vec<(String, String)>,
}

impl EndpointBlockerManager {
    pub fn new(
        paths: Vec<String>,
        use_regex: bool,
        block_methods: Vec<String>,
        block_response_code: u16,
        block_page_html: Option<String>,
    ) -> Self {
        // Compile each pattern once (see M-06): previously `validate_patterns`
        // compiled every regex and `new` recompiled the valid ones.
        let mut blocked_patterns = Vec::new();
        let mut invalid_patterns = Vec::new();
        for p in &paths {
            match Self::compile_pattern(p, use_regex) {
                Ok(re) => blocked_patterns.push(re),
                Err(_) => invalid_patterns.push(p.clone()),
            }
        }

        let block_methods: HashSet<String> = block_methods
            .into_iter()
            .map(|m| m.to_uppercase())
            .collect();

        EndpointBlockerManager {
            inner: Arc::new(RwLock::new(EndpointBlocker {
                blocked_patterns,
                invalid_patterns,
                block_methods,
                block_response_code,
                block_page_html,
            })),
        }
    }

    /// Compile a single pattern, returning the compiled regex or a reason.
    /// Shared by `new` and `validate_patterns` so each pattern is compiled
    /// exactly once per call site.
    fn compile_pattern(pattern: &str, use_regex: bool) -> Result<Regex, String> {
        if use_regex {
            let complexity = check_regex_complexity(pattern);
            if !complexity.safe {
                return Err(complexity
                    .reason
                    .unwrap_or_else(|| "Unknown risk".to_string()));
            }
            Regex::new(pattern).map_err(|e| e.to_string())
        } else {
            let escaped = regex::escape(pattern);
            Regex::new(&format!("^{}$", escaped)).map_err(|e| e.to_string())
        }
    }

    pub fn validate_patterns(paths: &[String], use_regex: bool) -> RegexValidationResult {
        let mut valid = Vec::new();
        let mut invalid = Vec::new();

        for p in paths {
            match Self::compile_pattern(p, use_regex) {
                Ok(_) => valid.push(p.clone()),
                Err(reason) => invalid.push((p.clone(), reason)),
            }
        }

        RegexValidationResult { valid, invalid }
    }

    pub fn check(&self, path: &str, method: &str) -> EndpointCheckResult {
        let guard = self.inner.read();

        if !guard.block_methods.is_empty()
            && !guard
                .block_methods
                .iter()
                .any(|m| m.eq_ignore_ascii_case(method))
        {
            return EndpointCheckResult::Allowed;
        }

        for pattern in &guard.blocked_patterns {
            if pattern.is_match(path) {
                return EndpointCheckResult::Blocked {
                    response_code: guard.block_response_code,
                    html: guard.block_page_html.clone(),
                    matched_pattern: Some(pattern.to_string()),
                };
            }
        }

        EndpointCheckResult::Allowed
    }

    pub fn is_path_blocked(&self, path: &str) -> bool {
        matches!(self.check(path, "GET"), EndpointCheckResult::Blocked { .. })
    }

    pub fn get_invalid_patterns(&self) -> Vec<String> {
        self.inner.read().invalid_patterns.clone()
    }
}

#[derive(Debug, Clone)]
pub enum EndpointCheckResult {
    Allowed,
    Blocked {
        response_code: u16,
        html: Option<String>,
        matched_pattern: Option<String>,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_endpoint_blocker_allows_non_blocked_methods() {
        let blocker = EndpointBlockerManager::new(
            vec!["/admin".to_string()],
            false,
            vec!["POST".to_string()],
            403,
            None,
        );
        assert!(matches!(
            blocker.check("/admin", "POST"),
            EndpointCheckResult::Blocked { .. }
        ));
        assert!(matches!(
            blocker.check("/admin", "GET"),
            EndpointCheckResult::Allowed
        ));
    }

    #[test]
    fn test_endpoint_blocker_blocks_path() {
        let blocker =
            EndpointBlockerManager::new(vec!["/admin".to_string()], false, vec![], 403, None);
        match blocker.check("/admin", "GET") {
            EndpointCheckResult::Blocked {
                response_code,
                matched_pattern,
                ..
            } => {
                assert_eq!(response_code, 403);
                assert!(matched_pattern.is_some());
            }
            _ => panic!("Expected Blocked"),
        }
        assert!(matches!(
            blocker.check("/public", "GET"),
            EndpointCheckResult::Allowed
        ));
    }

    #[test]
    fn test_endpoint_blocker_regex() {
        let blocker =
            EndpointBlockerManager::new(vec![r"^/admin/.*".to_string()], true, vec![], 403, None);
        assert!(matches!(
            blocker.check("/admin/users", "GET"),
            EndpointCheckResult::Blocked { .. }
        ));
        assert!(matches!(
            blocker.check("/public", "GET"),
            EndpointCheckResult::Allowed
        ));
    }

    #[test]
    fn test_endpoint_blocker_is_path_blocked() {
        let blocker =
            EndpointBlockerManager::new(vec!["/secret".to_string()], false, vec![], 403, None);
        assert!(blocker.is_path_blocked("/secret"));
        assert!(!blocker.is_path_blocked("/public"));
    }
}
