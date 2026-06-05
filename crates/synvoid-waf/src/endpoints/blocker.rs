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
        let validation = Self::validate_patterns(&paths, use_regex);

        let block_methods: HashSet<String> = block_methods
            .into_iter()
            .map(|m| m.to_uppercase())
            .collect();

        EndpointBlockerManager {
            inner: Arc::new(RwLock::new(EndpointBlocker {
                blocked_patterns: validation
                    .valid
                    .iter()
                    .filter_map(|p| Regex::new(p).ok())
                    .collect(),
                invalid_patterns: validation.invalid.iter().map(|(p, _)| p.clone()).collect(),
                block_methods,
                block_response_code,
                block_page_html,
            })),
        }
    }

    pub fn validate_patterns(paths: &[String], use_regex: bool) -> RegexValidationResult {
        let mut valid = Vec::new();
        let mut invalid = Vec::new();

        for p in paths {
            if use_regex {
                let complexity = check_regex_complexity(p);
                if !complexity.safe {
                    invalid.push((
                        p.clone(),
                        complexity
                            .reason
                            .unwrap_or_else(|| "Unknown risk".to_string()),
                    ));
                    continue;
                }
                match Regex::new(p) {
                    Ok(_) => valid.push(p.clone()),
                    Err(e) => invalid.push((p.clone(), e.to_string())),
                }
            } else {
                let escaped = regex::escape(p);
                match Regex::new(&format!("^{}$", escaped)) {
                    Ok(_) => valid.push(p.clone()),
                    Err(e) => invalid.push((p.clone(), e.to_string())),
                }
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
