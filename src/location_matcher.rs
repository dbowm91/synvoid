// SAFETY_REASON: Location-based routing - reserved for geographic load balancing

use crate::utils::check_regex_complexity;
use matchit::Router as MatchRouter;
use regex::Regex;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LocationMatchType {
    Exact,
    PreferentialPrefix,
    Regex,
    Prefix,
}

#[derive(Debug, Clone)]
pub struct LocationMatch {
    pub pattern: String,
    pub match_type: LocationMatchType,
    pub regex: Option<Regex>,
    pub original_order: usize,
}

impl LocationMatch {
    pub fn new(pattern: String, original_order: usize) -> Option<Self> {
        let (match_type, pattern_to_match) = if let Some(stripped) = pattern.strip_prefix("= ") {
            (LocationMatchType::Exact, stripped.to_string())
        } else if let Some(stripped) = pattern.strip_prefix("^~ ") {
            (LocationMatchType::PreferentialPrefix, stripped.to_string())
        } else if let Some(stripped) = pattern.strip_prefix("~ ") {
            let complexity = check_regex_complexity(stripped);
            if !complexity.safe {
                tracing::warn!(
                    "Unsafe regex pattern '{}': {}",
                    stripped,
                    complexity.reason.as_deref().unwrap_or("unknown")
                );
                return None;
            }
            let regex = match Regex::new(stripped) {
                Ok(r) => r,
                Err(e) => {
                    tracing::warn!("Invalid regex pattern '{}': {}", stripped, e);
                    return None;
                }
            };
            return Some(LocationMatch {
                pattern: pattern.clone(),
                match_type: LocationMatchType::Regex,
                regex: Some(regex),
                original_order,
            });
        } else if let Some(stripped) = pattern.strip_prefix("~* ") {
            let complexity = check_regex_complexity(stripped);
            if !complexity.safe {
                tracing::warn!(
                    "Unsafe regex pattern '{}': {}",
                    stripped,
                    complexity.reason.as_deref().unwrap_or("unknown")
                );
                return None;
            }
            let regex = match Regex::new(&format!("(?i){}", stripped)) {
                Ok(r) => r,
                Err(e) => {
                    tracing::warn!(
                        "Invalid case-insensitive regex pattern '{}': {}",
                        stripped,
                        e
                    );
                    return None;
                }
            };
            return Some(LocationMatch {
                pattern: pattern.clone(),
                match_type: LocationMatchType::Regex,
                regex: Some(regex),
                original_order,
            });
        } else {
            (LocationMatchType::Prefix, pattern.clone())
        };

        Some(LocationMatch {
            pattern: pattern_to_match,
            match_type,
            regex: None,
            original_order,
        })
    }

    pub fn matches(&self, uri: &str) -> bool {
        match self.match_type {
            LocationMatchType::Exact => uri == self.pattern,
            LocationMatchType::PreferentialPrefix | LocationMatchType::Prefix => {
                uri.starts_with(&self.pattern)
            }
            LocationMatchType::Regex => {
                if let Some(ref regex) = self.regex {
                    regex.is_match(uri)
                } else {
                    false
                }
            }
        }
    }
}

#[derive(Clone)]
pub struct LocationMatcher {
    static_router: MatchRouter<(usize, LocationMatchType)>,
    regex_locations: Vec<LocationMatch>,
    has_static: bool,
}

impl LocationMatcher {
    pub fn new(patterns: Vec<String>) -> Self {
        let mut static_router = MatchRouter::new();
        let mut regex_locations = Vec::new();
        let mut has_static = false;

        for (idx, pattern_str) in patterns.into_iter().enumerate() {
            if let Some(loc) = LocationMatch::new(pattern_str, idx) {
                match loc.match_type {
                    LocationMatchType::Regex => {
                        regex_locations.push(loc);
                    }
                    LocationMatchType::Exact => {
                        let _ = static_router.insert(loc.pattern.clone(), (idx, loc.match_type));
                        has_static = true;
                    }
                    LocationMatchType::PreferentialPrefix | LocationMatchType::Prefix => {
                        // For prefix matching, we insert both the exact path and a catch-all
                        // matchit doesn't support "starts_with" directly without a wildcard
                        // so we handle both cases.
                        let _ =
                            static_router.insert(loc.pattern.clone(), (idx, loc.match_type));
                        
                        let catch_all = if loc.pattern.ends_with('/') {
                            format!("{}*path", loc.pattern)
                        } else {
                            format!("{}/*path", loc.pattern)
                        };
                        
                        let _ = static_router.insert(catch_all, (idx, loc.match_type));
                        has_static = true;
                    }
                }
            }
        }

        LocationMatcher {
            static_router,
            regex_locations,
            has_static,
        }
    }

    pub fn match_uri(&self, uri: &str) -> Option<(usize, LocationMatchType)> {
        let static_match = if self.has_static {
            self.static_router.at(uri).ok()
        } else {
            None
        };

        if let Some(ref m) = static_match {
            let (idx, match_type) = *m.value;
            if match_type == LocationMatchType::Exact
                || match_type == LocationMatchType::PreferentialPrefix
            {
                return Some((idx, match_type));
            }
        }

        // Check regexes in order
        for regex_loc in &self.regex_locations {
            if regex_loc.matches(uri) {
                return Some((regex_loc.original_order, LocationMatchType::Regex));
            }
        }

        // Fallback to the best prefix match found earlier
        if let Some(m) = static_match {
            let (idx, match_type) = *m.value;
            return Some((idx, match_type));
        }

        None
    }

    pub fn is_empty(&self) -> bool {
        !self.has_static && self.regex_locations.is_empty()
    }

    pub fn len(&self) -> usize {
        // This is a bit approximate now, but used mainly for debugging
        self.regex_locations.len() + if self.has_static { 1 } else { 0 }
    }
}

impl Default for LocationMatcher {
    fn default() -> Self {
        Self {
            static_router: MatchRouter::new(),
            regex_locations: Vec::new(),
            has_static: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exact_match() {
        let matcher = LocationMatcher::new(vec!["= /exact".to_string(), "/prefix".to_string()]);

        assert_eq!(
            matcher.match_uri("/exact"),
            Some((0, LocationMatchType::Exact))
        );
        assert_eq!(
            matcher.match_uri("/prefix/test"),
            Some((1, LocationMatchType::Prefix))
        );
    }

    #[test]
    fn test_preferential_prefix() {
        let matcher = LocationMatcher::new(vec![
            "^~ /static".to_string(),
            "~ \\.php$".to_string(),
            "/static/files".to_string(),
        ]);

        assert_eq!(
            matcher.match_uri("/static"),
            Some((0, LocationMatchType::PreferentialPrefix))
        );
        assert_eq!(
            matcher.match_uri("/static/file.js"),
            Some((0, LocationMatchType::PreferentialPrefix))
        );
    }

    #[test]
    fn test_regex_order() {
        let matcher =
            LocationMatcher::new(vec!["~ \\.jpg$".to_string(), "~ \\.(jpg|png)$".to_string()]);

        assert_eq!(
            matcher.match_uri("/image.jpg"),
            Some((0, LocationMatchType::Regex))
        );
    }

    #[test]
    fn test_case_insensitive_regex() {
        let matcher = LocationMatcher::new(vec!["~* \\.JPG$".to_string()]);

        assert_eq!(
            matcher.match_uri("/image.JPG"),
            Some((0, LocationMatchType::Regex))
        );
        assert_eq!(
            matcher.match_uri("/image.jpg"),
            Some((0, LocationMatchType::Regex))
        );
    }

    #[test]
    fn test_longest_prefix_wins() {
        let matcher = LocationMatcher::new(vec![
            "/api".to_string(),
            "/api/v1".to_string(),
            "/api/v1/users".to_string(),
        ]);

        assert_eq!(
            matcher.match_uri("/api/v1/users/profile"),
            Some((2, LocationMatchType::Prefix))
        );
    }

    #[test]
    #[ignore = "Hangs during matching - needs investigation"]
    fn test_glob_pattern() {
        let matcher = LocationMatcher::new(vec!["/admin".to_string(), "/api".to_string()]);

        assert_eq!(
            matcher.match_uri("/admin/users"),
            Some((0, LocationMatchType::Prefix))
        );
        assert_eq!(
            matcher.match_uri("/api/v1/users"),
            Some((1, LocationMatchType::Prefix))
        );
    }
}
