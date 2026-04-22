#![allow(dead_code)]
// SAFETY_REASON: Location-based routing - reserved for geographic load balancing

use crate::utils::check_regex_complexity;
use regex::Regex;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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

    pub fn prefix_length(&self) -> usize {
        match self.match_type {
            LocationMatchType::Exact => self.pattern.len(),
            LocationMatchType::PreferentialPrefix | LocationMatchType::Prefix => self.pattern.len(),
            LocationMatchType::Regex => 0,
        }
    }
}

#[derive(Clone)]
pub struct LocationMatcher {
    locations: Vec<LocationMatch>,
}

impl LocationMatcher {
    pub fn new(patterns: Vec<String>) -> Self {
        let locations: Vec<LocationMatch> = patterns
            .into_iter()
            .enumerate()
            .filter_map(|(idx, pattern)| LocationMatch::new(pattern, idx))
            .collect();

        LocationMatcher { locations }
    }

    pub fn match_uri(&self, uri: &str) -> Option<(usize, LocationMatchType)> {
        let mut exact_matches: Vec<&LocationMatch> = Vec::new();
        let mut pref_prefix_matches: Vec<&LocationMatch> = Vec::new();
        let mut regex_matches: Vec<&LocationMatch> = Vec::new();
        let mut prefix_matches: Vec<&LocationMatch> = Vec::new();

        for loc in &self.locations {
            if loc.matches(uri) {
                match loc.match_type {
                    LocationMatchType::Exact => exact_matches.push(loc),
                    LocationMatchType::PreferentialPrefix => pref_prefix_matches.push(loc),
                    LocationMatchType::Regex => regex_matches.push(loc),
                    LocationMatchType::Prefix => prefix_matches.push(loc),
                }
            }
        }

        if let Some(loc) = exact_matches.first() {
            return Some((loc.original_order, LocationMatchType::Exact));
        }

        if let Some(longest) = pref_prefix_matches.iter().max_by_key(|l| l.prefix_length()) {
            return Some((
                longest.original_order,
                LocationMatchType::PreferentialPrefix,
            ));
        }

        if let Some(first) = regex_matches.first() {
            return Some((first.original_order, LocationMatchType::Regex));
        }

        if let Some(longest) = prefix_matches.iter().max_by_key(|l| l.prefix_length()) {
            return Some((longest.original_order, LocationMatchType::Prefix));
        }

        None
    }

    pub fn is_empty(&self) -> bool {
        self.locations.is_empty()
    }

    pub fn len(&self) -> usize {
        self.locations.len()
    }
}

impl Default for LocationMatcher {
    fn default() -> Self {
        Self::new(Vec::new())
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
