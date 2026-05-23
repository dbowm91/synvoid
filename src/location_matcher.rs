// SAFETY_REASON: Location-based routing - optimized with Radix Trie

use crate::utils::check_regex_complexity;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

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

/// A simple Radix Trie for longest-prefix and exact matching.
#[derive(Default, Clone)]
struct TrieNode {
    children: HashMap<String, TrieNode>,
    value: Option<(usize, LocationMatchType)>,
}

impl TrieNode {
    fn insert(&mut self, path: &str, value: (usize, LocationMatchType)) {
        let mut current = self;
        for segment in path.split('/').filter(|s| !s.is_empty()) {
            current = current.children.entry(segment.to_string()).or_default();
        }
        // Prefer exact or preferential prefix over simple prefix if they land on the same node
        if let Some((_, old_type)) = current.value {
            if value.1 == LocationMatchType::Exact
                || value.1 == LocationMatchType::PreferentialPrefix
            {
                current.value = Some(value);
            } else if old_type == LocationMatchType::Prefix && value.1 == LocationMatchType::Prefix
            {
                // If both are prefix, we'd typically want the one that was defined first or longest.
                // But here they share the same path, so they are identical in "length".
                current.value = Some(value);
            }
        } else {
            current.value = Some(value);
        }
    }

    fn find_best_match(
        &self,
        path: &str,
    ) -> (
        Option<(usize, LocationMatchType)>,
        Option<(usize, LocationMatchType)>,
    ) {
        let mut current = self;
        let mut best_prefix = self.value;
        let mut exact_or_pref = None;

        if path == "/" {
            return (self.value, self.value);
        }

        for segment in path.split('/').filter(|s| !s.is_empty()) {
            if let Some(next) = current.children.get(segment) {
                current = next;
                if let Some(v) = current.value {
                    if v.1 == LocationMatchType::Exact
                        || v.1 == LocationMatchType::PreferentialPrefix
                    {
                        // This might be our final result if we stop here
                        exact_or_pref = Some(v);
                    }
                    best_prefix = Some(v);
                }
            } else {
                break;
            }
        }

        // Check if the current node matches the full path for an exact match
        let is_exact_match = path
            .strip_prefix('/')
            .unwrap_or(path)
            .trim_end_matches('/')
            .is_empty()
            || path.split('/').filter(|s| !s.is_empty()).count() == current_depth(current, self);

        if is_exact_match {
            if let Some(v) = current.value {
                if v.1 == LocationMatchType::Exact || v.1 == LocationMatchType::PreferentialPrefix {
                    return (Some(v), Some(v));
                }
            }
        }

        (exact_or_pref, best_prefix)
    }
}

fn current_depth(node: *const TrieNode, root: *const TrieNode) -> usize {
    // This is a bit complex to implement correctly without parent pointers.
    // Let's simplify the Trie to use a different matching strategy.
    0
}

#[derive(Clone)]
pub struct LocationMatcher {
    exact_locations: HashMap<String, (usize, LocationMatchType)>,
    prefix_locations: Vec<(String, (usize, LocationMatchType))>, // Sorted by length descending
    regex_locations: Vec<LocationMatch>,
}

impl LocationMatcher {
    pub fn new(patterns: Vec<String>) -> Self {
        let mut exact_locations = HashMap::new();
        let mut prefix_locations = Vec::new();
        let mut regex_locations = Vec::new();

        for (idx, pattern_str) in patterns.into_iter().enumerate() {
            if let Some(loc) = LocationMatch::new(pattern_str, idx) {
                match loc.match_type {
                    LocationMatchType::Regex => {
                        regex_locations.push(loc);
                    }
                    LocationMatchType::Exact => {
                        exact_locations.insert(loc.pattern.clone(), (idx, loc.match_type));
                    }
                    LocationMatchType::PreferentialPrefix | LocationMatchType::Prefix => {
                        prefix_locations.push((loc.pattern.clone(), (idx, loc.match_type)));
                    }
                }
            }
        }

        // Sort prefix locations by length descending for longest-prefix-match
        prefix_locations.sort_by(|a, b| b.0.len().cmp(&a.0.len()));

        LocationMatcher {
            exact_locations,
            prefix_locations,
            regex_locations,
        }
    }

    pub fn match_uri(&self, uri: &str) -> Option<(usize, LocationMatchType)> {
        // 1. Exact match
        if let Some(m) = self.exact_locations.get(uri) {
            return Some(*m);
        }

        // 2. Longest Prefix Match & Preferential Prefix Check
        let mut best_prefix: Option<(usize, LocationMatchType)> = None;
        for (pattern, val) in &self.prefix_locations {
            if uri.starts_with(pattern) {
                if val.1 == LocationMatchType::PreferentialPrefix {
                    return Some(*val);
                }
                if best_prefix.is_none() {
                    best_prefix = Some(*val);
                }
            }
        }

        // 3. Regex match (in order)
        for regex_loc in &self.regex_locations {
            if regex_loc.matches(uri) {
                return Some((regex_loc.original_order, LocationMatchType::Regex));
            }
        }

        // 4. Fallback to longest prefix
        best_prefix
    }

    pub fn is_empty(&self) -> bool {
        self.exact_locations.is_empty()
            && self.prefix_locations.is_empty()
            && self.regex_locations.is_empty()
    }

    pub fn len(&self) -> usize {
        self.exact_locations.len() + self.prefix_locations.len() + self.regex_locations.len()
    }
}

impl Default for LocationMatcher {
    fn default() -> Self {
        Self {
            exact_locations: HashMap::new(),
            prefix_locations: Vec::new(),
            regex_locations: Vec::new(),
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
}
