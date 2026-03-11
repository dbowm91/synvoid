//! Zone Trie Module
//!
//! Provides efficient DNS zone lookup using a radix trie (prefix tree).
//! This replaces the O(N) linear scan with O(L) lookup where L is the number of labels.

use std::collections::HashMap;
use std::sync::Arc;

/// A node in the zone trie
#[derive(Debug, Clone)]
struct TrieNode {
    /// Children nodes keyed by label
    children: HashMap<String, TrieNode>,
    /// The zone origin stored at this node (if this is a zone end)
    zone_origin: Option<String>,
    /// Whether this node represents a complete zone
    is_zone: bool,
}

impl TrieNode {
    fn new() -> Self {
        Self {
            children: HashMap::new(),
            zone_origin: None,
            is_zone: false,
        }
    }
}

/// A radix trie for efficient DNS zone matching
#[derive(Debug, Clone)]
pub struct ZoneTrie {
    root: TrieNode,
    count: usize,
}

impl ZoneTrie {
    /// Create a new empty zone trie
    pub fn new() -> Self {
        Self {
            root: TrieNode::new(),
            count: 0,
        }
    }

    /// Insert a zone origin into the trie
    ///
    /// # Arguments
    /// * `origin` - The zone origin (e.g., "example.com")
    ///
    /// # Returns
    /// `true` if the zone was inserted, `false` if it already existed
    pub fn insert(&mut self, origin: &str) -> bool {
        let labels: Vec<String> = origin
            .trim_end_matches('.')
            .to_lowercase()
            .split('.')
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
            .collect();

        if labels.is_empty() {
            return false;
        }

        let mut current = &mut self.root;

        // Navigate/create path for labels in reverse order (TLD first)
        for label in labels.iter().rev() {
            current = current
                .children
                .entry(label.clone())
                .or_insert_with(TrieNode::new);
        }

        // Check if already exists
        if current.is_zone {
            return false;
        }

        // Mark as zone (store lowercased version for consistency)
        current.is_zone = true;
        current.zone_origin = Some(origin.trim_end_matches('.').to_lowercase());
        self.count += 1;
        true
    }

    /// Find the best matching zone for a given domain name
    ///
    /// # Arguments
    /// * `name` - The domain name to match (e.g., "sub.example.com")
    ///
    /// # Returns
    /// The origin of the best matching zone, or None if no match
    pub fn find_zone(&self, name: &str) -> Option<String> {
        let labels: Vec<String> = name
            .trim_end_matches('.')
            .to_lowercase()
            .split('.')
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
            .collect();

        if labels.is_empty() {
            return None;
        }

        let mut current = Some(&self.root);
        let mut best_match: Option<String> = None;

        // Navigate down the trie following labels in reverse order
        for label in labels.iter().rev() {
            if let Some(node) = current {
                if let Some(child) = node.children.get(label) {
                    current = Some(child);
                    // If this node is a zone, record it as a potential match
                    if child.is_zone {
                        best_match = child.zone_origin.clone();
                    }
                } else {
                    // No match found, stop here
                    break;
                }
            } else {
                break;
            }
        }

        best_match
    }

    /// Remove a zone from the trie
    ///
    /// # Arguments
    /// * `origin` - The zone origin to remove
    ///
    /// # Returns
    /// `true` if the zone was removed, `false` if it didn't exist
    pub fn remove(&mut self, origin: &str) -> bool {
        let labels: Vec<String> = origin
            .trim_end_matches('.')
            .to_lowercase()
            .split('.')
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
            .collect();

        if labels.is_empty() {
            return false;
        }

        // Navigate to the node
        let mut current = &mut self.root;
        for label in labels.iter().rev() {
            if !current.children.contains_key(label) {
                return false;
            }
            current = current.children.get_mut(label).unwrap();
        }

        if current.is_zone {
            current.is_zone = false;
            current.zone_origin = None;
            self.count -= 1;
            true
        } else {
            false
        }
    }

    /// Check if a zone exists in the trie
    pub fn contains(&self, origin: &str) -> bool {
        let labels: Vec<String> = origin
            .trim_end_matches('.')
            .to_lowercase()
            .split('.')
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
            .collect();

        if labels.is_empty() {
            return false;
        }

        let mut current = Some(&self.root);
        for label in labels.iter().rev() {
            if let Some(node) = current {
                current = node.children.get(label);
            } else {
                return false;
            }
        }

        current.map(|n| n.is_zone).unwrap_or(false)
    }

    /// Get the number of zones in the trie
    pub fn len(&self) -> usize {
        self.count
    }

    /// Check if the trie is empty
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Clear all zones from the trie
    pub fn clear(&mut self) {
        self.root = TrieNode::new();
        self.count = 0;
    }

    /// Get all zones in the trie
    pub fn get_all_zones(&self) -> Vec<String> {
        let mut zones = Vec::new();
        self.collect_zones(&self.root, &mut zones);
        zones
    }

    fn collect_zones(&self, node: &TrieNode, zones: &mut Vec<String>) {
        if node.is_zone {
            if let Some(origin) = &node.zone_origin {
                zones.push(origin.clone());
            }
        }
        for child in node.children.values() {
            self.collect_zones(child, zones);
        }
    }
}

impl Default for ZoneTrie {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_insert_and_find() {
        let mut trie = ZoneTrie::new();
        trie.insert("example.com");
        trie.insert("sub.example.com");
        trie.insert("test.org");

        assert_eq!(
            trie.find_zone("www.example.com"),
            Some("example.com".to_string())
        );
        assert_eq!(
            trie.find_zone("sub.example.com"),
            Some("sub.example.com".to_string())
        );
        assert_eq!(
            trie.find_zone("deep.sub.example.com"),
            Some("sub.example.com".to_string())
        );
        assert_eq!(trie.find_zone("www.test.org"), Some("test.org".to_string()));
        assert_eq!(trie.find_zone("nonexistent.com"), None);
    }

    #[test]
    fn test_longest_match() {
        let mut trie = ZoneTrie::new();
        trie.insert("com");
        trie.insert("example.com");
        trie.insert("sub.example.com");

        // Should match the most specific zone
        assert_eq!(
            trie.find_zone("www.sub.example.com"),
            Some("sub.example.com".to_string())
        );
        assert_eq!(
            trie.find_zone("www.example.com"),
            Some("example.com".to_string())
        );
        assert_eq!(trie.find_zone("www.other.com"), Some("com".to_string()));
    }

    #[test]
    fn test_remove() {
        let mut trie = ZoneTrie::new();
        trie.insert("example.com");
        assert!(trie.contains("example.com"));
        assert_eq!(trie.len(), 1);

        assert!(trie.remove("example.com"));
        assert!(!trie.contains("example.com"));
        assert_eq!(trie.len(), 0);
    }

    #[test]
    fn test_case_insensitive() {
        let mut trie = ZoneTrie::new();
        trie.insert("EXAMPLE.COM");

        assert_eq!(
            trie.find_zone("www.example.com"),
            Some("example.com".to_string())
        );
        assert_eq!(
            trie.find_zone("WWW.EXAMPLE.COM"),
            Some("example.com".to_string())
        );
    }

    #[test]
    fn test_empty_trie() {
        let trie = ZoneTrie::new();
        assert!(trie.is_empty());
        assert_eq!(trie.len(), 0);
        assert_eq!(trie.find_zone("example.com"), None);
    }
}
