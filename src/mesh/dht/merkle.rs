use std::collections::HashMap;

use rkyv::{Archive, Deserialize as RkyvDeserialize, Serialize as RkyvSerialize};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const MERKLE_TREE_DEGREE: usize = 2;

fn compute_leaf_hash(key: &str, value: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(key.as_bytes());
    hasher.update(b":");
    hasher.update(value);
    hasher.finalize().to_vec()
}

fn empty_hash() -> Vec<u8> {
    Sha256::digest(b"empty").to_vec()
}

#[derive(Debug, Clone, Serialize, Deserialize, Archive, RkyvSerialize, RkyvDeserialize)]
pub struct MerkleNode {
    pub hash: Vec<u8>,
    pub key: Option<String>,
    pub is_leaf: bool,
    pub children_hashes: Vec<Vec<u8>>,
    pub level: u32,
}

impl MerkleNode {
    pub fn new_leaf(key: String, value: &[u8], level: u32) -> Self {
        Self {
            hash: compute_leaf_hash(&key, value),
            key: Some(key),
            is_leaf: true,
            children_hashes: Vec::new(),
            level,
        }
    }

    pub fn new_internal(level: u32, children: &[&MerkleNode]) -> Self {
        let mut hasher = Sha256::new();
        for child in children {
            hasher.update(&child.hash);
        }
        Self {
            hash: hasher.finalize().to_vec(),
            key: None,
            is_leaf: false,
            children_hashes: children.iter().map(|c| c.hash.clone()).collect(),
            level,
        }
    }

    pub fn empty_hash() -> Vec<u8> {
        empty_hash()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Archive, RkyvSerialize, RkyvDeserialize)]
pub struct MerkleProof {
    pub root_hash: Vec<u8>,
    pub queried_keys: Vec<String>,
    pub proof_nodes: Vec<MerkleProofNode>,
    pub tree_height: u32,
}

impl MerkleProof {
    pub fn verify(&self, record_key: &str, record_value: &[u8]) -> bool {
        if self.queried_keys.is_empty() {
            return false;
        }

        let mut hasher = Sha256::new();
        hasher.update(record_key.as_bytes());
        hasher.update(b":");
        hasher.update(record_value);
        let leaf_hash: Vec<u8> = hasher.finalize().to_vec();

        let mut current_hash = leaf_hash.clone();

        let mut found_leaf = false;
        for node in &self.proof_nodes {
            if node.key.as_deref() == Some(record_key) {
                if node.hash != leaf_hash {
                    return false;
                }
                found_leaf = true;
                continue;
            }

            if !found_leaf {
                continue;
            }

            let mut h = Sha256::new();
            match node.position {
                ProofPosition::Left => {
                    h.update(&node.hash);
                    h.update(&current_hash);
                }
                ProofPosition::Right => {
                    h.update(&current_hash);
                    h.update(&node.hash);
                }
                ProofPosition::Root => {
                    continue;
                }
            }
            current_hash = h.finalize().to_vec();
        }

        current_hash == self.root_hash
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Archive, RkyvSerialize, RkyvDeserialize)]
pub struct MerkleProofNode {
    pub hash: Vec<u8>,
    pub position: ProofPosition,
    pub sibling_hash: Option<Vec<u8>>,
    pub key: Option<String>,
}

#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Serialize,
    Deserialize,
    Archive,
    RkyvSerialize,
    RkyvDeserialize,
)]
pub enum ProofPosition {
    Left,
    Right,
    Root,
}

#[derive(Debug, Clone)]
pub struct MerkleTree {
    levels: Vec<Vec<Vec<u8>>>,
    key_index: HashMap<String, usize>,
    sorted_keys: Vec<String>,
    values: HashMap<String, Vec<u8>>,
    height: u32,
}

impl MerkleTree {
    pub fn new() -> Self {
        Self {
            levels: Vec::new(),
            key_index: HashMap::new(),
            sorted_keys: Vec::new(),
            values: HashMap::new(),
            height: 0,
        }
    }

    pub fn from_records(records: &HashMap<String, Vec<u8>>) -> Self {
        if records.is_empty() {
            return Self::new();
        }

        let mut sorted_keys: Vec<String> = records.keys().cloned().collect();
        sorted_keys.sort();

        let key_index: HashMap<String, usize> = sorted_keys
            .iter()
            .enumerate()
            .map(|(i, k)| (k.clone(), i))
            .collect();

        let empty = empty_hash();

        let mut levels: Vec<Vec<Vec<u8>>> = Vec::new();

        let leaf_level: Vec<Vec<u8>> = sorted_keys
            .iter()
            .map(|k| {
                let empty_val = Vec::new();
                let value = records.get(k).unwrap_or(&empty_val);
                compute_leaf_hash(k, value)
            })
            .collect();
        levels.push(leaf_level);

        while levels.last().map_or(false, |l| l.len() > 1) {
            let current = levels.last().unwrap();
            let mut next: Vec<Vec<u8>> = Vec::new();
            for chunk in current.chunks(MERKLE_TREE_DEGREE) {
                let left = &chunk[0];
                let right = chunk.get(1).unwrap_or(&empty);
                let mut hasher = Sha256::new();
                hasher.update(left);
                hasher.update(right);
                next.push(hasher.finalize().to_vec());
            }
            levels.push(next);
        }

        let height = levels.len() as u32;

        let values: HashMap<String, Vec<u8>> = records
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();

        Self {
            levels,
            key_index,
            sorted_keys,
            values,
            height,
        }
    }

    pub fn insert_or_update(&mut self, key: String, value: &[u8]) {
        if let Some(&idx) = self.key_index.get(&key) {
            let new_hash = compute_leaf_hash(&key, value);
            self.levels[0][idx] = new_hash;
            self.values.insert(key, value.to_vec());
            self.rehash_path(idx);
        } else {
            let mut record_map = self.values.clone();
            record_map.insert(key, value.to_vec());
            *self = Self::from_records(&record_map);
        }
    }

    pub fn remove_key(&mut self, key: &str) {
        if !self.key_index.contains_key(key) {
            return;
        }
        let mut record_map = self.values.clone();
        record_map.remove(key);
        *self = Self::from_records(&record_map);
    }

    fn rehash_path(&mut self, leaf_idx: usize) {
        if self.height <= 1 {
            return;
        }
        let empty = empty_hash();
        let mut idx = leaf_idx;
        for level in 1..self.height as usize {
            idx /= 2;
            let left_idx = 2 * idx;
            let right_idx = left_idx + 1;
            let left = &self.levels[level - 1][left_idx];
            let right = self.levels[level - 1].get(right_idx).unwrap_or(&empty);
            let mut hasher = Sha256::new();
            hasher.update(left);
            hasher.update(right);
            self.levels[level][idx] = hasher.finalize().to_vec();
        }
    }

    pub fn root_hash(&self) -> Option<Vec<u8>> {
        self.levels
            .last()
            .and_then(|l| l.first())
            .cloned()
    }

    pub fn height(&self) -> u32 {
        self.height
    }

    pub fn is_empty(&self) -> bool {
        self.sorted_keys.is_empty()
    }

    pub fn get_leaf_hash(&self, key: &str) -> Option<Vec<u8>> {
        let idx = self.key_index.get(key)?;
        self.levels.first()?.get(*idx).cloned()
    }

    pub fn leaf_count(&self) -> usize {
        self.sorted_keys.len()
    }

    pub fn generate_proof(&self, keys: &[String]) -> Option<MerkleProof> {
        if self.is_empty() {
            return None;
        }

        let root_hash = self.root_hash()?;
        let empty = empty_hash();
        let mut proof_nodes = Vec::new();

        for key in keys {
            let leaf_idx = match self.key_index.get(key) {
                Some(&i) => i,
                None => continue,
            };

            let leaf_hash = self.levels[0][leaf_idx].clone();

            proof_nodes.push(MerkleProofNode {
                hash: leaf_hash.clone(),
                position: ProofPosition::Root,
                sibling_hash: None,
                key: Some(key.clone()),
            });

            let mut idx = leaf_idx;
            for level in 0..self.height as usize - 1 {
                let sibling_idx = idx ^ 1;
                let sibling_hash_val = self.levels[level]
                    .get(sibling_idx)
                    .cloned()
                    .unwrap_or_else(|| empty.clone());

                let position = if idx % 2 == 0 {
                    ProofPosition::Right
                } else {
                    ProofPosition::Left
                };

                proof_nodes.push(MerkleProofNode {
                    hash: sibling_hash_val,
                    position,
                    sibling_hash: None,
                    key: None,
                });

                idx /= 2;
            }
        }

        Some(MerkleProof {
            root_hash,
            queried_keys: keys.to_vec(),
            proof_nodes,
            tree_height: self.height,
        })
    }

    pub fn compute_differences(&self, other: &MerkleTree) -> (Vec<String>, Vec<String>) {
        let self_keys: std::collections::HashSet<_> = self.key_index.keys().cloned().collect();
        let other_keys: std::collections::HashSet<_> = other.key_index.keys().cloned().collect();

        let only_in_self: Vec<String> = self_keys.difference(&other_keys).cloned().collect();
        let only_in_other: Vec<String> = other_keys.difference(&self_keys).cloned().collect();

        let common_keys: Vec<&String> = self_keys.intersection(&other_keys).collect();

        let mut missing_from_other: Vec<String> = only_in_self;
        let mut present_in_other: Vec<String> = only_in_other;

        for key in common_keys {
            if let (Some(self_hash), Some(other_hash)) =
                (self.get_leaf_hash(key), other.get_leaf_hash(key))
            {
                if self_hash != other_hash {
                    missing_from_other.push(key.clone());
                    present_in_other.push(key.clone());
                }
            }
        }

        (missing_from_other, present_in_other)
    }
}

impl Default for MerkleTree {
    fn default() -> Self {
        Self::new()
    }
}

impl Serialize for MerkleTree {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        #[derive(Serialize)]
        struct SerdeMerkleTree {
            root: Option<MerkleNode>,
            leaf_count: usize,
            height: u32,
        }

        let root = self.root_hash().map(|hash| MerkleNode {
            hash,
            key: None,
            is_leaf: false,
            children_hashes: Vec::new(),
            level: self.height,
        });

        let s = SerdeMerkleTree {
            root,
            leaf_count: self.sorted_keys.len(),
            height: self.height,
        };
        s.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for MerkleTree {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[allow(dead_code)]
        struct SerdeMerkleTree {
            root: Option<MerkleNode>,
            leaf_count: usize,
            height: u32,
        }

        let SerdeMerkleTree {
            root: _,
            leaf_count: _,
            height,
        } = SerdeMerkleTree::deserialize(deserializer)?;

        Ok(MerkleTree {
            levels: Vec::new(),
            key_index: HashMap::new(),
            sorted_keys: Vec::new(),
            values: HashMap::new(),
            height,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_merkle_tree_empty() {
        let tree = MerkleTree::new();
        assert!(tree.is_empty());
        assert!(tree.root_hash().is_none());
    }

    #[test]
    fn test_merkle_tree_single_record() {
        let mut records = HashMap::new();
        records.insert("key1".to_string(), b"value1".to_vec());

        let tree = MerkleTree::from_records(&records);
        assert!(!tree.is_empty());
        assert!(tree.root_hash().is_some());
    }

    #[test]
    fn test_merkle_tree_multiple_records() {
        let mut records = HashMap::new();
        records.insert("key1".to_string(), b"value1".to_vec());
        records.insert("key2".to_string(), b"value2".to_vec());
        records.insert("key3".to_string(), b"value3".to_vec());

        let tree = MerkleTree::from_records(&records);
        assert!(!tree.is_empty());
        assert!(tree.root_hash().is_some());
    }

    #[test]
    fn test_merkle_proof_generation() {
        let mut records = HashMap::new();
        records.insert("key1".to_string(), b"value1".to_vec());
        records.insert("key2".to_string(), b"value2".to_vec());

        let tree = MerkleTree::from_records(&records);
        let proof = tree.generate_proof(&["key1".to_string()]);

        assert!(proof.is_some());
    }

    #[test]
    fn test_merkle_proof_verification() {
        let mut records = HashMap::new();
        records.insert("key1".to_string(), b"value1".to_vec());

        let tree = MerkleTree::from_records(&records);
        let proof = tree.generate_proof(&["key1".to_string()]).unwrap();

        assert!(proof.verify("key1", b"value1"));
        assert!(!proof.verify("key1", b"wrong_value"));
    }

    #[test]
    fn test_merkle_differences() {
        let mut records1 = HashMap::new();
        records1.insert("key1".to_string(), b"value1".to_vec());
        records1.insert("key2".to_string(), b"value2".to_vec());

        let mut records2 = HashMap::new();
        records2.insert("key2".to_string(), b"value2".to_vec());
        records2.insert("key3".to_string(), b"value3".to_vec());

        let tree1 = MerkleTree::from_records(&records1);
        let tree2 = MerkleTree::from_records(&records2);

        let (in_tree1, in_tree2) = tree1.compute_differences(&tree2);

        assert!(in_tree1.contains(&"key1".to_string()));
        assert!(in_tree2.contains(&"key3".to_string()));
    }

    #[test]
    fn test_incremental_update_existing_key() {
        let mut records = HashMap::new();
        records.insert("key1".to_string(), b"value1".to_vec());
        records.insert("key2".to_string(), b"value2".to_vec());
        records.insert("key3".to_string(), b"value3".to_vec());

        let mut tree = MerkleTree::from_records(&records);
        let original_root = tree.root_hash().unwrap();

        tree.insert_or_update("key2".to_string(), b"new_value2");

        let new_root = tree.root_hash().unwrap();
        assert_ne!(original_root, new_root);
        assert_eq!(tree.leaf_count(), 3);

        let mut expected_records = records.clone();
        expected_records.insert("key2".to_string(), b"new_value2".to_vec());
        let expected_tree = MerkleTree::from_records(&expected_records);
        assert_eq!(new_root, expected_tree.root_hash().unwrap());
    }

    #[test]
    fn test_incremental_insert_new_key() {
        let mut records = HashMap::new();
        records.insert("key1".to_string(), b"value1".to_vec());
        records.insert("key3".to_string(), b"value3".to_vec());

        let mut tree = MerkleTree::from_records(&records);
        tree.insert_or_update("key2".to_string(), b"value2");

        assert_eq!(tree.leaf_count(), 3);

        let mut expected_records = records.clone();
        expected_records.insert("key2".to_string(), b"value2".to_vec());
        let expected_tree = MerkleTree::from_records(&expected_records);
        assert_eq!(tree.root_hash().unwrap(), expected_tree.root_hash().unwrap());
    }

    #[test]
    fn test_incremental_remove_key() {
        let mut records = HashMap::new();
        records.insert("key1".to_string(), b"value1".to_vec());
        records.insert("key2".to_string(), b"value2".to_vec());
        records.insert("key3".to_string(), b"value3".to_vec());

        let mut tree = MerkleTree::from_records(&records);
        tree.remove_key("key2");

        assert_eq!(tree.leaf_count(), 2);

        let mut expected_records = HashMap::new();
        expected_records.insert("key1".to_string(), b"value1".to_vec());
        expected_records.insert("key3".to_string(), b"value3".to_vec());
        let expected_tree = MerkleTree::from_records(&expected_records);
        assert_eq!(tree.root_hash().unwrap(), expected_tree.root_hash().unwrap());
    }

    #[test]
    fn test_proof_verification_after_update() {
        let mut records = HashMap::new();
        records.insert("key1".to_string(), b"value1".to_vec());
        records.insert("key2".to_string(), b"value2".to_vec());
        records.insert("key3".to_string(), b"value3".to_vec());

        let mut tree = MerkleTree::from_records(&records);
        tree.insert_or_update("key2".to_string(), b"updated_value2");

        let proof = tree.generate_proof(&["key2".to_string()]).unwrap();
        assert!(proof.verify("key2", b"updated_value2"));
        assert!(!proof.verify("key2", b"value2"));
    }

    #[test]
    fn test_proof_verification_four_leaves() {
        let mut records = HashMap::new();
        records.insert("a".to_string(), b"va".to_vec());
        records.insert("b".to_string(), b"vb".to_vec());
        records.insert("c".to_string(), b"vc".to_vec());
        records.insert("d".to_string(), b"vd".to_vec());

        let tree = MerkleTree::from_records(&records);

        for key in &["a", "b", "c", "d"] {
            let proof = tree.generate_proof(&[key.to_string()]).unwrap();
            let value = format!("v{}", key);
            assert!(proof.verify(key, value.as_bytes()), "Proof failed for key {}", key);
        }
    }

    #[test]
    fn test_proof_verification_two_leaves() {
        let mut records = HashMap::new();
        records.insert("key1".to_string(), b"value1".to_vec());
        records.insert("key2".to_string(), b"value2".to_vec());

        let tree = MerkleTree::from_records(&records);

        let proof1 = tree.generate_proof(&["key1".to_string()]).unwrap();
        assert!(proof1.verify("key1", b"value1"));
        assert!(!proof1.verify("key1", b"value2"));

        let proof2 = tree.generate_proof(&["key2".to_string()]).unwrap();
        assert!(proof2.verify("key2", b"value2"));
        assert!(!proof2.verify("key2", b"value1"));
    }

    #[test]
    fn test_proof_verification_three_leaves() {
        let mut records = HashMap::new();
        records.insert("a".to_string(), b"va".to_vec());
        records.insert("b".to_string(), b"vb".to_vec());
        records.insert("c".to_string(), b"vc".to_vec());

        let tree = MerkleTree::from_records(&records);

        for key in &["a", "b", "c"] {
            let proof = tree.generate_proof(&[key.to_string()]).unwrap();
            let value = format!("v{}", key);
            assert!(proof.verify(key, value.as_bytes()), "Proof failed for key {}", key);
        }
    }

    #[test]
    fn test_update_preserves_other_keys() {
        let mut records = HashMap::new();
        for i in 0..10 {
            records.insert(format!("key{}", i), format!("value{}", i).into_bytes());
        }

        let mut tree = MerkleTree::from_records(&records);
        let hash_key5_before = tree.get_leaf_hash("key5").unwrap();

        tree.insert_or_update("key3".to_string(), b"updated");

        let hash_key5_after = tree.get_leaf_hash("key5").unwrap();
        assert_eq!(hash_key5_before, hash_key5_after, "Unrelated key hash should not change");
    }

    #[test]
    fn test_large_tree_incremental_update() {
        let mut records = HashMap::new();
        for i in 0..1000 {
            records.insert(format!("key{:06}", i), format!("value{}", i).into_bytes());
        }

        let mut tree = MerkleTree::from_records(&records);
        let root_before = tree.root_hash().unwrap();

        tree.insert_or_update("key000500".to_string(), b"updated");

        let root_after = tree.root_hash().unwrap();
        assert_ne!(root_before, root_after);

        let mut expected = records.clone();
        expected.insert("key000500".to_string(), b"updated".to_vec());
        let expected_tree = MerkleTree::from_records(&expected);
        assert_eq!(root_after, expected_tree.root_hash().unwrap());
    }

    #[test]
    fn test_incremental_update_deterministic() {
        let mut records = HashMap::new();
        for i in 0..100 {
            records.insert(format!("key{}", i), format!("value{}", i).into_bytes());
        }

        let mut tree1 = MerkleTree::from_records(&records);
        let mut tree2 = MerkleTree::from_records(&records);

        for i in (0..100).step_by(7) {
            let key = format!("key{}", i);
            let val = format!("updated{}", i);
            tree1.insert_or_update(key.clone(), val.as_bytes());
            tree2.insert_or_update(key.clone(), val.as_bytes());
        }

        assert_eq!(tree1.root_hash(), tree2.root_hash());
    }

    #[test]
    fn test_benchmark_incremental_update_100k() {
        let n = 100_000;
        let mut records = HashMap::new();
        for i in 0..n {
            records.insert(
                format!("key{:08}", i),
                format!("value{:08}", i).into_bytes(),
            );
        }

        let mut tree = MerkleTree::from_records(&records);
        assert!(!tree.is_empty());

        let update_count = 100;
        let start = std::time::Instant::now();
        for i in 0..update_count {
            let key = format!("key{:08}", (i * 997) % n);
            let value = format!("updated{}", i);
            tree.insert_or_update(key, value.as_bytes());
        }
        let elapsed = start.elapsed();
        let per_update = elapsed / update_count;

        assert!(
            per_update < std::time::Duration::from_millis(1),
            "Per-update time {:?} exceeds 1ms target for {} records",
            per_update,
            n,
        );
    }
}
