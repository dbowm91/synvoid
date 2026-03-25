use std::collections::HashMap;

use rkyv::{Archive, Deserialize as RkyvDeserialize, Serialize as RkyvSerialize};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const MERKLE_TREE_DEGREE: usize = 16;

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
        let mut hasher = Sha256::new();
        hasher.update(key.as_bytes());
        hasher.update(b":");
        hasher.update(value);

        Self {
            hash: hasher.finalize().to_vec(),
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
        Sha256::digest(b"empty").to_vec()
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
        use sha2::{Digest, Sha256};

        if self.queried_keys.is_empty() {
            return false;
        }

        let mut hasher = Sha256::new();
        hasher.update(record_key.as_bytes());
        hasher.update(b":");
        hasher.update(record_value);
        let leaf_hash: Vec<u8> = hasher.finalize().to_vec();

        let mut proof_nodes = self.proof_nodes.clone();
        proof_nodes.reverse();

        let mut current_hash = leaf_hash.clone();

        for node in &proof_nodes {
            if node.key.as_deref() == Some(record_key) {
                if node.hash != leaf_hash {
                    return false;
                }
                continue;
            }

            let mut hasher = Sha256::new();

            match node.position {
                ProofPosition::Left => {
                    if let Some(ref sibling) = node.sibling_hash {
                        hasher.update(sibling);
                    }
                    hasher.update(&current_hash);
                }
                ProofPosition::Right => {
                    hasher.update(&current_hash);
                    if let Some(ref sibling) = node.sibling_hash {
                        hasher.update(sibling);
                    }
                }
                ProofPosition::Root => {
                    if node.hash != leaf_hash {
                        return false;
                    }
                    continue;
                }
            }

            current_hash = hasher.finalize().to_vec();
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
    root: Option<MerkleNode>,
    leaf_map: HashMap<String, Vec<u8>>,
    height: u32,
    node_map: HashMap<Vec<u8>, MerkleNode>,
    key_path_map: HashMap<String, Vec<usize>>,
}

impl MerkleTree {
    pub fn new() -> Self {
        Self {
            root: None,
            leaf_map: HashMap::new(),
            height: 0,
            node_map: HashMap::new(),
            key_path_map: HashMap::new(),
        }
    }

    pub fn from_records(records: &HashMap<String, Vec<u8>>) -> Self {
        if records.is_empty() {
            return Self::new();
        }

        let mut keys: Vec<String> = records.keys().cloned().collect();
        keys.sort();

        let empty_vec = Vec::new();

        let leaves: Vec<MerkleNode> = keys
            .iter()
            .map(|k| {
                let value = records.get(k).unwrap_or(&empty_vec);
                MerkleNode::new_leaf(k.clone(), value, 0)
            })
            .collect();

        let leaf_map: HashMap<String, Vec<u8>> = keys
            .iter()
            .filter_map(|k| {
                records.get(k).map(|v| {
                    let mut hasher = Sha256::new();
                    hasher.update(k.as_bytes());
                    hasher.update(b":");
                    hasher.update(v);
                    (k.clone(), hasher.finalize().to_vec())
                })
            })
            .collect();

        let mut node_map: HashMap<Vec<u8>, MerkleNode> = HashMap::new();
        for leaf in &leaves {
            node_map.insert(leaf.hash.clone(), leaf.clone());
        }

        let mut key_path_map: HashMap<String, Vec<usize>> = HashMap::new();
        for k in &keys {
            key_path_map.insert(k.clone(), Vec::new());
        }

        let (root, height) = Self::build_tree(&leaves, 1, &mut node_map, &mut key_path_map, &keys);

        Self {
            root,
            leaf_map,
            height,
            node_map,
            key_path_map,
        }
    }

    fn build_tree(
        leaves: &[MerkleNode],
        start_level: u32,
        node_map: &mut HashMap<Vec<u8>, MerkleNode>,
        key_path_map: &mut HashMap<String, Vec<usize>>,
        all_keys: &[String],
    ) -> (Option<MerkleNode>, u32) {
        if leaves.is_empty() {
            return (None, 0);
        }

        if leaves.len() == 1 {
            return (Some(leaves[0].clone()), 1);
        }

        let mut level = start_level;
        let empty_hash = MerkleNode::empty_hash();

        let mut leaf_positions: HashMap<usize, Vec<usize>> = HashMap::new();
        for (i, _) in leaves.iter().enumerate() {
            leaf_positions.insert(i, Vec::new());
        }

        let mut current_leaves: Vec<(usize, MerkleNode)> = leaves
            .iter()
            .enumerate()
            .map(|(i, l)| (i, l.clone()))
            .collect();

        while current_leaves.len() > 1 {
            let chunks: Vec<Vec<(usize, MerkleNode)>> = current_leaves
                .chunks(MERKLE_TREE_DEGREE)
                .map(|c| c.to_vec())
                .collect();

            let mut next_leaves: Vec<(usize, MerkleNode)> = Vec::new();
            let mut internal_nodes: Vec<MerkleNode> = Vec::new();
            let empty_node = MerkleNode {
                hash: empty_hash.clone(),
                key: None,
                is_leaf: false,
                children_hashes: Vec::new(),
                level,
            };

            for (chunk_idx, chunk) in chunks.into_iter().enumerate() {
                if chunk.len() == 1 {
                    next_leaves.push(chunk[0].clone());
                } else {
                    let mut padded: Vec<&MerkleNode> = chunk.iter().map(|(_, n)| n).collect();
                    while padded.len() < MERKLE_TREE_DEGREE {
                        padded.push(&empty_node);
                    }

                    let internal = MerkleNode::new_internal(level, &padded);
                    node_map.insert(internal.hash.clone(), internal.clone());
                    internal_nodes.push(internal.clone());
                    next_leaves.push((chunk[0].0, internal_nodes.last().unwrap().clone()));

                    for (orig_idx, _) in chunk.iter() {
                        if let Some(path) = leaf_positions.get_mut(orig_idx) {
                            path.push(chunk_idx);
                        }
                    }
                }
            }

            current_leaves = next_leaves;
            level += 1;
        }

        for (key_idx, key) in all_keys.iter().enumerate() {
            if let Some(path) = leaf_positions.get(&key_idx) {
                key_path_map.insert(key.clone(), path.clone());
            }
        }

        (Some(current_leaves[0].1.clone()), level)
    }

    pub fn root_hash(&self) -> Option<Vec<u8>> {
        self.root.as_ref().map(|n| n.hash.clone())
    }

    pub fn height(&self) -> u32 {
        self.height
    }

    pub fn is_empty(&self) -> bool {
        self.root.is_none()
    }

    pub fn get_leaf_hash(&self, key: &str) -> Option<Vec<u8>> {
        self.leaf_map.get(key).cloned()
    }

    pub fn generate_proof(&self, keys: &[String]) -> Option<MerkleProof> {
        let root = self.root.as_ref()?;

        let mut proof_nodes = Vec::new();
        for key in keys {
            if let Some(path) = self.find_proof_path(key) {
                proof_nodes.extend(path);
            }
        }

        Some(MerkleProof {
            root_hash: root.hash.clone(),
            queried_keys: keys.to_vec(),
            proof_nodes,
            tree_height: self.height,
        })
    }

    fn find_proof_path(&self, key: &str) -> Option<Vec<MerkleProofNode>> {
        let leaf_hash = self.leaf_map.get(key)?.clone();

        let path_indices = self.key_path_map.get(key)?;

        let mut proof_nodes = Vec::new();

        let mut current_node = self.root.as_ref()?;

        for &child_index in path_indices.iter() {
            let child_count = current_node.children_hashes.len();
            if child_count == 0 || child_index >= child_count {
                return None;
            }

            if child_index > 0 {
                let sibling_index = child_index - 1;
                proof_nodes.push(MerkleProofNode {
                    hash: current_node.children_hashes[sibling_index].clone(),
                    position: ProofPosition::Left,
                    sibling_hash: Some(current_node.children_hashes[child_index].clone()),
                    key: None,
                });
            }

            if child_index < child_count - 1 {
                let sibling_index = child_index + 1;
                proof_nodes.push(MerkleProofNode {
                    hash: current_node.children_hashes[sibling_index].clone(),
                    position: ProofPosition::Right,
                    sibling_hash: Some(current_node.children_hashes[child_index].clone()),
                    key: None,
                });
            }

            let next_hash = current_node.children_hashes[child_index].clone();
            current_node = self.node_map.get(&next_hash)?;
        }

        proof_nodes.push(MerkleProofNode {
            hash: leaf_hash.clone(),
            position: ProofPosition::Root,
            sibling_hash: None,
            key: Some(key.to_string()),
        });

        Some(proof_nodes)
    }

    pub fn compute_differences(&self, other: &MerkleTree) -> (Vec<String>, Vec<String>) {
        let self_keys: std::collections::HashSet<_> = self.leaf_map.keys().cloned().collect();
        let other_keys: std::collections::HashSet<_> = other.leaf_map.keys().cloned().collect();

        let only_in_self: Vec<String> = self_keys.difference(&other_keys).cloned().collect();
        let only_in_other: Vec<String> = other_keys.difference(&self_keys).cloned().collect();

        let common_keys: Vec<&String> = self_keys.intersection(&other_keys).collect();

        let mut missing_from_other: Vec<String> = only_in_self.clone();
        let mut present_in_other: Vec<String> = only_in_other.clone();

        for key in common_keys {
            if let (Some(self_hash), Some(other_hash)) =
                (self.leaf_map.get(key), other.leaf_map.get(key))
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

        let s = SerdeMerkleTree {
            root: self.root.clone(),
            leaf_count: self.leaf_map.len(),
            height: self.height,
        };
        s.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for MerkleTree {
    fn deserialize<D>(_deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Ok(MerkleTree::new())
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
}
