use std::cmp::Ordering;
use std::fmt;
use std::ops::BitXor;

use rkyv::{Archive, Deserialize as RkyvDeserialize, Serialize as RkyvSerialize};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const NODE_ID_LEN: usize = 32;
pub const NODE_ID_POW_DIFFICULTY: u32 = 16;
pub const NODE_ID_POW_PREFIX: &[u8] = b"nodeid-pow-v1:";

#[derive(
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    Serialize,
    Deserialize,
    Archive,
    RkyvDeserialize,
    RkyvSerialize,
)]
pub struct NodeId(pub [u8; NODE_ID_LEN]);

impl NodeId {
    pub fn from_node_id_string(s: &str) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(s.as_bytes());
        let result = hasher.finalize();
        let mut id = [0u8; NODE_ID_LEN];
        id.copy_from_slice(&result);
        NodeId(id)
    }

    pub fn from_public_key(public_key: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(b"nodeid-v1:");
        hasher.update(public_key);
        let result = hasher.finalize();
        let mut id = [0u8; NODE_ID_LEN];
        id.copy_from_slice(&result);
        NodeId(id)
    }

    pub fn from_hex(hex: &str) -> Option<Self> {
        let bytes = hex::decode(hex).ok()?;
        Self::from_bytes(&bytes)
    }

    pub fn random() -> Self {
        // rand::rng() uses OsRng internally in rand 0.9+ - acceptable for node ID
        let mut id = [0u8; NODE_ID_LEN];
        use rand::RngCore;
        rand::rng().fill_bytes(&mut id);
        NodeId(id)
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != NODE_ID_LEN {
            return None;
        }
        let mut id = [0u8; NODE_ID_LEN];
        id.copy_from_slice(bytes);
        Some(NodeId(id))
    }

    pub fn xor_distance(&self, other: &NodeId) -> NodeId {
        let mut result = [0u8; NODE_ID_LEN];
        for (i, result_byte) in result.iter_mut().enumerate().take(NODE_ID_LEN) {
            *result_byte = self.0[i] ^ other.0[i];
        }
        NodeId(result)
    }

    pub fn common_prefix_len(&self, other: &NodeId) -> usize {
        for byte_idx in 0..NODE_ID_LEN {
            let xor_byte = self.0[byte_idx] ^ other.0[byte_idx];
            if xor_byte != 0 {
                for bit_idx in 0..8 {
                    if (xor_byte & (0x80 >> bit_idx)) != 0 {
                        return byte_idx * 8 + bit_idx;
                    }
                }
                return NODE_ID_LEN * 8;
            }
        }
        NODE_ID_LEN * 8
    }

    pub fn as_hex(&self) -> String {
        hex::encode(self.0)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn is_zero(&self) -> bool {
        self.0.iter().all(|&b| b == 0)
    }

    pub fn from_u64(val: u64) -> Self {
        let mut id = [0u8; NODE_ID_LEN];
        id[NODE_ID_LEN - 8..].copy_from_slice(&val.to_be_bytes());
        NodeId(id)
    }

    pub fn bucket_index(&self, local: &NodeId) -> usize {
        let prefix_len = local.common_prefix_len(self);
        255 - prefix_len.min(255)
    }

    pub fn generate_with_pow(public_key: &[u8], nonce: u64) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(NODE_ID_POW_PREFIX);
        hasher.update(public_key);
        hasher.update(nonce.to_le_bytes());
        let result = hasher.finalize();
        let mut id = [0u8; NODE_ID_LEN];
        id.copy_from_slice(&result);
        NodeId(id)
    }

    pub fn verify_pow(&self, public_key: &[u8], nonce: u64) -> bool {
        let hash = {
            let mut hasher = Sha256::new();
            hasher.update(NODE_ID_POW_PREFIX);
            hasher.update(public_key);
            hasher.update(nonce.to_le_bytes());
            hasher.finalize()
        };

        let leading_zeros = hash.iter().take_while(|&&b| b == 0).count();
        leading_zeros >= (NODE_ID_POW_DIFFICULTY as usize / 8)
    }

    pub fn find_pow_nonce(public_key: &[u8]) -> Option<u64> {
        const MAX_ITERATIONS: u64 = 10_000_000;
        for nonce in 0..MAX_ITERATIONS {
            let hash = {
                let mut hasher = Sha256::new();
                hasher.update(NODE_ID_POW_PREFIX);
                hasher.update(public_key);
                hasher.update(nonce.to_le_bytes());
                hasher.finalize()
            };

            let leading_zeros = hash.iter().take_while(|&&b| b == 0).count();
            if leading_zeros >= (NODE_ID_POW_DIFFICULTY as usize / 8) {
                return Some(nonce);
            }
        }
        None
    }

    pub fn generate_random_in_bucket(bucket_index: usize, local: &NodeId) -> NodeId {
        let prefix_len = 255usize.saturating_sub(bucket_index);
        let mut id = local.0;

        if prefix_len < 256 {
            let divergence_bit = 255usize - prefix_len;
            let byte_idx = divergence_bit / 8;
            let bit_idx = 7 - (divergence_bit % 8);
            id[byte_idx] ^= 1 << bit_idx;
        }

        use rand::RngCore;
        let mut rng = rand::rng();
        rng.fill_bytes(&mut id);

        NodeId(id)
    }
}

impl fmt::Debug for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "NodeId({})", &self.as_hex()[..16])
    }
}

impl fmt::Display for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_hex())
    }
}

impl PartialOrd for NodeId {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for NodeId {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0.cmp(&other.0)
    }
}

impl BitXor for NodeId {
    type Output = NodeId;

    fn bitxor(self, rhs: NodeId) -> Self::Output {
        self.xor_distance(&rhs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_node_id_from_string() {
        let id = NodeId::from_node_id_string("node-abcdef12");
        assert_eq!(id.0.len(), 32);
    }

    #[test]
    fn test_xor_distance() {
        let id1 = NodeId::from_bytes(&[0xFF; 32]).unwrap();
        let id2 = NodeId::from_bytes(&[0x00; 32]).unwrap();
        let dist = id1.xor_distance(&id2);
        assert_eq!(dist.0, [0xFF; 32]);
    }

    #[test]
    fn test_xor_distance_zero() {
        let id1 = NodeId::random();
        let id2 = id1;
        let dist = id1.xor_distance(&id2);
        assert!(dist.is_zero());
    }

    #[test]
    fn test_common_prefix_len_identical() {
        let id1 = NodeId::random();
        let id2 = id1;
        assert_eq!(id1.common_prefix_len(&id2), 256);
    }

    #[test]
    fn test_common_prefix_len_different() {
        let id1 = NodeId::from_bytes(&[0x00; 32]).unwrap();
        let id2 = NodeId::from_bytes(&[0xFF; 32]).unwrap();
        assert_eq!(id1.common_prefix_len(&id2), 0);
    }

    #[test]
    fn test_bucket_index() {
        let local = NodeId::from_bytes(&[0x00; 32]).unwrap();

        let mut close_bytes = [0x00u8; 32];
        close_bytes[1] = 0x01;
        let close = NodeId::from_bytes(&close_bytes).unwrap();

        let far = NodeId::from_bytes(&[0xFFu8; 32]).unwrap();

        assert!(local.bucket_index(&close) < local.bucket_index(&far));
    }

    #[test]
    fn test_ordering() {
        let mut ids = [
            NodeId::from_bytes(&[0x02; 32]).unwrap(),
            NodeId::from_bytes(&[0x01; 32]).unwrap(),
            NodeId::from_bytes(&[0x03; 32]).unwrap(),
        ];
        ids.sort();
        assert_eq!(ids[0].0[0], 0x01);
        assert_eq!(ids[1].0[0], 0x02);
        assert_eq!(ids[2].0[0], 0x03);
    }

    #[test]
    fn test_node_id_from_public_key() {
        let test_key = b"test-public-key-bytes-123456789012";
        let node_id = NodeId::from_public_key(test_key);

        let expected = {
            let mut hasher = Sha256::new();
            hasher.update(b"nodeid-v1:");
            hasher.update(test_key);
            let result = hasher.finalize();
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&result);
            NodeId(arr)
        };

        assert_eq!(node_id, expected);
    }

    #[test]
    fn test_node_id_from_hex() {
        let hex = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
        let node_id = NodeId::from_hex(hex).unwrap();
        assert_eq!(node_id.as_hex(), hex);
    }

    #[test]
    fn test_node_id_from_hex_invalid() {
        assert!(NodeId::from_hex("invalid").is_none());
        assert!(NodeId::from_hex("010203").is_none());
    }
}
