use std::time::Instant;

use serde::{Deserialize, Serialize};

use super::contact::PeerContact;
use super::node_id::NodeId;

pub const K_SIZE: usize = 20;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BucketError {
    PeerNotFound,
    BucketFull,
    SameNodeId,
}

#[derive(Clone, Debug)]
pub struct KBucket {
    pub index: usize,
    peers: Vec<PeerContact>,
    last_updated: Instant,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KBucketPersistable {
    pub index: usize,
    pub peers: Vec<PeerContact>,
    pub last_updated_secs: u64,
}

impl KBucket {
    pub fn new(index: usize) -> Self {
        Self {
            index,
            peers: Vec::with_capacity(K_SIZE),
            last_updated: Instant::now(),
        }
    }

    pub fn insert(&mut self, peer: PeerContact) -> Result<Option<PeerContact>, BucketError> {
        let node_id = peer.node_id;

        if let Some(existing_idx) = self.peers.iter().position(|p| p.node_id == node_id) {
            let mut existing = self.peers.remove(existing_idx);
            existing.mark_seen();
            self.peers.push(existing);
            self.last_updated = Instant::now();
            return Ok(None);
        }

        if self.peers.len() < K_SIZE {
            self.peers.push(peer);
            self.last_updated = Instant::now();
            Ok(None)
        } else {
            let _oldest = self.peers.first().cloned();
            Err(BucketError::BucketFull)
        }
    }

    pub fn try_insert(&mut self, peer: PeerContact) -> Option<PeerContact> {
        let node_id = peer.node_id;

        if let Some(existing_idx) = self.peers.iter().position(|p| p.node_id == node_id) {
            let mut existing = self.peers.remove(existing_idx);
            existing.mark_seen();
            self.peers.push(existing);
            self.last_updated = Instant::now();
            return None;
        }

        if self.peers.len() < K_SIZE {
            self.peers.push(peer);
            self.last_updated = Instant::now();
            None
        } else {
            if let Some(oldest) = self.peers.first() {
                if oldest.is_stale(std::time::Duration::from_secs(15 * 60)) {
                    let evicted = self.peers.remove(0);
                    self.peers.push(peer);
                    self.last_updated = Instant::now();
                    return Some(evicted);
                }
            }
            None
        }
    }

    pub fn remove(&mut self, node_id: &NodeId) -> Option<PeerContact> {
        if let Some(idx) = self.peers.iter().position(|p| p.node_id == *node_id) {
            self.last_updated = Instant::now();
            Some(self.peers.remove(idx))
        } else {
            None
        }
    }

    pub fn get_closest(&self, target: &NodeId, k: usize) -> Vec<&PeerContact> {
        let mut peers_with_distance: Vec<(&PeerContact, NodeId)> = self
            .peers
            .iter()
            .map(|p| (p, target.xor_distance(&p.node_id)))
            .collect();

        peers_with_distance.sort_by(|a, b| a.1.cmp(&b.1));

        peers_with_distance
            .into_iter()
            .take(k)
            .map(|(p, _)| p)
            .collect()
    }

    pub fn contains(&self, node_id: &NodeId) -> bool {
        self.peers.iter().any(|p| p.node_id == *node_id)
    }

    pub fn get(&self, node_id: &NodeId) -> Option<&PeerContact> {
        self.peers.iter().find(|p| p.node_id == *node_id)
    }

    pub fn get_mut(&mut self, node_id: &NodeId) -> Option<&mut PeerContact> {
        self.peers.iter_mut().find(|p| p.node_id == *node_id)
    }

    pub fn mark_seen(&mut self, node_id: &NodeId) -> bool {
        if let Some(peer) = self.peers.iter_mut().find(|p| p.node_id == *node_id) {
            peer.mark_seen();
            self.last_updated = Instant::now();
            true
        } else {
            false
        }
    }

    pub fn is_full(&self) -> bool {
        self.peers.len() >= K_SIZE
    }

    pub fn last_updated(&self) -> Instant {
        self.last_updated
    }

    pub fn len(&self) -> usize {
        self.peers.len()
    }

    pub fn is_empty(&self) -> bool {
        self.peers.is_empty()
    }

    pub fn get_oldest(&self) -> Option<&PeerContact> {
        self.peers.first()
    }

    pub fn get_oldest_mut(&mut self) -> Option<&mut PeerContact> {
        self.peers.first_mut()
    }

    pub fn get_all(&self) -> &[PeerContact] {
        &self.peers
    }

    pub fn get_all_mut(&mut self) -> &mut Vec<PeerContact> {
        &mut self.peers
    }

    pub fn replace_oldest_if_stale(
        &mut self,
        new_peer: PeerContact,
        stale_duration: std::time::Duration,
    ) -> Option<PeerContact> {
        if !self.is_full() {
            self.peers.push(new_peer);
            self.last_updated = Instant::now();
            return None;
        }

        if let Some(oldest) = self.peers.first() {
            if oldest.is_stale(stale_duration) {
                self.peers.remove(0);
                self.peers.push(new_peer);
                self.last_updated = Instant::now();
                return None;
            }
        }

        Some(new_peer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_contact(prefix: u8) -> PeerContact {
        let mut id = [prefix; 32];
        id[0] = prefix;
        PeerContact::new(
            NodeId(id),
            format!("node-{:02x}", prefix),
            "127.0.0.1".to_string(),
            443,
        )
    }

    #[test]
    fn test_insert_new_peer() {
        let mut bucket = KBucket::new(0);
        let peer = make_contact(0x01);

        let result = bucket.insert(peer.clone());
        assert!(result.is_ok());
        assert_eq!(bucket.len(), 1);
    }

    #[test]
    fn test_insert_duplicate() {
        let mut bucket = KBucket::new(0);
        let peer = make_contact(0x01);

        bucket.insert(peer.clone()).unwrap();
        bucket.insert(peer.clone()).unwrap();

        assert_eq!(bucket.len(), 1);
    }

    #[test]
    fn test_insert_full() {
        let mut bucket = KBucket::new(0);

        for i in 0..K_SIZE {
            bucket.insert(make_contact(i as u8)).unwrap();
        }

        assert!(bucket.is_full());

        let extra = make_contact(0xFF);
        let result = bucket.insert(extra);
        assert!(matches!(result, Err(BucketError::BucketFull)));
    }

    #[test]
    fn test_remove() {
        let mut bucket = KBucket::new(0);
        let peer = make_contact(0x01);

        bucket.insert(peer.clone()).unwrap();
        assert_eq!(bucket.len(), 1);

        let removed = bucket.remove(&peer.node_id);
        assert!(removed.is_some());
        assert_eq!(bucket.len(), 0);
    }

    #[test]
    fn test_contains() {
        let mut bucket = KBucket::new(0);
        let peer = make_contact(0x01);

        assert!(!bucket.contains(&peer.node_id));

        bucket.insert(peer).unwrap();

        let check = NodeId([0x01; 32]);
        assert!(bucket.contains(&check));
    }

    #[test]
    fn test_closest() {
        let mut bucket = KBucket::new(0);

        for i in 0..10 {
            bucket.insert(make_contact(i)).unwrap();
        }

        let target = NodeId([0x05; 32]);
        let closest = bucket.get_closest(&target, 3);

        assert_eq!(closest.len(), 3);
    }
}
