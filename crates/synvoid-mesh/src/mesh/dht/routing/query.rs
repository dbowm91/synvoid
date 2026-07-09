use std::collections::HashSet;

use super::contact::PeerContact;
use super::node_id::NodeId;
use metrics::counter;

pub const ALPHA: usize = 3;

pub struct LookupQuery {
    pub target: NodeId,
    contacted: HashSet<NodeId>,
    pub closest: Vec<PeerContact>,
    pending: Vec<PeerContact>,
    alpha: usize,
    completed: bool,
}

impl LookupQuery {
    pub fn new(target: NodeId) -> Self {
        Self {
            target,
            contacted: HashSet::new(),
            closest: Vec::new(),
            pending: Vec::new(),
            alpha: ALPHA,
            completed: false,
        }
    }

    pub fn with_alpha(mut self, alpha: usize) -> Self {
        self.alpha = alpha;
        self
    }

    pub fn init(&mut self, initial_peers: Vec<PeerContact>) {
        let mut seen: HashSet<NodeId> = HashSet::new();
        for peer in initial_peers {
            if !self.contacted.contains(&peer.node_id) && seen.insert(peer.node_id) {
                self.closest.push(peer.clone());
                self.pending.push(peer);
            }
        }

        self.closest.sort_by(|a, b| {
            let dist_a = self.target.xor_distance(&a.node_id);
            let dist_b = self.target.xor_distance(&b.node_id);
            dist_a.cmp(&dist_b)
        });
    }

    pub fn next_peers_to_query(&self) -> Vec<&PeerContact> {
        if self.completed {
            return Vec::new();
        }

        let mut to_query: Vec<&PeerContact> = Vec::new();
        let mut seen: HashSet<NodeId> = HashSet::new();

        for peer in &self.pending {
            if !self.contacted.contains(&peer.node_id) && seen.insert(peer.node_id) {
                to_query.push(peer);
            }
        }

        if to_query.len() < self.alpha {
            for peer in &self.closest {
                if !self.contacted.contains(&peer.node_id)
                    && seen.insert(peer.node_id)
                    && to_query.len() < self.alpha
                {
                    to_query.push(peer);
                }
            }
        }

        to_query
    }

    pub fn mark_queried(&mut self, peer: &PeerContact) {
        self.contacted.insert(peer.node_id);
        self.pending.retain(|p| p.node_id != peer.node_id);
    }

    pub fn add_pending(&mut self, peers: Vec<PeerContact>) {
        for peer in peers {
            if !self.contacted.contains(&peer.node_id)
                && !self.pending.iter().any(|p| p.node_id == peer.node_id)
            {
                self.pending.push(peer);
            }
        }
    }

    pub fn process_response(&mut self, peer: &PeerContact, new_peers: Vec<PeerContact>) {
        self.mark_queried(peer);

        let mut added = false;
        for new_peer in new_peers {
            if !self.contacted.contains(&new_peer.node_id) {
                if !self.closest.iter().any(|p| p.node_id == new_peer.node_id) {
                    self.closest.push(new_peer.clone());
                    added = true;
                }
                if !self.pending.iter().any(|p| p.node_id == new_peer.node_id) {
                    self.pending.push(new_peer);
                }
            }
        }

        if added {
            self.closest.sort_by(|a, b| {
                let dist_a = self.target.xor_distance(&a.node_id);
                let dist_b = self.target.xor_distance(&b.node_id);
                dist_a.cmp(&dist_b)
            });
        }
    }

    pub fn is_complete(&self) -> bool {
        if self.closest.is_empty() {
            return self.pending.is_empty();
        }

        if self.pending.is_empty() {
            return true;
        }

        let mut queried_count = 0;
        for peer in &self.closest {
            if self.contacted.contains(&peer.node_id) {
                queried_count += 1;
            }
        }

        let closest_dist = self
            .target
            .xor_distance(&self.closest.first().unwrap().node_id);

        for peer in &self.pending {
            let peer_dist = self.target.xor_distance(&peer.node_id);
            if peer_dist < closest_dist {
                return false;
            }
        }

        queried_count >= self.closest.len().min(self.alpha)
    }

    pub fn get_result(&self) -> Vec<PeerContact> {
        self.closest.clone()
    }

    pub fn contacted_count(&self) -> usize {
        self.contacted.len()
    }

    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }

    pub fn reset_pending(&mut self) {
        for peer in &self.closest {
            if !self.contacted.contains(&peer.node_id) {
                self.pending.push(peer.clone());
            }
        }
    }
}

pub struct DhtQuery {
    pub target_key: String,
    pub lookup: LookupQuery,
    pub quorum: usize,
    pub responses: Vec<QueryResponse>,
    pub completed: bool,
}

#[derive(Clone)]
pub struct QueryResponse {
    pub peer: PeerContact,
    pub value: Option<Vec<u8>>,
    pub closer_peers: Vec<PeerContact>,
}

impl DhtQuery {
    pub fn new(target_key: String, target_node_id: NodeId, quorum: usize) -> Self {
        Self {
            target_key,
            lookup: LookupQuery::new(target_node_id),
            quorum,
            responses: Vec::new(),
            completed: false,
        }
    }

    pub fn init(&mut self, initial_peers: Vec<PeerContact>) {
        self.lookup.init(initial_peers);
    }

    pub fn next_peers(&self) -> Vec<&PeerContact> {
        self.lookup.next_peers_to_query()
    }

    pub fn record_response(
        &mut self,
        peer: PeerContact,
        value: Option<Vec<u8>>,
        closer_peers: Vec<PeerContact>,
    ) {
        self.responses.push(QueryResponse {
            peer,
            value,
            closer_peers: closer_peers.clone(),
        });

        self.lookup
            .process_response(&self.responses.last().unwrap().peer, closer_peers);

        let value_count = self.responses.iter().filter(|r| r.value.is_some()).count();
        if value_count >= self.quorum && !self.completed {
            self.completed = true;
            counter!("synvoid.dht.quorum.achieved", "type" => "read").increment(1);
            tracing::debug!("DHT read quorum achieved: {}/{}", value_count, self.quorum);
        }
    }

    pub fn is_complete(&self) -> bool {
        self.completed || self.lookup.is_complete()
    }

    pub fn get_closest_peers(&self) -> Vec<PeerContact> {
        self.lookup.get_result()
    }

    pub fn get_best_value(&self) -> Option<(PeerContact, Vec<u8>)> {
        self.responses
            .iter()
            .filter_map(|r| r.value.as_ref().map(|v| (r.peer.clone(), v.clone())))
            .next()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_contact(id: &str) -> PeerContact {
        PeerContact::new(
            NodeId::from_node_id_string(id),
            id.to_string(),
            "127.0.0.1".to_string(),
            443,
        )
    }

    #[test]
    fn test_lookup_init() {
        let target = NodeId::from_node_id_string("target");
        let mut query = LookupQuery::new(target);

        let peers = vec![
            make_contact("peer1"),
            make_contact("peer2"),
            make_contact("peer3"),
        ];

        query.init(peers);

        assert_eq!(query.closest.len(), 3);
        assert!(!query.next_peers_to_query().is_empty());
    }

    #[test]
    fn test_mark_queried() {
        let target = NodeId::from_node_id_string("target");
        let mut query = LookupQuery::new(target);

        let peer = make_contact("peer1");
        query.init(vec![peer.clone()]);

        query.mark_queried(&peer);

        assert!(query.contacted.contains(&peer.node_id));
    }

    #[test]
    fn test_process_response() {
        let target = NodeId::from_node_id_string("target");
        let mut query = LookupQuery::new(target);

        let peer1 = make_contact("peer1");
        query.init(vec![peer1.clone()]);

        let new_peers = vec![make_contact("peer2"), make_contact("peer3")];

        query.process_response(&peer1, new_peers);

        assert_eq!(query.closest.len(), 3);
    }

    #[test]
    fn test_is_complete() {
        let target = NodeId::from_node_id_string("target");
        let mut query = LookupQuery::new(target);

        let peer = make_contact("peer1");
        query.init(vec![peer.clone()]);

        assert!(!query.is_complete());

        query.mark_queried(&peer);

        assert!(query.is_complete());
    }

    #[test]
    fn test_dht_query_quorum() {
        let target = NodeId::from_node_id_string("target");
        let mut query = DhtQuery::new("test_key".to_string(), target, 2);

        let peer1 = make_contact("peer1");
        let peer2 = make_contact("peer2");

        query.init(vec![peer1.clone(), peer2.clone()]);

        query.record_response(peer1, Some(b"value1".to_vec()), vec![]);
        assert!(!query.is_complete());

        query.record_response(peer2, Some(b"value2".to_vec()), vec![]);
        assert!(query.is_complete());
    }
}
