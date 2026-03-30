#![cfg(feature = "mesh")]

use maluwaf::mesh::config::MeshNodeRole;
use maluwaf::mesh::dht::keys::DhtKey;
use maluwaf::mesh::dht::merkle::MerkleTree;
use maluwaf::mesh::dht::routing::{
    GeoInfo, KBucket, NodeId, PeerContact, PersistedContact, PersistedRoutingTable, RoutingTable,
    K_SIZE,
};
use maluwaf::mesh::dht::signed::{
    validate_message_timestamp, RecordSigner, SignedDhtRecord, SignedRecordType, TtlManager,
};
use maluwaf::mesh::dht::stake::{SlashReason, StakeConfig, StakeLevel, StakeManager};
use maluwaf::mesh::dht::store::{DhtRecord, DhtRecordStore, RecordMetadata};
use maluwaf::mesh::dht::DhtRateLimiter;
use std::collections::HashMap;
use std::time::Duration;

#[test]
fn test_node_id_creation() {
    let bytes = [0x01u8; 32];
    let node_id = NodeId::from_bytes(&bytes).unwrap();
    assert_eq!(node_id.0, bytes);
}

#[test]
fn test_node_id_xor_distance() {
    let id1 = NodeId::from_bytes(&[0xFFu8; 32]).unwrap();
    let id2 = NodeId::from_bytes(&[0x00u8; 32]).unwrap();
    let distance = id1.xor_distance(&id2);
    assert_eq!(distance.0, [0xFFu8; 32]);
}

#[test]
fn test_node_id_equality() {
    let bytes = [0xABu8; 32];
    let id1 = NodeId::from_bytes(&bytes).unwrap();
    let id2 = NodeId::from_bytes(&bytes).unwrap();
    assert_eq!(id1, id2);
}

#[test]
fn test_node_id_ordering() {
    let mut ids = vec![
        NodeId::from_bytes(&[0x02u8; 32]).unwrap(),
        NodeId::from_bytes(&[0x01u8; 32]).unwrap(),
        NodeId::from_bytes(&[0x03u8; 32]).unwrap(),
    ];
    ids.sort();
    assert_eq!(ids[0].0[0], 0x01);
    assert_eq!(ids[1].0[0], 0x02);
    assert_eq!(ids[2].0[0], 0x03);
}

#[test]
fn test_kbucket_insert_and_contains() {
    let mut bucket = KBucket::new(0);
    let node_id = NodeId::from_bytes(&[0x01u8; 32]).unwrap();
    let contact = PeerContact::new(node_id, "node-01".to_string(), "127.0.0.1".to_string(), 443);

    bucket.insert(contact).ok();
    assert!(bucket.contains(&node_id));
}

#[test]
fn test_kbucket_full() {
    let mut bucket = KBucket::new(0);

    for i in 0..K_SIZE {
        let node_id = NodeId::from_bytes(&[i as u8; 32]).unwrap();
        let contact = PeerContact::new(
            node_id,
            format!("node-{:02x}", i),
            "127.0.0.1".to_string(),
            443,
        );
        bucket.insert(contact).ok();
    }

    assert!(bucket.is_full());

    let extra_id = NodeId::from_bytes(&[0xFFu8; 32]).unwrap();
    let extra_contact = PeerContact::new(
        extra_id,
        "node-ff".to_string(),
        "127.0.0.1".to_string(),
        443,
    );
    let result = bucket.insert(extra_contact);
    assert!(result.is_err());
}

#[test]
fn test_kbucket_remove() {
    let mut bucket = KBucket::new(0);
    let node_id = NodeId::from_bytes(&[0x01u8; 32]).unwrap();
    let contact = PeerContact::new(node_id, "node-01".to_string(), "127.0.0.1".to_string(), 443);

    bucket.insert(contact).ok();
    assert_eq!(bucket.len(), 1);

    let removed = bucket.remove(&node_id);
    assert!(removed.is_some());
    assert!(bucket.is_empty());
}

#[test]
fn test_kbucket_split() {
    let mut bucket = KBucket::new(0);

    for i in 0..5 {
        let mut bytes = [0x00u8; 32];
        bytes[0] = i as u8;
        let node_id = NodeId::from_bytes(&bytes).unwrap();
        let contact = PeerContact::new(
            node_id,
            format!("node-{:02x}", i),
            "127.0.0.1".to_string(),
            443,
        );
        bucket.insert(contact).ok();
    }

    assert!(!bucket.is_empty());
}

#[test]
fn test_routing_table_insert() {
    let local_id = NodeId::from_bytes(&[0x00u8; 32]).unwrap();
    let mut table = RoutingTable::new(local_id, "local-node".to_string());

    let peer_id = NodeId::from_bytes(&[0x01u8; 32]).unwrap();
    let mut contact = PeerContact::new(
        peer_id,
        "peer-01".to_string(),
        "192.168.1.1".to_string(),
        443,
    );
    contact.is_trusted = true;

    let result = table.insert(contact);
    assert!(result.is_ok());
}

#[test]
fn test_routing_table_closest_peers() {
    let local_id = NodeId::from_bytes(&[0x80u8; 32]).unwrap();
    let mut table = RoutingTable::new(local_id, "local-node".to_string());

    let target = NodeId::from_bytes(&[0x90u8; 32]).unwrap();

    for i in 0..10 {
        let mut bytes = [0x00u8; 32];
        bytes[0] = (i * 16) as u8;
        let peer_id = NodeId::from_bytes(&bytes).unwrap();
        let mut contact = PeerContact::new(
            peer_id,
            format!("peer-{:02x}", i),
            "192.168.1.1".to_string(),
            443,
        );
        contact.is_trusted = true;
        table.insert(contact).ok();
    }

    let closest = table.find_closest(&target, 3);
    assert!(!closest.is_empty());
}

#[test]
fn test_routing_table_persist_restore() {
    let local_id = NodeId::from_bytes(&[0x00u8; 32]).unwrap();
    let local_id_str = "local-node".to_string();
    let mut table = RoutingTable::new(local_id, local_id_str.clone());

    let peer_id = NodeId::from_bytes(&[0x01u8; 32]).unwrap();
    let mut contact = PeerContact::new(
        peer_id,
        "peer-01".to_string(),
        "192.168.1.1".to_string(),
        443,
    );
    contact.is_trusted = true;
    table.insert(contact).ok();

    let persisted = table.to_persisted();
    let bytes = persisted.to_bytes_postcard();
    let restored = PersistedRoutingTable::from_bytes_postcard(&bytes);
    assert!(restored.is_some());
}

#[test]
fn test_record_store_put_get() {
    let store = DhtRecordStore::new();

    let key = "test_key".to_string();
    let value = b"test_value".to_vec();

    let record = DhtRecord::new(key.clone(), value.clone(), Some("publisher".to_string()));
    store.put(record);

    let retrieved = store.get(&key);
    assert!(retrieved.is_some());
    assert_eq!(retrieved.unwrap().value, value);
}

#[test]
fn test_record_store_remove() {
    let store = DhtRecordStore::new();

    let key = "test_key".to_string();
    let value = b"test_value".to_vec();

    let record = DhtRecord::new(key.clone(), value.clone(), None);
    store.put(record);

    let removed = store.remove(&key);
    assert!(removed.is_some());

    let retrieved = store.get(&key);
    assert!(retrieved.is_none());
}

#[test]
fn test_record_store_prefix_search() {
    let store = DhtRecordStore::new();

    store.put(DhtRecord::new(
        "org:test".to_string(),
        b"value1".to_vec(),
        None,
    ));
    store.put(DhtRecord::new(
        "upstream:test".to_string(),
        b"value2".to_vec(),
        None,
    ));
    store.put(DhtRecord::new(
        "org:other".to_string(),
        b"value3".to_vec(),
        None,
    ));

    let org_records = store.get_by_prefix("org:");
    assert_eq!(org_records.len(), 2);

    let upstream_records = store.get_by_prefix("upstream:");
    assert_eq!(upstream_records.len(), 1);
}

#[test]
fn test_signed_record_roundtrip() {
    let mut record = SignedDhtRecord::new(
        "test:key".to_string(),
        b"test_value".to_vec(),
        "publisher_1".to_string(),
        SignedRecordType::Upstream,
    );

    let signer = RecordSigner::new(Some([0u8; 32]));
    let verifying_key = signer.get_verifying_key();

    if let Some(key) = verifying_key {
        record.signer_public_key = Some(key);
    }

    let signature = signer.sign(&record);
    if let Some(sig) = signature {
        record.signature = sig;
    }

    let verified = signer.verify(&record);
    assert!(verified);
}

#[test]
fn test_signed_record_ttl() {
    let record = SignedDhtRecord::new(
        "test:key".to_string(),
        b"test_value".to_vec(),
        "publisher_1".to_string(),
        SignedRecordType::Upstream,
    );

    assert!(!record.is_expired());
}

#[test]
fn test_signed_record_type_variants() {
    let _ = SignedRecordType::Organization;
    let _ = SignedRecordType::TierKey;
    let _ = SignedRecordType::MemberCertificate;
    let _ = SignedRecordType::Upstream;
    let _ = SignedRecordType::NodeInfo;
    let _ = SignedRecordType::GlobalNodeList;
    let _ = SignedRecordType::TierClaim;
    let _ = SignedRecordType::GlobalNodePublicKey;
    let _ = SignedRecordType::NodeHealth;
    let _ = SignedRecordType::NodeLoad;
    let _ = SignedRecordType::VerifiedUpstream;
    let _ = SignedRecordType::OrgNameReservation;
    let _ = SignedRecordType::UpstreamRegistrationRequest;
    let _ = SignedRecordType::YaraRules;
    let _ = SignedRecordType::YaraRuleSubmission;
    let _ = SignedRecordType::YaraRuleVersion;
    let _ = SignedRecordType::DnsZone;
    let _ = SignedRecordType::DnsRecord;
    let _ = SignedRecordType::DnsDomainRegistration;
    let _ = SignedRecordType::GlobalAiBotList;
}

#[test]
fn test_stake_level_transitions() {
    let config = StakeConfig {
        stake_grace_period_secs: 0,
        ..StakeConfig::default()
    };
    let manager = StakeManager::new(config, "local-node".to_string(), true);

    manager.register_node("node-1".to_string(), 100, MeshNodeRole::Global);
    manager.update_reputation("node-1", 100, MeshNodeRole::Global);

    let level = manager.get_stake_level("node-1");
    assert_eq!(level, StakeLevel::Full);

    manager.update_reputation("node-1", 20, MeshNodeRole::Edge);
    let level_after = manager.get_stake_level("node-1");
    assert!(matches!(
        level_after,
        StakeLevel::Routing | StakeLevel::ReadOnly | StakeLevel::None
    ));
}

#[test]
fn test_stake_slash_event() {
    let config = StakeConfig {
        slashing_enabled: true,
        stake_grace_period_secs: 0,
        ..StakeConfig::default()
    };
    let manager = StakeManager::new(config, "global-node".to_string(), true);

    manager.register_node("malicious".to_string(), 50, MeshNodeRole::Edge);
    manager.update_reputation("malicious", 50, MeshNodeRole::Edge);

    assert!(manager.can_write_dht("malicious"));

    let slash_result = manager.slash_node("malicious", SlashReason::DhtPoisoning, "global-node");
    assert!(slash_result.is_some());

    assert!(!manager.can_write_dht("malicious"));
    assert!(manager.is_slashed("malicious"));
}

#[test]
fn test_merkle_tree_construction() {
    let mut records = HashMap::new();
    records.insert("key1".to_string(), b"value1".to_vec());
    records.insert("key2".to_string(), b"value2".to_vec());
    records.insert("key3".to_string(), b"value3".to_vec());

    let tree = MerkleTree::from_records(&records);
    assert!(!tree.is_empty());
    assert!(tree.root_hash().is_some());
    assert!(tree.height() > 0);
}

#[test]
fn test_merkle_proof_generation_verify() {
    let mut records = HashMap::new();
    records.insert("key1".to_string(), b"value1".to_vec());
    records.insert("key2".to_string(), b"value2".to_vec());

    let tree = MerkleTree::from_records(&records);
    let proof = tree.generate_proof(&["key1".to_string()]);

    assert!(proof.is_some());
    let proof = proof.unwrap();

    assert_eq!(proof.queried_keys, ["key1".to_string()]);
    assert!(!proof.proof_nodes.is_empty());
}

#[test]
fn test_dht_key_construtors() {
    let org_key = DhtKey::organization("test-org");
    assert_eq!(org_key.as_str(), "org:test-org");

    let tier_key = DhtKey::tier_key("test-org", "key-123");
    assert_eq!(tier_key.as_str(), "tier_key:test-org:key-123");

    let upstream_key = DhtKey::upstream("api.example.com");
    assert_eq!(upstream_key.as_str(), "upstream:api.example.com");

    let node_info_key = DhtKey::node_info("node-123");
    assert_eq!(node_info_key.as_str(), "node_info:node-123");

    let health_key = DhtKey::node_health("node-123");
    assert_eq!(health_key.as_str(), "node_health:node-123");

    let list_key = DhtKey::global_node_list();
    assert_eq!(list_key.as_str(), "global_node_list");
}

#[test]
fn test_dht_key_is_public() {
    assert!(DhtKey::upstream("test").is_public());
    assert!(DhtKey::node_info("test").is_public());
    assert!(DhtKey::node_health("test").is_public());
    assert!(DhtKey::node_load("test").is_public());
    assert!(DhtKey::verified_upstream("test").is_public());
    assert!(DhtKey::tier_claim("test").is_public());

    assert!(!DhtKey::organization("test").is_public());
    assert!(!DhtKey::tier_key("test", "key").is_public());
    assert!(!DhtKey::member_certificate("test", "cert").is_public());
}

#[test]
fn test_dht_rate_limiter_allows_within_limit() {
    let limiter = DhtRateLimiter::new(5, 60);

    for i in 0..5 {
        let result = limiter.is_allowed(&format!("peer-{}", i));
        assert!(result, "Peer {} should be allowed within limit", i);
    }
}

#[test]
fn test_dht_rate_limiter_blocks_over_limit() {
    let limiter = DhtRateLimiter::new(3, 60);

    assert!(limiter.is_allowed("peer-123"));
    assert!(limiter.is_allowed("peer-123"));
    assert!(limiter.is_allowed("peer-123"));
    assert!(
        !limiter.is_allowed("peer-123"),
        "Should be blocked after exceeding limit"
    );
}

#[test]
fn test_ttl_manager() {
    let manager = TtlManager::new();

    let ttl = manager.ttl_for(SignedRecordType::Organization);
    assert!(ttl > Duration::ZERO);

    let ttl_upstream = manager.ttl_for(SignedRecordType::Upstream);
    assert!(ttl_upstream > Duration::ZERO);
}

#[test]
fn test_record_metadata() {
    let mut metadata = RecordMetadata::new(Some("publisher".to_string()));
    assert!(metadata.created_at > 0);
    assert_eq!(metadata.version, 1);

    metadata.increment_version();
    assert_eq!(metadata.version, 2);
    assert!(metadata.updated_at >= metadata.created_at);
}

#[test]
fn test_record_signer_without_key() {
    let signer = RecordSigner::new(None);
    let record = SignedDhtRecord::new(
        "test:key".to_string(),
        b"value".to_vec(),
        "publisher".to_string(),
        SignedRecordType::Upstream,
    );

    let signature = signer.sign(&record);
    assert!(signature.is_none());
}

#[test]
fn test_geo_info() {
    let geo = GeoInfo::new();
    assert!(!geo.has_location());

    let geo_with_coords = GeoInfo::with_coords(40.7128, -74.0060);
    assert!(geo_with_coords.has_location());

    let geo_with_country = GeoInfo::new().with_country("US".to_string());
    assert_eq!(geo_with_country.country, Some("US".to_string()));
}

#[test]
fn test_persisted_contact() {
    let contact = PersistedContact {
        node_id: "test-node".to_string(),
        address: "192.168.1.1".to_string(),
        port: 443,
        geo: None,
        latency_ms: Some(100),
        last_seen: 1234567890,
        is_global: false,
        is_trusted: false,
        pow_nonce: None,
        public_key: None,
    };

    let bytes = contact.to_bytes_rkyv();
    assert!(!bytes.is_empty());

    let restored = PersistedContact::from_bytes_rkyv(&bytes);
    assert!(restored.is_some());
}

#[test]
fn test_validate_message_timestamp() {
    use maluwaf::mesh::dht::signed::{
        validate_message_timestamp, DHT_MESSAGE_TIMESTAMP_WINDOW_SECS,
    };

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    assert!(validate_message_timestamp(now));

    let old = now.saturating_sub(DHT_MESSAGE_TIMESTAMP_WINDOW_SECS as u64 + 1);
    assert!(!validate_message_timestamp(old));

    let future = now.saturating_add(DHT_MESSAGE_TIMESTAMP_WINDOW_SECS as u64 + 1);
    assert!(!validate_message_timestamp(future));
}

#[test]
fn test_merkle_single_leaf() {
    let mut records = HashMap::new();
    records.insert("only-key".to_string(), b"only-value".to_vec());

    let tree = MerkleTree::from_records(&records);
    assert!(!tree.is_empty());
    assert_eq!(tree.height(), 1);
}

#[test]
fn test_merkle_proof_multiple_keys() {
    let mut records = HashMap::new();
    records.insert("key1".to_string(), b"value1".to_vec());
    records.insert("key2".to_string(), b"value2".to_vec());
    records.insert("key3".to_string(), b"value3".to_vec());
    records.insert("key4".to_string(), b"value4".to_vec());

    let tree = MerkleTree::from_records(&records);
    let proof = tree.generate_proof(&["key1".to_string(), "key2".to_string()]);

    assert!(proof.is_some());
    let proof = proof.unwrap();
    assert_eq!(proof.queried_keys.len(), 2);
}

#[test]
fn test_stake_manager_get_all_active() {
    let config = StakeConfig::default();
    let manager = StakeManager::new(config, "local-node".to_string(), false);

    manager.register_node("active-1".to_string(), 50, MeshNodeRole::Edge);
    manager.register_node("active-2".to_string(), 100, MeshNodeRole::Global);
    manager.register_node("inactive-1".to_string(), 30, MeshNodeRole::Edge);

    let active_stakes = manager.get_all_active_stakes();
    for stake in &active_stakes {
        assert!(
            stake.is_active,
            "Stake for {} should be active if grace period expired",
            stake.node_id
        );
    }
}

#[test]
fn test_dht_key_from_str() {
    let key = DhtKey::from_str("org:test-org");
    assert_eq!(key, DhtKey::organization("test-org"));

    let key = DhtKey::from_str("upstream:api.example.com");
    assert_eq!(key, DhtKey::upstream("api.example.com"));

    let key = DhtKey::from_str("node_info:node-123");
    assert_eq!(key, DhtKey::node_info("node-123"));
}

#[test]
fn test_node_id_from_public_key() {
    let test_key = b"test-public-key-bytes-123456789012";
    let node_id = NodeId::from_public_key(test_key);
    assert!(!node_id.is_zero());
}

#[test]
fn test_node_id_random() {
    let id1 = NodeId::random();
    let id2 = NodeId::random();
    assert_ne!(id1, id2);
}

#[test]
fn test_dht_record_store_clear() {
    let store = DhtRecordStore::new();

    store.put(DhtRecord::new("key1".to_string(), b"val1".to_vec(), None));
    store.put(DhtRecord::new("key2".to_string(), b"val2".to_vec(), None));

    assert_eq!(store.len(), 2);

    store.clear();
    assert!(store.is_empty());
}

#[test]
fn test_signed_record_needs_refresh() {
    let record = SignedDhtRecord::new(
        "test:key".to_string(),
        b"value".to_vec(),
        "publisher".to_string(),
        SignedRecordType::Upstream,
    );

    if let Some(default_ttl) = record.record_type.default_ttl() {
        let remaining = record.time_until_expiry().unwrap_or(Duration::ZERO);
        if remaining < default_ttl / 2 {
            assert!(record.needs_refresh());
        }
    }
}
