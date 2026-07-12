#![cfg(feature = "mesh")]

use std::collections::HashMap;
use std::time::Duration;
use synvoid::mesh::config::MeshNodeRole;
use synvoid::mesh::dht::keys::DhtKey;
use synvoid::mesh::dht::merkle::MerkleTree;
use synvoid::mesh::dht::routing::{
    GeoInfo, GeoRoutingConfig, KBucket, NodeId, PeerContact, PersistedContact,
    PersistedRoutingTable, RegionalHub, RegionalHubConfig, RoutingTable, K_SIZE,
};
use synvoid::mesh::dht::signed::{RecordSigner, SignedDhtRecord, SignedRecordType, TtlManager};
use synvoid::mesh::dht::stake::{SlashReason, StakeConfig, StakeLevel, StakeManager};
use synvoid::mesh::dht::store::{DhtRecord, DhtRecordStore, RecordMetadata};
use synvoid::mesh::dht::DhtRateLimiter;

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
    let mut ids = [
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

    let signer = RecordSigner::new(Some(synvoid::mesh::protocol::MeshMessageSigner::new(
        [0u8; 32],
    )));
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

    manager.register_node("node-1".to_string(), 100, MeshNodeRole::GLOBAL, None);
    manager.update_reputation("node-1", 100, MeshNodeRole::GLOBAL);

    let level = manager.get_stake_level("node-1");
    assert_eq!(level, StakeLevel::Full);

    manager.update_reputation("node-1", 20, MeshNodeRole::EDGE);
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

    manager.register_node("malicious".to_string(), 50, MeshNodeRole::EDGE, None);
    manager.update_reputation("malicious", 50, MeshNodeRole::EDGE);

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
    use synvoid::mesh::dht::signed::{
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

    manager.register_node("active-1".to_string(), 50, MeshNodeRole::EDGE, None);
    manager.register_node("active-2".to_string(), 100, MeshNodeRole::GLOBAL, None);
    manager.register_node("inactive-1".to_string(), 30, MeshNodeRole::EDGE, None);

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

// ── Regional Hub Routing Tests ───────────────────────────────────

fn make_hub_peer(id: &str, country: &str, lat: f64, lon: f64, is_global: bool) -> PeerContact {
    let geo = GeoInfo {
        country: Some(country.to_string()),
        region: None,
        latitude: Some(lat),
        longitude: Some(lon),
    };

    PeerContact::new(
        NodeId::from_node_id_string(id),
        id.to_string(),
        "192.168.1.1".to_string(),
        443,
    )
    .with_geo(geo)
    .with_global(is_global)
}

#[test]
fn test_regional_hub_config_defaults() {
    let config = RegionalHubConfig::default();
    assert!(config.enabled);
    assert_eq!(config.hubs_per_region, 3);
    assert_eq!(config.min_reputation_for_hub, 30);
    assert_eq!(config.refresh_interval_secs, 300);
    assert!(config.prefer_regional);
}

#[test]
fn test_regional_hub_disabled_returns_empty() {
    let config = RegionalHubConfig {
        enabled: false,
        ..RegionalHubConfig::default()
    };
    let hub = RegionalHub::new(config, GeoRoutingConfig::default());

    let peers = vec![
        make_hub_peer("peer1", "US", 37.7749, -122.4194, true),
        make_hub_peer("peer2", "US", 34.0522, -118.2437, false),
    ];
    hub.update_peers(peers);

    assert!(hub.get_hubs().is_empty());
    assert!(hub.get_hubs_for_region("US").is_empty());
    assert!(hub.get_regional_hub(None).is_none());
    assert_eq!(hub.total_hub_count(), 0);
    assert_eq!(hub.region_count(), 0);
}

#[test]
fn test_hub_selection_selects_global_peers() {
    let hub = RegionalHub::with_defaults();
    let peers = vec![
        make_hub_peer("global1", "US", 37.7749, -122.4194, true),
        make_hub_peer("global2", "US", 34.0522, -118.2437, true),
        make_hub_peer("local1", "US", 40.7128, -74.0060, false),
    ];

    hub.update_peers(peers);

    let hubs = hub.get_hubs();
    assert!(!hubs.is_empty());
    // Global peers should be preferred (score 50 vs 0)
    let has_global = hubs.iter().any(|h| h.is_global);
    assert!(
        has_global,
        "Expected at least one global peer in hub selection"
    );
}

#[test]
fn test_regional_separation() {
    let hub = RegionalHub::with_defaults();

    let us_peers = vec![
        make_hub_peer("us1", "US", 37.7749, -122.4194, true),
        make_hub_peer("us2", "US", 40.7128, -74.0060, true),
    ];
    let eu_peers = vec![
        make_hub_peer("eu1", "DE", 52.5200, 13.4050, true),
        make_hub_peer("eu2", "FR", 48.8566, 2.3522, false),
    ];

    let all_peers: Vec<PeerContact> = us_peers.into_iter().chain(eu_peers).collect();
    hub.update_peers(all_peers);

    let us_hubs = hub.get_hubs_for_region("US");
    let de_hubs = hub.get_hubs_for_region("DE");

    assert!(!us_hubs.is_empty(), "US should have hubs");
    assert!(!de_hubs.is_empty(), "DE should have hubs");
    assert_eq!(hub.region_count(), 3);
}

#[test]
fn test_hub_count_respects_hubs_per_region() {
    let config = RegionalHubConfig {
        hubs_per_region: 2,
        min_reputation_for_hub: 0,
        ..RegionalHubConfig::default()
    };
    let hub = RegionalHub::new(config, GeoRoutingConfig::default());

    let peers: Vec<PeerContact> = (0..5)
        .map(|i| make_hub_peer(&format!("peer{}", i), "US", 37.0 + i as f64, -122.0, true))
        .collect();

    hub.update_peers(peers);

    let hubs = hub.get_hubs_for_region("US");
    assert!(
        hubs.len() <= 2,
        "Expected at most 2 hubs, got {}",
        hubs.len()
    );
}

#[test]
fn test_hub_reputation_threshold_fallback() {
    let config = RegionalHubConfig {
        min_reputation_for_hub: 100,
        ..RegionalHubConfig::default()
    };
    let hub = RegionalHub::new(config, GeoRoutingConfig::default());

    // No peer can have reputation 100 without being global+trusted+low-latency
    // But with non-global non-trusted peers, it should fall back to best available
    let peers = vec![
        make_hub_peer("normal1", "US", 37.7749, -122.4194, false),
        make_hub_peer("normal2", "US", 34.0522, -118.2437, false),
    ];

    hub.update_peers(peers);
    // Fallback should still select hubs
    let hubs = hub.get_hubs();
    assert!(!hubs.is_empty(), "Expected fallback hub selection");
}

#[test]
fn test_hub_remove_peer() {
    let hub = RegionalHub::with_defaults();
    let id1 = NodeId::from_node_id_string("peer-remove-1");
    let id2 = NodeId::from_node_id_string("peer-remove-2");

    let peers = vec![
        make_hub_peer("peer-remove-1", "US", 37.7749, -122.4194, true),
        make_hub_peer("peer-remove-2", "US", 34.0522, -118.2437, true),
    ];
    hub.update_peers(peers);

    hub.remove_peer(&id1);

    let hubs = hub.get_hubs();
    let has_removed = hubs.iter().any(|h| h.node_id == id1);
    assert!(!has_removed, "Removed peer should not appear in hubs");

    let has_remaining = hubs.iter().any(|h| h.node_id == id2);
    assert!(has_remaining, "Remaining peer should still be in hubs");
}

#[test]
fn test_hub_mark_offline_online() {
    let hub = RegionalHub::with_defaults();
    let peers = vec![make_hub_peer("lifecycle-1", "US", 37.7749, -122.4194, true)];
    hub.update_peers(peers);

    let node_id = NodeId::from_node_id_string("lifecycle-1");
    hub.mark_hub_offline(&node_id);

    let hubs = hub.get_hubs();
    let offline = hubs.iter().any(|h| h.node_id == node_id);
    assert!(!offline, "Offline hub should not appear in online hubs");

    hub.mark_hub_online(&node_id);
    let hubs = hub.get_hubs();
    let online = hubs.iter().any(|h| h.node_id == node_id);
    assert!(online, "Hub should be back online after mark_hub_online");
}

#[test]
fn test_find_closest_via_hubs_prefers_local() {
    let config = RegionalHubConfig {
        prefer_regional: true,
        min_reputation_for_hub: 0,
        ..RegionalHubConfig::default()
    };
    let hub = RegionalHub::new(config, GeoRoutingConfig::default());

    let local_geo = GeoInfo {
        country: Some("US".to_string()),
        region: None,
        latitude: Some(37.7749),
        longitude: Some(-122.4194),
    };
    let hub = hub.with_local_geo(local_geo);

    let us_peer = make_hub_peer("us-hub", "US", 37.7749, -122.4194, true);
    let de_peer = make_hub_peer("de-hub", "DE", 52.5200, 13.4050, true);

    hub.update_peers(vec![us_peer, de_peer]);

    let target = NodeId::random();
    let result = hub.find_closest_via_hubs(&target, None, 10);
    assert!(!result.is_empty());

    // Local region (US) hubs should come first
    let first = &result[0];
    assert_eq!(
        first.geo.as_ref().unwrap().country,
        Some("US".to_string()),
        "First result should be from local region"
    );
}

#[test]
fn test_find_closest_via_hubs_different_target_region() {
    let config = RegionalHubConfig {
        prefer_regional: true,
        min_reputation_for_hub: 0,
        ..RegionalHubConfig::default()
    };
    let hub = RegionalHub::new(config, GeoRoutingConfig::default());

    let local_geo = GeoInfo {
        country: Some("US".to_string()),
        region: None,
        latitude: Some(37.7749),
        longitude: Some(-122.4194),
    };
    let hub = hub.with_local_geo(local_geo);

    hub.update_peers(vec![
        make_hub_peer("us-hub", "US", 37.7749, -122.4194, true),
        make_hub_peer("de-hub", "DE", 52.5200, 13.4050, true),
        make_hub_peer("jp-hub", "JP", 35.6762, 139.6503, true),
    ]);

    let target = NodeId::random();
    let target_geo = GeoInfo {
        country: Some("DE".to_string()),
        region: None,
        latitude: Some(52.5200),
        longitude: Some(13.4050),
    };

    let result = hub.find_closest_via_hubs(&target, Some(&target_geo), 10);
    // Should include both US (local) and DE (target) hubs
    let countries: Vec<_> = result
        .iter()
        .filter_map(|p| p.geo.as_ref().and_then(|g| g.country.clone()))
        .collect();
    assert!(
        countries.contains(&"US".to_string()),
        "Should include local US hub"
    );
    assert!(
        countries.contains(&"DE".to_string()),
        "Should include target DE hub"
    );
}

#[test]
fn test_find_closest_via_hubs_disabled_returns_empty() {
    let config = RegionalHubConfig {
        enabled: false,
        ..RegionalHubConfig::default()
    };
    let hub = RegionalHub::new(config, GeoRoutingConfig::default());
    hub.update_peers(vec![make_hub_peer("p1", "US", 37.0, -122.0, true)]);

    let target = NodeId::random();
    let result = hub.find_closest_via_hubs(&target, None, 5);
    assert!(result.is_empty());
}

#[test]
fn test_find_closest_via_hubs_respects_k_limit() {
    let config = RegionalHubConfig {
        min_reputation_for_hub: 0,
        ..RegionalHubConfig::default()
    };
    let hub = RegionalHub::new(config, GeoRoutingConfig::default());

    let peers: Vec<PeerContact> = (0..10)
        .map(|i| make_hub_peer(&format!("p{}", i), "US", 37.0 + i as f64, -122.0, true))
        .collect();
    hub.update_peers(peers);

    let target = NodeId::random();
    let result = hub.find_closest_via_hubs(&target, None, 3);
    assert!(result.len() <= 3, "Should not exceed k={}", 3);
}

#[test]
fn test_routing_table_hybrid_fallback() {
    let local_id = NodeId::from_bytes(&[0x01u8; 32]).unwrap();
    let mut table = RoutingTable::new(local_id, "local".to_string());

    // No regional hub set — find_closest_hybrid should fall back to pure Kademlia
    for i in 0..5 {
        let peer = PeerContact::new(
            NodeId::from_node_id_string(&format!("peer-{}", i)),
            format!("peer-{}", i),
            "192.168.1.1".to_string(),
            443,
        );
        table.insert(peer).ok();
    }

    let target = NodeId::random();
    let result = table.find_closest_hybrid(&target, None, 3);
    assert!(result.len() <= 3);
}

#[test]
fn test_routing_table_hybrid_with_hub() {
    use std::sync::Arc;

    let local_id = NodeId::from_bytes(&[0x02u8; 32]).unwrap();
    let mut table = RoutingTable::new(local_id, "local".to_string());

    let hub = RegionalHub::new(
        RegionalHubConfig {
            min_reputation_for_hub: 0,
            ..RegionalHubConfig::default()
        },
        GeoRoutingConfig::default(),
    );

    let hub_peers = vec![
        make_hub_peer("hub-us", "US", 37.7749, -122.4194, true),
        make_hub_peer("hub-de", "DE", 52.5200, 13.4050, true),
    ];
    hub.update_peers(hub_peers);

    table = table.with_regional_hub(Arc::new(hub));

    // Add bucket peers
    for i in 0..5 {
        let peer = PeerContact::new(
            NodeId::from_node_id_string(&format!("bucket-{}", i)),
            format!("bucket-{}", i),
            "192.168.1.1".to_string(),
            443,
        );
        table.insert(peer).ok();
    }

    let target = NodeId::random();
    let result = table.find_closest_hybrid(&target, None, 5);
    assert!(!result.is_empty());
    assert!(result.len() <= 5);
}

#[test]
fn test_routing_table_hybrid_dedup() {
    use std::sync::Arc;

    let local_id = NodeId::from_bytes(&[0x03u8; 32]).unwrap();
    let mut table = RoutingTable::new(local_id, "local".to_string());

    let hub = RegionalHub::new(
        RegionalHubConfig {
            min_reputation_for_hub: 0,
            ..RegionalHubConfig::default()
        },
        GeoRoutingConfig::default(),
    );

    // Same peer in both hub and bucket — should be deduplicated
    let shared_peer = make_hub_peer("shared-peer", "US", 37.7749, -122.4194, true);
    hub.update_peers(vec![shared_peer.clone()]);

    table = table.with_regional_hub(Arc::new(hub));
    table.insert(shared_peer).ok();

    let target = NodeId::random();
    let result = table.find_closest_hybrid(&target, None, 10);

    let seen_ids: std::collections::HashSet<_> = result.iter().map(|p| p.node_id).collect();
    assert_eq!(
        seen_ids.len(),
        result.len(),
        "find_closest_hybrid should deduplicate by node_id"
    );
}

#[test]
fn test_sync_to_regional_hub() {
    use std::sync::Arc;

    let local_id = NodeId::from_bytes(&[0x04u8; 32]).unwrap();
    let mut table = RoutingTable::new(local_id, "local".to_string());

    let hub = RegionalHub::new(
        RegionalHubConfig {
            min_reputation_for_hub: 0,
            ..RegionalHubConfig::default()
        },
        GeoRoutingConfig::default(),
    );

    table = table.with_regional_hub(Arc::new(hub));

    for i in 0..3 {
        let peer = PeerContact::new(
            NodeId::from_node_id_string(&format!("sync-peer-{}", i)),
            format!("sync-peer-{}", i),
            "192.168.1.1".to_string(),
            443,
        )
        .with_geo(GeoInfo {
            country: Some("US".to_string()),
            region: None,
            latitude: Some(37.0 + i as f64),
            longitude: Some(-122.0),
        })
        .with_global(true);
        table.insert(peer).ok();
    }

    table.sync_to_regional_hub();

    let hubs = table.get_regional_hubs();
    assert!(
        !hubs.is_empty(),
        "sync_to_regional_hub should populate hub peers"
    );
}

// ── DHT Record Operations Under Various Conditions ──────────────────

#[test]
fn test_record_store_basic_operations() {
    use synvoid::mesh::dht::store::DhtRecordStore;

    let store = DhtRecordStore::new();
    let key = "test_key".to_string();
    let value = b"test_value".to_vec();

    store.put(DhtRecord::new(key.clone(), value.clone(), None));

    let retrieved = store.get(&key);
    assert!(retrieved.is_some(), "Record should exist after put");
    assert_eq!(retrieved.unwrap().value, value);
}

#[test]
fn test_record_store_insert_and_retrieve() {
    use synvoid::mesh::dht::store::DhtRecordStore;

    let store = DhtRecordStore::new();
    let key = "insert_test".to_string();
    let value = b"insert_value".to_vec();

    store.put(DhtRecord::new(key.clone(), value.clone(), None));

    let retrieved = store.get(&key);
    assert!(retrieved.is_some());
    assert_eq!(retrieved.unwrap().value, value);
}

#[test]
fn test_record_store_multiple_keys_same_prefix() {
    use synvoid::mesh::dht::store::DhtRecordStore;

    let store = DhtRecordStore::new();

    store.put(DhtRecord::new(
        "site:example.com".to_string(),
        b"content1".to_vec(),
        None,
    ));
    store.put(DhtRecord::new(
        "site:example.org".to_string(),
        b"content2".to_vec(),
        None,
    ));
    store.put(DhtRecord::new(
        "site:example.net".to_string(),
        b"content3".to_vec(),
        None,
    ));
    store.put(DhtRecord::new(
        "upstream:example.com".to_string(),
        b"upstream1".to_vec(),
        None,
    ));

    let site_records = store.get_by_prefix("site:");
    assert_eq!(site_records.len(), 3, "Should find 3 site: records");

    let upstream_records = store.get_by_prefix("upstream:");
    assert_eq!(upstream_records.len(), 1, "Should find 1 upstream: record");
}

#[test]
fn test_record_store_clear_preserves_nothing() {
    use synvoid::mesh::dht::store::DhtRecordStore;

    let store = DhtRecordStore::new();
    store.put(DhtRecord::new("k1".to_string(), b"v1".to_vec(), None));
    store.put(DhtRecord::new("k2".to_string(), b"v2".to_vec(), None));

    assert_eq!(store.len(), 2);

    store.clear();

    assert!(store.is_empty(), "Store should be empty after clear");
    assert_eq!(store.len(), 0);
}

#[test]
fn test_signed_record_with_ttl() {
    use synvoid::mesh::dht::signed::{SignedDhtRecord, SignedRecordType};

    let record = SignedDhtRecord::new(
        "test:key".to_string(),
        b"test_value".to_vec(),
        "publisher_1".to_string(),
        SignedRecordType::Upstream,
    );

    assert!(!record.is_expired());
}

#[test]
fn test_ttl_manager_different_record_types() {
    use synvoid::mesh::dht::signed::{SignedRecordType, TtlManager};

    let manager = TtlManager::new();

    let org_ttl = manager.ttl_for(SignedRecordType::Organization);
    let upstream_ttl = manager.ttl_for(SignedRecordType::Upstream);
    let node_ttl = manager.ttl_for(SignedRecordType::NodeInfo);

    assert!(org_ttl > Duration::ZERO, "Organization TTL should be set");
    assert!(upstream_ttl > Duration::ZERO, "Upstream TTL should be set");
    assert!(node_ttl > Duration::ZERO, "NodeInfo TTL should be set");

    assert_ne!(
        org_ttl, upstream_ttl,
        "Different record types should have different TTLs"
    );
}

#[test]
fn test_validate_message_timestamp_edge_cases() {
    use synvoid::mesh::dht::signed::{
        validate_message_timestamp, DHT_MESSAGE_TIMESTAMP_WINDOW_SECS,
    };

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    assert!(
        validate_message_timestamp(now),
        "Current time should be valid"
    );

    let at_window_edge = now + DHT_MESSAGE_TIMESTAMP_WINDOW_SECS as u64;
    assert!(
        validate_message_timestamp(at_window_edge),
        "At window edge should be valid"
    );

    let just_outside_window = now + DHT_MESSAGE_TIMESTAMP_WINDOW_SECS as u64 + 1;
    assert!(
        !validate_message_timestamp(just_outside_window),
        "Just outside window should be invalid"
    );
}

#[test]
fn test_kbucket_eviction_when_full() {
    let mut bucket = KBucket::new(0);

    for i in 0..K_SIZE {
        let node_id = NodeId::from_bytes(&[i as u8; 32]).unwrap();
        let contact = PeerContact::new(
            node_id,
            format!("node-{:02x}", i),
            "192.168.1.1".to_string(),
            443,
        );
        let result = bucket.insert(contact);
        assert!(result.is_ok(), "Should insert {}th node", i);
    }

    assert!(bucket.is_full(), "Bucket should be full");

    let new_id = NodeId::from_bytes(&[0xFFu8; 32]).unwrap();
    let new_contact = PeerContact::new(
        new_id,
        "node-ff".to_string(),
        "192.168.1.1".to_string(),
        443,
    );
    let eviction_result = bucket.insert(new_contact);
    assert!(eviction_result.is_err(), "Should reject when full");
}

#[test]
fn test_geo_info_distance_calculation() {
    let us_geo = GeoInfo::with_coords(37.7749, -122.4194);
    let eu_geo = GeoInfo::with_coords(52.5200, 13.4050);

    let us_lat = us_geo.latitude.unwrap();
    let us_lon = us_geo.longitude.unwrap();
    let eu_lat = eu_geo.latitude.unwrap();
    let eu_lon = eu_geo.longitude.unwrap();

    let distance = ((eu_lat - us_lat).powi(2) + (eu_lon - us_lon).powi(2)).sqrt();
    assert!(
        distance > 0.0,
        "Distance between US and EU should be non-zero"
    );
}

#[test]
fn test_persisted_bucket_roundtrip() {
    use synvoid::mesh::dht::routing::PersistedBucket;

    let bucket = PersistedBucket {
        index: 0,
        peers: vec![],
        last_updated: 1234567890,
    };

    let bytes = bucket.to_bytes_rkyv();
    let restored = PersistedBucket::from_bytes_rkyv(&bytes).unwrap();

    assert_eq!(restored.index, 0);
    assert_eq!(restored.last_updated, 1234567890);
}

#[test]
fn test_record_signer_produces_valid_signature() {
    use synvoid::mesh::dht::signed::RecordSigner;

    let mut record = SignedDhtRecord::new(
        "test:key".to_string(),
        b"test_value".to_vec(),
        "publisher_1".to_string(),
        SignedRecordType::Upstream,
    );

    let signer = RecordSigner::new(Some(synvoid::mesh::protocol::MeshMessageSigner::new(
        [0x42u8; 32],
    )));
    let verifying_key = signer.get_verifying_key();

    if let Some(key) = verifying_key {
        record.signer_public_key = Some(key);
    }

    let signature = signer.sign(&record);
    assert!(signature.is_some(), "Should produce a signature");

    if let Some(sig) = signature {
        record.signature = sig;
        assert!(signer.verify(&record), "Signature should verify");
    }
}

#[test]
fn test_stake_manager_initial_state() {
    use synvoid::mesh::dht::stake::StakeManager;

    let config = StakeConfig::default();
    let manager = StakeManager::new(config, "test-node".to_string(), false);

    let active = manager.get_all_active_stakes();
    assert!(
        active.is_empty(),
        "New manager should have no active stakes"
    );

    let can_write = manager.can_write_dht("unknown-node");
    assert!(!can_write, "Unknown node should not be able to write");
}

#[test]
fn test_dht_rate_limiter_different_peers_independent() {
    use synvoid::mesh::dht::DhtRateLimiter;

    let limiter = DhtRateLimiter::new(2, 60);

    assert!(limiter.is_allowed("peer-a"));
    assert!(limiter.is_allowed("peer-a"));
    assert!(
        !limiter.is_allowed("peer-a"),
        "peer-a should be blocked after limit"
    );

    assert!(
        limiter.is_allowed("peer-b"),
        "peer-b should still be allowed"
    );
    assert!(
        limiter.is_allowed("peer-b"),
        "peer-b should still be allowed"
    );
    assert!(
        !limiter.is_allowed("peer-b"),
        "peer-b should now be blocked"
    );
}

#[test]
fn test_dht_key_privileged_vs_public() {
    let org_key = DhtKey::organization("test");
    let upstream_key = DhtKey::upstream("api.example.com");
    let tier_key = DhtKey::tier_key("org", "key");

    assert!(
        !org_key.is_public(),
        "Organization key should not be public"
    );
    assert!(
        org_key.is_privileged(),
        "Organization key should be privileged"
    );

    assert!(upstream_key.is_public(), "Upstream key should be public");
    assert!(
        !upstream_key.is_privileged(),
        "Upstream key should not be privileged"
    );

    assert!(!tier_key.is_public(), "TierKey should not be public");
    assert!(tier_key.is_privileged(), "TierKey should be privileged");
}

// ── ThreatIntelligence Tests ─────────────────────────────────────

mod threat_intel_tests {
    use std::net::IpAddr;
    use std::sync::Arc;
    use synvoid::mesh::config::MeshNodeRole;
    use synvoid::mesh::protocol::{ThreatIndicator, ThreatSeverity, ThreatType};
    use synvoid::mesh::threat_intel::{
        ThreatIndicatorEntry, ThreatIntelligenceConfig, ThreatIntelligenceConfigInternal,
        ThreatIntelligenceManager,
    };

    fn create_test_manager(role: MeshNodeRole) -> ThreatIntelligenceManager {
        use synvoid::config::DenyListLimitsConfig;
        let config = ThreatIntelligenceConfigInternal {
            enabled: true,
            push_enabled: false,
            sync_enabled: true,
            sync_interval_secs: 60,
            threat_sync_interval_secs: 30,
            push_severity_threshold: ThreatSeverity::Medium,
            min_ttl_seconds: 60,
            max_indicators_per_message: 50,
            hub_only_mode: false,
            reputation_config: synvoid::mesh::reputation::ReputationConfig {
                enabled: false,
                ..Default::default()
            },
            fanout_factor: 0.5,
            re_announce_interval_secs: 300,
            trusted_signers: Vec::new(),
            behavioral_enabled: false,
            min_samples_for_fingerprint: 10,
            fingerprint_ttl_secs: 3600,
            high_severity_threshold: 70,
        };
        let block_store = Arc::new(synvoid::block_store::BlockStore::new(
            true,
            None,
            DenyListLimitsConfig {
                max_entries: 1000,
                persist_interval_secs: 0,
                target_state_persist: false,
                ..DenyListLimitsConfig::default()
            },
        ));
        ThreatIntelligenceManager::new(config, block_store, "test-node".to_string(), role, None)
    }

    fn make_indicator(ip: &str, threat_type: ThreatType) -> ThreatIndicator {
        let now = synvoid::mesh::safe_unix_timestamp();
        ThreatIndicator {
            threat_type,
            indicator_value: ip.to_string(),
            severity: ThreatSeverity::High,
            reason: "test threat".to_string(),
            ttl_seconds: 300,
            source_node_id: "test-source".to_string(),
            timestamp: now,
            site_scope: "test-site".to_string(),
            rate_limit_requests: None,
            rate_limit_window_secs: None,
            suspicious_pattern: None,
            signature: Vec::new(),
            signer_public_key: None,
        }
    }

    #[test]
    fn test_threat_intelligence_config_defaults() {
        let config = ThreatIntelligenceConfig::default();
        assert!(config.enabled);
        assert!(config.push_enabled);
        assert!(config.sync_enabled);
        assert_eq!(config.sync_interval_secs, 300);
        assert_eq!(config.threat_sync_interval_secs, 60);
        assert_eq!(config.push_severity_threshold, "medium");
        assert_eq!(config.min_ttl_seconds, 60);
        assert_eq!(config.max_indicators_per_message, 50);
        assert!(!config.hub_only_mode);
        assert_eq!(config.re_announce_interval_secs, 300);
    }

    #[test]
    fn test_threat_intelligence_config_hub_only() {
        let config = ThreatIntelligenceConfig {
            hub_only_mode: true,
            behavioral_enabled: false,
            min_samples_for_fingerprint: 10,
            fingerprint_ttl_secs: 3600,
            high_severity_threshold: 70,
            ..Default::default()
        };
        assert!(config.hub_only_mode);
    }

    #[test]
    fn test_threat_intelligence_config_to_internal() {
        let config = ThreatIntelligenceConfig {
            enabled: true,
            push_enabled: false,
            sync_enabled: true,
            sync_interval_secs: 120,
            threat_sync_interval_secs: 60,
            push_severity_threshold: "high".to_string(),
            min_ttl_seconds: 120,
            max_indicators_per_message: 100,
            hub_only_mode: true,
            reputation_config: Default::default(),
            fanout_factor: 0.8,
            re_announce_interval_secs: 600,
            trusted_signers: Vec::new(),
            behavioral_enabled: false,
            min_samples_for_fingerprint: 10,
            fingerprint_ttl_secs: 3600,
            high_severity_threshold: 70,
        };

        let internal = config.to_internal();
        assert!(internal.enabled);
        assert!(!internal.push_enabled);
        assert!(internal.sync_enabled);
        assert_eq!(internal.sync_interval_secs, 120);
        assert_eq!(internal.push_severity_threshold, ThreatSeverity::High);
        assert_eq!(internal.min_ttl_seconds, 120);
        assert_eq!(internal.max_indicators_per_message, 100);
        assert!(internal.hub_only_mode);
        assert_eq!(internal.fanout_factor, 0.8);
        assert_eq!(internal.re_announce_interval_secs, 600);
    }

    #[test]
    fn test_manager_creation_edge_role() {
        let manager = create_test_manager(MeshNodeRole::EDGE);
        assert_eq!(manager.get_node_role(), MeshNodeRole::EDGE);
        assert_eq!(manager.get_indicator_count(), 0);
        assert_eq!(manager.get_version(), 1);
    }

    #[test]
    fn test_manager_creation_global_role() {
        let manager = create_test_manager(MeshNodeRole::GLOBAL);
        assert_eq!(manager.get_node_role(), MeshNodeRole::GLOBAL);
        assert!(manager.get_node_role().is_global());
    }

    #[test]
    fn test_announce_local_block() {
        let manager = create_test_manager(MeshNodeRole::GLOBAL);
        let ip: IpAddr = "192.168.1.100".parse().unwrap();

        manager.announce_local_block(
            ip,
            "test block reason".to_string(),
            300,
            "test-site".to_string(),
        );

        assert_eq!(manager.get_indicator_count(), 1);
        let indicator = manager.lookup_local_indicator("192.168.1.100", ThreatType::IpBlock);
        assert!(indicator.is_some());
        assert_eq!(indicator.unwrap().severity, ThreatSeverity::High);
    }

    #[test]
    fn test_announce_local_rate_limit() {
        let manager = create_test_manager(MeshNodeRole::EDGE);
        let ip: IpAddr = "10.0.0.50".parse().unwrap();

        manager.announce_local_rate_limit(ip, 1000, 60, "rate-limited-site".to_string());

        assert_eq!(manager.get_indicator_count(), 1);
        let indicator = manager.lookup_local_indicator("10.0.0.50", ThreatType::RateLimitViolation);
        assert!(indicator.is_some());
        assert_eq!(indicator.unwrap().severity, ThreatSeverity::Medium);
    }

    #[test]
    fn test_announce_local_suspicious() {
        let manager = create_test_manager(MeshNodeRole::GLOBAL);
        let ip: IpAddr = "172.16.0.10".parse().unwrap();

        manager.announce_local_suspicious(
            ip,
            "suspicious pattern".to_string(),
            ThreatSeverity::High,
            "suspicious-site".to_string(),
        );

        assert_eq!(manager.get_indicator_count(), 1);
        let indicator =
            manager.lookup_local_indicator("172.16.0.10", ThreatType::SuspiciousActivity);
        assert!(indicator.is_some());
    }

    #[test]
    fn test_lookup_local_indicator_not_found() {
        let manager = create_test_manager(MeshNodeRole::EDGE);
        let indicator = manager.lookup_local_indicator("192.168.1.1", ThreatType::IpBlock);
        assert!(indicator.is_none());
    }

    #[test]
    fn test_lookup_local_indicator_by_ip() {
        let manager = create_test_manager(MeshNodeRole::GLOBAL);
        let ip: IpAddr = "8.8.8.8".parse().unwrap();

        manager.announce_local_block(ip, "block test".to_string(), 300, "test".to_string());

        let indicator = manager.lookup_local_indicator_by_ip("8.8.8.8");
        assert!(indicator.is_some());
        assert_eq!(indicator.unwrap().threat_type, ThreatType::IpBlock);
    }

    #[test]
    fn test_handle_incoming_threat_rejects_expired() {
        let manager = create_test_manager(MeshNodeRole::GLOBAL);
        manager.update_global_nodes(vec![synvoid::mesh::protocol::MeshPeerInfo {
            node_id: "global-1".to_string(),
            address: "192.168.1.1".to_string(),
            role: MeshNodeRole::GLOBAL,
            capabilities: Default::default(),
            is_global: true,
            latency_ms: None,
            upstreams: Vec::new(),
            is_trusted: false,
            quic_port: Some(443),
            wireguard_port: None,
            advertised_port: None,
            dns_serving_healthy: false,
        }]);

        let now = synvoid::mesh::safe_unix_timestamp();
        let expired_indicator = ThreatIndicator {
            threat_type: ThreatType::IpBlock,
            indicator_value: "5.6.7.8".to_string(),
            severity: ThreatSeverity::High,
            reason: "expired threat".to_string(),
            ttl_seconds: 1,
            source_node_id: "test".to_string(),
            timestamp: now - 3600,
            site_scope: "test".to_string(),
            rate_limit_requests: None,
            rate_limit_window_secs: None,
            suspicious_pattern: None,
            signature: Vec::new(),
            signer_public_key: None,
        };

        let result = manager.handle_incoming_threat(
            expired_indicator,
            "global-1",
            MeshNodeRole::GLOBAL,
            None,
        );

        assert!(!result, "Expired threat should be rejected");
    }

    #[test]
    fn test_announce_local_block_multiple_indicators() {
        let manager = create_test_manager(MeshNodeRole::GLOBAL);

        let ip1: IpAddr = "192.168.1.100".parse().unwrap();
        let ip2: IpAddr = "192.168.1.101".parse().unwrap();

        manager.announce_local_block(ip1, "block 1".to_string(), 300, "test".to_string());
        manager.announce_local_block(ip2, "block 2".to_string(), 300, "test".to_string());

        assert_eq!(manager.get_indicator_count(), 2);
        assert!(manager
            .lookup_local_indicator("192.168.1.100", ThreatType::IpBlock)
            .is_some());
        assert!(manager
            .lookup_local_indicator("192.168.1.101", ThreatType::IpBlock)
            .is_some());
    }

    #[test]
    fn test_handle_incoming_threat_rejects_global_node_ip() {
        let manager = create_test_manager(MeshNodeRole::GLOBAL);
        manager.register_peer("peer-node".to_string(), MeshNodeRole::EDGE);
        manager.update_global_nodes(vec![synvoid::mesh::protocol::MeshPeerInfo {
            node_id: "global-1".to_string(),
            address: "192.168.1.1".to_string(),
            role: MeshNodeRole::GLOBAL,
            capabilities: Default::default(),
            is_global: true,
            latency_ms: None,
            upstreams: Vec::new(),
            is_trusted: false,
            quic_port: Some(443),
            wireguard_port: None,
            advertised_port: None,
            dns_serving_healthy: false,
        }]);

        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        let indicator = ThreatIndicator {
            threat_type: ThreatType::IpBlock,
            indicator_value: ip.to_string(),
            severity: ThreatSeverity::High,
            reason: "block global".to_string(),
            ttl_seconds: 300,
            source_node_id: "test".to_string(),
            timestamp: 1700000000,
            site_scope: "test".to_string(),
            rate_limit_requests: None,
            rate_limit_window_secs: None,
            suspicious_pattern: None,
            signature: Vec::new(),
            signer_public_key: None,
        };

        let result =
            manager.handle_incoming_threat(indicator, "peer-node", MeshNodeRole::EDGE, None);

        assert!(!result);
    }

    #[test]
    fn test_handle_incoming_threat_expired() {
        let manager = create_test_manager(MeshNodeRole::GLOBAL);
        manager.register_peer("peer-node".to_string(), MeshNodeRole::GLOBAL);
        let now = synvoid::mesh::safe_unix_timestamp();
        let indicator = ThreatIndicator {
            threat_type: ThreatType::IpBlock,
            indicator_value: "5.6.7.8".to_string(),
            severity: ThreatSeverity::High,
            reason: "expired threat".to_string(),
            ttl_seconds: 1,
            source_node_id: "test".to_string(),
            timestamp: now - 3600,
            site_scope: "test".to_string(),
            rate_limit_requests: None,
            rate_limit_window_secs: None,
            suspicious_pattern: None,
            signature: Vec::new(),
            signer_public_key: None,
        };

        let result =
            manager.handle_incoming_threat(indicator, "peer-node", MeshNodeRole::GLOBAL, None);

        assert!(!result);
    }

    #[test]
    fn test_handle_incoming_threat_duplicate() {
        let manager = create_test_manager(MeshNodeRole::GLOBAL);
        let indicator = make_indicator("7.8.9.0", ThreatType::IpBlock);

        manager.register_peer("peer-node".to_string(), MeshNodeRole::GLOBAL);
        let first = manager.handle_incoming_threat(
            indicator.clone(),
            "peer-node",
            MeshNodeRole::GLOBAL,
            None,
        );
        assert!(first);

        let second =
            manager.handle_incoming_threat(indicator, "peer-node", MeshNodeRole::GLOBAL, None);

        assert!(second);
    }

    #[test]
    fn test_get_indicators_for_sync() {
        let manager = create_test_manager(MeshNodeRole::GLOBAL);
        let ip: IpAddr = "2.3.4.5".parse().unwrap();

        manager.announce_local_block(ip, "sync test".to_string(), 300, "test".to_string());

        let indicators = manager.get_indicators_for_sync(0);
        assert_eq!(indicators.len(), 1);

        let indicators_v2 = manager.get_indicators_for_sync(1);
        assert_eq!(indicators_v2.len(), 0);
    }

    #[test]
    fn test_get_stats() {
        let manager = create_test_manager(MeshNodeRole::GLOBAL);
        let stats = manager.get_stats();

        assert_eq!(stats.node_id, "test-node");
        assert_eq!(stats.node_role, MeshNodeRole::GLOBAL);
        assert_eq!(stats.version, 1);
        assert_eq!(stats.indicator_count, 0);
    }

    #[test]
    fn test_create_sync_request() {
        let manager = create_test_manager(MeshNodeRole::EDGE);
        let msg = manager.create_sync_request();

        match msg {
            synvoid::mesh::protocol::MeshMessage::ThreatSyncRequest { .. } => {}
            _ => panic!("Expected ThreatSyncRequest"),
        }
    }

    #[test]
    fn test_create_sync_response() {
        let manager = create_test_manager(MeshNodeRole::GLOBAL);
        let msg = manager.create_sync_response("req-123", 0);

        match msg {
            synvoid::mesh::protocol::MeshMessage::ThreatSyncResponse { .. } => {}
            _ => panic!("Expected ThreatSyncResponse"),
        }
    }

    #[test]
    fn test_threat_indicator_entry_serde() {
        let indicator = ThreatIndicator {
            threat_type: ThreatType::IpBlock,
            indicator_value: "192.168.1.1".to_string(),
            severity: ThreatSeverity::High,
            reason: "test".to_string(),
            ttl_seconds: 300,
            source_node_id: "source".to_string(),
            timestamp: 1700000000,
            site_scope: "site".to_string(),
            rate_limit_requests: None,
            rate_limit_window_secs: None,
            suspicious_pattern: None,
            signature: vec![1, 2, 3],
            signer_public_key: Some("key123".to_string()),
        };

        let entry = ThreatIndicatorEntry {
            indicator: indicator.clone(),
            received_from: Some("peer".to_string()),
            local_origin: false,
            version: 42,
        };

        let json = serde_json::to_string(&entry).unwrap();
        let restored: ThreatIndicatorEntry = serde_json::from_str(&json).unwrap();

        assert_eq!(restored.indicator.indicator_value, "192.168.1.1");
        assert_eq!(restored.indicator.threat_type, ThreatType::IpBlock);
        assert_eq!(restored.indicator.severity, ThreatSeverity::High);
        assert_eq!(restored.received_from, Some("peer".to_string()));
        assert!(!restored.local_origin);
        assert_eq!(restored.version, 42);
    }

    #[test]
    fn test_hub_only_mode_skips_push() {
        use synvoid::config::DenyListLimitsConfig;
        let config_internal = ThreatIntelligenceConfigInternal {
            enabled: true,
            push_enabled: true,
            sync_enabled: true,
            sync_interval_secs: 60,
            threat_sync_interval_secs: 30,
            push_severity_threshold: ThreatSeverity::Medium,
            min_ttl_seconds: 60,
            max_indicators_per_message: 50,
            hub_only_mode: true,
            reputation_config: synvoid::mesh::reputation::ReputationConfig {
                enabled: false,
                ..Default::default()
            },
            fanout_factor: 0.5,
            re_announce_interval_secs: 300,
            trusted_signers: Vec::new(),
            behavioral_enabled: false,
            min_samples_for_fingerprint: 10,
            fingerprint_ttl_secs: 3600,
            high_severity_threshold: 70,
        };

        let block_store = Arc::new(synvoid::block_store::BlockStore::new(
            true,
            None,
            DenyListLimitsConfig {
                max_entries: 1000,
                persist_interval_secs: 0,
                target_state_persist: false,
                ..DenyListLimitsConfig::default()
            },
        ));

        let edge_manager = ThreatIntelligenceManager::new(
            config_internal.clone(),
            block_store.clone(),
            "edge-node".to_string(),
            MeshNodeRole::EDGE,
            None,
        );

        let global_manager = ThreatIntelligenceManager::new(
            ThreatIntelligenceConfigInternal {
                hub_only_mode: false,
                ..config_internal.clone()
            },
            block_store,
            "global-node".to_string(),
            MeshNodeRole::GLOBAL,
            None,
        );

        assert!(!edge_manager.is_mesh_available());
        assert!(!global_manager.is_mesh_available());
    }
}
