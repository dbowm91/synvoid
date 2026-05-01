#[cfg(test)]
mod signed_record_tests {
    use crate::mesh::dht::signed::{RecordSigner, SignedDhtRecord, SignedRecordType};
    use base64::Engine;

    fn create_valid_record() -> SignedDhtRecord {
        SignedDhtRecord::new(
            "test_key".to_string(),
            b"test_value".to_vec(),
            "publisher_1".to_string(),
            SignedRecordType::Upstream,
        )
    }

    #[test]
    fn test_signed_record_empty_signature_rejected() {
        let record = create_valid_record();
        assert!(record.signature.is_empty());

        let signer = RecordSigner::new(Some([0x42u8; 32]));
        assert!(!signer.verify(&record));
    }

    #[test]
    fn test_signed_record_wrong_public_key_rejected() {
        let mut record = create_valid_record();
        record.signature = vec![1, 2, 3, 4];
        record.signer_public_key = Some("wrong_key".to_string());

        let signer = RecordSigner::new(Some([0x42u8; 32]));
        assert!(!signer.verify(&record));
    }

    #[test]
    fn test_signed_record_invalid_signature_rejected() {
        let mut record = create_valid_record();
        record.signature = vec![1, 2, 3, 4];
        record.signer_public_key =
            Some(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0x42u8; 32]));

        let signer = RecordSigner::new(Some([0x99u8; 32]));
        assert!(!signer.verify(&record));
    }

    #[test]
    fn test_signed_record_tampered_value_rejected() {
        let record = create_valid_record();

        let signing_key = [0x42u8; 32];
        let signer = RecordSigner::new(Some(signing_key));

        let signature = signer.sign(&record);
        assert!(signature.is_some());

        let mut signed_record = record;
        signed_record.value = b"tampered_value".to_vec();
        signed_record.signature = signature.unwrap();
        signed_record.signer_public_key = signer.get_verifying_key();

        assert!(!signer.verify(&signed_record));
    }

    #[test]
    fn test_signed_record_tampered_key_rejected() {
        let record = create_valid_record();

        let signing_key = [0x42u8; 32];
        let signer = RecordSigner::new(Some(signing_key));

        let signature = signer.sign(&record);
        assert!(signature.is_some());

        let mut signed_record = record;
        signed_record.key = "tampered_key".to_string();
        signed_record.signature = signature.unwrap();
        signed_record.signer_public_key = signer.get_verifying_key();

        assert!(!signer.verify(&signed_record));
    }

    #[test]
    fn test_signed_record_tampered_publisher_rejected() {
        let record = create_valid_record();

        let signing_key = [0x42u8; 32];
        let signer = RecordSigner::new(Some(signing_key));

        let signature = signer.sign(&record);
        assert!(signature.is_some());

        let mut signed_record = record;
        signed_record.source_node_id = "tampered_node".to_string();
        signed_record.signature = signature.unwrap();
        signed_record.signer_public_key = signer.get_verifying_key();

        assert!(!signer.verify(&signed_record));
    }

    #[test]
    fn test_signed_record_valid_signature_accepted() {
        let record = create_valid_record();

        let signing_key = [0x42u8; 32];
        let signer = RecordSigner::new(Some(signing_key));

        let signature = signer.sign(&record);
        assert!(signature.is_some());

        let mut signed_record = record;
        signed_record.signature = signature.unwrap();
        signed_record.signer_public_key = signer.get_verifying_key();

        assert!(signer.verify(&signed_record));
    }

    #[test]
    fn test_record_without_public_key_rejected() {
        let mut record = create_valid_record();
        record.signer_public_key = None;
        record.signature = vec![1, 2, 3, 4];

        let signer = RecordSigner::new(Some([0x42u8; 32]));
        assert!(!signer.verify(&record));
    }

    #[test]
    fn test_record_with_valid_signature_has_verifiable_content() {
        let record = create_valid_record();
        let signing_key = [0xABu8; 32];
        let signer = RecordSigner::new(Some(signing_key));

        let signature = signer.sign(&record);
        assert!(signature.is_some());

        let mut signed_record = record;
        signed_record.signature = signature.unwrap();
        signed_record.signer_public_key = signer.get_verifying_key();

        let content = signed_record.get_signable_content();
        assert!(!content.is_empty());
    }
}

#[cfg(test)]
mod pending_entry_leak_tests {
    use std::collections::HashMap;
    use std::sync::Arc;
    use tokio::sync::Mutex;

    #[tokio::test]
    async fn test_pending_response_timeout_cleanup() {
        let pending_responses: Arc<Mutex<HashMap<String, tokio::sync::oneshot::Sender<String>>>> =
            Arc::new(Mutex::new(HashMap::new()));

        let (tx1, _rx1) = tokio::sync::oneshot::channel();
        let (tx2, _rx2) = tokio::sync::oneshot::channel();

        {
            let mut guard = pending_responses.lock().await;
            guard.insert("req1".to_string(), tx1);
            guard.insert("req2".to_string(), tx2);
        }

        let mut guard = pending_responses.lock().await;
        assert!(guard.contains_key("req1"));
        assert!(guard.contains_key("req2"));

        guard.remove("req1");

        assert_eq!(guard.len(), 1);
        assert!(guard.contains_key("req2"));
    }

    #[tokio::test]
    async fn test_pending_response_map_maintains_entries_until_cleaned() {
        let pending: Arc<Mutex<HashMap<String, tokio::sync::oneshot::Sender<Vec<u8>>>>> =
            Arc::new(Mutex::new(HashMap::new()));

        for i in 0..5 {
            let (tx, _rx) = tokio::sync::oneshot::channel();
            let mut guard = pending.lock().await;
            guard.insert(format!("req_{}", i), tx);
        }

        assert_eq!(pending.lock().await.len(), 5);
    }

    #[tokio::test]
    async fn test_orphaned_response_channels_can_be_detected() {
        let pending: Arc<Mutex<HashMap<String, tokio::sync::oneshot::Sender<String>>>> =
            Arc::new(Mutex::new(HashMap::new()));

        let (tx1, rx1) = tokio::sync::oneshot::channel::<String>();
        let (tx2, rx2) = tokio::sync::oneshot::channel::<String>();

        {
            let mut guard = pending.lock().await;
            guard.insert("orphan1".to_string(), tx1);
            guard.insert("orphan2".to_string(), tx2);
        }

        drop(rx1);
        drop(rx2);

        let mut guard = pending.lock().await;
        let before = guard.len();
        guard.retain(|_, sender| !sender.is_closed());
        let after = guard.len();

        assert!(before >= 2);
        assert_eq!(after, 0);
    }
}

#[cfg(test)]
mod dht_adversarial_tests {
    use crate::mesh::dht::signed::{validate_message_timestamp, SignedDhtRecord, SignedRecordType};
    use crate::mesh::safe_unix_timestamp;

    #[test]
    fn test_expired_timestamp_rejected() {
        let old_timestamp = safe_unix_timestamp() - 400;
        assert!(!validate_message_timestamp(old_timestamp));
    }

    #[test]
    fn test_future_timestamp_rejected() {
        let future_timestamp = safe_unix_timestamp() + 400;
        assert!(!validate_message_timestamp(future_timestamp));
    }

    #[test]
    fn test_valid_timestamp_accepted() {
        let now = safe_unix_timestamp();
        assert!(validate_message_timestamp(now));
    }

    #[test]
    fn test_margin_timestamp_accepted() {
        let margin_timestamp = safe_unix_timestamp() - 299;
        assert!(validate_message_timestamp(margin_timestamp));
    }

    #[test]
    fn test_record_expired_check() {
        let mut record = SignedDhtRecord::new(
            "test_key".to_string(),
            b"test_value".to_vec(),
            "publisher".to_string(),
            SignedRecordType::Upstream,
        );

        assert!(!record.is_expired());

        record.created_at = safe_unix_timestamp() - 10000;
        record.expires_at = Some(safe_unix_timestamp() - 5000);

        assert!(record.is_expired());
    }

    #[test]
    fn test_record_not_expired_with_future_expiry() {
        let mut record = SignedDhtRecord::new(
            "test_key".to_string(),
            b"test_value".to_vec(),
            "publisher".to_string(),
            SignedRecordType::Upstream,
        );

        record.created_at = safe_unix_timestamp();
        record.expires_at = Some(safe_unix_timestamp() + 3600);

        assert!(!record.is_expired());
    }

    #[test]
    fn test_record_without_expiry_not_expired() {
        let record = SignedDhtRecord::new(
            "test_key".to_string(),
            b"test_value".to_vec(),
            "publisher".to_string(),
            SignedRecordType::Upstream,
        );

        assert!(!record.is_expired());
    }

    #[test]
    fn test_privileged_record_type_requires_signature() {
        let org_record = SignedDhtRecord::new(
            "org_key".to_string(),
            b"value".to_vec(),
            "publisher".to_string(),
            SignedRecordType::Organization,
        );

        assert!(org_record.requires_signature());

        let upstream_record = SignedDhtRecord::new(
            "upstream_key".to_string(),
            b"value".to_vec(),
            "publisher".to_string(),
            SignedRecordType::Upstream,
        );

        assert!(upstream_record.requires_signature());
    }

    #[test]
    fn test_record_needs_refresh_when_expiry_imminent() {
        let mut record = SignedDhtRecord::new(
            "test_key".to_string(),
            b"test_value".to_vec(),
            "publisher".to_string(),
            SignedRecordType::Upstream,
        );

        record.created_at = safe_unix_timestamp() - 250;
        record.expires_at = Some(safe_unix_timestamp() - 50);

        assert!(record.is_expired());
        assert!(record.needs_refresh());
    }
}

#[cfg(test)]
mod raft_command_tests {
    use crate::mesh::raft::state_machine::RaftCommand;

    #[test]
    fn test_raft_command_set_serialization() {
        let cmd = RaftCommand::Set {
            namespace: crate::mesh::raft::state_machine::Namespace::Org,
            key: "test_key".to_string(),
            value: b"test_value".to_vec(),
            source_node_id: None,
            signature: None,
        };

        let serialized = crate::serialization::serialize(&cmd).unwrap();
        let deserialized: RaftCommand = crate::serialization::deserialize(&serialized).unwrap();

        match deserialized {
            RaftCommand::Set {
                namespace,
                key,
                value,
                source_node_id: _,
                signature: _,
            } => {
                assert_eq!(namespace, crate::mesh::raft::state_machine::Namespace::Org);
                assert_eq!(key, "test_key");
                assert_eq!(value, b"test_value");
            }
            _ => panic!("Expected Set command"),
        }
    }

    #[test]
    fn test_raft_command_delete_serialization() {
        let cmd = RaftCommand::Delete {
            namespace: crate::mesh::raft::state_machine::Namespace::Intel,
            key: "delete_key".to_string(),
            source_node_id: None,
            signature: None,
        };

        let serialized = crate::serialization::serialize(&cmd).unwrap();
        let deserialized: RaftCommand = crate::serialization::deserialize(&serialized).unwrap();

        match deserialized {
            RaftCommand::Delete {
                namespace,
                key,
                source_node_id: _,
                signature: _,
            } => {
                assert_eq!(
                    namespace,
                    crate::mesh::raft::state_machine::Namespace::Intel
                );
                assert_eq!(key, "delete_key");
            }
            _ => panic!("Expected Delete command"),
        }
    }

    #[test]
    fn test_raft_command_set_display() {
        let cmd = RaftCommand::Set {
            namespace: crate::mesh::raft::state_machine::Namespace::Org,
            key: "my_key".to_string(),
            value: vec![],
            source_node_id: None,
            signature: None,
        };

        let display = format!("{}", cmd);
        assert!(display.contains("my_key"));
        assert!(display.contains("org"));
    }

    #[test]
    fn test_raft_command_delete_display() {
        let cmd = RaftCommand::Delete {
            namespace: crate::mesh::raft::state_machine::Namespace::Revocation,
            key: "revoke_key".to_string(),
            source_node_id: None,
            signature: None,
        };

        let display = format!("{}", cmd);
        assert!(display.contains("revoke_key"));
        assert!(display.contains("revocation"));
    }
}

#[cfg(test)]
mod edge_replica_tests {
    use crate::mesh::raft::edge_replica::EdgeReplicaManager;
    use crate::mesh::raft::state_machine::{Namespace, OrgPublicKey, ThreatIntel};
    use tempfile::TempDir;

    fn create_test_manager() -> (EdgeReplicaManager, TempDir) {
        let temp_dir = TempDir::new().unwrap();
        let manager = EdgeReplicaManager::new(temp_dir.path().to_path_buf()).unwrap();
        (manager, temp_dir)
    }

    fn create_org_key_value(org_id: &str, _key_id: &str) -> Vec<u8> {
        let key = OrgPublicKey {
            org_id: org_id.to_string(),
            public_key: vec![1, 2, 3, 4],
            created_at: 1000,
            signer_node_id: "node1".to_string(),
        };
        postcard::to_stdvec(&key).unwrap()
    }

    fn create_threat_intel_value(indicator_id: &str) -> Vec<u8> {
        let intel = ThreatIntel {
            indicator_id: indicator_id.to_string(),
            indicator_type: "malware".to_string(),
            pattern: "*.evil.com".to_string(),
            severity: "high".to_string(),
            created_at: 1000,
            expires_at: Some(2000),
            source_node_id: "node1".to_string(),
        };
        postcard::to_stdvec(&intel).unwrap()
    }

    #[test]
    fn test_edge_replica_update_and_get() {
        let (manager, _temp_dir) = create_test_manager();
        let value = create_org_key_value("org1", "key1");
        manager.update_org_key("key1", &value).unwrap();
        let retrieved = manager.get_org_key("key1");
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().org_id, "org1");
    }

    #[test]
    fn test_edge_replica_cache_isolation() {
        let (manager, _temp_dir) = create_test_manager();

        let value1 = create_org_key_value("org1", "key1");
        let value2 = create_org_key_value("org2", "key2");

        manager.update_org_key("key1", &value1).unwrap();
        manager.update_org_key("key2", &value2).unwrap();

        assert_eq!(manager.get_org_key("key1").unwrap().org_id, "org1");
        assert_eq!(manager.get_org_key("key2").unwrap().org_id, "org2");
    }

    #[test]
    fn test_edge_replica_threat_intel() {
        let (manager, _temp_dir) = create_test_manager();
        let value = create_threat_intel_value("indicator1");
        manager.update_threat_intel("indicator1", &value).unwrap();
        let retrieved = manager.get_threat_intel("indicator1");
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().severity, "high");
    }

    #[test]
    fn test_edge_replica_update_from_notification() {
        let (manager, _temp_dir) = create_test_manager();
        let org_value = create_org_key_value("org1", "key1");
        let intel_value = create_threat_intel_value("indicator1");

        manager
            .update_from_notification(&Namespace::Org, "key1", &org_value)
            .unwrap();
        manager
            .update_from_notification(&Namespace::Intel, "indicator1", &intel_value)
            .unwrap();

        assert!(manager.get_org_key("key1").is_some());
        assert!(manager.get_threat_intel("indicator1").is_some());
    }

    #[test]
    fn test_edge_replica_delete() {
        let (manager, _temp_dir) = create_test_manager();
        let value = create_org_key_value("org1", "key1");
        manager.update_org_key("key1", &value).unwrap();
        assert!(manager.get_org_key("key1").is_some());

        manager
            .delete_from_notification(&Namespace::Org, "key1")
            .unwrap();
        assert!(manager.get_org_key("key1").is_none());
    }

    #[test]
    fn test_edge_replica_cache_invalidation_on_delete() {
        let (manager, _temp_dir) = create_test_manager();
        let value = create_org_key_value("org1", "key1");
        manager.update_org_key("key1", &value).unwrap();

        manager.get_org_key("key1");
        assert!(manager.get_org_key("key1").is_some());

        manager.delete_org_key("key1").unwrap();
        assert!(manager.get_org_key("key1").is_none());
    }

    #[test]
    fn test_edge_replica_sync_index_tracking() {
        let (manager, _temp_dir) = create_test_manager();

        assert!(manager.get_last_sync_index().is_none());

        manager.set_last_sync_index(100).unwrap();
        assert_eq!(manager.get_last_sync_index(), Some(100));

        manager.set_last_sync_index(200).unwrap();
        assert_eq!(manager.get_last_sync_index(), Some(200));
    }

    #[test]
    fn test_edge_replica_cache_stats_initially_zero() {
        let (manager, _temp_dir) = create_test_manager();
        let (entries, size) = manager.get_cache_stats();
        assert_eq!(entries, 0);
        assert_eq!(size, 0);
    }
}

#[cfg(test)]
mod mesh_message_raft_tests {
    use crate::mesh::protocol::{ArcStr, MeshMessage, RaftMsgType, RaftPayload};

    #[test]
    fn test_append_entries_via_mesh_message() {
        let data = postcard::to_stdvec(&()).unwrap();

        let payload = RaftPayload {
            msg_type: RaftMsgType::AppendEntries,
            data,
            request_id: Some("test_append".into()),
        };

        let mesh_msg = MeshMessage::Raft {
            target_node_id: ArcStr::from("node1"),
            payload,
        };

        let encoded = mesh_msg.encode().expect("Failed to encode MeshMessage");
        let decoded = MeshMessage::decode(&encoded).expect("Failed to decode MeshMessage");

        match decoded {
            MeshMessage::Raft {
                payload: decoded_payload,
                ..
            } => {
                assert!(matches!(
                    decoded_payload.msg_type,
                    RaftMsgType::AppendEntries
                ));
            }
            _ => panic!("Expected Raft message"),
        }
    }

    #[test]
    fn test_vote_request_via_mesh_message() {
        let payload = RaftPayload {
            msg_type: RaftMsgType::VoteRequest,
            data: postcard::to_stdvec(&()).unwrap(),
            request_id: Some("test_vote".into()),
        };

        let mesh_msg = MeshMessage::Raft {
            target_node_id: ArcStr::from("node1"),
            payload,
        };

        let encoded = mesh_msg.encode().expect("Failed to encode MeshMessage");
        let decoded = MeshMessage::decode(&encoded).expect("Failed to decode MeshMessage");

        match decoded {
            MeshMessage::Raft {
                payload: decoded_payload,
                ..
            } => {
                assert!(matches!(decoded_payload.msg_type, RaftMsgType::VoteRequest));
            }
            _ => panic!("Expected Raft message"),
        }
    }

    #[test]
    fn test_raft_message_roundtrip_all_msg_types() {
        let msg_types = vec![
            RaftMsgType::VoteRequest,
            RaftMsgType::AppendEntries,
            RaftMsgType::ClientProposal,
            RaftMsgType::InstallSnapshot,
        ];

        for msg_type in msg_types {
            let payload = RaftPayload {
                msg_type,
                data: vec![],
                request_id: Some("roundtrip_test".into()),
            };

            let mesh_msg = MeshMessage::Raft {
                target_node_id: ArcStr::from("node1"),
                payload,
            };

            let encoded = mesh_msg.encode().expect("Failed to encode");
            let decoded = MeshMessage::decode(&encoded).expect("Failed to decode");

            match decoded {
                MeshMessage::Raft { .. } => {}
                _ => panic!("Expected Raft message"),
            }
        }
    }

    #[test]
    fn test_installsnapshot_header_encode_decode() {
        let header = crate::mesh::protocol::SnapshotHeader {
            request_id: "snap-123".to_string(),
            vote: vec![1, 2, 3],
            meta: vec![4, 5, 6],
            total_size: 1024,
        };

        let bytes = postcard::to_stdvec(&header).expect("Failed to serialize");
        let decoded: crate::mesh::protocol::SnapshotHeader =
            postcard::from_bytes(&bytes).expect("Failed to deserialize");

        assert_eq!(decoded.request_id, "snap-123");
        assert_eq!(decoded.total_size, 1024);
    }

    #[test]
    fn test_installsnapshot_chunk_encode_decode() {
        let chunk = crate::mesh::protocol::SnapshotChunk {
            request_id: "snap-456".to_string(),
            offset: 512,
            is_last: false,
            data: vec![7u8; 256],
        };

        let bytes = postcard::to_stdvec(&chunk).expect("Failed to serialize");
        let decoded: crate::mesh::protocol::SnapshotChunk =
            postcard::from_bytes(&bytes).expect("Failed to deserialize");

        assert_eq!(decoded.request_id, "snap-456");
        assert_eq!(decoded.offset, 512);
        assert_eq!(decoded.is_last, false);
        assert_eq!(decoded.data.len(), 256);
    }
}

#[cfg(test)]
mod snapshot_install_tests {
    use crate::mesh::transport::InProgressSnapshot;

    #[test]
    fn test_in_progress_snapshot_add_chunk() {
        let mut snapshot =
            InProgressSnapshot::new("test-snap".to_string(), 1024, vec![1, 2, 3], vec![4, 5, 6]);

        assert_eq!(snapshot.offset, 0);
        assert_eq!(snapshot.total_size, 1024);

        let chunk1 = vec![0u8; 512];
        assert!(snapshot.add_chunk(0, chunk1, false));
        assert_eq!(snapshot.offset, 512);

        let chunk2 = vec![0u8; 512];
        assert!(snapshot.add_chunk(512, chunk2, true));
        assert_eq!(snapshot.offset, 1024);
        assert!(snapshot.is_complete());
    }

    #[test]
    fn test_in_progress_snapshot_rejects_out_of_order() {
        let mut snapshot = InProgressSnapshot::new("test-snap".to_string(), 1024, vec![], vec![]);

        let chunk1 = vec![0u8; 512];
        assert!(snapshot.add_chunk(0, chunk1, false));
        assert_eq!(snapshot.offset, 512);

        let chunk_wrong_offset = vec![0u8; 512];
        assert!(!snapshot.add_chunk(256, chunk_wrong_offset, false));
    }

    #[test]
    fn test_in_progress_snapshot_rejects_oversized() {
        let mut snapshot = InProgressSnapshot::new("test-snap".to_string(), 512, vec![], vec![]);

        let oversized_chunk = vec![0u8; 1024];
        assert!(!snapshot.add_chunk(0, oversized_chunk, true));
    }
}

#[cfg(test)]
mod dht_signable_bytes_tests {
    use crate::mesh::dht::signed::{RecordSigner, SignedDhtRecord, SignedRecordType};

    #[test]
    fn test_dht_signable_content_key_difference_detected() {
        let mut record1 = SignedDhtRecord::new(
            "key_a".to_string(),
            b"same_value".to_vec(),
            "node_x".to_string(),
            SignedRecordType::Upstream,
        );

        let mut record2 = SignedDhtRecord::new(
            "key_b".to_string(),
            b"same_value".to_vec(),
            "node_x".to_string(),
            SignedRecordType::Upstream,
        );

        record1.created_at = 1000;
        record1.ttl_seconds = 3600;
        record1.sequence_number = 1;
        record2.created_at = 1000;
        record2.ttl_seconds = 3600;
        record2.sequence_number = 1;

        let content1 = record1.get_signable_content();
        let content2 = record2.get_signable_content();

        assert_ne!(
            content1, content2,
            "Records with different keys should have different signable content"
        );

        let signing_key = [0x42u8; 32];
        let signer = RecordSigner::new(Some(signing_key));

        let sig1 = signer.sign(&record1);
        let sig2 = signer.sign(&record2);

        assert!(sig1.is_some());
        assert!(sig2.is_some());

        assert_ne!(sig1.unwrap(), sig2.unwrap());
    }

    #[test]
    fn test_dht_record_signable_content_is_deterministic() {
        let mut record1 = SignedDhtRecord::new(
            "org:test".to_string(),
            b"value123".to_vec(),
            "node_a".to_string(),
            SignedRecordType::OrgPublicKey,
        );

        let mut record2 = SignedDhtRecord::new(
            "org:test".to_string(),
            b"value123".to_vec(),
            "node_a".to_string(),
            SignedRecordType::OrgPublicKey,
        );

        record1.created_at = 1000;
        record1.ttl_seconds = 3600;
        record1.sequence_number = 1;
        record2.created_at = 1000;
        record2.ttl_seconds = 3600;
        record2.sequence_number = 1;

        assert_eq!(
            record1.get_signable_content(),
            record2.get_signable_content()
        );
    }

    #[test]
    fn test_dht_record_signable_content_changes_with_value() {
        let mut record1 = SignedDhtRecord::new(
            "org:test".to_string(),
            b"value123".to_vec(),
            "node_a".to_string(),
            SignedRecordType::OrgPublicKey,
        );

        let mut record2 = SignedDhtRecord::new(
            "org:test".to_string(),
            b"value456".to_vec(),
            "node_a".to_string(),
            SignedRecordType::OrgPublicKey,
        );

        record1.created_at = 1000;
        record1.ttl_seconds = 3600;
        record1.sequence_number = 1;
        record2.created_at = 1000;
        record2.ttl_seconds = 3600;
        record2.sequence_number = 1;

        assert_ne!(
            record1.get_signable_content(),
            record2.get_signable_content()
        );
    }

    #[test]
    fn test_dht_record_signable_content_changes_with_key() {
        let mut record1 = SignedDhtRecord::new(
            "org:key1".to_string(),
            b"value".to_vec(),
            "node_a".to_string(),
            SignedRecordType::OrgPublicKey,
        );

        let mut record2 = SignedDhtRecord::new(
            "org:key2".to_string(),
            b"value".to_vec(),
            "node_a".to_string(),
            SignedRecordType::OrgPublicKey,
        );

        record1.created_at = 1000;
        record1.ttl_seconds = 3600;
        record1.sequence_number = 1;
        record2.created_at = 1000;
        record2.ttl_seconds = 3600;
        record2.sequence_number = 1;

        assert_ne!(
            record1.get_signable_content(),
            record2.get_signable_content()
        );
    }
}

#[cfg(test)]
mod dht_snapshot_signable_tests {
    use crate::mesh::dht::signed::{get_snapshot_signable_content, get_sync_signable_content};

    #[test]
    fn test_snapshot_signable_content_deterministic() {
        let content1 = get_snapshot_signable_content("req1", "node_a", 100, 50, 1000, &[]);
        let content2 = get_snapshot_signable_content("req1", "node_a", 100, 50, 1000, &[]);
        assert_eq!(content1, content2);
    }

    #[test]
    fn test_snapshot_signable_content_differs_with_params() {
        let content1 = get_snapshot_signable_content("req1", "node_a", 100, 50, 1000, &[]);
        let content2 = get_snapshot_signable_content("req2", "node_a", 100, 50, 1000, &[]);
        assert_ne!(content1, content2);

        let content3 = get_snapshot_signable_content("req1", "node_a", 101, 50, 1000, &[]);
        assert_ne!(content1, content3);

        let content4 = get_snapshot_signable_content("req1", "node_a", 100, 51, 1000, &[]);
        assert_ne!(content1, content4);
    }

    #[test]
    fn test_sync_signable_content_deterministic() {
        let content1 = get_sync_signable_content("req1", "peer_a", "node_a", 100, 25, 1000, &[]);
        let content2 = get_sync_signable_content("req1", "peer_a", "node_a", 100, 25, 1000, &[]);
        assert_eq!(content1, content2);
    }

    #[test]
    fn test_sync_signable_content_differs_with_params() {
        let content1 = get_sync_signable_content("req1", "peer_a", "node_a", 100, 25, 1000, &[]);
        let content2 = get_sync_signable_content("req2", "peer_a", "node_a", 100, 25, 1000, &[]);
        assert_ne!(content1, content2);

        let content3 = get_sync_signable_content("req1", "peer_b", "node_a", 100, 25, 1000, &[]);
        assert_ne!(content1, content3);

        let content4 = get_sync_signable_content("req1", "peer_a", "node_a", 101, 25, 1000, &[]);
        assert_ne!(content1, content4);
    }
}

#[cfg(test)]
mod streaming_snapshot_tests {
    use crate::mesh::raft::state_machine::{GlobalRegistryStateMachine, Namespace, RaftSnapshotData};
    use rusqlite::Connection;
    use tokio::io::AsyncReadExt;

    fn in_memory_state_machine() -> GlobalRegistryStateMachine {
        let db = Connection::open_in_memory().unwrap();
        GlobalRegistryStateMachine::new_with_connection(db).unwrap()
    }

    async fn snapshot_to_vec(mut data: RaftSnapshotData) -> Vec<u8> {
        let mut buf = Vec::new();
        data.read_to_end(&mut buf).await.unwrap();
        buf
    }

    #[tokio::test]
    async fn test_streaming_round_trip_empty() {
        let sm = in_memory_state_machine();
        let serialized = sm.streaming_serialize().await.unwrap();
        
        let sm2 = in_memory_state_machine();
        sm2.streaming_deserialize_and_apply(serialized).await.unwrap();
        assert!(sm2.get_all_entries().is_empty());
    }

    #[tokio::test]
    async fn test_streaming_round_trip_with_entries() {
        let sm = in_memory_state_machine();
        sm.set(&Namespace::Org, "key1", b"value1".to_vec()).unwrap();
        sm.set(&Namespace::Intel, "key2", b"value2".to_vec())
            .unwrap();
        sm.set(&Namespace::Revocation, "key3", b"value3_longer".to_vec())
            .unwrap();

        let serialized = sm.streaming_serialize().await.unwrap();

        let sm2 = in_memory_state_machine();
        sm2.streaming_deserialize_and_apply(serialized).await.unwrap();

        let entries = sm2.get_all_entries();
        assert_eq!(entries.len(), 3);

        assert_eq!(sm2.get(&Namespace::Org, "key1"), Some(b"value1".to_vec()));
        assert_eq!(sm2.get(&Namespace::Intel, "key2"), Some(b"value2".to_vec()));
        assert_eq!(
            sm2.get(&Namespace::Revocation, "key3"),
            Some(b"value3_longer".to_vec())
        );
    }

    #[tokio::test]
    async fn test_streaming_format_has_magic() {
        let sm = in_memory_state_machine();
        sm.set(&Namespace::Org, "k", b"v".to_vec()).unwrap();

        let serialized = sm.streaming_serialize().await.unwrap();
        let bytes = snapshot_to_vec(serialized).await;
        let magic = u32::from_le_bytes(bytes[..4].try_into().unwrap());
        assert_eq!(magic, 0x53524D53);
    }

    #[tokio::test]
    async fn test_streaming_entry_count_matches() {
        let sm = in_memory_state_machine();
        for i in 0..50 {
            sm.set(
                &Namespace::Org,
                &format!("key{}", i),
                format!("val{}", i).into_bytes(),
            )
            .unwrap();
        }

        let serialized = sm.streaming_serialize().await.unwrap();
        let bytes = snapshot_to_vec(serialized).await;
        let count = u64::from_le_bytes(bytes[4..12].try_into().unwrap());
        assert_eq!(count, 50);
    }

    #[tokio::test]
    async fn test_fallback_json_deserialization() {
        let sm = in_memory_state_machine();
        sm.set(&Namespace::Org, "key1", b"value1".to_vec()).unwrap();

        let json_data = serde_json::to_vec(&sm.get_all_entries()).unwrap();

        let sm2 = in_memory_state_machine();
        sm2.streaming_deserialize_and_apply(RaftSnapshotData::from_bytes(bytes::Bytes::from(json_data))).await.unwrap();

        assert_eq!(sm2.get(&Namespace::Org, "key1"), Some(b"value1".to_vec()));
    }

    #[tokio::test]
    async fn test_streaming_replaces_existing_data() {
        let sm = in_memory_state_machine();
        sm.set(&Namespace::Org, "old_key", b"old_value".to_vec())
            .unwrap();

        let sm2 = in_memory_state_machine();
        sm2.set(&Namespace::Intel, "existing", b"data".to_vec())
            .unwrap();

        let serialized = sm.streaming_serialize().await.unwrap();
        sm2.streaming_deserialize_and_apply(serialized).await.unwrap();

        assert!(sm2.get(&Namespace::Intel, "existing").is_none());
        assert_eq!(
            sm2.get(&Namespace::Org, "old_key"),
            Some(b"old_value".to_vec())
        );
    }

    #[tokio::test]
    async fn test_streaming_large_dataset() {
        let sm = in_memory_state_machine();
        let entry_count: usize = 10_000;
        for i in 0..entry_count {
            sm.set(
                &Namespace::Intel,
                &format!("indicator:{}", i),
                vec![0xABu8; 100],
            )
            .unwrap();
        }

        let serialized = sm.streaming_serialize().await.unwrap();

        let sm2 = in_memory_state_machine();
        sm2.streaming_deserialize_and_apply(serialized).await.unwrap();

        let entries = sm2.get_all_entries();
        assert_eq!(entries.len(), entry_count);

        assert_eq!(
            sm2.get(&Namespace::Intel, "indicator:0"),
            Some(vec![0xABu8; 100])
        );
        assert_eq!(
            sm2.get(&Namespace::Intel, &format!("indicator:{}", entry_count - 1)),
            Some(vec![0xABu8; 100])
        );
    }

    #[tokio::test]
    async fn test_streaming_binary_values() {
        let sm = in_memory_state_machine();
        let binary_val: Vec<u8> = (0u8..=255).collect();
        sm.set(&Namespace::Org, "binary_key", binary_val.clone())
            .unwrap();

        let serialized = sm.streaming_serialize().await.unwrap();

        let sm2 = in_memory_state_machine();
        sm2.streaming_deserialize_and_apply(serialized).await.unwrap();

        assert_eq!(sm2.get(&Namespace::Org, "binary_key"), Some(binary_val));
    }
}
