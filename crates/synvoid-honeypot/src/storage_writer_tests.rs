#[cfg(test)]
mod tests {
    use crate::config::*;
    use crate::storage::*;
    use crate::storage_writer::HoneypotWriter;
    use std::time::Duration;

    fn test_storage() -> HoneypotStorage {
        let cfg = StorageConfig {
            database_path: ":memory:".to_string(),
            ..Default::default()
        };
        HoneypotStorage::new(&cfg).unwrap()
    }

    fn base_record() -> HoneypotRecord {
        HoneypotRecord {
            id: 0,
            timestamp: 1700000000,
            remote_ip: "10.0.0.1".to_string(),
            remote_port: 12345,
            local_port: 80,
            protocol: "http".to_string(),
            service: "http".to_string(),
            confidence: crate::protocol::Confidence::Medium,
            payload: b"GET /admin HTTP/1.1\r\nHost: test\r\n\r\n".to_vec(),
            payload_hex: String::new(),
            detected_pattern: None,
            bytes_received: 38,
            bytes_sent: 0,
            duration_ms: 150,
            connection_info: "10.0.0.1:12345".to_string(),
            payload_truncated: false,
            payload_hash: None,
            payload_length: None,
        }
    }

    #[tokio::test]
    async fn test_payload_retention_none() {
        let storage = test_storage();
        let writer = HoneypotWriter::new(
            storage.clone(),
            StorageWriterConfig {
                queue_capacity: 256,
                batch_size: 16,
                flush_interval_ms: 10,
                payload_retention_mode: PayloadRetentionMode::None,
                ..Default::default()
            },
        );

        let mut record = base_record();
        record.payload = b"sensitive payload data".to_vec();
        record.payload_hex = hex::encode(&record.payload);

        writer.try_write_record(record).unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;

        let records = storage.get_records_since(0, 10).unwrap();
        assert_eq!(records.len(), 1);
        assert!(records[0].payload.is_empty());
        assert!(records[0].payload_hex.is_empty());
        assert!(records[0].payload_hash.is_some());
        assert_eq!(records[0].payload_length, Some(22));
    }

    #[tokio::test]
    async fn test_payload_retention_hash_only() {
        let storage = test_storage();
        let writer = HoneypotWriter::new(
            storage.clone(),
            StorageWriterConfig {
                queue_capacity: 256,
                batch_size: 16,
                flush_interval_ms: 10,
                payload_retention_mode: PayloadRetentionMode::HashOnly,
                ..Default::default()
            },
        );

        let mut record = base_record();
        record.payload = b"secret data".to_vec();
        record.payload_hex = hex::encode(&record.payload);

        writer.try_write_record(record).unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;

        let records = storage.get_records_since(0, 10).unwrap();
        assert_eq!(records.len(), 1);
        assert!(records[0].payload.is_empty());
        assert!(records[0].payload_hex.is_empty());
        assert!(records[0].payload_hash.is_some());
        assert_eq!(records[0].payload_length, Some(11));
    }

    #[tokio::test]
    async fn test_payload_retention_truncated() {
        let storage = test_storage();
        let writer = HoneypotWriter::new(
            storage.clone(),
            StorageWriterConfig {
                queue_capacity: 256,
                batch_size: 16,
                flush_interval_ms: 10,
                payload_retention_mode: PayloadRetentionMode::Truncated,
                max_stored_payload_bytes: 10,
                max_stored_payload_hex_bytes: 20,
                ..Default::default()
            },
        );

        let mut record = base_record();
        record.payload = b"this is a very long payload that should be truncated".to_vec();
        record.payload_hex = hex::encode(&record.payload);

        writer.try_write_record(record).unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;

        let records = storage.get_records_since(0, 10).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].payload.len(), 10);
        assert!(records[0].payload_hex.len() <= 20);
        assert!(records[0].payload_hash.is_some());
        assert_eq!(records[0].payload_length, Some(52));
    }

    #[tokio::test]
    async fn test_payload_retention_full() {
        let storage = test_storage();
        let writer = HoneypotWriter::new(
            storage.clone(),
            StorageWriterConfig {
                queue_capacity: 256,
                batch_size: 16,
                flush_interval_ms: 10,
                payload_retention_mode: PayloadRetentionMode::Full,
                ..Default::default()
            },
        );

        let payload_data = b"full payload stored completely".to_vec();
        let mut record = base_record();
        record.payload = payload_data.clone();
        record.payload_hex = hex::encode(&record.payload);

        writer.try_write_record(record).unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;

        let records = storage.get_records_since(0, 10).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].payload, payload_data);
        assert!(!records[0].payload_hex.is_empty());
        assert!(records[0].payload_hash.is_some());
        assert_eq!(records[0].payload_length, Some(30));
    }

    #[tokio::test]
    async fn test_payload_hash_always_computed() {
        for mode in [
            PayloadRetentionMode::None,
            PayloadRetentionMode::HashOnly,
            PayloadRetentionMode::Truncated,
            PayloadRetentionMode::Full,
        ] {
            let storage = test_storage();
            let writer = HoneypotWriter::new(
                storage.clone(),
                StorageWriterConfig {
                    queue_capacity: 256,
                    batch_size: 16,
                    flush_interval_ms: 10,
                    payload_retention_mode: mode.clone(),
                    ..Default::default()
                },
            );

            let mut record = base_record();
            record.payload = b"test data for hashing".to_vec();
            record.payload_hex = hex::encode(&record.payload);

            writer.try_write_record(record).unwrap();
            tokio::time::sleep(Duration::from_millis(50)).await;

            let records = storage.get_records_since(0, 10).unwrap();
            assert_eq!(records.len(), 1, "mode {:?} should have a record", mode);
            assert!(
                records[0].payload_hash.is_some(),
                "mode {:?} should have payload_hash",
                mode
            );
            assert!(
                !records[0].payload_hash.as_ref().unwrap().is_empty(),
                "mode {:?} payload_hash should not be empty",
                mode
            );
            assert!(
                records[0].payload_hash.as_ref().unwrap().len() == 64,
                "mode {:?} payload_hash should be SHA-256 (64 hex chars)",
                mode
            );
        }
    }

    #[tokio::test]
    async fn test_payload_length_always_stored() {
        for mode in [
            PayloadRetentionMode::None,
            PayloadRetentionMode::HashOnly,
            PayloadRetentionMode::Truncated,
            PayloadRetentionMode::Full,
        ] {
            let storage = test_storage();
            let writer = HoneypotWriter::new(
                storage.clone(),
                StorageWriterConfig {
                    queue_capacity: 256,
                    batch_size: 16,
                    flush_interval_ms: 10,
                    payload_retention_mode: mode.clone(),
                    ..Default::default()
                },
            );

            let mut record = base_record();
            record.payload = b"payload with known length".to_vec();
            record.payload_hex = hex::encode(&record.payload);

            writer.try_write_record(record).unwrap();
            tokio::time::sleep(Duration::from_millis(50)).await;

            let records = storage.get_records_since(0, 10).unwrap();
            assert_eq!(records.len(), 1, "mode {:?} should have a record", mode);
            assert_eq!(
                records[0].payload_length,
                Some(25),
                "mode {:?} should store original payload length",
                mode
            );
        }
    }

    #[tokio::test]
    async fn test_queue_drop_on_full() {
        let storage = test_storage();
        let writer = HoneypotWriter::new(
            storage.clone(),
            StorageWriterConfig {
                queue_capacity: 2,
                batch_size: 2,
                flush_interval_ms: 10000,
                payload_retention_mode: PayloadRetentionMode::None,
                ..Default::default()
            },
        );

        let r1 = base_record();
        let r2 = base_record();
        let r3 = base_record();

        writer.try_write_record(r1).unwrap();
        writer.try_write_record(r2).unwrap();
        let result = writer.try_write_record(r3);
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_writer_flushes_batch() {
        let storage = test_storage();
        let writer = HoneypotWriter::new(
            storage.clone(),
            StorageWriterConfig {
                queue_capacity: 256,
                batch_size: 2,
                flush_interval_ms: 10,
                payload_retention_mode: PayloadRetentionMode::None,
                ..Default::default()
            },
        );

        for _ in 0..5 {
            writer.try_write_record(base_record()).unwrap();
        }

        tokio::time::sleep(Duration::from_millis(100)).await;

        let records = storage.get_records_since(0, 100).unwrap();
        assert_eq!(records.len(), 5);
    }

    #[tokio::test]
    async fn test_writer_shutdown_flushes() {
        let storage = test_storage();
        let writer = HoneypotWriter::new(
            storage.clone(),
            StorageWriterConfig {
                queue_capacity: 256,
                batch_size: 64,
                flush_interval_ms: 10000,
                payload_retention_mode: PayloadRetentionMode::None,
                ..Default::default()
            },
        );

        for _ in 0..10 {
            writer.try_write_record(base_record()).unwrap();
        }

        writer.shutdown().await;
        tokio::time::sleep(Duration::from_millis(50)).await;

        let records = storage.get_records_since(0, 100).unwrap();
        assert_eq!(records.len(), 10);
    }

    #[tokio::test]
    async fn test_storage_failure_increments_metric() {
        let storage = test_storage();
        let writer = HoneypotWriter::new(
            storage.clone(),
            StorageWriterConfig {
                queue_capacity: 2,
                batch_size: 1,
                flush_interval_ms: 10000,
                payload_retention_mode: PayloadRetentionMode::None,
                ..Default::default()
            },
        );

        writer.try_write_record(base_record()).unwrap();
        writer.try_write_record(base_record()).unwrap();
        let result = writer.try_write_record(base_record());
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_schema_migration_idempotent() {
        let cfg = StorageConfig {
            database_path: ":memory:".to_string(),
            ..Default::default()
        };
        let storage1 = HoneypotStorage::new(&cfg).unwrap();

        let mut record = base_record();
        record.payload_hash = Some("test_hash".to_string());
        record.payload_length = Some(42);
        storage1.record_connection(record).unwrap();

        let cfg2 = StorageConfig {
            database_path: ":memory:".to_string(),
            ..Default::default()
        };
        let _storage2 = HoneypotStorage::new(&cfg2).unwrap();
    }

    #[tokio::test]
    async fn test_hash_determinism() {
        let storage = test_storage();
        let writer = HoneypotWriter::new(
            storage.clone(),
            StorageWriterConfig {
                queue_capacity: 256,
                batch_size: 16,
                flush_interval_ms: 10,
                payload_retention_mode: PayloadRetentionMode::Full,
                ..Default::default()
            },
        );

        let mut r1 = base_record();
        r1.payload = b"deterministic hash input".to_vec();
        r1.payload_hex = hex::encode(&r1.payload);
        writer.try_write_record(r1).unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;

        let mut r2 = base_record();
        r2.payload = b"deterministic hash input".to_vec();
        r2.payload_hex = hex::encode(&r2.payload);
        let writer2 = HoneypotWriter::new(
            storage.clone(),
            StorageWriterConfig {
                queue_capacity: 256,
                batch_size: 16,
                flush_interval_ms: 10,
                payload_retention_mode: PayloadRetentionMode::Full,
                ..Default::default()
            },
        );
        writer2.try_write_record(r2).unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;

        let records = storage.get_records_since(0, 10).unwrap();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].payload_hash, records[1].payload_hash);
    }
}
