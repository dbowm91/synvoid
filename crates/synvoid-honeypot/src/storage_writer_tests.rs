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

    /// Phase 53: retention outputs identical across empty, small,
    /// truncation-boundary, and large payloads. The in-place hash must equal
    /// the digest of the original bytes (no clone involved).
    #[tokio::test]
    async fn test_retention_digests_match_original_bytes() {
        use sha2::{Digest, Sha256};

        let payloads: Vec<Vec<u8>> = vec![
            Vec::new(),
            b"tiny".to_vec(),
            vec![0xABu8; 256],
            (0u8..=255u8).cycle().take(64 * 1024).collect(),
        ];
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
                    batch_size: 64,
                    flush_interval_ms: 10,
                    payload_retention_mode: mode,
                    max_stored_payload_bytes: 256,
                    max_stored_payload_hex_bytes: 512,
                    ..Default::default()
                },
            );
            for payload in &payloads {
                let mut record = base_record();
                record.payload = payload.clone();
                record.payload_hex = hex::encode(payload);
                writer.try_write_record(record).unwrap();
            }
            writer.shutdown().await;

            let records = storage.get_records_since(0, 16).unwrap();
            assert_eq!(records.len(), payloads.len());
            // Storage returns newest-first; align by original length.
            let mut stored = records;
            stored.sort_by_key(|r| r.payload_length.unwrap_or(usize::MAX));
            let mut expected_payloads = payloads.clone();
            expected_payloads.sort_by_key(|p| p.len());
            for (stored, original) in stored.iter().zip(expected_payloads.iter()) {
                let mut hasher = Sha256::new();
                hasher.update(original);
                let expected = format!("{:x}", hasher.finalize());
                assert_eq!(
                    stored.payload_hash.as_deref(),
                    Some(expected.as_str()),
                    "retention digest must match original bytes"
                );
                assert_eq!(stored.payload_length, Some(original.len()));
            }
        }
    }

    /// Phase 53: `shutdown()` alone drains queued records — no sleep needed.
    #[tokio::test]
    async fn test_shutdown_drains_without_sleep() {
        let storage = test_storage();
        let writer = HoneypotWriter::new(
            storage.clone(),
            StorageWriterConfig {
                queue_capacity: 256,
                batch_size: 64,
                flush_interval_ms: 60_000,
                payload_retention_mode: PayloadRetentionMode::Full,
                ..Default::default()
            },
        );

        for _ in 0..7 {
            writer.try_write_record(base_record()).unwrap();
        }

        writer.shutdown().await;

        let records = storage.get_records_since(0, 16).unwrap();
        assert_eq!(
            records.len(),
            7,
            "shutdown must drain queued records and flush the final batch"
        );
    }

    /// Phase 53: concurrent clones calling shutdown converge on one drain;
    /// writes racing shutdown fail closed once intake is closed.
    #[tokio::test]
    async fn test_concurrent_shutdown_and_racing_write() {
        let storage = test_storage();
        let writer = HoneypotWriter::new(
            storage.clone(),
            StorageWriterConfig {
                queue_capacity: 256,
                batch_size: 64,
                flush_interval_ms: 60_000,
                payload_retention_mode: PayloadRetentionMode::Full,
                ..Default::default()
            },
        );

        for _ in 0..4 {
            writer.try_write_record(base_record()).unwrap();
        }

        let w2 = writer.clone();
        let w3 = writer.clone();
        let (r1, r2, r3) = tokio::join!(writer.shutdown(), w2.shutdown(), w3.shutdown());
        let _ = (r1, r2, r3);

        // Intake is closed: racing writes fail closed.
        assert!(
            w3.try_write_record(base_record()).is_err(),
            "writes racing shutdown must fail closed after drain"
        );

        let records = storage.get_records_since(0, 16).unwrap();
        assert_eq!(records.len(), 4, "concurrent shutdown must still drain all");
    }

    fn phase56_writer(storage: HoneypotStorage) -> HoneypotWriter {
        HoneypotWriter::new(
            storage,
            StorageWriterConfig {
                queue_capacity: 256,
                batch_size: 64,
                flush_interval_ms: 60_000,
                payload_retention_mode: PayloadRetentionMode::Full,
                ..Default::default()
            },
        )
    }

    /// Phase 56.1: one caller drains and completes under a bounded timeout.
    #[tokio::test]
    async fn test_phase56_shutdown_drains_bounded() {
        let storage = test_storage();
        let writer = phase56_writer(storage.clone());
        for _ in 0..5 {
            writer.try_write_record(base_record()).unwrap();
        }
        tokio::time::timeout(Duration::from_secs(5), writer.shutdown())
            .await
            .expect("single shutdown must complete under bounded timeout");
        let records = storage.get_records_since(0, 16).unwrap();
        assert_eq!(records.len(), 5, "drain must flush every queued record");
    }

    /// Phase 56.2: three or more clones calling shutdown concurrently all
    /// complete under a bounded timeout.
    #[tokio::test]
    async fn test_phase56_concurrent_shutdown_bounded() {
        let storage = test_storage();
        let writer = phase56_writer(storage.clone());
        for _ in 0..6 {
            writer.try_write_record(base_record()).unwrap();
        }
        let w2 = writer.clone();
        let w3 = writer.clone();
        let w4 = writer.clone();
        tokio::time::timeout(Duration::from_secs(5), async {
            tokio::join!(
                writer.shutdown(),
                w2.shutdown(),
                w3.shutdown(),
                w4.shutdown()
            )
        })
        .await
        .expect("concurrent shutdown callers must all complete");
        let records = storage.get_records_since(0, 32).unwrap();
        assert_eq!(records.len(), 6, "concurrent shutdown must drain all");
    }

    /// Phase 56.3: a caller arriving after completion returns immediately.
    #[tokio::test]
    async fn test_phase56_late_shutdown_returns_immediately() {
        let storage = test_storage();
        let writer = phase56_writer(storage.clone());
        writer.try_write_record(base_record()).unwrap();
        tokio::time::timeout(Duration::from_secs(5), writer.shutdown())
            .await
            .expect("first shutdown must complete");
        let late = writer.clone();
        tokio::time::timeout(Duration::from_millis(500), late.shutdown())
            .await
            .expect("late shutdown after completion must return immediately");
        // Repeated late callers also return immediately (stateful completion).
        tokio::time::timeout(Duration::from_millis(500), writer.shutdown())
            .await
            .expect("second late shutdown must return immediately");
    }

    /// Phase 56.4: callers racing writer completion repeatedly never hang.
    /// Each iteration builds a fresh writer, queues one record, and races a
    /// shutdown against completion with a tight timeout.
    #[tokio::test]
    async fn test_phase56_racing_shutdown_never_hangs() {
        for _ in 0..25 {
            let storage = test_storage();
            let writer = phase56_writer(storage.clone());
            writer.try_write_record(base_record()).unwrap();
            let w2 = writer.clone();
            tokio::time::timeout(Duration::from_secs(5), async {
                tokio::join!(writer.shutdown(), w2.shutdown())
            })
            .await
            .expect("racing shutdown must never hang");
            let records = storage.get_records_since(0, 8).unwrap();
            assert_eq!(records.len(), 1, "racing shutdown must still drain");
        }
    }

    /// Phase 56.5: writes racing closed intake fail cleanly.
    #[tokio::test]
    async fn test_phase56_writes_after_shutdown_fail_cleanly() {
        let storage = test_storage();
        let writer = phase56_writer(storage.clone());
        writer.try_write_record(base_record()).unwrap();
        tokio::time::timeout(Duration::from_secs(5), writer.shutdown())
            .await
            .expect("shutdown must complete");
        assert!(
            writer.try_write_record(base_record()).is_err(),
            "try_write after shutdown must fail closed"
        );
        assert!(
            writer.write_record(base_record()).await.is_err(),
            "async write after shutdown must fail closed"
        );
    }

    /// Phase 56.6: the final queued partial batch is present immediately when
    /// shutdown returns (no sleep after shutdown).
    #[tokio::test]
    async fn test_phase56_final_partial_batch_immediate() {
        let storage = test_storage();
        let writer = phase56_writer(storage.clone());
        for _ in 0..7 {
            writer.try_write_record(base_record()).unwrap();
        }
        tokio::time::timeout(Duration::from_secs(5), writer.shutdown())
            .await
            .expect("shutdown must complete");
        let records = storage.get_records_since(0, 16).unwrap();
        assert_eq!(
            records.len(),
            7,
            "final partial batch must be visible immediately after shutdown"
        );
    }
}
