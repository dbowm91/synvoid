use std::sync::Arc;

use rusqlite::params;
use sha2::{Digest, Sha256};
use tokio::sync::mpsc;

use crate::config::{PayloadRetentionMode, StorageWriterConfig};
use crate::storage::{HoneypotRecord, HoneypotStorage};

pub struct HoneypotWriter {
    tx: mpsc::Sender<HoneypotRecord>,
    storage: Arc<HoneypotStorage>,
    config: StorageWriterConfig,
}

impl Clone for HoneypotWriter {
    fn clone(&self) -> Self {
        Self {
            tx: self.tx.clone(),
            storage: Arc::clone(&self.storage),
            config: self.config.clone(),
        }
    }
}

impl HoneypotWriter {
    pub fn new(storage: HoneypotStorage, config: StorageWriterConfig) -> Self {
        let (tx, rx) = mpsc::channel(config.queue_capacity);
        let storage = Arc::new(storage);
        let writer = Self {
            tx,
            storage: Arc::clone(&storage),
            config: config.clone(),
        };

        let writer_clone = writer.clone();
        tokio::spawn(writer_clone.writer_task(rx));

        writer
    }

    pub fn storage(&self) -> &HoneypotStorage {
        &self.storage
    }

    pub fn config(&self) -> &StorageWriterConfig {
        &self.config
    }

    pub async fn write_record(
        &self,
        mut record: HoneypotRecord,
    ) -> Result<(), mpsc::error::SendError<HoneypotRecord>> {
        Self::apply_retention(&mut record, &self.config);
        self.tx.send(record).await
    }

    #[allow(clippy::result_large_err)]
    pub fn try_write_record(
        &self,
        mut record: HoneypotRecord,
    ) -> Result<(), mpsc::error::TrySendError<HoneypotRecord>> {
        Self::apply_retention(&mut record, &self.config);
        self.tx.try_send(record)
    }

    pub async fn shutdown(&self) {
        drop(self.tx.clone());
    }

    fn apply_retention(record: &mut HoneypotRecord, config: &StorageWriterConfig) {
        let original_payload = record.payload.clone();
        let original_length = original_payload.len();
        record.payload_length = Some(original_length);

        let hash = {
            let mut hasher = Sha256::new();
            hasher.update(&original_payload);
            format!("{:x}", hasher.finalize())
        };

        match config.payload_retention_mode {
            PayloadRetentionMode::None | PayloadRetentionMode::HashOnly => {
                record.payload = Vec::new();
                record.payload_hex = String::new();
                record.payload_hash = Some(hash);
            }
            PayloadRetentionMode::Truncated => {
                if record.payload.len() > config.max_stored_payload_bytes {
                    record.payload.truncate(config.max_stored_payload_bytes);
                }
                if record.payload_hex.len() > config.max_stored_payload_hex_bytes {
                    record
                        .payload_hex
                        .truncate(config.max_stored_payload_hex_bytes);
                }
                record.payload_hash = Some(hash);
            }
            PayloadRetentionMode::Full => {
                record.payload_hash = Some(hash);
            }
        }
    }

    async fn writer_task(self, mut rx: mpsc::Receiver<HoneypotRecord>) {
        let mut batch: Vec<HoneypotRecord> = Vec::with_capacity(self.config.batch_size);
        let mut interval = tokio::time::interval(tokio::time::Duration::from_millis(
            self.config.flush_interval_ms,
        ));

        loop {
            tokio::select! {
                record = rx.recv() => {
                    match record {
                        Some(record) => {
                            batch.push(record);
                            if batch.len() >= self.config.batch_size {
                                Self::flush_records(&self.storage, &mut batch).await;
                            }
                        }
                        None => {
                            if !batch.is_empty() {
                                Self::flush_records(&self.storage, &mut batch).await;
                            }
                            break;
                        }
                    }
                }
                _ = interval.tick() => {
                    if !batch.is_empty() {
                        Self::flush_records(&self.storage, &mut batch).await;
                    }
                }
            }
        }
    }

    async fn flush_records(storage: &HoneypotStorage, batch: &mut Vec<HoneypotRecord>) {
        if batch.is_empty() {
            return;
        }

        let records = std::mem::take(batch);
        let conn = storage.conn();

        match conn.execute_batch("BEGIN TRANSACTION") {
            Ok(()) => {
                let mut success_count = 0;
                for record in &records {
                    let result = conn.execute(
                        "INSERT INTO honeypot_connections 
                         (timestamp, remote_ip, remote_port, local_port, protocol, service, confidence,
                          payload, payload_hex, detected_pattern, bytes_received, bytes_sent, 
                          duration_ms, connection_info, payload_truncated, payload_hash, payload_length)
                         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17)",
                        params![
                            record.timestamp,
                            record.remote_ip,
                            record.remote_port,
                            record.local_port,
                            record.protocol,
                            record.service,
                            record.confidence.to_string(),
                            record.payload,
                            record.payload_hex,
                            record.detected_pattern,
                            record.bytes_received,
                            record.bytes_sent,
                            record.duration_ms,
                            record.connection_info,
                            record.payload_truncated as i32,
                            record.payload_hash,
                            record.payload_length.map(|l| l as i64),
                        ],
                    );
                    match result {
                        Ok(_) => success_count += 1,
                        Err(_) => {
                            metrics::counter!("honeypot_storage_write_errors").increment(1);
                        }
                    }
                }

                if let Err(e) = conn.execute_batch("COMMIT") {
                    tracing::error!("Failed to commit honeypot batch: {}", e);
                    metrics::counter!("honeypot_storage_write_errors").increment(1);
                }

                if success_count > 0 {
                    tracing::debug!("Flushed {} honeypot records", success_count);
                }
            }
            Err(e) => {
                tracing::error!("Failed to begin honeypot batch transaction: {}", e);
                metrics::counter!("honeypot_storage_write_errors").increment(1);
                let _ = conn.execute_batch("ROLLBACK");
            }
        }
    }
}
