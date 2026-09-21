use std::sync::Arc;

use rusqlite::params;
use sha2::{Digest, Sha256};
use tokio::sync::{mpsc, watch, Notify};

use crate::config::{PayloadRetentionMode, StorageWriterConfig};
use crate::storage::{HoneypotRecord, HoneypotStorage};

/// Shared writer-task lifecycle. `shutdown()` signals the task, closes intake
/// so queued records still drain, and waits for the final flush to complete.
///
/// Completion is stateful (`watch<bool>`): the writer publishes `true` once
/// after the final drain/flush, and every shutdown caller observes that
/// durable state. This is immune to the check-to-wait lost-wakeup race of an
/// edge-triggered `Notify`, because a late subscriber reads `true`
/// immediately instead of waiting for a notification edge that already fired.
struct WriterLifecycle {
    shutdown_notify: Notify,
    done_tx: watch::Sender<bool>,
}

pub struct HoneypotWriter {
    tx: mpsc::Sender<HoneypotRecord>,
    storage: Arc<HoneypotStorage>,
    config: StorageWriterConfig,
    lifecycle: Arc<WriterLifecycle>,
}

impl Clone for HoneypotWriter {
    fn clone(&self) -> Self {
        Self {
            tx: self.tx.clone(),
            storage: Arc::clone(&self.storage),
            config: self.config.clone(),
            lifecycle: Arc::clone(&self.lifecycle),
        }
    }
}

impl HoneypotWriter {
    pub fn new(storage: HoneypotStorage, config: StorageWriterConfig) -> Self {
        let (tx, rx) = mpsc::channel(config.queue_capacity);
        let storage = Arc::new(storage);
        let (done_tx, _initial_rx) = watch::channel(false);
        let writer = Self {
            tx,
            storage: Arc::clone(&storage),
            config: config.clone(),
            lifecycle: Arc::new(WriterLifecycle {
                shutdown_notify: Notify::new(),
                done_tx,
            }),
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

    #[allow(clippy::result_large_err)]
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

    /// Drain contract: signal the writer to stop accepting new work, close
    /// intake so already-queued records still drain, flush the final partial
    /// batch, and wait for the writer task to exit. Idempotent across clones:
    /// concurrent callers all wait for the same completion. Writes racing
    /// shutdown fail closed with a send error once intake is closed.
    ///
    /// Phase 56: completion waits on a stateful `watch` channel. A caller
    /// arriving after the writer already published completion returns
    /// immediately; a caller racing completion cannot miss the wakeup because
    /// the completed state is durable, not an edge.
    pub async fn shutdown(&self) {
        self.lifecycle.shutdown_notify.notify_one();
        let mut done_rx = self.lifecycle.done_tx.subscribe();
        if *done_rx.borrow() {
            return;
        }
        // `wait_for` resolves immediately if the writer completes between the
        // borrow above and waiter registration. If the writer task is gone
        // without publishing (sender closed), return rather than hang.
        let _ = done_rx.wait_for(|done| *done).await;
    }

    fn apply_retention(record: &mut HoneypotRecord, config: &StorageWriterConfig) {
        // Phase 53: hash the payload in place. The previous implementation
        // cloned the complete payload before hashing; the SHA-256 digest and
        // retention outputs are unchanged.
        let original_length = record.payload.len();
        record.payload_length = Some(original_length);

        let hash = {
            let mut hasher = Sha256::new();
            hasher.update(&record.payload);
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
                _ = self.lifecycle.shutdown_notify.notified() => {
                    // Stop intake (racing sends fail closed) while buffered
                    // records still drain through the normal `recv` path to
                    // `None`, which flushes the final partial batch below.
                    rx.close();
                }
            }
        }

        let _ = self.lifecycle.done_tx.send(true);
    }

    /// Batch flush isolated from Tokio core workers: at most one
    /// `spawn_blocking` flush is in flight per writer because the single
    /// writer task awaits it before accepting the next flush. Queue/batch
    /// backpressure, insertion/error metrics, and transaction semantics are
    /// unchanged.
    async fn flush_records(storage: &HoneypotStorage, batch: &mut Vec<HoneypotRecord>) {
        if batch.is_empty() {
            return;
        }

        let records = std::mem::take(batch);
        let storage = storage.clone();
        match tokio::task::spawn_blocking(move || Self::flush_records_blocking(&storage, records))
            .await
        {
            Ok(()) => {}
            Err(join_err) => {
                tracing::error!("Honeypot batch flush task failed: {}", join_err);
                metrics::counter!("honeypot_storage_write_errors").increment(1);
            }
        }
    }

    /// Single INSERT statement parsed once per batch (`prepare_cached`) and
    /// executed inside one transaction. Column ordering, confidence
    /// formatting, optional payload hash/length representation, error-counter
    /// behavior, and commit/rollback semantics match the previous
    /// per-record `execute` implementation.
    fn flush_records_blocking(storage: &HoneypotStorage, records: Vec<HoneypotRecord>) {
        if records.is_empty() {
            return;
        }

        const INSERT_SQL: &str = "INSERT INTO honeypot_connections
             (timestamp, remote_ip, remote_port, local_port, protocol, service, confidence,
              payload, payload_hex, detected_pattern, bytes_received, bytes_sent,
              duration_ms, connection_info, payload_truncated, payload_hash, payload_length)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17)";

        let conn = storage.conn();

        if let Err(e) = conn.execute_batch("BEGIN TRANSACTION") {
            tracing::error!("Failed to begin honeypot batch transaction: {}", e);
            metrics::counter!("honeypot_storage_write_errors").increment(1);
            let _ = conn.execute_batch("ROLLBACK");
            return;
        }

        let mut statement = match conn.prepare_cached(INSERT_SQL) {
            Ok(statement) => statement,
            Err(e) => {
                tracing::error!("Failed to prepare honeypot batch statement: {}", e);
                metrics::counter!("honeypot_storage_write_errors").increment(1);
                let _ = conn.execute_batch("ROLLBACK");
                return;
            }
        };

        let mut success_count = 0;
        for record in &records {
            let result = statement.execute(params![
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
            ]);
            match result {
                Ok(_) => success_count += 1,
                Err(_) => {
                    metrics::counter!("honeypot_storage_write_errors").increment(1);
                }
            }
        }
        drop(statement);

        if let Err(e) = conn.execute_batch("COMMIT") {
            tracing::error!("Failed to commit honeypot batch: {}", e);
            metrics::counter!("honeypot_storage_write_errors").increment(1);
        }

        if success_count > 0 {
            tracing::debug!("Flushed {} honeypot records", success_count);
        }
    }
}
