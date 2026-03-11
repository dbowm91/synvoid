use parking_lot::Mutex;
use rusqlite::{params, Connection, OptionalExtension};
use std::path::Path;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use super::config::StorageConfig;

#[derive(Debug, Clone)]
pub struct HoneypotRecord {
    pub id: i64,
    pub timestamp: i64,
    pub remote_ip: String,
    pub remote_port: u16,
    pub local_port: u16,
    pub protocol: String,
    pub service: String,
    pub payload: Vec<u8>,
    pub payload_hex: String,
    pub detected_pattern: Option<String>,
    pub bytes_received: u32,
    pub bytes_sent: u32,
    pub duration_ms: u32,
    pub connection_info: String,
}

pub struct HoneypotStorage {
    conn: Arc<Mutex<Connection>>,
    config: StorageConfig,
}

impl Clone for HoneypotStorage {
    fn clone(&self) -> Self {
        Self {
            conn: self.conn.clone(),
            config: self.config.clone(),
        }
    }
}

impl HoneypotStorage {
    pub fn new(config: &StorageConfig) -> Result<Self, rusqlite::Error> {
        let db_path = Path::new(&config.database_path);

        if let Some(parent) = db_path.parent() {
            std::fs::create_dir_all(parent).ok();
        }

        let conn = Connection::open(db_path)?;

        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA synchronous = NORMAL;
             PRAGMA cache_size = -64000;
             PRAGMA temp_store = MEMORY;
             PRAGMA mmap_size = 268435456;",
        )?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS honeypot_connections (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp INTEGER NOT NULL,
                remote_ip TEXT NOT NULL,
                remote_port INTEGER NOT NULL,
                local_port INTEGER NOT NULL,
                protocol TEXT NOT NULL,
                service TEXT NOT NULL,
                payload BLOB,
                payload_hex TEXT,
                detected_pattern TEXT,
                bytes_received INTEGER NOT NULL DEFAULT 0,
                bytes_sent INTEGER NOT NULL DEFAULT 0,
                duration_ms INTEGER NOT NULL DEFAULT 0,
                connection_info TEXT
            )",
            [],
        )?;

        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_honeypot_timestamp ON honeypot_connections(timestamp)",
            [],
        )?;

        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_honeypot_remote_ip ON honeypot_connections(remote_ip)",
            [],
        )?;

        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_honeypot_service ON honeypot_connections(service)",
            [],
        )?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS honeypot_metadata (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                updated_at INTEGER NOT NULL
            )",
            [],
        )?;

        let storage = Self {
            conn: Arc::new(Mutex::new(conn)),
            config: config.clone(),
        };

        Ok(storage)
    }

    pub fn record_connection(&self, record: HoneypotRecord) -> Result<i64, rusqlite::Error> {
        let conn = self.conn.lock();

        conn.execute(
            "INSERT INTO honeypot_connections 
             (timestamp, remote_ip, remote_port, local_port, protocol, service, 
              payload, payload_hex, detected_pattern, bytes_received, bytes_sent, 
              duration_ms, connection_info)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
            params![
                record.timestamp,
                record.remote_ip,
                record.remote_port,
                record.local_port,
                record.protocol,
                record.service,
                record.payload,
                record.payload_hex,
                record.detected_pattern,
                record.bytes_received,
                record.bytes_sent,
                record.duration_ms,
                record.connection_info,
            ],
        )?;

        Ok(conn.last_insert_rowid())
    }

    pub fn prune_old_records(&self) -> Result<usize, rusqlite::Error> {
        let conn = self.conn.lock();

        let cutoff = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
            - (self.config.retention_days as i64 * 86400);

        let deleted = conn.execute(
            "DELETE FROM honeypot_connections WHERE timestamp < ?1",
            params![cutoff],
        )?;

        tracing::info!("Pruned {} old honeypot connection records", deleted);

        Ok(deleted)
    }

    pub fn enforce_max_records(&self) -> Result<usize, rusqlite::Error> {
        let conn = self.conn.lock();

        let count: i64 =
            conn.query_row("SELECT COUNT(*) FROM honeypot_connections", [], |row| {
                row.get(0)
            })?;

        if count as u64 > self.config.max_records {
            let to_delete = count as u64 - self.config.max_records;

            conn.execute(
                "DELETE FROM honeypot_connections WHERE id IN 
                 (SELECT id FROM honeypot_connections ORDER BY timestamp ASC LIMIT ?1)",
                params![to_delete as i64],
            )?;

            tracing::info!(
                "Enforced max records limit, deleted {} oldest records",
                to_delete
            );
            return Ok(to_delete as usize);
        }

        Ok(0)
    }

    pub fn get_connection_count(&self) -> Result<i64, rusqlite::Error> {
        let conn = self.conn.lock();

        conn.query_row("SELECT COUNT(*) FROM honeypot_connections", [], |row| {
            row.get(0)
        })
    }

    pub fn get_records_since(
        &self,
        since_timestamp: i64,
        limit: usize,
    ) -> Result<Vec<HoneypotRecord>, rusqlite::Error> {
        let conn = self.conn.lock();

        let mut stmt = conn.prepare(
            "SELECT id, timestamp, remote_ip, remote_port, local_port, protocol, service,
                    payload, payload_hex, detected_pattern, bytes_received, bytes_sent,
                    duration_ms, connection_info
             FROM honeypot_connections 
             WHERE timestamp > ?1
             ORDER BY timestamp DESC
             LIMIT ?2",
        )?;

        let records = stmt.query_map(params![since_timestamp, limit as i64], |row| {
            Ok(HoneypotRecord {
                id: row.get(0)?,
                timestamp: row.get(1)?,
                remote_ip: row.get(2)?,
                remote_port: row.get(3)?,
                local_port: row.get(4)?,
                protocol: row.get(5)?,
                service: row.get(6)?,
                payload: row.get(7).unwrap_or_default(),
                payload_hex: row.get(8).unwrap_or_default(),
                detected_pattern: row.get(9)?,
                bytes_received: row.get(10)?,
                bytes_sent: row.get(11)?,
                duration_ms: row.get(12)?,
                connection_info: row.get(13).unwrap_or_default(),
            })
        })?;

        records.collect()
    }

    pub fn get_unique_ips(&self, since_timestamp: i64) -> Result<Vec<String>, rusqlite::Error> {
        let conn = self.conn.lock();

        let mut stmt = conn
            .prepare("SELECT DISTINCT remote_ip FROM honeypot_connections WHERE timestamp > ?1")?;

        let ips = stmt.query_map(params![since_timestamp], |row| row.get(0))?;

        ips.collect()
    }

    pub fn get_service_counts(
        &self,
        since_timestamp: i64,
    ) -> Result<Vec<(String, i64)>, rusqlite::Error> {
        let conn = self.conn.lock();

        let mut stmt = conn.prepare(
            "SELECT service, COUNT(*) as cnt 
             FROM honeypot_connections 
             WHERE timestamp > ?1
             GROUP BY service
             ORDER BY cnt DESC",
        )?;

        let counts = stmt.query_map(params![since_timestamp], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
        })?;

        counts.collect()
    }

    pub fn set_metadata(&self, key: &str, value: &str) -> Result<(), rusqlite::Error> {
        let conn = self.conn.lock();

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        conn.execute(
            "INSERT OR REPLACE INTO honeypot_metadata (key, value, updated_at) VALUES (?1, ?2, ?3)",
            params![key, value, now],
        )?;

        Ok(())
    }

    pub fn get_metadata(&self, key: &str) -> Result<Option<String>, rusqlite::Error> {
        let conn = self.conn.lock();

        conn.query_row(
            "SELECT value FROM honeypot_metadata WHERE key = ?1",
            params![key],
            |row| row.get(0),
        )
        .optional()
    }
}
