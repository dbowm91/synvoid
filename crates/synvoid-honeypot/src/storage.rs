use parking_lot::Mutex;
use rusqlite::{params, Connection, OpenFlags, OptionalExtension};
use std::path::Path;
use std::sync::Arc;

const STORAGE_SCHEMA_VERSION: i32 = 1;

use super::config::StorageConfig;
use super::protocol::Confidence;

#[derive(Debug, Clone)]
pub struct HoneypotRecord {
    pub id: i64,
    pub timestamp: i64,
    pub remote_ip: String,
    pub remote_port: u16,
    pub local_port: u16,
    pub protocol: String,
    pub service: String,
    pub confidence: Confidence,
    pub payload: Vec<u8>,
    pub payload_hex: String,
    pub detected_pattern: Option<String>,
    pub bytes_received: u32,
    pub bytes_sent: u32,
    pub duration_ms: u32,
    pub connection_info: String,
    pub payload_truncated: bool,
    pub payload_hash: Option<String>,
    pub payload_length: Option<usize>,
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
    pub fn conn(&self) -> parking_lot::MutexGuard<'_, Connection> {
        self.conn.lock()
    }

    pub fn new(config: &StorageConfig) -> Result<Self, rusqlite::Error> {
        let db_path = Path::new(&config.database_path);
        prepare_storage_path(db_path)?;
        let mut conn = Connection::open_with_flags(
            db_path,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_CREATE
                | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )?;
        harden_storage_file(db_path)?;

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
                confidence TEXT NOT NULL DEFAULT 'low',
                payload BLOB,
                payload_hex TEXT,
                detected_pattern TEXT,
                bytes_received INTEGER NOT NULL DEFAULT 0,
                bytes_sent INTEGER NOT NULL DEFAULT 0,
                duration_ms INTEGER NOT NULL DEFAULT 0,
                connection_info TEXT,
                payload_truncated INTEGER NOT NULL DEFAULT 0
            )",
            [],
        )?;

        // Migration: add confidence column if missing (existing databases)
        migrate_schema(&mut conn)?;

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

        conn.execute(
            "CREATE TABLE IF NOT EXISTS honeypot_announced_indicators (
                indicator_key TEXT PRIMARY KEY,
                announced_at INTEGER NOT NULL
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
        )?;

        Ok(conn.last_insert_rowid())
    }

    pub fn prune_old_records(&self) -> Result<usize, rusqlite::Error> {
        let conn = self.conn.lock();

        let cutoff =
            crate::time::unix_timestamp_secs() as i64 - (self.config.retention_days as i64 * 86400);

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
                    confidence, payload, payload_hex, detected_pattern, bytes_received, bytes_sent,
                    duration_ms, connection_info, payload_truncated, payload_hash, payload_length
             FROM honeypot_connections 
             WHERE timestamp > ?1
             ORDER BY timestamp DESC
             LIMIT ?2",
        )?;

        let records = stmt.query_map(params![since_timestamp, limit as i64], |row| {
            let conf_str: String = row.get(7).unwrap_or_else(|_| "low".to_string());
            let confidence = match conf_str.as_str() {
                "high" => Confidence::High,
                "medium" => Confidence::Medium,
                _ => Confidence::Low,
            };
            Ok(HoneypotRecord {
                id: row.get(0)?,
                timestamp: row.get(1)?,
                remote_ip: row.get(2)?,
                remote_port: row.get(3)?,
                local_port: row.get(4)?,
                protocol: row.get(5)?,
                service: row.get(6)?,
                confidence,
                payload: row.get(8).unwrap_or_default(),
                payload_hex: row.get(9).unwrap_or_default(),
                detected_pattern: row.get(10)?,
                bytes_received: row.get(11)?,
                bytes_sent: row.get(12)?,
                duration_ms: row.get(13)?,
                connection_info: row.get(14).unwrap_or_default(),
                payload_truncated: row.get::<_, i32>(15).unwrap_or(0) != 0,
                payload_hash: row.get(16).ok(),
                payload_length: row.get::<_, i64>(17).ok().map(|l| l as usize),
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

        let now = crate::time::unix_timestamp_secs() as i64;

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

    pub fn get_announced_indicator_keys(
        &self,
    ) -> Result<std::collections::HashSet<String>, rusqlite::Error> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare("SELECT indicator_key FROM honeypot_announced_indicators")?;
        let keys = stmt
            .query_map([], |row| row.get(0))?
            .filter_map(|r| r.ok())
            .collect();
        Ok(keys)
    }

    pub fn mark_indicator_announced(&self, key: &str) -> Result<(), rusqlite::Error> {
        let conn = self.conn.lock();
        let now = crate::time::unix_timestamp_secs() as i64;
        conn.execute(
            "INSERT OR IGNORE INTO honeypot_announced_indicators (indicator_key, announced_at) VALUES (?1, ?2)",
            params![key, now],
        )?;
        Ok(())
    }
}

fn storage_io_error(error: std::io::Error) -> rusqlite::Error {
    rusqlite::Error::ToSqlConversionFailure(Box::new(error))
}

fn prepare_storage_path(path: &Path) -> Result<(), rusqlite::Error> {
    if path == Path::new(":memory:") {
        return Ok(());
    }
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        #[cfg(unix)]
        let parent_existed = parent.exists();
        std::fs::create_dir_all(parent).map_err(storage_io_error)?;
        #[cfg(unix)]
        if !parent_existed {
            use std::os::unix::fs::PermissionsExt;
            let mut permissions = std::fs::metadata(parent)
                .map_err(storage_io_error)?
                .permissions();
            permissions.set_mode(0o700);
            std::fs::set_permissions(parent, permissions).map_err(storage_io_error)?;
        }
    }
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            Err(storage_io_error(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "honeypot database path is a symlink",
            )))
        }
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(storage_io_error(error)),
    }
}

fn harden_storage_file(path: &Path) -> Result<(), rusqlite::Error> {
    if path == Path::new(":memory:") {
        return Ok(());
    }
    let metadata = std::fs::symlink_metadata(path).map_err(storage_io_error)?;
    if metadata.file_type().is_symlink() {
        return Err(storage_io_error(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "honeypot database path became a symlink",
        )));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut permissions = metadata.permissions();
        permissions.set_mode(0o600);
        std::fs::set_permissions(path, permissions).map_err(storage_io_error)?;
    }
    Ok(())
}

fn migrate_schema(conn: &mut Connection) -> Result<(), rusqlite::Error> {
    let version: i32 = conn.pragma_query_value(None, "user_version", |row| row.get(0))?;
    if version > STORAGE_SCHEMA_VERSION {
        return Err(rusqlite::Error::SqliteFailure(
            rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_MISMATCH),
            Some(format!("database schema version {version} is newer than supported {STORAGE_SCHEMA_VERSION}")),
        ));
    }
    let tx = conn.transaction()?;
    ensure_column(&tx, "confidence", "confidence TEXT NOT NULL DEFAULT 'low'")?;
    ensure_column(&tx, "payload_hash", "payload_hash TEXT")?;
    ensure_column(
        &tx,
        "payload_length",
        "payload_length INTEGER NOT NULL DEFAULT 0",
    )?;
    tx.pragma_update(None, "user_version", STORAGE_SCHEMA_VERSION)?;
    tx.commit()
}

fn ensure_column(conn: &Connection, name: &str, definition: &str) -> Result<(), rusqlite::Error> {
    let mut statement = conn.prepare("PRAGMA table_info(honeypot_connections)")?;
    let columns = statement
        .query_map([], |row| row.get::<_, String>(1))?
        .collect::<Result<Vec<_>, _>>()?;
    if !columns.iter().any(|column| column == name) {
        conn.execute_batch(&format!(
            "ALTER TABLE honeypot_connections ADD COLUMN {definition}"
        ))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::StorageConfig;
    use tempfile::tempdir;

    #[test]
    fn creates_versioned_schema_and_nested_private_database_path() {
        let tmp = tempdir().unwrap();
        let path = tmp.path().join("private").join("honeypot.db");
        let config = StorageConfig {
            database_path: path.to_string_lossy().into_owned(),
            ..StorageConfig::default()
        };
        let storage = HoneypotStorage::new(&config).unwrap();
        let conn = storage.conn();
        let version: i32 = conn
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .unwrap();
        assert_eq!(version, STORAGE_SCHEMA_VERSION);
        let columns = conn
            .prepare("PRAGMA table_info(honeypot_connections)")
            .unwrap()
            .query_map([], |row| row.get::<_, String>(1))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        for expected in ["confidence", "payload_hash", "payload_length"] {
            assert!(columns.iter().any(|column| column == expected));
        }
        drop(conn);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
            assert_eq!(
                std::fs::metadata(path.parent().unwrap())
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o700
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn refuses_database_symlinks() {
        use std::os::unix::fs::symlink;
        let tmp = tempdir().unwrap();
        let target = tmp.path().join("target.db");
        Connection::open(&target).unwrap();
        let link = tmp.path().join("link.db");
        symlink(&target, &link).unwrap();
        let config = StorageConfig {
            database_path: link.to_string_lossy().into_owned(),
            ..StorageConfig::default()
        };
        assert!(HoneypotStorage::new(&config).is_err());
    }

    #[test]
    fn invalid_parent_path_fails_closed() {
        let tmp = tempdir().unwrap();
        let blocker = tmp.path().join("not-a-directory");
        std::fs::write(&blocker, b"x").unwrap();
        let path = blocker.join("honeypot.db");
        let config = StorageConfig {
            database_path: path.to_string_lossy().into_owned(),
            ..StorageConfig::default()
        };
        assert!(HoneypotStorage::new(&config).is_err());
    }

    #[test]
    fn rejects_database_schema_from_a_newer_version() {
        let tmp = tempdir().unwrap();
        let path = tmp.path().join("future.db");
        let conn = Connection::open(&path).unwrap();
        conn.pragma_update(None, "user_version", STORAGE_SCHEMA_VERSION + 1)
            .unwrap();
        drop(conn);
        let config = StorageConfig {
            database_path: path.to_string_lossy().into_owned(),
            ..StorageConfig::default()
        };
        assert!(HoneypotStorage::new(&config).is_err());
    }

    #[test]
    fn upgrades_legacy_schema_transactionally_and_records_user_version() {
        let tmp = tempdir().unwrap();
        let path = tmp.path().join("legacy.db");
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch(
            "CREATE TABLE honeypot_connections (
            id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp INTEGER NOT NULL,
            remote_ip TEXT NOT NULL, remote_port INTEGER NOT NULL, local_port INTEGER NOT NULL,
            protocol TEXT NOT NULL, service TEXT NOT NULL, payload BLOB, payload_hex TEXT,
            detected_pattern TEXT, bytes_received INTEGER NOT NULL DEFAULT 0,
            bytes_sent INTEGER NOT NULL DEFAULT 0, duration_ms INTEGER NOT NULL DEFAULT 0,
            connection_info TEXT, payload_truncated INTEGER NOT NULL DEFAULT 0);",
        )
        .unwrap();
        drop(conn);
        let config = StorageConfig {
            database_path: path.to_string_lossy().into_owned(),
            ..StorageConfig::default()
        };
        let storage = HoneypotStorage::new(&config).unwrap();
        let conn = storage.conn();
        let version: i32 = conn
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .unwrap();
        assert_eq!(version, STORAGE_SCHEMA_VERSION);
        let columns = conn
            .prepare("PRAGMA table_info(honeypot_connections)")
            .unwrap()
            .query_map([], |row| row.get::<_, String>(1))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert!(columns.iter().any(|column| column == "confidence"));
        assert!(columns.iter().any(|column| column == "payload_hash"));
        assert!(columns.iter().any(|column| column == "payload_length"));
    }
}
