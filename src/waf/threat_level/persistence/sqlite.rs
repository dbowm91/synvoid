use crate::waf::threat_level::baseline::BaselineStats;
use crate::waf::threat_level::persistence::{ThreatHistoryAll, ThreatHistorySample};
use parking_lot::{Mutex, RwLock};
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const CURRENT_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistedBaseline {
    pub version: u32,
    pub site_id: Option<String>,
    pub computed_at: i64,
    pub learning_duration_secs: u32,
    pub statistics: Vec<BaselineStats>,
}

pub struct SqlitePersistence {
    conn: Arc<Mutex<Connection>>,
}

impl SqlitePersistence {
    pub fn new(data_dir: Option<PathBuf>, site_id: Option<String>) -> std::io::Result<Self> {
        let db_path = if let Some(dir) = data_dir {
            let base = dir.join("threat_level");
            if let Some(parent) = base.parent() {
                std::fs::create_dir_all(parent)?;
            }
            base.join("history.db")
        } else {
            PathBuf::from("/var/lib/maluwaf/threat_level/history.db")
        };

        let conn = Connection::open(&db_path).map_err(|e| {
            std::io::Error::other(
                format!("Failed to open database: {}", e),
            )
        })?;
        conn.execute_batch(
            "PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL; PRAGMA cache_size=1000;",
        )
        .map_err(|e| {
            std::io::Error::other(
                format!("Failed to set PRAGMA: {}", e),
            )
        })?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS threat_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                site_id TEXT NOT NULL,
                timestamp INTEGER NOT NULL,
                level INTEGER NOT NULL,
                score REAL NOT NULL,
                requests_per_second INTEGER NOT NULL,
                requests_per_minute INTEGER NOT NULL,
                attacks_per_minute INTEGER NOT NULL,
                rate_limit_hits INTEGER NOT NULL,
                blocked INTEGER NOT NULL,
                created_at INTEGER NOT NULL
            )",
            [],
        )
        .map_err(|e| {
            std::io::Error::other(
                format!("Failed to create table: {}", e),
            )
        })?;

        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_threat_history_site_time 
             ON threat_history(site_id, timestamp)",
            [],
        )
        .map_err(|e| {
            std::io::Error::other(
                format!("Failed to create index: {}", e),
            )
        })?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS sites (
                site_id TEXT PRIMARY KEY,
                created_at INTEGER NOT NULL,
                last_sample_at INTEGER NOT NULL
            )",
            [],
        )
        .map_err(|e| {
            std::io::Error::other(
                format!("Failed to create sites table: {}", e),
            )
        })?;

        if let Some(sid) = site_id {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64;
            conn.execute(
                "INSERT OR IGNORE INTO sites (site_id, created_at, last_sample_at) VALUES (?1, ?2, ?2)",
                params![sid, now],
            ).map_err(|e| {
                std::io::Error::other(format!("Failed to insert site: {}", e))
            })?;
        }

        tracing::info!("SQLite persistence initialized at {:?}", db_path);

        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    pub fn save(
        &self,
        baselines: &[BaselineStats],
        learning_duration_secs: u32,
        site_id: Option<&str>,
    ) -> std::io::Result<()> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        let persisted = PersistedBaseline {
            version: CURRENT_VERSION,
            site_id: site_id.map(String::from),
            computed_at: now,
            learning_duration_secs,
            statistics: baselines.to_vec(),
        };

        let json = serde_json::to_string_pretty(&persisted).map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("JSON serialization failed: {}", e),
            )
        })?;

        let table = if site_id.is_some() {
            "baselines"
        } else {
            "baselines_global"
        };

        let conn = self.conn.lock();

        conn.execute(
            &format!(
                "CREATE TABLE IF NOT EXISTS {} (
                id INTEGER PRIMARY KEY,
                data TEXT NOT NULL,
                computed_at INTEGER NOT NULL
            )",
                table
            ),
            [],
        )
        .map_err(|e| {
            std::io::Error::other(
                format!("Failed to create table: {}", e),
            )
        })?;

        conn.execute(
            &format!(
                "INSERT OR REPLACE INTO {} (id, data, computed_at) VALUES (1, ?1, ?2)",
                table
            ),
            params![json, now],
        )
        .map_err(|e| {
            std::io::Error::other(
                format!("Failed to insert baseline: {}", e),
            )
        })?;

        tracing::info!("Saved baseline to SQLite with {} metrics", baselines.len());
        Ok(())
    }

    pub fn load(&self, site_id: Option<&str>) -> std::io::Result<Option<Vec<BaselineStats>>> {
        let query = if site_id.is_some() {
            "SELECT data FROM baselines WHERE id = 1"
        } else {
            "SELECT data FROM baselines_global WHERE id = 1"
        };

        let conn = self.conn.lock();

        let result: Option<String> = conn
            .query_row(query, [], |row| row.get(0))
            .optional()
            .map_err(|e| {
                std::io::Error::other(
                    format!("Failed to query baseline: {}", e),
                )
            })?;

        if let Some(json) = result {
            let persisted: PersistedBaseline = serde_json::from_str(&json).map_err(|e| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("JSON parse failed: {}", e),
                )
            })?;

            tracing::info!(
                "Loaded baseline from SQLite with {} metrics",
                persisted.statistics.len()
            );
            Ok(Some(persisted.statistics))
        } else {
            Ok(None)
        }
    }

    pub fn exists(&self, site_id: Option<&str>) -> bool {
        let query = if site_id.is_some() {
            "SELECT 1 FROM baselines WHERE id = 1"
        } else {
            "SELECT 1 FROM baselines_global WHERE id = 1"
        };
        let conn = self.conn.lock();
        conn.query_row(query, [], |_| Ok(())).is_ok()
    }

    pub fn get_connection(&self) -> Arc<Mutex<Connection>> {
        self.conn.clone()
    }
}

#[derive(Clone)]
pub struct SqliteHistory {
    conn: Arc<Mutex<Connection>>,
    buffer: Arc<RwLock<Vec<ThreatHistorySample>>>,
    flush_interval: Duration,
    last_flush: Arc<RwLock<Instant>>,
    site_id: String,
    buffer_size: Arc<AtomicUsize>,
}

impl SqliteHistory {
    pub fn new(
        data_dir: Option<PathBuf>,
        site_id: String,
        flush_interval_secs: u32,
    ) -> std::io::Result<Arc<Self>> {
        let db_path = if let Some(dir) = data_dir {
            let base = dir.join("threat_level");
            std::fs::create_dir_all(&base)?;
            base.join("history.db")
        } else {
            PathBuf::from("/var/lib/maluwaf/threat_level/history.db")
        };

        let conn = Connection::open(&db_path).map_err(|e| {
            std::io::Error::other(
                format!("Failed to open database: {}", e),
            )
        })?;
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;")
            .map_err(|e| {
                std::io::Error::other(
                    format!("Failed to set PRAGMA: {}", e),
                )
            })?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS threat_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                site_id TEXT NOT NULL,
                timestamp INTEGER NOT NULL,
                level INTEGER NOT NULL,
                score REAL NOT NULL,
                requests_per_second INTEGER NOT NULL,
                requests_per_minute INTEGER NOT NULL,
                attacks_per_minute INTEGER NOT NULL,
                rate_limit_hits INTEGER NOT NULL,
                blocked INTEGER NOT NULL,
                created_at INTEGER NOT NULL
            )",
            [],
        )
        .map_err(|e| {
            std::io::Error::other(
                format!("Failed to create table: {}", e),
            )
        })?;

        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_threat_history_site_time 
             ON threat_history(site_id, timestamp)",
            [],
        )
        .map_err(|e| {
            std::io::Error::other(
                format!("Failed to create index: {}", e),
            )
        })?;

        let flush_interval = Duration::from_secs(flush_interval_secs as u64);

        let history = Arc::new(Self {
            conn: Arc::new(Mutex::new(conn)),
            buffer: Arc::new(RwLock::new(Vec::with_capacity(120))),
            flush_interval,
            last_flush: Arc::new(RwLock::new(Instant::now())),
            site_id,
            buffer_size: Arc::new(AtomicUsize::new(0)),
        });

        tracing::info!(
            "SQLite history initialized with {}s flush interval",
            flush_interval_secs
        );

        Ok(history)
    }

    pub fn add_sample(&self, sample: ThreatHistorySample) {
        if sample.requests_per_minute == 0
            && sample.attacks_per_minute == 0
            && sample.blocked == 0
            && sample.rate_limit_hits == 0
        {
            return;
        }

        let now = Instant::now();
        let should_flush = {
            let last_flush = *self.last_flush.read();
            now.duration_since(last_flush) >= self.flush_interval
        };

        {
            let mut buffer = self.buffer.write();
            buffer.push(sample);

            let new_size = buffer.len();
            self.buffer_size.store(new_size, Ordering::Relaxed);
        }

        if should_flush {
            self.flush();
        }
    }

    pub fn flush(&self) {
        let samples = {
            let mut buffer = self.buffer.write();
            if buffer.is_empty() {
                return;
            }
            std::mem::take(&mut *buffer)
        };

        let count = samples.len();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        {
            let conn = self.conn.lock();
            for sample in &samples {
                if let Err(e) = conn.execute(
                    "INSERT INTO threat_history 
                     (site_id, timestamp, level, score, requests_per_second, 
                      requests_per_minute, attacks_per_minute, rate_limit_hits, 
                      blocked, created_at)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                    params![
                        self.site_id,
                        sample.timestamp,
                        sample.level,
                        sample.score,
                        sample.requests_per_second,
                        sample.requests_per_minute,
                        sample.attacks_per_minute,
                        sample.rate_limit_hits,
                        sample.blocked,
                        now
                    ],
                ) {
                    tracing::error!("Failed to execute insert: {}", e);
                }
            }
        }

        *self.last_flush.write() = Instant::now();
        tracing::debug!("Flushed {} history samples to SQLite", count);
    }

    pub fn get_minute_history(&self, limit: usize) -> Vec<ThreatHistorySample> {
        self.flush();

        let conn = self.conn.lock();

        let mut stmt = match conn.prepare(
            "SELECT timestamp, level, score, requests_per_second, requests_per_minute,
                    attacks_per_minute, rate_limit_hits, blocked
             FROM threat_history
             WHERE site_id = ?1
             ORDER BY timestamp DESC
             LIMIT ?2",
        ) {
            Ok(stmt) => stmt,
            Err(e) => {
                tracing::error!("Failed to prepare statement: {}", e);
                return Vec::new();
            }
        };

        let rows = stmt.query_map(params![self.site_id, limit as i64], |row| {
            Ok(ThreatHistorySample {
                timestamp: row.get(0)?,
                level: row.get(1)?,
                score: row.get(2)?,
                requests_per_second: row.get(3)?,
                requests_per_minute: row.get(4)?,
                attacks_per_minute: row.get(5)?,
                rate_limit_hits: row.get(6)?,
                blocked: row.get(7)?,
            })
        });

        match rows {
            Ok(rows) => rows.filter_map(|r| r.ok()).collect(),
            Err(e) => {
                tracing::error!("Failed to query history: {}", e);
                Vec::new()
            }
        }
    }

    pub fn get_hour_history(&self, limit: usize) -> Vec<ThreatHistorySample> {
        self.flush();

        let conn = self.conn.lock();

        let mut stmt = match conn.prepare(
            "SELECT MAX(timestamp), MAX(level), MAX(score),
                    AVG(requests_per_second), AVG(requests_per_minute),
                    AVG(attacks_per_minute), AVG(rate_limit_hits), AVG(blocked)
             FROM (
                 SELECT timestamp / 3600 as bucket, 
                        MAX(timestamp) as timestamp, MAX(level) as level, 
                        MAX(score) as score, AVG(requests_per_second) as requests_per_second,
                        AVG(requests_per_minute) as requests_per_minute,
                        AVG(attacks_per_minute) as attacks_per_minute,
                        AVG(rate_limit_hits) as rate_limit_hits,
                        AVG(blocked) as blocked
                 FROM threat_history
                 WHERE site_id = ?1
                 GROUP BY bucket
                 ORDER BY bucket DESC
                 LIMIT ?2
             )",
        ) {
            Ok(stmt) => stmt,
            Err(e) => {
                tracing::error!("Failed to prepare statement: {}", e);
                return Vec::new();
            }
        };

        let rows = stmt.query_map(params![self.site_id, limit as i64], |row| {
            Ok(ThreatHistorySample {
                timestamp: row.get(0)?,
                level: row.get(1)?,
                score: row.get(2)?,
                requests_per_second: row.get::<_, f64>(3)? as u32,
                requests_per_minute: row.get::<_, f64>(4)? as u32,
                attacks_per_minute: row.get::<_, f64>(5)? as u32,
                rate_limit_hits: row.get::<_, f64>(6)? as u32,
                blocked: row.get::<_, f64>(7)? as u32,
            })
        });

        match rows {
            Ok(rows) => rows.filter_map(|r| r.ok()).collect(),
            Err(e) => {
                tracing::error!("Failed to query history: {}", e);
                Vec::new()
            }
        }
    }

    pub fn get_day_history(&self, limit: usize) -> Vec<ThreatHistorySample> {
        self.flush();

        let conn = self.conn.lock();

        let mut stmt = match conn.prepare(
            "SELECT MAX(timestamp), MAX(level), MAX(score),
                    AVG(requests_per_second), AVG(requests_per_minute),
                    AVG(attacks_per_minute), AVG(rate_limit_hits), AVG(blocked)
             FROM (
                 SELECT timestamp / 86400 as bucket, 
                        MAX(timestamp) as timestamp, MAX(level) as level, 
                        MAX(score) as score, AVG(requests_per_second) as requests_per_second,
                        AVG(requests_per_minute) as requests_per_minute,
                        AVG(attacks_per_minute) as attacks_per_minute,
                        AVG(rate_limit_hits) as rate_limit_hits,
                        AVG(blocked) as blocked
                 FROM threat_history
                 WHERE site_id = ?1
                 GROUP BY bucket
                 ORDER BY bucket DESC
                 LIMIT ?2
             )",
        ) {
            Ok(stmt) => stmt,
            Err(e) => {
                tracing::error!("Failed to prepare statement: {}", e);
                return Vec::new();
            }
        };

        let rows = stmt.query_map(params![self.site_id, limit as i64], |row| {
            Ok(ThreatHistorySample {
                timestamp: row.get(0)?,
                level: row.get(1)?,
                score: row.get(2)?,
                requests_per_second: row.get::<_, f64>(3)? as u32,
                requests_per_minute: row.get::<_, f64>(4)? as u32,
                attacks_per_minute: row.get::<_, f64>(5)? as u32,
                rate_limit_hits: row.get::<_, f64>(6)? as u32,
                blocked: row.get::<_, f64>(7)? as u32,
            })
        });

        match rows {
            Ok(rows) => rows.filter_map(|r| r.ok()).collect(),
            Err(e) => {
                tracing::error!("Failed to query history: {}", e);
                Vec::new()
            }
        }
    }

    pub fn get_week_history(&self, limit: usize) -> Vec<ThreatHistorySample> {
        self.get_aggregated_history(limit, 86400 * 7)
    }

    pub fn get_month_history(&self, limit: usize) -> Vec<ThreatHistorySample> {
        self.get_aggregated_history(limit, 86400 * 30)
    }

    fn get_aggregated_history(&self, limit: usize, bucket_secs: i64) -> Vec<ThreatHistorySample> {
        self.flush();

        let conn = self.conn.lock();

        let query = format!(
            "SELECT MAX(timestamp), MAX(level), MAX(score),
                    AVG(requests_per_second), AVG(requests_per_minute),
                    AVG(attacks_per_minute), AVG(rate_limit_hits), AVG(blocked)
             FROM (
                 SELECT timestamp / {} as bucket, 
                        MAX(timestamp) as timestamp, MAX(level) as level, 
                        MAX(score) as score, AVG(requests_per_second) as requests_per_second,
                        AVG(requests_per_minute) as requests_per_minute,
                        AVG(attacks_per_minute) as attacks_per_minute,
                        AVG(rate_limit_hits) as rate_limit_hits,
                        AVG(blocked) as blocked
                 FROM threat_history
                 WHERE site_id = ?1
                 GROUP BY bucket
                 ORDER BY bucket DESC
                 LIMIT ?2
             )",
            bucket_secs
        );

        let mut stmt = match conn.prepare(&query) {
            Ok(stmt) => stmt,
            Err(e) => {
                tracing::error!("Failed to prepare statement: {}", e);
                return Vec::new();
            }
        };

        let rows = stmt.query_map(params![self.site_id, limit as i64], |row| {
            Ok(ThreatHistorySample {
                timestamp: row.get(0)?,
                level: row.get(1)?,
                score: row.get(2)?,
                requests_per_second: row.get::<_, f64>(3)? as u32,
                requests_per_minute: row.get::<_, f64>(4)? as u32,
                attacks_per_minute: row.get::<_, f64>(5)? as u32,
                rate_limit_hits: row.get::<_, f64>(6)? as u32,
                blocked: row.get::<_, f64>(7)? as u32,
            })
        });

        match rows {
            Ok(rows) => rows.filter_map(|r| r.ok()).collect(),
            Err(e) => {
                tracing::error!("Failed to query history: {}", e);
                Vec::new()
            }
        }
    }

    pub fn get_all_history(&self) -> ThreatHistoryAll {
        ThreatHistoryAll {
            minute: self.get_minute_history(60),
            hour: self.get_hour_history(24),
            day: self.get_day_history(7),
            week: self.get_week_history(4),
            month: self.get_month_history(12),
        }
    }

    pub fn prune(&self, retention_days: u32) -> std::io::Result<usize> {
        let cutoff = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
            - (retention_days as i64 * 86400);

        let conn = self.conn.lock();

        let deleted = conn
            .execute(
                "DELETE FROM threat_history WHERE timestamp < ?1 AND site_id = ?2",
                params![cutoff, self.site_id],
            )
            .map_err(|e| {
                std::io::Error::other(format!("Failed to prune: {}", e))
            })?;

        conn.execute("VACUUM", []).map_err(|e| {
            std::io::Error::other(
                format!("Failed to VACUUM: {}", e),
            )
        })?;

        tracing::info!(
            "Pruned {} old history samples for site {}",
            deleted,
            self.site_id
        );
        Ok(deleted)
    }

    pub fn get_site_ids(&self) -> Vec<String> {
        let conn = self.conn.lock();
        let mut stmt = match conn.prepare("SELECT DISTINCT site_id FROM threat_history") {
            Ok(stmt) => stmt,
            Err(_) => return Vec::new(),
        };
        let rows = stmt.query_map([], |row| row.get(0));
        match rows {
            Ok(rows) => rows.filter_map(|r| r.ok()).collect(),
            Err(_) => Vec::new(),
        }
    }

    pub fn get_total_sample_count(&self) -> i64 {
        let conn = self.conn.lock();
        conn.query_row(
            "SELECT COUNT(*) FROM threat_history WHERE site_id = ?1",
            params![self.site_id],
            |row| row.get(0),
        )
        .unwrap_or(0)
    }

    pub fn get_db_path(&self) -> PathBuf {
        let conn = self.conn.lock();
        PathBuf::from(conn.path().unwrap_or_default())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupInfo {
    pub path: String,
    pub size_bytes: u64,
    pub created_at: i64,
    pub sample_count: i64,
}

pub struct SqliteBackup;

impl SqliteBackup {
    pub fn create_backup(
        db_path: &Path,
        backup_dir: &Path,
        site_id: &str,
    ) -> std::io::Result<BackupInfo> {
        std::fs::create_dir_all(backup_dir)?;

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let backup_filename = format!("threat_history_{}_{}.db", site_id, timestamp);
        let backup_path = backup_dir.join(&backup_filename);

        std::fs::copy(db_path, &backup_path)?;

        let conn = Connection::open(&backup_path).map_err(|e| {
            std::io::Error::other(
                format!("Failed to open backup for counting: {}", e),
            )
        })?;

        let metadata = std::fs::metadata(&backup_path)?;
        let size_bytes = metadata.len();

        let sample_count = conn
            .query_row(
                "SELECT COUNT(*) FROM threat_history WHERE site_id = ?1",
                params![site_id],
                |row| row.get(0),
            )
            .unwrap_or(0);

        tracing::info!(
            "Created backup at {:?} with {} samples",
            backup_path,
            sample_count
        );

        Ok(BackupInfo {
            path: backup_path.to_string_lossy().to_string(),
            size_bytes,
            created_at: timestamp as i64,
            sample_count,
        })
    }

    pub fn list_backups(backup_dir: &PathBuf) -> std::io::Result<Vec<BackupInfo>> {
        if !backup_dir.exists() {
            return Ok(Vec::new());
        }

        let mut backups = Vec::new();

        for entry in std::fs::read_dir(backup_dir)? {
            let entry = entry?;
            let path = entry.path();

            if path.extension().and_then(|s| s.to_str()) == Some("db") {
                let metadata = std::fs::metadata(&path)?;
                let created_at = metadata
                    .modified()
                    .ok()
                    .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                    .map(|d| d.as_secs() as i64)
                    .unwrap_or(0);

                if let Ok(conn) = Connection::open(&path) {
                    let sample_count = conn
                        .query_row("SELECT COUNT(*) FROM threat_history", [], |row| row.get(0))
                        .unwrap_or(0);

                    backups.push(BackupInfo {
                        path: path.to_string_lossy().to_string(),
                        size_bytes: metadata.len(),
                        created_at,
                        sample_count,
                    });
                }
            }
        }

        backups.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        Ok(backups)
    }

    pub fn delete_backup(backup_path: &str) -> std::io::Result<()> {
        let path = Path::new(backup_path);

        let canonical_path = path
            .canonicalize()
            .map_err(|e| std::io::Error::new(e.kind(), format!("Invalid path: {}", e)))?;

        let expected_dir = Path::new("/var/lib/maluwaf/threat_level/backups");
        let expected_dir_canonical = expected_dir.canonicalize().map_err(|e| {
            std::io::Error::new(
                e.kind(),
                format!("Failed to resolve backup directory: {}", e),
            )
        })?;

        if !canonical_path.starts_with(&expected_dir_canonical) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "Path traversal attempt detected",
            ));
        }

        if !canonical_path.exists() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "Backup file not found",
            ));
        }

        std::fs::remove_file(&canonical_path)?;
        tracing::info!("Deleted backup at {}", canonical_path.display());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    #[test]
    fn test_sqlite_history_basic() {
        let temp_dir = env::temp_dir().join("maluwaf_test_history");
        std::fs::create_dir_all(&temp_dir).unwrap();

        let history =
            SqliteHistory::new(Some(temp_dir.clone()), "test_site".to_string(), 60).unwrap();

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        for i in 0..5 {
            let sample = ThreatHistorySample {
                timestamp: now + i * 60,
                level: 2,
                score: 1.5,
                requests_per_second: 10,
                requests_per_minute: 600,
                attacks_per_minute: 5,
                rate_limit_hits: 10,
                blocked: 2,
            };
            history.add_sample(sample);
        }

        history.flush();

        let minute_history = history.get_minute_history(10);
        assert!(!minute_history.is_empty());

        std::fs::remove_dir_all(&temp_dir).ok();
    }
}
