use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use parking_lot::RwLock;
use rusqlite::{params, Connection};

use crate::server::{DnsZoneRecord, RecordType, SerialPolicy, Zone};

pub struct ZoneStore {
    conn: Arc<RwLock<Connection>>,
    /// If true, zones are stored in-memory only (no SQLite persistence).
    volatile: bool,
}

impl ZoneStore {
    pub fn new(data_dir: PathBuf) -> Result<Self, String> {
        std::fs::create_dir_all(&data_dir)
            .map_err(|e| format!("Failed to create DNS data directory: {}", e))?;

        let db_path = data_dir.join("zones.db");

        let conn = Connection::open(&db_path)
            .map_err(|e| format!("Failed to open DNS database: {}", e))?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS zones (
                id INTEGER PRIMARY KEY,
                origin TEXT NOT NULL UNIQUE,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL
            )",
            [],
        )
        .map_err(|e| format!("Failed to create zones table: {}", e))?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS records (
                id INTEGER PRIMARY KEY,
                zone_id INTEGER NOT NULL,
                name TEXT NOT NULL,
                record_type INTEGER NOT NULL,
                value TEXT NOT NULL,
                ttl INTEGER NOT NULL,
                priority INTEGER,
                FOREIGN KEY (zone_id) REFERENCES zones(id) ON DELETE CASCADE
            )",
            [],
        )
        .map_err(|e| format!("Failed to create records table: {}", e))?;

        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_records_zone ON records(zone_id)",
            [],
        )
        .ok();

        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_records_lookup ON records(zone_id, name, record_type)",
            [],
        )
        .ok();

        tracing::info!("DNS zone store initialized at {:?}", db_path);

        Ok(Self {
            #[allow(clippy::arc_with_non_send_sync)]
            conn: Arc::new(RwLock::new(conn)),
            volatile: false,
        })
    }

    /// Create a volatile (in-memory only) zone store. No persistence.
    pub fn new_volatile() -> Result<Self, String> {
        let conn = Connection::open(":memory:")
            .map_err(|e| format!("Failed to open in-memory database: {}", e))?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS zones (
                id INTEGER PRIMARY KEY,
                origin TEXT NOT NULL UNIQUE,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL
            )",
            [],
        )
        .map_err(|e| format!("Failed to create zones table: {}", e))?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS records (
                id INTEGER PRIMARY KEY,
                zone_id INTEGER NOT NULL,
                name TEXT NOT NULL,
                record_type INTEGER NOT NULL,
                value TEXT NOT NULL,
                ttl INTEGER NOT NULL,
                priority INTEGER,
                FOREIGN KEY (zone_id) REFERENCES zones(id) ON DELETE CASCADE
            )",
            [],
        )
        .map_err(|e| format!("Failed to create records table: {}", e))?;

        Ok(Self {
            #[allow(clippy::arc_with_non_send_sync)]
            conn: Arc::new(RwLock::new(conn)),
            volatile: true,
        })
    }

    pub fn is_volatile(&self) -> bool {
        self.volatile
    }

    pub fn load_zones(&self) -> Result<HashMap<String, Zone>, String> {
        if self.volatile {
            return Ok(HashMap::new());
        }

        let conn = self.conn.read();
        let mut zones = HashMap::new();

        let mut stmt = conn
            .prepare("SELECT id, origin FROM zones")
            .map_err(|e| format!("Failed to prepare query: {}", e))?;

        let zone_ids: Vec<(i64, String)> = stmt
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
            .map_err(|e| format!("Failed to query zones: {}", e))?
            .filter_map(|r| r.ok())
            .collect();

        for (zone_id, origin) in zone_ids {
            let mut rec_stmt = conn
                .prepare(
                    "SELECT name, record_type, value, ttl, priority FROM records WHERE zone_id = ?",
                )
                .map_err(|e| format!("Failed to prepare records query: {}", e))?;

            let records: Vec<(String, i32, String, u32, Option<i32>)> = rec_stmt
                .query_map(params![zone_id], |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                    ))
                })
                .map_err(|e| format!("Failed to query records: {}", e))?
                .filter_map(|r| r.ok())
                .collect();

            let mut zone_records = HashMap::new();
            let mut corrupt_count = 0;
            for (name, rt, value, ttl, priority) in records {
                // R4: the stored type is the wire type. The old table mapped
                // 39 (DNAME) to CNAME and sent every other unlisted type to 0,
                // which lost the record on the next load.
                if rt <= 0 || rt > u16::MAX as i32 {
                    corrupt_count += 1;
                    tracing::warn!(
                        zone = %origin,
                        name = %name,
                        record_type_raw = rt,
                        "Skipping corrupt record with out-of-range type {}",
                        rt
                    );
                    continue;
                }
                let record_type = RecordType::from(rt as u16);

                let record = DnsZoneRecord {
                    name: name.clone(),
                    record_type,
                    value,
                    ttl,
                    priority: priority.map(|p| p as u32),
                };

                zone_records
                    .entry((name, record_type))
                    .or_insert_with(Vec::new)
                    .push(record);
            }

            if corrupt_count > 0 {
                tracing::warn!(
                    zone = %origin,
                    corrupt_count,
                    "Skipped {} corrupt records during zone load",
                    corrupt_count
                );
            }

            let mut zone = Zone::new(origin.clone());
            // R4: install through the single writer, which normalizes the
            // persisted owner keys, rebuilds the owner index, and restores the
            // zone serial from the SOA (an IXFR comparison must not start
            // from 0).
            zone.commit_records(zone_records, SerialPolicy::AdoptSoa)
                .map_err(|reason| format!("Zone {origin} (from store): {reason}"))?;
            zones.insert(origin.clone(), zone);
        }

        Ok(zones)
    }

    pub fn save_zone(
        &self,
        zone: &str,
        records: &[(String, RecordType, String, u32, Option<u32>)],
    ) -> Result<(), String> {
        let conn = self.conn.write();

        let tx = conn
            .unchecked_transaction()
            .map_err(|e| format!("Failed to begin transaction: {}", e))?;

        // Persist the zone row before its records. `zones.origin` is UNIQUE,
        // so this is an upsert: the first save of a loaded zone creates the
        // row, a later save refreshes `updated_at` (R4: a zone can actually be
        // written, not only read).
        let now = crate::time::unix_timestamp_secs();
        tx.execute(
            "INSERT INTO zones (origin, created_at, updated_at) VALUES (?, ?, ?)
             ON CONFLICT(origin) DO UPDATE SET updated_at = excluded.updated_at",
            params![zone, now, now],
        )
        .map_err(|e| format!("Failed to upsert zone row: {}", e))?;

        let zone_id: i64 = tx
            .query_row(
                "SELECT id FROM zones WHERE origin = ?",
                params![zone],
                |row| row.get(0),
            )
            .map_err(|e| format!("Failed to get zone id: {}", e))?;

        tx.execute("DELETE FROM records WHERE zone_id = ?", params![zone_id])
            .map_err(|e| format!("Failed to delete old records: {}", e))?;

        for (name, record_type, value, ttl, priority) in records {
            // R4: round-trip the record type as its wire value. DNAME (39)
            // must not load as CNAME, and no supported type may be written as
            // 0 and dropped as corrupt on the next load.
            let rt = u16::from(*record_type);

            tx.execute(
                "INSERT INTO records (zone_id, name, record_type, value, ttl, priority) VALUES (?, ?, ?, ?, ?, ?)",
                params![zone_id, name, rt, value, ttl, priority],
            ).map_err(|e| format!("Failed to save record: {}", e))?;
        }

        tx.commit()
            .map_err(|e| format!("Failed to commit transaction: {}", e))?;

        Ok(())
    }

    pub fn delete_zone(&self, zone: &str) -> Result<(), String> {
        let conn = self.conn.write();

        conn.execute("DELETE FROM zones WHERE origin = ?", params![zone])
            .map_err(|e| format!("Failed to delete zone: {}", e))?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_volatile_store_is_volatile() {
        let store = ZoneStore::new_volatile().unwrap();
        assert!(store.is_volatile());
    }

    #[test]
    fn test_file_store_is_not_volatile() {
        let dir = tempfile::tempdir().unwrap();
        let store = ZoneStore::new(dir.path().to_path_buf()).unwrap();
        assert!(!store.is_volatile());
    }

    #[test]
    fn test_volatile_store_load_returns_empty() {
        let store = ZoneStore::new_volatile().unwrap();
        let zones = store.load_zones().unwrap();
        assert!(zones.is_empty());
    }

    #[test]
    fn test_save_zone_atomic() {
        let store = ZoneStore::new_volatile().unwrap();

        // First, we need to insert a zone row directly since save_zone expects it
        {
            let conn = store.conn.write();
            conn.execute(
                "INSERT INTO zones (origin, created_at, updated_at) VALUES (?, ?, ?)",
                params!["test.com", 0i64, 0i64],
            )
            .unwrap();
        }

        let records = vec![
            (
                "@".to_string(),
                RecordType::A,
                "1.2.3.4".to_string(),
                3600u32,
                None,
            ),
            (
                "www".to_string(),
                RecordType::A,
                "5.6.7.8".to_string(),
                3600u32,
                None,
            ),
        ];

        store.save_zone("test.com", &records).unwrap();

        // Verify records were saved
        let conn = store.conn.read();
        let count: i32 = conn
            .query_row(
                "SELECT COUNT(*) FROM records WHERE zone_id = (SELECT id FROM zones WHERE origin = 'test.com')",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 2);
    }

    #[test]
    fn test_save_zone_replaces_existing() {
        let dir = tempfile::tempdir().unwrap();
        let store = ZoneStore::new(dir.path().to_path_buf()).unwrap();

        {
            let conn = store.conn.write();
            conn.execute(
                "INSERT INTO zones (origin, created_at, updated_at) VALUES (?, ?, ?)",
                params!["test.com", 0i64, 0i64],
            )
            .unwrap();
        }

        let records1 = vec![(
            "@".to_string(),
            RecordType::A,
            "1.1.1.1".to_string(),
            3600u32,
            None,
        )];
        store.save_zone("test.com", &records1).unwrap();

        // Replace with different records
        let records2 = vec![(
            "@".to_string(),
            RecordType::AAAA,
            "::1".to_string(),
            3600u32,
            None,
        )];
        store.save_zone("test.com", &records2).unwrap();

        // Should have only the new record
        let zones = store.load_zones().unwrap();
        let zone = zones.get("test.com").unwrap();
        let a_records = zone.records.get(&("@".to_string(), RecordType::A));
        let aaaa_records = zone.records.get(&("@".to_string(), RecordType::AAAA));
        assert!(a_records.is_none() || a_records.unwrap().is_empty());
        assert!(aaaa_records.is_some());
    }

    #[test]
    fn test_delete_zone_removes_from_store() {
        let store = ZoneStore::new_volatile().unwrap();

        {
            let conn = store.conn.write();
            conn.execute(
                "INSERT INTO zones (origin, created_at, updated_at) VALUES (?, ?, ?)",
                params!["test.com", 0i64, 0i64],
            )
            .unwrap();
        }

        store.delete_zone("test.com").unwrap();

        let zones = store.load_zones().unwrap();
        assert!(zones.is_empty());
    }
}
