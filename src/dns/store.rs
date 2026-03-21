use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use parking_lot::RwLock;
use rusqlite::{params, Connection};

use crate::dns::server::{DnsZoneRecord, RecordType, RecordTypeExt, Zone};

pub struct ZoneStore {
    conn: Arc<RwLock<Connection>>,
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
            conn: Arc::new(RwLock::new(conn)),
        })
    }

    pub fn load_zones(&self) -> Result<HashMap<String, Zone>, String> {
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
            for (name, rt, value, ttl, priority) in records {
                let record_type = match rt {
                    1 => RecordType::A,
                    28 => RecordType::AAAA,
                    5 => RecordType::CNAME,
                    15 => RecordType::MX,
                    16 => RecordType::TXT,
                    2 => RecordType::NS,
                    6 => RecordType::SOA,
                    33 => RecordType::SRV,
                    _ => RecordTypeExt::UNKNOWN,
                };

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

            let mut zone = Zone::new(origin.clone());
            zone.records = zone_records;
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
        let _now = chrono::Utc::now().timestamp();

        let zone_id: i64 = conn
            .query_row(
                "SELECT id FROM zones WHERE origin = ?",
                params![zone],
                |row| row.get(0),
            )
            .map_err(|e| format!("Failed to get zone id: {}", e))?;

        conn.execute("DELETE FROM records WHERE zone_id = ?", params![zone_id])
            .map_err(|e| format!("Failed to delete old records: {}", e))?;

        for (name, record_type, value, ttl, priority) in records {
            let rt = match record_type {
                RecordType::A => 1,
                RecordType::AAAA => 28,
                RecordType::CNAME => 5,
                RecordType::MX => 15,
                RecordType::TXT => 16,
                RecordType::NS => 2,
                RecordType::SOA => 6,
                RecordType::SRV => 33,
                _ => 0,
            };

            conn.execute(
                "INSERT INTO records (zone_id, name, record_type, value, ttl, priority) VALUES (?, ?, ?, ?, ?, ?)",
                params![zone_id, name, rt, value, ttl, priority],
            ).map_err(|e| format!("Failed to save record: {}", e))?;
        }

        Ok(())
    }

    pub fn delete_zone(&self, zone: &str) -> Result<(), String> {
        let conn = self.conn.write();

        conn.execute("DELETE FROM zones WHERE origin = ?", params![zone])
            .map_err(|e| format!("Failed to delete zone: {}", e))?;

        Ok(())
    }
}
