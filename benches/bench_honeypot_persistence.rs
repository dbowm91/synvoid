//! Phase 49: honeypot persistence baseline.
//!
//! Database creation/schema initialization happens OUTSIDE the timed loop.
//! Alongside enqueue/flush throughput per payload-retention mode, an
//! event-loop heartbeat measures Tokio scheduler fairness while synchronous
//! SQLite flushes occur (the Phase 53 target).

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use synvoid_honeypot::config::{PayloadRetentionMode, StorageConfig, StorageWriterConfig};
use synvoid_honeypot::protocol::Confidence;
use synvoid_honeypot::storage::{HoneypotRecord, HoneypotStorage};
use synvoid_honeypot::storage_writer::HoneypotWriter;

fn test_record(payload: Vec<u8>) -> HoneypotRecord {
    HoneypotRecord {
        id: 0,
        timestamp: 1_700_000_000,
        remote_ip: "10.0.0.9".to_string(),
        remote_port: 41234,
        local_port: 23,
        protocol: "tcp".to_string(),
        service: "telnet".to_string(),
        confidence: Confidence::High,
        payload_hex: String::new(),
        detected_pattern: None,
        bytes_received: 128,
        bytes_sent: 64,
        duration_ms: 5,
        connection_info: String::new(),
        payload_truncated: false,
        payload_hash: None,
        payload_length: None,
        payload,
    }
}

fn temp_storage() -> (tempfile::TempDir, HoneypotStorage) {
    let dir = tempfile::tempdir().expect("bench tempdir");
    let db_path = dir.path().join("bench.db");
    let config = StorageConfig {
        database_path: db_path.to_string_lossy().into_owned(),
        max_records: 100_000,
        retention_days: 7,
        flush_interval_secs: 3600,
        writer: StorageWriterConfig::default(),
    };
    let storage = HoneypotStorage::new(&config).expect("bench storage");
    (dir, storage)
}

fn benchmark_enqueue_only(c: &mut Criterion) {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("bench runtime");
    let (_dir, storage) = temp_storage();
    // Healthy consumer: small batches + short interval so the queue drains
    // during the benchmark and `try_send` measures steady-state enqueue cost.
    let writer = rt.block_on(async {
        HoneypotWriter::new(
            storage.clone(),
            StorageWriterConfig {
                queue_capacity: 8192,
                batch_size: 64,
                flush_interval_ms: 50,
                ..StorageWriterConfig::default()
            },
        )
    });

    let mut group = c.benchmark_group("honeypot/enqueue");
    group.bench_function("try_write_record", |b| {
        b.iter(|| {
            let _ = writer.try_write_record(test_record(vec![0x41; 64]));
        });
    });
    group.bench_function("write_record_healthy_consumer", |b| {
        b.iter(|| {
            rt.block_on(writer.write_record(test_record(vec![0x41; 64])))
                .expect("healthy consumer drains");
        });
    });
    group.finish();
}

fn benchmark_flush_sizes(c: &mut Criterion) {
    let (_dir, storage) = temp_storage();

    let mut group = c.benchmark_group("honeypot/flush");
    for (name, payload_len) in [("empty", 0usize), ("small_64", 64), ("medium_1k", 1024)] {
        group.bench_with_input(
            BenchmarkId::new("record_connection", name),
            &payload_len,
            |b, &n| {
                let record = test_record(vec![0x42; n]);
                b.iter(|| {
                    let _ = criterion::black_box(storage.record_connection(record.clone()));
                });
            },
        );
    }
    group.bench_function("prune_maintenance", |b| {
        b.iter(|| criterion::black_box(storage.prune_old_records()));
    });
    group.bench_function("enforce_max_records", |b| {
        b.iter(|| criterion::black_box(storage.enforce_max_records()));
    });
    group.finish();
}

fn benchmark_retention_modes(c: &mut Criterion) {
    // Retention (`apply_retention`: hash + truncate) runs synchronously inside
    // `try_write_record`, so per-mode enqueue cost isolates retention cost.
    // One writer per mode, each with a draining consumer, built outside the
    // timed loop.
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("bench runtime");
    let modes = [
        ("none", PayloadRetentionMode::None),
        ("hash_only", PayloadRetentionMode::HashOnly),
        ("truncated", PayloadRetentionMode::Truncated),
        ("full", PayloadRetentionMode::Full),
    ];
    let mut writers = Vec::new();
    let mut _dirs = Vec::new();
    for (_, mode) in &modes {
        let (dir, storage) = temp_storage();
        _dirs.push(dir);
        let writer = rt.block_on(async {
            HoneypotWriter::new(
                storage.clone(),
                StorageWriterConfig {
                    queue_capacity: 8192,
                    batch_size: 64,
                    flush_interval_ms: 50,
                    payload_retention_mode: mode.clone(),
                    ..StorageWriterConfig::default()
                },
            )
        });
        writers.push(writer);
    }

    let mut group = c.benchmark_group("honeypot/retention");
    for ((name, _), writer) in modes.iter().zip(writers.iter()) {
        group.bench_with_input(BenchmarkId::new("try_write_1k", name), &1, |b, _| {
            b.iter(|| {
                let _ = writer.try_write_record(test_record(vec![0x43; 1024]));
            });
        });
    }
    group.finish();
}

/// Tokio event-loop heartbeat while synchronous SQLite flushes run: the
/// heartbeat task records max interval gap; smaller gaps mean a fairer loop.
fn benchmark_event_loop_fairness(c: &mut Criterion) {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("bench runtime");
    let (_dir, storage) = temp_storage();

    let mut group = c.benchmark_group("honeypot/event_loop");
    group.bench_function("heartbeat_during_flush", |b| {
        b.iter(|| {
            rt.block_on(async {
                let heartbeat = tokio::spawn(async {
                    let mut max_gap = std::time::Duration::ZERO;
                    let mut last = tokio::time::Instant::now();
                    for _ in 0..50 {
                        tokio::task::yield_now().await;
                        let now = tokio::time::Instant::now();
                        max_gap = max_gap.max(now - last);
                        last = now;
                    }
                    max_gap
                });
                for _ in 0..16 {
                    let record = test_record(vec![0x44; 512]);
                    let _ = storage.record_connection(record);
                }
                criterion::black_box(heartbeat.await.expect("heartbeat"));
            });
        });
    });
    group.finish();
}

criterion_group!(
    benches,
    benchmark_enqueue_only,
    benchmark_flush_sizes,
    benchmark_retention_modes,
    benchmark_event_loop_fairness,
);
criterion_main!(benches);
