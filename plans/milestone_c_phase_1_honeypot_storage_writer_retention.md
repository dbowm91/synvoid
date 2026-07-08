# Milestone C Phase 1: Honeypot Storage Writer, Retention, and Backpressure

## Purpose

Harden honeypot persistence so listener tasks cannot be stalled or resource-exhausted by SQLite writes, payload-heavy events, or bursty scanner traffic. This phase turns honeypot storage from a direct persistence side effect into a bounded operational pipeline with clear retention and failure semantics.

## Current issues to address

1. Honeypot storage uses a shared SQLite connection path that can become a contention point under bursts.
2. Listener tasks should not block indefinitely on storage writes.
3. Payload bytes and payload hex can grow sensitive/noisy retention risk even after Milestone B payload caps.
4. Storage failures need explicit metrics and drop/backpressure policy.
5. Retention, truncation, and indexing should be operator-visible.

## Non-goals

- Do not redesign all event storage in SynVoid.
- Do not add distributed analytics here.
- Do not add aggressive threat-intel actionability here; Phase 2 owns that.
- Do not store raw attacker payloads indefinitely by default.

## Target design

Introduce a bounded storage writer pipeline:

```rust
struct HoneypotWriterConfig {
    queue_capacity: usize,
    batch_size: usize,
    flush_interval_ms: u64,
    write_timeout_ms: u64,
    payload_retention_mode: PayloadRetentionMode,
    max_stored_payload_bytes: usize,
    max_stored_payload_hex_bytes: usize,
}

enum PayloadRetentionMode {
    None,
    HashOnly,
    Truncated,
    Full,
}

enum StorageBackpressurePolicy {
    DropNewest,
    DropOldest,
    BlockForTimeout,
}
```

Use existing config structures if equivalent fields already exist. The important behavior is bounded queueing, bounded write time, explicit loss accounting, and safe default payload retention.

## Implementation tasks

### 1. Storage writer queue

Add a bounded `tokio::mpsc` channel or equivalent between listener tasks and storage writer.

Requirements:

- listener tasks submit records non-blockingly or with a short bounded timeout
- queue capacity configurable
- overflow policy explicit
- drops counted with metrics
- writer task owns or serializes SQLite writes
- shutdown flush behavior documented

### 2. Batch writes

Add batch insertion if low churn:

- accumulate up to `batch_size`
- flush on interval or batch size reached
- use SQLite transaction for batches
- fall back to single insert only if batching creates excessive churn

### 3. Payload retention policy

Implement safe payload retention defaults:

- default should be `Truncated` or `HashOnly`, not indefinite full raw payload retention
- always store payload length and hash
- store payload preview only up to configured bytes
- preserve `payload_truncated` metadata from Milestone B
- avoid raw payload in logs by default

### 4. Schema and migrations

If schema changes are needed, add migrations for:

- payload hash
- original payload length
- retained payload length
- retention mode
- dropped/write failure metrics if stored

Migrations must be idempotent and tolerate existing DBs.

### 5. Backpressure and failure semantics

Define behavior for:

- queue full
- writer timeout
- SQLite busy/locked
- disk full/write error
- shutdown while queue non-empty

Default behavior should protect listener availability over perfect storage retention, but loss must be observable.

### 6. Indexing and retention cleanup

Review indexes for common queries:

- timestamp
- remote IP
- protocol/service
- severity/confidence if stored

Add retention cleanup:

- max age
- max row count
- max DB size, if practical

### 7. Tests

Required tests:

- queue full applies configured drop policy
- writer flushes batch
- storage failure increments metric and does not panic listener
- shutdown flushes or reports dropped records
- payload retention `None` stores no raw bytes
- payload retention `HashOnly` stores hash/length only
- payload retention `Truncated` stores bounded preview
- existing DB migration adds new columns safely
- SQLite locked/busy path is bounded

## Local validation commands

```bash
cargo fmt --all -- --check
cargo clippy -p synvoid-honeypot --all-targets -- -D warnings
cargo test -p synvoid-honeypot --all-targets storage
cargo test -p synvoid-honeypot --all-targets
```

Preferred additional checks:

```bash
cargo test -p synvoid-honeypot --all-features --all-targets
cargo test -p synvoid-honeypot --release
```

## Success criteria

- Listener tasks cannot block indefinitely on storage writes.
- Storage queue is bounded and drop behavior is observable.
- Payload retention defaults minimize sensitive raw payload storage.
- Migrations are idempotent.
- Storage errors are counted and do not crash listener tasks.
- Tests cover queue pressure, retention modes, migration, and writer failure.

## Handoff notes

Phase 1 should land before Phase 2. Threat-intel scoring is more reliable once storage records carry stable confidence, payload hash/length, and loss/truncation metadata.
