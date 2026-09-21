//! Phase 54: buffer-pool soft-accounting contract tests.
//!
//! These tests assert exact values of the process-global checkout counter,
//! so they live in their own binary (no other test in this process touches
//! the pool) and serialize against each other with a static mutex.

use std::sync::Mutex;
use synvoid_utils::buffer::pool::BufferPool;

static SERIALIZER: Mutex<()> = Mutex::new(());

#[test]
fn take_bytes_releases_accounting_once() {
    let _guard = SERIALIZER.lock().unwrap();
    let before = BufferPool::allocated_bytes();
    let mut buf = BufferPool::acquire(2048);
    let checked_out = buf.capacity() as u64;
    let during = BufferPool::allocated_bytes();
    assert_eq!(
        during - before,
        checked_out,
        "checkout must account actual capacity"
    );

    let taken = buf.take_bytes();
    assert_eq!(taken.len(), 2048);
    assert_eq!(
        BufferPool::allocated_bytes(),
        before,
        "take_bytes must release the checkout exactly once"
    );
    drop(buf);
    assert_eq!(
        BufferPool::allocated_bytes(),
        before,
        "drop after take_bytes must not double-release"
    );
}

#[test]
fn growth_updates_accounting_and_drop_releases() {
    let _guard = SERIALIZER.lock().unwrap();
    let before = BufferPool::allocated_bytes();
    let mut buf = BufferPool::acquire(512);
    let small_tracked = BufferPool::allocated_bytes();
    assert!(small_tracked >= before);

    buf.resize(100 * 1024);
    assert_eq!(buf.len(), 100 * 1024);
    let grown = BufferPool::allocated_bytes();
    assert!(
        grown > small_tracked,
        "growth across tiers must update accounting"
    );

    drop(buf);
    assert_eq!(
        BufferPool::allocated_bytes(),
        before,
        "drop must release grown capacity"
    );
}

#[test]
fn pathological_capacity_not_retained() {
    let _guard = SERIALIZER.lock().unwrap();
    let before = BufferPool::allocated_bytes();
    let mut buf = BufferPool::acquire(1024);
    buf.resize(8 * 1024 * 1024);
    drop(buf);
    assert_eq!(
        BufferPool::allocated_bytes(),
        before,
        "oversized buffers must be freed, not retained"
    );
}

#[test]
fn repeated_grow_drop_cycles_do_not_drift() {
    let _guard = SERIALIZER.lock().unwrap();
    let before = BufferPool::allocated_bytes();
    for _ in 0..50 {
        let mut buf = BufferPool::acquire(256);
        buf.resize(48 * 1024);
        let _ = buf.take_bytes();
        let mut buf2 = BufferPool::acquire(128);
        buf2.extend_from_slice(&[0xABu8; 4096]);
        drop(buf2);
        drop(buf);
    }
    assert_eq!(
        BufferPool::allocated_bytes(),
        before,
        "grow/take/drop cycles must not drift the counter"
    );
}
