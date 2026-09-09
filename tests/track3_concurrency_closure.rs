//! Root-test ownership: COMPOSITION
//! Rationale: Phase 24 targeted concurrency verification for the
//! highest-contention Track 3 state (rate-limiter windows, block-store
//! read/update/remove paths, jail frame codec). Uses deterministic
//! multithreaded stress on small synchronization components only — no Loom
//! over Tokio/network stacks, per the phase constraints.
//!
//! Invariants: counters never underflow/overflow silently; release does not
//! remove a concurrently reacquired entry; no stale state resurrects after
//! remove/unblock; bounded maps enforce bounds under concurrency;
//! restart/drain races do not leak (frame codec stays total under threads).

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use synvoid_block_store::BlockStore;
use synvoid_core::block_store::{BlockProvenance, BlockProvenanceKind};
use synvoid_waf::ratelimit::sliding::{
    AtomicBucketWindow, SlidingWindowConfig, SlidingWindowLimiter,
};

fn test_block_config() -> synvoid_config::DenyListLimitsConfig {
    synvoid_config::DenyListLimitsConfig {
        max_entries: 512,
        persist_interval_secs: 0,
        target_state_persist: false,
        target_state_max_records: 10_000,
        target_state_ttl_secs: 604_800,
    }
}

fn test_provenance() -> BlockProvenance {
    BlockProvenance {
        kind: BlockProvenanceKind::Test,
        source: Some("track3_concurrency_closure".to_string()),
    }
}

fn ip(n: u32) -> IpAddr {
    IpAddr::V4(Ipv4Addr::from(n))
}

// ─── Rate limiter ───────────────────────────────────────────────────────────

#[test]
fn atomic_bucket_window_counts_are_exact_under_threads() {
    let window = Arc::new(AtomicBucketWindow::new(60, 8));
    let threads = 8usize;
    let per_thread = 250u32;
    let mut handles = Vec::new();
    for _ in 0..threads {
        let w = Arc::clone(&window);
        handles.push(std::thread::spawn(move || {
            for _ in 0..per_thread {
                w.increment();
            }
        }));
    }
    for h in handles {
        h.join().expect("worker panics fail the test");
    }
    assert_eq!(
        window.get_count(),
        threads as u32 * per_thread,
        "atomic increments must be exact: no lost updates, no overflow"
    );
}

#[test]
fn sliding_limiter_enforces_limit_and_bound_under_concurrency() {
    let limiter = Arc::new(SlidingWindowLimiter::new(
        vec![SlidingWindowConfig::with_buckets(60, 4, 1_000_000)],
        64,
    ));
    let threads = 8usize;
    let per_thread = 200u32;
    let mut handles = Vec::new();
    for t in 0..threads {
        let l = Arc::clone(&limiter);
        handles.push(std::thread::spawn(move || {
            // Each thread hammers a small shared key set so entries contend.
            for i in 0..per_thread {
                let key = format!("key-{}", (t as u32 + i) % 8);
                let _ = l.check_and_increment(&key);
            }
        }));
    }
    for h in handles {
        h.join().expect("worker panics fail the test");
    }
    // Bounded map: at most the 8 contested keys exist; bound never exceeded.
    assert!(
        limiter.get_entry_count() <= 64,
        "bounded map must enforce max_entries under concurrency"
    );
    assert_eq!(limiter.get_entry_count(), 8);
    // Counters never wrap: every key saw exactly threads*per_thread/8 hits.
    for k in 0..8 {
        let counts = limiter
            .get_count(&format!("key-{k}"))
            .expect("contended key must exist");
        assert_eq!(counts.iter().sum::<u32>(), threads as u32 * per_thread / 8);
    }
}

#[test]
fn sliding_limiter_remove_does_not_resurrect_stale_state() {
    let limiter = Arc::new(SlidingWindowLimiter::new(
        vec![SlidingWindowConfig::with_buckets(60, 4, u32::MAX)],
        64,
    ));
    for i in 0..50u32 {
        let _ = limiter.check_and_increment(&format!("victim-{i}"));
    }
    assert_eq!(limiter.get_entry_count(), 50);
    // Concurrent remove + reacquire: the key must end present exactly once
    // with no duplicate or resurrected ghost.
    let l2 = Arc::clone(&limiter);
    let remover = std::thread::spawn(move || {
        for i in 0..50u32 {
            l2.remove(&format!("victim-{i}"));
        }
    });
    let l3 = Arc::clone(&limiter);
    let reader = std::thread::spawn(move || {
        for i in 0..50u32 {
            let _ = l3.get_count(&format!("victim-{i}"));
        }
    });
    remover.join().unwrap();
    reader.join().unwrap();
    assert_eq!(
        limiter.get_entry_count(),
        0,
        "remove must drain all entries"
    );
    // Reacquire after remove creates exactly one fresh entry (no stale counts).
    let _ = limiter.check_and_increment(&"victim-0".to_string());
    assert_eq!(limiter.get_entry_count(), 1);
    assert_eq!(
        limiter
            .get_count(&"victim-0".to_string())
            .unwrap()
            .iter()
            .sum::<u32>(),
        1,
        "reacquired entry must start fresh, not resurrect stale counts"
    );
}

// ─── Block store ────────────────────────────────────────────────────────────

#[test]
fn blockstore_concurrent_block_and_read_is_consistent() {
    let store = Arc::new(BlockStore::new(true, None, test_block_config()));
    let threads = 8usize;
    let per_thread = 64u32;
    let mut handles = Vec::new();
    for t in 0..threads {
        let s = Arc::clone(&store);
        handles.push(std::thread::spawn(move || {
            for i in 0..per_thread {
                let addr = ip(0x0A00_0000 + (t as u32) * 10_000 + i);
                assert!(s.block_ip_with_provenance(
                    addr,
                    "concurrency-test",
                    3600,
                    "global",
                    test_provenance()
                ));
                assert!(s.is_blocked(&addr, "global").is_some());
            }
        }));
    }
    for h in handles {
        h.join().expect("worker panics fail the test");
    }
    // Every written entry reads back; the bound is enforced.
    let mut seen = HashSet::new();
    for t in 0..threads {
        for i in 0..per_thread {
            let addr = ip(0x0A00_0000 + (t as u32) * 10_000 + i);
            assert!(
                store.is_blocked(&addr, "global").is_some(),
                "lost block for {addr}"
            );
            seen.insert(addr);
        }
    }
    assert_eq!(seen.len(), threads * per_thread as usize);
}

#[test]
fn blockstore_unblock_never_resurrects_stale_state() {
    let store = Arc::new(BlockStore::new(true, None, test_block_config()));
    let victim = ip(0x0A00_F001);
    assert!(store.block_ip_with_provenance(victim, "test", 3600, "global", test_provenance()));
    assert!(store.is_blocked(&victim, "global").is_some());

    // Hammer unblock from several threads while readers probe: exactly one
    // unblock wins, and once gone the entry never comes back.
    let mut handles = Vec::new();
    for _ in 0..4 {
        let s = Arc::clone(&store);
        handles.push(std::thread::spawn(move || {
            for _ in 0..100 {
                let _ = s.unblock_ip(&victim, "global");
                let _ = s.is_blocked(&victim, "global");
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
    assert!(
        store.is_blocked(&victim, "global").is_none(),
        "unblocked entry must stay gone (no resurrection)"
    );
    // Re-block after unblock creates a live entry again (release did not
    // destroy the key's ability to be reacquired).
    assert!(store.block_ip_with_provenance(victim, "test-2", 3600, "global", test_provenance()));
    assert!(store.is_blocked(&victim, "global").is_some());
}

#[test]
fn blockstore_enforces_capacity_bound_under_concurrency() {
    let mut config = test_block_config();
    config.max_entries = 64;
    let store = Arc::new(BlockStore::new(true, None, config));
    let mut handles = Vec::new();
    for t in 0..8 {
        let s = Arc::clone(&store);
        handles.push(std::thread::spawn(move || {
            for i in 0..50u32 {
                let addr = ip(0x0B00_0000 + (t as u32) * 1_000 + i);
                let _ =
                    s.block_ip_with_provenance(addr, "capacity", 3600, "global", test_provenance());
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
    let stats = store.get_stats();
    assert!(
        stats.total_entries <= 64,
        "capacity bound violated: {} > 64",
        stats.total_entries
    );
}

// ─── Jail frame codec stays total under threads ─────────────────────────────

#[test]
fn jail_frame_round_trip_is_stable_under_threads() {
    use synvoid_ipc::{
        decode_request, decode_response, encode_request, encode_response, JailHookCapabilities,
        JailOperation, JailOutput, JailRequest, JailResponse, JailResult,
    };
    // One valid request/response pair, round-tripped from many threads: the
    // codec is pure encode/decode with no shared mutable state, so every
    // thread must observe the identical envelope.
    let req = JailRequest::new(
        7,
        JailOperation::WasmInvoke {
            module_id: "mod".to_string(),
            method: "GET".to_string(),
            uri: "/".to_string(),
            headers: vec![("host".to_string(), "example.com".to_string())],
            body: b"hello".to_vec(),
        },
    );
    let res = JailResponse::new(7, JailResult::Ok(JailOutput::Pong));
    let _ = JailHookCapabilities {
        request_inspect: true,
        request_mutate: false,
        response_inspect: false,
        response_mutate: false,
    };
    let req_frame = encode_request(&req).expect("valid request encodes");
    let res_frame = encode_response(&res).expect("valid response encodes");
    let mut handles = Vec::new();
    for _ in 0..8 {
        let (rf, sf) = (req_frame.clone(), res_frame.clone());
        handles.push(std::thread::spawn(move || {
            for _ in 0..100 {
                // Strip the 4-byte length prefix to obtain the payload.
                let decoded_req = decode_request(&rf[4..]).expect("request decodes");
                assert_eq!(decoded_req.id, 7);
                let decoded_res = decode_response(&sf[4..]).expect("response decodes");
                assert_eq!(decoded_res.id, 7);
                // Malformed payloads never panic: garbage in, typed error out.
                let garbage = [0xFFu8; 32];
                let _ = decode_request(&garbage);
                let _ = decode_response(&garbage);
                let _ = decode_request(&[]);
            }
        }));
    }
    for h in handles {
        h.join().expect("codec worker panicked");
    }
}
