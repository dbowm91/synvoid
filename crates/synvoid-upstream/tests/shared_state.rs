//! Phase 42 mmap behavior tests for `synvoid-upstream::shared_state`.
//!
//! Pure layout arithmetic lives in `shared_state.rs::layout_tests`; these
//! integration tests cover file-backed behavior: header round-trips,
//! independent-handle visibility, truncated/corrupt rejection, symlink and
//! permission hardening, fail-closed dimensions, and a true child-process
//! sharing contract (parent creates, child opens via `open_existing`).

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;

use synvoid_upstream::shared_state::{
    ConnectionTableLayout, RateLimitTableLayout, SharedConnectionTable, SharedRateLimitTable,
};

fn temp_path(dir: &tempfile::TempDir, name: &str) -> PathBuf {
    dir.path().join(name)
}

// ---------------------------------------------------------------------------
// Header round-trip + independent-handle visibility
// ---------------------------------------------------------------------------

#[test]
fn connection_header_round_trip_and_visibility() {
    let dir = tempfile::TempDir::new().expect("tempdir");
    let path = temp_path(&dir, "connections.shm");
    let table = SharedConnectionTable::new(path.clone(), 4, 8).expect("create");
    assert_eq!(table.max_workers(), 4);
    assert_eq!(table.max_backends(), 8);

    // Header bytes are magic/version/dims in little-endian.
    let raw = std::fs::read(&path).expect("read backing file");
    assert!(raw.len() >= synvoid_upstream::shared_state::CONNECTION_HEADER_LEN);
    assert_eq!(&raw[0..4], &0x5443_5653u32.to_le_bytes());
    assert_eq!(&raw[4..8], &1u32.to_le_bytes());
    assert_eq!(&raw[8..16], &4u64.to_le_bytes());
    assert_eq!(&raw[16..24], &8u64.to_le_bytes());

    // Counters start at zero.
    assert_eq!(
        table
            .get_counter_atomic(0, 0)
            .expect("counter exists")
            .load(Ordering::SeqCst),
        0
    );

    // An independently opened handle (no shared Arc) sees the same file.
    let reopened = SharedConnectionTable::open_existing(&path).expect("open_existing");
    assert_eq!(reopened.max_workers(), 4);
    assert_eq!(reopened.max_backends(), 8);

    table.record_heartbeat(2, 12345);
    assert_eq!(
        reopened
            .get_heartbeat_atomic(2)
            .expect("heartbeat exists")
            .load(Ordering::SeqCst),
        12345,
        "writes via one handle must be visible via an independent open"
    );
    reopened
        .get_counter_atomic(1, 7)
        .expect("counter exists")
        .fetch_add(3, Ordering::SeqCst);
    assert_eq!(
        table
            .get_counter_atomic(1, 7)
            .expect("counter exists")
            .load(Ordering::SeqCst),
        3
    );
}

#[test]
fn ratelimit_header_round_trip_and_visibility() {
    let dir = tempfile::TempDir::new().expect("tempdir");
    let path = temp_path(&dir, "ratelimit.shm");
    let table = SharedRateLimitTable::new(path.clone(), 128).expect("create");
    assert_eq!(table.num_slots(), 128);
    assert_eq!(table.second_counters().len(), 128);
    assert_eq!(table.minute_counters().len(), 128);
    assert_eq!(table.five_min_counters().len(), 128);
    assert_eq!(table.dirty_words().len(), 128 / 32);

    let raw = std::fs::read(&path).expect("read backing file");
    assert_eq!(&raw[0..4], &0x4c52_5653u32.to_le_bytes());
    assert_eq!(&raw[4..8], &1u32.to_le_bytes());
    assert_eq!(&raw[8..16], &128u64.to_le_bytes());

    table.second_counters()[5].store(7, Ordering::SeqCst);
    let reopened = SharedRateLimitTable::open_existing(&path).expect("open_existing");
    assert_eq!(reopened.num_slots(), 128);
    assert_eq!(reopened.second_counters()[5].load(Ordering::SeqCst), 7);
    reopened.minute_counters()[9].store(11, Ordering::SeqCst);
    assert_eq!(table.minute_counters()[9].load(Ordering::SeqCst), 11);
}

// ---------------------------------------------------------------------------
// Rejection paths: corrupt, truncated, wrong version, bad dimensions
// ---------------------------------------------------------------------------

#[test]
fn rejects_garbage_magic_and_truncation() {
    let dir = tempfile::TempDir::new().expect("tempdir");

    // Garbage file: magic mismatch.
    let bad = temp_path(&dir, "bad.shm");
    std::fs::write(&bad, vec![0xAAu8; 64]).expect("write garbage");
    assert!(SharedConnectionTable::open_existing(&bad).is_err());
    assert!(SharedRateLimitTable::open_existing(&bad).is_err());

    // Valid file, then truncated below the header.
    let conn = temp_path(&dir, "conn.shm");
    SharedConnectionTable::new(conn.clone(), 2, 2).expect("create");
    {
        let f = std::fs::OpenOptions::new()
            .write(true)
            .open(&conn)
            .expect("open");
        f.set_len(7).expect("truncate");
    }
    assert!(SharedConnectionTable::open_existing(&conn).is_err());

    let rl = temp_path(&dir, "rl.shm");
    SharedRateLimitTable::new(rl.clone(), 32).expect("create");
    {
        let f = std::fs::OpenOptions::new()
            .write(true)
            .open(&rl)
            .expect("open");
        f.set_len(3).expect("truncate");
    }
    assert!(SharedRateLimitTable::open_existing(&rl).is_err());
}

#[test]
fn rejects_wrong_version_without_panic() {
    let dir = tempfile::TempDir::new().expect("tempdir");
    let path = temp_path(&dir, "conn.shm");
    SharedConnectionTable::new(path.clone(), 2, 2).expect("create");
    // Rewrite the version field to an unsupported value.
    {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .expect("open");
        f.write_all_at(&99u32.to_le_bytes(), 4)
            .expect("overwrite version");
    }
    let err = match SharedConnectionTable::open_existing(&path) {
        Ok(_) => panic!("version must reject"),
        Err(e) => e,
    };
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);

    let rl = temp_path(&dir, "rl.shm");
    SharedRateLimitTable::new(rl.clone(), 32).expect("create");
    {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .open(&rl)
            .expect("open");
        f.write_all_at(&99u32.to_le_bytes(), 4)
            .expect("overwrite version");
    }
    let err = match SharedRateLimitTable::open_existing(&rl) {
        Ok(_) => panic!("version must reject"),
        Err(e) => e,
    };
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
}

// `write_all_at` helper: `File::write_at` is Unix-only, so emulate portably.
trait WriteAt {
    fn write_all_at(&mut self, buf: &[u8], offset: u64) -> std::io::Result<()>;
}

impl WriteAt for std::fs::File {
    fn write_all_at(&mut self, buf: &[u8], offset: u64) -> std::io::Result<()> {
        use std::io::{Seek, SeekFrom};
        self.seek(SeekFrom::Start(offset))?;
        self.write_all(buf)?;
        self.flush()
    }
}

#[test]
fn invalid_dimensions_fail_closed_without_panic() {
    let dir = tempfile::TempDir::new().expect("tempdir");
    // Zero / unbounded / overflow dimensions return errors, never panic.
    assert!(SharedConnectionTable::new(temp_path(&dir, "a"), 0, 1).is_err());
    assert!(SharedConnectionTable::new(temp_path(&dir, "b"), 1, 0).is_err());
    assert!(SharedConnectionTable::new(temp_path(&dir, "c"), usize::MAX, 1).is_err());
    assert!(SharedConnectionTable::new(temp_path(&dir, "d"), 1, usize::MAX).is_err());
    assert!(SharedRateLimitTable::new(temp_path(&dir, "e"), 0).is_err());
    assert!(SharedRateLimitTable::new(temp_path(&dir, "f"), usize::MAX).is_err());

    // Out-of-range access returns None, never panics.
    let table = SharedConnectionTable::new(temp_path(&dir, "g"), 2, 2).expect("create");
    assert!(table.get_heartbeat_atomic(2).is_none());
    assert!(table.get_heartbeat_atomic(usize::MAX).is_none());
    assert!(table.get_counter_atomic(2, 0).is_none());
    assert!(table.get_counter_atomic(0, 2).is_none());
    assert!(table.get_counter_atomic(usize::MAX, usize::MAX).is_none());
    // Recording a heartbeat for an invalid worker is a silent no-op.
    table.record_heartbeat(99, 1);

    // Pure layout types agree: no panic on extreme inputs.
    assert!(ConnectionTableLayout::new(usize::MAX, usize::MAX).is_err());
    assert!(RateLimitTableLayout::new(usize::MAX).is_err());
}

// ---------------------------------------------------------------------------
// File hardening: symlinks, regular-file check, permissions
// ---------------------------------------------------------------------------

#[cfg(unix)]
#[test]
fn rejects_symlinked_targets() {
    use std::os::unix::fs::symlink;
    let dir = tempfile::TempDir::new().expect("tempdir");
    let real = temp_path(&dir, "real.shm");
    std::fs::write(&real, b"placeholder").expect("write");
    let link = temp_path(&dir, "link.shm");
    symlink(&real, &link).expect("symlink");
    assert!(SharedConnectionTable::new(link.clone(), 2, 2).is_err());
    assert!(SharedRateLimitTable::new(link, 32).is_err());
}

#[test]
fn rejects_non_regular_targets() {
    let dir = tempfile::TempDir::new().expect("tempdir");
    let subdir = dir.path().join("subdir");
    std::fs::create_dir(&subdir).expect("mkdir");
    assert!(SharedConnectionTable::new(subdir.clone(), 2, 2).is_err());
    assert!(SharedRateLimitTable::new(subdir, 32).is_err());
}

#[cfg(unix)]
#[test]
fn created_files_and_dirs_are_owner_only() {
    use std::os::unix::fs::PermissionsExt;
    let outer = tempfile::TempDir::new().expect("tempdir");
    // Nested parent must be created by the constructor.
    let path = outer
        .path()
        .join("nested")
        .join("run")
        .join("connections.shm");
    SharedConnectionTable::new(path.clone(), 2, 2).expect("create");
    let file_mode = std::fs::metadata(&path).expect("meta").permissions().mode() & 0o777;
    assert_eq!(
        file_mode, 0o600,
        "shm file must be owner-only, got {file_mode:o}"
    );
    let parent = path.parent().expect("parent");
    let dir_mode = std::fs::metadata(parent)
        .expect("meta")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(
        dir_mode, 0o700,
        "shm dir must be owner-only, got {dir_mode:o}"
    );
}

// ---------------------------------------------------------------------------
// Child-process sharing contract
// ---------------------------------------------------------------------------

fn is_child_mode() -> bool {
    std::env::var("SYNVOID_SHM_CHILD").as_deref() == Ok("1")
}

/// Child role: runs inside the spawned test binary (see
/// `cross_process_counters_visible`). Verifies the parent's sentinel values
/// through fresh `open_existing` mappings, then writes ack values.
#[test]
fn shared_state_child_worker() {
    if !is_child_mode() {
        return;
    }
    let conn_path = std::env::var("SYNVOID_SHM_CONN_PATH").expect("conn path env");
    let rl_path = std::env::var("SYNVOID_SHM_RL_PATH").expect("rl path env");

    let conn =
        SharedConnectionTable::open_existing(Path::new(&conn_path)).expect("child open conn");
    assert_eq!(conn.max_workers(), 4);
    assert_eq!(conn.max_backends(), 4);
    let hb = conn
        .get_heartbeat_atomic(1)
        .expect("heartbeat")
        .load(Ordering::SeqCst);
    assert_eq!(hb, 0xC0FFEE, "child must see parent heartbeat");
    let c = conn
        .get_counter_atomic(1, 2)
        .expect("counter")
        .load(Ordering::SeqCst);
    assert_eq!(c, 41, "child must see parent counter");

    conn.record_heartbeat(1, 0xC0FFEE + 1);
    conn.get_counter_atomic(1, 2)
        .expect("counter")
        .fetch_add(1, Ordering::SeqCst);

    let rl = SharedRateLimitTable::open_existing(Path::new(&rl_path)).expect("child open rl");
    assert_eq!(rl.num_slots(), 64);
    assert_eq!(rl.second_counters()[3].load(Ordering::SeqCst), 9);
    rl.second_counters()[3].store(10, Ordering::SeqCst);
}

#[test]
fn cross_process_counters_visible() {
    if is_child_mode() {
        return;
    }
    let dir = tempfile::TempDir::new().expect("tempdir");
    let conn_path = temp_path(&dir, "connections.shm");
    let rl_path = temp_path(&dir, "ratelimit.shm");

    let conn = SharedConnectionTable::new(conn_path.clone(), 4, 4).expect("create conn");
    let rl = SharedRateLimitTable::new(rl_path.clone(), 64).expect("create rl");

    conn.record_heartbeat(1, 0xC0FFEE);
    conn.get_counter_atomic(1, 2)
        .expect("counter")
        .store(41, Ordering::SeqCst);
    rl.second_counters()[3].store(9, Ordering::SeqCst);

    // Spawn this same test binary filtered to the child worker test. The
    // child is a separate OS process with an independent mapping.
    let exe = std::env::current_exe().expect("current exe");
    let output = std::process::Command::new(exe)
        .arg("--exact")
        .arg("shared_state_child_worker")
        .arg("--nocapture")
        .env("SYNVOID_SHM_CHILD", "1")
        .env("SYNVOID_SHM_CONN_PATH", &conn_path)
        .env("SYNVOID_SHM_RL_PATH", &rl_path)
        .output()
        .expect("spawn child test binary");
    assert!(
        output.status.success(),
        "child process failed: status={} stdout={} stderr={}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    // Ack values written by the child must be visible to the parent mapping.
    assert_eq!(
        conn.get_heartbeat_atomic(1)
            .expect("heartbeat")
            .load(Ordering::SeqCst),
        0xC0FFEE + 1
    );
    assert_eq!(
        conn.get_counter_atomic(1, 2)
            .expect("counter")
            .load(Ordering::SeqCst),
        42
    );
    assert_eq!(rl.second_counters()[3].load(Ordering::SeqCst), 10);
}
