# Socket Path & PID File Hardening - Priority 4 Documentation

## Issues Found

### 1. Symlink Following in `create_secure_dir_atomic()`

**File**: `src/process/socket_path.rs:16`

```rust
Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
    let metadata = std::fs::metadata(path)?;  // <-- FOLLOWS SYMLINKS
```

**Problem**: Uses `metadata()` instead of `symlink_metadata()`. If an attacker creates `/tmp/maluwaf` as a symlink to another directory owned by the attacker, the code follows the symlink and:
- May chmod a directory the attacker controls
- May treat attacker's directory as the runtime directory

### 2. `/tmp/maluwaf` Fallback Weaknesses

**File**: `src/process/socket_path.rs:55-58`

```rust
let path = PathBuf::from("/tmp").join("maluwaf");
let _ = create_secure_dir_atomic(&path);
path.join(name)
```

**Problems**:
- No per-UID isolation (`/tmp/maluwaf-$UID` would be safer)
- No ownership verification before chmod
- No rejection if another user owns the directory
- Symlink attack possible: attacker pre-creates `/tmp/maluwaf` symlink to their directory

### 3. Unix/Windows Logic Mixing in `pidfile.rs`

**File**: `src/process/pidfile.rs`

- **Line 3**: Unconditionally imports `nix::fcntl::{flock, FlockArg}` which is Unix-only
- **Line 7**: Unconditionally imports `std::os::unix::io::AsRawFd` which is Unix-only
- `try_acquire()` has `#[cfg(unix)]`, `#[cfg(windows)]`, and `#[cfg(not(any(unix, windows)))]` blocks that mix platform logic
- `is_running()` and `check_lock()` mix Unix/Windows code within the same function using `#[cfg]` attributes

### 4. Lock Acquisition Ordering Issue in `OverseerLockFile`

**File**: `src/process/pidfile.rs:388-416`

```rust
pub fn acquire(&mut self) -> Result<(), OverseerLockError> {
    // ...
    let file = File::create(&self.lock_path).map_err(OverseerLockError::IoError)?;  // <-- Truncates first

    match flock(file.as_raw_fd(), FlockArg::LockExclusiveNonblock) {  // <-- Lock acquired after
        Ok(()) => {}
```

**Problem**: `File::create()` truncates the file BEFORE `flock()` is acquired. If:
1. Process A creates/truncates the lock file
2. Process B creates/truncates the same lock file ( Process A hasn't locked yet)
3. Process A acquires lock
4. Process A writes its PID

Process B can overwrite Process A's lock content before Process A's flock is effective. The correct sequence is:
1. Open file WITHOUT truncate
2. Acquire lock
3. Write content / truncate

### 5. Windows `tasklist` Process Existence Check

**Files**: `src/process/pidfile.rs:288-298` and `src/process/pidfile.rs:472-482`

```rust
#[cfg(windows)]
{
    use std::process::Command;
    let output = Command::new("tasklist")
        .args(["/FI", &format!("PID eq {}", content.pid)])
        .output();
```

**Problems**:
- `tasklist` is an external process spawn, slow
- Parses string output which is fragile
- Should use Windows API: `OpenProcess` + `GetExitCodeProcess`

---

## The Symlink Vulnerability Explained

When `metadata()` is called on a path that is a symlink, it follows the symlink and returns metadata of the **target** file/directory, not the symlink itself. This allows an attacker to:

1. Create `/tmp/maluwaf` as a symlink pointing to a directory they own (e.g., `/home/attackercontrolled/maluwaf`)
2. When MaluWAF calls `metadata("/tmp/maluwaf")`, it gets metadata of the attacker's directory
3. MaluWAF then calls `set_permissions(path, 0o700)` on that directory
4. Now the attacker's directory has mode 0o700 - MaluWAF "securified" it, but it was already attacker-controlled

The fix: use `symlink_metadata()` which returns metadata of the symlink itself, then reject if it's a symlink.

---

## The Lock Acquisition Ordering Issue Explained

The sequence in `OverseerLockFile::acquire()`:

```
1. File::create() → opens with truncate → CONTENT ERASED
2. flock() → acquires lock AFTER truncate
```

Problematic timeline:
```
Time 0: Lock file exists with "1234\n5678" (Process A's PID + timestamp)
Time 1: Process B calls File::create() → file now empty (0 bytes)
Time 2: Process A calls flock() → acquires lock on now-empty file
Time 3: Process A writes "5678\n9999" → Process B's PID (but file was already empty!)
```

If Process B acquires flock between steps 1-2, Process A's lock is effectively lost when Process B truncates.

**Correct sequence**:
```
1. OpenOptions::new().write(true).create_new(true).open() WITHOUT truncate
2. flock() → acquire exclusive lock
3. Write content
4. Optionally ftruncate to 0 first, then write (or just write without pre-truncate)
```

---

## Items Not Fully Implemented

1. **Per-UID `/tmp` fallback directory** - The plan suggests `/tmp/maluwaf-$UID` but this was not designed in detail
2. **Windows `OpenProcess`/`GetExitCodeProcess` API** - Would require adding `windows-sys` features, not designed here
3. **Stale lock age reading from lock file content** - Currently uses file modification time; the plan mentions reading actual timestamp from lock content

This is documentation-only per the task requirements.
