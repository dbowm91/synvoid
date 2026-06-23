---
name: implementation_patterns
description: Common implementation patterns including semaphores, debounce, atomic writes, and worktree workflows.
---

# Implementation Patterns

## Worktree Workflow for Parallel Tasks

When implementing multiple independent fixes:

1. **Create worktrees** for each task to avoid conflicts:
   ```bash
   git worktree add /path/to/worktrees/task-name HEAD
   ```

2. **Each agent works in its own worktree** — never modify the main working directory directly

3. **Merge sequentially** after verification:
   ```bash
   git merge <commit-hash> --no-edit
   ```

4. **Clean up worktrees** after merge:
   ```bash
   git worktree remove --force /path/to/worktree
   ```

## Semaphore Pattern (FastCGI)

**Correct**: Hold permit for function scope
```rust
let _permit = timeout(self.config.connection_timeout, self.semaphore.acquire())
    .await
    .map_err(|_| FastCgiError::ConnectionFailed("Timeout acquiring permit".to_string()))?
    .map_err(|_| FastGError::ConnectionFailed("Semaphore closed".to_string()))?;
// Permit held until function returns
```

**Incorrect**: Drop permit immediately (bypasses concurrency limit)
```rust
let permit = timeout(...).await?;
drop(permit); // BUG: concurrency limit bypassed
```

## SSRF Validation Pattern

Always check both `http://` and `https://` URLs:
```rust
if url_lower.starts_with("http://") || url_lower.starts_with("https://") {
    let host = url
        .strip_prefix("http://")
        .or_else(|| url.strip_prefix("https://"))
        .unwrap_or(url);
    // ... check host for private IPs
}
```

## Cert Strength Validation

When loading certificates from disk, always validate key strength:
```rust
if let Ok(key) = load_private_key(&key_path) {
    if let Err(e) = self.validate_key_strength(&key) {
        tracing::warn!("Certificate for domain '{}' rejected: {}", domain, e);
        continue;
    }
    // ... proceed with key
}
```

## Admin Session Updates

Use single lock for atomic validate+update (eliminates TOCTOU):
```rust
let mut sessions = self.sessions.write().await;
if let Some(session) = sessions.get_mut(&session_id) {
    if session.is_valid() {
        session.last_used = now();
        return Ok(session.clone());
    }
}
```

## Static Response Body Pattern

Always use `Bytes` directly, not `PathBuf`:
```rust
pub enum StaticResponseBody {
    InMemory(Bytes),
    Buffered(Bytes),  // NOT PathBuf — avoids double-read
}
```

## CGI Async Pattern

Use `tokio::process::Command` instead of `std::process::Command`:
```rust
let child = tokio::process::Command::new(&script_path)
    .stdin(std::process::Stdio::piped())
    .stdout(std::process::Stdio::piped())
    .stderr(std::process::Stdio::piped())
    .spawn()?;
// Async stdin/stdout handling
```

## macOS/Linux Conditional Compilation

Use `#[cfg(target_os = "linux")]` for Linux-only APIs (like `/proc/self/fd`):
```rust
#[cfg(target_os = "linux")]
{ /* Linux impl using /proc/self/fd */ }

#[cfg(not(target_os = "linux"))]
{ /* macOS/BSD/Windows fallback */ }
```

## Cert File Reload Debounce

Use inner loop with `needs_reload` flag:
```rust
loop {
    let mut needs_reload = false;
    tokio::select! {
        Some(event) = rx.recv() => { needs_reload = true; }
        else => return,
    }
    while needs_reload {
        needs_reload = false;
        tokio::time::sleep(Duration::from_millis(500)).await;
        while let Ok(_) = rx.try_recv() { /* drain */ }
        load_certificates().await;
        if rx.try_recv().is_ok() {
            needs_reload = true; // Re-check after load
        }
    }
}
```
