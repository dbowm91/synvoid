# Quorum Manager Race Condition Fix

## Problem (FIXED 2026-05-22)

The `QuorumManager::start_request()` method had a race condition when delegating writes to Raft:

```rust
// OLD CODE (buggy - always sends unit regardless of result)
let (tx, rx) = oneshot::channel();
tokio::spawn(async move {
    let result = client.raft_write(ns, key, value).await;
    // ... log result ...
    let _ = tx.send(()); // Always sends unit - doesn't indicate success/failure!
});
```

When Raft write failed, `tx.send(())` still fired, causing `is_request_complete()` to return `true` (via `rx.is_closed()`), making the system think the request succeeded when it actually failed.

## Solution Implemented

Use `Result` through the oneshot channel to track actual success/failure:

```rust
pub struct QuorumRequest {
    // ... existing fields ...
    pub raft_write_completed: bool,
    pub raft_write_success: bool,
}
```

### Key Changes

1. **Channel sends Result instead of unit**:
   ```rust
   let (tx, rx) = oneshot::channel::<Result<(), RaftAwareClientError>>();
   tokio::spawn(async move {
       let result = client.raft_write(ns, key, value).await;
       match result {
           Ok(_) => {
               tracing::info!("Raft delegated write succeeded...");
               let _ = tx.send(Ok(()));
           }
           Err(e) => {
               tracing::error!("Raft delegated write failed...");
               let _ = tx.send(Err(e));
           }
       }
   });
   ```

2. **`is_request_complete()` now checks actual result**:
   ```rust
   pub async fn is_request_complete(&self, request_id: &str) -> bool {
       let mut pending_raft = self.pending_raft_requests.write().await;
       if let Some(rx) = pending_raft.get_mut(request_id) {
           if let Ok(result) = rx.try_recv() {
               let success = result.is_ok();
               drop(rx);
               pending_raft.remove(request_id);
               let mut pending = self.pending_requests.write().await;
               if let Some(req) = pending.get_mut(request_id) {
                   req.raft_write_completed = true;
                   req.raft_write_success = success;
               }
               return true;
           }
           false
       } else {
           true
       }
   }
   ```

3. **`check_quorum_completion()` treats failed Raft writes as timeout**:
   ```rust
   if request.threshold_met(total) {
       // ... rejections check ...
       
       if request.raft_write_completed && !request.raft_write_success {
           tracing::warn!(
               "Quorum request {} has successful DHT threshold but failed Raft write - treating as timeout",
               request_id
           );
           return Some(QuorumResult::Timeout { ... });
       }
       
       return Some(QuorumResult::Approved(...));
   }
   ```

## Files Modified

- `crates/synvoid-mesh/src/mesh/dht/quorum.rs` — Changed oneshot to send `Result`, added `raft_write_completed`/`raft_write_success` fields to `QuorumRequest`, updated `is_request_complete()`
- `crates/synvoid-mesh/src/mesh/dht/record_store_message.rs:1319-1345` — `check_quorum_completion()` now checks for Raft write failure

## Testing

- `cargo test --lib quorum` — Run quorum tests
- `cargo test --lib -- dht` — Run DHT tests

## Related

See `crates/synvoid-mesh/src/mesh/AGENTS.override.md` for more on Raft integration and quorum patterns.