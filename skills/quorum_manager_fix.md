# Quorum Manager Race Condition Fix

## Problem

The `QuorumManager::start_request()` method had a race condition when delegating writes to Raft:

```rust
// OLD CODE (race condition)
tokio::spawn(async move {
    if let Err(e) = client.raft_write(ns, key, value).await {
        tracing::error!("Raft delegated write failed...");
    }
});

// Pre-inject fake signature - race condition!
let mut approved_req = request.clone();
approved_req.signatures.push(QuorumSignature {
    node_id: "raft-leader".to_string(),
    signature: vec![],
    timestamp: safe_unix_timestamp(),
    signer_public_key: None,
});
```

If the Raft write failed silently, the request would appear complete with a fake signature.

## Solution

Use proper async pattern with oneshot channel:

```rust
pub struct QuorumManager {
    pending_requests: Arc<RwLock<HashMap<String, QuorumRequest>>>,
    pending_raft_requests: Arc<RwLock<HashMap<String, oneshot::Receiver<()>>>>, // NEW
    veto_history: Arc<RwLock<HashMap<String, Vec<RejectedClaim>>>>,
    verification_enabled: bool,
    raft_client: Arc<RwLock<Option<Arc<RaftAwareClient>>>>,
}
```

### Key Changes

1. **Store pending RAFT requests with oneshot::Receiver**:
   ```rust
   let (tx, rx) = oneshot::channel();
   {
       let mut pending_raft = self.pending_raft_requests.write().await;
       pending_raft.insert(request_id.clone(), rx);
   }
   ```

2. **Notify via channel when Raft completes**:
   ```rust
   tokio::spawn(async move {
       let result = client.raft_write(ns, key, value).await;
       // ... log result ...
       let _ = tx.send(()); // Notify completion
   });
   ```

3. **New helper method to check completion**:
   ```rust
   pub async fn is_request_complete(&self, request_id: &str) -> bool {
       let pending_raft = self.pending_raft_requests.read().await;
       if let Some(rx) = pending_raft.get(request_id) {
           rx.is_closed()
       } else {
           true
       }
   }
   ```

4. **Cleanup properly removes raft requests**:
   ```rust
   pub async fn complete_request(&self, request_id: &str) -> Option<QuorumRequest> {
       let mut pending = self.pending_requests.write().await;
       let result = pending.remove(request_id);
       if result.is_some() {
           let mut pending_raft = self.pending_raft_requests.write().await;
           pending_raft.remove(request_id);
       }
       result
   }
   ```

## Files Modified

- `src/mesh/dht/quorum.rs` — Added `pending_raft_requests`, `is_request_complete()`, proper cleanup

## Testing

- `cargo test --lib quorum` — Run quorum tests
- `cargo test --lib -- dht` — Run DHT tests

## Related

See `src/mesh/AGENTS.override.md` for more on Raft integration and quorum patterns.