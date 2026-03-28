# DHT Issues Plan

## Valid Issues Found

### 1. Unbounded PoW Nonce Search (VALID - HIGH PRIORITY)

**Location:** `src/mesh/dht/routing/node_id.rs:138-154`

**Issue:** The `find_pow_nonce` function iterates from 0 to u64::MAX with no iteration limit, causing a potential infinite loop if no valid nonce is found (which would indicate the difficulty is too high or impossible).

```rust
pub fn find_pow_nonce(public_key: &[u8]) -> Option<u64> {
    for nonce in 0..u64::MAX {  // <-- Can loop forever
        // ... hash verification
        if leading_zeros >= (NODE_ID_POW_DIFFICULTY as usize / 8) {
            return Some(nonce);
        }
    }
    None
}
```

**Fix:** Add a maximum iteration limit (e.g., 10 million iterations) before returning None, with a log warning.

**Note:** This is called in a background task every 24 hours (`src/mesh/transport.rs:885-900`) to refresh the node's PoW nonce. If it fails, the node simply warns and retries later.

---

### 2. Hardcoded Timestamp Window (VALID - LOW PRIORITY)

**Location:** `src/mesh/dht/signed.rs:9`

**Issue:** The DHT message timestamp validation window is hardcoded to 300 seconds (5 minutes):

```rust
pub const DHT_MESSAGE_TIMESTAMP_WINDOW_SECS: i64 = 300;
```

This should be configurable via DhtConfig.

**Fix:** Add `timestamp_window_secs` to `DhtConfig` and use it in `validate_message_timestamp`.

---

## Not Valid / Not Issues

### PoW Verification Optional
The optional PoW for peer contacts is by design - it's a defense-in-depth measure, not a hard requirement. The system uses other trust mechanisms (reputation, stake, signatures).

### Stale Peer Detection
The bucket refresh at 60s with 15-minute stale duration is appropriate. The code has `get_stale_peers()` and `get_peers_to_ping()` functions for ping-based eviction.

---

## Summary

| Issue | Priority | Status |
|-------|----------|--------|
| Unbounded find_pow_nonce | High | Valid - needs fix |
| Hardcoded timestamp window | Low | Valid - could be configurable |
| Optional PoW | - | By design, acceptable |
| Stale peer detection | - | Working as intended |