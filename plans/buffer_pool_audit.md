# Buffer Pool Audit - Priority 6

**Date**: 2026-05-02
**File**: `src/buffer/pool.rs` (1061 lines)
**Miri**: Not available on `stable-aarch64-apple-darwin`

---

## 1. Unsafe Code Inventory

### A. Treiber Stack (`TreiberStack` lines 65-137)

**Structure**:
```rust
struct TreiberStack {
    head: AtomicPtr<StackNode>,
    len: AtomicUsize,
}

struct StackNode {
    buf: BytesMut,
    next: *mut StackNode,
}
```

**Push (lines 83-105)**:
- `Box::into_raw(Box::new(...))` creates a raw pointer to a new node
- `unsafe { (*node).next = head }` writes to the node's next field
- `compare_exchange_weak` is a CAS loop that links nodes

**Pop (lines 107-127)**:
- Loads head pointer, reads `(*head).next` via unsafe
- On success, immediately `Box::from_raw(head)` - this frees the memory
- Returns the `BytesMut` buf to the caller

### B. Thread-Local Cache Mutation (lines 220-254)

**push_to_array (lines 220-230)**:
```rust
let mut_arr = arr as *const [Option<BytesMut>] as *mut [Option<BytesMut>];
unsafe {
    (*mut_arr)[current_len] = Some(buf);
}
```

**pop_from_array (lines 241-255)**:
```rust
let mut_arr = arr as *const [Option<BytesMut>] as *mut [Option<BytesMut>];
unsafe { std::ptr::replace(&mut (*mut_arr)[new_len], None) }
```

---

## 2. Hazard Analysis

### A. ABA Problem in Treiber Stack

**What is ABA**:
In a lock-free stack, ABA occurs when:
1. Thread A reads pointer `P` pointing to node `N`
2. Thread B pops `N`, frees it, allocates new node `N'` at same address `P`, pushes it
3. Thread A's CAS sees `P` unchanged and incorrectly thinks the stack hasn't changed

**Why the current code is vulnerable**:
- The stack uses `AtomicPtr<StackNode>` for the head
- `compare_exchange_weak` only compares the pointer value
- After `pop()` returns `Box::from_raw(head)`, the memory at that address can be reallocated
- If the same memory address is reused for a new push before another pop, the CAS succeeds with "stale" data

**Concrete scenario**:
1. Thread A: pops node at address `0x1000`, gets `Box::from_raw(0x1000)`, memory is freed
2. Thread B: pushes a new buffer, allocator returns `0x1000` (same address)
3. Thread A: CAS sees head is still `0x1000` (it's a "new" node at same address), links it incorrectly

**Severity**: HIGH - use-after-free is possible under contention

### B. Interior Mutation via Unsafe Cast

**What is interior mutation**:
Taking a shared reference (`&T`) and creating a mutable reference (`&mut T`) through raw pointers, bypassing Rust's borrow checker.

**Why this is unsafe here**:
- `push_to_array` takes `&self` (shared reference)
- It casts `arr: &[Option<BytesMut>]` to `*mut [Option<BytesMut>]`
- It dereferences and writes: `(*mut_arr)[current_len] = Some(buf)`

**The borrow checker violation**:
- `&self` implies no mutable alias exists
- The raw pointer cast creates `&mut [Option<BytesMut>]` from `&[Option<BytesMut>]`
- This is undefined behavior if another alias exists (Rust's "aliasing XOR mutability" rule)

**Why it "works" here**:
- Thread-local: each thread has its own `TLS_CACHE`
- No other references to `self.small` etc. exist during `push`/`pop`
- The `Cell<usize>` for length is used consistently

**Missing invariants**:
- No documentation states "TLS_CACHE is always accessed exclusively by the owning thread"
- No mechanism enforces this invariant (e.g., `Cell` only provides borrow-check-time safety)

**Severity**: MEDIUM - safe in current usage pattern but fragile and undocumented

---

## 3. Current Safety Arguments

### Treiber Stack Safety Claims

The code relies on:
1. `compare_exchange_weak` provides atomicity
2. After `pop()` succeeds, no other thread can observe the old node

**Why these arguments are INSUFFICIENT**:
1. CAS atomicity doesn't prevent memory reuse (ABA)
2. "No other thread observes" is not guaranteed - the popped value is returned while another thread might push a new node at the same address before the returning thread accesses the old node's memory

### Thread-Local Cache Safety Claims

The code relies on:
1. `thread_local!` guarantees thread-exclusive access
2. No concurrent access to the same `TLS_CACHE`

**Why these arguments are INSUFFICIENT**:
1. `thread_local!` only ensures one thread at a time accesses the data
2. The borrow checker doesn't know this - the raw pointer cast creates a raw `&mut` from `&self`
3. Any future code that stores a reference to `TLS_CACHE.small` and calls `push()` would create aliased mutability
4. No unsafe block comments explain the thread-safety invariants

---

## 4. Documented Invariants (None Found)

**Searching for safety documentation**:
- No `SAFETY:` comments on any unsafe block
- No comment on `TreiberStack` explaining ABA prevention
- No comment on `push_to_array` explaining interior mutation rationale
- No documentation on why this custom implementation was chosen over a safe alternative

---

## 5. Alternative Safe Implementations

### Option 1: `parking_lot::Mutex<Vec<BytesMut>>` per shard

```rust
struct TierArena {
    stack: parking_lot::Mutex<Vec<BytesMut>>,
    buf_size: usize,
}
```

**Pros**:
- Trivial to verify correct
- `Mutex` provides safe interior mutability
- `Vec` provides bounds-checked access

**Cons**:
- Lock contention on hot path (but sharded, so may be acceptable)

**Performance**: At 1000K RPS, if lock hold time is < 100ns and contention is low, this may be acceptable. Benchmark required.

### Option 2: `crossbeam-epoch` based GC

**Pros**:
- Proper memory reclamation prevents ABA
- Lock-free performance

**Cons**:
- External dependency
- More complex

### Option 3: Remove thread-local cache entirely

**Pros**:
- Eliminates interior mutation
- Simplifies design
- `BytesMut` is already efficient; pooling may not be needed

**Cons**:
- Loses the TLS fast-path

---

## 6. Recommendation

### Verdict: REPLACE

The current implementation has **documented unsoundness**:

1. **ABA hazard is real**: The Treiber stack can cause use-after-free under contention
2. **Interior mutation is undocumented**: The `thread_local!` pattern provides safety, but this is not explained in code
3. **No safety comments**: Every `unsafe` block lacks `SAFETY:` documentation

### Recommended Replacement

**Use `parking_lot::Mutex<Vec<BytesMut>>` per shard**:

1. Simpler - no raw pointers, no ABA concerns
2. Safe - borrow checker + Mutex provide full safety
3. Fast enough - sharded design limits contention
4. Benchmark first - measure before assuming it's too slow

### Before Replacing

1. Add benchmark for buffer pool (follow `benches/bench_attack_detection.rs` pattern)
2. Establish baseline throughput
3. Implement mutex-based replacement
4. Compare - if regression < 5%, use safe version
5. If regression > 5%, consider `crossbeam-epoch` or keep current with full safety documentation

### Immediate Actions

- [ ] Add `SAFETY:` comments to existing unsafe blocks (document invariants even if keeping current code)
- [ ] Create benchmark for buffer acquire/release
- [ ] Implement mutex-based replacement and benchmark
- [ ] If keeping current code, document ABA prevention strategy

---

## 7. Test Coverage Status

**Existing tests**: 27 tests passing
- Concurrent acquire/release tests (lines 963-982)
- Pool limits tests
- Basic acquire/release patterns

**Missing tests per plan.md**:
- Multi-thread stress with `take_bytes()`, `split_to()`, `advance()`
- Stress tests for ABA scenario
- Miri-compatible subset (not possible without miri)

**Current tests are insufficient** because concurrent tests use only 2 threads and 100 iterations - not enough to trigger ABA race conditions reliably.

---

## 8. Conclusion

The custom buffer pool uses unsafe code in ways that:
1. Create real memory safety hazards (ABA in Treiber stack)
2. Lack documentation explaining safety invariants
3. Can be replaced with a simple safe alternative

**Priority 6 should be implemented**: Replace or heavily document the buffer pool. Given MaluWAF's 1000K RPS target, benchmark-based decision is required, but the starting point should be the safer implementation.