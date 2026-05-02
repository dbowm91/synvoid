# Plan: Mockable Clock for TokenBucket Tests

## Problem
`test_token_bucket_basic` and `test_token_bucket_refill` in `src/waf/traffic_shaper/bucket.rs` use `std::thread::sleep()` to simulate time passage, making them flaky and slow.

## Solution
Create a `Clock` trait with `SystemClock` (production) and `MockClock` (testing) implementations.

## Implementation Steps

### Step 1: Add Clock trait to utils.rs
**File:** `src/utils.rs`

Add a `Clock` trait:
```rust
pub trait Clock: Send + Sync {
    fn now_ms(&self) -> u64;
}

pub struct SystemClock;
impl Clock for SystemClock {
    fn now_ms(&self) -> u64 {
        crate::utils::now_ms()
    }
}

pub struct MockClock {
    offset_ms: AtomicU64,
}
impl MockClock {
    pub fn new() -> Self {
        Self { offset_ms: AtomicU64::new(0) }
    }
    pub fn advance(&self, ms: u64) {
        self.offset_ms.fetch_add(ms, Ordering::Relaxed);
    }
    pub fn set(&self, ms: u64) {
        self.offset_ms.store(ms, Ordering::Relaxed);
    }
}
impl Clock for MockClock {
    fn now_ms(&self) -> u64 {
        let base = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        base + self.offset_ms.load(Ordering::Relaxed)
    }
}
```

### Step 2: Modify TokenBucket to use Clock
**File:** `src/waf/traffic_shaper/bucket.rs`

1. Change struct to hold clock as trait object or generic:
   ```rust
   pub struct TokenBucket<C: Clock = SystemClock> {
       capacity: u64,
       available: AtomicU64,
       refill_rate: AtomicU64,
       refill_interval_ms: u64,
       last_refill: AtomicU64,
       clock: C,
   }
   ```

2. Update `new()` to accept clock:
   ```rust
   pub fn new(/*...*/, clock: C) {
       // ...
       last_refill: AtomicU64::new(clock.now_ms()),
       // ...
   }
   ```

3. Update `refill()` to use clock:
   ```rust
   fn refill(&self) {
       let now = self.clock.now_ms();
       // ...
   }
   ```

### Step 3: Update production callers
Find all `TokenBucket::new()` calls in the codebase and ensure they still compile with `SystemClock` as default, OR update them to pass a clock.

### Step 4: Fix tests
**File:** `src/waf/traffic_shaper/bucket.rs`

```rust
#[test]
fn test_token_bucket_basic() {
    let clock = MockClock::new();
    let bucket = TokenBucket::new(100, 50, 100, clock);

    assert!(bucket.try_consume(50));
    assert!(bucket.try_consume(30));
    assert!(!bucket.try_consume(30));

    // Instead of sleep, advance mock clock
    bucket.clock.advance(500);

    assert!(bucket.try_consume(50));
}
```

Remove `#[ignore]` attribute.

### Step 5: Verify compilation and tests
```bash
cargo test --lib test_token_bucket_basic
cargo test --lib test_token_bucket_refill
```

## Files to Modify
1. `src/utils.rs` - Add Clock trait and implementations
2. `src/waf/traffic_shaper/bucket.rs` - Update TokenBucket and tests

## Risks
- Changing `TokenBucket` API may break existing callers
- Need to ensure `TokenBucket` remains `Send + Sync` with mock clock
- `MockClock::now_ms()` must not drift from real time unexpectedly

## Alternative Approach
Use a simpler pattern: store `offset_ms: u64` directly on `TokenBucket` and add a `advance_time()` method only for tests, without a full trait. This avoids trait generics.

**Simpler alternative for TokenBucket:**
```rust
#[cfg(test)]
impl TokenBucket {
    pub fn advance_time(&self, ms: u64) {
        self.last_refill.fetch_sub(ms as i64, Ordering::Relaxed);
    }
}
```

This is less invasive - just add a test-only method. The actual clock trait in utils.rs is still useful for other components.
