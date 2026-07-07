# Milestone A Phase 3: Bounded YARA Execution and Atomic Rule Reloads

## Objective

Make YARA scanning safe under hostile upload load and make rule reloads non-disruptive. Scans must be bounded by configured concurrency and queue limits, and rule reloads must use immutable generations rather than a global lock held for the duration of scanning.

This phase should land after Phase 1 and Phase 2. Once scan failure semantics and scan coverage are correct, the next production risk is resource exhaustion from expensive scans and reload contention.

## Current risk summary

`YaraScanner::scan_bytes` currently clones the entire input into a `Vec`, spawns a blocking scan, then applies a timeout to the oneshot receiver. If timeout fires, the blocking scan continues in the background. This means an attacker can create latent work after the request path has returned. Under sufficient load, these continuing blocking tasks can exhaust the blocking pool and consume memory/CPU.

The scanner also stores `Rules` behind an `RwLock`. Each scan takes a read lock and holds it while scanning. Reload takes a write lock. Long-running scans can therefore delay reloads, and timed-out scans may continue holding the read lock after the caller has already received a timeout.

## Desired behavior

YARA execution should be controlled by a bounded executor:

- Maximum active scans.
- Maximum queued scans.
- Optional per-site or per-path limits.
- Timeout behavior that is explicit and tied to Phase 1 failure policy.
- Metrics for queue pressure and scan duration.

Rule reloads should use immutable generations:

- Compile or deserialize new rules off-path.
- Verify version/hash/provenance before activation.
- Atomically swap the active rule generation.
- Keep last-known-good generation available if reload fails.
- Scans clone the current generation and do not hold a global lock for the whole scan.

## Implementation plan

### Step 1: Introduce scan executor configuration

Add config fields to upload/YARA config. Suggested names:

```toml
[upload]
yara_max_concurrent_scans = 4
yara_max_queued_scans = 64
yara_queue_timeout_ms = 1000
yara_timeout_ms = 30000
```

Defaults should be conservative. On low-power targets, `yara_max_concurrent_scans` should be small. It is better to fail according to policy than to create unbounded CPU contention.

### Step 2: Add a bounded scan executor

Create a small executor wrapper owned by `YaraScanner` or `MalwareScanner`:

- Use a semaphore for active scans.
- Optionally use a bounded channel if scan requests should queue before acquiring a permit.
- Apply queue timeout separately from scan timeout.
- If queue admission fails, return a scan-indeterminate error that Phase 1 policy can handle.

A simple first pass can acquire a semaphore permit with timeout before `spawn_blocking`. If the permit is unavailable, return `YaraError::QueueFull` or `YaraError::QueueTimeout`.

Add error variants:

```rust
QueueFull,
QueueTimeout,
ExecutorClosed,
```

### Step 3: Avoid unbounded copies

The current code clones `data` before spawning. For byte-slice scans this may be unavoidable because the blocking task needs owned data, but it should occur only after queue admission. Do not allocate a full copy before knowing a scan slot is available.

For large-file Phase 2 paths, prefer file-backed scan APIs or explicitly bounded window buffers. Avoid copying full uploads multiple times.

### Step 4: Replace scan-held rule lock with immutable generations

Create a rule generation struct:

```rust
pub struct YaraRuleGeneration {
    pub rules: Rules,
    pub version: Option<String>,
    pub hash: String,
    pub loaded_at: DateTime<Utc>,
}
```

Store it as an atomic `Arc` pointer. `arc-swap` is already present in the root workspace dependencies; use it if available to the upload crate or add it locally if appropriate.

Candidate shape:

```rust
active_rules: ArcSwap<YaraRuleGeneration>
```

Scan path:

1. Clone/load current `Arc<YaraRuleGeneration>`.
2. Build `Scanner::new(&generation.rules)` inside blocking task.
3. Scan using that generation.
4. Report generation version/hash with results.

Reload path:

1. Load/compile/deserialize candidate rules without modifying active generation.
2. Compute hash/version.
3. Optionally run a smoke-test scan/compile validation.
4. Atomically store the new generation.
5. Keep previous generation alive for in-flight scans.

### Step 5: Add last-known-good behavior

If reload fails, retain the current generation and return/log a reload failure. Do not leave the scanner in an empty or partially updated state.

If external compiled rules fail to deserialize, reject them and keep the previous generation. If source rules fail to compile, same behavior.

### Step 6: Add metrics

Add metrics for:

- `synvoid.yara.scan.active`
- `synvoid.yara.scan.queue_wait_ms`
- `synvoid.yara.scan.duration_ms`
- `synvoid.yara.scan.timeout`
- `synvoid.yara.scan.queue_timeout`
- `synvoid.yara.scan.error`
- `synvoid.yara.reload.success`
- `synvoid.yara.reload.failure`
- `synvoid.yara.rule_generation.active`

Keep cardinality low. Do not attach raw rule names for every metric label.

## Tests

Minimum tests:

1. Concurrency limit prevents more than configured active scans.
2. Queue timeout returns an explicit queue timeout error.
3. Scan timeout follows Phase 1 failure policy at validator level.
4. Reload succeeds while scans are in flight and new scans use the new generation.
5. In-flight scans continue using the old generation safely.
6. Failed reload preserves last-known-good rules.
7. Compiled-rule deserialization failure does not clear active rules.
8. Source-rule compilation failure does not clear active rules.
9. Scan data is copied only after scan admission, if this is easy to assert structurally.

Use controlled test rules and small synthetic payloads. For concurrency tests, inject a fake scanner or test hook that blocks until released.

## Operational considerations

The timeout cannot forcibly terminate arbitrary CPU work running in a Rust blocking task unless the underlying scanner supports cancellation. Therefore the most important control is admission: do not allow unbounded scans to start. Timeout should be treated as a request-level outcome, not proof that CPU work has stopped.

If YARA-X exposes scan limits or cancellation primitives in the future, wire them into this executor. Until then, semaphore-limited execution is required.

## Documentation updates

Document the YARA executor knobs and recommended defaults for:

- low-power Raspberry Pi style deployment
- typical VPS deployment
- high-throughput upload-heavy deployment

Clarify that queue exhaustion follows the scan failure policy from Phase 1.

## Success criteria

- YARA scans cannot be spawned without first passing bounded admission control.
- Scan input allocation happens after admission where practical.
- Timed-out scans cannot accumulate without bound.
- Rule reloads do not wait on a global scan-held `RwLock`.
- Reload failures preserve the last-known-good generation.
- Metrics expose scan pressure and reload health.

## Non-goals

- Do not change malware rule content in this phase.
- Do not implement rule signatures or dependency policy here; that is Phase 4.
- Do not implement archive traversal here.
- Do not change honeypot or tarpit code here.

## Handoff checklist

- [ ] Add YARA executor config fields.
- [ ] Add bounded scan admission using semaphore and/or queue.
- [ ] Add queue timeout and queue-full error variants.
- [ ] Ensure Phase 1 policy handles executor errors.
- [ ] Move scan input cloning after scan admission where practical.
- [ ] Replace rule `RwLock<Rules>` scan path with immutable generation pointer.
- [ ] Implement atomic reload and last-known-good behavior.
- [ ] Add metrics for active scans, queue wait, scan duration, timeouts, and reloads.
- [ ] Add concurrency, timeout, and reload tests.
- [ ] Run `cargo test -p synvoid-upload`.
- [ ] Run relevant workspace tests after integration.
