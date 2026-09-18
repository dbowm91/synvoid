# Phase 43 Plan: Authentication CPU Isolation and Durable Persistence

Status: detailed handoff plan.

Roadmap: `plans/runtime_truthfulness_security_publication_roadmap.md`.

Baseline: `03cec2235fb250e64c33f29b66258eeb0607cdbc`.

## Primary goal

Prevent CPU-hard password verification from blocking Tokio core executor threads, make authentication persistence crash-safe/fail-closed, and bound persisted audit-state growth.

## Evidence

Current synchronous bcrypt call sites include:

- `synvoid-auth::AuthManager::create_user` hashing;
- `AuthManager::verify_login` verification;
- `synvoid-auth::basic::BasicAuthManager::check_credentials` on the HTTP request path;
- admin bearer-token verification in `synvoid-admin` / root admin handlers;
- dummy bcrypt verification used for timing normalization.

Tokio's `spawn_blocking` documentation explicitly warns that its blocking thread limit is large and recommends a semaphore or other bound for CPU-bound work.

The auth store currently:

- snapshots the full `AuthStore` through a bounded channel;
- writes JSON directly to `auth/store.json`;
- chmods after creation/write on Unix;
- logs parse/read failure and returns `AuthStore::default()`;
- stores `login_logs: Vec<LoginLog>` with no observed retention cap.

A corrupt/truncated authorization database must not silently become an empty database.

## Workstream A — Introduce a bounded password-crypto executor

Add a small executor/service in `synvoid-auth`, for example:

```rust
pub struct PasswordCrypto {
    permits: Arc<Semaphore>,
    acquire_timeout: Duration,
}

pub enum PasswordCryptoError {
    Busy,
    Join,
    Hash,
    Verify,
}
```

Requirements:

- acquire a bounded permit before scheduling CPU work;
- use `tokio::task::spawn_blocking` only after admission;
- hold the permit until the blocking operation completes;
- return typed overload/backend errors;
- do not use unbounded fire-and-forget blocking tasks;
- use the configured bcrypt cost where appropriate;
- never log plaintext passwords/tokens.

Size the default concurrency conservatively relative to CPU-worker/runtime expectations. Make it configurable only if an operator actually needs tuning; otherwise keep it an internal constant with benchmark evidence.

## Workstream B — Convert async auth call sites

Convert `AuthManager::create_user` and `verify_login` to use the executor.

Do not hold `RwLock<AuthStore>` across bcrypt work. Required pattern:

1. take/read the minimum state needed;
2. release the lock;
3. perform hash/verify;
4. reacquire and revalidate mutable state before committing the result.

For login, account lock status and password-hash generation can change while bcrypt runs. Recheck the user identity/hash or use a generation/version field before mutating failed-attempt/session state.

## Workstream C — HTTP Basic Auth async boundary

`BasicAuthManager::authenticate_request` is currently synchronous.

Change the API to async or move verification behind an async request-path adapter. Do not hide `block_in_place` inside the synchronous API.

Preserve existing semantics:

- malformed/missing Basic header fails closed;
- unknown user and wrong password do not leak account existence through large timing differences;
- overload does not authenticate anyone.

Decide whether crypto saturation maps to 401 or 503. Prefer a typed internal result such as `AuthBackendBusy` so HTTP policy can distinguish bad credentials from unavailable authentication without revealing usernames.

## Workstream D — Admin token verification and timing normalization

Avoid performing a real bcrypt verify and then an additional dummy verify for the same failed request if one constant-work verification can provide the intended timing property.

Recommended shape:

- if a bearer token is present, verify it once against the real hash;
- if no token/invalid parse path would otherwise skip bcrypt, verify a dummy input against a dummy hash;
- apply any minimum response-time padding after the bounded crypto operation, without adding a second expensive bcrypt on ordinary invalid credentials.

Keep rate limiting in front of expensive work where current policy permits, but do not create a username/token oracle.

## Workstream E — Atomic auth-store persistence

Refactor persistence to a helper with the same durability discipline already used by the DNSSEC keystore:

1. create auth directory with restrictive permissions;
2. serialize to a uniquely named temp file in the same directory;
3. create the temp file as owner-only from creation time on Unix;
4. write all bytes;
5. `sync_all` the file;
6. atomically rename over the destination;
7. fsync/sync the parent directory where supported/required for rename durability;
8. clean up temp files on failure.

Do not delete/replace the last valid store until the new file is complete.

On Windows, use the safest available same-volume replacement semantics and document the durability difference rather than pretending Unix fsync rules apply identically.

## Workstream F — Corruption/error policy

Change `AuthManager::new` to return a result or add `try_new` and migrate production composition to it.

Existing store present + unreadable/corrupt must be a startup/control-plane error, not "creating new".

If recovery is desired, require an explicit operator action:

- quarantine/copy the corrupt file;
- expose a repair/reset command;
- create a new store only with explicit acknowledgement.

Do not automatically authenticate from partially parsed state.

## Workstream G — Bound audit and snapshot growth

Add a maximum login-audit retention count and, optionally, age.

The bound must apply on insertion, not only when querying `take(limit)`.

Because the entire store is cloned/serialized, an unbounded `login_logs` vector is both disk-growth and write-amplification debt.

Choose a default based on operational usefulness and file-size budget; expose a config knob only if needed. Test exact N/N+1 eviction behavior.

Consider pruning expired sessions before snapshotting so stale sessions do not permanently inflate the file.

## Workstream H — Failure-injection tests

Add tests for:

- bcrypt concurrency never exceeds the configured permit count;
- overload fails closed;
- no auth-store lock held while bcrypt runs;
- wrong password/unknown user timing paths both execute one bounded bcrypt;
- interrupted temp write preserves previous valid store;
- serialization/write/fsync/rename failure preserves previous store;
- corrupt existing store returns an error;
- restrictive permissions are present immediately on Unix;
- login log retention N/N+1;
- expired-session cleanup does not resurrect state.

Use injected filesystem/crypto traits or narrowly scoped test hooks rather than global sleeps where possible.

## Compatibility notes

This phase can change synchronous Basic Auth APIs to async. The crate is not externally supported yet, so prefer the correct boundary now rather than preserving a blocking compatibility wrapper on the request path.

Do not change password hash format incidentally. Existing bcrypt hashes must continue verifying.

Do not migrate to Argon2 in this phase unless a separate compatibility/storage migration is designed.

## Verification

```bash
cargo test -p synvoid-auth --profile ci
cargo test -p synvoid-admin --profile ci
cargo test -p synvoid-http --profile ci
cargo test -p synvoid-waf --profile ci
cargo test --profile ci --test admin_smoke_flow
cargo xtask verify
```

Add a focused benchmark or concurrency test that demonstrates request executor progress while bcrypt work is saturated.

## Acceptance criteria

- No CPU-hard bcrypt operation executes directly on a Tokio core request/control-plane thread.
- Blocking bcrypt work has an explicit concurrency bound and overload behavior.
- Auth state locks are not held across bcrypt.
- A failed/corrupt write cannot destroy the last valid store.
- A corrupt existing store does not silently become an empty auth database.
- Login audit persistence is bounded.
- Existing bcrypt hashes remain compatible.
