# Phase 42 Plan: Shared-Memory Unsafe-Boundary Hardening

Status: implemented and closed; retained as historical handoff detail.

Roadmap: `plans/runtime_truthfulness_security_publication_roadmap.md`.

Baseline: `03cec2235fb250e64c33f29b66258eeb0607cdbc`.

## Primary goal

Make `synvoid-upstream::shared_state` a small, auditable unsafe boundary whose memory layout, file sizing, alignment, index arithmetic, and cross-process assumptions are checked in release builds and independently testable.

## Current risk surface

`SharedConnectionTable::new(path, max_workers, max_backends)` currently computes:

```rust
let heartbeats_size = max_workers * 8;
let connections_size =
    max_workers * max_backends * std::mem::size_of::<AtomicUsize>();
let total_size = header_size + heartbeats_size + connections_size;
```

before truncating/mapping the file. `SharedRateLimitTable::new` similarly multiplies slot counts.

The table then constructs `&AtomicU64` / `&AtomicUsize` from mmap pointer offsets. Some alignment checks are `debug_assert!`, so release correctness depends on assumptions not enforced at the unsafe boundary.

`SharedRateLimitTable::get_mmap()` exports the raw mutable mapping and can bypass layout invariants.

The current production caller uses small fixed values, which reduces immediate exposure, but the constructors are public and the unsafe implementation should not rely on caller discipline.

## Workstream A — Introduce checked layout value types

Create private or narrowly public layout structs for connection and rate-limit regions. Construct them only through validated constructors using `checked_add`, `checked_mul`, and checked ceil/rounding logic.

Reject:

- zero dimensions if runtime behavior is undefined;
- arithmetic overflow;
- total lengths that cannot convert to `u64`;
- lengths above an explicit implementation/resource ceiling;
- offsets not aligned for the element type.

Use typed errors or `io::ErrorKind::InvalidInput`; do not panic for caller-controlled dimensions.

All index-to-byte-offset calculations must reuse the layout object and checked helpers rather than duplicating formulas.

## Workstream B — Release-mode pointer preconditions

Before every unsafe reference construction, prove:

1. requested element index is in range;
2. byte offset plus element size is within mmap length;
3. pointer address satisfies `align_of::<T>()`;
4. mapped region is initialized for the type being exposed.

Convert debug-only alignment assertions to runtime validation at construction. Once construction proves whole-region invariants, per-access checks can be minimized to bounds plus a documented safety proof.

Add `// SAFETY:` comments immediately adjacent to every unsafe block describing which constructor invariant makes it sound.

## Workstream C — Atomic initialization and header ownership

Do not create non-atomic writes that race with readers.

Define startup ownership explicitly: the supervisor must fully initialize/truncate/map the region before workers receive/access it.

If workers map/open the same file independently elsewhere, inventory that code and verify header/version/length before use.

Add a format/version marker if the mapping can be opened by independently versioned processes during upgrade handoff. If mappings are recreated on every supervisor generation and never reused across binary versions, document that non-persistence contract instead.

## Workstream D — Cross-process atomic support decision

The implementation uses mmap to share standard atomics across worker processes. Record an architecture decision that answers:

- supported operating systems/architectures;
- whether the implementation relies on hardware cache-coherent process-shared mappings;
- whether `AtomicUsize` width differences matter during upgrades;
- whether mixed-version/mixed-architecture access is impossible by construction;
- required mapping type (shared, writable);
- required ordering semantics.

If the project cannot justify this as a supported contract on a target, replace that target's implementation with an OS-supported process-shared primitive or disable this optimization there.

Do not introduce a portability crate merely to rename the same assumption.

## Workstream E — File/path hardening

Audit the runtime directory guarantees from `synvoid-platform::PlatformPaths`.

At minimum:

- ensure the shared-state directory is owner-controlled;
- reject or safely replace symlink/non-regular file targets where feasible;
- create files with restrictive permissions from creation time on Unix;
- do not follow an attacker-controlled path from config;
- decide whether stale files are always truncated or version-validated.

Reuse platform primitives rather than reimplement secure-directory logic.

## Workstream F — Narrow the public escape hatches

Search all users of `SharedConnectionTable::new`, `SharedRateLimitTable::new`, `get_mmap()`, and direct knowledge of table offsets.

If `get_mmap()` is used only by root WAF code for counter manipulation, replace it with narrowly typed accessors or a dedicated counter-array facade. Raw `MmapMut` should not be the normal API.

Do not move the mmap implementation into `synvoid-rate-limit`; Phase 33 deliberately kept unsafe/process policy out of that std-only mechanism crate.

## Tests

Add pure layout tests:

- zero dimensions;
- one-by-one minimum;
- current production sizes;
- `usize::MAX` dimensions;
- multiplication/addition overflow;
- dirty-bit ceil boundaries 31/32/33;
- alignment for every region;
- last valid and first invalid index;
- platform-dependent `AtomicUsize` size.

Add mmap behavior tests:

- initialized header round-trip;
- counters visible between independently opened handles/processes where supported;
- invalid/truncated file rejected rather than referenced;
- no panic on invalid dimensions;
- stale/wrong version rejected if versioning is introduced.

Prefer a small child-process integration test for the process-sharing contract rather than only two handles in one process.

## Verification

```bash
cargo test -p synvoid-upstream --profile ci
cargo test -p synvoid-platform --profile ci
cargo test -p synvoid --profile ci --test integration_test
cargo clippy -p synvoid-upstream --all-targets -- -D warnings
cargo xtask verify
```

Run relevant target checks for every platform on which the shared-memory implementation is claimed supported.

## Acceptance criteria

- No mmap size or offset arithmetic can wrap.
- Unsafe atomic references depend only on release-mode validated invariants.
- Invalid layout input returns a typed error; it does not panic or truncate an unintended size.
- Raw mutable mmap exposure is removed or precisely justified.
- Cross-process atomic support is documented and behavior-tested on claimed targets.
- Shared-state files inherit the runtime directory's secure ownership contract.
- `synvoid-rate-limit` remains free of mmap/process-specific policy.

## Closeout (Phase 48)

Implemented in `0026e934e49b`. Binding: `architecture/shared_memory_atomic_contract.md`. Campaign closeout: `architecture/runtime_truthfulness_security_publication_closeout.md`.
