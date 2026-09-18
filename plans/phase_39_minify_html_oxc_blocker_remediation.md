# Phase 39 Plan: Minify-HTML / Oxc Resolver Blocker Remediation

Status: planned (2026-09-18).

Roadmap: `plans/runtime_dependency_blocker_followup_roadmap.md`.

Primary goal: eliminate the `minify-html 0.18.1 -> Oxc 0.95 -> bumpalo 3.19` dependency constraint that prevents SynVoid from resolving current YARA-X/Wasmtime releases, while preserving current minification semantics and keeping the workaround temporary.

This is a dependency-compatibility phase, not a minifier rewrite.

## Why this is the next blocker

Current SynVoid has already moved its direct plugin runtime to Wasmtime 36.0.15 LTS. The remaining old Wasmtime line is introduced by YARA-X 1.15.

Attempting to move YARA-X to 1.20 reaches a resolver conflict because:

- `crates/synvoid-static-files` depends on `minify-html = "0.18"`;
- released `minify-html 0.18.1` depends on five Oxc 0.95 crates;
- `oxc_allocator 0.95` depends on workspace `bumpalo` at the 3.19 line;
- modern Wasmtime required by current YARA-X needs the 3.20+ line.

The correct ownership boundary is therefore the static-file minifier dependency, not the plugin runtime.

## Upstream evidence

Record these facts in the implementation closeout and refresh them immediately before coding:

1. `wilsonzlin/minify-html` current release/master dependency versions.
2. PR #270 status and patch intent.
3. Oxc 0.111 `rust-version` and `oxc_allocator` dependency list.
4. Current YARA-X release and its Wasmtime dependency.
5. YARA-X PR #769 or successor status.

As researched on 2026-09-18:

- minify-html remains 0.18.1 with Oxc 0.95;
- PR #270 attempted Oxc 0.111 but did not merge;
- Oxc 0.111 uses Rust 1.91 and `oxc_allocator` no longer has an external `bumpalo` dependency;
- SynVoid pins Rust 1.98.1, so Oxc 0.111's MSRV is acceptable.

## Part A — Reproduce and preserve the baseline

Before changing dependencies, capture:

```bash
cargo tree -i minify-html --workspace
cargo tree -i oxc_allocator@0.95.0 --workspace
cargo tree -i bumpalo@3.19.0 --workspace
cargo tree -i yara-x --workspace
cargo tree -i wasmtime --workspace
cargo audit
cargo deny check
```

In a disposable branch/worktree, reproduce the blocked upgrade:

```bash
cargo update -p yara-x --precise 1.20.0
```

Record the exact resolver diagnostic.

Do not modify the main lockfile merely to prove the failure.

## Part B — Add SynVoid-owned minification parity coverage first

Current coverage proves basic minification, but it is not sufficient to safely change the engine under `minify-html`.

Add focused tests under `crates/synvoid-static-files/tests/` or an equivalent crate-local test module before changing the dependency.

The corpus must include at least:

- ordinary HTML whitespace/comment reduction;
- `<pre>` and `<textarea>` whitespace preservation;
- attribute quoting/entity cases used by existing sites;
- inline classic JavaScript;
- inline `type="module"` JavaScript;
- JS template literals, regex literals, optional chaining, nullish coalescing, and comments;
- inline CSS in `<style>`;
- style attributes where relevant;
- script bodies that are data rather than JavaScript, such as JSON/LD+JSON;
- malformed-but-browser-tolerated HTML currently accepted by the minifier;
- empty documents and fragments;
- UTF-8/non-ASCII text;
- cases where the embedded JS/CSS minifier chooses the original because minification is not smaller.

Use two classes of assertions:

1. exact/golden output for stable representative inputs;
2. semantic invariants for cases where Oxc may legitimately choose different but equivalent formatting.

Do not accept a dependency update solely because output is smaller.

Capture the current 0.18.1 outputs as the baseline before switching.

## Part C — Preferred unblock: minimal compatibility fork

Preferred implementation is a temporary project-controlled fork of the exact released `minify-html 0.18.1` source.

The fork should initially change only:

```toml
oxc_allocator = "0.111"
oxc_codegen = "0.111"
oxc_minifier = "0.111"
oxc_parser = "0.111"
oxc_span = "0.111"
```

Rationale:

- Oxc 0.111 is the first researched line that removes the external `bumpalo` edge from `oxc_allocator`;
- upstream minify-html PR #270 independently selected the same 0.111 target;
- 0.111 minimizes API distance from the existing 0.95 integration;
- jumping directly to Oxc 0.150+ increases compatibility risk without additional value for this blocker.

### Compatibility rule

First attempt must be manifest-only.

If source changes are required to compile against Oxc 0.111:

- keep them limited to direct API adaptation in the minify-html/Oxc integration;
- do not change HTML parsing/minification policy;
- do not add SynVoid-specific behavior;
- preserve upstream public API used by SynVoid: `Cfg` and `minify(&[u8], &Cfg)`;
- document every source delta from the official 0.18.1 tag.

If the required source delta becomes non-trivial, stop and execute the rejection/alternative decision in Part H instead of silently owning a fork.

## Part D — Consume the fork safely

Pin the temporary fork by immutable commit revision.

Preferred dependency shape:

```toml
minify-html = { git = "<project-controlled fork>", rev = "<immutable sha>" }
```

or a root `[patch.crates-io]` entry if that produces a cleaner single-source override.

Do not pin to a moving branch.

Because Phase 38 intentionally tightened source policy, add a narrowly scoped temporary source exception/guard containing:

- owner;
- upstream project and exact base tag;
- immutable fork revision;
- purpose: Oxc/bumpalo resolver unblock;
- upstream issue/PR reference;
- date added;
- review/re-audit date;
- mandatory removal condition.

Removal condition:

> Remove the fork as soon as an official minify-html release eliminates the Oxc 0.95 / external bumpalo 3.19 path and passes SynVoid's parity corpus.

The temporary exception must not normalize arbitrary git dependencies.

## Part E — Prove the blocker is actually removed

After switching to the compatibility fork:

```bash
cargo tree -i minify-html --workspace
cargo tree -i oxc_allocator --workspace
cargo tree -i bumpalo --workspace
cargo tree -e features -i minify-html --workspace
```

Required proof:

- `minify-html` no longer resolves Oxc 0.95;
- no `minify-html -> oxc_allocator -> bumpalo 3.19` path remains;
- any remaining `bumpalo 3.19` instance is classified by its actual consumer rather than assumed to be this blocker.

Then rerun the previously blocked resolver operation:

```bash
cargo update -p yara-x --precise 1.20.0
```

For Phase 39, success means dependency resolution gets past the old bumpalo conflict. Do not commit stock YARA-X 1.20.0 yet if its Wasmtime line remains affected; Phase 40 owns the actual YARA upgrade.

Restore the intended Phase 39 lockfile after the resolver probe if the probe modified it.

## Part F — Minification behavior/performance verification

Run the parity corpus against:

1. released minify-html 0.18.1 baseline;
2. compatibility fork.

Classify every output difference.

Reject unexplained changes in:

- script semantics;
- CSS semantics;
- whitespace-sensitive elements;
- entities/escaping;
- script type handling;
- malformed-input behavior relied on by existing tests.

Capture representative before/after:

- HTML minification throughput;
- inline-JS-heavy page throughput;
- inline-CSS-heavy page throughput;
- output-size delta;
- `synvoid-static-files` build time;
- final release binary size or linked dependency-size delta.

Small performance changes are acceptable if security/dependency unblocking is achieved and semantics are preserved. Material regressions require an explicit decision record.

## Part G — Full project verification

At minimum:

```bash
cargo fmt --all -- --check
cargo test -p synvoid-static-files
cargo test -p synvoid-http
cargo test -p synvoid-repo-guards
cargo check -p synvoid-static-files --all-targets
cargo xtask verify
cargo xtask verify-full
cargo audit
cargo deny check
cargo check --no-default-features
cargo check --no-default-features --features mesh
cargo check --no-default-features --features dns
cargo check --no-default-features --features mesh,dns
```

Pay special attention to the known macOS Oxc/rkyv/linker instability recorded by earlier closeout work. Do not misclassify an unrelated nondeterministic linker failure as semantic minifier breakage.

## Part H — Rejection and fallback path

Reject the compatibility-fork approach if any of the following is true:

- Oxc 0.111 requires broad minify-html source rewrites;
- parity tests find unresolved semantic regressions;
- the fork needs SynVoid-specific behavior;
- binary/build footprint rises materially without a clear benefit;
- supply-chain policy cannot accommodate the temporary pinned source safely.

If rejected, perform a separate minifier replacement decision before coding.

Replacement requirements:

- mature Rust library;
- no external process/runtime;
- explicit HTML semantic preservation;
- safe handling of inline JS/CSS or a design that cleanly delegates those bodies;
- no dependency conflict with current Wasmtime/YARA-X;
- lower or comparable maintenance burden;
- parity corpus passes.

Do not implement a custom HTML parser/minifier in SynVoid as fallback.

## Acceptance criteria

Phase 39 is complete only when:

- the current resolver failure is reproduced and documented;
- SynVoid has crate-local minification parity coverage;
- the selected minify-html compatibility fork is minimal and pinned by immutable revision, or a separately justified replacement is selected;
- `minify-html` no longer resolves Oxc 0.95;
- its external bumpalo 3.19 path is gone;
- a YARA-X 1.20 resolution probe passes the old bumpalo conflict;
- current minification semantics remain acceptable;
- temporary source-policy metadata and removal trigger exist;
- full verification is green.

## Non-goals

Do not:

- upgrade YARA-X to an advisory-bearing final state in this phase;
- move the direct plugin runtime off Wasmtime 36 LTS;
- force all Wasmtime consumers onto one major;
- vendor Oxc wholesale into SynVoid;
- create a SynVoid-specific fork that cannot be upstreamed;
- remove minification features merely to make Cargo resolve.
