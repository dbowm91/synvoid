# Post-Phase-35 Runtime and Dependency Security Roadmap

Status: Phase 36 complete; Phase 37 complete (2026-09-17, direct runtime on
Wasmtime 36.0.15 LTS, git patch removed); Phase 38 pending.

This roadmap follows the crate-boundary closeout in Phase 35. The next work is deliberately security- and evidence-driven rather than another decomposition pass.

The research trigger for this roadmap is that the current dependency baseline has two materially different Wasmtime/YARA risks:

1. `synvoid-yara` is pinned to `yara-x 1.15`, while YARA-X <=1.18 is affected by GHSA-2jx3-ff3v-j7jj: the safe `Rules::deserialize` API can accept malformed serialized rule data that leads to memory corruption/undefined behavior. SynVoid currently calls `yara_x::Rules::deserialize(compiled_rules)` in the production YARA reload path, and mesh/upload composition can prefer compiled rule bytes.
2. The direct plugin runtime is pinned to Wasmtime 42.0.2 through a git patch. That line is outside Wasmtime's normal support window and is affected by RUSTSEC-2026-0269, although SynVoid currently proves `wasmtime-wasi` is absent and the vulnerable filesystem capability is unreachable. The previous baseline only evaluated upgrading forward to >=46.0.3 and found the `bumpalo` conflict from `minify-html`/Oxc. Current Wasmtime support policy provides a better option: Wasmtime 36 is an LTS line supported through 2027-08-20, and 36.0.14+ contains the 0269 fix. The current patch release is 36.0.15.

Current upstream facts to re-verify at implementation time:

- YARA-X 1.20.0 is released on crates.io; the unsafe-deserialization advisory is fixed starting in 1.19.0.
- YARA-X 1.20.0 uses Wasmtime 45.0.3 internally. That removes the old 40.0.4 dependency but does not by itself clear RUSTSEC-2026-0269; the same capability-reachability test remains required for the transitive YARA engine.
- Wasmtime 36.0.15 is the current 36 LTS patch release. RUSTSEC-2026-0269 is fixed in 36.0.14 and later on that LTS line.

Authoritative upstream references:

- https://github.com/VirusTotal/yara-x/security/advisories/GHSA-2jx3-ff3v-j7jj
- https://docs.rs/crate/yara-x/1.20.0
- https://rustsec.org/advisories/RUSTSEC-2026-0269.html
- https://github.com/bytecodealliance/wasmtime/security/advisories/GHSA-vqjp-4c8c-hfgg
- https://docs.wasmtime.dev/stability-release.html

## Ordering

Execute in this order:

1. **Phase 36 — YARA-X deserialization exposure closure and engine upgrade**
   - First remove remote/mesh compiled bytes from the executable trust path.
   - Then upgrade `yara-x` from 1.15 to 1.20.x and refresh engine/artifact bindings.
   - Recompute the transitive Wasmtime advisory set instead of retaining the 40.x ignores mechanically.

2. **Phase 37 — Direct Wasmtime migration to the supported 36 LTS line** — DONE 2026-09-17
   (see `plans/phase_37_closeout_results.md`).
   - Replace direct 42.0.2/git ownership with 36.0.15+ LTS if the production plugin ABI and containment controls pass parity.
   - Remove the git patch and source allowlist when no longer necessary.
   - Tighten the direct Wasmtime feature surface only after behavior parity is established
     (evaluated; deferred to a follow-up — parity kept: defaults + `component-model`).

3. **Phase 38 — Security baseline and guard closeout**
   - Recompute `cargo audit`/`cargo deny` state from the final graph.
   - Remove stale advisory ignores and stale direct-version claims.
   - Add regression guards for the YARA compiled-byte boundary and supported Wasmtime ownership.
   - Reconcile security/architecture docs, including the stale mesh overview line that still describes worker mesh supervision as deferred even though Iterations 82/85 implemented it.

## Non-goals

This roadmap does **not** authorize:

- another broad crate decomposition pass;
- a fork of YARA-X or Wasmtime merely to make `cargo audit` visually clean;
- enabling WASI filesystem capabilities in the plugin runtime;
- weakening plugin fuel, epoch, resource, signature, or host-call budgets to ease a Wasmtime migration;
- trusting mesh-provided compiled YARA blobs because they carry a checksum alone;
- replacing source-authenticated YARA distribution with compiled-only distribution;
- changing upload malware-scan fail-closed defaults;
- dropping YARA modules or WASM/plugin features without a consumer audit;
- editing `deny.toml` ignores before the resolved final dependency graph is known.

## Priority rationale

Phase 36 is first because it addresses an API that SynVoid actually invokes with externally originated compiled-rule state. That is a stronger exposure than the direct Wasmtime 0269 finding, where the vulnerable `wasmtime-wasi` filesystem implementation is currently absent from the graph.

Phase 37 is still high priority because the direct plugin runtime should not remain indefinitely on an unsupported normal Wasmtime line plus a git patch when a supported LTS line can satisfy the security requirement without the `bumpalo` conflict that blocks the newer 46+/48 path.

## Roadmap acceptance criteria

This roadmap is complete only when:

- no mesh/remote compiled YARA bytes can flow directly into `yara_x::Rules::deserialize`;
- the YARA engine is on a release that fixes GHSA-2jx3-ff3v-j7jj;
- engine-version/artifact compatibility is explicit and old compiled artifacts fail deterministically;
- the direct Wasmtime runtime is on a supported security-maintained line, or a new implementation-time blocker is recorded with exact API/capability evidence;
- the direct Wasmtime git patch is removed if the LTS migration succeeds;
- advisory ignores match the final graph exactly and carry capability evidence + re-audit metadata where an affected transitive package remains;
- plugin containment semantics are unchanged or strengthened;
- YARA scanning/reload behavior, plugin execution, and release verification remain green;
- docs and repo guards describe the compiled behavior rather than historical intent.
