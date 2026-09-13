# Track 4 Roadmap: Dependency Security and Capability Segregation

Status: complete (Phases 25-31 landed; closeout evidence in
`architecture/track4_dependency_security_closeout.md`).

Post-closure handoff: `plans/track4_post_closure_corrective.md` is the active narrow corrective pass for plan/security metadata truth, real-time advisory expiry, final bounded fuzz evidence, and the mesh-to-YARA validation trust-path decision. Track 4 architecture remains closed unless that audit discovers a genuinely new boundary defect.

Scope: follow-on work after the completed Track 3 architecture-convergence line. Track 4 is intentionally narrower: reduce security-sensitive dependency authority, make dependency-policy evidence truthful and continuously enforced, and introduce new crates/process boundaries only where they remove a meaningful capability from a broader process or package.

This roadmap is based on a fresh dependency/security review of `main` at `f8a2690ff13f4e8c2c075caa57a265baebea9464` plus current upstream security research dated 2026-09-11.

## Why a new track

Track 3 correctly converged domain ownership and rejected crate creation solely to reduce root LOC. The remaining opportunities are different. Several dependency families themselves confer authority:

- Wasmtime / YARA compilation and guest execution;
- `libloading` and native shared-library execution;
- mesh protocol/signing types currently coupled to the full mesh control plane;
- DNSSEC private-key generation/signing/HSM access;
- root package dependencies whose ownership ledger no longer proves live entitlement.

The target is therefore capability segregation, not another mechanical root-module burn-down.

## Current findings that drive this track

1. `.github/workflows/ci.yml` runs `cargo xtask verify`, but the routine `verify` contract does not run `cargo deny check` or `cargo audit`, despite `SECURITY.md`, release docs, and `deny.toml` treating those checks as part of the security policy.
2. `deny.toml` documents `RUSTSEC-2026-0269` as mitigated for the direct Wasmtime 42.0.2 runtime. Current RustSec/Wasmtime guidance says 37.0.0 through 46.0.2 are affected; patched lines include 46.0.3 and 47.0.4. The advisory is specifically in `wasmtime-wasi` filesystem sandboxing, so direct exploitability must be established from actual feature/reachability evidence rather than assumed either way.
3. YARA compilation exists in more than one authority domain: `synvoid-upload` owns `yara-x`, `synvoid-mesh` directly links `yara-x` and compiles/serializes rules, while the operational YARA jail already provides a bounded out-of-process execution path.
4. `synvoid-plugin-runtime` always declares `libloading` and owns both sandboxed WASM runtime code and explicitly unsafe in-process native extension loading.
5. `synvoid-mesh` remains a very high-capability crate. Protocol/signing vocabulary such as `MeshMessage`/`MeshMessageSigner` is consumed broadly inside mesh and at selected cross-boundary verification sites, but its current home brings the entire mesh dependency graph with it.
6. The root test self-dependency enables default features during nominal `--no-default-features` tests, so mesh/DNS absence behavior is not executed honestly.
7. The root dependency ledger proves manifest/ledger presence, not actual source entitlement. Some owner labels and old facade-era rationales have drifted.
8. At least one pure facade directory (`src/honeypot_port/`) retains dead implementation source below a `pub use synvoid_honeypot::*` facade. Dead security-sensitive source should not survive extraction.
9. CI follows mutable `stable` and mutable third-party Action tags. Rust 1.98.1 was released specifically to repair a 1.98.0 vtable miscompilation, illustrating why a security appliance should deliberately advance a pinned toolchain.

## Explicit non-goals

Do not create `synvoid-admin-server` or `synvoid-waf-runtime` in this track merely to move root code. Phase 21 and Phase 19 already establish those areas as intentional application composition with broad typed fan-in. Revisit only if a future extraction removes a measurable dependency/capability set or gains multiple real consumers.

Do not split `synvoid-mesh` merely because it is large. Phase 27 extracts only the low-level contract surface needed to decouple consumers from the high-capability implementation crate.

Do not replace the existing jail protocol, enforcement contracts, admin mutation authority, or distributed-state semantics. Track 4 builds beneath/around those contracts.

## Phase order

1. **Phase 25 — Dependency security baseline and entitlement closure**
   - Correct Wasmtime advisory handling.
   - Put dependency policy into CI/release verification.
   - Make minimal-feature tests honest.
   - Strengthen root dependency entitlement and stale-source guards.
   - Pin toolchain/tooling/Actions deliberately.

2. **Phase 26 — YARA execution boundary consolidation**
   - Create one canonical YARA engine/contract owner.
   - Remove `yara-x` compilation from mesh and upload-facing orchestration.
   - Route untrusted compilation/scanning through the existing jail boundary.

3. **Phase 27 — Mesh protocol/identity contract extraction**
   - Introduce a low-dependency `synvoid-mesh-protocol` (name may be adjusted after metadata audit).
   - Move stable wire/signing/identity vocabulary without pulling DHT/Raft/SQLite/HTTP/YARA into consumers.

4. **Phase 28 — Unsafe native extension capability isolation**
   - Remove `libloading` from the ordinary WASM/plugin-runtime dependency surface.
   - Put in-process native loading behind an explicit feature/crate boundary and prepare the existing external-client seam for process isolation.

5. **Phase 29 — Jail runtime package/process split**
   - Move child-side WASM/YARA jail services out of the root application crate into an explicit runtime package/binary while preserving the Phase 22 wire protocol and supervisor contract.

6. **Phase 30 — DNSSEC key-custody boundary extraction**
   - Separate private-key generation/signing/HSM/trust-anchor persistence from resolver/server transport logic where the dependency graph supports a clean one-way boundary.

7. **Phase 31 — Dependency-surface closeout and release verification**
   - Recompute the actual workspace dependency graph.
   - Remove residual direct dependencies/facade dead source.
   - Reconcile all ledgers/docs/guards.
   - Re-run package/release/security qualification and decide whether an umbrella SDK crate is justified or should remain deferred.

## Dependency order and safe parallelism

Phase 25 is mandatory first because later phases must operate from a truthful advisory and verification baseline.

Phase 26 should precede Phase 29: first establish one canonical YARA API/engine owner, then move the child executable/runtime boundary without simultaneously changing YARA semantics.

Phase 27 can run in parallel with Phase 26 after Phase 25 lands, provided it does not move YARA or consensus authority into the protocol crate.

Phase 28 can begin after Phase 25 and is independent of mesh protocol extraction. If an out-of-process native host is implemented, reuse proven IPC framing/lifecycle ideas but do not overload the existing WASM/YARA jail protocol with generic execution.

Phase 30 can proceed after Phase 25 and in parallel with Phases 27-29, but must preserve DNS wire/DNSSEC compatibility tests.

Phase 31 runs last.

## Track-wide acceptance criteria

Track 4 is complete only when:

- current known dependency vulnerabilities are either removed or represented by narrow, dated, evidence-backed exceptions;
- routine/release CI cannot silently skip the repository's declared dependency policy;
- `--no-default-features` tests do not gain mesh/DNS through the root self-dev edge;
- direct root dependencies have mechanically checked source entitlement, not only a ledger row;
- YARA compilation/scanning has one canonical owner and network-facing mesh code no longer links the compiler merely to validate/distribute rules;
- ordinary WASM plugin builds do not link native `libloading` capability unless explicitly enabled;
- child jail execution is packaged as an explicit process/runtime boundary rather than root implementation code;
- cross-crate mesh consumers can depend on stable mesh protocol/identity vocabulary without linking the full mesh control plane;
- DNSSEC private-key/HSM dependencies are isolated if the extraction preserves one-way dependency flow and protocol behavior;
- dead facade implementation source is removed and guarded against recurrence;
- `cargo xtask verify`, `verify-full`, and `verify-release` have clearly documented dependency-security responsibilities;
- `architecture/root_dependency_ownership.md`, crate granularity audit, surface audit, and Track 4 closeout evidence agree.

## Rejection criteria

Reject implementation that:

- creates crates only to reduce line counts;
- moves broad root composition into a crate with the same or worse fan-in and calls that isolation;
- weakens existing fail-closed jail behavior;
- keeps vulnerable dependencies by writing an exception without reachability/exposure evidence;
- makes advisory checks permanently non-blocking without a separate blocking release/security gate;
- adds a generic remote-exec operation to jail/native-extension IPC;
- moves Raft/DHT/storage authority into a mesh protocol crate;
- changes DNSSEC algorithms or key lifecycle as an incidental refactor;
- reports completion while root/test feature leakage or dependency-ledger drift remains.

## Primary external security references

- RustSec `RUSTSEC-2026-0269`: https://rustsec.org/advisories/RUSTSEC-2026-0269.html
- Wasmtime `GHSA-vqjp-4c8c-hfgg`: https://github.com/bytecodealliance/wasmtime/security/advisories/GHSA-vqjp-4c8c-hfgg
- Rust 1.98.1 release (vtable miscompilation fix): https://blog.rust-lang.org/releases/latest/
- cargo-deny advisory/source policy: https://embarkstudios.github.io/cargo-deny/

Historical Track 1-3 plans remain authoritative for the behavior they closed. Track 4 must update current architecture evidence rather than rewriting historical result documents.