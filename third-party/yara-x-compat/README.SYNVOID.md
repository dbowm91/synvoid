# SynVoid temporary `yara-x` compatibility fork (Phase 40; Phase 103 Wasmtime 48 LTS security delta)

Base: official `yara-x 1.20.0` (crates.io; upstream tag `v1.20.0`,
released 2026-08-24 at https://github.com/VirusTotal/yara-x;
upstream git sha1 `60ad06971467029e77967e59d580cbbe85a1474d` for `lib/`;
`.crate` sha256
`015b06cc60800856d04c3115ef6b7c6cbb95f59f20a9df4358dd2f85f3d5b391`).

Vendored: 2026-09-18 by unpacking the released crate (Phase 40). The
vendored `Cargo.lock` and `.cargo_vcs_info.json` were removed;
`Cargo.toml.orig` is retained as provenance evidence. `Cargo.toml`
carries the Phase 40 + Phase 103 manifest deltas plus a provenance
header (lines marked `SYNVOID-PHASE40` and `SYNVOID-PHASE103`).

## Delta from upstream 1.20.0 (complete)

Manifest-only. No file under `src/` or `build.rs` is modified:

```diff
-rust-version = "1.93.0"
+rust-version = "1.95.0"
 [target.'cfg(not(target_family = "wasm"))'.dependencies.wasmtime]
-version = "45.0.3"
+version = "48.0.3"
```

Phase 103 advanced from the Phase 40 wasmtime 47.0.4 / rust-version
1.94.0 line because 47.0.4 is affected by RUSTSEC-2026-0315
(exponential fuel amplification in `call_ref` / exception `catch`) and
RUSTSEC-2026-0316 (dynamic component-record lifting fuel-limit bypass).
Wasmtime 48.0.3 (48 LTS line, supported for 24 months from 2026-06-04,
`rust-version = "1.95.0"`) is the minimum line patched for both. The
fork does NOT track any contributor's PR branch: it re-applies the
manifest delta as an immutable in-tree vendor, not a moving git ref.
Phase 40's reference to upstream PR #769 is now historical (PR #769
was closed-unmerged on 2026-09-22); the fork does not depend on it.

Verify the delta stays manifest-only after any touch:

```bash
diff -r <fresh yara-x 1.20.0 unpack> third-party/yara-x-compat \
  --exclude=Cargo.toml --exclude=Cargo.lock --exclude=.cargo_vcs_info.json
# expect: no differences
```

## Why not stock 1.20.0 / 1.21.0

- Stock `1.20.0` (crates.io) resolves wasmtime 45.0.3, which is
  affected by RUSTSEC-2026-0222 (patched `>=46.0.2,<47.0.0` /
  `>=47.0.3`) and RUSTSEC-2026-0269 (patched `>=46.0.3,<47.0.0` /
  `>=47.0.4`).
- Stock `1.21.0` (released 2026-09-29) still resolves
  `wasmtime ^45.0.3` (verified via crates.io dependency API) and
  therefore does NOT clear 0222 or 0269, let alone the Phase 103
  findings 0315 / 0316. It does not satisfy the removal condition.
- Wasmtime 48.0.3 (crates.io, 48 LTS line) is the minimum line
  patched for 0315 / 0316 (severity medium / low respectively), and
  satisfies the rest of the enabled-feature advisory set
  (`cranelift`+`runtime`, no `wasi`: 0222 patched at `>=48.0.3`,
  0269 patched at `>=48.0.3`, 0114 patched at `>=44.0.1`, the
  April-2026 batch patched at `>=43.0.1`). SynVoid pins Rust 1.98.1,
  which satisfies wasmtime 48.0.3's `rust-version = "1.95.0"`.
- The direct plugin runtime stays on wasmtime 36.0.16 LTS (Phase 103:
  in-line LTS patch from 36.0.15 to clear RUSTSEC-2026-0316); the two
  lines are Standard dual-runtime ownership (see the dependency-security
  baseline §4/§6/§12).

`rsa 0.9.10` (RUSTSEC-2023-0071, no fixed upgrade upstream) is still
pulled via yara-x `crypto`; that ignore is retained and unrelated. Its
re-audit is recorded in `deny.toml` and
`architecture/dependency_security_baseline_phase25.md` §11/§12.

## Removal

See `Cargo.toml` header and
`architecture/dependency_security_baseline_phase25.md` §11/§12:
remove this fork as soon as an official crates.io yara-x release
>= 1.19 resolves a Wasmtime line patched for all advisories relevant
to the enabled feature set (currently >= 48.0.3 for
RUSTSEC-2026-0315 / -0316, or a supported LTS successor). Enforced by
`yara_fork_is_temporary_guard`.
