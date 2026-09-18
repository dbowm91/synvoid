# SynVoid temporary `yara-x` compatibility fork (Phase 40)

Base: official `yara-x 1.20.0` (crates.io; upstream tag `v1.20.0`,
released 2026-08-24 at https://github.com/VirusTotal/yara-x;
upstream git sha1 `60ad06971467029e77967e59d580cbbe85a1474d` for `lib/`;
`.crate` sha256
`015b06cc60800856d04c3115ef6b7c6cbb95f59f20a9df4358dd2f85f3d5b391`).

Vendored: 2026-09-18 by unpacking the released crate. The vendored
`Cargo.lock` and `.cargo_vcs_info.json` were removed; `Cargo.toml.orig`
is retained as provenance evidence. `Cargo.toml` carries the two-line
Phase 40 delta plus a provenance header (lines marked `SYNVOID-PHASE40`).

## Delta from upstream 1.20.0 (complete)

Manifest-only. No file under `src/` or `build.rs` is modified:

```diff
-rust-version = "1.93.0"
+rust-version = "1.94.0"
-[target.'cfg(not(target_family = "wasm"))'.dependencies.wasmtime]
-version = "45.0.3"
+version = "47.0.4"
```

This is exactly the change proposed by upstream PR #769
("fix(deps): Bump wasmtime and msrv version", branch
`wasmtime-47.0.4-msrv-1.94`; open, unmerged as of 2026-09-18). The fork
does NOT track that contributor branch: it re-applies the same
two-line change to the official 1.20.0 release so the pin is an
immutable in-tree vendor, not a moving git ref.

Verify the delta stays manifest-only after any touch:

```bash
diff -r <fresh yara-x 1.20.0 unpack> third-party/yara-x-compat \
  --exclude=Cargo.toml --exclude=Cargo.lock --exclude=.cargo_vcs_info.json
# expect: no differences
```

## Why not stock 1.20.0

Stock 1.20.0 resolves wasmtime 45.0.3, which is affected by
RUSTSEC-2026-0222 (patched `>=46.0.2,<47.0.0` / `>=47.0.3`) and
RUSTSEC-2026-0269 (patched `>=46.0.3,<47.0.0` / `>=47.0.4`).
Wasmtime 47.0.4 (crates.io, 2026-08-20) is the minimum line patched for
both, and satisfies the remaining wasmtime advisories relevant to the
enabled feature set (`cranelift`+`runtime`, no `wasi`: the April-2026
batch is patched at `>=43.0.1`, RUSTSEC-2026-0114 at `>=44.0.1`).
SynVoid pins Rust 1.98.1, which satisfies wasmtime 47.0.4's
`rust-version = "1.94.0"`. The direct plugin runtime stays on wasmtime
36.0.15 LTS; the two lines are Standard dual-runtime ownership (see the
dependency-security baseline §4/§6).

`rsa 0.9.10` (RUSTSEC-2023-0071, no fixed upgrade upstream) is still
pulled via yara-x `crypto`; that ignore is retained and unrelated.

## Removal

See `Cargo.toml` header and
`architecture/dependency_security_baseline_phase25.md` §11: remove this
fork as soon as an official crates.io yara-x release >= 1.19 resolves a
Wasmtime line patched for all advisories relevant to the enabled
feature set. Enforced by `yara_fork_is_temporary_guard`.
