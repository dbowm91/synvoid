# Public Crate Release Policy (Phase 47, binding)

Status: binding for any crate promoted to externally supported (class 3).
Plans: `plans/phase_47_public_crate_release_readiness.md`.
Readiness evidence: `architecture/public_crate_release_readiness_phase47.md`.

Class vocabulary (from Phase 35, unchanged):

- 1 = application-internal;
- 2 = reusable workspace library with **no** external support promise;
- 3 = externally supported library (crates.io support promise);
- 4 = compatibility facade/transitional.

Only class 3 crates carry a support promise. Every other `synvoid-*` crate
is class 1 or 2 however "reusable" it looks. No `publish = false` is added
for internal crates (Phase 35 documented policy, retained): internal-only
status is documented, not enforced by registry churn.

## 1. Pre-1.0 semver expectations

All SynVoid library crates are pre-1.0 (`0.x`). Within `0.x`:

- patch bumps are compatible fixes only;
- minor bumps may extend the API in backwards-compatible ways;
- minor bumps must never silently change documented behavior, wire formats,
  or serialized layouts — those go through the compatibility rules below.

## 2. Compatibility classification

Every class 3 crate documents which surface falls in each bucket:

| Bucket | Semver-guaranteed? | Examples |
|--------|-------------------|----------|
| Public stable API | Yes (within §1) | documented functions, types, traits, error variants |
| Experimental feature-gated API | No — may change behind its feature | anything behind a non-default Cargo feature |
| Wire format | Only under the crate's wire-version policy | mesh envelopes, framing layouts |
| Serialized data | Only as documented per format | postcard-stable structs vs debug JSON |
| Behavior / performance | Never | timings, hash slot values, eviction order, log text |

Anything not listed as stable in the crate README/rustdoc is not stable.

## 3. MSRV rules

- A class 3 crate declares `rust-version` equal to the lowest toolchain with
  **build + test evidence from the packaged tarball outside the workspace**
  (Workstream C). The repository pinned toolchain (1.98.1) is newer and is
  not automatically any crate's MSRV.
- MSRV is never lowered for marketing: lowering requires re-running the
  packaged-tarball evidence on the older toolchain.
- Raising MSRV is a minor-bump-compatible change only if announced in the
  crate changelog; dependents pin by version as usual.

## 4. Promotion bar (class 2 → 3)

A crate may be promoted only when **all** hold (Phase 47 acceptance criteria):

1. API purpose is independently useful, not just a SynVoid implementation seam.
2. No hidden root/runtime requirement (`cargo tree`, packaged-tarball build
   outside the workspace, no root-relative config paths, no undocumented env
   vars, no unavailable `path =` deps, sensible feature defaults).
3. MSRV declared and tested per §3.
4. Semver/wire compatibility policy written (crate README + this policy).
5. Consumer-oriented docs and runnable examples; no phase-history narrative
   as the primary user-facing description.
6. Deterministic tests for security/performance invariants relevant to the crate.
7. Registry and maintenance burden explicitly justified.

Promotion may conclude that zero crates qualify, or exactly one. There is no
quota.

## 5. Verification envelope for a class 3 crate

```bash
cargo test -p <crate> --profile ci
cargo test -p <crate> --doc --profile ci
cargo doc -p <crate> --no-deps            # with RUSTDOCFLAGS="-D warnings"
cargo package -p <crate> --allow-dirty
cargo publish -p <crate> --dry-run
```

Plus the packaged-tarball MSRV build/test on the declared toolchain, and
`cargo deny check` / `cargo audit` for security-sensitive crates. Routine CI
stays proportional (`cargo xtask verify` + repo guards); full publication
qualification lives in `cargo xtask verify-release`, which never publishes.

## 6. Release ordering

Class 3 crates with no internal workspace dependencies publish
independently. A later class 3 crate depending on another SynVoid crate
requires a released registry version and uses `version + path` during
workspace development. The externally supported order is recorded in
`docs/releasing.md` separately from the technical package order.

## 7. Name and ownership

Before first registry publication: verify crates.io name availability,
repository metadata, and intentional maintainers/owners. Do not rename after
publishing without a compatibility/deprecation plan.
