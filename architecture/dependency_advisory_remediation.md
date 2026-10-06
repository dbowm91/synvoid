# Dependency Advisory Remediation (2026-10-06)

Record of the three open Dependabot alerts that were resolved on 2026-10-06, the
evidence for each resolution, and the one dev-scope advisory that is **recorded
rather than suppressed** because upstream has no patch.

This is a present-state remediation record. The historical baseline it updates is
`architecture/dependency_security_baseline_phase25.md` (re-audit 2026-10-01);
that document is unchanged by this pass and remains the binding baseline for
`deny.toml` ignore metadata, the `third-party/` fork policy, and the wasmtime
version baseline.

## Scope

GitHub Dependabot reported three `open` alerts on the default branch at the start
of this pass. All three are resolved. `cargo audit` now exits 0 with no
vulnerability findings; the only remaining output is six allowed `unmaintained`
warnings (`atomic-polyfill`, `bincode`, `fxhash`, `proc-macro-error`,
`proc-macro-error2`) that are pre-existing and already tolerated by
`.cargo/audit.toml`.

## Resolved

### 1. `xxhash-rust` — GHSA-6g2r-675j-hx59 (runtime scope, low, CVSS 2.3)

> Safe `xxh3` custom-secret API accepts too-short secret in release.

- Vulnerable range `< 0.8.16`; resolved **0.8.15 → 0.8.19**.
- Arrived transitively, never a direct dependency. `cargo tree -i xxhash-rust`
  shows two distinct parents: `notify` (runtime, reached from
  `synvoid-plugin-runtime`) and `iscc-lib` via `stegoeggo` (license tooling).
  The runtime edge is the one that matters for the `runtime` alert scope.
- Fix was lockfile-only: `cargo update -p xxhash-rust`. **No `Cargo.toml` change
  and no `[patch.crates-io]` entry** — the `[patch.crates-io]` table must keep
  holding exactly `yara-x` and `minify-html` only.
- Verified with `cargo check --workspace --profile ci` (clean) and
  `cargo audit --file Cargo.lock` (exit 0).

### 2. `source-map-js` — GHSA-68fv-2mgg-jv7q / CVE-2026-93749 (dev scope, high, CVSS 7.5)

> Event-loop denial of service through indexed source-map section offsets.

- Vulnerable range `>= 1.0.0, < 1.2.2`; resolved **1.2.1 → 1.2.2**.
- Transitive through `postcss`. `admin-ui/package.json` already declared
  `postcss: ^8.5.23` but the committed `package-lock.json` and `node_modules` had
  drifted to 8.5.10, so the resolved tree did not even satisfy the declared range.
  `postcss` 8.5.10 requires `source-map-js: ^1.2.1`, which permits the vulnerable
  1.2.1.
- Fix: raised the `postcss` devDependency floor to **`^8.5.29`**, the first
  release whose `source-map-js` range is `^1.2.2`. This closes the lockfile
  drift and the advisory in one step.

### 3. `postcss-selector-parser` — GHSA-rj75-hqrm-r3gf / CVE-2026-104844 (dev scope, medium, CVSS 5.9)

> Quadratic complexity in flat selector parsing allows CPU exhaustion.

- Vulnerable range `< 7.1.6`; resolved **6.1.4 → 7.1.6**.
- This is the awkward one. `tailwindcss` 3.4.19 pins
  `postcss-selector-parser: ^6.1.2` and `postcss-nested` 6.2.0 pins `^6.0.2`, so
  no 6.x release satisfies the advisory — the fix exists only on the 7.x line, a
  semver-major jump that npm will not resolve on its own.
- Fix: an npm `overrides` entry in `admin-ui/package.json` forcing
  `postcss-selector-parser: ^7.1.6` for all dependents. This is a deliberate
  semver-major override of a declared peer range, and it was verified rather
  than assumed:
  - `npm run build` (tailwindcss → postcss → autoprefixer) succeeds under 7.1.6.
  - The regenerated `admin-ui/dist/styles.css` was diffed selector-by-selector
    against the committed output: **zero selectors lost, nine added**
    (`.sr-only`, `.bg-blue-500`, `.bg-red-700`, `.opacity-60` and five related
    red/yellow utility variants). All nine are real usage across 15
    `admin-ui/src/**/*.rs` files, which means the committed `dist/styles.css` was
    **stale** rather than the new build being degraded.
  - `admin-ui/dist/` is tracked in git, so the regenerated `styles.css` is
    committed. `dist/index.html` links `styles.css` directly and the Trunk
    bundle is content-hashed, so no WASM rebuild was required.

## Recorded, not suppressed: `braces` — GHSA-vfj7-8cjw-p6xm (dev scope, high)

> Stack-exhaustion denial of service through deeply nested patterns.

- **There is no patched version.** The advisory's vulnerable range is
  `<= 3.0.3` and `first_patched_version` is `null` — `braces` is unmaintained at
  its final release.
- Reachability is build-time only: `tailwindcss` → `chokidar` → `braces`, plus
  `tailwindcss` → `fast-glob` → `micromatch` → `braces`. None of this ships in a
  SynVoid binary; it is the CSS authoring toolchain in `admin-ui/`.
- GitHub has already **auto-dismissed** this alert for that reason. `npm audit`
  still reports it because npm has no auto-dismiss concept.
- No fix is applied, and none is possible without abandoning Tailwind 3.x for
  Tailwind 4.x — a breaking migration of the entire `admin-ui` CSS pipeline
  (`@tailwind` directives, `postcss.config.js` plugin wiring, `tailwind.css`
  input shape) for a build-time-only advisory whose upstream project is dead.
  That trade is not worth making unilaterally; it is recorded here so the
  decision is visible rather than inherited as silence.

**If `braces` must be cleared**, the only available route is a Tailwind 4
migration. Do not add an ignore entry to suppress it — `deny.toml` ignore rules
are Rust-scoped and governed by
`architecture/dependency_security_baseline_phase25.md`, and an npm advisory
cannot be governed there anyway.

## Verification performed

| Check | Result |
|-------|--------|
| `cargo audit --file Cargo.lock` | exit 0, no vulnerabilities; 6 allowed `unmaintained` warnings |
| `cargo check --workspace --profile ci` | clean (pre-existing warnings only, in the vendored `third-party/minify-html-compat` fork) |
| `npm audit` (admin-ui) | 3 targeted advisories gone; `braces` chain remains, unpatched upstream |
| `npm run build` (admin-ui) | succeeds under `postcss-selector-parser` 7.1.6 |
| `dist/styles.css` selector diff | 0 lost, 9 added (all real usage) |
| `[patch.crates-io]` entries | unchanged — still exactly `yara-x` + `minify-html` |
| `deny.toml` ignores | unchanged — still exactly `RUSTSEC-2023-0071` + `RUSTSEC-2026-0235` |

## Recurring-check pointer

`architecture/agent_knowledge_maintenance.md` carries the recurring checklist.
This pass adds one item: dependency advisories must be classified by **scope and
reachability**, not severity alone, before a remediation is chosen — a
build-time-only advisory with no upstream patch is recorded, not suppressed and
not silently ignored.