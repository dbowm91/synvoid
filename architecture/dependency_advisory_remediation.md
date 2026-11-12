# Dependency Advisory Remediation (2026-10-06)

Record of the three open Dependabot alerts that were resolved on 2026-10-06, the
evidence for each resolution, and the one dev-scope advisory that is **recorded
rather than suppressed** because upstream has no patch.

This 2026-10-06 record is historical. The binding baseline it updated is
`architecture/dependency_security_baseline_phase25.md`; the current evidence is
its §15 (Phase 01, 2026-11-10). The baseline remains the authority for
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
## Phase 01 production-readiness refresh (2026-11-10)

The 2026-10-06 record above is historical. A later advisory-database update
(2026-10-14 through 2026-10-30) found 53 vulnerabilities; the Phase 01 refresh
remediated all of them by version upgrade, not by suppression:

| Crate family | Landed version | Findings cleared |
|---|---|---|
| `rustls` / `rustls-webpki` | 0.23.46 / 0.103.16 | RUSTSEC-2026-0346…-0349, -0382 |
| `webpki-roots` / `webpki-root-certs` | 1.0.11 / 1.0.11 | RUSTSEC-2026-0381, -0383 |
| `quinn` / `quinn-proto` | 0.11.12 / 0.11.19 | RUSTSEC-2026-0338…-0342 |
| `rusqlite` / `libsqlite3-sys` | 0.41.1 / 0.39.1 | RUSTSEC-2026-0459 |
| `wasmtime` (direct / YARA) | 36.0.20 / 48.0.8 | RUSTSEC-2026-0353…-0364, -0378…-0380, -0422…-0424 |
| `yara-x` | 1.23.0 (official; fork retired) | resolves Wasmtime 48.0.8 + zip 9.0.5 |
| `zip` (runtime paths) | 9.5.0 | RUSTSEC-2026-0367…-0369, -0429 |
| `zstd` / `zstd-safe` / `zstd-sys` | 0.13.4 + 0.14.3 / 7.4.0 + 8.2.0 / 2.1.2 | RUSTSEC-2026-0391, -0395…-0410 |
| `tokio` | 1.54.1 | RUSTSEC-2026-0386 |
| `pulldown-cmark` | 0.13.6 (build-time via prost) | RUSTSEC-2026-0414, -0433 |
| `crypto-bigint` / `ctutils` | 0.7.11 / 0.4.8 (via yara-x 1.23) | RUSTSEC-2026-0387, -0385 |

`cargo audit --file Cargo.lock` now exits 0 with no findings; `cargo deny check`
exits 0. The remaining documented exceptions are:

- `RUSTSEC-2023-0071` (`rsa 0.9.10`, direct DNS/DNSSEC/TLS paths; verify,
  sign and key-parse only, zero decrypt call sites). The yara-x path now uses
  patched `rsa 0.10.0`.
- `RUSTSEC-2026-0235` (`rkyv 0.7.46` via the retained minify-html chain).
- `RUSTSEC-2026-0367/-0368/-0369/-0429` (`zip 3.0.0` as a **build** dependency
  of `utoipa-swagger-ui 9.0.2`; it extracts only the crate's pinned vendored
  archive, never runtime/operator input).
- Six unmaintained-only notices with no patched release (`atomic-polyfill`,
  `basic-toml`, `bincode` 1.3.3 + 2.0.1, `fxhash`, `proc-macro-error`,
  `proc-macro-error2`), each recorded with path/capability/exposure/owner and
  a 2027-04-10 re-audit date in `deny.toml` and `.cargo/audit.toml`.

The npm `braces` decision is unchanged (no upstream patch; dev-only Tailwind
toolchain). Full evidence: `architecture/dependency_security_baseline_phase25.md`
§15.
