# Releasing SynVoid

This document defines the manual crates.io publication process for SynVoid workspace crates. Publication is always manual through `cargo publish`. GitHub Actions does not publish, approve, qualify, schedule, or assemble releases.

## Binding Rules

- Publication is manual through `cargo publish`.
- Release cadence is decided by the maintainer.
- GitHub Actions does not publish, approve, qualify, schedule, or assemble releases.
- Version tags do not trigger workflows.
- GitHub releases are optional and manual.
- crates.io is the authoritative package distribution channel.
- Published crate versions are immutable. A failed publication is corrected with a new version.

## 1. Publishable Crates

The following workspace members are publishable to crates.io. Nonpublishable crates (`publish = false` or internal-only) are excluded.

### Nonpublishable crates

| Crate | Reason |
|-------|--------|
| `synvoid-fuzz` | Fuzz testing harness |
| `xtask` | Build tooling |
| `admin-ui` | WASM frontend (not a library crate) |
| `synvoid-repo-guards` | Architecture guard tests |
| `myapp-dynamic` | Example plugin |
| `my-waf-app` | Example application |

### Publication order (dependency order)

Crates must be published in this exact order. Each crate's path dependencies must already be available on crates.io before publishing it.

| # | Crate | Path Dependencies |
|---|-------|-------------------|
| 1 | `pqc` | *(none)* |
| 2 | `synvoid-utils` | *(none)* |
| 3 | `synvoid-platform` | *(none)* |
| 4 | `synvoid-core` | *(none)* |
| 5 | `synvoid-cli` | *(none)* |
| 6 | `synvoid-filter` | *(none)* |
| 7 | `synvoid-proxy-cache` | *(none)* |
| 8 | `synvoid-config` | pqc |
| 9 | `synvoid-theme` | synvoid-config |
| 10 | `synvoid-challenge` | synvoid-theme, synvoid-utils |
| 11 | `synvoid-http-client` | synvoid-config, synvoid-core |
| 12 | `synvoid-app-server` | synvoid-utils, synvoid-http-client |
| 13 | `synvoid-tls` | synvoid-config |
| 14 | `synvoid-plugin-runtime` | synvoid-utils |
| 15 | `synvoid-integrity` | pqc |
| 16 | `synvoid-geoip` | synvoid-config, synvoid-http-client |
| 17 | `synvoid-upstream` | synvoid-utils, synvoid-http-client |
| 18 | `synvoid-proxy` | synvoid-core, synvoid-config, synvoid-http-client, synvoid-upstream, synvoid-proxy-cache, synvoid-waf, synvoid-utils, synvoid-static-files, synvoid-plugin-runtime, synvoid-platform, synvoid-metrics |
| 19 | `synvoid-tunnel` | synvoid-config, synvoid-upstream, synvoid-utils |
| 20 | `synvoid-mesh` | synvoid-core, synvoid-config, synvoid-utils, synvoid-integrity, synvoid-geoip, synvoid-tls, synvoid-tunnel, synvoid-proxy, synvoid-proxy-cache, synvoid-serverless, pqc |
| 21 | `synvoid-waf` | synvoid-core, synvoid-utils, synvoid-challenge, synvoid-config |
| 22 | `synvoid-metrics` | synvoid-core, synvoid-utils, synvoid-waf |
| 23 | `synvoid-ipc` | synvoid-config, synvoid-utils, synvoid-platform, synvoid-metrics, synvoid-tls |
| 24 | `synvoid-block-store` | synvoid-config, synvoid-core, synvoid-utils, synvoid-waf, synvoid-mesh |
| 25 | `synvoid-serverless` | synvoid-config, synvoid-plugin-runtime |
| 26 | `synvoid-app-handlers` | synvoid-core, synvoid-config, synvoid-serverless, synvoid-plugin-runtime, synvoid-http-client |
| 27 | `synvoid-static-files` | synvoid-config, synvoid-ipc, synvoid-theme, synvoid-utils, synvoid-app-handlers |
| 28 | `synvoid-honeypot` | synvoid-config, synvoid-utils, synvoid-http-client, synvoid-mesh |
| 29 | `synvoid-upload` | synvoid-config, synvoid-utils, synvoid-http-client, synvoid-platform, synvoid-app-handlers, synvoid-mesh |
| 30 | `synvoid-admin` | synvoid-core, synvoid-config, synvoid-ipc, synvoid-waf, synvoid-metrics, synvoid-static-files, synvoid-app-server |
| 31 | `synvoid-http` | synvoid-core, synvoid-config, synvoid-metrics, synvoid-waf, synvoid-challenge, synvoid-http-client, synvoid-app-server, synvoid-app-handlers, synvoid-proxy, synvoid-upload, synvoid-plugin-runtime, synvoid-utils, synvoid-mesh, synvoid-serverless, synvoid-static-files, synvoid-ipc |
| 32 | `synvoid-http3` | synvoid-core, synvoid-config, synvoid-http, synvoid-http-client, synvoid-proxy, synvoid-waf, synvoid-metrics, synvoid-platform |
| 33 | `synvoid-dns` | synvoid-core, synvoid-mesh, synvoid-config, synvoid-tls, synvoid-utils, synvoid-geoip |
| 34 | `synvoid-icmp-filter` | *(none)* |
| 35 | `synvoid-tarpit` | *(none)* |
| 36 | `synvoid-vpn-client` | synvoid-config, synvoid-tunnel, synvoid-platform, synvoid-utils |
| 37 | `synvoid-testkit` | synvoid-core, synvoid-config |
| 38 | `synvoid` | *(root — all workspace crates)* |
| 39 | `synvoid-wasm-pow` | *(none)* |

## 2. Package Metadata Requirements

Every publishable crate must have these Cargo.toml fields:

| Field | Source | Notes |
|-------|--------|-------|
| `name` | Crate-level | Package name |
| `version` | Crate-level | SemVer version |
| `description` | Crate-level | One-line description (required by crates.io) |
| `license` | Crate-level or `workspace.package` | Must resolve to an SPDX expression |
| `repository` | `workspace.package` | Inherited from workspace |
| `edition` | `workspace.package` | Inherited from workspace |

`verify-release` validates that each publishable crate has `description` and `license` fields.

## 3. Package-Content Inspection

`verify-release` runs `cargo package --list` for each publishable crate and rejects packages containing:

| Pattern | Reason |
|---------|--------|
| `target/` | Build output |
| `.git/` | Repository metadata |
| `.env` files | Secrets / configuration |
| `credentials` | Secrets |
| `fuzz/` | Fuzz corpora and crash artifacts |
| `plans/` | Planning documents |
| `corpus/` | Test corpora |
| `crash-` | Crash artifacts |

Each crate's package contents are verified against these patterns before dry-run packaging.

## 4. Release Procedure

### Prepare

1. Update intended crate versions in each crate's `Cargo.toml`.
2. Update internal dependency version constraints (path deps use `*`).
3. Update CHANGELOG.md or release notes.
4. Confirm repository state and target commit.
5. Run `verify-release`:

```bash
cargo xtask verify-release
```

This runs full verification, package metadata validation, package content inspection, and dry-run packaging. It never publishes.

### Dry Run

The dry run is included in `verify-release`. For manual verification:

```bash
# Verify package file lists
cargo package --list -p <crate-name>

# Dry-run package assembly (each crate)
cargo publish --dry-run -p <crate-name>
```

Run these in dependency order (see the publication order table above).

### Publish

1. Authenticate to crates.io through your local Cargo configuration:

```bash
cargo login <your-token>
```

Do not commit the token or store it in environment variables in the repository.

2. Publish each crate in dependency order:

```bash
cargo publish -p pqc
# Wait for crates.io to index...
cargo publish -p synvoid-utils
# Wait for crates.io to index...
# ... continue for each crate in order
```

3. After publishing each crate, verify it resolves from crates.io before publishing dependents:

```bash
cargo search pqc --limit 1
```

4. Verify the published crate page on crates.io and download the package to confirm contents.

### Tag and Record

1. After all crates are published and verified on crates.io, create the version tag:

```bash
git tag v1.1.0
git push origin v1.1.0
```

2. Optionally create a GitHub release manually with release notes.

3. Do not attach CI-generated binaries unless separately intended.

**Why tag after publish**: A public tag implies successful publication. If the tag is created before publication and publication fails, the tag points to an unpublished state. Tagging after successful publication avoids this confusion.

## 5. Immutable-Version Recovery

crates.io published versions are immutable. You cannot overwrite a published version. A failed or defective publication is corrected with a new version.

### Scenario: One crate publishes but a dependent fails

1. The already-published crate remains on crates.io. Do not yank it unless it is broken.
2. Fix the failing dependent crate.
3. Bump the failing crate's version.
4. Update any downstream dependency constraints if needed.
5. Publish the corrected crate.

### Scenario: Package metadata is wrong after publication

1. Fix the metadata in the crate source.
2. Bump the patch version.
3. Publish the corrected version.
4. If the incorrect metadata is misleading (wrong description, wrong license), yank the bad version and explain the reason.

### Scenario: docs.rs fails after publication

docs.rs builds are triggered automatically and may fail for reasons outside your control (rustdoc changes, dependency issues). This does not affect the published crate.

1. Check the docs.rs build logs for the specific failure.
2. If the issue is in your crate's documentation, fix it and publish a patch release.
3. If the issue is a docs.rs infrastructure problem, it typically resolves on its own or can be triggered with a rebuild request on docs.rs.

### Scenario: Severe defect discovered after publication

1. Do not attempt to delete or overwrite the published version.
2. Fix the defect in source.
3. Bump the version (patch for bug fixes, minor for new functionality that replaces the broken behavior, major for breaking changes).
4. Publish the corrected version.
5. Yank the defective version if it causes data loss, security issues, or significant incorrect behavior:

```bash
cargo yank --version <version> --crate <crate-name>
```

6. Explain the yank reason in the crate's changelog or release notes.

### Scenario: Version number reserved or published unintentionally

1. If the version is published but broken, yank it.
2. Bump to the next version number.
3. Publish the correct source.

### Scenario: A crate must be yanked

Yanking removes the version from default resolution but keeps it downloadable. Use yanking for:

- Security vulnerabilities
- Data corruption or loss
- Incorrect license metadata
- Significant API breakage not covered by semver

Do not yank for minor documentation typos or non-breaking cosmetic issues — publish a patch instead.

```bash
cargo yank --version <version> --crate <crate-name>

# To un-yank (if the issue is resolved):
cargo yank --version <version> --crate <crate-name> --undo
```

## 6. Release Tag Policy

The preferred tag ordering is:

1. Verify the exact commit locally (`cargo xtask verify-release`).
2. Publish all crates to crates.io.
3. Verify crates.io availability.
4. Create and push the tag pointing to the verified commit.

This avoids a public tag implying successful publication before crates.io accepts the release.

If repository policy chooses tag-before-publish, the recovery procedure must explicitly cover a failed publication after tagging (see Section 5).

## 7. Security Rules

- No crates.io token is referenced in repository workflows or scripts.
- No publication credential is expected by `verify-release`.
- Local Cargo authentication is configured through `cargo login` (writes to `~/.cargo/credentials.toml`).
- Package-content inspection rejects files matching secret and credential patterns.
- Publication commands print no tokens.
- Do not commit `~/.cargo/credentials.toml` or any file containing a crates.io token.
