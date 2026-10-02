# Standalone-capable class-2 package contract

Status: **BINDING** (Phase 115, 2026-10-02).

This classification describes packaged-source independence. It does not create
an externally supported library promise, a release cadence, or a separate
repository. The binding class-3/public policy remains
[`public_crate_release_policy.md`](public_crate_release_policy.md).

## Package states

| State | Meaning |
|---|---|
| Internal class 1 | Application implementation; workspace consumption only is expected. |
| Reusable class 2 | A useful crate boundary with no external support claim. |
| Standalone-capable class 2 | Satisfies every package, metadata, dependency, feature, and consumer proof below; still unsupported externally. |
| Class 3 | Explicitly promoted by the public-crate policy and its independent support requirements. |

Standalone-capable class 2 requires all of the following:

1. No normal dependency on the root `synvoid`, `synvoid-config`, `synvoid-core`, or other application-policy crate. An explicitly named security leaf pairing may be allowed in the candidate registry.
2. No hidden root-relative files, workspace-only build assumptions, or undocumented environment variables.
3. Cargo metadata states the package's purpose, license, repository, README, and evidence-based MSRV. Package metadata says `standalone_class = "class2"` and `external_support = false`.
4. Default features are useful and bounded; heavyweight/native capabilities are opt-in where appropriate.
5. Any persisted, wire, and storage surface has a written compatibility classification.
6. `cargo package` source is extracted outside the repository and compiled by a tiny consumer with workspace Cargo variables removed. Feature selections are recorded.
7. Native security claims refer only to natively qualified targets.

The reusable harness is `cargo xtask standalone consumer <package> [--features a,b]`.
It runs offline so it cannot silently become a routine network dependency. A
positive control is `synvoid-rate-limit`; `synvoid` is the negative control.
Evidence snapshots are regenerated with `cargo xtask standalone baseline` and
are descriptive outputs of Cargo metadata/tree/package commands, never manually
maintained dependency counts.

The candidate registry is `architecture/standalone_crate_candidates.toml`.
Only entries present there are subject to the focused repository guard. Adding an
entry requires a proof-bearing phase closeout and passing outside-workspace
consumer test. Existing class-3 crates are governed separately.
