# Phase 123 Closeout — Standalone-Crate Campaign Gate

Date: 2026-10-02.
Plan: `plans/phase_123_standalone_crate_campaign_qualification_gate.md`.
Disposition: **CLOSED WITH EXPLICIT QUALIFICATION RESIDUALS**. No class-3
promotion or repository-extraction plan is justified. The campaign remains
monorepo-first. The initial exact-head hosted CI run exposed two new Wasmtime
advisories; Phase 123's security response updated the manifest-only YARA
compatibility pin from 48.0.3 to 48.0.5. Native macOS and live PKCS#11
evidence remain unqualified.

## Dependency and package comparison

The generated ten-candidate baseline is
`architecture/standalone_crate_dependency_baseline.json`. Comparing its
Phase 115 version at `c968594` with the refreshed Phase 123 version shows:

| Candidate | Phase 115 → 123 direct SynVoid edges | Expanded normal tree lines | Package files | Phase 123 outcome |
|---|---:|---:|---:|---|
| `synvoid-dns` | 7 → 7 | 838 → 838 | 116 → 116 | Class 1; runtime/provider neutralization DEFER |
| `synvoid-mesh` | 14 → 14 | 1928 → 1928 | 124 → 124 | Class 1; dispatch inversion/runtime DEFER |
| `synvoid-platform` | 1 → 1 | 106 → 106 | 29 → 29 | Class 2; keep combined, no sandbox split |
| `synvoid-honeypot` | 0 → 0 | 99 → 99 | 26 → 29 | Class 2; Linux package consumer passed, macOS deferred |
| `synvoid-dnssec-keystore` | 0 → 0 | 132 → 132 | 15 → 16 | Class 2; live HSM deferred, RSA promotion blocked |
| `synvoid-mesh-protocol` | 0 → 0 | 85 → 85 | 14 → 15 | Class 2; protocol leaf consumer passed |

The changed package contents for the three hardened leaves are README and
metadata additions; they do not reduce dependency reachability or establish
maintenance savings. No DNS/mesh edge was removed and no `synvoid-sandbox` or
`synvoid-mesh-runtime` crate was created. The generated inventory also records
ICMP, YARA, proxy-cache and tarpit as gate-only/internal candidates. Their
expanded dependency trees, Cargo features and package file lists remain in the
JSON baseline. No file-count metric is used as a maintenance claim.

## Qualification and class decisions

- `synvoid-honeypot`, `synvoid-dnssec-keystore`, and
  `synvoid-mesh-protocol` have packaged-source public API smoke tests outside
  the workspace on Rust 1.85.0/Linux. Their Phase 121/122 closeouts contain
  package/test/doc evidence. All remain class 2 with `external_support=false`.
- Existing `synvoid-rate-limit` remains the only class-3 crate. No class-3
  candidate satisfied the support, semver, MSRV, security and maintenance bar.
- No package was published, no repository was created, and no git dependency
  was added. No entry was added to the external publication order.
- Extraction fails the campaign test: DNS, mesh and sandbox tracks have no
  completed independent package seam; no second production consumer or
  separately accepted stewardship/CI/release owner justifies a new repository;
  routine development still shares the workspace and release train.

## Local verification

Passed before the all-features lint correction in commit `888fb99`:

- `cargo fmt --all -- --check`, normal all-targets clippy, the bounded five
  feature-profile checks, no-default-features tests, `cargo deny check`, and
  `cargo audit` (six existing allowed unmaintained-dependency warnings).
- `cargo nextest run --workspace --cargo-profile ci --profile ci --exclude synvoid-fuzz`:
  all 7,948 tests passed; 10 skipped by the checked-in profile.
- `cargo test --workspace --doc --profile ci`: passed.

The `cargo xtask verify-release` invocation completed 12 of 13 phase-1 steps.
Its only initial failure was all-features clippy on five
`needless_return` diagnostics in `synvoid-icmp-filter`. Those expression-only
returns were removed in `19bdd33`; afterward both
`cargo fmt --all -- --check` and
`cargo clippy --all-targets --all-features -- -D warnings` passed. The
release-profile library test compilation
(`cargo test --lib --no-run --release`) also passed on `19bdd33`. Thus the
initial `verify-release` command did not reach its package-inspection phase;
the three campaign leaf tarballs were separately packaged, dry-run checked and
consumer-qualified in Phases 121–122. Hosted CI for the exact final branch head
must be checked after push. The all-workspace suite ran on `888fb99` before the
semantics-preserving ICMP lint cleanup. After that cleanup,
`cargo test -p synvoid-icmp-filter --profile ci` passed (60 unit, 12 boundary,
16 transactional-enforcement tests and 3 doctests). Final-head hosted CI is the
requested exact-SHA regression check.

Phase 115's earlier `cargo xtask verify` failure-injection compile was
interrupted and is not reported as a pass. Linux is the only available native
target. No macOS, live HSM or Windows support claim is made.

## Successor-plan gate

No future promotion/extraction plan is unblocked by this campaign:

| Track | Decision and trigger to revisit |
|---|---|
| DNS 116/117 | Remain closed DEFER. Reopen only after the persisted/runtime DTO split, composition adapters, provider seam and authoritative/resolver/DNSSEC/encrypted-transport parity tests can be delivered together. Hickory remains the protocol foundation. |
| Mesh 118/119 | Remain closed DEFER. Reopen only with a typed async application-capability boundary plus authority, failure, cancellation, framing and differential parity evidence; do not create a runtime crate before that one-way seam is measured. |
| Sandbox 120 | RETAIN in `synvoid-platform`. Reconsider an internal split only with a concrete dependency-reachability reduction and unchanged guarantee/native conformance evidence. |
| Honeypot 121 | Class 2 remains closed; native macOS runtime qualification needs a macOS runner. Do not treat cross-compilation as support. |
| Keystore 122 | Class 2 remains closed; live provider qualification needs an actual PKCS#11 module/token. Public promotion also requires a resolved RSA advisory/exposure decision. |
| Mesh protocol 122 | Keep class 2; no independent support/repository case was demonstrated. |
| ICMP | Keep RETAIN. No second independent production consumer or complete native/package support matrix was established. |
| YARA | Keep DEFER. Temporary-fork/security compatibility and second-consumer gates are not both open. |
| Proxy cache | Keep internal until an explicit supported HTTP/object-cache semantic contract exists. |
| Tarpit, filter, jail protocol, native extension | Keep internal; no independent use case and maintenance benefit justified a new plan. |

No successor plan has been registered. Any future promotion or extraction must
be separately scoped, owned and approved under
`architecture/public_crate_release_policy.md` and the campaign rules.

## Exact-head CI follow-up

The first workflow-dispatch run on `d044609711ebfe719d6984a190d41aa7fbfa33bb`
failed its `dependency-security` job because Wasmtime 48.0.3 had become
affected by `RUSTSEC-2026-0326` and `RUSTSEC-2026-0327`; the main verify job
also stopped at dependency policy. The pinned YARA fork and lockfile now use
Wasmtime 48.0.5 (48.0.4 is the fixed minimum), with no advisory ignore.

The exact-head workflow-dispatch run for `f81182149889e21c4908b7ee38c74bc6b4518f6b`
passed both required jobs: `ci` / Verify and `dependency-security` (cargo-deny
and cargo-audit). The two optional native qualification jobs were skipped by
their false-by-default inputs; macOS and HSM qualification remain residuals.
