# Public Crate Release Readiness — Phase 47 (2026-09-19)

Status: complete. Plan: `plans/phase_47_public_crate_release_readiness.md`.
Policy: `architecture/public_crate_release_policy.md` (binding).

Outcome: **exactly one crate promoted** — `synvoid-rate-limit` 0.1.0 moves
from class 2 to class 3 (first externally supported SynVoid library). Every
other candidate stays class 1/2 with the reason recorded below. Publication
itself remains manual (`cargo publish` only); this phase performed dry-runs,
never uploads.

## 1. Promotion: `synvoid-rate-limit` 0.1.0 → class 3

Why it qualifies (Phase 47 acceptance criteria, all hold):

- Independently useful: lock-free sliding-window + neutral admission
  vocabulary, std-only, policy-free; two production consumer domains (root
  WAF composition, mesh peer/global admission).
- No hidden workspace requirement: `cargo tree -p synvoid-rate-limit` is a
  single node (zero dependencies); `cargo package --list` contains only
  crate-local sources, README, CHANGELOG, and tests; the produced tarball
  builds and tests outside the workspace.
- MSRV declared and tested: `rust-version = "1.81"`, verified by unpacking
  the packaged tarball to a scratch dir and running the full test suite on
  `1.81.0` (21 unit + 5 integration + 7 property + 1 doctest, all pass).
- Semver/wire policy written: crate README + `public_crate_release_policy.md`
  §§1–2 (stable API vs implementation-detail slot mapping vs performance).
- Consumer docs: crate README quickstart, overflow/time-base semantics,
  slot-hashing stability decision, non-goals, MSRV/support statement;
  crate-level rustdoc quickstart doctest; `CHANGELOG.md`.
- Deterministic tests: 21 unit (rotation, N/N+1, large jumps, saturation,
  concurrent rotation without underflow), 5 consumer-mapping integration,
  7 property sweeps (`tests/rotation_properties.rs`), 1 doctest — no sleeps.
- Package evidence: `cargo package`, `cargo publish --dry-run`, `cargo doc
  --no-deps` with `-D warnings` all pass.
- Burden justified: zero-dependency leaf, stable mechanism semantics, bench
  evidence (`bench_ratelimit`: `increment_at` ~36ns, `count_at` ~24ns).

Slot-hashing decision (Workstream A/B): `ip_to_slot` is an implementation
detail, **not** a stable cross-version hash. Guarantees: determinism within
one version, range containment, `None` for zero slots. Pinned by guard
(`public_crate_release_policy_guard`) and documented in README/rustdoc.

Per-crate metadata added: `rust-version`, `readme`, `documentation`,
`keywords`, `categories`, description (already held), license/repository
(workspace-inherited).

## 2. Not promoted (remain class 2 unless noted)

### `synvoid-mesh-protocol` — stays class 2

Good SynVoid-tooling seam, not a generic mesh library. Missing before any
support promise: independent wire/protocol versioning policy beyond the
single `MESH_MESSAGE_VERSION = 1` constant, `#[non_exhaustive]` (or
equivalent) evolution strategy on the public enums, explicit public
replay-window/time assumptions (current replay docs are extraction notes),
and semver rules separating Rust API from wire compatibility. Golden vectors
exist and already act as compatibility fixtures internally, but are not yet
published as a versioned compatibility contract. No `rust-version`/README/
support statement added — deliberately, so nothing implies a promise.

### `synvoid-proxy-cache` — stays class 1/2 internal, no RFC claim

The crate is a reverse-proxy **object cache** (TTL + stale-while-revalidate /
stale-if-error + single `Vary` key + status/method allowlists + memory/disk
tiers), not an RFC 9111 HTTP cache. Before any publication it would need an
explicit supported-subset definition (cache-key derivation, `Vary`
semantics, validators/ETag/Last-Modified, 304 merging,
Authorization/private/no-store, stale handling, header normalization, disk
persistence). That subset is not defined and not implemented; implying RFC
coverage would be false advertising. No rename is needed while internal —
the crate name is honest inside the workspace — but any future public
release must either define the subset or rename to a non-RFC-implying
object-cache name first.

### `synvoid-dnssec-keystore` — stays class 2

Well isolated (one-way leaf, opaque handles, atomic `0600` persistence,
fail-closed HSM) with KAT/rotation/permission tests and doctests, but a
support promise needs more: a public threat model and security-contact
policy, an MSRV/feature matrix including the `pkcs11`/`hsm` surface, a
zeroization/secret-lifetime review framed for external callers,
crash-consistency tests, documented Unix/Windows permission behavior,
PKCS#11 CI or release validation, and an RSA advisory review (the `rsa`
dependency carries RUSTSEC-2023-0071 with no upstream fix — see
`architecture/dependency_security_baseline_phase25.md`; never describe it as
patched). A leaf is not automatically supportable.

### `synvoid-platform` — stays class 2 (deferred)

Phase 46 closed, but promotion still needs an explicit MSRV/`rust-version`,
a semver-support statement, and runnable consumer examples, plus broader
native-enforcement evidence beyond the current matrix. Revisit only then.

### `synvoid-yara` — stays class 2 (deferred)

Deferred while SynVoid carries the temporary YARA-X compatibility fork
(`third-party/yara-x-compat`, `yara_fork_is_temporary_guard`-enforced);
a downstream dependency exception must not become an external support burden.

### `synvoid-http-client` — stays class 2 (deferred)

Historical decision (2026-09-19, against the then-current baseline):
crates.io showed `eggfetch-core` 0.1.4 (2026-09-13; ~93 downloads) with no
0.1.5+ line, so there was no refreshed eggfetch line to evaluate. The
Phase 34 capability matrix (ring-only TLS without aws-lc-rs/PQ parity,
closed request body, no direct-UDS parity, coarse verification toggle, same
transitive stack, pre-1.0 maturity) therefore stood as the then-current
evidence for the retain-`synvoid-http-client` decision (Branch 2,
`architecture/egress_client_decision_phase34.md`). No second public generic
HTTP client.

Current status (Phase 48 closeout): a newer eggfetch line now exists, so the
0.1.4-era matrix above is dated decision history, not current evidence. It
must not be cited to justify the present disposition. `synvoid-http-client`
remains internal pending a fresh parity/consolidation review against the
current eggfetch line — see `plans/eggfetch_current_line_parity_review.md`.
Revisit only when that review re-runs the full matrix with parity tests.

### `synvoid-utils`, `synvoid-core` — remain internal (class 1)

Workspace contract/implementation ownership; publication would freeze
incidental helpers and domain semantics. Permanent non-goal per the roadmap.

## 3. Workstream disposition

- A (metadata): done for `synvoid-rate-limit` (rust-version, README,
  documentation URL, keywords/categories, description, feature table —
  there are no Cargo features, documented as such — support/security
  statement, CHANGELOG). No other crate touched: adding metadata without a
  support promise would imply one.
- B (semver/API): shared binding policy (`public_crate_release_policy.md`)
  + crate-local classification in the rate-limit README/rustdoc.
- C (hidden assumptions): `cargo tree`, `cargo package --list`,
  packaged-tarball outside-workspace build/test all evidenced for
  rate-limit (§1). No `path =` deps anywhere in the promoted crate.
  Phase 35 `publish = false` decision retained: no churn.
- D (docs gate): rate-limit README/rustdoc/CHANGELOG are consumer-oriented
  with no phase-history narrative. Other candidates' internals unchanged.
- E (CI gate): no new workspace matrix. Routine CI covers the promotion via
  the new `public_crate_release_policy` repo-guard test; full qualification
  stays in `cargo xtask verify-release` (never publishes). Focused commands:
  `cargo test -p synvoid-rate-limit --profile ci`,
  `cargo test -p synvoid-rate-limit --doc --profile ci`,
  `RUSTDOCFLAGS="-D warnings" cargo doc -p synvoid-rate-limit --no-deps`,
  `cargo publish -p synvoid-rate-limit --dry-run`,
  plus the MSRV tarball build recorded in §1.
- F (name/ownership): `synvoid-rate-limit` name/namespace decision recorded
  here — keep the `synvoid-` prefix (first supported crate sets the
  precedent; no neutral rename). Registry availability, repository metadata,
  and maintainer intent must be verified immediately before the first real
  `cargo publish`; no rename after publishing without a deprecation plan.
- G (ordering): `docs/releasing.md` gains an "externally supported library"
  order (§1a) separate from the technical package order: only
  `synvoid-rate-limit` 0.1.0, independently publishable (no internal
  predecessors).

## 4. Verification evidence (local, 2026-09-19, pinned 1.98.1 unless noted)

- `cargo test -p synvoid-rate-limit --profile ci`: 21 unit + 5 integration
  + 7 property pass.
- `cargo test -p synvoid-rate-limit --doc --profile ci`: 1 doctest passes.
- `RUSTDOCFLAGS="-D warnings" cargo doc -p synvoid-rate-limit --no-deps`: pass.
- `cargo package -p synvoid-rate-limit --allow-dirty`: 12 files, pass.
- `cargo publish -p synvoid-rate-limit --dry-run --allow-dirty`: pass.
- MSRV: packaged tarball unpacked to scratch, full suite on `1.81.0`:
  21 + 5 + 7 + 1 pass (see §1).
- `cargo package --list` for mesh-protocol / proxy-cache / dnssec-keystore:
  crate-local files only (no root-fixture leakage); left unpromoted per §2.
- Full gates after this phase: `cargo xtask verify`, `verify-full`,
  `verify-release` (clean tree), `deny`, `audit` — recorded in the release
  commit and CI run.
