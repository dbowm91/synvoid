# Plan: Root README Public-Support Boundary Corrective

Status: **READY**.

> **Workstream A applied (2026-10-06).** The root README now carries a
> `Library crates` section satisfying §4: it names `synvoid-rate-limit` as the only
> **externally supported** library, states that other `synvoid-*` crates carry no
> support promise absent explicit promotion, and points at
> `architecture/public_crate_release_policy.md` and `docs/releasing.md` §1a. No
> class-1/class-2 crate is promoted. Implemented in `cd79ffe5`, an unrelated
> config-corrective commit that independently hit the same guard failure; the
> guard was left unchanged per §6, and `cargo xtask verify` is green on that head
> (10/10 steps, 163/163 repo guards).
>
> The status stays **READY** rather than CLOSED because §7 boundary item 5
> requires exact-head hosted CI green before closure, which has not run on
> `cd79ffe5`.

Registered in: `plans/roadmap.md`.

Corrective baseline:
`e23bf2e5e0f47fc89bdda8465b52930c963284e0`.

Triggering documentation rewrite:
`e23bf2e5e0f47fc89bdda8465b52930c963284e0`
(`docs: rewrite README around a verified quickstart; audit user-facing docs`).

Last known green parent:
`e3bbc8cac60f8f1aaedd21a0ffd928b7eb9f3f74`
(CI `37494224344` green).

Triggering CI:
`37500080697`.

Binding policy authority:

- `architecture/public_crate_release_policy.md`;
- `architecture/public_crate_release_readiness_phase47.md`;
- `docs/releasing.md` §1a;
- `plans/phase_47_public_crate_release_readiness.md`.

## 1. Corrective disposition

The 2026-10-06 documentation rewrite is retained. Its quickstart-first
structure, verified configuration examples, command documentation, deployment
guidance, and broader user-facing documentation audit are not reopened by this
corrective.

One binding support-boundary statement was accidentally lost from the root
README:

- before the rewrite, `README.md` contained a `Reusable libraries` section
  stating that only `synvoid-rate-limit` is externally supported;
- after the rewrite, the root README contains no equivalent statement;
- the underlying Phase 47 policy did not change;
- `docs/releasing.md` still correctly records the external-support order;
- the repository guard
  `public_crate_release_policy::root_readme_documents_support_boundary`
  therefore fails.

This is documentation-policy drift, not a production/runtime defect and not a
reason to reopen Phase 47.

## 2. Trigger evidence

Current-head CI `37500080697` fails only in the blocking `ci` job at:

~~~text
synvoid-repo-guards::public_crate_release_policy
  ::root_readme_documents_support_boundary
~~~

The guard requires the root README to communicate the Phase 47 external-support
boundary. On the same run:

- `cargo fmt --all -- --check` passes;
- strict Clippy passes;
- dependency policy passes;
- no-default-features core compilation passes;
- dependency-security is green;
- 162/163 repository-guard tests pass.

The failure text is:

~~~text
public_crate_release_policy_guard: root README must document the
externally supported library boundary (Phase 47)
~~~

The immediately preceding revision
`e3bbc8cac60f8f1aaedd21a0ffd928b7eb9f3f74` has green CI
`37494224344`.

## 3. Binding support truth

The corrective must preserve the current binding classification:

1. `synvoid-rate-limit` is the only class-3, externally supported SynVoid
   library;
2. it carries the Phase 47 semver/MSRV/support promise;
3. all other `synvoid-*` crates remain class 1 or class 2 unless separately
   promoted by a registered, qualified plan;
4. a crate being reusable, packageable, or independently buildable is not an
   external support promise;
5. publication remains manual;
6. `docs/releasing.md` §1a remains the canonical release-order summary;
7. `architecture/public_crate_release_policy.md` remains the binding support
   policy.

The standalone-crate campaign did not promote an additional class-3 crate.
Do not infer external support from later package-hardening or standalone-capable
class-2 evidence.

## 4. Workstream A — restore the root README support boundary

Add a concise user-facing section to the root README, preferably near build
profiles / developer-facing documentation where library consumers can discover
it without disrupting the quickstart.

A suitable heading is:

~~~text
## Reusable libraries
~~~

The section must state semantically that:

- only `synvoid-rate-limit` is externally supported;
- other workspace crates do not carry an external support promise unless a
  later policy decision explicitly promotes them;
- the binding support/semver policy lives in
  `architecture/public_crate_release_policy.md`;
- release order/publishing guidance lives in `docs/releasing.md`.

Preserve the useful substance of the pre-rewrite statement, but edit it to fit
the new README rather than mechanically restoring old prose.

The wording should contain the literal phrase `externally supported` and the
crate name `synvoid-rate-limit` because those are stable concepts enforced by
the repository guard.

## 5. Workstream B — reconcile README against binding docs

Before closing, compare the restored README statement with:

- `architecture/public_crate_release_policy.md`;
- `architecture/public_crate_release_readiness_phase47.md`;
- `docs/releasing.md` §1a;
- `architecture/runtime_truthfulness_security_publication_closeout.md`;
- `architecture/standalone_crate_phase123_closeout.md`;
- `architecture/standalone_crate_phase124_closeout.md`.

Reject any wording that accidentally promotes:

- `synvoid-dns`;
- `synvoid-dnssec-keystore`;
- `synvoid-honeypot`;
- `synvoid-mesh-protocol`;
- `synvoid-http-client`;
- or any other class-1/class-2 crate.

No binding architecture document should need a semantic change for this
corrective. If one disagrees with the Phase 47 support boundary, stop and open a
separate policy-reconciliation plan instead of silently changing the README.

## 6. Workstream C — keep the guard meaningful

Do not remove, weaken, skip, or special-case:

`root_readme_documents_support_boundary`.

The guard caught a real policy-documentation regression.

A narrow improvement to the guard is permitted only if it makes the assertion
less syntactically brittle while preserving the same semantic invariant.
No such change is required to close this corrective.

Preferred implementation: restore the missing README contract and leave the
guard unchanged.

## 7. Scope and non-goals

### In scope

- root README support-boundary restoration;
- targeted policy-document reconciliation;
- focused guard verification;
- exact-head CI proof;
- roadmap/closeout truth.

### Out of scope

- production Rust changes;
- Cargo feature changes;
- crate extraction;
- crates.io publication;
- class-2 -> class-3 promotion;
- MSRV changes;
- semver-policy changes;
- release automation;
- broad README restructuring;
- reverting the 2026-10-06 quickstart rewrite;
- reopening Phases 47/48 or the standalone-crate campaign.

## 8. Required verification

At minimum:

~~~text
cargo test -p synvoid-repo-guards --profile ci public_crate_release_policy
cargo xtask verify
~~~

If the repository's test runner does not support the exact focused filter above,
run the complete guard package:

~~~text
cargo nextest run -p synvoid-repo-guards --cargo-profile ci --profile ci
~~~

Then require the normal hosted CI workflow green on the exact corrective head.

The verification record should explicitly show that
`root_readme_documents_support_boundary` passes.

Dependency-security should remain green; no dependency changes are expected.

## 9. Acceptance criteria

This corrective closes only when:

1. the root README again names `synvoid-rate-limit`;
2. it explicitly states that `synvoid-rate-limit` is externally supported;
3. it does not imply external support for any other workspace crate;
4. it links or points consumers to the binding public-crate support policy;
5. it points release/publishing guidance to `docs/releasing.md`;
6. the quickstart-first README structure is retained;
7. `root_readme_documents_support_boundary` passes unchanged, unless a
   separately justified semantic-equivalent guard refinement is made;
8. all repository guards pass;
9. `cargo xtask verify` passes;
10. exact-head hosted CI is green;
11. no production, dependency, feature, MSRV, or crate-classification change is
    included;
12. roadmap status is reconciled and a short closeout records the triggering
    failure and green corrective evidence.

## 10. Rejection criteria

Reject an implementation that:

- merely inserts hidden text or an unnatural keyword string to satisfy the
  guard;
- removes or weakens the guard;
- claims all reusable crates are supported;
- treats class-2 standalone capability as an external-support promise;
- changes Phase 47 policy to match the rewritten README;
- adds `publish = false` or registry churn to internal crates;
- changes crate versions/MSRV;
- reverts the documentation rewrite wholesale;
- closes without exact-head hosted CI.

## 11. Closeout

On successful verification, create:

`architecture/readme_public_support_boundary_corrective_closeout.md`.

Record:

- corrective baseline;
- corrective implementation SHA;
- exact README support statement;
- focused guard result;
- `cargo xtask verify` result;
- hosted CI run ID;
- confirmation that dependency-security remains green;
- confirmation that class-3 membership remains exactly
  `synvoid-rate-limit`.

## 12. Handoff

This corrective is dependency-ready and should be a very small documentation
change.

Expected production/document change:

- `README.md`.

Expected evidence/status changes:

- `plans/roadmap.md`;
- closeout file after green verification.

No Rust production code change is expected.
