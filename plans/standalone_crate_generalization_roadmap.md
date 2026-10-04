# Standalone-Capable Crate Generalization Roadmap (Phases 115–123)

Status: **CLOSED WITH EXPLICIT QUALIFICATION RESIDUALS** (2026-10-02; Phases
116–119 DEFER; Phase 120 RETAIN; Phase 121 class-2 with native macOS deferred;
Phase 122 class-2 with live-HSM deferred and RSA promotion blocked; Phase 123
found no class-3 promotion or repository-extraction trigger. Exact-SHA hosted
CI remains a post-push check.)

Registered in: `plans/roadmap.md`.

Planning baseline: `main` at `10ac2e330d74d012819c592b395f67ee8cc09a38`.

## Purpose

Continue the subsystem-boundary work without turning SynVoid into a collection of
tightly synchronized repositories. The target is a monorepo containing a small set
of crates that are genuinely usable outside SynVoid: they build from packaged
source, expose application-neutral APIs, carry explicit compatibility boundaries,
and can be tested by independent consumers.

This campaign distinguishes three decisions that previous work sometimes had to
consider together:

1. **Internal crate boundary** — useful for dependency isolation, auditability,
   compile scope, unsafe/security capability isolation, or conceptual ownership.
2. **Standalone-capable package** — can be packaged and consumed outside the
   workspace without SynVoid application dependencies or hidden runtime
   assumptions. This remains class 2 unless separately promoted.
3. **Externally supported/public project** — class 3 support promise and/or
   independent repository. This is a later decision and is NOT authorized by this
   campaign merely because a package becomes standalone-capable.

The campaign is therefore monorepo-first. No phase may create a new external
repository, add a long-lived git dependency, or publish a new crate to crates.io
without a separately registered release/extraction plan after Phase 123.

## Current ecosystem research baseline

### DNS

SynVoid is already on Hickory 0.26.3. Hickory's current project provides protocol,
server, resolver and recursor libraries and supports authoritative serving,
forwarding/recursion, DNSSEC, TSIG/SIG(0), DoT, DoH, DoQ and HTTP/3. Hickory 0.26.2
was a security-heavy patch release and 0.26.3 fixed regressions in DNSSEC, QUIC,
HTTP/3 and dependency selection. The correct direction is therefore not a second
general DNS protocol implementation. Any reusable SynVoid DNS package must justify
itself as an application-neutral operational/policy runtime layered on Hickory,
with SynVoid-specific Geo/health/mesh/config/certificate behavior supplied through
capabilities.

Research references:
- https://hickory-dns.org/
- https://github.com/hickory-dns/hickory-dns
- https://github.com/hickory-dns/hickory-dns/releases/tag/v0.26.3

### Mesh / peer networking

The Rust ecosystem already has broad peer-network primitives. rust-libp2p provides
Kademlia, Identify, Gossipsub and multiple transports; Iroh provides public-key
addressing, relay fallback, hole punching and QUIC-based protocol composition; noq
is a general QUIC implementation with multipath/address-discovery/NAT-traversal
work. OpenRaft remains a reusable consensus engine, but its 0.10 line is still
alpha and has moved substantially beyond SynVoid's current alpha.18 pin.

The reusable SynVoid opportunity is consequently NOT "another generic libp2p."
The candidate is the narrower authenticated peer/session/liveness/routing runtime
needed by SynVoid, with explicit canonical-vs-advisory state boundaries above it.
Application dispatch into proxy, cache, tunnel, serverless, DNS or threat policy
must not live in that reusable layer.

Research references:
- https://github.com/libp2p/rust-libp2p
- https://github.com/libp2p/specs/tree/master/pubsub/gossipsub
- https://github.com/n0-computer/iroh
- https://github.com/n0-computer/noq
- https://docs.rs/openraft/

A 2026 libp2p-quic reachable-panic advisory is additional evidence that transport
backends should remain replaceable/testable boundaries rather than being fused to
SynVoid policy:
- https://nvd.nist.gov/vuln/detail/CVE-2026-61544

### Process sandboxing

Birdcage is archived as of 2026-07-06. Current alternatives include Skarn
(Landlock+seccomp, Seatbelt, AppContainer/Job Object with explicit maturity
caveats) and Zerobox (currently macOS/Linux, Bubblewrap/seccomp/namespaces on
Linux). These projects overlap mechanism coverage but do not eliminate the value
of SynVoid's caller-selected Required/Optional guarantees, prepare/enter staging,
retained enforcement receipts, preopened-resource contract and jail lifecycle
semantics.

The appropriate near-term move is therefore to isolate that guarantee model from
the broad `synvoid-platform` crate if a one-way dependency can be proven, while
keeping it class 2/internal until independent native support and consumer gates
are satisfied.

Research references:
- https://github.com/phylum-dev/birdcage
- https://github.com/Rani367/Skarn
- https://github.com/afshinm/zerobox

## Candidate classes for this campaign

### Primary generalization tracks

- `synvoid-dns`: application-neutral runtime/config/provider inversion, then
  outside-workspace qualification.
- mesh runtime: remove application-service dispatch from `synvoid-mesh`, then
  decide whether a new low-capability `synvoid-mesh-runtime` crate is justified.
- sandbox guarantee/runtime boundary: determine whether the guarantee contract can
  move from broad `synvoid-platform` into an internal `synvoid-sandbox` crate.

### Package-hardening tracks

- `synvoid-honeypot`: architecture-neutral already; close standalone package
  security/support hygiene without promising publication.
- `synvoid-dnssec-keystore`: low-capability custody leaf; close security,
  platform, feature and package-consumer gaps.
- `synvoid-mesh-protocol`: low-capability wire leaf; formalize evolution,
  replay/time and mixed-version expectations.

### Gate-only candidates

No implementation is authorized for these unless Phase 123 proves a trigger:
- `synvoid-icmp-filter`;
- `synvoid-yara`;
- `synvoid-proxy-cache`;
- `synvoid-tarpit`;
- `synvoid-filter`;
- `synvoid-jail-protocol`;
- `synvoid-native-extension`.

They already receive most of the benefit of crate isolation. A second repository
or support promise is not a success metric.

## Binding rules

1. Keep the Git monorepo. No external repository is created in Phases 115–123.
2. "Standalone-capable" means packaged-source consumer proof, not crates.io
   publication.
3. Class-2 crates remain unsupported externally unless Phase 123 explicitly
   registers a later class-3 promotion plan.
4. A standalone-capable crate must not require root `synvoid`,
   `synvoid-config`, `synvoid-core`, or another application policy crate.
   Security leaf dependencies may be allowed only when deliberately part of the
   proposed package topology (for example DNS -> DNSSEC keystore).
5. Persisted SynVoid configuration remains owned by SynVoid. Reusable crates own
   runtime config and receive exhaustive adapters at the composition boundary.
6. Observability must be optional/facade-level where practical; no standalone
   package may require a SynVoid metrics exporter.
7. No wire/storage compatibility change is hidden inside dependency inversion.
8. Hickory remains the DNS protocol foundation unless parity evidence proves a
   custom behavior cannot be expressed safely upstream or through composition.
9. Mesh canonical-vs-advisory authority must not change. Transport/runtime
   extraction cannot make DHT advisory state canonical or bypass Raft quorum.
10. OpenRaft upgrades, QUIC backend migrations and other major dependency
    migrations are separate concerns. Register them separately if discovered;
    do not smuggle them into boundary extraction.
11. Native security support claims require native evidence. Cross-compilation is
    build evidence only.
12. New crates are allowed only when they remove dependency reachability or
    isolate a trust/capability boundary; crate-count reduction/increase is not a
    goal.
13. Existing root compatibility facades remain thin and are migrated only where
    needed by the new canonical owner.
14. Every implementation phase records before/after `cargo metadata` /
    `cargo tree` evidence so maintenance reduction is measurable.

## Execution order

1. **Phase 115 — Standalone crate contract and dependency baseline.**
2. **Phase 116 — DNS runtime-config/core neutralization.**
3. **Phase 117 — DNS provider inversion and standalone consumer proof.**
4. **Phase 118 — Mesh application-dispatch capability inversion.**
5. **Phase 119 — Mesh runtime extraction decision and standalone qualification.**
6. **Phase 120 — Sandbox guarantee-boundary internal crate split decision.**
7. **Phase 121 — Honeypot standalone-package hardening.**
8. **Phase 122 — DNSSEC-keystore and mesh-protocol leaf hardening.**
9. **Phase 123 — Campaign qualification and promotion/repository gate refresh.**

Phases 116–119 have formally closed DEFER: DNS provider inversion and mesh
runtime extraction were closed because their prerequisite boundaries were not
delivered. Phase 120 closed RETAIN. Phase 121 implemented package hardening and
closed with native macOS qualification deferred. Phase 122 closed both leaf
packages as class 2, with live-HSM qualification deferred and class-3 RSA
promotion blocked. Phase 123 is eligible to reconcile these outcomes.

Phase 115's implementation is recorded in
`architecture/standalone_crate_phase115_closeout.md`. The contract and baseline
outputs are complete and available to successors. Routine verification was
interrupted during failure-injection compilation after earlier routine stages
passed; this residual is carried into the terminal campaign evidence and is not
treated as a passing routine gate.

Phases 116/117 DNS DEFER outcomes are recorded in
`architecture/standalone_crate_phase116_closeout.md`. Phases 118/119 mesh DEFER
outcomes are recorded in `architecture/standalone_crate_phase118_closeout.md`.

Phase 120's RETAIN decision is recorded in
`architecture/standalone_crate_phase120_closeout.md`; no sandbox crate was
created and no support tier changed.

Phase 121's implementation and Linux-only qualification evidence are recorded
in `architecture/standalone_crate_phase121_closeout.md`; the native macOS gate
remains open for a suitable runner.

Phase 122's dual-package evidence and live-HSM/RSA promotion limitations are
recorded in `architecture/standalone_crate_phase122_closeout.md`.

Phase 123's final graph, candidate table, local qualification and successor
gate decisions are recorded in
`architecture/standalone_crate_phase123_closeout.md`. No future standalone
promotion/extraction plan is unblocked. Reconsider DNS or mesh only after the
named DTO/provider or typed async capability prerequisites are implemented and
parity-tested; reconsider platform splitting only with a demonstrated dependency
reduction. Gate-only candidates remain closed until their specific second
consumer/security/semantic triggers are evidenced. Native macOS, live HSM, and
exact-SHA hosted CI are external evidence gates, not support claims.

## Success criteria

The campaign is successful if:

- at least the DNS and mesh tracks end with objectively smaller application
  dependency reachability, even if the final standalone extraction verdict is
  RETAIN/DEFER;
- package-neutral candidates can be built and exercised from their packaged
  tarballs outside the workspace without hidden SynVoid runtime assumptions;
- no supported SynVoid capability or security invariant regresses;
- any new internal crate removes a real trust/dependency boundary rather than
  duplicating modules;
- class-2 versus class-3/public status remains explicit;
- no new cross-repository coordination burden is introduced;
- the root/module ledgers, release policy, package-order docs and roadmap agree
  with the final dependency graph.

## Rejection criteria

Reject a closeout that:

- calls a crate standalone because `cargo check -p` succeeds inside the
  workspace;
- creates an external repository as a substitute for dependency inversion;
- makes SynVoid persisted config types public library API;
- duplicates Hickory/libp2p/Iroh/OpenRaft behavior without a documented
  SynVoid-specific need;
- changes mesh authority semantics while "generalizing" networking;
- moves sandbox code without preserving fail-closed guarantee reports and native
  evidence truthfulness;
- promotes a crate to class 3 because metadata/docs were added but no independent
  support burden was justified;
- reports file movement or crate count as maintenance reduction without dependency
  and consumer evidence.
