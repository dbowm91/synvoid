# Phase 91 Plan: ICMP Privileged Native Qualification Harness Preparation

Status: planned (2026-09-26).

Registered in: `plans/roadmap.md` and
`plans/icmp_post_retain_operator_truth_and_native_qualification_roadmap.md`.

Baseline: `main` at `0c8d3cac2fb214932c22dc360057acdad3c44c98`.

Depends on: Phase 90 operator/lifecycle truth, so harness observations and
status assertions use the canonical report semantics.

## Goal

Create a safe, reproducible, opt-in native Linux nftables qualification harness
that can produce the privileged evidence Phase 88 deliberately lacked.

Phase 91 is a **harness/preparation phase**. Its closure does not claim that
native qualification passed unless it was actually run on a suitable host.
The Phase 88 RETAIN decision remains unchanged.

## Research basis

Linux network namespaces isolate network devices, protocol stacks, routing
tables, sockets, and firewall rules. A veth pair can connect isolated
namespaces. This makes a disposable network namespace the preferred test
boundary for nftables enforcement instead of modifying the host's default
firewall namespace.

Reference:
- `network_namespaces(7)`
- `ip-netns(8)`
- nftables `nft(8)`

The harness may use standard Linux tools already needed for this proof
(`ip`, `nft`, packet generator/ping) rather than adding permanent runtime
dependencies to `synvoid-icmp-filter`.

## Binding safety requirements

1. Never run destructive qualification in the initial/default host network
   namespace.
2. Require an explicit opt-in flag/environment variable in addition to
   privilege detection.
3. Use collision-resistant namespace/interface/table identifiers.
4. Record every created resource and clean it in normal and failure paths.
5. Refuse to proceed when the namespace cannot be proven disposable/isolated.
6. Do not flush or inspect unrelated host firewall tables.
7. A skipped test is "not qualified," not success.
8. Routine CI must exercise harness argument/preflight/dry-run behavior without
   requiring privilege.
9. The harness must emit machine-readable evidence sufficient for a later
   qualification/closeout record.
10. eBPF, PF, WFP, Windows Firewall, FreeBSD/OpenBSD, and NetBSD are outside
    Phase 91 execution scope; design extension points only where they are
    natural.

## Workstream A — choose the harness shape

Prefer a repository-local test/support tool rather than embedding root-only
behavior into normal unit tests.

Acceptable shapes include:

- a dedicated `cargo xtask` subcommand;
- a small Linux-only test utility/binary under `tools/`;
- an ignored specialist integration target driven by a wrapper.

Whichever shape is chosen must support:

- `--check` / preflight mode;
- `--dry-run`;
- explicit destructive/native mode;
- structured output (JSON or stable artifact file);
- unique run id;
- timeout;
- guaranteed cleanup attempt.

Do not make the ordinary `cargo test` path invoke privileged firewall
operations.

## Workstream B — isolated Linux topology

Construct an isolated topology sufficient to exercise inbound/outbound ICMP
semantics.

Preferred topology:

```text
namespace A                namespace B
  veth-a  <-------------->   veth-b
  IPv4 + IPv6                 IPv4 + IPv6
       nftables policy applied in target namespace
```

The harness must:

- create namespaces/veth devices only after opt-in and preflight;
- configure deterministic private IPv4 and IPv6 addresses;
- bring loopback/veth links up;
- prove the test process/command is operating in the intended namespace before
  touching nftables;
- destroy namespaces on completion;
- use a cleanup fallback that can be rerun safely after interrupted execution.

If implementation finds a simpler isolated topology that proves the same
semantics, document why it is equivalent.

## Workstream C — native nftables qualification matrix

Prepare executable cases for the exact Phase 88 trigger.

### 1. Install and owned-state readback

- apply a minimal ICMP policy;
- confirm the owned table/chain/marker through the crate readback path;
- confirm unrelated namespace nftables state is untouched.

### 2. ICMP type/code behavior

Exercise at least:

- ICMPv4 Echo Request block/allow behavior;
- ICMPv6 Echo Request block/allow behavior;
- one code-qualified rule where practical.

Observe packet behavior from the peer namespace, not only generated rule text.

### 3. Exemptions

- block a relevant ICMP class;
- exempt the peer source;
- prove exempt traffic is allowed while a non-exempt source/prefix remains
  subject to policy.

If the topology requires a second source address/namespace, create it inside
the disposable test environment.

### 4. Rate limit

Exercise the currently supported `Global` rate-limit semantics.

The test must distinguish:

- traffic below threshold;
- a burst above threshold;
- recovery/refill behavior.

Use tolerances appropriate to scheduler/timer granularity; do not assert an
unrealistically exact packet count.

### 5. Atomic update/replacement

- install generation A;
- replace with generation B;
- verify B's behavior and ownership fingerprint;
- ensure stale generation-A objects are absent.

### 6. Drift detection

- install through the crate;
- mutate/delete an owned object externally inside the disposable namespace;
- call `verify_live()`;
- require Drifted/Absent as appropriate, never Applied.

### 7. Disable/cleanup

- disable through the manager;
- verify Absent;
- prove ordinary peer ICMP behavior returns once policy is removed;
- assert no owned nftables objects remain.

### 8. Rollback/failure path

Inject at least one deterministic native installation failure after a known
working generation exists, without relying on random resource exhaustion.

Prove:

- failure is returned;
- previous generation remains effective when the backend contract promises it;
- report/receipt do not advance to the rejected generation.

If the current subprocess boundary makes a particular failure stage impossible
to inject safely, add the smallest test-only fault seam rather than damaging
host state.

## Workstream D — evidence artifact

Every privileged run should produce a bounded artifact containing:

- git SHA;
- timestamp;
- kernel release;
- nft version;
- architecture;
- effective UID/capability/preflight summary;
- namespace/run id;
- exact test-case names and pass/fail/skip;
- backend selected;
- policy fingerprints/generations where relevant;
- cleanup result;
- overall disposition.

Do not include secrets or arbitrary environment dumps.

The artifact format should be stable enough to attach/reference from a future
architecture qualification record.

## Workstream E — non-privileged/routine-CI behavior

Routine CI must validate the harness without firewall mutation.

Add deterministic tests for:

- opt-in missing => refuses native run;
- insufficient privilege => explicit unsupported/preflight failure;
- missing `ip`/`nft` => explicit prerequisite failure;
- namespace-name validation;
- command construction/escaping;
- cleanup ledger ordering/idempotence;
- evidence serialization;
- dry-run performs zero mutation.

A normal CI "skip" must not be counted as native proof.

## Workstream F — operational documentation

Document how an authorized maintainer runs the harness on a disposable or
controlled Linux host.

Include:

- prerequisites;
- explicit warning that privileged mode manipulates firewall/network namespace
  state;
- command;
- expected artifact location;
- cleanup/recovery command;
- how to verify no leftover namespace exists;
- how evidence feeds the Phase 88 re-evaluation trigger.

Prefer disposable VM/host execution even though namespaces isolate firewall
state.

## Workstream G — do not prematurely reopen extraction

On Phase 91 closure:

- record that native qualification tooling exists;
- record whether a privileged run was available;
- if unavailable, leave Linux nftables at its current evidence tier;
- do not register/publish an extraction plan merely because the harness exists.

Only when actual native evidence is collected should a subsequent focused
qualification/re-evaluation plan be registered.

## Verification

Routine/non-privileged:

```bash
cargo fmt --all -- --check
cargo test -p synvoid-icmp-filter --profile ci
cargo xtask test guards
cargo xtask verify
```

Plus the harness's own preflight/dry-run/unit tests.

Privileged execution, when a suitable Linux host is intentionally available,
must be an explicit separate command documented by the implementation. Do not
silently embed it in routine verification.

## Acceptance criteria

- an opt-in Linux nftables qualification harness exists;
- it operates only inside a proven disposable network namespace;
- it can build an IPv4/IPv6 veth topology;
- it contains executable cases for install, type/code, exemption, rate limit,
  update, readback, drift, disable, and rollback;
- cleanup is ledgered/idempotent and exercised in failure tests;
- routine CI tests the harness without privilege or firewall mutation;
- privileged runs emit a machine-readable bounded evidence artifact;
- lack of a privileged host is recorded as unqualified, not pass;
- Phase 88 RETAIN remains in force unless a later plan re-evaluates it with
  real evidence.

## Rejection criteria

Reject implementation that:

- runs against the host/default namespace;
- enables privileged behavior without a second explicit opt-in gate;
- treats generated nft syntax as packet-enforcement proof;
- treats a skipped root test as passing qualification;
- depends on cleanup only through normal process exit;
- flushes broad nftables state;
- mixes eBPF/PF/WFP qualification into this phase;
- changes publication/extraction status.
