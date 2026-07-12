# Post-Milestone D Corrective Closure and Polish Plan

## Purpose

Milestone D moved the repository from broad workspace debt to **State B: release-ready for supported profiles**. This follow-up pass closes the remaining ambiguity before any stronger release claim: the `synvoid-icmp-filter` eBPF/all-features exception, supported-profile documentation, dependency/audit evidence, CI status visibility, and final release-polish notes.

This is not a new feature milestone. It is a corrective/closure/polish pass to make the repository's release boundary explicit and defensible.

## Current baseline

Recent validation claims:

- 2,760 tests passing across 9 targeted crates.
- Workspace clippy clean.
- Default supported profiles compile.
- Four no-default feature profiles compile.
- Zero ignored tests.
- `cargo-deny` passes.
- CI parity improved to include tarpit and mesh jobs.
- Final classification: **State B** because `--all-features` still fails on `synvoid-icmp-filter` eBPF dependency.

Remaining ambiguity:

- Whether the eBPF path should be supported now, stubbed/deferred like WireGuard, or excluded from release all-features validation.
- Whether CI status can be observed/reconciled for the final commit.
- Whether `cargo-audit` has been run locally or only cargo-deny has been used.
- Whether docs clearly define supported profiles versus experimental/host-dependent profiles.

## Non-goals

- Do not add new ICMP/eBPF functionality unless required to make existing feature behavior honest.
- Do not reopen Milestone A/B/C/D completed work.
- Do not claim absolute all-features release cleanliness if host/toolchain-dependent eBPF remains unsupported.
- Do not use broad feature removals that silently break documented functionality.

## Workstream 1: `synvoid-icmp-filter` eBPF feature classification

### Problem

The final Milestone D validation notes an all-features failure in `synvoid-icmp-filter` related to eBPF compilation. This prevents a strict State A classification unless the feature is fixed, safely stubbed, or formally excluded from release profiles.

### Tasks

1. Reproduce the failure:

```bash
cargo check -p synvoid-icmp-filter --all-targets
cargo check -p synvoid-icmp-filter --all-features --all-targets
cargo clippy -p synvoid-icmp-filter --all-targets -- -D warnings
cargo clippy -p synvoid-icmp-filter --all-features --all-targets -- -D warnings
```

2. Identify the feature and dependency boundary:

- feature name(s)
- eBPF crate/dependency involved
- host requirements
- toolchain requirements
- kernel/platform requirements
- whether failure is compile-time dependency availability, build script, generated artifact, or API drift

3. Choose one of three paths.

#### Option A: Fully support eBPF in this release

Use only if the dependency/toolchain path is stable enough.

Required:

- Add/fix missing optional dependencies.
- Gate Linux-only code with `cfg(target_os = "linux")`.
- Add clear unsupported-platform errors.
- Add tests that compile without requiring root/kernel privileges.
- Add CI job or documented manual validation for eBPF profile.

#### Option B: Supported safe stub/defer path

Preferred if eBPF needs host/kernel/toolchain work.

Required:

- Keep the feature compiling.
- Return explicit `UnsupportedFeature` / `EbpfUnavailable` errors at runtime.
- Do not pull host-only eBPF dependencies into default profiles.
- Document eBPF as experimental/deferred.
- Ensure `cargo check -p synvoid-icmp-filter --all-features --all-targets` passes.

#### Option C: Exclude eBPF from release all-features profile

Use only if the repository intentionally treats eBPF as out-of-band.

Required:

- Rename feature or mark it as `experimental-ebpf` if practical.
- Exclude it from release profile docs.
- Add a separate manual validation command.
- Make CI and docs explicit that `--all-features` is not the release profile.

### Success criteria

- `synvoid-icmp-filter` eBPF behavior is no longer ambiguous.
- Either all-features passes, or docs/CI define a supported release feature set that deliberately excludes eBPF.
- Runtime behavior for unavailable eBPF is explicit and safe.

## Workstream 2: Supported profile matrix formalization

### Problem

The repo is currently “release-ready for supported profiles,” but supported profiles must be named and documented. Otherwise future agents will continue treating all-features failures as ambiguous regressions.

### Tasks

1. Add or update a profile matrix document:

- `architecture/release_profile_matrix.md`, or
- `docs/RELEASE_PROFILES.md`

2. Include rows for:

- default workspace
- no-default-features core
- mesh
- dns
- mesh+dns
- upload
- honeypot
- tarpit
- tunnel default
- tunnel wireguard stub/deferred profile
- icmp-filter default
- icmp-filter eBPF experimental/deferred profile

3. For each row, include:

- command
- supported/beta/experimental/deferred status
- platform assumptions
- CI coverage
- local validation status
- release-blocking status

4. Update `AGENTS.md` and relevant docs to point to the matrix.

### Success criteria

- Supported release profiles are explicit.
- Experimental/deferred profiles are not confused with release blockers.
- CI commands and local validation commands align with the matrix.

## Workstream 3: Dependency/audit evidence closure

### Problem

Milestone D reports `cargo-deny` passing, but earlier workspace validation noted `cargo-audit` was unavailable locally. This pass should make dependency audit evidence explicit.

### Tasks

Run and record:

```bash
cargo deny check
cargo audit
cargo tree -d
cargo tree -i zip
cargo tree -i yara-x
cargo tree -i wasmtime
cargo tree -i defguard_boringtun
```

If `cargo audit` is unavailable:

- install it if allowed by local workflow, or
- record exact absence and confirm CI job runs it, or
- add a release-blocking note if neither local nor CI coverage exists.

Review:

- advisory ignores in `deny.toml`
- eBPF/WireGuard related deps
- duplicate dependency tree
- security-sensitive transitive dependencies

### Success criteria

- `cargo-deny` status is current.
- `cargo-audit` status is current or its absence is explicitly accepted with CI evidence.
- dependency exceptions are dated and justified.

## Workstream 4: CI status and workflow closure

### Problem

Connector status for the final commit may return no statuses. The repo should still make CI expectations explicit.

### Tasks

1. Query/check CI status manually if available.
2. Confirm workflow contains:

- upload job
- honeypot job
- tarpit job
- mesh job
- cargo-deny/security audit job
- dependency audit job
- fmt/clippy/test jobs
- summary job with all required `needs`

3. Verify workflow syntax after recent job additions.

Suggested local syntax checks:

```bash
ruby -e "require 'yaml'; YAML.load_file('.github/workflows/ci.yml'); puts 'workflow yaml parses'"
```

or:

```bash
python - <<'PY'
import yaml
from pathlib import Path
yaml.safe_load(Path('.github/workflows/ci.yml').read_text())
print('workflow yaml parses')
PY
```

4. If remote CI remains invisible, update validation notes to say local validation is authoritative and remote status visibility is unavailable.

### Success criteria

- CI workflow has no obvious stale job names.
- Summary job references all release-critical jobs.
- Remote status limitations are documented honestly.

## Workstream 5: Final release-polish validation note

### Required output

Create:

- `plans/post_milestone_d_closure_results.md`

Include:

- date/branch/commit SHA
- exact commands run
- eBPF/ICMP decision
- supported profile matrix link
- cargo-deny/audit results
- CI visibility status
- final classification

### Final classification choices

#### State A: Full release-clean

Use only if:

- all supported profiles pass
- all-features passes or eBPF is no longer in all-features
- clippy/test/fmt/deny/audit pass
- CI/profile docs align

#### State B+: Supported-profile release-clean with explicit experimental exceptions

Use if:

- all supported profiles pass
- eBPF remains experimental/deferred
- docs/CI clearly exclude eBPF from release profile
- no ambiguity remains

#### State C: Release blocked

Use if:

- supported profiles fail
- eBPF is documented as supported but does not compile
- audit/deny has unaccepted blocker
- CI/profile docs contradict actual commands

## Final acceptance checklist

- [ ] `synvoid-icmp-filter` eBPF failure is reproduced and classified.
- [ ] eBPF is fixed, safely stubbed, or explicitly excluded from supported release profiles.
- [ ] Supported release profile matrix exists.
- [ ] `AGENTS.md` points to the profile matrix.
- [ ] `cargo deny check` result is current.
- [ ] `cargo audit` result is current or explicitly covered by CI/exception.
- [ ] CI workflow syntax is checked.
- [ ] CI status visibility is documented.
- [ ] `plans/post_milestone_d_closure_results.md` exists.
- [ ] Final State A/B+/C classification is explicit.

## Handoff guidance

Prefer honest State B+ over a brittle State A claim. If eBPF requires kernel/toolchain integration, make it explicit as an experimental profile and keep default/supported release profiles clean and well documented.
