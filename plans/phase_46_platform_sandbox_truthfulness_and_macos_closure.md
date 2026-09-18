# Phase 46 Plan: Platform Sandbox Truthfulness and macOS Closure

Status: detailed handoff plan.

Roadmap: `plans/runtime_truthfulness_security_publication_roadmap.md`.

Baseline: `03cec2235fb250e64c33f29b66258eeb0607cdbc`.

## Primary goal

Treat `synvoid-platform` sandboxing as an enforceable security contract on every claimed platform, with special attention to the macOS Seatbelt backend's deprecated API, SBPL generation, capability reporting, and native verification.

## Current macOS implementation concerns

`crates/synvoid-platform/src/sandbox.rs` builds SBPL source by interpolating path strings into expressions such as:

```text
(allow file-read* (subpath "..."))
```

Current escaping only replaces backslashes. Quotes, newlines, control characters, or SBPL-significant input need an explicit encoding/rejection policy.

`apply_sandbox_impl` calls deprecated `sandbox_init` and passes a null error buffer, then reports `last_os_error()` on failure. The API provides an error string that should be consumed/freed when available.

The backend advertises broad `process_limits`, `network_restrictions`, and `child_process_restrictions` capability flags. Those flags need to describe actual enforced profile semantics, not assumptions from `deny default`.

The `Basic` profile generation currently emits both `(allow default)` and `(deny default)`; its intended semantics need explicit native verification.

Apple's supported application model is App Sandbox via entitlements, while `sandbox_init` is deprecated. For a CLI daemon/jail helper, moving wholesale to App Sandbox would be an architectural/distribution change rather than a drop-in API migration.

## Workstream A — Define support tiers

Document per platform:

- backend;
- minimum OS/kernel requirement;
- `Basic` semantics;
- `Strict` semantics;
- filesystem enforcement;
- network enforcement;
- child-process enforcement;
- process/resource limits;
- native CI/test evidence;
- support tier: supported / experimental / unavailable.

Do not expose one `SandboxCapabilities` boolean as true unless a test or platform primitive actually supports that statement.

## Workstream B — Safe SBPL path representation

Implement one canonical helper for SBPL string/path literals.

Options:

- reject paths containing bytes/characters that cannot be represented safely;
- or encode all required quote/backslash/control characters according to SBPL grammar.

Do not interpolate `Path::display()` output directly.

Canonicalize allowed paths before profile creation where doing so is compatible with jail startup order and path existence.

Add tests with:

- quote;
- backslash;
- newline/control;
- closing parenthesis;
- Unicode;
- symlink/canonicalization cases.

The resulting profile must never gain an extra SBPL expression from a path value.

## Workstream C — Correct Basic/Strict profiles

Define expected policy first, then generate it.

For `Basic`, decide whether it is deny-write outside allowed areas while allowing general reads/network, or another precisely bounded policy.

Do not emit contradictory default rules without a test proving the parser semantics.

For `Strict`, enumerate the minimum required runtime operations for WASM/YARA jail helpers. Avoid broad `(allow process)` if a narrower operation set is sufficient.

Explicitly decide networking: jail helpers should normally need no outbound network unless a capability says otherwise.

## Workstream D — Error reporting and FFI hygiene

Bind both `sandbox_init` and `sandbox_free_error`.

Pass a real error-buffer pointer, convert the message safely, free it on every failure path, and preserve an errno fallback only when no API error is available.

Keep runtime `dlsym` probing if needed, but make compile/link/probe semantics consistent: "compiled with feature" is not equal to "runtime backend available."

Add `// SAFETY:` comments around FFI calls describing pointer lifetime and ownership.

## Workstream E — Native macOS verification

Add a small child-process test binary or integration test that applies the sandbox and attempts operations after restriction.

Verify at minimum:

- allowed read succeeds;
- denied read fails;
- allowed write succeeds where configured;
- denied write fails;
- network connect behavior matches capability claim;
- child process behavior matches capability claim;
- strict mode cannot be "success" when Seatbelt feature/runtime support is absent.

Because sandboxing the test process is irreversible, use child processes per case.

Run on a native macOS release-validation host. A cross-compile check alone is not evidence of enforcement.

## Workstream F — Deprecation/support policy

Document plainly that the CLI/jail Seatbelt implementation uses deprecated `sandbox_init`.

Do not claim Apple App Sandbox equivalence.

Evaluate three long-term paths:

1. retain deprecated Seatbelt as an opt-in experimental CLI hardening backend with native tests;
2. package signed sandboxed helper executables with entitlements if distribution architecture supports it;
3. make Linux the strict-isolation production recommendation and document macOS as development/experimental.

Choose based on actual deployment goals, not aesthetics.

If the backend cannot be responsibly supported, downgrade the support claim rather than hiding the deprecation.

## Workstream G — Other platform capability truthfulness

Use the same audit to verify Windows/Capsicum/Pledge/Landlock capability flags.

Examples:

- Windows DACL manipulation is not automatically a complete read/write allowlist;
- Job Objects provide limits but not full network restriction;
- Capsicum/pledge semantics differ from path allowlists;
- Landlock availability should preferably probe the syscall/ABI rather than infer only from kernel version text.

Do not broaden implementation unless a capability claim is currently false.

## Publication dependency

Phase 47 must not classify `synvoid-platform` as an externally supported crate until this phase closes and the native platform matrix exists.

## Verification

```bash
cargo test -p synvoid-platform --profile ci
cargo check -p synvoid-platform --all-targets
cargo check --no-default-features --features macos-sandbox --target aarch64-apple-darwin
cargo xtask verify
```

Plus native macOS enforcement tests on the release-validation host.

## Acceptance criteria

- SBPL path input cannot alter profile syntax.
- Basic/Strict semantics are explicit and native-tested.
- Seatbelt FFI error strings are handled correctly.
- capability flags describe verified enforcement.
- documentation states the deprecated API/support tier truthfully.
- strict jail mode still fails closed when the requested backend is unavailable.
