# Command-Line Output Compatibility Cleanup — Iteration 109

## Purpose

The command/supervisor cleanup line is architecturally complete after Iterations 101–108:

- `src/main.rs` is thin.
- `src/commands/plan.rs` owns typed command classification.
- `src/commands/execute.rs` is a thin dispatcher.
- supervisor-control commands have typed outcomes/errors.
- runtime launch has a typed planning/execution boundary.
- one-shot commands have typed outcomes/errors.
- final planner and source guards cover precedence, feature gates, restart behavior, boundaries, and docs.

The only remaining cleanup concern is output compatibility. Iteration 107 centralized one-shot formatting, which is correct architecturally, but some command output was reconstructed from earlier print sequences. This pass should lock down script-facing output and document human-facing output expectations without reopening the architecture.

## Non-Goals

Do not introduce new architecture boundaries.

Do not change command classification.

Do not change command names or flags.

Do not change supervisor IPC semantics.

Do not change runtime launch behavior.

Do not move code back into `src/main.rs` or `src/commands/execute.rs`.

Do not add dependencies unless the repository already has an approved snapshot-testing dependency.

Do not perform broad style cleanup.

## Scope

Focus on output contracts for commands that users or scripts may consume directly:

- `--export-openapi`;
- `--export-api-spec`;
- `--hash-token`;
- `--generatetoken`;
- `--generatenewtoken`;
- `--checkregex`;
- `--configtest`;
- mesh-gated human-facing commands where enabled: `--genesis`, `--show-node-info`, `--export-threat-feed`.

The highest-risk contracts are JSON-only and token/hash-only outputs. Human-facing informational text can be documented as stable-shape rather than byte-for-byte stable unless the old output is known to be script-consumed.

## Desired End State

After this pass:

- JSON export commands are guaranteed to emit only valid JSON on stdout on success.
- `--hash-token` emits only the hash on stdout on success.
- `--generatetoken` emits only the token on stdout on success.
- `--checkregex` preserves documented safe/unsafe output and exit-code behavior.
- `--generatenewtoken` documents and tests which lines are stdout vs stderr/logging-sensitive.
- human-facing commands have shape tests or documented compatibility notes.
- `architecture/cli_supervisor_command_dispatch.md` documents output contracts.
- guard tests prevent JSON/hash/token implementation details from regressing into extra stdout text.

## Phase 1 — Audit Historical Output Expectations

Inspect the pre-Iteration-107 behavior if available in git history or commit diffs. Compare old print behavior to current `OneShotOutcome::display()` output for:

```text
--export-openapi
--export-api-spec
--hash-token
--generatetoken
--generatenewtoken
--checkregex
--configtest
--genesis
--show-node-info
```

Record findings in the implementation commit body or architecture doc:

```text
command | old stdout | current stdout | compatibility target | script-facing?
```

Do not modify code during this audit unless a clear output regression is found.

## Phase 2 — Lock Script-Facing Outputs

Add focused tests in `src/commands/one_shot.rs` or a dedicated integration test.

Required assertions:

```rust
#[test]
fn hash_token_outcome_stdout_is_hash_only() { ... }

#[test]
fn generated_token_outcome_stdout_is_token_only() { ... }

#[test]
fn openapi_outcome_stdout_is_json_only() { ... }

#[test]
fn api_spec_outcome_stdout_is_json_only() { ... }
```

For JSON-only tests, do not assert exact formatting unless already stable. Assert:

- output starts with `{` or `[`;
- output parses as JSON;
- output does not contain human preamble text such as `Exported`, `Schema`, `OpenAPI`, unless that is part of the JSON value.

For hash/token tests, assert:

- exactly one line;
- no labels such as `Token:` or `Hash:`;
- no trailing explanatory text;
- newline handling is performed by the outer `println!`, not embedded display text if possible.

## Phase 3 — Lock Regex Output And Exit Codes

Add tests for:

```rust
RegexCheck { safe: true } => exit code 0 and text contains "Pattern is safe"
RegexCheck { safe: false } => exit code 1 and text contains "Pattern is UNSAFE"
unsafe regex with reason includes reason line
unsafe regex without reason does not print "unknown" unless this was historical behavior
```

If the previous implementation printed `unknown` when no reason existed, decide whether compatibility requires keeping it. Prefer documented stable-shape behavior over preserving awkward text unless scripts rely on it.

## Phase 4 — Config Test Output Compatibility

Current `OneShotOutcome::ConfigValid` displays:

```text
All configuration files are valid
```

Compare with prior `handle_configtest()` success output.

If prior output differed, choose one:

1. Preserve prior output exactly; or
2. Document the new success message and treat it as human-facing.

Given configtest may be used in scripts, exit code is more important than success text. Add tests for:

- success exits 0;
- config invalid errors exit 1;
- no JSON/token contamination in configtest output.

## Phase 5 — `--generatenewtoken` Output Split

`--generatenewtoken` is likely semi-script-facing because it emits a token and writes config.

Current `NewTokenGenerated` display includes token, config path, and admin-token note.

Decide and document the contract:

- first stdout line is the token;
- later stdout lines are human-facing notes; or
- token-only output is preferred and notes move to stderr/logging.

For compatibility, preserve the existing/current shape unless old behavior clearly differed.

Add tests:

```rust
new_token_generated_first_line_is_token()
new_token_generated_mentions_config_path()
new_token_generated_exit_code_zero()
```

If scripts need token-only output in future, defer to a new explicit flag. Do not change behavior silently.

## Phase 6 — Human-Facing Mesh Command Shape Tests

For mesh-gated commands, use cfg-gated tests.

`--genesis` shape test:

- contains `Genesis key generated successfully`;
- contains `genesis_key_base64`;
- contains the generated key at least once;
- exits 0.

`--show-node-info` shape test:

- contains `Node Information:`;
- contains either `Mesh Role:` or `Mesh: NOT enabled`;
- exits 0 when config exists; otherwise error path is documented.

Do not require live mesh networking.

## Phase 7 — Add Output Contract Documentation

Update:

```text
architecture/cli_supervisor_command_dispatch.md
```

Add a concise section:

```markdown
## Output Compatibility Contracts

Script-facing stdout contracts:

- `--export-openapi`: stdout is JSON only on success.
- `--export-api-spec`: stdout is JSON only on success.
- `--hash-token`: stdout is the bcrypt hash only on success.
- `--generatetoken`: stdout is the token only on success.
- `--generatenewtoken`: first stdout line is the token; later lines are human-facing notes.
- `--checkregex`: stdout is human-facing; exit code is the machine contract.

Stderr is reserved for errors and warnings unless noted.
```

Update `AGENTS.md` only if it has a command-dispatch section that should mention output contracts.

## Phase 8 — Add Guard Against Output Contract Regression

Extend `tests/cli_command_dispatch_guard.rs` with source guards if useful.

Examples:

```rust
#[test]
fn one_shot_json_outputs_are_not_prefixed_with_human_text() {
    let source = read("src/commands/one_shot.rs");
    assert!(!source.contains("OpenAPI schema:"));
    assert!(!source.contains("Exported OpenAPI"));
}

#[test]
fn token_hash_outputs_are_not_labeled() {
    let source = read("src/commands/one_shot.rs");
    assert!(!source.contains("Hash:"));
    assert!(!source.contains("Token:"));
}
```

Prefer behavioral unit tests over brittle source guards when possible.

## Phase 9 — Verification

Minimum:

```bash
cargo fmt
cargo check -p synvoid
cargo test -p synvoid one_shot
cargo test -p synvoid commands::plan
cargo test --test cli_command_dispatch_guard
```

Recommended broader guard suite:

```bash
cargo test -p synvoid commands
cargo test command_dispatch
cargo test --test root_module_ledger_guard
```

Feature checks if mesh output paths are touched:

```bash
cargo check --no-default-features --features mesh,dns
cargo check -p synvoid-mesh --features mesh
```

Manual smoke checks when possible:

```bash
synvoid --export-openapi | jq . >/dev/null
synvoid --export-api-spec | jq . >/dev/null
synvoid --hash-token test-token
synvoid --generatetoken
synvoid --checkregex '\d+'
```

If commands require config or a running supervisor, document why they were not run.

## Acceptance Criteria

This cleanup pass is complete when:

- script-facing stdout contracts are documented;
- JSON export outputs are protected as JSON-only;
- token/hash outputs are protected as token/hash-only;
- regex safe/unsafe output and exit codes are tested;
- `generatenewtoken` first-line token behavior is documented/tested or intentionally adjusted with rationale;
- human-facing mesh command output is covered by shape tests where practical;
- no architectural boundary changes are introduced;
- the command/supervisor cleanup line can remain closed after this compatibility lock.

## Expected Files To Touch

Likely:

```text
src/commands/one_shot.rs
tests/cli_command_dispatch_guard.rs
architecture/cli_supervisor_command_dispatch.md
AGENTS.md
```

Possibly:

```text
plans/roadmap.md
```

Avoid touching unless an output regression requires it:

```text
src/main.rs
src/commands/execute.rs
src/commands/plan.rs
src/commands/runtime_launch.rs
src/commands/supervisor_control.rs
src/worker/unified_server/**
crates/synvoid-http/**
crates/synvoid-http3/**
crates/synvoid-mesh/**
```

## Handoff Summary

Iteration 109 is a final compatibility lock, not a new refactor. The command architecture is complete; this pass should only audit and protect stdout/stderr contracts for commands likely to be used by scripts, especially JSON export, token/hash generation, regex checks, and generated-token config updates.
