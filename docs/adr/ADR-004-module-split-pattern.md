# ADR-004: Module Split Pattern for Large Files

## Status
Accepted

## Date
2026-04-05

## Context
Some modules in the codebase exceed 1000 lines (e.g., `http/server.rs` ~3238 lines, `tls/server.rs` ~1747 lines, `mesh/transport.rs` ~2609 lines). The question arose about when and how to split large modules.

## Decision
**Large files are split using sibling files (`foo_bar.rs`), NOT subdirectories.** Each submodule is a sibling file to the parent module file.

### Module Split Rules

1. **Struct definitions stay in parent file**; submodules add `impl StructName { ... }` blocks to avoid circular references

2. **Each submodule is a sibling file** (`foo_bar.rs`), NOT a subdirectory. Subdirectories add unnecessary nesting depth.

3. **Submodules use `use super::*`** or `use crate::module::*` for imports

4. **Fields accessed from submodules must be `pub(crate)`**, not private

5. **Module declarations go in parent module file**, not in the struct's file

### When NOT to Split

Do NOT split cohesive request pipelines like:
- `http/server.rs` and `tls/server.rs` - These handle a single logical flow with 15 distinct phases in `handle_request()`. Section comments delineate each phase.
- `tls/server.rs` mirrors `http/server.rs` with the same reasoning.

For these files, **prefer section comments over refactoring** for readability.

## Examples

### Correct Split Pattern
```
src/mesh/
├── mod.rs           # Declares submodules
├── transport.rs     # Struct definitions, small impl blocks
├── transport_types.rs  # Additional types
├── transport_peer.rs   # Peer-specific logic
└── transport_proxy.rs  # Proxy-specific logic
```

### Incorrect (Would be)
```
src/mesh/
├── mod.rs
├── transport/
│   ├── mod.rs      # Unnecessary nesting
│   ├── core.rs     # Overly granular
│   ├── peer.rs
│   └── proxy.rs
│   └── types.rs
└── ...
```

## Rationale

### Sibling Files Over Subdirectories
- Shallow module hierarchy is easier to navigate
- Flat structure reduces import path complexity
- IDE tooling works better with flat structures
- Avoids `mod.rs` boilerplate

### Section Comments Over Full Split
For cohesive pipelines like `http/server.rs`, splitting introduces risk without meaningful benefit:
- The phases are sequential and interdependent
- Splitting adds cross-module communication overhead
- Section comments provide organization within the file

## Consequences

### Positive
- Clear guideline for when to split
- Consistent module structure across codebase
- Avoids over-engineering small files

### Negative
- Some large files remain large (intentional)
- Requires discipline to maintain section comments

## References
- `AGENTS.md` - Module Size Guide
- `src/mesh/` - Example of correct sibling file pattern
