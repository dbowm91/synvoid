# Static Files Root Compatibility Path

`src/static_files` is a transitional compatibility surface. The canonical static file implementation lives in `crates/synvoid-static-files`.

Do not add new domain implementation here. Root-local adapters may remain only when they are documented in `architecture/root_module_ledger.md` and cannot yet move without introducing a circular dependency. The local `file_manager` submodule is a known root-owned adapter that needs investigation before it can be extracted.
