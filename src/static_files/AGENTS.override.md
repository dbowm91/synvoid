# Static Files Root Compatibility Path

`src/static_files` is a compatibility facade. The canonical static file implementation lives in `crates/synvoid-static-files`.

Do not add new static file implementation here. Add implementation to `crates/synvoid-static-files` and expose only compatibility re-exports from this directory when needed.
