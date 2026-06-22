# App Server Root Compatibility Path

`src/app_server` is a compatibility facade. The canonical app-server implementation lives in `crates/synvoid-app-server`.

Do not add new app-server implementation here. Add implementation to `crates/synvoid-app-server` and expose only compatibility re-exports from this directory when needed.
