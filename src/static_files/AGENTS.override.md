# Static Files Root Compatibility Path

`src/static_files` is a pure re-export facade. The canonical static file implementation — including `FileManager` (`crates/synvoid-static-files/src/file_manager.rs`) — lives in `crates/synvoid-static-files`.

Do not add domain implementation here. Upload security capabilities (malware scanning, rate limiting, MIME detection) are injected into `FileManager` through the narrow `FileManagerSecurityBackend` trait; the production `UploadFileManagerBackend` adapter lives in the root HTTP layer (`src/http/file_manager.rs`). There is no periodic YARA-refresh background task: rule updates require a new backend + manager (see `FileManager::yara_rule_version`).
