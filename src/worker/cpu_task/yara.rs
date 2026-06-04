// Submodule: YARA scanner construction for the static CPU offload worker.

use std::sync::Arc;

use crate::upload::yara_scanner::{YaraRulesSource, YaraScanner};

pub fn build_yara_scanner_from_main_config(
    main_config: &crate::config::MainConfig,
) -> Option<Arc<YaraScanner>> {
    let defaults = &main_config.defaults.upload;
    if !defaults.scan_with_yara {
        return None;
    }
    let source = YaraRulesSource::from_config(
        defaults
            .yara_rules_dir
            .clone()
            .map(std::path::PathBuf::from),
        true,
    )
    .unwrap_or(YaraRulesSource::Bundled);
    match YaraScanner::with_timeout(source, defaults.yara_timeout_ms, 3, 100 * 1024 * 1024) {
        Ok(scanner) => Some(Arc::new(scanner)),
        Err(e) => {
            tracing::warn!("Failed to initialize cpu-worker YARA scanner: {}", e);
            None
        }
    }
}
