//! Root composition adapter from mesh-owned approved YARA rules to the
//! upload consumer's source-only snapshot contract.

use std::sync::Arc;

use synvoid_upload::YaraRuleSnapshotProvider;

/// Exposes the mesh manager's accepted source and version without giving the
/// upload crate access to mesh transport, signing, or distribution controls.
pub struct MeshYaraRuleSnapshotAdapter {
    manager: Arc<crate::mesh::yara_rules::YaraRulesManager>,
}

impl MeshYaraRuleSnapshotAdapter {
    pub fn new(manager: Arc<crate::mesh::yara_rules::YaraRulesManager>) -> Self {
        Self { manager }
    }
}

impl YaraRuleSnapshotProvider for MeshYaraRuleSnapshotAdapter {
    fn current_version(&self) -> Option<String> {
        self.manager.get_current_version()
    }

    fn current_source(&self) -> Option<String> {
        self.manager.get_current_rules()
    }
}
