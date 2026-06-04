// NOTE: The OverseerState and UpgradeState types were removed during the
// overseer->supervisor refactor. The tests below are preserved as ignored
// to document the original intent. The state machine was either inlined or
// replaced by a different mechanism in the new SupervisorState.
#[allow(dead_code)]
mod upgrade_flow_tests {
    #[test]
    #[ignore = "UpgradeState was removed during overseer->supervisor refactor"]
    fn test_upgrade_state_default() {}

    #[test]
    #[ignore = "UpgradeState was removed during overseer->supervisor refactor"]
    fn test_upgrade_state_transitions() {}

    #[test]
    #[ignore = "UpgradeState was removed during overseer->supervisor refactor"]
    fn test_upgrade_state_is_terminal() {}

    #[test]
    #[ignore = "UpgradeState was removed during overseer->supervisor refactor"]
    fn test_upgrade_state_is_transition() {}

    #[test]
    #[ignore = "UpgradeState was removed during overseer->supervisor refactor"]
    fn test_upgrade_state_max_duration() {}

    #[test]
    #[ignore = "OverseerState was removed during overseer->supervisor refactor"]
    fn test_overseer_state_default() {}

    #[test]
    #[ignore = "OverseerState was removed during overseer->supervisor refactor"]
    fn test_overseer_state_can_stage() {}

    #[test]
    #[ignore = "OverseerState was removed during overseer->supervisor refactor"]
    fn test_overseer_state_can_apply() {}

    #[test]
    #[ignore = "OverseerState was removed during overseer->supervisor refactor"]
    fn test_overseer_state_can_rollback() {}

    #[test]
    #[ignore = "OverseerState was removed during overseer->supervisor refactor"]
    fn test_overseer_state_enter_state() {}

    #[test]
    #[ignore = "OverseerState was removed during overseer->supervisor refactor"]
    fn test_overseer_state_needs_recovery() {}

    #[test]
    #[ignore = "OverseerState was removed during overseer->supervisor refactor"]
    fn test_overseer_state_is_dual_master_state() {}

    #[test]
    #[ignore = "OverseerState was removed during overseer->supervisor refactor"]
    fn test_overseer_state_can_abort_upgrade() {}

    #[test]
    #[ignore = "OverseerState was removed during overseer->supervisor refactor"]
    fn test_overseer_state_version_tracking() {}

    #[test]
    #[ignore = "OverseerState was removed during overseer->supervisor refactor"]
    fn test_overseer_state_error_tracking() {}

    #[test]
    #[ignore = "OverseerState was removed during overseer->supervisor refactor"]
    fn test_overseer_persistence_can_create() {}
}
