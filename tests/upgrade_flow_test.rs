mod upgrade_flow_tests {
    use maluwaf::overseer::state::{OverseerState, UpgradeState};

    #[test]
    fn test_upgrade_state_default() {
        let state = UpgradeState::default();
        assert!(matches!(state, UpgradeState::Idle));
    }

    #[test]
    fn test_upgrade_state_transitions() {
        let states = vec![
            UpgradeState::Idle,
            UpgradeState::Staging,
            UpgradeState::Spawning,
            UpgradeState::Validating,
            UpgradeState::Draining,
            UpgradeState::Committed,
            UpgradeState::RollingBack,
            UpgradeState::Failed,
            UpgradeState::RecoveryNeeded,
            UpgradeState::DualMasterActive,
            UpgradeState::DrainingOldMaster,
        ];

        for state in states {
            let display = format!("{}", state);
            assert!(!display.is_empty());
        }
    }

    #[test]
    fn test_upgrade_state_is_terminal() {
        assert!(UpgradeState::Idle.is_terminal());
        assert!(UpgradeState::Committed.is_terminal());
        assert!(UpgradeState::Failed.is_terminal());

        assert!(!UpgradeState::Staging.is_terminal());
        assert!(!UpgradeState::Draining.is_terminal());
    }

    #[test]
    fn test_upgrade_state_is_transition() {
        assert!(!UpgradeState::Idle.is_transition());
        assert!(UpgradeState::Staging.is_transition());
        assert!(UpgradeState::Spawning.is_transition());
    }

    #[test]
    fn test_upgrade_state_max_duration() {
        assert_eq!(UpgradeState::Staging.max_duration_secs(), Some(300));
        assert_eq!(UpgradeState::Spawning.max_duration_secs(), Some(120));
        assert_eq!(UpgradeState::Validating.max_duration_secs(), Some(300));
        assert_eq!(UpgradeState::Draining.max_duration_secs(), Some(600));
        assert_eq!(UpgradeState::Idle.max_duration_secs(), None);
    }

    #[test]
    fn test_overseer_state_default() {
        let state = OverseerState::default();
        assert!(matches!(state.state, UpgradeState::Idle));
    }

    #[test]
    fn test_overseer_state_can_stage() {
        let state = OverseerState::default();
        assert!(state.can_stage());

        let mut state = OverseerState::default();
        state.state = UpgradeState::Staging;
        assert!(!state.can_stage());
    }

    #[test]
    fn test_overseer_state_can_apply() {
        let mut state = OverseerState::default();
        state.state = UpgradeState::Staging;
        assert!(state.can_apply());

        let state = OverseerState::default();
        assert!(!state.can_apply());
    }

    #[test]
    fn test_overseer_state_can_rollback() {
        let mut state = OverseerState::default();
        state.state = UpgradeState::Validating;
        assert!(state.can_rollback());

        let mut state = OverseerState::default();
        state.state = UpgradeState::Failed;
        assert!(state.can_rollback());
    }

    #[test]
    fn test_overseer_state_enter_state() {
        let mut state = OverseerState::default();
        state.enter_state(UpgradeState::Staging);
        assert!(matches!(state.state, UpgradeState::Staging));
    }

    #[test]
    fn test_overseer_state_needs_recovery() {
        let mut state = OverseerState::default();
        state.state = UpgradeState::RecoveryNeeded;
        assert!(state.needs_recovery());

        let mut state = OverseerState::default();
        state.state = UpgradeState::DualMasterActive;
        assert!(state.needs_recovery());
    }

    #[test]
    fn test_overseer_state_is_dual_master_state() {
        let mut state = OverseerState::default();
        state.state = UpgradeState::DualMasterActive;
        assert!(state.is_dual_master_state());

        let mut state = OverseerState::default();
        state.state = UpgradeState::DrainingOldMaster;
        assert!(state.is_dual_master_state());
    }

    #[test]
    fn test_overseer_state_can_abort_upgrade() {
        let mut state = OverseerState::default();
        state.state = UpgradeState::Staging;
        assert!(state.can_abort_upgrade());

        let mut state = OverseerState::default();
        state.state = UpgradeState::DualMasterActive;
        assert!(state.can_abort_upgrade());
    }

    #[test]
    fn test_overseer_state_version_tracking() {
        let mut state = OverseerState::default();
        state.current_version = Some("1.0.0".to_string());
        state.staged_version = Some("2.0.0".to_string());
        state.staged_binary_path = Some("/path/to/binary".to_string());

        assert_eq!(state.current_version, Some("1.0.0".to_string()));
        assert_eq!(state.staged_version, Some("2.0.0".to_string()));
        assert_eq!(
            state.staged_binary_path,
            Some("/path/to/binary".to_string())
        );
    }

    #[test]
    fn test_overseer_state_error_tracking() {
        let mut state = OverseerState::default();
        state.last_error = Some("test error".to_string());
        state.state = UpgradeState::Failed;
        state.enter_state(UpgradeState::Failed);

        assert!(state.last_error.is_some());
        assert!(matches!(state.state, UpgradeState::Failed));
    }

    #[test]
    fn test_overseer_persistence_can_create() {
        let state = OverseerState::default();
        assert!(state.can_stage());
        assert_eq!(state.state, UpgradeState::Idle);
    }
}
