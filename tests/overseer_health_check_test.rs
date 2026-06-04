// NOTE: The overseer::health module was removed during the overseer->supervisor
// refactor. The EnhancedHealthConfig and ValidationMetrics types no longer exist
// in the codebase. The tests below referenced the removed module and are preserved
// as ignored to document the original intent.
#[allow(dead_code)]
mod overseer_health_check_tests {
    use synvoid::supervisor::state::SupervisorStateTrackers;

    #[test]
    #[ignore = "EnhancedHealthConfig and ValidationMetrics were removed during overseer->supervisor refactor"]
    fn test_validation_metrics_default() {}

    #[tokio::test]
    #[ignore = "EnhancedHealthConfig and ValidationMetrics were removed during overseer->supervisor refactor"]
    async fn test_validation_metrics_increment_successful() {}

    #[tokio::test]
    #[ignore = "EnhancedHealthConfig and ValidationMetrics were removed during overseer->supervisor refactor"]
    async fn test_validation_metrics_increment_failed() {}

    #[test]
    #[ignore = "EnhancedHealthConfig was removed during overseer->supervisor refactor"]
    fn test_enhanced_health_config_default() {}

    #[test]
    fn test_supervisor_state_trackers_default() {
        let trackers = SupervisorStateTrackers::default();
        assert!(trackers.probe_tracker.is_none());
        assert!(trackers.suspicious_word_tracker.is_none());
    }
}
