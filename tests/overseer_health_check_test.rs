mod overseer_health_check_tests {
    use synvoid::overseer::health::{EnhancedHealthConfig, ValidationMetrics};

    #[test]
    fn test_validation_metrics_default() {
        let metrics = ValidationMetrics::default();
        assert_eq!(metrics.total_checks, 0);
        assert_eq!(metrics.successful_checks, 0);
    }

    #[tokio::test]
    async fn test_validation_metrics_increment_successful() {
        let mut metrics = ValidationMetrics::default();
        metrics.record_successful();
        assert_eq!(metrics.successful_checks, 1);
        assert_eq!(metrics.total_checks, 1);
    }

    #[tokio::test]
    async fn test_validation_metrics_increment_failed() {
        let mut metrics = ValidationMetrics::default();
        metrics.record_failed();
        assert_eq!(metrics.total_checks, 1);
    }

    #[test]
    fn test_enhanced_health_config_default() {
        let config = EnhancedHealthConfig::default();
        assert!(config.latency_threshold_ms > 0);
    }
}
