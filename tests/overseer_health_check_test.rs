mod overseer_health_check_tests {
    use maluwaf::overseer::health::{EnhancedHealthConfig, HealthChecker, ValidationMetrics};

    #[test]
    fn test_validation_metrics_default() {
        let metrics = ValidationMetrics::default();
        assert_eq!(metrics.total_checks, 0);
        assert_eq!(metrics.successful_checks, 0);
        assert_eq!(metrics.failed_checks, 0);
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
        assert_eq!(metrics.failed_checks, 1);
        assert_eq!(metrics.total_checks, 1);
    }

    #[test]
    fn test_enhanced_health_config_default() {
        let config = EnhancedHealthConfig::default();
        assert_eq!(config.timeout_secs, 30);
    }

    #[tokio::test]
    async fn test_health_checker_creation() {
        let config = EnhancedHealthConfig::default();
        let checker = HealthChecker::new(config.health_check_path.clone(), config.timeout_secs);
        assert_eq!(checker.health_path(), config.health_check_path);
    }
}
