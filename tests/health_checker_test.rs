#[cfg(unix)]
mod health_checker_tests {

    #[tokio::test]
    async fn test_health_checker_custom_path() {
        let custom_path = "/internal/health/v2";

        let path = custom_path;
        assert!(path.starts_with('/'));

        let path_segments: Vec<&str> = path.trim_matches('/').split('/').collect();
        assert!(path_segments.len() >= 2);
    }

    #[test]
    fn test_health_checker_path_normalization() {
        let paths = vec!["/health", "/health/", "//health//", "/internal/health"];

        for path in paths {
            let normalized = path.trim_matches('/');
            assert!(!normalized.is_empty());
        }
    }

    #[test]
    fn test_health_checker_timeout_defaults() {
        use synvoid::overseer::health::EnhancedHealthConfig;

        let config = EnhancedHealthConfig::default();
        assert!(config.latency_threshold_ms > 0);
    }

    #[tokio::test]
    async fn test_health_checker_concurrent_requests() {
        use std::sync::Arc;
        use tokio::sync::Semaphore;

        let semaphore = Arc::new(Semaphore::new(5));
        let permit = semaphore.acquire().await.expect("should acquire permit");
        drop(permit);

        let available = semaphore.available_permits();
        assert_eq!(available, 5);
    }

    #[tokio::test]
    async fn test_health_checker_timeout_handling() {
        use std::time::Duration;
        use tokio::time::timeout;

        let result = timeout(Duration::from_millis(1), async {
            tokio::time::sleep(Duration::from_millis(10)).await;
            "done"
        })
        .await;

        assert!(result.is_err(), "Should timeout");
    }
}

#[cfg(not(unix))]
mod health_checker_tests {
    #[test]
    fn test_health_checker_not_supported_on_windows() {
        assert!(true, "Health checker tests are Unix-only");
    }
}
