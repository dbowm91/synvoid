mod corpus;
use corpus::{ExpectedResult, FixtureAttackType, RequestFixture};
use std::path::PathBuf;

#[cfg(test)]
mod waf_corpus_tests {
    use super::*;
    use http::HeaderMap;
    use maluwaf::waf::attack_detection::{AttackDetectionConfig, AttackDetector};
    use std::net::IpAddr;

    fn fixtures_dir() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/waf")
    }

    fn default_attack_config() -> AttackDetectionConfig {
        AttackDetectionConfig::default()
    }

    fn run_detection(
        detector: &AttackDetector,
        method: &http::Method,
        path: &str,
        query_string: Option<&str>,
        headers: &http::HeaderMap,
        body: Option<&[u8]>,
    ) -> Option<maluwaf::waf::attack_detection::AttackDetectionResult> {
        detector.check_request(method, path, query_string, headers, body).0
    }

    fn check_result_matches_expected(
        result: Option<&maluwaf::waf::attack_detection::AttackDetectionResult>,
        expected: ExpectedResult,
    ) -> bool {
        match expected {
            ExpectedResult::Detect => result.is_some(),
            ExpectedResult::Pass => result.is_none(),
        }
    }

    #[test]
    fn test_waf_corpus_trusted_proxy_xff() {
        let fixtures = RequestFixture::load_all(&fixtures_dir());
        let xff_fixtures: Vec<_> = fixtures
            .iter()
            .filter(|f| f.id.starts_with("xff_"))
            .collect();

        assert!(!xff_fixtures.is_empty(), "Expected XFF fixtures to exist");

        for fixture in xff_fixtures {
            let detector = AttackDetector::new(default_attack_config());
            let method = http::Method::from_bytes(fixture.request.method.as_bytes()).unwrap();
            let headers = fixture.build_headers(&fixtures_dir());

            let result = run_detection(
                &detector,
                &method,
                &fixture.request.path,
                fixture.request.query_string.as_deref(),
                &headers,
                fixture.body_bytes(&fixtures_dir()).as_deref(),
            );

            let matches = check_result_matches_expected(result.as_ref(), fixture.expected_result);
            assert!(
                matches,
                "Fixture {} (expected {:?}) got {:?}",
                fixture.id, fixture.expected_result, result
            );
        }
    }

    #[test]
    fn test_waf_corpus_serverless_bypass() {
        let fixtures = RequestFixture::load_all(&fixtures_dir());

        let fixture = fixtures
            .iter()
            .find(|f| f.id == "serverless_route_bypass")
            .expect("serverless_route_bypass fixture should exist");

        let detector = AttackDetector::new(default_attack_config());
        let method = http::Method::from_bytes(fixture.request.method.as_bytes()).unwrap();
        let headers = fixture.build_headers(&fixtures_dir());

        let result = run_detection(
            &detector,
            &method,
            &fixture.request.path,
            fixture.request.query_string.as_deref(),
            &headers,
            fixture.body_bytes(&fixtures_dir()).as_deref(),
        );

        assert!(
            result.is_none(),
            "Serverless bypass NOT detected (known bypass case): {}",
            fixture.request.path
        );
    }

    #[test]
    fn test_waf_corpus_sqli_with_invalid_utf8() {
        let fixtures = RequestFixture::load_all(&fixtures_dir());

        let fixture = fixtures
            .iter()
            .find(|f| f.id == "sqli_invalid_utf8")
            .expect("sqli_invalid_utf8 fixture should exist");

        let detector = AttackDetector::new(default_attack_config());
        let method = http::Method::from_bytes(fixture.request.method.as_bytes()).unwrap();

        let result = run_detection(
            &detector,
            &method,
            &fixture.request.path,
            fixture.request.query_string.as_deref(),
            &HeaderMap::new(),
            None,
        );

        assert!(
            result.is_some(),
            "SQLi with invalid UTF-8 should be detected"
        );
    }

    #[test]
    fn test_waf_corpus_xss_invalid_utf8() {
        let fixtures = RequestFixture::load_all(&fixtures_dir());

        let fixture = fixtures
            .iter()
            .find(|f| f.id == "xss_invalid_utf8")
            .expect("xss_invalid_utf8 fixture should exist");

        let detector = AttackDetector::new(default_attack_config());
        let method = http::Method::from_bytes(fixture.request.method.as_bytes()).unwrap();

        let result = run_detection(
            &detector,
            &method,
            &fixture.request.path,
            None,
            &HeaderMap::new(),
            None,
        );

        assert!(
            result.is_some(),
            "XSS with invalid UTF-8 should be detected"
        );
    }

    #[test]
    fn test_waf_corpus_multipart_field_attack() {
        let fixtures = RequestFixture::load_all(&fixtures_dir());

        let fixture = fixtures
            .iter()
            .find(|f| f.id == "multipart_field_attack")
            .expect("multipart_field_attack fixture should exist");

        let detector = AttackDetector::new(default_attack_config());
        let method = http::Method::from_bytes(fixture.request.method.as_bytes()).unwrap();
        let headers = fixture.build_headers(&fixtures_dir());
        let body = fixture.body_bytes(&fixtures_dir());

        let result = run_detection(
            &detector,
            &method,
            &fixture.request.path,
            fixture.request.query_string.as_deref(),
            &headers,
            body.as_deref(),
        );

        assert!(
            result.is_none(),
            "Multipart field attack NOT detected (known gap to fix)"
        );
    }

    #[test]
    fn test_waf_corpus_chunk_boundary_split() {
        let fixtures = RequestFixture::load_all(&fixtures_dir());

        let fixture = fixtures
            .iter()
            .find(|f| f.id == "chunk_boundary_split")
            .expect("chunk_boundary_split fixture should exist");

        let detector = AttackDetector::new(default_attack_config());
        let method = http::Method::from_bytes(fixture.request.method.as_bytes()).unwrap();
        let headers = fixture.build_headers(&fixtures_dir());
        let body = fixture.body_bytes(&fixtures_dir());

        let result = run_detection(
            &detector,
            &method,
            &fixture.request.path,
            fixture.request.query_string.as_deref(),
            &headers,
            body.as_deref(),
        );

        assert!(
            result.is_none(),
            "Chunk boundary split NOT detected (known bypass case)"
        );
    }

    #[test]
    fn test_waf_corpus_raw_cl_te_smuggling() {
        let fixtures = RequestFixture::load_all(&fixtures_dir());

        let fixture = fixtures
            .iter()
            .find(|f| f.id == "raw_cl_te_smuggling")
            .expect("raw_cl_te_smuggling fixture should exist");

        let detector = AttackDetector::new(default_attack_config());
        let method = http::Method::from_bytes(fixture.request.method.as_bytes()).unwrap();
        let headers = fixture.build_headers(&fixtures_dir());
        let body = fixture.body_bytes(&fixtures_dir());

        let result = run_detection(
            &detector,
            &method,
            &fixture.request.path,
            fixture.request.query_string.as_deref(),
            &headers,
            body.as_deref(),
        );

        assert!(result.is_some(), "Raw CL/TE smuggling should be detected");
    }

    #[test]
    fn test_waf_corpus_query_string_proxy_path() {
        let fixtures = RequestFixture::load_all(&fixtures_dir());

        let fixture = fixtures
            .iter()
            .find(|f| f.id == "query_string_proxy_path")
            .expect("query_string_proxy_path fixture should exist");

        let detector = AttackDetector::new(default_attack_config());
        let method = http::Method::from_bytes(fixture.request.method.as_bytes()).unwrap();

        let result = run_detection(
            &detector,
            &method,
            &fixture.request.path,
            fixture.request.query_string.as_deref(),
            &HeaderMap::new(),
            None,
        );

        assert!(
            result.is_some(),
            "Query string proxy path attack should be detected"
        );
    }

    #[test]
    fn test_waf_corpus_cache_purge_auth() {
        let fixtures = RequestFixture::load_all(&fixtures_dir());

        let fixture = fixtures
            .iter()
            .find(|f| f.id == "cache_purge_auth")
            .expect("cache_purge_auth fixture should exist");

        let detector = AttackDetector::new(default_attack_config());
        let method = http::Method::from_bytes(fixture.request.method.as_bytes()).unwrap();
        let headers = fixture.build_headers(&fixtures_dir());

        let result = run_detection(
            &detector,
            &method,
            &fixture.request.path,
            fixture.request.query_string.as_deref(),
            &headers,
            None,
        );

        assert!(
            result.is_none(),
            "Cache purge with auth should NOT be detected as attack"
        );
    }

    #[test]
    fn test_waf_corpus_ssrf_encoded_private_ip() {
        let fixtures = RequestFixture::load_all(&fixtures_dir());

        let ssrf_fixtures: Vec<_> = fixtures
            .iter()
            .filter(|f| f.id.starts_with("ssrf_"))
            .collect();

        assert!(!ssrf_fixtures.is_empty(), "Expected SSRF fixtures to exist");

        for fixture in ssrf_fixtures {
            let detector = AttackDetector::new(default_attack_config());
            let method = http::Method::from_bytes(fixture.request.method.as_bytes()).unwrap();

            let result = run_detection(
                &detector,
                &method,
                &fixture.request.path,
                fixture.request.query_string.as_deref(),
                &HeaderMap::new(),
                None,
            );

            let matches = check_result_matches_expected(result.as_ref(), fixture.expected_result);
            assert!(
                matches,
                "Fixture {} (expected {:?}) got {:?}",
                fixture.id, fixture.expected_result, result
            );
        }
    }

    #[test]
    fn test_waf_corpus_negative_controls() {
        let fixtures = RequestFixture::load_all(&fixtures_dir());

        let negative_fixtures: Vec<_> = fixtures
            .iter()
            .filter(|f| f.id.starts_with("normal_") || f.id.starts_with("benign_"))
            .collect();

        assert!(
            !negative_fixtures.is_empty(),
            "Expected negative control fixtures to exist"
        );

        for fixture in negative_fixtures {
            let detector = AttackDetector::new(default_attack_config());
            let method = http::Method::from_bytes(fixture.request.method.as_bytes()).unwrap();
            let headers = fixture.build_headers(&fixtures_dir());
            let body = fixture.body_bytes(&fixtures_dir());

            let result = run_detection(
                &detector,
                &method,
                &fixture.request.path,
                fixture.request.query_string.as_deref(),
                &headers,
                body.as_deref(),
            );

            assert!(
                result.is_none(),
                "Negative control {} should NOT be detected. Got: {:?}",
                fixture.id,
                result
            );
        }
    }

    #[test]
    fn test_waf_corpus_all_fixtures_loadable() {
        let fixtures = RequestFixture::load_all(&fixtures_dir());
        assert!(
            !fixtures.is_empty(),
            "At least one fixture should exist in tests/fixtures/waf/"
        );
    }

    #[test]
    fn test_waf_corpus_complete_coverage() {
        let fixtures = RequestFixture::load_all(&fixtures_dir());

        let expected_ids = vec![
            "xff_trusted_proxy_chain",
            "xff_external_ip_attack",
            "serverless_route_bypass",
            "sqli_invalid_utf8",
            "xss_invalid_utf8",
            "path_traversal_literal",
            "multipart_field_attack",
            "chunk_boundary_split",
            "raw_cl_te_smuggling",
            "cl_te_smuggling_detected",
            "query_string_proxy_path",
            "cache_purge_auth",
            "ssrf_encoded_private_ip",
            "ssrf_decimal_private_ip",
            "ssrf_octal_private_ip",
            "ssrf_localhost_variations",
            "normal_binary_upload",
            "normal_multipart_upload",
            "normal_admin_auth_failure",
            "normal_basic_auth_failure",
            "benign_query_strings",
            "benign_json_body",
            "benign_url_encoding",
        ];

        let loaded_ids: std::collections::HashSet<String> =
            fixtures.iter().map(|f| f.id.clone()).collect();
        let expected_ids: std::collections::HashSet<String> =
            expected_ids.into_iter().map(|s| s.to_string()).collect();

        let missing: Vec<_> = expected_ids.difference(&loaded_ids).collect();
        assert!(missing.is_empty(), "Missing fixtures: {:?}", missing);
    }

    #[tokio::test]
    async fn test_waf_full_request_path() {
        use maluwaf::waf::attack_detection::{AttackDetectionConfig, AttackDetector};

        let fixtures = RequestFixture::load_all(&fixtures_dir());
        let detector = AttackDetector::new(AttackDetectionConfig::default());

        for fixture in fixtures.iter().take(3) {
            let method = http::Method::from_bytes(fixture.request.method.as_bytes()).unwrap();
            let headers = fixture.build_headers(&fixtures_dir());
            let body = fixture.body_bytes(&fixtures_dir());

            let result = detector.check_request(
                &method,
                &fixture.request.path,
                fixture.request.query_string.as_deref(),
                &headers,
                body.as_deref(),
            ).0;

            match fixture.expected_result {
                ExpectedResult::Detect => {
                    assert!(
                        result.is_some(),
                        "Fixture {} should be detected",
                        fixture.id
                    );
                }
                ExpectedResult::Pass => {
                    assert!(
                        result.is_none(),
                        "Fixture {} should pass, got {:?}",
                        fixture.id,
                        result
                    );
                }
            }
        }
    }

    #[test]
    fn test_waf_corpus_request_smuggling_coverage() {
        let fixtures = RequestFixture::load_all(&fixtures_dir());

        let smuggling_fixtures: Vec<_> = fixtures
            .iter()
            .filter(|f| f.attack_type == FixtureAttackType::RequestSmuggling)
            .collect();

        assert!(
            !smuggling_fixtures.is_empty(),
            "Expected request smuggling fixtures"
        );

        for fixture in smuggling_fixtures {
            let detector = AttackDetector::new(default_attack_config());
            let method = http::Method::from_bytes(fixture.request.method.as_bytes()).unwrap();
            let headers = fixture.build_headers(&fixtures_dir());
            let body = fixture.body_bytes(&fixtures_dir());

            let result = run_detection(
                &detector,
                &method,
                &fixture.request.path,
                fixture.request.query_string.as_deref(),
                &headers,
                body.as_deref(),
            );

            match fixture.expected_result {
                ExpectedResult::Detect => {
                    assert!(
                        result.is_some(),
                        "Request smuggling fixture {} SHOULD be detected",
                        fixture.id
                    );
                }
                ExpectedResult::Pass => {
                    assert!(
                        result.is_none(),
                        "Request smuggling fixture {} NOT detected (known bypass case)",
                        fixture.id
                    );
                }
            }
        }
    }

    #[test]
    fn test_waf_corpus_entry_point_coverage() {
        let fixtures = RequestFixture::load_all(&fixtures_dir());

        let entry_points: std::collections::HashSet<_> =
            fixtures.iter().map(|f| f.entry_point.clone()).collect();

        assert!(
            entry_points.contains("path"),
            "Should have path entry point tests"
        );
        assert!(
            entry_points.contains("query_string"),
            "Should have query_string entry point tests"
        );
        assert!(
            entry_points.contains("post_body"),
            "Should have post_body entry point tests"
        );
        assert!(
            entry_points.contains("header:X-Forwarded-For"),
            "Should have X-Forwarded-For header entry point tests"
        );
        assert!(
            entry_points.contains("header:Authorization"),
            "Should have Authorization header entry point tests"
        );
    }

    #[test]
    fn test_waf_corpus_attack_type_coverage() {
        let fixtures = RequestFixture::load_all(&fixtures_dir());

        let mut attack_types = std::collections::HashSet::new();
        for fixture in &fixtures {
            if fixture.attack_type != FixtureAttackType::None {
                attack_types.insert(fixture.attack_type);
            }
        }

        let expected_attack_types = vec![
            FixtureAttackType::Sqli,
            FixtureAttackType::Xss,
            FixtureAttackType::PathTraversal,
            FixtureAttackType::Ssrf,
            FixtureAttackType::RequestSmuggling,
        ];

        for expected in expected_attack_types {
            assert!(
                attack_types.contains(&expected),
                "Missing attack type coverage for {:?}",
                expected
            );
        }
    }
}
