//! Worker process implementation.
//!
//! Handles HTTP request processing, TLS termination, connection management,
//! and WAF enforcement. Workers are spawned by the supervisor process and
//! communicate via IPC.
//!
//! ## Module layout
//!
//! The CPU offload worker (`run_cpu_worker`) lives in
//! the [`cpu_task`] subdirectory. The unified server worker
//! (`run_unified_server_worker`) lives in the [`unified_server`]
//! subdirectory.

use crate::common::setup_panic_handler;

pub mod common;
pub mod connect;
pub mod context;
pub mod cpu_task;
pub mod drain_adapter;
pub mod drain_state;
pub mod extension;
pub mod metrics;
pub mod traits;
pub mod unified_server;

mod connection;
mod image_poisoning;
mod response_builder;

pub use traits::{BaseWorkerState, WorkerLifecycle};

pub use cpu_task::{run_cpu_worker, CpuWorkerArgs};
pub use unified_server::{
    run_unified_server_worker, setup_unified_server_panic_handler, UnifiedServerWorkerArgs,
};

pub fn setup_worker_panic_handler() {
    let worker_panic_log = format!(
        "{}/synvoid-worker-panic.log",
        std::env::temp_dir().display()
    );
    setup_panic_handler("WORKER", Some(&worker_panic_log));
}

// The tests below exercise the minifier library used by the CPU offload
// worker. They live here (not in `cpu_task`) because the underlying types
// (`MinifierCache`, `ContentType`, `Encoding`, `MinifierGenerator`,
// `MinifierConfig`) live in `crate::static_files::minifier` and are shared
// by the unified server's static file path as well.
#[cfg(test)]
mod minifier_tests {
    use crate::config::site::SiteStaticConfig;
    use crate::static_files::minifier::{
        content_type_from_path, CacheEntry, CacheKey, ContentType, Encoding, MinifierCache,
        MinifierConfig, MinifierGenerator,
    };
    use bytes::Bytes;
    use std::io::Write;
    use std::sync::Arc;
    use std::time::{Instant, SystemTime};

    #[test]
    fn test_content_type_from_extension() {
        assert_eq!(ContentType::from_extension("html"), ContentType::Html);
        assert_eq!(ContentType::from_extension("htm"), ContentType::Html);
        assert_eq!(ContentType::from_extension("css"), ContentType::Css);
        assert_eq!(ContentType::from_extension("js"), ContentType::Js);
        assert_eq!(ContentType::from_extension("mjs"), ContentType::Js);
        assert_eq!(ContentType::from_extension("svg"), ContentType::Svg);
        assert_eq!(ContentType::from_extension("txt"), ContentType::Other);
        assert_eq!(ContentType::from_extension("bin"), ContentType::Other);
    }

    #[test]
    fn test_content_type_case_insensitive() {
        assert_eq!(ContentType::from_extension("HTML"), ContentType::Html);
        assert_eq!(ContentType::from_extension("CSS"), ContentType::Css);
        assert_eq!(ContentType::from_extension("SVG"), ContentType::Svg);
    }

    #[test]
    fn test_content_type_to_mime() {
        assert_eq!(ContentType::Html.to_mime(), "text/html");
        assert_eq!(ContentType::Css.to_mime(), "text/css");
        assert_eq!(ContentType::Js.to_mime(), "application/javascript");
        assert_eq!(ContentType::Svg.to_mime(), "image/svg+xml");
        assert_eq!(ContentType::Other.to_mime(), "application/octet-stream");
    }

    #[test]
    fn test_encoding_extension() {
        assert_eq!(Encoding::Gzip.extension(), "gz");
        assert_eq!(Encoding::Br.extension(), "br");
        assert_eq!(Encoding::None.extension(), "");
    }

    #[test]
    fn test_encoding_content_encoding() {
        assert_eq!(Encoding::Gzip.content_encoding(), "gzip");
        assert_eq!(Encoding::Br.content_encoding(), "br");
        assert_eq!(Encoding::None.content_encoding(), "");
    }

    #[test]
    fn test_cache_key_equality() {
        let key1 = CacheKey {
            site_id: Arc::from("site1"),
            path: Arc::from("/index.html"),
            encoding: Encoding::None,
        };
        let key2 = CacheKey {
            site_id: Arc::from("site1"),
            path: Arc::from("/index.html"),
            encoding: Encoding::None,
        };
        let key3 = CacheKey {
            site_id: Arc::from("site2"),
            path: Arc::from("/index.html"),
            encoding: Encoding::None,
        };

        assert_eq!(key1, key2);
        assert_ne!(key1, key3);
    }

    #[test]
    fn test_cache_key_with_different_encodings() {
        let key1 = CacheKey {
            site_id: Arc::from("site1"),
            path: Arc::from("/index.html"),
            encoding: Encoding::None,
        };
        let key2 = CacheKey {
            site_id: Arc::from("site1"),
            path: Arc::from("/index.html"),
            encoding: Encoding::Gzip,
        };

        assert_ne!(key1, key2);
    }

    #[test]
    fn test_cache_key_hash() {
        use std::collections::HashMap;
        let mut map = HashMap::new();

        let key1 = CacheKey {
            site_id: Arc::from("site1"),
            path: Arc::from("/index.html"),
            encoding: Encoding::None,
        };
        let key2 = CacheKey {
            site_id: Arc::from("site1"),
            path: Arc::from("/index.html"),
            encoding: Encoding::Gzip,
        };

        map.insert(key1.clone(), 1);
        map.insert(key2.clone(), 2);

        assert_eq!(map.len(), 2);
        assert_eq!(map.get(&key1), Some(&1));
        assert_eq!(map.get(&key2), Some(&2));
    }

    #[test]
    fn test_minifier_config_from_site_config_defaults() {
        let site_config = SiteStaticConfig {
            enabled: Some(true),
            enable_minification: Some(true),
            enable_html_minification: Some(true),
            enable_css_minification: Some(true),
            enable_js_minification: Some(true),
            enable_svg_compression: Some(true),
            enable_compression: Some(true),
            enable_brotli: Some(true),
            gzip_level: Some(6),
            brotli_level: Some(10),
            enable_file_cache: Some(true),
            cache_max_entries: Some(5000),
            cache_ttl_seconds: Some(1800),
            ..Default::default()
        };

        let config = MinifierConfig::from_site_config("test-site", &site_config);

        assert!(config.enabled);
        assert!(config.enable_html);
        assert!(config.enable_css);
        assert!(config.enable_js);
        assert!(config.enable_svg);
        assert!(config.enable_gzip);
        assert!(config.enable_brotli);
        assert_eq!(config.gzip_level, 6);
        assert_eq!(config.brotli_level, 10);
        assert!(config.enable_cache);
        assert_eq!(config.cache_max_entries, 5000);
        assert_eq!(config.cache_ttl_secs, 1800);
    }

    #[test]
    fn test_minifier_config_respects_disabled_flags() {
        let site_config = SiteStaticConfig {
            enable_minification: Some(false),
            enable_html_minification: Some(false),
            enable_css_minification: Some(false),
            enable_js_minification: Some(false),
            enable_svg_compression: Some(false),
            enable_compression: Some(false),
            enable_brotli: Some(false),
            enable_file_cache: Some(false),
            ..Default::default()
        };

        let config = MinifierConfig::from_site_config("test-site", &site_config);

        assert!(!config.enabled);
        assert!(!config.enable_html);
        assert!(!config.enable_css);
        assert!(!config.enable_js);
        assert!(!config.enable_svg);
        assert!(!config.enable_gzip);
        assert!(!config.enable_brotli);
        assert!(!config.enable_cache);
    }

    #[test]
    fn test_minifier_cache_insert_and_get() {
        let config = MinifierConfig {
            enabled: true,
            enable_html: true,
            enable_css: true,
            enable_js: true,
            enable_svg: true,
            enable_gzip: true,
            enable_brotli: true,
            gzip_level: 9,
            brotli_level: 11,
            minified_dir: std::env::temp_dir().join("synvoid-test-cache"),
            enable_cache: true,
            cache_max_entries: 100,
            cache_ttl_secs: 3600,
        };

        let cache = MinifierCache::new(config);

        let key = CacheKey {
            site_id: Arc::from("test-site"),
            path: Arc::from("/index.html"),
            encoding: Encoding::None,
        };

        let entry = CacheEntry {
            content: Bytes::from("<html>test</html>"),
            mtime: SystemTime::now(),
            generated_at: Instant::now(),
            content_type: ContentType::Html,
        };

        cache.insert(key.clone(), entry);

        let retrieved = cache.get(&key);
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().content, Bytes::from("<html>test</html>"));
    }

    #[test]
    fn test_minifier_cache_get_missing_returns_none() {
        let config = MinifierConfig {
            enabled: true,
            enable_html: true,
            enable_css: true,
            enable_js: true,
            enable_svg: true,
            enable_gzip: true,
            enable_brotli: true,
            gzip_level: 9,
            brotli_level: 11,
            minified_dir: std::env::temp_dir().join("synvoid-test-cache"),
            enable_cache: true,
            cache_max_entries: 100,
            cache_ttl_secs: 3600,
        };

        let cache = MinifierCache::new(config);

        let key = CacheKey {
            site_id: Arc::from("nonexistent"),
            path: Arc::from("/missing.html"),
            encoding: Encoding::None,
        };

        assert!(cache.get(&key).is_none());
    }

    #[test]
    fn test_minifier_cache_disabled_returns_none() {
        let config = MinifierConfig {
            enabled: false,
            enable_html: true,
            enable_css: true,
            enable_js: true,
            enable_svg: true,
            enable_gzip: true,
            enable_brotli: true,
            gzip_level: 9,
            brotli_level: 11,
            minified_dir: std::env::temp_dir().join("synvoid-test-cache"),
            enable_cache: true,
            cache_max_entries: 100,
            cache_ttl_secs: 3600,
        };

        let cache = MinifierCache::new(config);

        let key = CacheKey {
            site_id: Arc::from("test-site"),
            path: Arc::from("/index.html"),
            encoding: Encoding::None,
        };

        assert!(cache.get(&key).is_none());
    }

    #[test]
    fn test_minifier_cache_invalidate() {
        let config = MinifierConfig {
            enabled: true,
            enable_html: true,
            enable_css: true,
            enable_js: true,
            enable_svg: true,
            enable_gzip: true,
            enable_brotli: true,
            gzip_level: 9,
            brotli_level: 11,
            minified_dir: std::env::temp_dir().join("synvoid-test-cache"),
            enable_cache: true,
            cache_max_entries: 100,
            cache_ttl_secs: 3600,
        };

        let cache = MinifierCache::new(config);

        let key = CacheKey {
            site_id: Arc::from("test-site"),
            path: Arc::from("/index.html"),
            encoding: Encoding::None,
        };

        let entry = CacheEntry {
            content: Bytes::from("<html>test</html>"),
            mtime: SystemTime::now(),
            generated_at: Instant::now(),
            content_type: ContentType::Html,
        };

        cache.insert(key.clone(), entry.clone());
        assert!(cache.get(&key).is_some());

        cache.invalidate("test-site", "/index.html");
        assert!(cache.get(&key).is_none());
    }

    #[test]
    fn test_minifier_cache_clear_site() {
        let config = MinifierConfig {
            enabled: true,
            enable_html: true,
            enable_css: true,
            enable_js: true,
            enable_svg: true,
            enable_gzip: true,
            enable_brotli: true,
            gzip_level: 9,
            brotli_level: 11,
            minified_dir: std::env::temp_dir().join("synvoid-test-cache"),
            enable_cache: true,
            cache_max_entries: 100,
            cache_ttl_secs: 3600,
        };

        let cache = MinifierCache::new(config);

        let key1 = CacheKey {
            site_id: Arc::from("test-site"),
            path: Arc::from("/index.html"),
            encoding: Encoding::None,
        };
        let key2 = CacheKey {
            site_id: Arc::from("test-site"),
            path: Arc::from("/style.css"),
            encoding: Encoding::None,
        };
        let key3 = CacheKey {
            site_id: Arc::from("other-site"),
            path: Arc::from("/index.html"),
            encoding: Encoding::None,
        };

        let entry = CacheEntry {
            content: Bytes::from("content"),
            mtime: SystemTime::now(),
            generated_at: Instant::now(),
            content_type: ContentType::Other,
        };

        cache.insert(key1.clone(), entry.clone());
        cache.insert(key2.clone(), entry.clone());
        cache.insert(key3.clone(), entry.clone());

        assert!(cache.get(&key1).is_some());
        assert!(cache.get(&key2).is_some());
        assert!(cache.get(&key3).is_some());

        cache.clear_site("test-site");

        assert!(cache.get(&key1).is_none());
        assert!(cache.get(&key2).is_none());
        assert!(cache.get(&key3).is_some());
    }

    #[test]
    fn test_minifier_cache_hit_rate_calculation() {
        let config = MinifierConfig {
            enabled: true,
            enable_html: true,
            enable_css: true,
            enable_js: true,
            enable_svg: true,
            enable_gzip: true,
            enable_brotli: true,
            gzip_level: 9,
            brotli_level: 11,
            minified_dir: std::env::temp_dir().join("synvoid-test-cache"),
            enable_cache: true,
            cache_max_entries: 100,
            cache_ttl_secs: 3600,
        };

        let cache = MinifierCache::new(config);

        assert_eq!(cache.cache_hit_rate(), 0.0);

        let key = CacheKey {
            site_id: Arc::from("test-site"),
            path: Arc::from("/index.html"),
            encoding: Encoding::None,
        };

        let entry = CacheEntry {
            content: Bytes::from("<html>test</html>"),
            mtime: SystemTime::now(),
            generated_at: Instant::now(),
            content_type: ContentType::Html,
        };

        cache.insert(key.clone(), entry);

        cache.get(&key);
        let _misses = cache.cache_misses();

        let rate = cache.cache_hit_rate();
        assert!(rate >= 0.0 && rate <= 100.0);
    }

    #[test]
    fn test_cache_entry_clone() {
        let entry = CacheEntry {
            content: Bytes::from("test content"),
            mtime: SystemTime::now(),
            generated_at: Instant::now(),
            content_type: ContentType::Html,
        };

        let cloned = entry.clone();
        assert_eq!(cloned.content, entry.content);
        assert_eq!(cloned.mtime, entry.mtime);
        assert_eq!(cloned.generated_at, entry.generated_at);
        assert_eq!(cloned.content_type, entry.content_type);
    }

    #[test]
    fn test_encoding_clone() {
        let enc1 = Encoding::Gzip;
        let enc2 = enc1.clone();
        assert_eq!(enc1, enc2);

        let enc3 = Encoding::Br;
        let enc4 = enc3.clone();
        assert_eq!(enc3, enc4);

        let enc5 = Encoding::None;
        let enc6 = enc5.clone();
        assert_eq!(enc5, enc6);
    }

    #[test]
    fn test_minifier_generator_gzip_compression() {
        let generator = MinifierGenerator::new();

        let input = b"Hello, World! This is test content for gzip compression.";
        let compressed = generator.compress_gzip(input, 6).unwrap();

        assert!(compressed.len() < input.len() * 2);

        use std::io::Read;
        let mut decoder = flate2::read::GzDecoder::new(compressed.as_slice());
        let mut decompressed = Vec::new();
        decoder.read_to_end(&mut decompressed).unwrap();
        assert_eq!(decompressed.as_slice(), input);
    }

    #[test]
    fn test_minifier_generator_brotli_compression() {
        let generator = MinifierGenerator::new();

        let input = b"Hello, World! This is test content for brotli compression.";
        let compressed = generator.compress_brotli(input, 6).unwrap();

        assert!(compressed.len() < input.len() * 2);

        use std::io::Read;
        let mut decompressed = Vec::new();
        {
            let mut decoder = brotli::Decompressor::new(compressed.as_slice(), 4096);
            decoder.read_to_end(&mut decompressed).unwrap();
        }
        assert_eq!(decompressed.as_slice(), input);
    }

    #[test]
    fn test_minifier_generator_css_minification() {
        let generator = MinifierGenerator::new();

        let css = r#"
            body {
                color: red;
                background-color: blue;
            }
            .container {
                margin: 10px;
                padding: 5px;
            }
        "#;

        let result = generator.minify_css(css);
        assert!(result.is_ok());

        let minified = result.unwrap();
        assert!(!minified.contains("\n"));
        assert!(!minified.contains("  "));
        assert!(minified.contains("color:red"));
    }

    #[test]
    fn test_minifier_generator_html_minification() {
        let generator = MinifierGenerator::new();

        let html = r#"
            <!DOCTYPE html>
            <html>
                <head>
                    <title>Test</title>
                </head>
                <body>
                    <p>Hello World</p>
                </body>
            </html>
        "#;

        let result = generator.minify_html(html);
        assert!(result.is_ok());

        let minified = result.unwrap();
        assert!(!minified.contains("\n"));
        assert!(!minified.contains("  "));
    }

    #[test]
    fn test_minifier_generator_js_minification() {
        let generator = MinifierGenerator::new();

        let js = r#"
            function hello(name) {
                console.log("Hello, " + name + "!");
                return true;
            }
            hello("World");
        "#;

        let result = generator.minify_js(js);
        assert!(result.is_ok());

        let minified = result.unwrap();
        assert!(minified.contains("hello"));
        assert!(!minified.contains("\n"));
    }

    #[test]
    fn test_content_type_from_path() {
        assert_eq!(content_type_from_path("/index.html"), "text/html");
        assert_eq!(content_type_from_path("/style.css"), "text/css");
        assert_eq!(
            content_type_from_path("/script.js"),
            "application/javascript"
        );
        assert_eq!(content_type_from_path("/image.svg"), "image/svg+xml");
        assert_eq!(
            content_type_from_path("/unknown.xyz"),
            "application/octet-stream"
        );
    }

    #[test]
    fn test_content_type_from_mime() {
        assert_eq!(
            ContentType::from_mime("text/html; charset=utf-8"),
            ContentType::Html
        );
        assert_eq!(ContentType::from_mime("text/css"), ContentType::Css);
        assert_eq!(
            ContentType::from_mime("application/javascript"),
            ContentType::Js
        );
        assert_eq!(ContentType::from_mime("image/svg+xml"), ContentType::Svg);
        assert_eq!(
            ContentType::from_mime("application/octet-stream"),
            ContentType::Other
        );
    }
}
