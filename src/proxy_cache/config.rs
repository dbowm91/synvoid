use std::path::PathBuf;
use std::time::Duration;

#[derive(Clone, Debug)]
pub struct ProxyCacheSettings {
    pub enabled: bool,
    pub path: PathBuf,
    pub max_memory_size: usize,
    pub max_disk_size: usize,
    pub inactive: Duration,
    pub use_temp_file: bool,
    pub valid_status: Vec<u16>,
    pub methods: Vec<String>,
    pub use_stale: Vec<String>,
    pub min_uses: u32,
    pub key_pattern: String,
    pub vary_by: Vec<String>,
}

impl Default for ProxyCacheSettings {
    fn default() -> Self {
        Self {
            enabled: false,
            path: PathBuf::from("/var/cache/rustwaf/proxy"),
            max_memory_size: 100 * 1024 * 1024, // 100MB
            max_disk_size: 1024 * 1024 * 1024,  // 1GB
            inactive: Duration::from_secs(3600),
            use_temp_file: true,
            valid_status: vec![200, 301, 302, 304],
            methods: vec!["GET".to_string(), "HEAD".to_string()],
            use_stale: vec![
                "error".to_string(),
                "timeout".to_string(),
                "invalid_header".to_string(),
                "http_500".to_string(),
                "http_502".to_string(),
                "http_503".to_string(),
                "http_504".to_string(),
            ],
            min_uses: 1,
            key_pattern: "$scheme$request_method$host$request_uri".to_string(),
            vary_by: vec!["Accept-Encoding".to_string()],
        }
    }
}

impl ProxyCacheSettings {
    pub fn from_config(
        enable: Option<bool>,
        path: Option<String>,
        max_size: Option<String>,
        inactive: u64,
        use_temp_file: Option<bool>,
        valid_status: Vec<u16>,
        methods: Vec<String>,
        use_stale: Vec<String>,
        min_uses: u32,
        key: Option<String>,
        vary_by: Vec<String>,
        memory_max: Option<String>,
        disk_max: Option<String>,
    ) -> Self {
        let enabled = enable.unwrap_or(false);

        let cache_path = path
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/var/cache/rustwaf/proxy"));

        let max_disk_size = max_size
            .as_ref()
            .and_then(|s| Self::parse_size(s))
            .unwrap_or(1024 * 1024 * 1024);

        let max_memory_size = memory_max
            .as_ref()
            .and_then(|s| Self::parse_size(s))
            .unwrap_or(100 * 1024 * 1024);

        Self {
            enabled,
            path: cache_path,
            max_memory_size,
            max_disk_size,
            inactive: Duration::from_secs(inactive),
            use_temp_file: use_temp_file.unwrap_or(true),
            valid_status,
            methods,
            use_stale,
            min_uses,
            key_pattern: key
                .unwrap_or_else(|| "$scheme$request_method$host$request_uri".to_string()),
            vary_by,
        }
    }

    fn parse_size(s: &str) -> Option<usize> {
        let s = s.trim().to_lowercase();
        let (num, unit) = s.split_at(s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len()));
        let num: usize = num.parse().ok()?;

        match unit.trim() {
            "k" | "kb" => Some(num * 1024),
            "m" | "mb" => Some(num * 1024 * 1024),
            "g" | "gb" => Some(num * 1024 * 1024 * 1024),
            "t" | "tb" => Some(num * 1024 * 1024 * 1024 * 1024),
            "" => Some(num),
            _ => None,
        }
    }
}
