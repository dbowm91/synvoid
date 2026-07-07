use arc_swap::ArcSwap;
use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use yara_x::Rules;
use yara_x::Scanner;

const DEFAULT_ARCHIVE_MAX_DEPTH: u32 = 3;
const DEFAULT_ARCHIVE_MAX_SIZE: u64 = 100 * 1024 * 1024; // 100MB

/// Empty slice of category names to exclude from YARA scan results.
/// Pass this to scan functions when you want to include all rule matches
/// (i.e., no categories should be filtered out).
pub const NO_EXCLUDED_CATEGORIES: &[&str] = &[];

pub static DEFAULT_MALWARE_RULES: &str = r#"
rule executable_pe {
    meta:
        description = "PE executable header detected"
        severity = "high"
        category = "executable"
    strings:
        $mz = { 4D 5A }
    condition:
        @mz[0] == 0
}

rule executable_elf {
    meta:
        description = "ELF executable header detected"
        severity = "high"
        category = "executable"
    strings:
        $elf = { 7F 45 4C 46 }
    condition:
        @elf[0] == 0
}

rule executable_macho {
    meta:
        description = "Mach-O executable header detected"
        severity = "high"
        category = "executable"
    strings:
        $macho = { FE ED FA CE }
        $macho64 = { FE ED FA CF }
        $macho_fat = { BE BA FE CA }
    condition:
        any of them
}

rule suspicious_polyglot_pe_zip {
    meta:
        description = "PE/zip polyglot detected"
        severity = "high"
        category = "evasion"
    strings:
        $mz = { 4D 5A }
        $zip = { 50 4B 03 04 }
    condition:
        $mz at 0 and $zip in (0..filesize)
}

rule office_macro_autoopen {
    meta:
        description = "Office document with auto-trigger macro"
        severity = "medium"
        category = "macro"
    strings:
        $autoopen = /autoopen/i
        $autoexec = /autoexec/i
        $autoclose = /autoclose/i
        $shell = /wscript\.shell|shell|wscript|powershell|cmd\.exe/i
    condition:
        any of ($auto*) and $shell
}

rule script_obfuscation {
    meta:
        description = "Obfuscated script detected"
        severity = "medium"
        category = "script"
    strings:
        $eval = /eval\s*\(/i
        $fromcharcode = /fromcharcode/i
        $unescape = /unescape/i
        $atob = /atob/i
        $btoa = /btoa/i
        $exec = /exec\s*\(/i
        $spawn = /spawn/i
    condition:
        3 of them
}

rule php_webshell {
    meta:
        description = "PHP webshell detected"
        severity = "critical"
        category = "webshell"
    strings:
        $exec_func = /base64_decode|eval\s*\(|system\s*\(|passthru|shell_exec|exec\s*\(|popen|proc_open/i
        $input = /\$_GET|\$_POST|\$_REQUEST/i
    condition:
        $exec_func and $input
}

rule jsp_webshell {
    meta:
        description = "JSP webshell detected"
        severity = "critical"
        category = "webshell"
    strings:
        $runtime = /Runtime\.getRuntime\(\)|ProcessBuilder|ScriptEngine/i
        $exec = /\.exec\s*\(/i
        $param = /getParameter/i
    condition:
        ($runtime and $exec) or ($runtime and $param)
}

rule asp_webshell {
    meta:
        description = "ASP webshell detected"
        severity = "critical"
        category = "webshell"
    strings:
        $trigger = /wscript\.shell|shellexecute|execute\s*\(|eval\s*\(/i
        $request = /request\.form|request\.querystring/i
    condition:
        $trigger and $request
}

rule archive_bomb {
    meta:
        description = "Archive bomb detected (many files)"
        severity = "medium"
        category = "archive"
    strings:
        $zip = { 50 4B 03 04 }
        $rar = { 52 61 72 21 }
    condition:
        for any i in (0..#zip) : (@zip[i] < 1000) or
        for any i in (0..#rar) : (@rar[i] < 1000)
}

rule embedded_exe {
    meta:
        description = "Embedded executable detected"
        severity = "high"
        category = "embedded"
    strings:
        $mz = "MZ"
        $pe = "PE\0\0"
    condition:
        $mz in (0..filesize) and $pe in (0..filesize)
}

rule hta_script {
    meta:
        description = "HTA script detected"
        severity = "high"
        category = "script"
    strings:
        $hta = /<hta:application/i
        $suspicious = /wscript\.shell|powershell|cmd\.exe|shellexecute/i
    condition:
        $hta and $suspicious
}

rule lnk_exploit {
    meta:
        description = "LNK exploit detected"
        severity = "high"
        category = "exploit"
    strings:
        $lnk = { 4C 00 00 00 }
        $powershell = /powershell/i
        $cmd = /cmd\.exe/i
        $wscript = /wscript|cscript|mshta/i
    condition:
        @lnk[0] == 0 and any of ($powershell, $cmd, $wscript)
}

rule double_extension {
    meta:
        description = "Suspicious double extension detected"
        severity = "medium"
        category = "social_engineering"
    strings:
        $double_ext = /\.pdf\.exe|\.doc\.exe|\.docx\.exe|\.xls\.exe|\.xlsx\.exe|\.jpg\.exe|\.png\.exe|\.txt\.exe|\.zip\.exe|\.rar\.exe|\.7z\.exe/i
    condition:
        $double_ext
}
"#;

#[derive(Error, Debug)]
pub enum YaraError {
    #[error("YARA compilation error: {0}")]
    CompilationError(String),
    #[error("YARA scan error: {0}")]
    ScanError(String),
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("YARA scan timeout")]
    Timeout,
    #[error("No rules available")]
    NoRules,
    #[error("Scan queue full: {0} active, {1} queued")]
    QueueFull(u32, u32),
    #[error("Scan queue timeout: waited {0}ms for admission")]
    QueueTimeout(u64),
    #[error("Scan executor closed")]
    ExecutorClosed,
}

/// An immutable generation of compiled YARA rules.
///
/// Scans clone the `Arc` to the current generation and hold it for the duration
/// of the scan. Reloads atomically swap the pointer, leaving in-flight scans
/// on the previous generation until they complete.
pub struct YaraRuleGeneration {
    pub rules: Rules,
    pub version: Option<String>,
    pub hash: String,
    pub loaded_at: DateTime<Utc>,
}

pub struct YaraScanner {
    generation: ArcSwap<YaraRuleGeneration>,
    rules_source: YaraRulesSource,
    scan_semaphore: Arc<tokio::sync::Semaphore>,
    max_concurrent_scans: usize,
    queue_timeout: Duration,
    timeout_ms: u64,
    archive_max_depth: u32,
    archive_max_size: u64,
}

impl Clone for YaraScanner {
    fn clone(&self) -> Self {
        Self {
            generation: ArcSwap::from(self.generation.load_full()),
            rules_source: self.rules_source.clone(),
            scan_semaphore: Arc::clone(&self.scan_semaphore),
            max_concurrent_scans: self.max_concurrent_scans,
            queue_timeout: self.queue_timeout,
            timeout_ms: self.timeout_ms,
            archive_max_depth: self.archive_max_depth,
            archive_max_size: self.archive_max_size,
        }
    }
}

impl YaraScanner {
    pub fn new(rules_source: YaraRulesSource) -> Result<Self, YaraError> {
        Self::with_timeout(
            rules_source,
            30000,
            DEFAULT_ARCHIVE_MAX_DEPTH,
            DEFAULT_ARCHIVE_MAX_SIZE,
            4,
            1000,
        )
    }

    /// Create a new scanner with configurable timeout and executor parameters.
    ///
    /// * `timeout_ms` — per-scan timeout in milliseconds.
    /// * `max_concurrent_scans` — maximum simultaneously executing scans.
    /// * `queue_timeout_ms` — how long to wait for a scan slot before rejecting.
    pub fn with_timeout(
        rules_source: YaraRulesSource,
        timeout_ms: u64,
        archive_max_depth: u32,
        archive_max_size: u64,
        max_concurrent_scans: u32,
        queue_timeout_ms: u64,
    ) -> Result<Self, YaraError> {
        let rules_content = Self::compile_rules(&rules_source)?;

        let rules = yara_x::compile(rules_content.as_str())
            .map_err(|e| YaraError::CompilationError(e.to_string()))?;

        let mut hasher = Sha256::new();
        hasher.update(rules_content.as_bytes());
        let hash = format!("{:x}", hasher.finalize());
        let version = Some(format!("init-{}", &hash[..16]));

        let generation = Arc::new(YaraRuleGeneration {
            rules,
            version,
            hash,
            loaded_at: Utc::now(),
        });

        let scan_semaphore = Arc::new(tokio::sync::Semaphore::new(
            max_concurrent_scans as usize,
        ));

        Ok(Self {
            generation: ArcSwap::from(generation),
            rules_source,
            scan_semaphore,
            max_concurrent_scans: max_concurrent_scans as usize,
            queue_timeout: Duration::from_millis(queue_timeout_ms),
            timeout_ms,
            archive_max_depth,
            archive_max_size,
        })
    }

    /// Maximum number of concurrent scans this executor permits.
    pub fn max_concurrent_scans(&self) -> usize {
        self.max_concurrent_scans
    }

    /// Queue timeout duration.
    pub fn queue_timeout(&self) -> Duration {
        self.queue_timeout
    }

    pub fn archive_max_depth(&self) -> u32 {
        self.archive_max_depth
    }

    pub fn archive_max_size(&self) -> u64 {
        self.archive_max_size
    }

    pub fn check_depth_limit(&self, current_depth: u32) -> bool {
        current_depth >= self.archive_max_depth
    }

    pub fn check_size_limit(&self, current_size: u64, additional_size: u64) -> bool {
        current_size.saturating_add(additional_size) > self.archive_max_size
    }

    pub fn would_exceed_depth_limit(&self, depth: u32) -> bool {
        depth > self.archive_max_depth
    }

    pub fn would_exceed_size_limit(&self, current_extracted: u64, new_size: u64) -> bool {
        current_extracted
            .checked_add(new_size)
            .map(|total| total > self.archive_max_size)
            .unwrap_or(true)
    }

    fn compile_rules(source: &YaraRulesSource) -> Result<String, YaraError> {
        match source {
            YaraRulesSource::Directory(path) => Self::load_rules_from_directory(path),
            YaraRulesSource::Bundled => Ok(DEFAULT_MALWARE_RULES.to_string()),
            YaraRulesSource::DirectoryWithFallback(path) => {
                match Self::load_rules_from_directory(path) {
                    Ok(rules) => Ok(rules),
                    Err(e) => {
                        tracing::warn!(
                            "Failed to load YARA rules from {}: {}, using bundled defaults",
                            path.display(),
                            e
                        );
                        Ok(DEFAULT_MALWARE_RULES.to_string())
                    }
                }
            }
            YaraRulesSource::Inline(rules) => Ok(rules.clone()),
        }
    }

    /// Reload rules from the configured source (file/directory/inline).
    ///
    /// Compiles new rules off-path, then atomically swaps the active generation.
    /// On failure, the previous generation is retained (last-known-good).
    pub fn reload(&self) -> Result<(), YaraError> {
        let rules_content = Self::compile_rules(&self.rules_source)?;
        self.reload_from_source(&rules_content, None)
    }

    /// Reload with externally-provided source rules.
    ///
    /// Compiles new rules, then atomically swaps the active generation.
    /// On failure, the previous generation is retained.
    pub fn reload_with_rules(
        &self,
        rules_content: &str,
        version: Option<String>,
    ) -> Result<(), YaraError> {
        self.reload_from_source(rules_content, version)
    }

    /// Reload with pre-compiled binary rules.
    ///
    /// Deserializes the compiled rules, then atomically swaps the active generation.
    /// On failure, the previous generation is retained.
    pub fn reload_with_compiled_rules(
        &self,
        compiled_rules: &[u8],
        version: Option<String>,
    ) -> Result<(), YaraError> {
        let new_rules = yara_x::Rules::deserialize(compiled_rules)
            .map_err(|e| YaraError::CompilationError(format!("Failed to deserialize: {}", e)))?;

        let mut hasher = Sha256::new();
        hasher.update(compiled_rules);
        let hash = format!("{:x}", hasher.finalize());

        let generation = Arc::new(YaraRuleGeneration {
            rules: new_rules,
            version,
            hash,
            loaded_at: Utc::now(),
        });

        self.generation.store(generation);
        crate::metrics::increment_yara_reload_success();
        tracing::info!("YARA-X rules reloaded from compiled binary source");
        Ok(())
    }

    fn reload_from_source(
        &self,
        rules_content: &str,
        version: Option<String>,
    ) -> Result<(), YaraError> {
        let new_rules = yara_x::compile(rules_content)
            .map_err(|e| YaraError::CompilationError(e.to_string()))?;

        let mut hasher = Sha256::new();
        hasher.update(rules_content.as_bytes());
        let hash = format!("{:x}", hasher.finalize());

        let generation = Arc::new(YaraRuleGeneration {
            rules: new_rules,
            version,
            hash,
            loaded_at: Utc::now(),
        });

        self.generation.store(generation);
        crate::metrics::increment_yara_reload_success();
        tracing::info!("YARA-X rules reloaded successfully");
        Ok(())
    }

    pub fn get_version(&self) -> Option<String> {
        self.generation.load().version.clone()
    }

    /// Get the hash of the currently active rule generation.
    pub fn get_generation_hash(&self) -> String {
        self.generation.load().hash.clone()
    }

    fn load_rules_from_directory(dir_path: &Path) -> Result<String, YaraError> {
        let mut combined_rules = String::new();
        let mut has_rules = false;

        for entry in walkdir::WalkDir::new(dir_path)
            .max_depth(1)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            let entry_path = entry.path();
            if entry_path.is_file() {
                if let Some(ext) = entry_path.extension() {
                    if ext == "yar" || ext == "yara" {
                        let content = std::fs::read_to_string(entry_path)?;
                        combined_rules.push_str(&content);
                        combined_rules.push('\n');
                        has_rules = true;
                    }
                }
            }
        }

        if !has_rules {
            return Err(YaraError::NoRules);
        }

        Ok(combined_rules)
    }

    /// Acquire a scan permit with timeout. Returns the guard, or an error if
    /// the queue is full or the timeout expires.
    async fn acquire_scan_permit(
        &self,
    ) -> Result<tokio::sync::OwnedSemaphorePermit, YaraError> {
        let start = std::time::Instant::now();
        match tokio::time::timeout(self.queue_timeout, Arc::clone(&self.scan_semaphore).acquire_owned()).await {
            Ok(Ok(permit)) => {
                let wait_ms = start.elapsed().as_millis() as u64;
                if wait_ms > 100 {
                    tracing::debug!(wait_ms, "YARA scan queue wait");
                }
                Ok(permit)
            }
            Ok(Err(_)) => {
                crate::metrics::increment_scan_queue_full();
                let active = self.max_concurrent_scans as u32
                    - self.scan_semaphore.available_permits() as u32;
                Err(YaraError::QueueFull(
                    active,
                    self.max_concurrent_scans as u32,
                ))
            }
            Err(_) => {
                crate::metrics::increment_scan_queue_timeout();
                Err(YaraError::QueueTimeout(self.queue_timeout.as_millis() as u64))
            }
        }
    }

    pub async fn scan_bytes(
        &self,
        data: &[u8],
        excluded_categories: &[&str],
    ) -> Result<Vec<YaraMatch>, YaraError> {
        let _permit = self.acquire_scan_permit().await?;

        let timeout_ms = self.timeout_ms;
        let generation = self.generation.load_full();
        let data = data.to_vec();
        let excluded: Vec<String> = excluded_categories
            .iter()
            .map(|s| (*s).to_string())
            .collect();

        let runtime = tokio::runtime::Handle::current();
        let (tx, rx) = tokio::sync::oneshot::channel();

        runtime.spawn_blocking(move || {
            let mut scanner = Scanner::new(&generation.rules);

            let result = match scanner.scan(&data) {
                Ok(results) => {
                    let matches: Vec<YaraMatch> = results
                        .matching_rules()
                        .filter_map(|rule| {
                            let mut category = "unknown".to_string();
                            let mut severity = "medium".to_string();
                            let mut description = String::new();

                            for (key, value) in rule.metadata() {
                                match key {
                                    "category" => {
                                        if let yara_x::MetaValue::String(s) = value {
                                            category = s.to_string();
                                        }
                                    }
                                    "severity" => {
                                        if let yara_x::MetaValue::String(s) = value {
                                            severity = s.to_string();
                                        }
                                    }
                                    "description" => {
                                        if let yara_x::MetaValue::String(s) = value {
                                            description = s.to_string();
                                        }
                                    }
                                    _ => {}
                                }
                            }

                            if excluded.contains(&category) {
                                None
                            } else {
                                Some(YaraMatch {
                                    rule_name: rule.identifier().to_string(),
                                    namespace: rule.namespace().to_string(),
                                    tags: vec![],
                                    category,
                                    severity,
                                    description,
                                })
                            }
                        })
                        .collect();
                    Ok(matches)
                }
                Err(e) => Err(YaraError::ScanError(e.to_string())),
            };

            let _ = tx.send(result);
        });

        match tokio::time::timeout(Duration::from_millis(timeout_ms), rx).await {
            Ok(Ok(result)) => result,
            Ok(Err(_)) => Err(YaraError::ScanError("scan task panicked".into())),
            Err(_) => {
                crate::metrics::increment_scan_timeout();
                tracing::warn!(
                    timeout_ms,
                    "YARA scan timed out; scan task continues in background"
                );
                Err(YaraError::Timeout)
            }
        }
    }

    pub async fn scan_file_with_exclusions(
        &self,
        path: &Path,
        excluded_categories: &[&str],
    ) -> Result<Vec<YaraMatch>, YaraError> {
        let data = std::fs::read(path)?;
        self.scan_bytes(&data, excluded_categories).await
    }

    /// Scan a file in multiple windows (header, footer, middle chunks).
    ///
    /// `windows` is a list of `(offset, length)` byte ranges to scan.
    /// Each window is read and scanned independently. Matches are deduplicated
    /// by rule_name (first match wins).
    pub async fn scan_file_windows(
        &self,
        path: &Path,
        windows: &[(u64, u32)],
        excluded_categories: &[&str],
    ) -> Result<WindowedScanResult, YaraError> {
        use std::io::{Read, Seek, SeekFrom};

        let _permit = self.acquire_scan_permit().await?;

        let timeout_ms = self.timeout_ms;
        let generation = self.generation.load_full();
        let excluded: Vec<String> = excluded_categories
            .iter()
            .map(|s| (*s).to_string())
            .collect();
        let windows = windows.to_vec();
        let path = path.to_path_buf();

        let runtime = tokio::runtime::Handle::current();
        let (tx, rx) = tokio::sync::oneshot::channel();

        runtime.spawn_blocking(move || {
            let mut all_matches: Vec<YaraMatch> = Vec::new();
            let mut seen_rules: std::collections::HashSet<String> =
                std::collections::HashSet::new();
            let mut total_scanned: u64 = 0;

            for (offset, length) in &windows {
                let mut file = match std::fs::File::open(&path) {
                    Ok(f) => f,
                    Err(e) => {
                        let _ = tx.send(Err(YaraError::IoError(e)));
                        return;
                    }
                };

                if file.seek(SeekFrom::Start(*offset)).is_err() {
                    continue;
                }

                let mut buf = vec![0u8; *length as usize];
                let bytes_read = match file.read(&mut buf) {
                    Ok(n) => n,
                    Err(e) => {
                        let _ = tx.send(Err(YaraError::IoError(e)));
                        return;
                    }
                };
                buf.truncate(bytes_read);
                total_scanned += bytes_read as u64;

                let mut scanner = Scanner::new(&generation.rules);
                if let Ok(results) = scanner.scan(&buf) {
                    for rule in results.matching_rules() {
                        let mut category = "unknown".to_string();
                        let mut severity = "medium".to_string();
                        let mut description = String::new();

                        for (key, value) in rule.metadata() {
                            match key {
                                "category" => {
                                    if let yara_x::MetaValue::String(s) = value {
                                        category = s.to_string();
                                    }
                                }
                                "severity" => {
                                    if let yara_x::MetaValue::String(s) = value {
                                        severity = s.to_string();
                                    }
                                }
                                "description" => {
                                    if let yara_x::MetaValue::String(s) = value {
                                        description = s.to_string();
                                    }
                                }
                                _ => {}
                            }
                        }

                        if excluded.contains(&category) {
                            continue;
                        }

                        let rule_id = rule.identifier().to_string();
                        if seen_rules.insert(rule_id.clone()) {
                            all_matches.push(YaraMatch {
                                rule_name: rule_id,
                                namespace: rule.namespace().to_string(),
                                tags: vec![],
                                category,
                                severity,
                                description,
                            });
                        }
                    }
                }
            }

            let _ = tx.send(Ok(WindowedScanResult {
                matches: all_matches,
                scanned_bytes: total_scanned,
                window_count: windows.len() as u32,
            }));
        });

        match tokio::time::timeout(Duration::from_millis(timeout_ms), rx).await {
            Ok(Ok(result)) => result,
            Ok(Err(_)) => Err(YaraError::ScanError("scan task panicked".into())),
            Err(_) => {
                crate::metrics::increment_scan_timeout();
                tracing::warn!(
                    timeout_ms,
                    "YARA windowed scan timed out; scan task continues in background"
                );
                Err(YaraError::Timeout)
            }
        }
    }
}

#[derive(Clone, Debug)]
pub struct YaraMatch {
    pub rule_name: String,
    pub namespace: String,
    pub tags: Vec<String>,
    pub category: String,
    pub severity: String,
    pub description: String,
}

/// Result of a windowed scan across multiple file regions.
#[derive(Debug)]
pub struct WindowedScanResult {
    /// All YARA matches found across all windows.
    pub matches: Vec<YaraMatch>,
    /// Total number of bytes scanned across all windows.
    pub scanned_bytes: u64,
    /// Number of windows scanned.
    pub window_count: u32,
}

impl YaraMatch {
    pub fn to_malware_match(&self) -> crate::MalwareMatch {
        let mut meta = std::collections::HashMap::new();
        meta.insert("severity".to_string(), self.severity.clone());
        meta.insert("category".to_string(), self.category.clone());
        meta.insert("description".to_string(), self.description.clone());
        meta.insert("yara_rule".to_string(), self.rule_name.clone());

        crate::MalwareMatch {
            rule_name: self.rule_name.clone(),
            namespace: self.namespace.clone(),
            tags: self.tags.clone(),
            meta,
        }
    }
}

pub enum YaraRulesSource {
    Directory(std::path::PathBuf),
    Bundled,
    DirectoryWithFallback(std::path::PathBuf),
    Inline(String),
}

impl Clone for YaraRulesSource {
    fn clone(&self) -> Self {
        match self {
            Self::Directory(path) => Self::Directory(path.clone()),
            Self::Bundled => Self::Bundled,
            Self::DirectoryWithFallback(path) => Self::DirectoryWithFallback(path.clone()),
            Self::Inline(rules) => Self::Inline(rules.clone()),
        }
    }
}

impl YaraRulesSource {
    pub fn from_config(
        yara_rules_dir: Option<std::path::PathBuf>,
        scan_with_yara: bool,
    ) -> Option<Self> {
        if !scan_with_yara {
            return None;
        }

        match yara_rules_dir {
            Some(path) => Some(Self::DirectoryWithFallback(path)),
            None => Some(Self::Bundled),
        }
    }

    pub fn from_inline(rules: String) -> Self {
        Self::Inline(rules)
    }
}

pub fn create_yara_scanner(
    yara_rules_dir: Option<std::path::PathBuf>,
    scan_with_yara: bool,
    archive_max_depth: u32,
    archive_max_size: u64,
) -> Result<Option<YaraScanner>, YaraError> {
    YaraScanner::with_scan_executor(yara_rules_dir, scan_with_yara, archive_max_depth, archive_max_size, 4, 1000)
}

impl YaraScanner {
    /// Factory that accepts scan executor parameters.
    pub fn with_scan_executor(
        yara_rules_dir: Option<std::path::PathBuf>,
        scan_with_yara: bool,
        archive_max_depth: u32,
        archive_max_size: u64,
        max_concurrent_scans: u32,
        queue_timeout_ms: u64,
    ) -> Result<Option<YaraScanner>, YaraError> {
        let source = YaraRulesSource::from_config(yara_rules_dir, scan_with_yara);

        match source {
            Some(source) => {
                let scanner = YaraScanner::with_timeout(
                    source,
                    30000,
                    archive_max_depth,
                    archive_max_size,
                    max_concurrent_scans,
                    queue_timeout_ms,
                )?;
                tracing::info!(
                    max_concurrent = max_concurrent_scans,
                    queue_timeout_ms,
                    "YARA-X malware scanner initialized"
                );
                Ok(Some(scanner))
            }
            None => {
                tracing::debug!("YARA-X malware scanning disabled");
                Ok(None)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[tokio::test]
    async fn test_scan_file_windows_clean() {
        let scanner = YaraScanner::new(YaraRulesSource::Inline(
            "rule dummy { condition: false }".to_string(),
        ))
        .expect("inline rules should compile");
        let mut tmp = NamedTempFile::new().unwrap();
        tmp.write_all(b"Hello, World! This is a clean file.")
            .unwrap();
        let windows = vec![(0, 35)];
        let result = scanner
            .scan_file_windows(tmp.path(), &windows, &[])
            .await
            .unwrap();
        assert!(result.matches.is_empty());
        assert_eq!(result.window_count, 1);
        assert_eq!(result.scanned_bytes, 35);
    }

    #[tokio::test]
    async fn test_scan_file_windows_empty_file() {
        let scanner = YaraScanner::new(YaraRulesSource::Inline(
            "rule dummy { condition: false }".to_string(),
        ))
        .expect("inline rules should compile");
        let tmp = NamedTempFile::new().unwrap();
        let windows = vec![(0, 0)];
        let result = scanner
            .scan_file_windows(tmp.path(), &windows, &[])
            .await
            .unwrap();
        assert!(result.matches.is_empty());
        assert_eq!(result.window_count, 1);
    }

    #[tokio::test]
    async fn test_scan_file_windows_multiple_windows() {
        let scanner = YaraScanner::new(YaraRulesSource::Inline(
            "rule dummy { condition: false }".to_string(),
        ))
        .expect("inline rules should compile");
        let mut tmp = NamedTempFile::new().unwrap();
        let data = vec![0u8; 4096];
        tmp.write_all(&data).unwrap();
        let windows = vec![(0, 1024), (2048, 1024)];
        let result = scanner
            .scan_file_windows(tmp.path(), &windows, &[])
            .await
            .unwrap();
        assert_eq!(result.window_count, 2);
        assert_eq!(result.scanned_bytes, 2048);
    }

    #[tokio::test]
    async fn test_concurrency_limit() {
        let scanner = YaraScanner::with_timeout(
            YaraRulesSource::Inline("rule dummy { condition: false }".to_string()),
            30000,
            DEFAULT_ARCHIVE_MAX_DEPTH,
            DEFAULT_ARCHIVE_MAX_SIZE,
            2, // max 2 concurrent
            5000,
        )
        .expect("should compile");

        assert_eq!(scanner.max_concurrent_scans(), 2);

        // Fill both slots
        let p1 = scanner.acquire_scan_permit().await.unwrap();
        let p2 = scanner.acquire_scan_permit().await.unwrap();

        // Third acquisition should timeout (queue timeout is 5s, but we use a short timeout)
        let scanner2 = YaraScanner::with_timeout(
            YaraRulesSource::Inline("rule dummy { condition: false }".to_string()),
            30000,
            DEFAULT_ARCHIVE_MAX_DEPTH,
            DEFAULT_ARCHIVE_MAX_SIZE,
            1, // max 1 concurrent
            100, // 100ms queue timeout
        )
        .expect("should compile");

        let _p = scanner2.acquire_scan_permit().await.unwrap();
        let result = tokio::time::timeout(
            Duration::from_millis(200),
            scanner2.acquire_scan_permit(),
        )
        .await;

        assert!(result.is_ok());
        match result.unwrap() {
            Err(YaraError::QueueTimeout(_)) => {} // expected
            other => panic!("expected QueueTimeout, got {:?}", other),
        }

        drop(p1);
        drop(p2);
    }

    #[tokio::test]
    async fn test_reload_preserves_generation() {
        let scanner = YaraScanner::new(YaraRulesSource::Inline(
            "rule detect_pe { meta: description = \"test\" severity = \"high\" category = \"test\" strings: $mz = { 4D 5A } condition: $mz at 0 }".to_string(),
        ))
        .expect("should compile");

        let version_before = scanner.get_version();

        // Reload with invalid rules — should fail and preserve old generation
        let result = scanner.reload_with_rules("invalid rule syntax !!!!", Some("bad-version".into()));
        assert!(result.is_err());
        assert_eq!(scanner.get_version(), version_before);

        // Reload with valid rules — should succeed
        let result = scanner.reload_with_rules(
            "rule clean { condition: false }",
            Some("v2".into()),
        );
        assert!(result.is_ok());
        assert_eq!(scanner.get_version(), Some("v2".into()));
    }

    #[tokio::test]
    async fn test_compiled_rules_deserialization_failure_preserves_generation() {
        let scanner = YaraScanner::new(YaraRulesSource::Inline(
            "rule detect_pe { meta: description = \"test\" severity = \"high\" category = \"test\" strings: $mz = { 4D 5A } condition: $mz at 0 }".to_string(),
        ))
        .expect("should compile");

        let version_before = scanner.get_version();
        let hash_before = scanner.get_generation_hash();

        // Try to reload with garbage compiled rules
        let result = scanner.reload_with_compiled_rules(b"not-valid-compiled-rules", Some("bad".into()));
        assert!(result.is_err());
        assert_eq!(scanner.get_version(), version_before);
        assert_eq!(scanner.get_generation_hash(), hash_before);
    }

    #[tokio::test]
    async fn test_scan_uses_generation_after_reload() {
        let scanner = YaraScanner::new(YaraRulesSource::Inline(
            "rule detect_pe { meta: description = \"test\" severity = \"high\" category = \"test\" strings: $mz = { 4D 5A } condition: $mz at 0 }".to_string(),
        ))
        .expect("should compile");

        // Should detect PE header
        let pe_data = b"MZ\x90\x00\x03\x00";
        let matches = scanner.scan_bytes(pe_data, &[]).await.unwrap();
        assert!(!matches.is_empty());

        // Reload with non-matching rules
        scanner
            .reload_with_rules("rule clean { condition: false }", Some("v2".into()))
            .unwrap();

        // Should no longer detect
        let matches = scanner.scan_bytes(pe_data, &[]).await.unwrap();
        assert!(matches.is_empty());
    }

    #[tokio::test]
    async fn test_get_generation_hash() {
        let scanner = YaraScanner::new(YaraRulesSource::Inline(
            "rule dummy { condition: false }".to_string(),
        ))
        .expect("should compile");

        let hash1 = scanner.get_generation_hash();
        assert!(!hash1.is_empty());

        // Reload with different rules — hash should change
        scanner
            .reload_with_rules("rule dummy2 { condition: true }", None)
            .unwrap();
        let hash2 = scanner.get_generation_hash();
        assert!(!hash2.is_empty());
        assert_ne!(hash1, hash2);
    }
}
