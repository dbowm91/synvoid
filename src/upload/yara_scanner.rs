use parking_lot::RwLock;
use std::path::Path;
use std::sync::Arc;
use thiserror::Error;
use yara_x::Rules;
use yara_x::Scanner;

/// Empty slice of category names to exclude from YARA scan results.
/// Pass this to scan functions when you want to include all rule matches
/// (i.e., no categories should be filtered out).
pub const NO_EXCLUDED_CATEGORIES: &[&str] = &[];

static DEFAULT_MALWARE_RULES: &str = r#"
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
}

#[derive(Clone)]
pub struct YaraScanner {
    rules: Arc<RwLock<Rules>>,
    rules_source: YaraRulesSource,
    current_version: Arc<RwLock<Option<String>>>,
}

impl YaraScanner {
    pub fn new(rules_source: YaraRulesSource) -> Result<Self, YaraError> {
        let rules_content = Self::compile_rules(&rules_source)?;

        let rules = yara_x::compile(rules_content.as_str())
            .map_err(|e| YaraError::CompilationError(e.to_string()))?;

        Ok(Self {
            rules: Arc::new(RwLock::new(rules)),
            rules_source,
            current_version: Arc::new(RwLock::new(None)),
        })
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

    pub fn reload(&self) -> Result<(), YaraError> {
        let rules_content = Self::compile_rules(&self.rules_source)?;

        let new_rules = yara_x::compile(rules_content.as_str())
            .map_err(|e| YaraError::CompilationError(e.to_string()))?;

        let mut rules = self.rules.write();
        *rules = new_rules;
        *self.current_version.write() = Some(format!("reload-{}", chrono::Utc::now().timestamp()));

        tracing::info!("YARA-X rules reloaded successfully");
        Ok(())
    }

    pub fn reload_with_rules(
        &self,
        rules_content: &str,
        version: Option<String>,
    ) -> Result<(), YaraError> {
        let new_rules = yara_x::compile(rules_content)
            .map_err(|e| YaraError::CompilationError(e.to_string()))?;

        let mut rules = self.rules.write();
        *rules = new_rules;
        *self.current_version.write() = version;

        tracing::info!("YARA-X rules reloaded from external source");
        Ok(())
    }

    pub fn get_version(&self) -> Option<String> {
        self.current_version.read().clone()
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

    pub fn scan_bytes(
        &self,
        data: &[u8],
        excluded_categories: &[&str],
    ) -> Result<Vec<YaraMatch>, YaraError> {
        let rules = self.rules.read();
        let mut scanner = Scanner::new(&rules);

        let results = scanner
            .scan(data)
            .map_err(|e| YaraError::ScanError(e.to_string()))?;

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

                if excluded_categories.contains(&category.as_str()) {
                    None
                } else {
                    // Tags extraction requires resolving yara-x Tag API - leave empty for now
                    // Tags aren't currently used in the malware scanning flow
                    let tags = vec![];
                    Some(YaraMatch {
                        rule_name: rule.identifier().to_string(),
                        namespace: rule.namespace().to_string(),
                        tags,
                        category,
                        severity,
                        description,
                    })
                }
            })
            .collect();

        Ok(matches)
    }

    pub fn scan_file_with_exclusions(
        &self,
        path: &Path,
        excluded_categories: &[&str],
    ) -> Result<Vec<YaraMatch>, YaraError> {
        let data = std::fs::read(path)?;
        self.scan_bytes(&data, excluded_categories)
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

impl YaraMatch {
    pub fn to_malware_match(&self) -> crate::upload::MalwareMatch {
        let mut meta = std::collections::HashMap::new();
        meta.insert("severity".to_string(), self.severity.clone());
        meta.insert("category".to_string(), self.category.clone());
        meta.insert("description".to_string(), self.description.clone());
        meta.insert("yara_rule".to_string(), self.rule_name.clone());

        crate::upload::MalwareMatch {
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
) -> Result<Option<YaraScanner>, YaraError> {
    let source = YaraRulesSource::from_config(yara_rules_dir, scan_with_yara);

    match source {
        Some(source) => {
            let scanner = YaraScanner::new(source)?;
            tracing::info!("YARA-X malware scanner initialized");
            Ok(Some(scanner))
        }
        None => {
            tracing::debug!("YARA-X malware scanning disabled");
            Ok(None)
        }
    }
}
