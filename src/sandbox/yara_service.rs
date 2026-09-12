//! YARA jail execution service (child side).
//!
//! Implements [`synvoid_ipc::JailHandler`] for [`synvoid_ipc::JailKind::Yara`]
//! by compiling parent-approved rule text with the canonical
//! `synvoid-yara` engine and scanning bounded buffers.
//!
//! Phase 26: imports the generic engine directly (never
//! `synvoid-upload`). Trust model mirrors the WASM service: the parent
//! validated rule provenance before sending; the jail verifies the content
//! digest (constant-time) and enforces per-scan timeouts plus input/match
//! bounds. Compilation and scan errors are typed and never terminate the jail.

use std::collections::HashMap;

use synvoid_ipc::{
    JailError, JailHandler, JailOperation, JailOutput, JailResult, YaraMatchDto, JAIL_MAX_MATCHES,
    JAIL_MAX_RULESETS,
};
use synvoid_yara::{YaraRulesSource, YaraScanner};

/// Per-scan timeout inside the jail (parent call deadline is the outer bound;
/// quarantine+restart applies if this is ever exceeded pathologically).
const JAIL_YARA_SCAN_TIMEOUT_MS: u64 = 10_000;

/// Jail-side YARA rule registry plus scanning.
pub struct YaraJailService {
    rulesets: HashMap<String, YaraScanner>,
    runtime: tokio::runtime::Runtime,
}

impl YaraJailService {
    pub fn new() -> std::io::Result<Self> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        Ok(Self {
            rulesets: HashMap::new(),
            runtime,
        })
    }

    /// Number of loaded rule sets (for limit tests).
    pub fn loaded_count(&self) -> usize {
        self.rulesets.len()
    }

    fn load(&mut self, rules_id: &str, digest_sha256_hex: &str, rules_text: &str) -> JailResult {
        if self.rulesets.len() >= JAIL_MAX_RULESETS && !self.rulesets.contains_key(rules_id) {
            return JailResult::Err(
                JailError::ResourceExhausted("too many loaded rule sets".to_string()).to_dto(),
            );
        }
        if !synvoid_ipc::verify_sha256_hex(rules_text.as_bytes(), digest_sha256_hex) {
            return JailResult::Err(
                JailError::DigestMismatch("yara rules digest mismatch".to_string()).to_dto(),
            );
        }
        match YaraScanner::new(YaraRulesSource::Inline(rules_text.to_string())) {
            Ok(scanner) => {
                self.rulesets.insert(rules_id.to_string(), scanner);
                tracing::info!("jail loaded yara rule set");
                JailResult::Ok(JailOutput::YaraRulesLoaded)
            }
            Err(e) => JailResult::Err(
                JailError::ExecutionFailed(format!("yara compile failed: {e}")).to_dto(),
            ),
        }
    }

    fn scan(&self, rules_id: &str, data: &[u8]) -> JailResult {
        let scanner = match self.rulesets.get(rules_id) {
            Some(scanner) => scanner,
            None => {
                return JailResult::Err(
                    JailError::NotFound("yara rule set not loaded".to_string()).to_dto(),
                );
            }
        };
        // Bound the data actually handed to the scanner even though framing
        // already validated the length (defense in depth).
        if data.len() > synvoid_ipc::JAIL_MAX_SCAN_INPUT_BYTES {
            return JailResult::Err(
                JailError::Oversized("yara scan input too large".to_string()).to_dto(),
            );
        }
        let result = self.runtime.block_on(async {
            tokio::time::timeout(
                std::time::Duration::from_millis(JAIL_YARA_SCAN_TIMEOUT_MS),
                scanner.scan_bytes(data, &[]),
            )
            .await
        });
        match result {
            Ok(Ok(matches)) => {
                let mut dtos: Vec<YaraMatchDto> = matches
                    .into_iter()
                    .take(JAIL_MAX_MATCHES)
                    .map(|m| {
                        YaraMatchDto {
                            rule_name: m.rule_name,
                            namespace: m.namespace,
                            tags: m.tags,
                            category: m.category,
                            severity: m.severity,
                            description: m.description,
                        }
                        .truncated()
                    })
                    .collect();
                dtos.truncate(JAIL_MAX_MATCHES);
                JailResult::Ok(JailOutput::YaraScanResult { matches: dtos })
            }
            Ok(Err(e)) => JailResult::Err(
                JailError::ExecutionFailed(format!("yara scan failed: {e}")).to_dto(),
            ),
            Err(_) => JailResult::Err(
                JailError::Timeout("yara scan exceeded jail deadline".to_string()).to_dto(),
            ),
        }
    }
}

impl JailHandler for YaraJailService {
    fn handle(&mut self, op: &JailOperation) -> JailResult {
        match op {
            JailOperation::Ping => JailResult::Ok(JailOutput::Pong),
            JailOperation::Shutdown => JailResult::Ok(JailOutput::ShutdownAck),
            JailOperation::YaraLoadRules {
                rules_id,
                digest_sha256_hex,
                rules_text,
            } => self.load(rules_id, digest_sha256_hex, rules_text),
            JailOperation::YaraScan { rules_id, data } => self.scan(rules_id, data),
            JailOperation::YaraUnload { rules_id } => {
                if self.rulesets.remove(rules_id).is_some() {
                    JailResult::Ok(JailOutput::YaraUnloaded)
                } else {
                    JailResult::Err(
                        JailError::NotFound("yara rule set not loaded".to_string()).to_dto(),
                    )
                }
            }
            // Wrong-kind operations are rejected, never executed.
            JailOperation::WasmLoad { .. }
            | JailOperation::WasmInvoke { .. }
            | JailOperation::WasmUnload { .. } => JailResult::Err(
                JailError::PolicyDenied("wasm operation sent to yara jail".to_string()).to_dto(),
            ),
        }
    }
}
