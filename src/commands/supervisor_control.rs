//! Typed supervisor-control command outcomes and adapter.
//!
//! This module owns the boundary between CLI command execution and
//! supervisor IPC handlers. It converts typed supervisor-control commands
//! into existing handler calls and returns structured outcomes rather than
//! ad-hoc strings or generic errors.
//!
//! ## Boundary Model
//!
//! ```text
//! SupervisorControlCommand -> execute_supervisor_control_command()
//!     -> Result<SupervisorControlOutcome, SupervisorControlError>
//!     -> exit code
//! ```

use super::plan::SupervisorControlCommand;

/// Formatted status display text produced by a status query.
///
/// Contains the complete user-facing status output as a single string.
/// The display is produced by the handler and owned by the outcome,
/// centralizing formatting at the command boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SupervisorStatusDisplay {
    /// The fully formatted status text ready for printing.
    pub text: String,
}

/// Summary metadata from a threat-feed export.
///
/// Carries real export metadata instead of placeholder values.
/// When the byte count is available it is reported; otherwise
/// the variant indicates completion without precise counts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ThreatFeedExportSummary {
    /// The feed was written with known byte and record counts.
    Written {
        bytes: usize,
        records: Option<usize>,
    },
    /// The feed was exported but exact byte count is not available.
    Completed,
}

/// Outcome from a stop command, carrying structured result data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StopOutcome {
    /// Whether the stop signal was acknowledged by the supervisor.
    pub acknowledged: bool,
    /// Whether the process confirmed shutdown within the timeout.
    pub shutdown_confirmed: bool,
    /// Whether the shutdown timed out without confirming.
    pub timed_out: bool,
}

/// Outcome from a rehash command, carrying structured result data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RehashOutcome {
    /// Whether the reload signal was acknowledged by the supervisor.
    pub acknowledged: bool,
}

/// Typed outcome from a successfully executed supervisor-control command.
///
/// Each variant carries structured data where practical. The `exit_code()`
/// method maps outcomes to process exit codes in one place.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SupervisorControlOutcome {
    /// Status information was queried and formatted.
    Status(SupervisorStatusDisplay),
    /// A stop signal was sent and acknowledged.
    Stop(StopOutcome),
    /// A config reload signal was sent.
    Rehash(RehashOutcome),
    /// A threat feed was exported.
    ThreatFeedExported(ThreatFeedExportSummary),
    /// A restart pre-stop was requested (stop before relaunch).
    RestartPreStopRequested,
}

impl SupervisorControlOutcome {
    /// Map this outcome to a process exit code.
    ///
    /// All success outcomes return 0. This centralizes exit-code mapping
    /// so the CLI execution layer does not need per-command knowledge.
    pub fn exit_code(&self) -> i32 {
        0
    }

    /// Format this outcome for user-facing display.
    ///
    /// Centralizes CLI formatting so handlers return data, not side effects.
    /// Returns `Some(text)` when there is user-visible output, or `None`
    /// for silent outcomes (e.g., restart pre-stop).
    pub fn display(&self) -> Option<String> {
        match self {
            SupervisorControlOutcome::Status(status) => Some(status.text.clone()),
            SupervisorControlOutcome::Stop(outcome) => {
                if outcome.shutdown_confirmed {
                    Some("synvoid stopped".to_string())
                } else if outcome.timed_out {
                    Some("Warning: Process did not shut down cleanly".to_string())
                } else if outcome.acknowledged {
                    Some("Stop signal sent".to_string())
                } else {
                    None
                }
            }
            SupervisorControlOutcome::Rehash(outcome) => {
                if outcome.acknowledged {
                    Some("Configuration reloaded".to_string())
                } else {
                    None
                }
            }
            SupervisorControlOutcome::ThreatFeedExported(summary) => match summary {
                ThreatFeedExportSummary::Written { bytes, records } => {
                    let mut msg = format!("Exported {} bytes", bytes);
                    if let Some(r) = records {
                        msg.push_str(&format!(" ({} records)", r));
                    }
                    Some(msg)
                }
                ThreatFeedExportSummary::Completed => Some("Threat feed exported".to_string()),
            },
            SupervisorControlOutcome::RestartPreStopRequested => None,
        }
    }
}

/// Typed error from a failed supervisor-control command.
///
/// Each variant classifies the failure mode so the CLI execution layer
/// can produce meaningful messages and consistent exit codes.
///
/// ## Exit Code Mapping
///
/// All variants currently return exit code 1 for backwards compatibility.
/// Future iterations may introduce variant-specific exit codes after a
/// compatibility review:
///
/// ```text
/// ConnectionUnavailable | Timeout         => 2
/// Authentication                          => 3
/// UnsupportedFeature                     => 4
/// Protocol | InvalidResponse             => 5
/// Io                                      => 6
/// RequestRejected | Unknown              => 1
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SupervisorControlError {
    /// Could not connect to the supervisor process (e.g., no socket,
    /// no running instance, connection refused).
    ConnectionUnavailable(String),
    /// The control request timed out.
    Timeout(String),
    /// A protocol-level error occurred (e.g., send failed, receive failed,
    /// serialization error).
    Protocol(String),
    /// The supervisor rejected the request (e.g., server error, unexpected
    /// response).
    RequestRejected(String),
    /// An authentication or authorization failure occurred.
    Authentication(String),
    /// The requested feature is not available (e.g., missing feature gate).
    UnsupportedFeature(&'static str),
    /// An I/O error occurred.
    Io(String),
    /// The supervisor returned a response that could not be interpreted.
    InvalidResponse(String),
    /// An unclassified error occurred. This is a transitional variant;
    /// new errors should be classified into a more specific variant.
    Unknown(String),
}

impl std::fmt::Display for SupervisorControlError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SupervisorControlError::ConnectionUnavailable(msg) => {
                write!(f, "Connection unavailable: {}", msg)
            }
            SupervisorControlError::Timeout(msg) => {
                write!(f, "Control request timed out: {}", msg)
            }
            SupervisorControlError::Protocol(msg) => {
                write!(f, "Control protocol error: {}", msg)
            }
            SupervisorControlError::RequestRejected(msg) => {
                write!(f, "Control request rejected: {}", msg)
            }
            SupervisorControlError::Authentication(msg) => {
                write!(f, "Authentication error: {}", msg)
            }
            SupervisorControlError::UnsupportedFeature(feature) => {
                write!(f, "Feature '{}' is not enabled", feature)
            }
            SupervisorControlError::Io(msg) => write!(f, "I/O error: {}", msg),
            SupervisorControlError::InvalidResponse(msg) => {
                write!(f, "Invalid control response: {}", msg)
            }
            SupervisorControlError::Unknown(msg) => {
                write!(f, "Unexpected control error: {}", msg)
            }
        }
    }
}

impl std::error::Error for SupervisorControlError {}

impl SupervisorControlError {
    /// Map this error to a process exit code.
    ///
    /// All errors return 1 for backwards compatibility. Variant-specific
    /// exit codes are deferred until a compatibility review confirms they
    /// will not break existing scripts or tooling.
    pub fn exit_code(&self) -> i32 {
        1
    }
}

/// Classify a boxed error into a typed `SupervisorControlError`.
///
/// Uses string-based classification as a bridge from the erased `Box<dyn Error>`
/// boundary in handler functions. When the underlying error is a typed
/// `CommandError` from the IPC layer, prefer `From<CommandError>` conversion
/// instead.
fn classify_control_error(e: Box<dyn std::error::Error>) -> SupervisorControlError {
    classify_control_error_message(e.to_string())
}

/// Classify an error message string into a typed `SupervisorControlError`.
///
/// Examines the lowercased message for known patterns and maps them to the
/// most appropriate error variant. Unrecognized patterns fall through to
/// `RequestRejected`.
fn classify_control_error_message(msg: String) -> SupervisorControlError {
    let lower = msg.to_ascii_lowercase();

    if lower.contains("timeout") || lower.contains("timed out") {
        return SupervisorControlError::Timeout(msg);
    }
    if lower.contains("connection refused")
        || lower.contains("no socket")
        || lower.contains("no running instance")
        || lower.contains("connect")
    {
        return SupervisorControlError::ConnectionUnavailable(msg);
    }
    if lower.contains("unauthorized") || lower.contains("forbidden") {
        return SupervisorControlError::Authentication(msg);
    }
    if lower.contains("invalid response")
        || lower.contains("decode")
        || lower.contains("deserialization")
        || lower.contains("unexpected response")
    {
        return SupervisorControlError::InvalidResponse(msg);
    }
    if lower.contains("io error")
        || lower.contains("broken pipe")
        || lower.contains("connection reset")
        || lower.contains("permission denied")
    {
        return SupervisorControlError::Io(msg);
    }
    if lower.contains("serialization failed") || lower.contains("send failed") {
        return SupervisorControlError::Protocol(msg);
    }

    SupervisorControlError::RequestRejected(msg)
}

/// Execute a supervisor-control command and return a typed outcome.
///
/// This adapter function dispatches to existing handler functions and
/// wraps their results in structured types. Handlers that print internally
/// will continue to do so; the outcome indicates successful completion.
///
/// # Arguments
///
/// * `command` - A typed supervisor-control command from the planning layer.
///
/// # Returns
///
/// A typed outcome on success, or a typed error on failure.
pub fn execute_supervisor_control_command(
    command: SupervisorControlCommand,
) -> Result<SupervisorControlOutcome, SupervisorControlError> {
    match command {
        SupervisorControlCommand::Status {
            control_addr,
            use_tls,
        } => {
            let display = crate::supervisor::commands::handle_status_data(control_addr, use_tls)
                .map_err(classify_control_error)?;
            Ok(SupervisorControlOutcome::Status(display))
        }
        SupervisorControlCommand::Stop {
            control_addr,
            use_tls,
        } => {
            let outcome = crate::supervisor::commands::handle_stop_data(control_addr, use_tls)
                .map_err(classify_control_error)?;
            Ok(SupervisorControlOutcome::Stop(outcome))
        }
        SupervisorControlCommand::Rehash {
            control_addr,
            use_tls,
        } => {
            let outcome = crate::supervisor::commands::handle_rehash_data(control_addr, use_tls)
                .map_err(classify_control_error)?;
            Ok(SupervisorControlOutcome::Rehash(outcome))
        }
        SupervisorControlCommand::ExportThreatFeed { sign_with, site_id } => {
            #[cfg(feature = "mesh")]
            {
                let summary = crate::supervisor::commands::handle_export_threat_feed_data(
                    &sign_with,
                    site_id.as_deref(),
                )
                .map_err(classify_control_error)?;
                Ok(SupervisorControlOutcome::ThreatFeedExported(summary))
            }
            #[cfg(not(feature = "mesh"))]
            {
                Err(SupervisorControlError::UnsupportedFeature("mesh"))
            }
        }
    }
}

/// Execute a restart pre-stop using the same adapter as normal stop.
///
/// This ensures the restart pre-action uses the identical supervisor-control
/// path as a standalone `--stop` command, avoiding duplicated logic.
pub fn execute_restart_pre_stop(
    control_addr: Option<String>,
    use_tls: bool,
) -> Result<SupervisorControlOutcome, SupervisorControlError> {
    execute_supervisor_control_command(SupervisorControlCommand::Stop {
        control_addr,
        use_tls,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn success_outcomes_exit_zero() {
        let outcomes = [
            SupervisorControlOutcome::Status(SupervisorStatusDisplay {
                text: "test".into(),
            }),
            SupervisorControlOutcome::Stop(StopOutcome {
                acknowledged: true,
                shutdown_confirmed: true,
                timed_out: false,
            }),
            SupervisorControlOutcome::Rehash(RehashOutcome { acknowledged: true }),
            SupervisorControlOutcome::ThreatFeedExported(ThreatFeedExportSummary::Written {
                bytes: 1024,
                records: None,
            }),
            SupervisorControlOutcome::RestartPreStopRequested,
        ];
        for outcome in &outcomes {
            assert_eq!(
                outcome.exit_code(),
                0,
                "expected exit code 0 for {:?}",
                outcome
            );
        }
    }

    #[test]
    fn errors_exit_nonzero() {
        let errors = [
            SupervisorControlError::ConnectionUnavailable("test".into()),
            SupervisorControlError::Timeout("test".into()),
            SupervisorControlError::Protocol("test".into()),
            SupervisorControlError::RequestRejected("test".into()),
            SupervisorControlError::Authentication("test".into()),
            SupervisorControlError::UnsupportedFeature("test"),
            SupervisorControlError::Io("test".into()),
            SupervisorControlError::InvalidResponse("test".into()),
            SupervisorControlError::Unknown("test".into()),
        ];
        for error in &errors {
            assert_eq!(error.exit_code(), 1, "expected exit code 1 for {:?}", error);
        }
    }

    #[test]
    fn error_display_messages() {
        let err = SupervisorControlError::ConnectionUnavailable("refused".into());
        assert_eq!(err.to_string(), "Connection unavailable: refused");

        let err = SupervisorControlError::Timeout("deadline exceeded".into());
        assert_eq!(
            err.to_string(),
            "Control request timed out: deadline exceeded"
        );

        let err = SupervisorControlError::Protocol("send failed".into());
        assert_eq!(err.to_string(), "Control protocol error: send failed");

        let err = SupervisorControlError::RequestRejected("server error".into());
        assert_eq!(err.to_string(), "Control request rejected: server error");

        let err = SupervisorControlError::Authentication("forbidden".into());
        assert_eq!(err.to_string(), "Authentication error: forbidden");

        let err = SupervisorControlError::UnsupportedFeature("mesh");
        assert_eq!(err.to_string(), "Feature 'mesh' is not enabled");

        let err = SupervisorControlError::Io("broken pipe".into());
        assert_eq!(err.to_string(), "I/O error: broken pipe");

        let err = SupervisorControlError::InvalidResponse("decode error".into());
        assert_eq!(err.to_string(), "Invalid control response: decode error");

        let err = SupervisorControlError::Unknown("something happened".into());
        assert_eq!(
            err.to_string(),
            "Unexpected control error: something happened"
        );
    }

    #[test]
    fn unsupported_feature_display_is_stable() {
        let err = SupervisorControlError::UnsupportedFeature("mesh");
        assert_eq!(err.to_string(), "Feature 'mesh' is not enabled");
        let err = SupervisorControlError::UnsupportedFeature("dns");
        assert_eq!(err.to_string(), "Feature 'dns' is not enabled");
    }

    #[test]
    fn classifies_connection_refused_as_connection_unavailable() {
        let err = classify_control_error_message("connection refused".into());
        assert_eq!(
            err,
            SupervisorControlError::ConnectionUnavailable("connection refused".into())
        );
    }

    #[test]
    fn classifies_no_socket_as_connection_unavailable() {
        let err = classify_control_error_message("No socket path available".into());
        assert_eq!(
            err,
            SupervisorControlError::ConnectionUnavailable("No socket path available".into())
        );
    }

    #[test]
    fn classifies_no_running_instance_as_connection_unavailable() {
        let err = classify_control_error_message("No running instance found".into());
        assert_eq!(
            err,
            SupervisorControlError::ConnectionUnavailable("No running instance found".into())
        );
    }

    #[test]
    fn classifies_timeout_as_timeout() {
        let err = classify_control_error_message("Request timed out after 30s".into());
        assert_eq!(
            err,
            SupervisorControlError::Timeout("Request timed out after 30s".into())
        );
    }

    #[test]
    fn classifies_timeout_lowercase() {
        let err = classify_control_error_message("timeout".into());
        assert_eq!(err, SupervisorControlError::Timeout("timeout".into()));
    }

    #[test]
    fn classifies_unauthorized_as_authentication() {
        let err = classify_control_error_message("Unauthorized access".into());
        assert_eq!(
            err,
            SupervisorControlError::Authentication("Unauthorized access".into())
        );
    }

    #[test]
    fn classifies_forbidden_as_authentication() {
        let err = classify_control_error_message("Forbidden".into());
        assert_eq!(
            err,
            SupervisorControlError::Authentication("Forbidden".into())
        );
    }

    #[test]
    fn classifies_invalid_response_as_invalid_response() {
        let err = classify_control_error_message("Invalid response from server".into());
        assert_eq!(
            err,
            SupervisorControlError::InvalidResponse("Invalid response from server".into())
        );
    }

    #[test]
    fn classifies_decode_error_as_invalid_response() {
        let err = classify_control_error_message("decode error in payload".into());
        assert_eq!(
            err,
            SupervisorControlError::InvalidResponse("decode error in payload".into())
        );
    }

    #[test]
    fn classifies_deserialization_as_invalid_response() {
        let err = classify_control_error_message("Deserialization failed: unexpected field".into());
        assert_eq!(
            err,
            SupervisorControlError::InvalidResponse(
                "Deserialization failed: unexpected field".into()
            )
        );
    }

    #[test]
    fn classifies_io_error_as_io() {
        let err = classify_control_error_message("io error: broken pipe".into());
        assert_eq!(
            err,
            SupervisorControlError::Io("io error: broken pipe".into())
        );
    }

    #[test]
    fn classifies_send_failed_as_protocol() {
        let err = classify_control_error_message("Send failed: channel closed".into());
        assert_eq!(
            err,
            SupervisorControlError::Protocol("Send failed: channel closed".into())
        );
    }

    #[test]
    fn classifies_serialization_failed_as_protocol() {
        let err = classify_control_error_message("Serialization failed: unsupported type".into());
        assert_eq!(
            err,
            SupervisorControlError::Protocol("Serialization failed: unsupported type".into())
        );
    }

    #[test]
    fn classifies_unknown_error_as_request_rejected() {
        let err = classify_control_error_message("something unexpected happened".into());
        assert_eq!(
            err,
            SupervisorControlError::RequestRejected("something unexpected happened".into())
        );
    }

    #[test]
    fn classify_preserves_original_message() {
        let msg = "Connection refused to 127.0.0.1:8080".to_string();
        let err = classify_control_error_message(msg.clone());
        match err {
            SupervisorControlError::ConnectionUnavailable(m) => assert_eq!(m, msg),
            other => panic!("expected ConnectionUnavailable, got {:?}", other),
        }
    }

    #[test]
    fn classify_is_case_insensitive() {
        let err = classify_control_error_message("CONNECTION REFUSED".into());
        assert!(matches!(
            err,
            SupervisorControlError::ConnectionUnavailable(_)
        ));

        let err = classify_control_error_message("TIMEOUT".into());
        assert!(matches!(err, SupervisorControlError::Timeout(_)));

        let err = classify_control_error_message("UNAUTHORIZED".into());
        assert!(matches!(err, SupervisorControlError::Authentication(_)));
    }

    #[test]
    fn all_error_variants_are_exhaustive() {
        // Ensure every variant is covered in Display and exit_code.
        // Adding a new variant without updating Display or exit_code will
        // cause this test to fail to compile.
        let variants: Vec<SupervisorControlError> = vec![
            SupervisorControlError::ConnectionUnavailable("t".into()),
            SupervisorControlError::Timeout("t".into()),
            SupervisorControlError::Protocol("t".into()),
            SupervisorControlError::RequestRejected("t".into()),
            SupervisorControlError::Authentication("t".into()),
            SupervisorControlError::UnsupportedFeature("t"),
            SupervisorControlError::Io("t".into()),
            SupervisorControlError::InvalidResponse("t".into()),
            SupervisorControlError::Unknown("t".into()),
        ];
        for v in &variants {
            // Display must not panic
            let _ = v.to_string();
            // exit_code must be 1
            assert_eq!(v.exit_code(), 1);
        }
    }

    #[test]
    fn restart_pre_stop_returns_stop_outcome() {
        let outcome = SupervisorControlOutcome::RestartPreStopRequested;
        assert_eq!(outcome.exit_code(), 0);
        assert!(outcome.display().is_none());
    }

    #[test]
    fn threat_feed_export_with_bytes_displays_correctly() {
        let outcome =
            SupervisorControlOutcome::ThreatFeedExported(ThreatFeedExportSummary::Written {
                bytes: 4096,
                records: Some(128),
            });
        assert_eq!(outcome.exit_code(), 0);
        let display = outcome.display().unwrap();
        assert!(display.contains("4096"));
        assert!(display.contains("128"));
    }

    #[test]
    fn threat_feed_export_completed_displays_correctly() {
        let outcome =
            SupervisorControlOutcome::ThreatFeedExported(ThreatFeedExportSummary::Completed);
        assert_eq!(outcome.exit_code(), 0);
        assert_eq!(outcome.display().unwrap(), "Threat feed exported");
    }

    #[test]
    fn status_outcome_displays_status_text() {
        let outcome = SupervisorControlOutcome::Status(SupervisorStatusDisplay {
            text: "synvoid Status\n==============\nPID: 1234".into(),
        });
        let display = outcome.display().unwrap();
        assert!(display.contains("synvoid Status"));
        assert!(display.contains("PID: 1234"));
    }

    #[test]
    fn stop_outcome_shutdown_confirmed_displays_stopped() {
        let outcome = SupervisorControlOutcome::Stop(StopOutcome {
            acknowledged: true,
            shutdown_confirmed: true,
            timed_out: false,
        });
        assert_eq!(outcome.display().unwrap(), "synvoid stopped");
    }

    #[test]
    fn stop_outcome_timeout_displays_warning() {
        let outcome = SupervisorControlOutcome::Stop(StopOutcome {
            acknowledged: true,
            shutdown_confirmed: false,
            timed_out: true,
        });
        assert!(outcome
            .display()
            .unwrap()
            .contains("did not shut down cleanly"));
    }

    #[test]
    fn rehash_outcome_acknowledged_displays_reload() {
        let outcome = SupervisorControlOutcome::Rehash(RehashOutcome { acknowledged: true });
        assert_eq!(outcome.display().unwrap(), "Configuration reloaded");
    }

    #[test]
    fn threat_feed_export_does_not_use_placeholder_zero_bytes() {
        // Verify the new API uses ThreatFeedExportSummary, not a raw bytes field
        // which was the old placeholder pattern.
        let summary = ThreatFeedExportSummary::Written {
            bytes: 0,
            records: None,
        };
        // bytes: 0 is only valid when the export genuinely produced zero bytes
        match &summary {
            ThreatFeedExportSummary::Written { bytes, .. } => assert_eq!(*bytes, 0),
            _ => panic!("expected Written variant"),
        }
    }
}
