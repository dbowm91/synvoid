use std::path::PathBuf;

use synvoid_cli::Args;

/// Errors that can occur during command planning.
#[derive(Debug, Clone)]
pub enum CommandPlanError {
    /// Multiple mutually exclusive worker modes specified.
    MultipleWorkerModes,
    /// A mesh-only command was invoked without the mesh feature.
    MeshFeatureRequired,
    /// Test mode requires --force flag.
    TestModeRequiresForce,
    /// --hash-token was provided without a token value.
    MissingHashToken,
}

impl std::fmt::Display for CommandPlanError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CommandPlanError::MultipleWorkerModes => write!(
                f,
                "Only one mode (--worker, --cpu-worker/--static-worker, --unified-server-worker, \
                 --mesh-agent, --wasm-jail, --yara-jail) can be specified"
            ),
            CommandPlanError::MeshFeatureRequired => {
                write!(f, "This command requires the mesh feature to be enabled.")
            }
            CommandPlanError::TestModeRequiresForce => {
                write!(f, "--test requires --force flag")
            }
            CommandPlanError::MissingHashToken => {
                write!(f, "--hash-token requires a token value")
            }
        }
    }
}

impl std::error::Error for CommandPlanError {}

/// A one-shot command that completes without launching the server runtime.
#[derive(Debug, Clone)]
pub enum OneShotCommand {
    /// Validate config files and exit.
    ConfigTest,
    /// Export OpenAPI schema as JSON and exit.
    ExportOpenApi,
    /// Export API specification (OpenAPI 3.0) as JSON and exit.
    ExportApiSpec,
    /// Generate a new genesis key for mesh setup.
    Genesis,
    /// Show current node information.
    ShowNodeInfo,
    /// Generate and print an admin token.
    GenerateToken,
    /// Generate a new admin token and save to config.
    GenerateNewToken { config_path: Option<PathBuf> },
    /// Hash an admin token with bcrypt.
    HashToken { token: String, cost: u32 },
    /// Check if a regex pattern is safe (ReDoS check).
    CheckRegex { pattern: String },
}

/// A command that communicates with a running supervisor via IPC.
#[derive(Debug, Clone)]
pub enum SupervisorControlCommand {
    /// Show status of running instance.
    Status {
        control_addr: Option<String>,
        use_tls: bool,
    },
    /// Stop running instance.
    Stop {
        control_addr: Option<String>,
        use_tls: bool,
    },
    /// Reload configuration and propagate to workers.
    Rehash {
        control_addr: Option<String>,
        use_tls: bool,
    },
    /// Export threat feed as signed JSON.
    ExportThreatFeed {
        sign_with: Option<PathBuf>,
        site_id: Option<String>,
    },
}

/// A runtime launch command that starts a long-running process.
#[derive(Debug, Clone)]
pub enum RuntimeCommand {
    /// Run as supervisor (default — manages workers).
    Supervisor,
    /// Run as unified server worker (HTTP/HTTPS/HTTP3 + WAF + proxy).
    UnifiedServerWorker,
    /// Run as CPU offload worker.
    CpuWorker,
    /// Run as mesh agent process.
    MeshAgent,
    /// Run as WASM plugin execution jail.
    WasmJail,
    /// Run as YARA rule evaluation jail.
    YaraJail,
}

/// A pre-action executed before the main command plan (e.g., restart pre-stop).
#[derive(Debug, Clone)]
pub enum CommandPreAction {
    /// Stop the running supervisor before launching a new runtime instance.
    RestartSupervisor {
        control_addr: Option<String>,
        use_tls: bool,
    },
}

/// The top-level command plan produced from parsed CLI args.
#[derive(Debug, Clone)]
pub enum SynvoidCommandPlan {
    /// A one-shot command that completes and exits.
    OneShot(OneShotCommand),
    /// A supervisor-control command sent via IPC to a running instance.
    SupervisorControl(SupervisorControlCommand),
    /// A runtime launch command that starts a long-running process.
    Runtime(RuntimeCommand),
}

/// Complete command plan carrying the full CLI args for execution.
#[derive(Debug)]
pub struct CommandPlan {
    pub plan: SynvoidCommandPlan,
    /// Parsed test flags, if any.
    pub test_flags: Option<Vec<String>>,
    /// Config path from CLI args.
    pub config_path: Option<PathBuf>,
    /// Pre-action to execute before the main plan (e.g., restart pre-stop).
    pub pre_action: Option<CommandPreAction>,
    /// Foreground mode flag.
    pub foreground: bool,
    /// CPU worker args from CLI.
    pub cpu_worker_id: Option<usize>,
    /// Unified server worker args from CLI.
    pub unified_worker_id: Option<usize>,
    pub worker_threads: Option<usize>,
    pub cpu_affinity: Option<usize>,
    pub total_workers: Option<usize>,
    pub reuse_port: bool,
}

/// Pure command planning from parsed CLI args.
///
/// Validates mutual exclusivity of worker modes and classifies the command
/// without launching any runtime or performing I/O.
pub fn plan_command(args: &Args) -> Result<CommandPlan, CommandPlanError> {
    // Validate mutual exclusivity of worker modes
    let worker_mode_count = [
        args.worker,
        args.cpu_worker,
        args.unified_server_worker,
        args.mesh_agent,
        args.wasm_jail,
        args.yara_jail,
    ]
    .into_iter()
    .filter(|&b| b)
    .count();

    if worker_mode_count > 1 {
        return Err(CommandPlanError::MultipleWorkerModes);
    }

    // Validate test mode requires force
    if args.test.is_some() && !args.force {
        return Err(CommandPlanError::TestModeRequiresForce);
    }

    let plan = if args.configtest {
        SynvoidCommandPlan::OneShot(OneShotCommand::ConfigTest)
    } else if args.export_openapi {
        SynvoidCommandPlan::OneShot(OneShotCommand::ExportOpenApi)
    } else if args.export_api_spec {
        SynvoidCommandPlan::OneShot(OneShotCommand::ExportApiSpec)
    } else if args.genesis {
        #[cfg(feature = "mesh")]
        {
            SynvoidCommandPlan::OneShot(OneShotCommand::Genesis)
        }
        #[cfg(not(feature = "mesh"))]
        {
            return Err(CommandPlanError::MeshFeatureRequired);
        }
    } else if args.show_node_info {
        #[cfg(feature = "mesh")]
        {
            SynvoidCommandPlan::OneShot(OneShotCommand::ShowNodeInfo)
        }
        #[cfg(not(feature = "mesh"))]
        {
            return Err(CommandPlanError::MeshFeatureRequired);
        }
    } else if args.generatetoken {
        SynvoidCommandPlan::OneShot(OneShotCommand::GenerateToken)
    } else if args.hash_token.is_some() {
        let token = match args.hash_token.clone().flatten() {
            Some(t) => t,
            None => {
                return Err(CommandPlanError::MissingHashToken);
            }
        };
        let cost = args.hash_cost.unwrap_or(12).clamp(4, 31);
        SynvoidCommandPlan::OneShot(OneShotCommand::HashToken { token, cost })
    } else if let Some(ref pattern) = args.checkregex {
        SynvoidCommandPlan::OneShot(OneShotCommand::CheckRegex {
            pattern: pattern.clone(),
        })
    } else if args.generatenewtoken {
        SynvoidCommandPlan::OneShot(OneShotCommand::GenerateNewToken {
            config_path: args.config_path.clone(),
        })
    } else if args.status {
        SynvoidCommandPlan::SupervisorControl(SupervisorControlCommand::Status {
            control_addr: args.control_addr.clone(),
            use_tls: args.control_api_tls,
        })
    } else if args.stop {
        SynvoidCommandPlan::SupervisorControl(SupervisorControlCommand::Stop {
            control_addr: args.control_addr.clone(),
            use_tls: args.control_api_tls,
        })
    } else if args.rehash {
        SynvoidCommandPlan::SupervisorControl(SupervisorControlCommand::Rehash {
            control_addr: args.control_addr.clone(),
            use_tls: args.control_api_tls,
        })
    } else if args.export_threat_feed {
        #[cfg(feature = "mesh")]
        {
            SynvoidCommandPlan::SupervisorControl(SupervisorControlCommand::ExportThreatFeed {
                sign_with: args.sign_with.clone(),
                site_id: args.site_id.clone(),
            })
        }
        #[cfg(not(feature = "mesh"))]
        {
            return Err(CommandPlanError::MeshFeatureRequired);
        }
    } else if args.cpu_worker {
        SynvoidCommandPlan::Runtime(RuntimeCommand::CpuWorker)
    } else if args.unified_server_worker {
        SynvoidCommandPlan::Runtime(RuntimeCommand::UnifiedServerWorker)
    } else if args.mesh_agent {
        SynvoidCommandPlan::Runtime(RuntimeCommand::MeshAgent)
    } else if args.wasm_jail {
        SynvoidCommandPlan::Runtime(RuntimeCommand::WasmJail)
    } else if args.yara_jail {
        SynvoidCommandPlan::Runtime(RuntimeCommand::YaraJail)
    } else {
        // Default: Supervisor
        SynvoidCommandPlan::Runtime(RuntimeCommand::Supervisor)
    };

    let pre_action = if args.restart {
        Some(CommandPreAction::RestartSupervisor {
            control_addr: args.control_addr.clone(),
            use_tls: args.control_api_tls,
        })
    } else {
        None
    };

    Ok(CommandPlan {
        plan,
        test_flags: args.test.clone(),
        config_path: args.config_path.clone(),
        pre_action,
        foreground: args.foreground,
        cpu_worker_id: args.cpu_worker_id,
        unified_worker_id: args.unified_worker_id,
        worker_threads: args.worker_threads,
        cpu_affinity: args.cpu_affinity,
        total_workers: args.total_workers,
        reuse_port: args.reuse_port,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_args() -> Args {
        Args {
            mesh_agent: false,
            wasm_jail: false,
            yara_jail: false,
            worker: false,
            worker_id: None,
            port: None,
            config_path: None,
            supervisor_socket: None,
            cpu_worker: false,
            cpu_worker_id: None,
            unified_server_worker: false,
            unified_worker_id: None,
            worker_threads: None,
            cpu_affinity: None,
            total_workers: None,
            reuse_port: false,
            foreground: false,
            configtest: false,
            status: false,
            stop: false,
            restart: false,
            rehash: false,
            generatenewtoken: false,
            generatetoken: false,
            hash_token: None,
            hash_cost: None,
            test: None,
            checkregex: None,
            force: false,
            log_level: None,
            control_addr: None,
            control_api_tls: false,
            export_openapi: false,
            export_api_spec: false,
            export_threat_feed: false,
            sign_with: None,
            site_id: None,
            genesis: false,
            show_node_info: false,
        }
    }

    #[test]
    fn default_invocation_maps_to_supervisor() {
        let args = default_args();
        let plan = plan_command(&args).unwrap();
        assert!(matches!(
            plan.plan,
            SynvoidCommandPlan::Runtime(RuntimeCommand::Supervisor)
        ));
    }

    #[test]
    fn cpu_worker_maps_to_runtime() {
        let mut args = default_args();
        args.cpu_worker = true;
        let plan = plan_command(&args).unwrap();
        assert!(matches!(
            plan.plan,
            SynvoidCommandPlan::Runtime(RuntimeCommand::CpuWorker)
        ));
    }

    #[test]
    fn unified_server_worker_maps_to_runtime() {
        let mut args = default_args();
        args.unified_server_worker = true;
        let plan = plan_command(&args).unwrap();
        assert!(matches!(
            plan.plan,
            SynvoidCommandPlan::Runtime(RuntimeCommand::UnifiedServerWorker)
        ));
    }

    #[test]
    fn mesh_agent_maps_to_runtime() {
        #[cfg(feature = "mesh")]
        {
            let mut args = default_args();
            args.mesh_agent = true;
            let plan = plan_command(&args).unwrap();
            assert!(matches!(
                plan.plan,
                SynvoidCommandPlan::Runtime(RuntimeCommand::MeshAgent)
            ));
        }
    }

    #[test]
    fn wasm_jail_maps_to_runtime() {
        let mut args = default_args();
        args.wasm_jail = true;
        let plan = plan_command(&args).unwrap();
        assert!(matches!(
            plan.plan,
            SynvoidCommandPlan::Runtime(RuntimeCommand::WasmJail)
        ));
    }

    #[test]
    fn yara_jail_maps_to_runtime() {
        let mut args = default_args();
        args.yara_jail = true;
        let plan = plan_command(&args).unwrap();
        assert!(matches!(
            plan.plan,
            SynvoidCommandPlan::Runtime(RuntimeCommand::YaraJail)
        ));
    }

    #[test]
    fn configtest_maps_to_one_shot() {
        let mut args = default_args();
        args.configtest = true;
        let plan = plan_command(&args).unwrap();
        assert!(matches!(
            plan.plan,
            SynvoidCommandPlan::OneShot(OneShotCommand::ConfigTest)
        ));
    }

    #[test]
    fn export_openapi_maps_to_one_shot() {
        let mut args = default_args();
        args.export_openapi = true;
        let plan = plan_command(&args).unwrap();
        assert!(matches!(
            plan.plan,
            SynvoidCommandPlan::OneShot(OneShotCommand::ExportOpenApi)
        ));
    }

    #[test]
    fn export_api_spec_maps_to_one_shot() {
        let mut args = default_args();
        args.export_api_spec = true;
        let plan = plan_command(&args).unwrap();
        assert!(matches!(
            plan.plan,
            SynvoidCommandPlan::OneShot(OneShotCommand::ExportApiSpec)
        ));
    }

    #[test]
    fn generatetoken_maps_to_one_shot() {
        let mut args = default_args();
        args.generatetoken = true;
        let plan = plan_command(&args).unwrap();
        assert!(matches!(
            plan.plan,
            SynvoidCommandPlan::OneShot(OneShotCommand::GenerateToken)
        ));
    }

    #[test]
    fn checkregex_maps_to_one_shot() {
        let mut args = default_args();
        args.checkregex = Some(r"\d+".to_string());
        let plan = plan_command(&args).unwrap();
        assert!(matches!(
            plan.plan,
            SynvoidCommandPlan::OneShot(OneShotCommand::CheckRegex { .. })
        ));
    }

    #[test]
    fn status_maps_to_supervisor_control() {
        let mut args = default_args();
        args.status = true;
        let plan = plan_command(&args).unwrap();
        assert!(matches!(
            plan.plan,
            SynvoidCommandPlan::SupervisorControl(SupervisorControlCommand::Status { .. })
        ));
    }

    #[test]
    fn stop_maps_to_supervisor_control() {
        let mut args = default_args();
        args.stop = true;
        let plan = plan_command(&args).unwrap();
        assert!(matches!(
            plan.plan,
            SynvoidCommandPlan::SupervisorControl(SupervisorControlCommand::Stop { .. })
        ));
    }

    #[test]
    fn rehash_maps_to_supervisor_control() {
        let mut args = default_args();
        args.rehash = true;
        let plan = plan_command(&args).unwrap();
        assert!(matches!(
            plan.plan,
            SynvoidCommandPlan::SupervisorControl(SupervisorControlCommand::Rehash { .. })
        ));
    }

    #[test]
    fn multiple_worker_modes_rejects() {
        let mut args = default_args();
        args.cpu_worker = true;
        args.unified_server_worker = true;
        let result = plan_command(&args);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            CommandPlanError::MultipleWorkerModes
        ));
    }

    #[test]
    fn test_mode_without_force_rejects() {
        let mut args = default_args();
        args.test = Some(vec!["all-off".to_string()]);
        let result = plan_command(&args);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            CommandPlanError::TestModeRequiresForce
        ));
    }

    #[test]
    fn test_mode_with_force_ok() {
        let mut args = default_args();
        args.test = Some(vec!["all-off".to_string()]);
        args.force = true;
        let plan = plan_command(&args).unwrap();
        // Still supervisor by default
        assert!(matches!(
            plan.plan,
            SynvoidCommandPlan::Runtime(RuntimeCommand::Supervisor)
        ));
        assert!(plan.test_flags.is_some());
    }

    #[test]
    fn genesis_without_mesh_rejects() {
        #[cfg(not(feature = "mesh"))]
        {
            let mut args = default_args();
            args.genesis = true;
            let result = plan_command(&args);
            assert!(result.is_err());
            assert!(matches!(
                result.unwrap_err(),
                CommandPlanError::MeshFeatureRequired
            ));
        }
    }

    #[test]
    fn foreground_flag_preserved() {
        let mut args = default_args();
        args.foreground = true;
        let plan = plan_command(&args).unwrap();
        assert!(plan.foreground);
    }

    #[test]
    fn config_path_preserved() {
        let mut args = default_args();
        args.config_path = Some(PathBuf::from("/custom/config"));
        let plan = plan_command(&args).unwrap();
        assert_eq!(plan.config_path, Some(PathBuf::from("/custom/config")));
    }

    #[test]
    fn restart_preserves_control_addr_and_tls() {
        let mut args = default_args();
        args.restart = true;
        args.control_addr = Some("127.0.0.1:9443".to_string());
        args.control_api_tls = true;

        let plan = plan_command(&args).unwrap();

        assert!(matches!(
            plan.pre_action,
            Some(CommandPreAction::RestartSupervisor { ref control_addr, use_tls: true })
                if control_addr.as_deref() == Some("127.0.0.1:9443")
        ));
    }

    #[test]
    fn restart_defaults_to_supervisor_runtime_after_pre_stop() {
        let mut args = default_args();
        args.restart = true;

        let plan = plan_command(&args).unwrap();
        assert!(matches!(
            plan.plan,
            SynvoidCommandPlan::Runtime(RuntimeCommand::Supervisor)
        ));
        assert!(matches!(
            plan.pre_action,
            Some(CommandPreAction::RestartSupervisor { .. })
        ));
    }

    #[test]
    fn restart_without_control_addr_uses_default() {
        let mut args = default_args();
        args.restart = true;

        let plan = plan_command(&args).unwrap();
        assert!(matches!(
            plan.pre_action,
            Some(CommandPreAction::RestartSupervisor {
                control_addr: None,
                use_tls: false
            })
        ));
    }

    #[test]
    fn hash_token_without_value_reports_missing_hash_token() {
        let mut args = default_args();
        args.hash_token = Some(None);

        let result = plan_command(&args);
        assert!(matches!(
            result.unwrap_err(),
            CommandPlanError::MissingHashToken
        ));
    }
}
