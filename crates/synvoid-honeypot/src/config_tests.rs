use crate::config::*;

#[test]
fn default_runtime_config_is_within_hard_resource_ceilings() {
    PortHoneypotConfig::default()
        .validate_resource_limits()
        .expect("defaults must remain valid");
}

#[test]
fn payload_limit_accepts_boundary_and_rejects_one_byte_over() {
    let mut config = PortHoneypotConfig {
        max_payload_size: MAX_RETAINED_PAYLOAD_BYTES,
        ..Default::default()
    };
    assert!(config.validate_resource_limits().is_ok());
    config.max_payload_size += 1;
    let error = config.validate_resource_limits().unwrap_err();
    assert_eq!(error.field, "max_payload_size");
    assert_eq!(error.actual, MAX_RETAINED_PAYLOAD_BYTES + 1);
}

#[test]
fn concurrent_connections_and_listener_counts_are_bounded() {
    let config = PortHoneypotConfig {
        max_concurrent_connections: MAX_CONNECTIONS + 1,
        ..Default::default()
    };
    assert_eq!(
        config.validate_resource_limits().unwrap_err().field,
        "max_concurrent_connections"
    );

    let config = PortHoneypotConfig {
        num_honeypot_ports: MAX_LISTENERS + 1,
        ..Default::default()
    };
    assert_eq!(
        config.validate_resource_limits().unwrap_err().field,
        "num_honeypot_ports"
    );
}

#[test]
fn storage_queue_and_batch_sizes_are_bounded() {
    let config = PortHoneypotConfig {
        storage: StorageConfig {
            writer: StorageWriterConfig {
                queue_capacity: MAX_STORAGE_QUEUE_CAPACITY + 1,
                ..Default::default()
            },
            ..Default::default()
        },
        ..Default::default()
    };
    assert_eq!(
        config.validate_resource_limits().unwrap_err().field,
        "storage.writer.queue_capacity"
    );

    let config = PortHoneypotConfig {
        storage: StorageConfig {
            writer: StorageWriterConfig {
                batch_size: MAX_STORAGE_BATCH_SIZE + 1,
                ..Default::default()
            },
            ..Default::default()
        },
        ..Default::default()
    };
    assert_eq!(
        config.validate_resource_limits().unwrap_err().field,
        "storage.writer.batch_size"
    );
}

#[test]
fn ai_prompt_response_and_concurrency_budgets_are_bounded() {
    let mut config = PortHoneypotConfig {
        ai_config: Some(AiConfig {
            mode: AiResponderMode::ExternalProvider,
            provider: "test".into(),
            endpoint: None,
            api_key: None,
            model: "test".into(),
            timeout_secs: 1,
            system_prompt: None,
            budget: AiBudgetConfig::default(),
        }),
        ..Default::default()
    };
    config.ai_config.as_mut().unwrap().budget.max_prompt_bytes = MAX_AI_PROMPT_BYTES + 1;
    assert_eq!(
        config.validate_resource_limits().unwrap_err().field,
        "ai_config.budget.max_prompt_bytes"
    );
    config.ai_config.as_mut().unwrap().budget.max_prompt_bytes = MAX_AI_PROMPT_BYTES;
    config.ai_config.as_mut().unwrap().budget.max_response_bytes = MAX_AI_RESPONSE_BYTES + 1;
    assert_eq!(
        config.validate_resource_limits().unwrap_err().field,
        "ai_config.budget.max_response_bytes"
    );
    config.ai_config.as_mut().unwrap().budget.max_response_bytes = MAX_AI_RESPONSE_BYTES;
    config
        .ai_config
        .as_mut()
        .unwrap()
        .budget
        .max_concurrent_requests = MAX_AI_CONCURRENCY + 1;
    assert_eq!(
        config.validate_resource_limits().unwrap_err().field,
        "ai_config.budget.max_concurrent_requests"
    );
}

#[test]
fn aggregate_configured_response_bytes_are_bounded() {
    let mut config = PortHoneypotConfig::default();
    config.services[0].banner = vec![0; MAX_CONFIGURED_RESPONSE_BYTES + 1];
    assert_eq!(
        config.validate_resource_limits().unwrap_err().field,
        "services.response_data_bytes"
    );
}
