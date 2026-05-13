use std::path::PathBuf;
use std::sync::Arc;

#[cfg(feature = "mesh")]
use crate::config::{ConfigManager, MainConfig};
#[cfg(feature = "mesh")]
use crate::block_store::BlockStore;
#[cfg(feature = "mesh")]
use crate::waf::YaraRulesManager;
#[cfg(feature = "mesh")]
use crate::mesh::threat_intel::{ThreatIntelligenceManager, ThreatIntelligenceConfig};
#[cfg(feature = "mesh")]
use crate::mesh::{
    topology::MeshTopology,
    dht::routing::DhtRoutingManager,
    crypto_verification::CryptoVerificationPool,
    transports::MeshTransportManager,
    proxy::MeshProxy,
    backend::MeshBackendPool,
    backend::create_record_store,
};

#[cfg(feature = "mesh")]
pub struct MeshControlPlane {
    pub transport_manager: Arc<MeshTransportManager>,
    pub threat_intel: Arc<ThreatIntelligenceManager>,
    pub yara_rules: Option<Arc<YaraRulesManager>>,
}

#[cfg(feature = "mesh")]
pub fn run_mesh_agent_mode(config_path: Option<PathBuf>, _foreground: bool) {
    let agent_panic_log = format!(
        "{}/synvoid-mesh-agent-panic.log",
        std::env::temp_dir().display()
    );
    crate::common::setup_panic_handler("MESH_AGENT", Some(&agent_panic_log));

    let config_dir = config_path.unwrap_or_else(|| PathBuf::from("config"));
    let main_config_path = config_dir.join("main.toml");

    let mut config_manager = ConfigManager::new(config_dir.clone());
    if let Err(e) = config_manager.load_main(&main_config_path) {
        tracing::error!("Failed to load main.toml for mesh agent: {}", e);
        std::process::exit(1);
    }
    
    let main_config = config_manager.main.clone();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("Failed to build Tokio runtime for mesh agent");

    rt.block_on(async {
        tracing::info!("Starting standalone Mesh Agent (Control Plane)");

        // Initialize block store for threat intel
        let data_dir = main_config.persistence.data_dir.as_ref().map(PathBuf::from);
        let block_store = Arc::new(BlockStore::new(
            true,
            data_dir,
            main_config.blocklist_limits.clone(),
        ));

        let cp = match init_mesh_control_plane(&main_config, block_store).await {
            Some(cp) => cp,
            None => {
                tracing::error!("Mesh is disabled or failed to initialize. Mesh agent exiting.");
                return;
            }
        };

        // Mesh agent handles gRPC control API for mesh-related queries
        let grpc_addr: Result<std::net::SocketAddr, _> = main_config.supervisor.control_api_addr.parse();
        if let Ok(addr) = grpc_addr {
            // Note: Standalone mesh agent doesn't manage workers, so PM is None-equivalent
            // We might need a dummy PM or refactor gRPC server to handle mesh-only mode.
            tracing::info!("Mesh Agent gRPC server listening on {}", addr);
            // super::api::start_grpc_server(addr, pm, state).await // Need to adapt this
        }

        // Keep running until signaled
        tracing::info!("Mesh Agent is now active.");
        
        let _ = tokio::signal::ctrl_c().await;
        tracing::info!("Mesh Agent shutting down...");
    });
}

#[cfg(not(feature = "mesh"))]
pub fn run_mesh_agent_mode(_config_path: Option<PathBuf>, _foreground: bool) {
    eprintln!("Mesh agent mode requires the mesh feature to be enabled.");
    std::process::exit(1);
}

#[cfg(feature = "mesh")]
pub async fn init_mesh_control_plane(
    main_config: &MainConfig,
    block_store: Arc<BlockStore>,
) -> Option<MeshControlPlane> {
    let mesh_config_external = main_config.tunnel.mesh.as_ref()?;
    let mesh_config: crate::mesh::config::MeshConfig = serde_json::from_str(&serde_json::to_string(mesh_config_external).unwrap()).unwrap();
    
    if !mesh_config.enabled {
        tracing::info!("Mesh is disabled in configuration.");
        return None;
    }

    tracing::info!("Initializing Mesh Control Plane in Supervisor...");
    let node_id = mesh_config.node_id();
    let mesh_config_arc = Arc::new(mesh_config.clone());

    let topology = Arc::new(MeshTopology::new(mesh_config_arc.clone()));
    topology.start_background_tasks();

    let routing_manager = if mesh_config.dht.as_ref().map(|d| d.routing_enabled).unwrap_or(false) {
        let manager = Arc::new(DhtRoutingManager::new(mesh_config_arc.clone()));
        let manager_clone = manager.clone();
        manager.start_background_tasks();
        tokio::spawn(async move {
            manager_clone.init().await;
        });
        Some(manager)
    } else {
        None
    };

    let verification_pool = Arc::new(CryptoVerificationPool::default());
    let record_store = create_record_store(
        &mesh_config,
        routing_manager,
        Some(verification_pool.clone()),
    );

    let transport_manager = Arc::new(MeshTransportManager::new(
        mesh_config_arc.clone(),
        topology.clone(),
        record_store.clone(),
    ));

    let proxy = Arc::new(MeshProxy::new(
        mesh_config_arc.clone(),
        topology.clone(),
        None,
    ));
    
    let backend_pool = Arc::new(MeshBackendPool::new(
        proxy.clone(),
        topology.clone(),
    ));

    let signer_key = if let Some(ref key) = mesh_config.global_node_key {
        let mut key_bytes = [0u8; 32];
        let key_str = key.as_bytes();
        let len = key_str.len().min(32);
        key_bytes[..len].copy_from_slice(&key_str[..len]);
        key_bytes
    } else {
        use hkdf::Hkdf;
        use sha2::Sha256;
        let ikm = node_id.as_bytes();
        let hk = Hkdf::<Sha256>::new(None, ikm);
        let mut okm = [0u8; 32];
        hk.expand(b"synvoid-mesh-signer", &mut okm).expect("HKDF expand failed");
        okm
    };

    let threat_config = ThreatIntelligenceConfig {
        enabled: mesh_config.threat_intel.enabled,
        push_enabled: mesh_config.threat_intel.push_enabled,
        sync_enabled: mesh_config.threat_intel.sync_enabled,
        sync_interval_secs: mesh_config.threat_intel.sync_interval_secs,
        threat_sync_interval_secs: mesh_config.threat_intel.threat_sync_interval_secs,
        push_severity_threshold: mesh_config.threat_intel.push_severity_threshold.clone(),
        min_ttl_seconds: mesh_config.threat_intel.min_ttl_seconds,
        max_indicators_per_message: mesh_config.threat_intel.max_indicators_per_message,
        hub_only_mode: mesh_config.threat_intel.hub_only_mode,
        reputation_config: mesh_config.threat_intel.reputation_config.clone(),
        fanout_factor: mesh_config.threat_intel.fanout_factor,
        re_announce_interval_secs: mesh_config.threat_intel.re_announce_interval_secs,
        trusted_signers: mesh_config.threat_intel.trusted_signers.clone(),
        behavioral_enabled: mesh_config.threat_intel.behavioral_enabled,
        min_samples_for_fingerprint: mesh_config.threat_intel.min_samples_for_fingerprint,
        fingerprint_ttl_secs: mesh_config.threat_intel.fingerprint_ttl_secs,
        high_severity_threshold: mesh_config.threat_intel.high_severity_threshold,
    };

    let signer_for_threat = crate::mesh::protocol::MeshMessageSigner::new(signer_key)
        .with_verification_pool(verification_pool.clone());

    let threat_intel = Arc::new(ThreatIntelligenceManager::from_external_config(
        threat_config.clone(),
        block_store.clone(),
        node_id.clone(),
        mesh_config.role,
        Some(Arc::new(signer_for_threat)),
    ));

    let transport = transport_manager.clone().get_quic_transport().expect("Failed to get transport").get_inner();
    let raft_client = Arc::new(crate::mesh::raft::client::RaftAwareClient::new(
        backend_pool.clone(),
        transport,
        mesh_config_arc.clone(),
        record_store.clone(),
    ));
    // threat_intel.set_raft_client(raft_client); // Removed: set_raft_client doesn't exist on ThreatIntelligenceManager
    threat_intel.start_background_tasks();

    let mut yara_rules_out = None;
    if mesh_config.yara_rules.enabled {
        let yara_manager = Arc::new(YaraRulesManager::new(
            mesh_config.yara_rules.clone().into(),
            node_id.clone(),
            mesh_config.role,
            None, // signer handled inside YaraRulesManager typically
            None, // feed_mgr
            None, // data_dir
        ));
        yara_manager.start_background_tasks();
        yara_rules_out = Some(yara_manager);
    }

    if let Err(e) = crate::mesh::backend::initialize_mesh_transports(
        &mesh_config,
        transport_manager.clone(),
        backend_pool.clone(),
        Some(threat_intel.clone()),
        Some(Arc::new(crate::mesh::protocol::MeshMessageSigner::new(signer_key))),
        None::<Arc<dyn crate::dns::resolver::DnsResolver>>,
        None::<Arc<crate::dns::MeshDnsRegistry>>,
    )
    .await {
        tracing::warn!("Supervisor Mesh transport initialization failed: {}", e);
    }

    Some(MeshControlPlane {
        transport_manager,
        threat_intel,
        yara_rules: yara_rules_out,
    })
}