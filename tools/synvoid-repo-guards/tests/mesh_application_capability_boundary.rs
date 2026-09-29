use std::fs;
use synvoid_repo_guards::workspace_root;

#[test]
fn mesh_transport_application_services_are_grouped() {
    let root = workspace_root();
    let transport = fs::read_to_string(root.join("crates/synvoid-mesh/src/mesh/transport.rs"))
        .expect("read mesh transport");
    let transport_connection =
        fs::read_to_string(root.join("crates/synvoid-mesh/src/mesh/transport_connection.rs"))
            .expect("read transport connection");
    let transport_peer =
        fs::read_to_string(root.join("crates/synvoid-mesh/src/mesh/transport_peer.rs"))
            .expect("read transport peer");
    let worker_integration =
        fs::read_to_string(root.join("crates/synvoid-mesh/src/mesh/worker_integration.rs"))
            .expect("read mesh worker integration");
    let transport_routing =
        fs::read_to_string(root.join("crates/synvoid-mesh/src/mesh/transport_routing.rs"))
            .expect("read transport routing");

    assert!(transport.contains("pub(crate) application: MeshApplicationCapabilities"));
    assert!(transport.contains("pub(crate) struct MeshApplicationCapabilities"));
    assert!(transport.contains("pub(crate) lifecycle: MeshTransportLifecycle"));
    assert!(transport.contains("pub(crate) struct MeshTransportLifecycle"));
    let transport_struct = transport
        .split("pub struct MeshTransport {")
        .nth(1)
        .expect("MeshTransport declaration")
        .split("\n}")
        .next()
        .expect("MeshTransport struct body");
    let capability_struct = transport
        .split("pub(crate) struct MeshApplicationCapabilities {")
        .nth(1)
        .expect("MeshApplicationCapabilities declaration")
        .split("\n}")
        .next()
        .expect("application capability struct body");
    for field in [
        "threat_intel",
        "yara_rules",
        "backend_pool",
        "serverless_manager",
    ] {
        assert!(
            !transport_struct.contains(&format!("{field}:")),
            "application capability {field} must not be declared directly on MeshTransport"
        );
        assert!(capability_struct.contains(&format!("pub(crate) {field}:")));
        for source in [&transport_connection, &transport_peer] {
            assert!(
                !source.contains(&format!("self.{field}.")),
                "extension modules must access {field} through the named application capability"
            );
        }
    }
    let lifecycle_struct = transport
        .split("pub(crate) struct MeshTransportLifecycle {")
        .nth(1)
        .expect("MeshTransportLifecycle declaration")
        .split("\n}")
        .next()
        .expect("lifecycle struct body");
    for field in [
        "task_group",
        "lifecycle_state",
        "shutdown_started",
        "peer_sessions",
        "startup_generation",
        "session_generation",
        "auxiliary_tasks",
        "accept_loop_report",
    ] {
        assert!(lifecycle_struct.contains(&format!("{field}:")));
        assert!(!transport_struct.contains(&format!("{field}:")));
        for source in [&transport_connection, &transport_peer, &worker_integration] {
            assert!(
                !source.contains(&format!("self.{field}.")),
                "transport extensions must access {field} through the lifecycle capability"
            );
        }
    }
    assert!(transport.contains("pub(crate) pending: MeshPendingRequests"));
    let pending_struct = transport
        .split("pub(crate) struct MeshPendingRequests {")
        .nth(1)
        .expect("MeshPendingRequests declaration")
        .split("\n}")
        .next()
        .expect("pending request struct body");
    for field in [
        "query_dedup",
        "pending_queries",
        "pending_dht_queries",
        "pending_serverless_invocations",
        "pending_consistent_read_responses",
        "pending_snapshot_responses",
        "pending_snapshot_transfers",
    ] {
        assert!(pending_struct.contains(&format!("{field}:")));
        assert!(!transport_struct.contains(&format!("{field}:")));
        for source in [&transport_connection, &transport_peer, &transport_routing] {
            assert!(!source.contains(&format!("self.{field}.")));
        }
    }
}
