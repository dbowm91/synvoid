/// Validates that a peer claiming a global role actually has the correct global node key.
///
/// Returns `Ok(())` if the peer is not claiming global, or if their key matches.
/// Returns `Err(String)` with a descriptive message if verification fails.
///
/// # Arguments
/// * `role` - The role claimed by the peer
/// * `global_node_key` - The expected global node key (from local config)
/// * `peer_global_key` - The key provided by the peer
/// * `node_id` - The node ID of the peer (for error messages)
pub fn validate_peer_role(
    role: &crate::mesh::config::MeshNodeRole,
    global_node_key: Option<&str>,
    peer_global_key: Option<&str>,
    node_id: &str,
) -> Result<(), String> {
    if role.is_global() {
        let expected_key = global_node_key.ok_or_else(|| {
            format!(
                "Cannot verify global node {}: local node has no global_node_key configured",
                node_id
            )
        })?;
        if let Some(provided) = peer_global_key {
            if provided != expected_key {
                return Err(format!(
                    "Global node key verification failed for {}: key mismatch",
                    node_id
                ));
            }
        } else {
            return Err(format!(
                "Global node {} did not provide key verification",
                node_id
            ));
        }
    }
    Ok(())
}
