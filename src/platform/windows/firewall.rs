use std::process::Command;

pub fn inject_quic_firewall_rule(port: u16) -> Result<(), String> {
    let rule_name = format!("MaluWAF HTTP/3 QUIC Port {}", port);

    if let Ok(exists) = check_rule_exists(&rule_name) {
        if exists {
            tracing::debug!("Firewall rule '{}' already exists", rule_name);
            return Ok(());
        }
    }

    let output = Command::new("netsh")
        .args([
            "advfirewall",
            "firewall",
            "add",
            "rule",
            &format!("name={}", rule_name),
            "dir=in",
            "action=allow",
            "protocol=UDP",
            &format!("localport={}", port),
            "profile=any",
        ])
        .output()
        .map_err(|e| format!("Failed to execute netsh: {}", e))?;

    if !output.status.success() {
        return Err(format!(
            "Failed to add firewall rule: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    tracing::info!("Added firewall rule '{}' for UDP port {}", rule_name, port);
    Ok(())
}

pub fn remove_quic_firewall_rule(port: u16) -> Result<(), String> {
    let rule_name = format!("MaluWAF HTTP/3 QUIC Port {}", port);

    let output = Command::new("netsh")
        .args(["advfirewall", "firewall", "delete", "rule", &format!("name={}", rule_name)])
        .output()
        .map_err(|e| format!("Failed to execute netsh: {}", e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        if !stderr.contains("no firewall rule") && !stderr.contains("cannot find") {
            return Err(format!("Failed to remove firewall rule: {}", stderr));
        }
    }

    tracing::info!("Removed firewall rule '{}'", rule_name);
    Ok(())
}

fn check_rule_exists(rule_name: &str) -> Result<bool, String> {
    let output = Command::new("netsh")
        .args(["advfirewall", "firewall", "show", "rule", &format!("name={}", rule_name)])
        .output()
        .map_err(|e| format!("Failed to execute netsh: {}", e))?;

    Ok(output.status.success())
}

pub fn inject_http_firewall_rule(port: u16) -> Result<(), String> {
    let rule_name = format!("MaluWAF HTTP Port {}", port);

    if let Ok(exists) = check_rule_exists(&rule_name) {
        if exists {
            tracing::debug!("Firewall rule '{}' already exists", rule_name);
            return Ok(());
        }
    }

    let output = Command::new("netsh")
        .args([
            "advfirewall",
            "firewall",
            "add",
            "rule",
            &format!("name={}", rule_name),
            "dir=in",
            "action=allow",
            "protocol=TCP",
            &format!("localport={}", port),
            "profile=any",
        ])
        .output()
        .map_err(|e| format!("Failed to execute netsh: {}", e))?;

    if !output.status.success() {
        return Err(format!(
            "Failed to add HTTP firewall rule: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    tracing::info!("Added HTTP firewall rule '{}' for TCP port {}", rule_name, port);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_check_nonexistent_rule() {
        let result = check_rule_exists("NonExistentRule12345");
        assert!(result.is_ok());
        assert!(!result.unwrap());
    }

    #[test]
    fn test_remove_nonexistent_rule() {
        let result = remove_quic_firewall_rule(99999);
        assert!(result.is_ok());
    }
}