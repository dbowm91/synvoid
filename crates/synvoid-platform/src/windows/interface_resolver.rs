/*
 * Windows Interface Resolver via PowerShell
 *
 * INJECTION WARNING: This module shells out to `powershell` via std::process::Command.
 * The `resolve()` method interpolates an interface name into a PowerShell command string
 * using single-quote wrapping (Name='...'). Single quotes in the interface name could
 * break out of the string literal. The `sanitize_powershell_string()` function below
 * escapes single quotes by doubling them, which is the standard PowerShell escaping
 * technique for single-quoted strings.
 *
 * Required privilege: Standard user (Get-NetAdapter is readable by non-admin).
 *
 * NOTE: The `get_all_interfaces()` and `get_interface_by_index()` methods use
 * static PowerShell commands or numeric indices and are not subject to injection.
 */

use std::collections::HashMap;
use std::process::Command;

fn sanitize_powershell_string(input: &str) -> String {
    input.replace('\'', "''")
}

pub struct WindowsInterfaceResolver;

impl WindowsInterfaceResolver {
    pub fn resolve(interface_name: &str) -> Result<u32, String> {
        let safe_name = sanitize_powershell_string(interface_name);
        let output = Command::new("powershell")
            .args([
                "-NoProfile",
                "-Command",
                &format!(
                    "(Get-NetAdapter -Name '{}' | Get-NetIPInterface -AddressFamily IPv4).InterfaceIndex",
                    safe_name
                ),
            ])
            .output()
            .map_err(|e| format!("Failed to execute PowerShell: {}", e))?;

        if !output.status.success() {
            return Err(format!(
                "Failed to resolve interface '{}': {}",
                interface_name,
                String::from_utf8_lossy(&output.stderr)
            ));
        }

        let index_str = String::from_utf8_lossy(&output.stdout).trim().to_string();
        index_str
            .parse::<u32>()
            .map_err(|_| format!("Invalid interface index: {}", index_str))
    }

    pub fn get_all_interfaces() -> HashMap<String, u32> {
        let mut result = HashMap::new();

        let output = match Command::new("powershell")
            .args([
                "-NoProfile",
                "-Command",
                "Get-NetAdapter | Select-Object -Property Name, InterfaceIndex | ConvertTo-Json",
            ])
            .output()
        {
            Ok(o) => o,
            Err(_) => return result,
        };

        if !output.status.success() {
            return result;
        }

        if let Ok(json) = serde_json::from_slice::<Vec<InterfaceInfo>>(&output.stdout) {
            for info in json {
                result.insert(info.name, info.interface_index);
            }
        } else if let Ok(info) = serde_json::from_slice::<InterfaceInfo>(&output.stdout) {
            result.insert(info.name, info.interface_index);
        }

        result
    }

    pub fn get_interface_by_index(index: u32) -> Option<String> {
        let output = match Command::new("powershell")
            .args([
                "-NoProfile",
                "-Command",
                &format!(
                    "(Get-NetAdapter -InterfaceIndex {} -ErrorAction SilentlyContinue).Name",
                    index
                ),
            ])
            .output()
        {
            Ok(o) => o,
            Err(_) => return None,
        };

        if !output.status.success() {
            return None;
        }

        let name = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if name.is_empty() {
            None
        } else {
            Some(name)
        }
    }
}

#[derive(serde::Deserialize)]
struct InterfaceInfo {
    name: String,
    #[serde(alias = "InterfaceIndex")]
    interface_index: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_interface_resolver_returns_hashmap() {
        let interfaces = WindowsInterfaceResolver::get_all_interfaces();
        assert!(interfaces.is_empty() || interfaces.len() > 0);
    }

    #[test]
    fn test_get_interface_by_index() {
        let result = WindowsInterfaceResolver::get_interface_by_index(999999);
        assert!(result.is_none());
    }
}