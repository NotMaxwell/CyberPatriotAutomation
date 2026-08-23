use std::collections::HashMap;

/// Represents current system state information.
#[derive(Debug, Default, Clone)]
pub struct SystemInfo {
    pub os_version: Option<String>,
    pub running_services: Vec<String>,
    pub installed_applications: Vec<String>,
    pub user_accounts: Vec<String>,
    pub firewall_rules: Vec<String>,
    pub registry_settings: HashMap<String, String>,

    // Added for audit task output
    pub raw_output: Option<String>,
    pub error_output: Option<String>,
}

impl SystemInfo {
    pub fn new() -> Self {
        Self::default()
    }
}
