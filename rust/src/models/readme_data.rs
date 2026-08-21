use std::collections::HashMap;

/// Represents parsed data from a CyberPatriot README file.
#[derive(Debug, Default, Clone)]
pub struct ReadmeData {
    pub title: String,
    pub operating_system: String,
    pub scenario: String,
    pub administrators: Vec<AuthorizedUser>,
    pub users: Vec<AuthorizedUser>,
    pub required_software: Vec<SoftwareRequirement>,
    pub prohibited_software: Vec<String>,
    pub critical_services: Vec<String>,
    pub prohibited_services: Vec<String>,
    pub group_requirements: Vec<GroupRequirement>,
    pub users_to_create: Vec<String>,
    pub guidelines: Vec<String>,
    pub actionable_items: Vec<ActionableItem>,
    /// Raw sections extracted from the README (header -> content). Case-insensitive lookup helper below.
    pub sections: HashMap<String, String>,
}

impl ReadmeData {
    /// Case-insensitive section lookup, mirroring the C# OrdinalIgnoreCase dictionary.
    pub fn section(&self, header: &str) -> Option<&String> {
        self.sections
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(header))
            .map(|(_, v)| v)
    }
}

/// Represents an actionable item extracted from the README.
#[derive(Debug, Default, Clone)]
pub struct ActionableItem {
    pub item_type: ActionableItemType,
    pub description: String,
    pub raw_text: String,
    pub details: HashMap<String, String>,
}

/// Types of actionable items that can be extracted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum ActionableItemType {
    CreateUser,
    CreateGroup,
    AddUserToGroup,
    RemoveUserFromGroup,
    EnableService,
    DisableService,
    InstallSoftware,
    RemoveSoftware,
    ConfigureSetting,
    SecurityPolicy,
    FileOperation,
    #[default]
    Other,
}

/// Represents an authorized user from the README.
#[derive(Debug, Default, Clone)]
pub struct AuthorizedUser {
    pub username: String,
    pub password: Option<String>,
    pub is_admin: bool,
    pub is_primary_user: bool,
    pub notes: Option<String>,
}

/// Represents a software requirement from the README.
#[derive(Debug, Clone)]
pub struct SoftwareRequirement {
    pub name: String,
    pub version: Option<String>,
    pub should_be_latest: bool,
    pub is_required: bool,
    pub notes: Option<String>,
}

impl Default for SoftwareRequirement {
    fn default() -> Self {
        Self {
            name: String::new(),
            version: None,
            should_be_latest: false,
            is_required: true,
            notes: None,
        }
    }
}

/// Represents a group that needs to be created.
#[derive(Debug, Default, Clone)]
pub struct GroupRequirement {
    pub group_name: String,
    pub members: Vec<String>,
}
