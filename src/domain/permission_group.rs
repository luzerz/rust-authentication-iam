use serde::{Deserialize, Serialize};

/// PermissionGroup aggregate: represents a group of related permissions.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PermissionGroup {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub category: Option<String>, // e.g., "user_management", "system_admin", "data_access"
    pub metadata: serde_json::Value, // Additional metadata as JSON
    pub is_active: bool,
}

impl PermissionGroup {
    /// Creates a new PermissionGroup.
    pub fn new(id: String, name: String) -> Self {
        Self {
            id,
            name,
            description: None,
            category: None,
            metadata: serde_json::json!({}),
            is_active: true,
        }
    }

    /// Creates a new PermissionGroup with description.
    pub fn with_description(mut self, description: String) -> Self {
        self.description = Some(description);
        self
    }

    /// Creates a new PermissionGroup with category.
    pub fn with_category(mut self, category: String) -> Self {
        self.category = Some(category);
        self
    }

    /// Creates a new PermissionGroup with metadata.
    pub fn with_metadata(mut self, metadata: serde_json::Value) -> Self {
        self.metadata = metadata;
        self
    }

    /// Sets the active status of the permission group.
    pub fn set_active_status(&mut self, is_active: bool) {
        self.is_active = is_active;
    }

    /// Returns true if the permission group is active.
    pub fn is_group_active(&self) -> bool {
        self.is_active
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_permission_group_creation() {
        let group = PermissionGroup::new("group1".to_string(), "User Management".to_string());
        assert_eq!(group.id, "group1");
        assert_eq!(group.name, "User Management");
        assert!(group.is_active);
        assert!(group.description.is_none());
        assert!(group.category.is_none());
    }

    #[test]
    fn test_permission_group_with_description() {
        let group = PermissionGroup::new("group1".to_string(), "User Management".to_string())
            .with_description("Permissions for managing users".to_string());

        assert_eq!(
            group.description,
            Some("Permissions for managing users".to_string())
        );
    }

    #[test]
    fn test_permission_group_with_category() {
        let group = PermissionGroup::new("group1".to_string(), "User Management".to_string())
            .with_category("user_management".to_string());

        assert_eq!(group.category, Some("user_management".to_string()));
    }

    #[test]
    fn test_permission_group_with_metadata() {
        let metadata = serde_json::json!({
            "version": "1.0",
            "deprecated": false,
            "tags": ["admin", "user"]
        });

        let group = PermissionGroup::new("group1".to_string(), "User Management".to_string())
            .with_metadata(metadata.clone());

        assert_eq!(group.metadata, metadata);
    }

    #[test]
    fn test_permission_group_active_status() {
        let mut group = PermissionGroup::new("group1".to_string(), "User Management".to_string());

        assert!(group.is_group_active());

        group.set_active_status(false);
        assert!(!group.is_group_active());

        group.set_active_status(true);
        assert!(group.is_group_active());
    }
}
