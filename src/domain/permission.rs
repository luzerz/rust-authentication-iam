/// Permission value object: represents a permission in the system.
#[derive(Clone, serde::Serialize, serde::Deserialize, sqlx::FromRow)]
pub struct Permission {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub group_id: Option<String>,    // Associated permission group
    pub metadata: serde_json::Value, // Additional metadata as JSON
    pub is_active: bool,
}

impl Permission {
    /// Creates a new Permission value object.
    pub fn new(id: String, name: String) -> Self {
        Self {
            id,
            name,
            description: None,
            group_id: None,
            metadata: serde_json::json!({}),
            is_active: true,
        }
    }

    /// Creates a new Permission with description.
    pub fn with_description(mut self, description: String) -> Self {
        self.description = Some(description);
        self
    }

    /// Creates a new Permission with group association.
    pub fn with_group(mut self, group_id: String) -> Self {
        self.group_id = Some(group_id);
        self
    }

    /// Creates a new Permission with metadata.
    pub fn with_metadata(mut self, metadata: serde_json::Value) -> Self {
        self.metadata = metadata;
        self
    }

    /// Sets the active status of the permission.
    pub fn set_active_status(&mut self, is_active: bool) {
        self.is_active = is_active;
    }

    /// Returns true if the permission is active.
    pub fn is_permission_active(&self) -> bool {
        self.is_active
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_permission_new() {
        let perm = Permission::new("perm1".to_string(), "read".to_string());
        assert_eq!(perm.id, "perm1");
        assert_eq!(perm.name, "read");
        assert!(perm.is_active);
        assert!(perm.description.is_none());
        assert!(perm.group_id.is_none());
    }

    #[test]
    fn test_permission_with_description() {
        let perm = Permission::new("perm1".to_string(), "read".to_string())
            .with_description("Read access permission".to_string());
        assert_eq!(perm.description, Some("Read access permission".to_string()));
    }

    #[test]
    fn test_permission_with_group() {
        let perm = Permission::new("perm1".to_string(), "read".to_string())
            .with_group("group1".to_string());
        assert_eq!(perm.group_id, Some("group1".to_string()));
    }

    #[test]
    fn test_permission_with_metadata() {
        let metadata = serde_json::json!({
            "version": "1.0",
            "deprecated": false
        });
        let perm = Permission::new("perm1".to_string(), "read".to_string())
            .with_metadata(metadata.clone());
        assert_eq!(perm.metadata, metadata);
    }

    #[test]
    fn test_permission_active_status() {
        let mut perm = Permission::new("perm1".to_string(), "read".to_string());
        assert!(perm.is_permission_active());

        perm.set_active_status(false);
        assert!(!perm.is_permission_active());

        perm.set_active_status(true);
        assert!(perm.is_permission_active());
    }
}
