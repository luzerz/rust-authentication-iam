/// Role entity: represents a role in the RBAC system.
#[derive(Clone)]
pub struct Role {
    pub id: String,
    pub name: String,
    pub permissions: Vec<String>,       // permission IDs
    pub parent_role_id: Option<String>, // for role inheritance
}

impl Role {
    /// Adds a permission to the role (if not already present).
    pub fn add_permission(&mut self, permission_id: String) {
        if !self.permissions.contains(&permission_id) {
            self.permissions.push(permission_id);
        }
    }

    /// Removes a permission from the role.
    pub fn remove_permission(&mut self, permission_id: &str) {
        self.permissions.retain(|p| p != permission_id);
    }

    /// Sets the parent role for inheritance.
    pub fn set_parent_role(&mut self, parent_role_id: Option<String>) {
        self.parent_role_id = parent_role_id;
    }

    /// Gets the parent role ID.
    pub fn get_parent_role_id(&self) -> Option<&String> {
        self.parent_role_id.as_ref()
    }

    /// Checks if this role has a parent role.
    pub fn has_parent(&self) -> bool {
        self.parent_role_id.is_some()
    }

    /// Checks if this role would create a circular reference with the given parent.
    /// This is a basic check - full cycle detection requires traversing the hierarchy.
    pub fn would_create_circle(&self, new_parent_id: &str) -> bool {
        self.id == new_parent_id
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_role() -> Role {
        Role {
            id: "role1".to_string(),
            name: "admin".to_string(),
            permissions: vec!["perm1".to_string()],
            parent_role_id: None,
        }
    }

    #[test]
    fn test_add_and_remove_permission() {
        let mut role = test_role();
        role.add_permission("perm2".to_string());
        assert!(role.permissions.contains(&"perm2".to_string()));
        role.remove_permission("perm1");
        assert!(!role.permissions.contains(&"perm1".to_string()));
    }

    #[test]
    fn test_parent_role_management() {
        let mut role = test_role();

        // Test setting parent role
        role.set_parent_role(Some("parent_role".to_string()));
        assert!(role.has_parent());
        assert_eq!(role.get_parent_role_id(), Some(&"parent_role".to_string()));

        // Test removing parent role
        role.set_parent_role(None);
        assert!(!role.has_parent());
        assert_eq!(role.get_parent_role_id(), None);
    }

    #[test]
    fn test_circular_reference_check() {
        let role = Role {
            id: "role1".to_string(),
            name: "admin".to_string(),
            permissions: vec![],
            parent_role_id: None,
        };

        assert!(role.would_create_circle("role1"));
        assert!(!role.would_create_circle("role2"));
    }
}
