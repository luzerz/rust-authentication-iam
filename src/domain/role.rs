/// Role entity: represents a role in the RBAC system.
#[derive(Clone)]
pub struct Role {
    pub id: String,
    pub name: String,
    pub permissions: Vec<String>, // permission IDs
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
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_role() -> Role {
        Role {
            id: "role1".to_string(),
            name: "admin".to_string(),
            permissions: vec!["perm1".to_string()],
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
}
