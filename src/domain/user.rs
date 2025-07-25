use bcrypt::{BcryptError, verify};

/// User aggregate: represents an authenticated user in the system.
#[derive(Clone, Debug)]
pub struct User {
    pub id: String,
    pub email: String,
    pub password_hash: String,
    pub roles: Vec<String>, // role IDs
    pub is_locked: bool,
}

impl User {
    /// Verifies a plaintext password against the stored hash.
    pub fn verify_password(&self, password: &str) -> Result<bool, BcryptError> {
        verify(password, &self.password_hash)
    }

    /// Returns true if the account is locked.
    pub fn is_account_locked(&self) -> bool {
        self.is_locked
    }

    /// Adds a role to the user (if not already present).
    pub fn add_role(&mut self, role_id: String) {
        if !self.roles.contains(&role_id) {
            self.roles.push(role_id);
        }
    }

    /// Removes a role from the user.
    pub fn remove_role(&mut self, role_id: &str) {
        self.roles.retain(|r| r != role_id);
    }

    /// Locks the user account.
    pub fn lock_account(&mut self) {
        self.is_locked = true;
    }

    /// Unlocks the user account.
    pub fn unlock_account(&mut self) {
        self.is_locked = false;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bcrypt::{DEFAULT_COST, hash};

    fn create_test_user() -> User {
        let password_hash = hash("password123", DEFAULT_COST).unwrap();
        User {
            id: "user1".to_string(),
            email: "test@example.com".to_string(),
            password_hash,
            roles: vec![],
            is_locked: false,
        }
    }

    #[test]
    fn test_user_creation() {
        let user = create_test_user();

        assert_eq!(user.id, "user1");
        assert_eq!(user.email, "test@example.com");
        assert!(!user.is_locked);
        assert!(user.roles.is_empty());
    }

    #[test]
    fn test_password_verification() {
        let user = create_test_user();

        assert!(user.verify_password("password123").unwrap());
        assert!(!user.verify_password("wrongpassword").unwrap());
    }

    #[test]
    fn test_account_locking() {
        let mut user = create_test_user();

        assert!(!user.is_account_locked());
        user.lock_account();
        assert!(user.is_account_locked());
        user.unlock_account();
        assert!(!user.is_account_locked());
    }

    #[test]
    fn test_add_role() {
        let mut user = create_test_user();

        user.add_role("admin".to_string());
        assert_eq!(user.roles.len(), 1);
        assert!(user.roles.contains(&"admin".to_string()));

        // Adding same role again should not duplicate
        user.add_role("admin".to_string());
        assert_eq!(user.roles.len(), 1);
    }

    #[test]
    fn test_remove_role() {
        let mut user = create_test_user();

        user.add_role("admin".to_string());
        user.add_role("user".to_string());
        assert_eq!(user.roles.len(), 2);

        user.remove_role("admin");
        assert_eq!(user.roles.len(), 1);
        assert!(!user.roles.contains(&"admin".to_string()));
        assert!(user.roles.contains(&"user".to_string()));
    }

    #[test]
    fn test_remove_nonexistent_role() {
        let mut user = create_test_user();

        user.add_role("admin".to_string());
        assert_eq!(user.roles.len(), 1);

        user.remove_role("nonexistent");
        assert_eq!(user.roles.len(), 1); // Should remain unchanged
    }

    #[test]
    fn test_multiple_roles() {
        let mut user = create_test_user();

        user.add_role("admin".to_string());
        user.add_role("user".to_string());
        user.add_role("moderator".to_string());

        assert_eq!(user.roles.len(), 3);
        assert!(user.roles.contains(&"admin".to_string()));
        assert!(user.roles.contains(&"user".to_string()));
        assert!(user.roles.contains(&"moderator".to_string()));
    }

    #[test]
    fn test_user_clone() {
        let user = create_test_user();
        let cloned_user = user.clone();

        assert_eq!(user.id, cloned_user.id);
        assert_eq!(user.email, cloned_user.email);
        assert_eq!(user.password_hash, cloned_user.password_hash);
        assert_eq!(user.roles, cloned_user.roles);
        assert_eq!(user.is_locked, cloned_user.is_locked);
    }

    #[test]
    fn test_user_debug() {
        let user = create_test_user();
        let debug_str = format!("{:?}", user);

        assert!(debug_str.contains("user1"));
        assert!(debug_str.contains("test@example.com"));
    }
}
