/// Permission value object: represents a permission in the system.
#[derive(Clone, serde::Serialize, serde::Deserialize, sqlx::FromRow)]
pub struct Permission {
    pub id: String,
    pub name: String,
}

impl Permission {
    /// Creates a new Permission value object.
    pub fn new(id: String, name: String) -> Self {
        Self { id, name }
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
    }
}
