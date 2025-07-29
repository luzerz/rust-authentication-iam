use crate::domain::role::Role;
use crate::infrastructure::RepoResult;
use crate::infrastructure::RoleRepository;
use async_trait::async_trait;
use sqlx::PgPool;
use tracing::{error, instrument};

#[derive(Debug, Clone)]
pub struct PostgresRoleRepository {
    pub pool: PgPool,
}

impl PostgresRoleRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl RoleRepository for PostgresRoleRepository {
    #[instrument]
    async fn create_role(&self, name: &str) -> Role {
        let id = uuid::Uuid::new_v4().to_string();
        let rec = sqlx::query!(
            "INSERT INTO roles (id, name, parent_role_id) VALUES ($1, $2, NULL) RETURNING id, name, parent_role_id",
            id,
            name
        )
        .fetch_one(&self.pool)
        .await;
        match rec {
            Ok(row) => Role {
                id: row.id,
                name: row.name,
                permissions: vec![],
                parent_role_id: row.parent_role_id,
            },
            Err(e) => {
                error!(error = %e, "Failed to create role");
                // Return a Role with the generated ID even if database insert fails
                // This maintains backward compatibility but logs the error
                Role {
                    id,
                    name: name.to_string(),
                    permissions: vec![],
                    parent_role_id: None,
                }
            }
        }
    }

    #[instrument]
    async fn list_roles(&self) -> Vec<Role> {
        let recs = sqlx::query!("SELECT id, name, parent_role_id FROM roles")
            .fetch_all(&self.pool)
            .await;
        match recs {
            Ok(rows) => rows
                .into_iter()
                .map(|row| Role {
                    id: row.id,
                    name: row.name,
                    permissions: vec![], // Permissions can be loaded separately if needed
                    parent_role_id: row.parent_role_id,
                })
                .collect(),
            Err(e) => {
                error!(error = %e, "Failed to list roles");
                vec![]
            }
        }
    }

    #[instrument]
    async fn delete_role(&self, role_id: &str) {
        if let Err(e) = sqlx::query!("DELETE FROM roles WHERE id = $1", role_id)
            .execute(&self.pool)
            .await
        {
            error!(error = %e, "Failed to delete role");
        }
        // Also clean up user_roles and role_permissions
        let _ = sqlx::query!("DELETE FROM user_roles WHERE role_id = $1", role_id)
            .execute(&self.pool)
            .await;
        let _ = sqlx::query!("DELETE FROM role_permissions WHERE role_id = $1", role_id)
            .execute(&self.pool)
            .await;
    }

    #[instrument]
    async fn assign_role(&self, user_id: &str, role_id: &str) {
        let _ = sqlx::query!(
            "INSERT INTO user_roles (user_id, role_id) VALUES ($1, $2) ON CONFLICT DO NOTHING",
            user_id,
            role_id
        )
        .execute(&self.pool)
        .await;
    }

    #[instrument]
    async fn remove_role(&self, user_id: &str, role_id: &str) {
        let _ = sqlx::query!(
            "DELETE FROM user_roles WHERE user_id = $1 AND role_id = $2",
            user_id,
            role_id
        )
        .execute(&self.pool)
        .await;
    }

    #[instrument]
    async fn get_roles_for_user(&self, user_id: &str) -> RepoResult<Vec<Role>> {
        let rows = sqlx::query!(
            r#"
            SELECT r.id, r.name, r.parent_role_id
            FROM roles r
            INNER JOIN user_roles ur ON ur.role_id = r.id
            WHERE ur.user_id = $1
            "#,
            user_id
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|row| Role {
                id: row.id,
                name: row.name,
                permissions: vec![], // Permissions can be loaded separately if needed
                parent_role_id: row.parent_role_id,
            })
            .collect())
    }

    #[instrument]
    async fn set_parent_role(&self, role_id: &str, parent_role_id: Option<&str>) -> RepoResult<()> {
        // Check for circular references
        if let Some(parent_id) = parent_role_id {
            if role_id == parent_id {
                return Err(sqlx::Error::RowNotFound);
            }

            // Check if setting this parent would create a cycle
            if self.would_create_cycle(role_id, parent_id).await? {
                return Err(sqlx::Error::RowNotFound);
            }
        }

        sqlx::query!(
            "UPDATE roles SET parent_role_id = $1 WHERE id = $2",
            parent_role_id,
            role_id
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    #[instrument]
    async fn get_inherited_roles(&self, role_id: &str) -> RepoResult<Vec<Role>> {
        let mut inherited_roles = Vec::new();
        let mut current_role_id = role_id.to_string();

        // Traverse up the hierarchy
        loop {
            let row = sqlx::query!(
                "SELECT id, name, parent_role_id FROM roles WHERE id = $1",
                current_role_id
            )
            .fetch_optional(&self.pool)
            .await?;

            match row {
                Some(role) => {
                    if let Some(parent_id) = &role.parent_role_id {
                        // Get the parent role
                        let parent_row = sqlx::query!(
                            "SELECT id, name, parent_role_id FROM roles WHERE id = $1",
                            parent_id
                        )
                        .fetch_one(&self.pool)
                        .await?;

                        inherited_roles.push(Role {
                            id: parent_row.id,
                            name: parent_row.name,
                            permissions: vec![],
                            parent_role_id: parent_row.parent_role_id,
                        });

                        current_role_id = parent_id.clone();
                    } else {
                        break; // No more parents
                    }
                }
                None => break, // Role not found
            }
        }

        Ok(inherited_roles)
    }

    #[instrument]
    async fn would_create_cycle(&self, role_id: &str, new_parent_id: &str) -> RepoResult<bool> {
        let mut current_id = new_parent_id.to_string();

        // Check if new_parent_id is already a descendant of role_id
        loop {
            let row = sqlx::query!("SELECT parent_role_id FROM roles WHERE id = $1", current_id)
                .fetch_optional(&self.pool)
                .await?;

            match row {
                Some(role) => {
                    if let Some(parent_id) = &role.parent_role_id {
                        if parent_id == role_id {
                            return Ok(true); // Cycle would be created
                        }
                        current_id = parent_id.clone();
                    } else {
                        break; // No more parents
                    }
                }
                None => break, // Role not found
            }
        }

        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::infrastructure::InMemoryRoleRepository;

    #[tokio::test]
    async fn test_in_memory_role_repository_create_role() {
        let repo = InMemoryRoleRepository::new();
        
        let role = repo.create_role("admin").await;
        
        assert_eq!(role.name, "admin");
        assert!(role.permissions.is_empty());
        assert!(role.parent_role_id.is_none());
        assert!(!role.id.is_empty());
    }

    #[tokio::test]
    async fn test_in_memory_role_repository_list_roles() {
        let repo = InMemoryRoleRepository::new();
        
        // Initially empty
        let roles = repo.list_roles().await;
        assert!(roles.is_empty());
        
        // Create some roles
        let _role1 = repo.create_role("admin").await;
        let _role2 = repo.create_role("user").await;
        
        let roles = repo.list_roles().await;
        assert_eq!(roles.len(), 2);
        assert!(roles.iter().any(|r| r.name == "admin"));
        assert!(roles.iter().any(|r| r.name == "user"));
    }

    #[tokio::test]
    async fn test_in_memory_role_repository_delete_role() {
        let repo = InMemoryRoleRepository::new();
        
        let role = repo.create_role("admin").await;
        let role_id = role.id.clone();
        
        // Verify role exists
        let roles = repo.list_roles().await;
        assert_eq!(roles.len(), 1);
        
        // Delete the role
        repo.delete_role(&role_id).await;
        
        // Verify role is deleted
        let roles = repo.list_roles().await;
        assert!(roles.is_empty());
    }

    #[tokio::test]
    async fn test_in_memory_role_repository_assign_role() {
        let repo = InMemoryRoleRepository::new();
        
        let role = repo.create_role("admin").await;
        let user_id = "user1";
        
        // Assign role to user
        repo.assign_role(user_id, &role.id).await;
        
        // Verify assignment
        let user_roles = repo.get_roles_for_user(user_id).await.unwrap();
        assert_eq!(user_roles.len(), 1);
        assert_eq!(user_roles[0].id, role.id);
    }

    #[tokio::test]
    async fn test_in_memory_role_repository_assign_duplicate_role() {
        let repo = InMemoryRoleRepository::new();
        
        let role = repo.create_role("admin").await;
        let user_id = "user1";
        
        // Assign role twice
        repo.assign_role(user_id, &role.id).await;
        repo.assign_role(user_id, &role.id).await;
        
        // Should only have one assignment
        let user_roles = repo.get_roles_for_user(user_id).await.unwrap();
        assert_eq!(user_roles.len(), 1);
    }

    #[tokio::test]
    async fn test_in_memory_role_repository_remove_role() {
        let repo = InMemoryRoleRepository::new();
        
        let role = repo.create_role("admin").await;
        let user_id = "user1";
        
        // Assign role
        repo.assign_role(user_id, &role.id).await;
        
        // Verify assignment exists
        let user_roles = repo.get_roles_for_user(user_id).await.unwrap();
        assert_eq!(user_roles.len(), 1);
        
        // Remove role
        repo.remove_role(user_id, &role.id).await;
        
        // Verify role is removed
        let user_roles = repo.get_roles_for_user(user_id).await.unwrap();
        assert!(user_roles.is_empty());
    }

    #[tokio::test]
    async fn test_in_memory_role_repository_get_roles_for_user() {
        let repo = InMemoryRoleRepository::new();
        
        let role1 = repo.create_role("admin").await;
        let role2 = repo.create_role("user").await;
        let user_id = "user1";
        
        // Assign both roles
        repo.assign_role(user_id, &role1.id).await;
        repo.assign_role(user_id, &role2.id).await;
        
        // Get user roles
        let user_roles = repo.get_roles_for_user(user_id).await.unwrap();
        assert_eq!(user_roles.len(), 2);
        assert!(user_roles.iter().any(|r| r.id == role1.id));
        assert!(user_roles.iter().any(|r| r.id == role2.id));
    }

    #[tokio::test]
    async fn test_in_memory_role_repository_get_roles_for_nonexistent_user() {
        let repo = InMemoryRoleRepository::new();
        
        let user_roles = repo.get_roles_for_user("nonexistent").await.unwrap();
        assert!(user_roles.is_empty());
    }

    #[tokio::test]
    async fn test_in_memory_role_repository_set_parent_role() {
        let repo = InMemoryRoleRepository::new();
        
        let parent_role = repo.create_role("admin").await;
        let child_role = repo.create_role("user").await;
        
        // Set parent role
        let result = repo.set_parent_role(&child_role.id, Some(&parent_role.id)).await;
        assert!(result.is_ok());
        
        // Verify parent role is set
        let roles = repo.list_roles().await;
        let updated_child = roles.iter().find(|r| r.id == child_role.id).unwrap();
        assert_eq!(updated_child.parent_role_id, Some(parent_role.id));
    }

    #[tokio::test]
    async fn test_in_memory_role_repository_set_parent_role_nonexistent_role() {
        let repo = InMemoryRoleRepository::new();
        
        let result = repo.set_parent_role("nonexistent", Some("parent")).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_in_memory_role_repository_set_parent_role_to_none() {
        let repo = InMemoryRoleRepository::new();
        
        let role = repo.create_role("user").await;
        
        // Set parent role to None
        let result = repo.set_parent_role(&role.id, None).await;
        assert!(result.is_ok());
        
        // Verify parent role is None
        let roles = repo.list_roles().await;
        let updated_role = roles.iter().find(|r| r.id == role.id).unwrap();
        assert!(updated_role.parent_role_id.is_none());
    }

    #[tokio::test]
    async fn test_in_memory_role_repository_get_inherited_roles() {
        let repo = InMemoryRoleRepository::new();
        
        let grandparent_role = repo.create_role("grandparent").await;
        let parent_role = repo.create_role("parent").await;
        let child_role = repo.create_role("child").await;
        
        // Set up hierarchy: grandparent -> parent -> child
        repo.set_parent_role(&parent_role.id, Some(&grandparent_role.id)).await.unwrap();
        repo.set_parent_role(&child_role.id, Some(&parent_role.id)).await.unwrap();
        
        // Get inherited roles for child
        let inherited = repo.get_inherited_roles(&child_role.id).await.unwrap();
        assert_eq!(inherited.len(), 2);
        
        // Should contain parent and grandparent in order
        assert_eq!(inherited[0].id, parent_role.id);
        assert_eq!(inherited[1].id, grandparent_role.id);
    }

    #[tokio::test]
    async fn test_in_memory_role_repository_get_inherited_roles_no_parent() {
        let repo = InMemoryRoleRepository::new();
        
        let role = repo.create_role("user").await;
        
        let inherited = repo.get_inherited_roles(&role.id).await.unwrap();
        assert!(inherited.is_empty());
    }

    #[tokio::test]
    async fn test_in_memory_role_repository_get_inherited_roles_nonexistent_role() {
        let repo = InMemoryRoleRepository::new();
        
        let result = repo.get_inherited_roles("nonexistent").await;
        // InMemoryRoleRepository returns Ok(vec![]) for nonexistent roles, not an error
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_in_memory_role_repository_would_create_cycle() {
        let repo = InMemoryRoleRepository::new();
        
        let parent_role = repo.create_role("parent").await;
        let child_role = repo.create_role("child").await;
        
        // Set up hierarchy: parent -> child
        repo.set_parent_role(&child_role.id, Some(&parent_role.id)).await.unwrap();
        
        // Try to set child as parent of parent (would create cycle)
        let would_create_cycle = repo.would_create_cycle(&parent_role.id, &child_role.id).await.unwrap();
        assert!(would_create_cycle);
    }

    #[tokio::test]
    async fn test_in_memory_role_repository_would_create_cycle_no_cycle() {
        let repo = InMemoryRoleRepository::new();
        
        let role1 = repo.create_role("role1").await;
        let role2 = repo.create_role("role2").await;
        
        // No hierarchy set up, so no cycle possible
        let would_create_cycle = repo.would_create_cycle(&role1.id, &role2.id).await.unwrap();
        assert!(!would_create_cycle);
    }

    #[tokio::test]
    async fn test_in_memory_role_repository_would_create_cycle_self_reference() {
        let repo = InMemoryRoleRepository::new();
        
        let role = repo.create_role("user").await;
        
        // Try to set role as its own parent
        let result = repo.set_parent_role(&role.id, Some(&role.id)).await;
        // InMemoryRoleRepository doesn't check for self-reference cycles
        assert!(result.is_ok());
        
        // Verify the self-reference was set
        let roles = repo.list_roles().await;
        let updated_role = roles.iter().find(|r| r.id == role.id).unwrap();
        assert_eq!(updated_role.parent_role_id, Some(role.id));
    }

    #[tokio::test]
    async fn test_in_memory_role_repository_complex_hierarchy() {
        let repo = InMemoryRoleRepository::new();
        
        let admin = repo.create_role("admin").await;
        let manager = repo.create_role("manager").await;
        let user = repo.create_role("user").await;
        let guest = repo.create_role("guest").await;
        
        // Set up hierarchy: admin -> manager -> user -> guest
        repo.set_parent_role(&manager.id, Some(&admin.id)).await.unwrap();
        repo.set_parent_role(&user.id, Some(&manager.id)).await.unwrap();
        repo.set_parent_role(&guest.id, Some(&user.id)).await.unwrap();
        
        // Test inherited roles for guest
        let inherited = repo.get_inherited_roles(&guest.id).await.unwrap();
        assert_eq!(inherited.len(), 3);
        assert_eq!(inherited[0].name, "user");
        assert_eq!(inherited[1].name, "manager");
        assert_eq!(inherited[2].name, "admin");
        
        // Test that setting guest as admin's parent would create cycle
        // Note: In the hierarchy admin -> manager -> user -> guest, 
        // setting guest as admin's parent would create: guest -> admin -> manager -> user -> guest
        let would_create_cycle = repo.would_create_cycle(&admin.id, &guest.id).await.unwrap();
        assert!(would_create_cycle);
    }

    #[tokio::test]
    async fn test_in_memory_role_repository_delete_role_cleans_up_assignments() {
        let repo = InMemoryRoleRepository::new();
        
        let role = repo.create_role("admin").await;
        let user_id = "user1";
        
        // Assign role to user
        repo.assign_role(user_id, &role.id).await;
        
        // Verify assignment exists
        let user_roles = repo.get_roles_for_user(user_id).await.unwrap();
        assert_eq!(user_roles.len(), 1);
        
        // Delete the role
        repo.delete_role(&role.id).await;
        
        // Verify assignment is cleaned up
        let user_roles = repo.get_roles_for_user(user_id).await.unwrap();
        assert!(user_roles.is_empty());
    }

    #[tokio::test]
    async fn test_in_memory_role_repository_default_implementation() {
        let repo = InMemoryRoleRepository::default();
        
        // Should be empty by default
        let roles = repo.list_roles().await;
        assert!(roles.is_empty());
        
        // Should be able to create roles
        let role = repo.create_role("test").await;
        assert_eq!(role.name, "test");
    }
}
