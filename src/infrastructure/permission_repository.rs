use crate::domain::permission::Permission;
use crate::infrastructure::PermissionRepository;
use async_trait::async_trait;
use sqlx::PgPool;
use tracing::{error, instrument};

pub type RepoResult<T> = Result<T, sqlx::Error>;

#[derive(Debug)]
pub struct PostgresPermissionRepository {
    pub pool: PgPool,
}

impl PostgresPermissionRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl PermissionRepository for PostgresPermissionRepository {
    #[instrument]
    async fn create_permission(&self, name: &str) -> RepoResult<Permission> {
        let id = uuid::Uuid::new_v4().to_string();
        let rec = sqlx::query_as::<_, Permission>(
            "INSERT INTO permissions (id, name, description, group_id, metadata, is_active) VALUES ($1, $2, $3, $4, $5, $6) RETURNING id, name, description, group_id, metadata, is_active",
        )
        .bind(&id)
        .bind(name)
        .bind::<Option<String>>(None) // description
        .bind::<Option<String>>(None) // group_id
        .bind(serde_json::json!({})) // metadata
        .bind(true) // is_active
        .fetch_one(&self.pool)
        .await;
        if let Err(ref e) = rec {
            error!(error = %e, "Failed to create permission");
        }
        rec
    }
    #[instrument]
    async fn get_permission(&self, permission_id: &str) -> RepoResult<Option<Permission>> {
        let res = sqlx::query_as::<_, Permission>("SELECT id, name, description, group_id, metadata, is_active FROM permissions WHERE id = $1")
            .bind(permission_id)
            .fetch_optional(&self.pool)
            .await;
        if let Err(ref e) = res {
            error!(error = %e, "Failed to get permission");
        }
        res
    }
    #[instrument]
    async fn list_permissions(&self) -> RepoResult<Vec<Permission>> {
        let res = sqlx::query_as::<_, Permission>("SELECT id, name, description, group_id, metadata, is_active FROM permissions ORDER BY name")
            .fetch_all(&self.pool)
            .await;
        if let Err(ref e) = res {
            error!(error = %e, "Failed to list permissions");
        }
        res
    }
    #[instrument]
    async fn delete_permission(&self, permission_id: &str) -> RepoResult<()> {
        sqlx::query("DELETE FROM permissions WHERE id = $1")
            .bind(permission_id)
            .execute(&self.pool)
            .await
            .map_err(|e| {
                error!(error = %e, "Failed to delete permission");
                e
            })?;
        sqlx::query("DELETE FROM role_permissions WHERE permission_id = $1")
            .bind(permission_id)
            .execute(&self.pool)
            .await
            .map_err(|e| {
                error!(error = %e, "Failed to delete from role_permissions");
                e
            })?;
        Ok(())
    }
    #[instrument]
    async fn assign_permission(&self, role_id: &str, permission_id: &str) -> RepoResult<()> {
        sqlx::query("INSERT INTO role_permissions (role_id, permission_id) VALUES ($1, $2) ON CONFLICT DO NOTHING")
            .bind(role_id)
            .bind(permission_id)
            .execute(&self.pool)
            .await
            .map_err(|e| {
                error!(error = %e, "Failed to assign permission");
                e
            })?;
        Ok(())
    }
    #[instrument]
    async fn remove_permission(&self, role_id: &str, permission_id: &str) -> RepoResult<()> {
        sqlx::query("DELETE FROM role_permissions WHERE role_id = $1 AND permission_id = $2")
            .bind(role_id)
            .bind(permission_id)
            .execute(&self.pool)
            .await
            .map_err(|e| {
                error!(error = %e, "Failed to remove permission");
                e
            })?;
        Ok(())
    }
    #[instrument]
    async fn role_has_permission(&self, role_id: &str, permission_id: &str) -> RepoResult<bool> {
        let found: Option<i32> = sqlx::query_scalar(
            "SELECT 1 FROM role_permissions WHERE role_id = $1 AND permission_id = $2",
        )
        .bind(role_id)
        .bind(permission_id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(found.is_some())
    }
    #[instrument]
    async fn get_permissions_for_role(&self, role_id: &str) -> RepoResult<Vec<Permission>> {
        let rows = sqlx::query_as::<_, Permission>(
            r#"
            SELECT p.id, p.name, p.description, p.group_id, p.metadata, p.is_active
            FROM permissions p
            INNER JOIN role_permissions rp ON rp.permission_id = p.id
            WHERE rp.role_id = $1
            ORDER BY p.name
            "#,
        )
        .bind(role_id)
        .fetch_all(&self.pool)
        .await;
        if let Err(ref e) = rows {
            error!(error = %e, "Failed to get permissions for role");
        }
        rows
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::infrastructure::InMemoryPermissionRepository;



    #[tokio::test]
    async fn test_in_memory_permission_repository_create_permission() {
        let repo = InMemoryPermissionRepository::new();
        
        let permission = repo.create_permission("test_permission").await.unwrap();
        
        assert_eq!(permission.name, "test_permission");
        assert!(permission.is_active);
        assert!(permission.description.is_none());
        assert!(permission.group_id.is_none());
    }

    #[tokio::test]
    async fn test_in_memory_permission_repository_get_permission() {
        let repo = InMemoryPermissionRepository::new();
        
        let created = repo.create_permission("test_permission").await.unwrap();
        let retrieved = repo.get_permission(&created.id).await.unwrap();
        
        assert!(retrieved.is_some());
        let retrieved = retrieved.unwrap();
        assert_eq!(retrieved.id, created.id);
        assert_eq!(retrieved.name, "test_permission");
    }

    #[tokio::test]
    async fn test_in_memory_permission_repository_get_permission_not_found() {
        let repo = InMemoryPermissionRepository::new();
        
        let result = repo.get_permission("non_existent_id").await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_in_memory_permission_repository_list_permissions() {
        let repo = InMemoryPermissionRepository::new();
        
        repo.create_permission("permission1").await.unwrap();
        repo.create_permission("permission2").await.unwrap();
        repo.create_permission("permission3").await.unwrap();
        
        let permissions = repo.list_permissions().await.unwrap();
        assert_eq!(permissions.len(), 3);
        
        let names: Vec<&str> = permissions.iter().map(|p| p.name.as_str()).collect();
        assert!(names.contains(&"permission1"));
        assert!(names.contains(&"permission2"));
        assert!(names.contains(&"permission3"));
    }

    #[tokio::test]
    async fn test_in_memory_permission_repository_delete_permission() {
        let repo = InMemoryPermissionRepository::new();
        
        let permission = repo.create_permission("test_permission").await.unwrap();
        
        // Verify it exists
        let retrieved = repo.get_permission(&permission.id).await.unwrap();
        assert!(retrieved.is_some());
        
        // Delete it
        repo.delete_permission(&permission.id).await.unwrap();
        
        // Verify it's gone
        let retrieved = repo.get_permission(&permission.id).await.unwrap();
        assert!(retrieved.is_none());
    }

    #[tokio::test]
    async fn test_in_memory_permission_repository_assign_and_remove_permission() {
        let repo = InMemoryPermissionRepository::new();
        
        let permission = repo.create_permission("test_permission").await.unwrap();
        let role_id = "test_role_id";
        
        // Assign permission to role
        repo.assign_permission(role_id, &permission.id).await.unwrap();
        
        // Verify role has permission
        let has_permission = repo.role_has_permission(role_id, &permission.id).await.unwrap();
        assert!(has_permission);
        
        // Remove permission from role
        repo.remove_permission(role_id, &permission.id).await.unwrap();
        
        // Verify role no longer has permission
        let has_permission = repo.role_has_permission(role_id, &permission.id).await.unwrap();
        assert!(!has_permission);
    }

    #[tokio::test]
    async fn test_in_memory_permission_repository_get_permissions_for_role() {
        let repo = InMemoryPermissionRepository::new();
        
        let permission1 = repo.create_permission("permission1").await.unwrap();
        let permission2 = repo.create_permission("permission2").await.unwrap();
        let permission3 = repo.create_permission("permission3").await.unwrap();
        
        let role_id = "test_role_id";
        
        // Assign permissions to role
        repo.assign_permission(role_id, &permission1.id).await.unwrap();
        repo.assign_permission(role_id, &permission2.id).await.unwrap();
        
        // Get permissions for role
        let permissions = repo.get_permissions_for_role(role_id).await.unwrap();
        assert_eq!(permissions.len(), 2);
        
        let permission_ids: Vec<&str> = permissions.iter().map(|p| p.id.as_str()).collect();
        assert!(permission_ids.contains(&permission1.id.as_str()));
        assert!(permission_ids.contains(&permission2.id.as_str()));
        assert!(!permission_ids.contains(&permission3.id.as_str()));
    }

    #[tokio::test]
    async fn test_in_memory_permission_repository_role_has_permission() {
        let repo = InMemoryPermissionRepository::new();
        
        let permission = repo.create_permission("test_permission").await.unwrap();
        let role_id = "test_role_id";
        
        // Initially role should not have permission
        let has_permission = repo.role_has_permission(role_id, &permission.id).await.unwrap();
        assert!(!has_permission);
        
        // Assign permission
        repo.assign_permission(role_id, &permission.id).await.unwrap();
        
        // Now role should have permission
        let has_permission = repo.role_has_permission(role_id, &permission.id).await.unwrap();
        assert!(has_permission);
    }

    #[tokio::test]
    async fn test_in_memory_permission_repository_duplicate_assign_permission() {
        let repo = InMemoryPermissionRepository::new();
        
        let permission = repo.create_permission("test_permission").await.unwrap();
        let role_id = "test_role_id";
        
        // Assign permission twice
        repo.assign_permission(role_id, &permission.id).await.unwrap();
        repo.assign_permission(role_id, &permission.id).await.unwrap();
        
        // Should still only have one assignment
        let permissions = repo.get_permissions_for_role(role_id).await.unwrap();
        assert_eq!(permissions.len(), 1);
    }

    #[tokio::test]
    async fn test_in_memory_permission_repository_remove_nonexistent_permission() {
        let repo = InMemoryPermissionRepository::new();
        
        // Try to remove a permission that doesn't exist
        repo.remove_permission("test_role_id", "non_existent_permission_id").await.unwrap();
        
        // Should not cause an error
        let has_permission = repo.role_has_permission("test_role_id", "non_existent_permission_id").await.unwrap();
        assert!(!has_permission);
    }

    #[tokio::test]
    async fn test_in_memory_permission_repository_empty_list() {
        let repo = InMemoryPermissionRepository::new();
        
        let permissions = repo.list_permissions().await.unwrap();
        assert_eq!(permissions.len(), 0);
    }

    #[tokio::test]
    async fn test_in_memory_permission_repository_default_implementation() {
        let repo = InMemoryPermissionRepository::default();
        
        // Should be able to create a permission
        let permission = repo.create_permission("test_permission").await.unwrap();
        assert_eq!(permission.name, "test_permission");
    }
}

#[cfg(test)]
mod postgres_tests {
    use super::*;
    use crate::test_utils::create_test_pool;

    async fn create_test_repo() -> PostgresPermissionRepository {
        let pool = create_test_pool().await;
        PostgresPermissionRepository::new(pool)
    }

    async fn create_test_role(pool: &PgPool, role_id: &str, name: &str) {
        sqlx::query("INSERT INTO roles (id, name) VALUES ($1, $2) ON CONFLICT DO NOTHING")
            .bind(role_id)
            .bind(name)
            .execute(pool)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_postgres_permission_repository_create_permission() {
        let repo = create_test_repo().await;

        let unique_name = format!("test_permission_{}", uuid::Uuid::new_v4());
        let result = repo.create_permission(&unique_name).await;
        assert!(result.is_ok());
        let permission = result.unwrap();
        assert_eq!(permission.name, unique_name);
        assert!(permission.is_active);
    }

    #[tokio::test]
    async fn test_postgres_permission_repository_get_permission() {
        let repo = create_test_repo().await;

        // Create a permission first
        let unique_name = format!("test_permission_{}", uuid::Uuid::new_v4());
        let created_permission = repo.create_permission(&unique_name).await.unwrap();

        // Get the permission
        let result = repo.get_permission(&created_permission.id).await;
        assert!(result.is_ok());
        let permission = result.unwrap().unwrap();
        assert_eq!(permission.id, created_permission.id);
        assert_eq!(permission.name, unique_name);
    }

    #[tokio::test]
    async fn test_postgres_permission_repository_get_permission_not_found() {
        let repo = create_test_repo().await;

        let result = repo.get_permission("nonexistent-permission").await;
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_postgres_permission_repository_list_permissions() {
        let repo = create_test_repo().await;

        // Create some permissions
        let unique_name1 = format!("permission_list_{}", uuid::Uuid::new_v4());
        let unique_name2 = format!("permission_list_{}", uuid::Uuid::new_v4());
        repo.create_permission(&unique_name1).await.unwrap();
        repo.create_permission(&unique_name2).await.unwrap();

        let result = repo.list_permissions().await;
        assert!(result.is_ok());
        let permissions = result.unwrap();
        assert!(permissions.len() >= 2);
    }

    #[tokio::test]
    async fn test_postgres_permission_repository_delete_permission() {
        let repo = create_test_repo().await;

        // Create a permission first
        let permission = repo.create_permission("test_permission_delete").await.unwrap();

        // Delete the permission
        let result = repo.delete_permission(&permission.id).await;
        assert!(result.is_ok());

        // Verify it's deleted
        let get_result = repo.get_permission(&permission.id).await;
        assert!(get_result.is_ok());
        assert!(get_result.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_postgres_permission_repository_assign_permission() {
        let repo = create_test_repo().await;
        let pool = repo.pool.clone();

        // Create a test role first
        create_test_role(&pool, "test-role-1", "Test Role 1").await;

        // Create a permission
        let unique_name = format!("test_permission_assign_{}", uuid::Uuid::new_v4());
        let permission = repo.create_permission(&unique_name).await.unwrap();

        // Assign permission to a role
        let result = repo.assign_permission("test-role-1", &permission.id).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_postgres_permission_repository_remove_permission() {
        let repo = create_test_repo().await;
        let pool = repo.pool.clone();

        // Create a test role first
        create_test_role(&pool, "test-role-2", "Test Role 2").await;

        // Create a permission
        let unique_name = format!("test_permission_remove_{}", uuid::Uuid::new_v4());
        let permission = repo.create_permission(&unique_name).await.unwrap();

        // Assign permission to a role
        repo.assign_permission("test-role-2", &permission.id).await.unwrap();

        // Remove the permission
        let result = repo.remove_permission("test-role-2", &permission.id).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_postgres_permission_repository_role_has_permission() {
        let repo = create_test_repo().await;
        let pool = repo.pool.clone();

        // Create a test role first
        create_test_role(&pool, "test-role-3", "Test Role 3").await;

        // Create a permission
        let unique_name = format!("test_permission_has_{}", uuid::Uuid::new_v4());
        let permission = repo.create_permission(&unique_name).await.unwrap();

        // Initially, role should not have permission
        let result = repo.role_has_permission("test-role-3", &permission.id).await;
        assert!(result.is_ok());
        assert!(!result.unwrap());

        // Assign permission to role
        repo.assign_permission("test-role-3", &permission.id).await.unwrap();

        // Now role should have permission
        let result = repo.role_has_permission("test-role-3", &permission.id).await;
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[tokio::test]
    async fn test_postgres_permission_repository_get_permissions_for_role() {
        let repo = create_test_repo().await;
        let pool = repo.pool.clone();

        // Clean up any existing data for this test
        sqlx::query("DELETE FROM role_permissions WHERE role_id = $1")
            .bind("test-role-4")
            .execute(&pool)
            .await
            .unwrap();

        // Create a test role first
        create_test_role(&pool, "test-role-4", "Test Role 4").await;

        // Create permissions
        let unique_name1 = format!("permission_for_role_1_{}", uuid::Uuid::new_v4());
        let unique_name2 = format!("permission_for_role_2_{}", uuid::Uuid::new_v4());
        let permission1 = repo.create_permission(&unique_name1).await.unwrap();
        let permission2 = repo.create_permission(&unique_name2).await.unwrap();

        // Assign permissions to role
        repo.assign_permission("test-role-4", &permission1.id).await.unwrap();
        repo.assign_permission("test-role-4", &permission2.id).await.unwrap();

        // Get permissions for role
        let result = repo.get_permissions_for_role("test-role-4").await;
        assert!(result.is_ok());
        let permissions = result.unwrap();
        assert_eq!(permissions.len(), 2);
    }

    #[tokio::test]
    async fn test_postgres_permission_repository_duplicate_assign_permission() {
        let repo = create_test_repo().await;
        let pool = repo.pool.clone();

        // Create a test role first
        create_test_role(&pool, "test-role-5", "Test Role 5").await;

        // Create a permission
        let unique_name = format!("test_permission_duplicate_{}", uuid::Uuid::new_v4());
        let permission = repo.create_permission(&unique_name).await.unwrap();

        // Assign permission to role twice
        repo.assign_permission("test-role-5", &permission.id).await.unwrap();
        let result = repo.assign_permission("test-role-5", &permission.id).await;
        assert!(result.is_ok()); // Should not error due to ON CONFLICT DO NOTHING
    }

    #[tokio::test]
    async fn test_postgres_permission_repository_remove_nonexistent_permission() {
        let repo = create_test_repo().await;
        let pool = repo.pool.clone();

        // Create a test role first
        create_test_role(&pool, "test-role-6", "Test Role 6").await;

        // Try to remove a non-existent permission assignment
        let result = repo.remove_permission("test-role-6", "nonexistent-permission").await;
        assert!(result.is_ok()); // Should not error
    }

    #[tokio::test]
    async fn test_postgres_permission_repository_empty_permissions_for_role() {
        let repo = create_test_repo().await;
        let pool = repo.pool.clone();

        // Create a test role first
        create_test_role(&pool, "test-role-7", "Test Role 7").await;

        // Get permissions for a role that has none
        let result = repo.get_permissions_for_role("test-role-7").await;
        assert!(result.is_ok());
        let permissions = result.unwrap();
        assert!(permissions.is_empty());
    }
}
