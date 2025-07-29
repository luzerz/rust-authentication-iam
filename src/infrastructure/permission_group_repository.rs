use crate::domain::permission_group::PermissionGroup;
use crate::infrastructure::RepoResult;
use async_trait::async_trait;
use sqlx::PgPool;
use tracing::instrument;

#[async_trait]
pub trait PermissionGroupRepository: Send + Sync {
    async fn create_group(&self, group: PermissionGroup) -> RepoResult<PermissionGroup>;
    async fn get_group(&self, group_id: &str) -> RepoResult<Option<PermissionGroup>>;
    async fn list_groups(&self) -> RepoResult<Vec<PermissionGroup>>;
    async fn list_groups_by_category(&self, category: &str) -> RepoResult<Vec<PermissionGroup>>;
    async fn update_group(&self, group: &PermissionGroup) -> RepoResult<()>;
    async fn delete_group(&self, group_id: &str) -> RepoResult<()>;
    async fn get_permissions_in_group(
        &self,
        group_id: &str,
    ) -> RepoResult<Vec<crate::domain::permission::Permission>>;
    async fn get_permission_count(&self, group_id: &str) -> RepoResult<usize>;
}

#[derive(Debug, Clone)]
pub struct PostgresPermissionGroupRepository {
    pub pool: PgPool,
}

impl PostgresPermissionGroupRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl PermissionGroupRepository for PostgresPermissionGroupRepository {
    #[instrument]
    async fn create_group(&self, group: PermissionGroup) -> RepoResult<PermissionGroup> {
        sqlx::query!(
            r#"
            INSERT INTO permission_groups (id, name, description, category, metadata, is_active)
            VALUES ($1, $2, $3, $4, $5, $6)
            "#,
            group.id,
            group.name,
            group.description,
            group.category,
            group.metadata,
            group.is_active
        )
        .execute(&self.pool)
        .await?;

        Ok(group)
    }

    #[instrument]
    async fn get_group(&self, group_id: &str) -> RepoResult<Option<PermissionGroup>> {
        let row = sqlx::query!(
            r#"
            SELECT id, name, description, category, metadata, is_active
            FROM permission_groups
            WHERE id = $1
            "#,
            group_id
        )
        .fetch_optional(&self.pool)
        .await?;

        match row {
            Some(row) => Ok(Some(PermissionGroup {
                id: row.id,
                name: row.name,
                description: row.description,
                category: row.category,
                metadata: row.metadata,
                is_active: row.is_active,
            })),
            None => Ok(None),
        }
    }

    #[instrument]
    async fn list_groups(&self) -> RepoResult<Vec<PermissionGroup>> {
        let rows = sqlx::query!(
            r#"
            SELECT id, name, description, category, metadata, is_active
            FROM permission_groups
            ORDER BY name
            "#
        )
        .fetch_all(&self.pool)
        .await?;

        let groups: Vec<PermissionGroup> = rows
            .into_iter()
            .map(|row| PermissionGroup {
                id: row.id,
                name: row.name,
                description: row.description,
                category: row.category,
                metadata: row.metadata,
                is_active: row.is_active,
            })
            .collect();

        Ok(groups)
    }

    #[instrument]
    async fn list_groups_by_category(&self, category: &str) -> RepoResult<Vec<PermissionGroup>> {
        let rows = sqlx::query!(
            r#"
            SELECT id, name, description, category, metadata, is_active
            FROM permission_groups
            WHERE category = $1
            ORDER BY name
            "#,
            category
        )
        .fetch_all(&self.pool)
        .await?;

        let groups: Vec<PermissionGroup> = rows
            .into_iter()
            .map(|row| PermissionGroup {
                id: row.id,
                name: row.name,
                description: row.description,
                category: row.category,
                metadata: row.metadata,
                is_active: row.is_active,
            })
            .collect();

        Ok(groups)
    }

    #[instrument]
    async fn update_group(&self, group: &PermissionGroup) -> RepoResult<()> {
        sqlx::query!(
            r#"
            UPDATE permission_groups
            SET name = $1, description = $2, category = $3, metadata = $4, is_active = $5
            WHERE id = $6
            "#,
            group.name,
            group.description,
            group.category,
            group.metadata,
            group.is_active,
            group.id
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    #[instrument]
    async fn delete_group(&self, group_id: &str) -> RepoResult<()> {
        // First, remove group association from permissions
        sqlx::query!(
            "UPDATE permissions SET group_id = NULL WHERE group_id = $1",
            group_id
        )
        .execute(&self.pool)
        .await?;

        // Then delete the group
        sqlx::query!("DELETE FROM permission_groups WHERE id = $1", group_id)
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    #[instrument]
    async fn get_permissions_in_group(
        &self,
        group_id: &str,
    ) -> RepoResult<Vec<crate::domain::permission::Permission>> {
        let rows = sqlx::query!(
            r#"
            SELECT id, name, description, group_id, metadata, is_active
            FROM permissions
            WHERE group_id = $1 AND is_active = true
            ORDER BY name
            "#,
            group_id
        )
        .fetch_all(&self.pool)
        .await?;

        let permissions: Vec<crate::domain::permission::Permission> = rows
            .into_iter()
            .map(|row| crate::domain::permission::Permission {
                id: row.id,
                name: row.name,
                description: row.description,
                group_id: row.group_id,
                metadata: row.metadata,
                is_active: row.is_active,
            })
            .collect();

        Ok(permissions)
    }

    #[instrument]
    async fn get_permission_count(&self, group_id: &str) -> RepoResult<usize> {
        let count = sqlx::query!(
            r#"
            SELECT COUNT(*) as count
            FROM permissions
            WHERE group_id = $1 AND is_active = true
            "#,
            group_id
        )
        .fetch_one(&self.pool)
        .await?;

        Ok(count.count.unwrap_or(0) as usize)
    }
}

// In-memory implementation for testing
#[derive(Debug)]
pub struct InMemoryPermissionGroupRepository {
    groups: std::sync::Mutex<std::collections::HashMap<String, PermissionGroup>>,
    permissions:
        std::sync::Mutex<std::collections::HashMap<String, crate::domain::permission::Permission>>,
}

impl InMemoryPermissionGroupRepository {
    pub fn new() -> Self {
        Self {
            groups: std::sync::Mutex::new(std::collections::HashMap::new()),
            permissions: std::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }

    pub fn add_permission(&self, permission: crate::domain::permission::Permission) {
        let mut permissions = self.permissions.lock().unwrap();
        permissions.insert(permission.id.clone(), permission);
    }
}

impl Default for InMemoryPermissionGroupRepository {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl PermissionGroupRepository for InMemoryPermissionGroupRepository {
    async fn create_group(&self, group: PermissionGroup) -> RepoResult<PermissionGroup> {
        let mut groups = self.groups.lock().unwrap();
        groups.insert(group.id.clone(), group.clone());
        Ok(group)
    }

    async fn get_group(&self, group_id: &str) -> RepoResult<Option<PermissionGroup>> {
        let groups = self.groups.lock().unwrap();
        Ok(groups.get(group_id).cloned())
    }

    async fn list_groups(&self) -> RepoResult<Vec<PermissionGroup>> {
        let groups = self.groups.lock().unwrap();
        let mut result: Vec<PermissionGroup> = groups.values().cloned().collect();
        result.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(result)
    }

    async fn list_groups_by_category(&self, category: &str) -> RepoResult<Vec<PermissionGroup>> {
        let groups = self.groups.lock().unwrap();
        let mut result: Vec<PermissionGroup> = groups
            .values()
            .filter(|group| group.category.as_deref() == Some(category))
            .cloned()
            .collect();
        result.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(result)
    }

    async fn update_group(&self, group: &PermissionGroup) -> RepoResult<()> {
        let mut groups = self.groups.lock().unwrap();
        groups.insert(group.id.clone(), group.clone());
        Ok(())
    }

    async fn delete_group(&self, group_id: &str) -> RepoResult<()> {
        let mut groups = self.groups.lock().unwrap();
        groups.remove(group_id);
        Ok(())
    }

    async fn get_permissions_in_group(
        &self,
        group_id: &str,
    ) -> RepoResult<Vec<crate::domain::permission::Permission>> {
        let permissions = self.permissions.lock().unwrap();
        let mut result: Vec<crate::domain::permission::Permission> = permissions
            .values()
            .filter(|p| p.group_id == Some(group_id.to_string()))
            .cloned()
            .collect();
        result.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(result)
    }

    async fn get_permission_count(&self, group_id: &str) -> RepoResult<usize> {
        let permissions = self.permissions.lock().unwrap();
        Ok(permissions
            .values()
            .filter(|p| p.group_id == Some(group_id.to_string()))
            .count())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::permission::Permission;

    #[tokio::test]
    async fn test_in_memory_permission_group_repository_create_group() {
        let repo = InMemoryPermissionGroupRepository::new();
        
        let group = PermissionGroup {
            id: "group1".to_string(),
            name: "Admin Group".to_string(),
            description: Some("Administrative permissions".to_string()),
            category: Some("admin".to_string()),
            metadata: serde_json::json!({"level": "high"}),
            is_active: true,
        };
        
        let result = repo.create_group(group.clone()).await;
        assert!(result.is_ok());
        
        let created_group = result.unwrap();
        assert_eq!(created_group.id, "group1");
        assert_eq!(created_group.name, "Admin Group");
        assert_eq!(created_group.description, Some("Administrative permissions".to_string()));
        assert_eq!(created_group.category, Some("admin".to_string()));
        assert!(created_group.is_active);
    }

    #[tokio::test]
    async fn test_in_memory_permission_group_repository_get_group() {
        let repo = InMemoryPermissionGroupRepository::new();
        
        let group = PermissionGroup {
            id: "group1".to_string(),
            name: "Admin Group".to_string(),
            description: None,
            category: None,
            metadata: serde_json::json!({}),
            is_active: true,
        };
        
        repo.create_group(group.clone()).await.unwrap();
        
        let result = repo.get_group("group1").await;
        assert!(result.is_ok());
        
        let found_group = result.unwrap();
        assert!(found_group.is_some());
        assert_eq!(found_group.unwrap().id, "group1");
    }

    #[tokio::test]
    async fn test_in_memory_permission_group_repository_get_group_not_found() {
        let repo = InMemoryPermissionGroupRepository::new();
        
        let result = repo.get_group("nonexistent").await;
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_in_memory_permission_group_repository_list_groups() {
        let repo = InMemoryPermissionGroupRepository::new();
        
        let group1 = PermissionGroup {
            id: "group1".to_string(),
            name: "Admin Group".to_string(),
            description: None,
            category: None,
            metadata: serde_json::json!({}),
            is_active: true,
        };
        
        let group2 = PermissionGroup {
            id: "group2".to_string(),
            name: "User Group".to_string(),
            description: None,
            category: None,
            metadata: serde_json::json!({}),
            is_active: true,
        };
        
        repo.create_group(group1).await.unwrap();
        repo.create_group(group2).await.unwrap();
        
        let result = repo.list_groups().await;
        assert!(result.is_ok());
        
        let groups = result.unwrap();
        assert_eq!(groups.len(), 2);
        assert!(groups.iter().any(|g| g.name == "Admin Group"));
        assert!(groups.iter().any(|g| g.name == "User Group"));
    }

    #[tokio::test]
    async fn test_in_memory_permission_group_repository_list_groups_empty() {
        let repo = InMemoryPermissionGroupRepository::new();
        
        let result = repo.list_groups().await;
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_in_memory_permission_group_repository_list_groups_by_category() {
        let repo = InMemoryPermissionGroupRepository::new();
        
        let admin_group = PermissionGroup {
            id: "admin1".to_string(),
            name: "Admin Group".to_string(),
            description: None,
            category: Some("admin".to_string()),
            metadata: serde_json::json!({}),
            is_active: true,
        };
        
        let user_group = PermissionGroup {
            id: "user1".to_string(),
            name: "User Group".to_string(),
            description: None,
            category: Some("user".to_string()),
            metadata: serde_json::json!({}),
            is_active: true,
        };
        
        let another_admin_group = PermissionGroup {
            id: "admin2".to_string(),
            name: "Another Admin Group".to_string(),
            description: None,
            category: Some("admin".to_string()),
            metadata: serde_json::json!({}),
            is_active: true,
        };
        
        repo.create_group(admin_group).await.unwrap();
        repo.create_group(user_group).await.unwrap();
        repo.create_group(another_admin_group).await.unwrap();
        
        let result = repo.list_groups_by_category("admin").await;
        assert!(result.is_ok());
        
        let admin_groups = result.unwrap();
        assert_eq!(admin_groups.len(), 2);
        assert!(admin_groups.iter().all(|g| g.category.as_deref() == Some("admin")));
    }

    #[tokio::test]
    async fn test_in_memory_permission_group_repository_list_groups_by_nonexistent_category() {
        let repo = InMemoryPermissionGroupRepository::new();
        
        let result = repo.list_groups_by_category("nonexistent").await;
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_in_memory_permission_group_repository_update_group() {
        let repo = InMemoryPermissionGroupRepository::new();
        
        let mut group = PermissionGroup {
            id: "group1".to_string(),
            name: "Original Name".to_string(),
            description: None,
            category: None,
            metadata: serde_json::json!({}),
            is_active: true,
        };
        
        repo.create_group(group.clone()).await.unwrap();
        
        // Update the group
        group.name = "Updated Name".to_string();
        group.description = Some("Updated description".to_string());
        
        let result = repo.update_group(&group).await;
        assert!(result.is_ok());
        
        // Verify the update
        let updated_group = repo.get_group("group1").await.unwrap().unwrap();
        assert_eq!(updated_group.name, "Updated Name");
        assert_eq!(updated_group.description, Some("Updated description".to_string()));
    }

    #[tokio::test]
    async fn test_in_memory_permission_group_repository_update_nonexistent_group() {
        let repo = InMemoryPermissionGroupRepository::new();
        
        let group = PermissionGroup {
            id: "nonexistent".to_string(),
            name: "Test Group".to_string(),
            description: None,
            category: None,
            metadata: serde_json::json!({}),
            is_active: true,
        };
        
        let result = repo.update_group(&group).await;
        // InMemoryPermissionGroupRepository doesn't check if group exists before updating
        assert!(result.is_ok());
        
        // Verify the group was created by the update operation
        let found_group = repo.get_group("nonexistent").await.unwrap();
        assert!(found_group.is_some());
        assert_eq!(found_group.unwrap().name, "Test Group");
    }

    #[tokio::test]
    async fn test_in_memory_permission_group_repository_delete_group() {
        let repo = InMemoryPermissionGroupRepository::new();
        
        let group = PermissionGroup {
            id: "group1".to_string(),
            name: "Test Group".to_string(),
            description: None,
            category: None,
            metadata: serde_json::json!({}),
            is_active: true,
        };
        
        repo.create_group(group).await.unwrap();
        
        // Verify group exists
        let found_group = repo.get_group("group1").await.unwrap();
        assert!(found_group.is_some());
        
        // Delete the group
        let result = repo.delete_group("group1").await;
        assert!(result.is_ok());
        
        // Verify group is deleted
        let found_group = repo.get_group("group1").await.unwrap();
        assert!(found_group.is_none());
    }

    #[tokio::test]
    async fn test_in_memory_permission_group_repository_delete_nonexistent_group() {
        let repo = InMemoryPermissionGroupRepository::new();
        
        let result = repo.delete_group("nonexistent").await;
        // InMemoryPermissionGroupRepository doesn't check if group exists before deleting
        assert!(result.is_ok());
        
        // Verify the group doesn't exist (was never there)
        let found_group = repo.get_group("nonexistent").await.unwrap();
        assert!(found_group.is_none());
    }

    #[tokio::test]
    async fn test_in_memory_permission_group_repository_get_permissions_in_group() {
        let repo = InMemoryPermissionGroupRepository::new();
        
        let group = PermissionGroup {
            id: "group1".to_string(),
            name: "Test Group".to_string(),
            description: None,
            category: None,
            metadata: serde_json::json!({}),
            is_active: true,
        };
        
        repo.create_group(group).await.unwrap();
        
        let permission1 = Permission {
            id: "perm1".to_string(),
            name: "read".to_string(),
            description: None,
            group_id: Some("group1".to_string()),
            metadata: serde_json::json!({}),
            is_active: true,
        };
        
        let permission2 = Permission {
            id: "perm2".to_string(),
            name: "write".to_string(),
            description: None,
            group_id: Some("group1".to_string()),
            metadata: serde_json::json!({}),
            is_active: true,
        };
        
        let permission3 = Permission {
            id: "perm3".to_string(),
            name: "delete".to_string(),
            description: None,
            group_id: Some("other_group".to_string()),
            metadata: serde_json::json!({}),
            is_active: true,
        };
        
        repo.add_permission(permission1);
        repo.add_permission(permission2);
        repo.add_permission(permission3);
        
        let result = repo.get_permissions_in_group("group1").await;
        assert!(result.is_ok());
        
        let permissions = result.unwrap();
        assert_eq!(permissions.len(), 2);
        assert!(permissions.iter().any(|p| p.name == "read"));
        assert!(permissions.iter().any(|p| p.name == "write"));
        assert!(!permissions.iter().any(|p| p.name == "delete"));
    }

    #[tokio::test]
    async fn test_in_memory_permission_group_repository_get_permissions_in_nonexistent_group() {
        let repo = InMemoryPermissionGroupRepository::new();
        
        let result = repo.get_permissions_in_group("nonexistent").await;
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_in_memory_permission_group_repository_get_permission_count() {
        let repo = InMemoryPermissionGroupRepository::new();
        
        let group = PermissionGroup {
            id: "group1".to_string(),
            name: "Test Group".to_string(),
            description: None,
            category: None,
            metadata: serde_json::json!({}),
            is_active: true,
        };
        
        repo.create_group(group).await.unwrap();
        
        let permission1 = Permission {
            id: "perm1".to_string(),
            name: "read".to_string(),
            description: None,
            group_id: Some("group1".to_string()),
            metadata: serde_json::json!({}),
            is_active: true,
        };
        
        let permission2 = Permission {
            id: "perm2".to_string(),
            name: "write".to_string(),
            description: None,
            group_id: Some("group1".to_string()),
            metadata: serde_json::json!({}),
            is_active: true,
        };
        
        repo.add_permission(permission1);
        repo.add_permission(permission2);
        
        let result = repo.get_permission_count("group1").await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 2);
    }

    #[tokio::test]
    async fn test_in_memory_permission_group_repository_get_permission_count_nonexistent_group() {
        let repo = InMemoryPermissionGroupRepository::new();
        
        let result = repo.get_permission_count("nonexistent").await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 0);
    }

    #[tokio::test]
    async fn test_in_memory_permission_group_repository_default_implementation() {
        let repo = InMemoryPermissionGroupRepository::default();
        
        // Should be empty by default
        let groups = repo.list_groups().await.unwrap();
        assert!(groups.is_empty());
        
        // Should be able to create groups
        let group = PermissionGroup {
            id: "test".to_string(),
            name: "Test Group".to_string(),
            description: None,
            category: None,
            metadata: serde_json::json!({}),
            is_active: true,
        };
        
        let result = repo.create_group(group).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_in_memory_permission_group_repository_complex_scenario() {
        let repo = InMemoryPermissionGroupRepository::new();
        
        // Create multiple groups
        let admin_group = PermissionGroup {
            id: "admin".to_string(),
            name: "Administrators".to_string(),
            description: Some("System administrators".to_string()),
            category: Some("admin".to_string()),
            metadata: serde_json::json!({"level": "high"}),
            is_active: true,
        };
        
        let user_group = PermissionGroup {
            id: "user".to_string(),
            name: "Users".to_string(),
            description: Some("Regular users".to_string()),
            category: Some("user".to_string()),
            metadata: serde_json::json!({"level": "low"}),
            is_active: true,
        };
        
        repo.create_group(admin_group).await.unwrap();
        repo.create_group(user_group).await.unwrap();
        
        // Add permissions to groups
        let admin_permission1 = Permission {
            id: "admin_read".to_string(),
            name: "admin:read".to_string(),
            description: None,
            group_id: Some("admin".to_string()),
            metadata: serde_json::json!({}),
            is_active: true,
        };
        
        let admin_permission2 = Permission {
            id: "admin_write".to_string(),
            name: "admin:write".to_string(),
            description: None,
            group_id: Some("admin".to_string()),
            metadata: serde_json::json!({}),
            is_active: true,
        };
        
        let user_permission = Permission {
            id: "user_read".to_string(),
            name: "user:read".to_string(),
            description: None,
            group_id: Some("user".to_string()),
            metadata: serde_json::json!({}),
            is_active: true,
        };
        
        repo.add_permission(admin_permission1);
        repo.add_permission(admin_permission2);
        repo.add_permission(user_permission);
        
        // Test various operations
        let admin_groups = repo.list_groups_by_category("admin").await.unwrap();
        assert_eq!(admin_groups.len(), 1);
        assert_eq!(admin_groups[0].name, "Administrators");
        
        let admin_permissions = repo.get_permissions_in_group("admin").await.unwrap();
        assert_eq!(admin_permissions.len(), 2);
        
        let admin_count = repo.get_permission_count("admin").await.unwrap();
        assert_eq!(admin_count, 2);
        
        let user_count = repo.get_permission_count("user").await.unwrap();
        assert_eq!(user_count, 1);
        
        // Update a group
        let mut updated_admin_group = repo.get_group("admin").await.unwrap().unwrap();
        updated_admin_group.description = Some("Updated admin description".to_string());
        repo.update_group(&updated_admin_group).await.unwrap();
        
        let updated_group = repo.get_group("admin").await.unwrap().unwrap();
        assert_eq!(updated_group.description, Some("Updated admin description".to_string()));
    }
}
