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
            WHERE group_id = $1
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
}

// In-memory implementation for testing
#[derive(Debug)]
pub struct InMemoryPermissionGroupRepository {
    groups: std::sync::Mutex<std::collections::HashMap<String, PermissionGroup>>,
}

impl InMemoryPermissionGroupRepository {
    pub fn new() -> Self {
        Self {
            groups: std::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }
}

impl Default for InMemoryPermissionGroupRepository {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl PermissionGroupRepository for InMemoryPermissionGroupRepository {
    #[instrument]
    async fn create_group(&self, group: PermissionGroup) -> RepoResult<PermissionGroup> {
        let mut groups = self.groups.lock().unwrap();
        groups.insert(group.id.clone(), group.clone());
        Ok(group)
    }

    #[instrument]
    async fn get_group(&self, group_id: &str) -> RepoResult<Option<PermissionGroup>> {
        let groups = self.groups.lock().unwrap();
        Ok(groups.get(group_id).cloned())
    }

    #[instrument]
    async fn list_groups(&self) -> RepoResult<Vec<PermissionGroup>> {
        let groups = self.groups.lock().unwrap();
        let mut result: Vec<PermissionGroup> = groups.values().cloned().collect();
        result.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(result)
    }

    #[instrument]
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

    #[instrument]
    async fn update_group(&self, group: &PermissionGroup) -> RepoResult<()> {
        let mut groups = self.groups.lock().unwrap();
        groups.insert(group.id.clone(), group.clone());
        Ok(())
    }

    #[instrument]
    async fn delete_group(&self, group_id: &str) -> RepoResult<()> {
        let mut groups = self.groups.lock().unwrap();
        groups.remove(group_id);
        Ok(())
    }

    #[instrument]
    async fn get_permissions_in_group(
        &self,
        _group_id: &str,
    ) -> RepoResult<Vec<crate::domain::permission::Permission>> {
        // In-memory implementation would need access to permissions
        // For now, return empty vector
        Ok(vec![])
    }
}
