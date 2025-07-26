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
