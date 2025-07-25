use async_trait::async_trait;
use sqlx::PgPool;
use crate::domain::permission::Permission;
use tracing::{error, instrument};
use crate::infrastructure::PermissionRepository;

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
            "INSERT INTO permissions (id, name) VALUES ($1, $2) RETURNING id, name"
        )
        .bind(&id)
        .bind(name)
        .fetch_one(&self.pool)
        .await;
        if let Err(ref e) = rec {
            error!(error = %e, "Failed to create permission");
        }
        rec
    }
    #[instrument]
    async fn list_permissions(&self) -> RepoResult<Vec<Permission>> {
        let res = sqlx::query_as::<_, Permission>("SELECT id, name FROM permissions")
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
        let found: Option<i64> = sqlx::query_scalar(
            "SELECT 1 FROM role_permissions WHERE role_id = $1 AND permission_id = $2"
        )
        .bind(role_id)
        .bind(permission_id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(found.is_some())
    }
} 