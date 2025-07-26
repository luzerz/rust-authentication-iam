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
