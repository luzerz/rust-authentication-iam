use super::{RepoResult, UserRepository};
use crate::domain::user::User;
use async_trait::async_trait;
use sqlx::FromRow;
use sqlx::PgPool;
use std::collections::HashMap;
use std::collections::HashSet;
use std::sync::Mutex;

#[derive(Debug, FromRow)]
struct UserRow {
    pub id: String,
    pub email: String,
    pub password_hash: String,
    pub is_locked: bool,
    // roles: Vec<String> // For now, roles can be loaded separately or as a comma-separated string
}

#[derive(Debug, FromRow)]
struct RoleRow {
    pub name: String,
}

pub struct InMemoryUserRepository {
    users: Mutex<HashMap<String, User>>,       // key: email
    users_by_id: Mutex<HashMap<String, User>>, // key: id
}

impl InMemoryUserRepository {
    pub fn new(users: Vec<User>) -> Self {
        let mut users_by_email = HashMap::new();
        let mut users_by_id = HashMap::new();

        for user in users {
            users_by_email.insert(user.email.clone(), user.clone());
            users_by_id.insert(user.id.clone(), user);
        }

        Self {
            users: Mutex::new(users_by_email),
            users_by_id: Mutex::new(users_by_id),
        }
    }
}

#[async_trait]
impl UserRepository for InMemoryUserRepository {
    async fn find_by_email(&self, email: &str) -> Option<User> {
        self.users.lock().unwrap().get(email).cloned()
    }

    async fn create_user(&self, user: User) -> RepoResult<User> {
        let mut users = self.users.lock().unwrap();
        let mut users_by_id = self.users_by_id.lock().unwrap();

        users.insert(user.email.clone(), user.clone());
        users_by_id.insert(user.id.clone(), user.clone());

        Ok(user)
    }

    async fn update_user(&self, user: &User) -> RepoResult<()> {
        let mut users = self.users.lock().unwrap();
        let mut users_by_id = self.users_by_id.lock().unwrap();

        users.insert(user.email.clone(), user.clone());
        users_by_id.insert(user.id.clone(), user.clone());

        Ok(())
    }

    async fn update_password(&self, user_id: &str, new_password_hash: &str) -> RepoResult<()> {
        let mut users = self.users.lock().unwrap();
        let mut users_by_id = self.users_by_id.lock().unwrap();

        if let Some(user) = users_by_id.get_mut(user_id) {
            user.password_hash = new_password_hash.to_string();
            // Also update in the email-indexed map
            if let Some(user_by_email) = users.get_mut(&user.email) {
                user_by_email.password_hash = new_password_hash.to_string();
            }
        }

        Ok(())
    }

    async fn find_by_id(&self, user_id: &str) -> RepoResult<Option<User>> {
        Ok(self.users_by_id.lock().unwrap().get(user_id).cloned())
    }
}

pub struct PostgresUserRepository {
    pool: PgPool,
}

impl PostgresUserRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

unsafe impl Send for PostgresUserRepository {}
unsafe impl Sync for PostgresUserRepository {}

#[async_trait]
impl UserRepository for PostgresUserRepository {
    async fn find_by_email(&self, email: &str) -> Option<User> {
        let row = sqlx::query_as::<_, UserRow>(
            "SELECT id, email, password_hash, is_locked FROM users WHERE email = $1",
        )
        .bind(email)
        .fetch_optional(&self.pool)
        .await
        .ok()??;
        // Load roles
        let roles_result = sqlx::query_as::<_, RoleRow>(
            "SELECT r.name FROM roles r \
             INNER JOIN user_roles ur ON ur.role_id = r.id \
             WHERE ur.user_id = $1",
        )
        .bind(&row.id)
        .fetch_all(&self.pool)
        .await;

        let roles: Vec<String> = match roles_result {
            Ok(role_rows) => role_rows.into_iter().map(|r| r.name).collect(),
            Err(e) => {
                tracing::error!("Failed to load roles for user {}: {}", row.id, e);
                Vec::new()
            }
        };
        Some(User {
            id: row.id,
            email: row.email,
            password_hash: row.password_hash,
            roles,
            is_locked: row.is_locked,
        })
    }

    async fn create_user(&self, user: User) -> RepoResult<User> {
        // Insert the user
        sqlx::query!(
            "INSERT INTO users (id, email, password_hash, is_locked) VALUES ($1, $2, $3, $4)",
            user.id,
            user.email,
            user.password_hash,
            user.is_locked
        )
        .execute(&self.pool)
        .await?;

        Ok(user)
    }

    async fn update_user(&self, user: &User) -> RepoResult<()> {
        sqlx::query!(
            "UPDATE users SET email = $1, password_hash = $2, is_locked = $3 WHERE id = $4",
            user.email,
            user.password_hash,
            user.is_locked,
            user.id
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn update_password(&self, user_id: &str, new_password_hash: &str) -> RepoResult<()> {
        sqlx::query!(
            "UPDATE users SET password_hash = $1 WHERE id = $2",
            new_password_hash,
            user_id
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn find_by_id(&self, user_id: &str) -> RepoResult<Option<User>> {
        let row = sqlx::query_as::<_, UserRow>(
            "SELECT id, email, password_hash, is_locked FROM users WHERE id = $1",
        )
        .bind(user_id)
        .fetch_optional(&self.pool)
        .await?;

        match row {
            Some(row) => {
                // Load roles
                let roles_result = sqlx::query_as::<_, RoleRow>(
                    "SELECT r.name FROM roles r \
                     INNER JOIN user_roles ur ON ur.role_id = r.id \
                     WHERE ur.user_id = $1",
                )
                .bind(&row.id)
                .fetch_all(&self.pool)
                .await;

                let roles: Vec<String> = match roles_result {
                    Ok(role_rows) => role_rows.into_iter().map(|r| r.name).collect(),
                    Err(e) => {
                        tracing::error!("Failed to load roles for user {}: {}", row.id, e);
                        Vec::new()
                    }
                };

                Ok(Some(User {
                    id: row.id,
                    email: row.email,
                    password_hash: row.password_hash,
                    roles,
                    is_locked: row.is_locked,
                }))
            }
            None => Ok(None),
        }
    }
}

#[async_trait]
pub trait RefreshTokenRepository: Send + Sync {
    async fn insert(
        &self,
        token: crate::application::services::RefreshToken,
    ) -> Result<(), sqlx::Error>;
    async fn revoke(&self, jti: &str) -> Result<(), sqlx::Error>;
    async fn is_valid(&self, jti: &str) -> Result<bool, sqlx::Error>;
}

pub struct PostgresRefreshTokenRepository {
    pool: PgPool,
}

impl PostgresRefreshTokenRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl RefreshTokenRepository for PostgresRefreshTokenRepository {
    async fn insert(
        &self,
        token: crate::application::services::RefreshToken,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            "INSERT INTO refresh_tokens (jti, user_id, expires_at, revoked) VALUES ($1, $2, $3, $4)"
        )
        .bind(&token.jti)
        .bind(&token.user_id)
        .bind(token.expires_at)
        .bind(token.revoked)
        .execute(&self.pool)
        .await?;
        Ok(())
    }
    async fn revoke(&self, jti: &str) -> Result<(), sqlx::Error> {
        sqlx::query("UPDATE refresh_tokens SET revoked = TRUE WHERE jti = $1")
            .bind(jti)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
    async fn is_valid(&self, jti: &str) -> Result<bool, sqlx::Error> {
        let rec = sqlx::query_scalar::<_, bool>(
            "SELECT NOT revoked FROM refresh_tokens WHERE jti = $1 AND expires_at > NOW()",
        )
        .bind(jti)
        .fetch_optional(&self.pool)
        .await?;
        Ok(rec.unwrap_or(false))
    }
}

pub struct InMemoryRefreshTokenRepository {
    valid_tokens: Mutex<HashSet<String>>,
    revoked_tokens: Mutex<HashSet<String>>,
}

impl InMemoryRefreshTokenRepository {
    pub fn new() -> Self {
        Self {
            valid_tokens: Mutex::new(HashSet::new()),
            revoked_tokens: Mutex::new(HashSet::new()),
        }
    }
}
impl Default for InMemoryRefreshTokenRepository {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl RefreshTokenRepository for InMemoryRefreshTokenRepository {
    async fn insert(
        &self,
        token: crate::application::services::RefreshToken,
    ) -> Result<(), sqlx::Error> {
        self.valid_tokens.lock().unwrap().insert(token.jti);
        Ok(())
    }
    async fn revoke(&self, jti: &str) -> Result<(), sqlx::Error> {
        self.revoked_tokens.lock().unwrap().insert(jti.to_string());
        Ok(())
    }
    async fn is_valid(&self, jti: &str) -> Result<bool, sqlx::Error> {
        let valid = self.valid_tokens.lock().unwrap().contains(jti);
        let revoked = self.revoked_tokens.lock().unwrap().contains(jti);
        Ok(valid && !revoked)
    }
}

// Expected users table schema:
// CREATE TABLE users (
//   id TEXT PRIMARY KEY,
//   email TEXT UNIQUE NOT NULL,
//   password_hash TEXT NOT NULL,
//   is_locked BOOLEAN NOT NULL DEFAULT FALSE
// );
