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
            failed_login_attempts: 0, // Default value for existing users
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
                    failed_login_attempts: 0, // Default value for existing users
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
        .bind(false) // Default to not revoked
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::user::User;

    fn create_test_user(id: &str, email: &str) -> User {
        let mut user = User::new(
            id.to_string(),
            email.to_string(),
            "hashed_password".to_string(),
        );
        user.add_role("user".to_string());
        user
    }

    #[tokio::test]
    async fn test_in_memory_user_repository_find_by_email() {
        let user = create_test_user("user-1", "test@example.com");
        let repo = InMemoryUserRepository::new(vec![user.clone()]);

        let result = repo.find_by_email("test@example.com").await;
        assert!(result.is_some());
        let found_user = result.unwrap();
        assert_eq!(found_user.id, "user-1");
        assert_eq!(found_user.email, "test@example.com");
    }

    #[tokio::test]
    async fn test_in_memory_user_repository_find_by_email_not_found() {
        let repo = InMemoryUserRepository::new(vec![]);

        let result = repo.find_by_email("nonexistent@example.com").await;
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_in_memory_user_repository_create_user() {
        let repo = InMemoryUserRepository::new(vec![]);
        let user = create_test_user("user-1", "test@example.com");

        let result = repo.create_user(user.clone()).await;
        assert!(result.is_ok());
        let created_user = result.unwrap();
        assert_eq!(created_user.id, "user-1");
        assert_eq!(created_user.email, "test@example.com");
    }

    #[tokio::test]
    async fn test_in_memory_user_repository_create_user_duplicate() {
        let user1 = create_test_user("user-1", "test@example.com");
        let repo = InMemoryUserRepository::new(vec![user1.clone()]);
        let user2 = create_test_user("user-2", "test@example.com");

        // Should overwrite existing user with same email
        let result = repo.create_user(user2.clone()).await;
        assert!(result.is_ok());
        let created_user = result.unwrap();
        assert_eq!(created_user.id, "user-2");
        assert_eq!(created_user.email, "test@example.com");
    }

    #[tokio::test]
    async fn test_in_memory_user_repository_update_user() {
        let user = create_test_user("user-1", "test@example.com");
        let repo = InMemoryUserRepository::new(vec![user.clone()]);

        let mut updated_user = user.clone();
        updated_user.roles = vec!["admin".to_string()];

        let result = repo.update_user(&updated_user).await;
        assert!(result.is_ok());

        // Verify user was updated
        let found_user = repo.find_by_email("test@example.com").await.unwrap();
        assert_eq!(found_user.roles, vec!["admin".to_string()]);
    }

    #[tokio::test]
    async fn test_in_memory_user_repository_update_user_not_found() {
        let repo = InMemoryUserRepository::new(vec![]);
        let user = create_test_user("user-1", "test@example.com");

        let result = repo.update_user(&user).await;
        assert!(result.is_ok()); // In-memory repo creates user if not found
    }

    #[tokio::test]
    async fn test_in_memory_user_repository_update_password() {
        let user = create_test_user("user-1", "test@example.com");
        let repo = InMemoryUserRepository::new(vec![user.clone()]);

        let result = repo.update_password("user-1", "new_hashed_password").await;
        assert!(result.is_ok());

        // Verify password was updated
        let found_user = repo.find_by_email("test@example.com").await.unwrap();
        assert_eq!(found_user.password_hash, "new_hashed_password");
    }

    #[tokio::test]
    async fn test_in_memory_user_repository_update_password_not_found() {
        let repo = InMemoryUserRepository::new(vec![]);

        let result = repo.update_password("nonexistent-user", "new_hashed_password").await;
        assert!(result.is_ok()); // In-memory repo doesn't error on non-existent user
    }

    #[tokio::test]
    async fn test_in_memory_user_repository_find_by_id() {
        let user = create_test_user("user-1", "test@example.com");
        let repo = InMemoryUserRepository::new(vec![user.clone()]);

        let result = repo.find_by_id("user-1").await;
        assert!(result.is_ok());
        let found_user = result.unwrap().unwrap();
        assert_eq!(found_user.id, "user-1");
        assert_eq!(found_user.email, "test@example.com");
    }

    #[tokio::test]
    async fn test_in_memory_user_repository_find_by_id_not_found() {
        let repo = InMemoryUserRepository::new(vec![]);

        let result = repo.find_by_id("nonexistent-user").await;
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_in_memory_user_repository_multiple_users() {
        let user1 = create_test_user("user-1", "user1@example.com");
        let user2 = create_test_user("user-2", "user2@example.com");
        let repo = InMemoryUserRepository::new(vec![user1.clone(), user2.clone()]);

        // Find by email
        let found_user1 = repo.find_by_email("user1@example.com").await.unwrap();
        assert_eq!(found_user1.id, "user-1");

        let found_user2 = repo.find_by_email("user2@example.com").await.unwrap();
        assert_eq!(found_user2.id, "user-2");

        // Find by ID
        let found_user1_by_id = repo.find_by_id("user-1").await.unwrap().unwrap();
        assert_eq!(found_user1_by_id.email, "user1@example.com");

        let found_user2_by_id = repo.find_by_id("user-2").await.unwrap().unwrap();
        assert_eq!(found_user2_by_id.email, "user2@example.com");
    }

    #[tokio::test]
    async fn test_in_memory_user_repository_empty() {
        let repo = InMemoryUserRepository::new(vec![]);

        // Find by email
        let result = repo.find_by_email("test@example.com").await;
        assert!(result.is_none());

        // Find by ID
        let result = repo.find_by_id("user-1").await;
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }

    // Refresh Token Repository Tests
    #[tokio::test]
    async fn test_in_memory_refresh_token_repository_insert() {
        let repo = InMemoryRefreshTokenRepository::new();
        let token = crate::application::services::RefreshToken {
            jti: "token-1".to_string(),
            user_id: "user-1".to_string(),
            expires_at: chrono::Utc::now() + chrono::Duration::hours(1),
        };

        let result = repo.insert(token).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_in_memory_refresh_token_repository_is_valid() {
        let repo = InMemoryRefreshTokenRepository::new();
        let token = crate::application::services::RefreshToken {
            jti: "token-1".to_string(),
            user_id: "user-1".to_string(),
            expires_at: chrono::Utc::now() + chrono::Duration::hours(1),
        };

        // Insert token
        repo.insert(token).await.unwrap();

        // Check if valid
        let result = repo.is_valid("token-1").await;
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[tokio::test]
    async fn test_in_memory_refresh_token_repository_is_valid_not_found() {
        let repo = InMemoryRefreshTokenRepository::new();

        let result = repo.is_valid("nonexistent-token").await;
        assert!(result.is_ok());
        assert!(!result.unwrap());
    }

    #[tokio::test]
    async fn test_in_memory_refresh_token_repository_revoke() {
        let repo = InMemoryRefreshTokenRepository::new();
        let token = crate::application::services::RefreshToken {
            jti: "token-1".to_string(),
            user_id: "user-1".to_string(),
            expires_at: chrono::Utc::now() + chrono::Duration::hours(1),
        };

        // Insert token
        repo.insert(token).await.unwrap();

        // Verify token is valid
        let result = repo.is_valid("token-1").await;
        assert!(result.unwrap());

        // Revoke token
        let result = repo.revoke("token-1").await;
        assert!(result.is_ok());

        // Verify token is no longer valid
        let result = repo.is_valid("token-1").await;
        assert!(result.is_ok());
        assert!(!result.unwrap());
    }

    #[tokio::test]
    async fn test_in_memory_refresh_token_repository_revoke_not_found() {
        let repo = InMemoryRefreshTokenRepository::new();

        let result = repo.revoke("nonexistent-token").await;
        assert!(result.is_ok()); // Revoking non-existent token doesn't error
    }

    #[tokio::test]
    async fn test_in_memory_refresh_token_repository_default_implementation() {
        let repo = InMemoryRefreshTokenRepository::default();

        // Test that default creates an empty repository
        let result = repo.is_valid("any-token").await;
        assert!(result.is_ok());
        assert!(!result.unwrap());
    }

    #[tokio::test]
    async fn test_in_memory_refresh_token_repository_multiple_tokens() {
        let repo = InMemoryRefreshTokenRepository::new();
        let token1 = crate::application::services::RefreshToken {
            jti: "token-1".to_string(),
            user_id: "user-1".to_string(),
            expires_at: chrono::Utc::now() + chrono::Duration::hours(1),
        };
        let token2 = crate::application::services::RefreshToken {
            jti: "token-2".to_string(),
            user_id: "user-2".to_string(),
            expires_at: chrono::Utc::now() + chrono::Duration::hours(1),
        };

        // Insert tokens
        repo.insert(token1).await.unwrap();
        repo.insert(token2).await.unwrap();

        // Verify both tokens are valid
        assert!(repo.is_valid("token-1").await.unwrap());
        assert!(repo.is_valid("token-2").await.unwrap());

        // Revoke one token
        repo.revoke("token-1").await.unwrap();

        // Verify only one token is still valid
        assert!(!repo.is_valid("token-1").await.unwrap());
        assert!(repo.is_valid("token-2").await.unwrap());
    }
}
