use super::commands::LoginUserCommand;
use super::services::{AuthError, AuthService, PasswordService, TokenService};
use crate::infrastructure::{RefreshTokenRepository, UserRepository};
use std::sync::Arc;
use tracing::instrument;

pub struct LoginUserHandler;

impl LoginUserHandler {
    /// Handles the user login flow: authenticates and issues tokens.
    #[instrument(name = "login_user", skip(self, auth_service, token_service, password_service, user_repo, refresh_token_repo, cmd), fields(email = %cmd.email))]
    pub async fn handle(
        &self,
        cmd: LoginUserCommand,
        auth_service: &AuthService,
        token_service: &TokenService,
        password_service: &PasswordService,
        user_repo: Arc<dyn UserRepository>,
        refresh_token_repo: Arc<dyn RefreshTokenRepository>,
    ) -> Result<(String, String), AuthError> {
        tracing::info!("Authenticating user");
        let user = auth_service
            .authenticate_user(&cmd.email, &cmd.password, user_repo, password_service)
            .await?;
        tracing::info!(user_id = %user.id, "User authenticated, issuing tokens");
        let (access_token, refresh_token) =
            token_service.issue_tokens(&user, refresh_token_repo).await;
        tracing::info!(user_id = %user.id, "Tokens issued");
        Ok((access_token, refresh_token))
    }
}

pub struct ChangePasswordHandler;
pub struct ResetPasswordHandler;
pub struct AssignRolesHandler;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::user::User;
    use crate::infrastructure::RepoResult;
    use async_trait::async_trait;
    use bcrypt::{DEFAULT_COST, hash};
    use std::sync::Arc;

    // Mock implementations for testing
    struct MockUserRepository {
        users: std::collections::HashMap<String, User>,
    }

    impl MockUserRepository {
        fn new() -> Self {
            let mut users = std::collections::HashMap::new();
            let password_hash = hash("password123", DEFAULT_COST).unwrap();
            users.insert(
                "test@example.com".to_string(),
                User {
                    id: "user1".to_string(),
                    email: "test@example.com".to_string(),
                    password_hash,
                    roles: vec!["user".to_string()],
                    is_locked: false,
                },
            );
            Self { users }
        }
    }

    #[async_trait]
    impl UserRepository for MockUserRepository {
        async fn find_by_email(&self, email: &str) -> Option<User> {
            self.users.get(email).cloned()
        }

        async fn create_user(&self, user: User) -> RepoResult<User> {
            Ok(user)
        }

        async fn update_user(&self, _user: &User) -> RepoResult<()> {
            Ok(())
        }

        async fn update_password(
            &self,
            _user_id: &str,
            _new_password_hash: &str,
        ) -> RepoResult<()> {
            Ok(())
        }

        async fn find_by_id(&self, user_id: &str) -> RepoResult<Option<User>> {
            // For simplicity, assume user_id is email in this mock
            Ok(self.users.get(user_id).cloned())
        }
    }

    struct MockRefreshTokenRepository;

    #[async_trait]
    impl RefreshTokenRepository for MockRefreshTokenRepository {
        async fn insert(
            &self,
            _token: crate::application::services::RefreshToken,
        ) -> Result<(), sqlx::Error> {
            Ok(())
        }

        async fn revoke(&self, _jti: &str) -> Result<(), sqlx::Error> {
            Ok(())
        }

        async fn is_valid(&self, _jti: &str) -> Result<bool, sqlx::Error> {
            Ok(true)
        }
    }

    #[tokio::test]
    async fn test_login_user_handler_success() {
        // Set up test environment
        unsafe {
            std::env::set_var("JWT_SECRET", "test-secret-key-for-testing-only");
        }

        let handler = LoginUserHandler;
        let auth_service = AuthService;
        let token_service = TokenService;
        let password_service = PasswordService;
        let user_repo = Arc::new(MockUserRepository::new());
        let refresh_token_repo = Arc::new(MockRefreshTokenRepository);

        let cmd = LoginUserCommand {
            email: "test@example.com".to_string(),
            password: "password123".to_string(),
        };

        let result = handler
            .handle(
                cmd,
                &auth_service,
                &token_service,
                &password_service,
                user_repo,
                refresh_token_repo,
            )
            .await;

        assert!(result.is_ok());
        let (access_token, refresh_token) = result.unwrap();
        assert!(!access_token.is_empty());
        assert!(!refresh_token.is_empty());
        assert_ne!(access_token, refresh_token);
    }

    #[tokio::test]
    async fn test_login_user_handler_invalid_credentials() {
        let handler = LoginUserHandler;
        let auth_service = AuthService;
        let token_service = TokenService;
        let password_service = PasswordService;
        let user_repo = Arc::new(MockUserRepository::new());
        let refresh_token_repo = Arc::new(MockRefreshTokenRepository);

        let cmd = LoginUserCommand {
            email: "test@example.com".to_string(),
            password: "wrongpassword".to_string(),
        };

        let result = handler
            .handle(
                cmd,
                &auth_service,
                &token_service,
                &password_service,
                user_repo,
                refresh_token_repo,
            )
            .await;

        assert!(result.is_err());
        match result.unwrap_err() {
            AuthError::InvalidCredentials => {}
            _ => panic!("Expected InvalidCredentials error"),
        }
    }

    #[tokio::test]
    async fn test_login_user_handler_user_not_found() {
        let handler = LoginUserHandler;
        let auth_service = AuthService;
        let token_service = TokenService;
        let password_service = PasswordService;
        let user_repo = Arc::new(MockUserRepository::new());
        let refresh_token_repo = Arc::new(MockRefreshTokenRepository);

        let cmd = LoginUserCommand {
            email: "nonexistent@example.com".to_string(),
            password: "password123".to_string(),
        };

        let result = handler
            .handle(
                cmd,
                &auth_service,
                &token_service,
                &password_service,
                user_repo,
                refresh_token_repo,
            )
            .await;

        assert!(result.is_err());
        match result.unwrap_err() {
            AuthError::InvalidCredentials => {}
            _ => panic!("Expected InvalidCredentials error"),
        }
    }

    #[tokio::test]
    async fn test_login_user_handler_locked_account() {
        let handler = LoginUserHandler;
        let auth_service = AuthService;
        let token_service = TokenService;
        let password_service = PasswordService;

        // Create a repository with a locked user
        let mut user_repo = MockUserRepository::new();
        let password_hash = hash("password123", DEFAULT_COST).unwrap();
        let locked_user = User {
            id: "locked_user".to_string(),
            email: "locked@example.com".to_string(),
            password_hash,
            roles: vec!["user".to_string()],
            is_locked: true,
        };
        user_repo
            .users
            .insert("locked@example.com".to_string(), locked_user);
        let user_repo = Arc::new(user_repo);
        let refresh_token_repo = Arc::new(MockRefreshTokenRepository);

        let cmd = LoginUserCommand {
            email: "locked@example.com".to_string(),
            password: "password123".to_string(),
        };

        let result = handler
            .handle(
                cmd,
                &auth_service,
                &token_service,
                &password_service,
                user_repo,
                refresh_token_repo,
            )
            .await;

        assert!(result.is_err());
        match result.unwrap_err() {
            AuthError::AccountLocked => {}
            _ => panic!("Expected AccountLocked error"),
        }
    }
}
