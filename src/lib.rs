pub mod application;
pub mod domain;
pub mod infrastructure;
pub mod interface;
pub mod test_utils;

use application::{
    command_bus::CommandBus,
    command_handlers::{
        AssignAbacPolicyToUserCommandHandler, AssignPermissionsToRoleCommandHandler,
        AssignRolesCommandHandler, AuthenticateUserCommandHandler, ChangePasswordCommandHandler,
        CreateAbacPolicyCommandHandler, CreatePermissionCommandHandler,
        CreatePermissionGroupCommandHandler, CreateRoleCommandHandler, CreateUserCommandHandler,
        DeleteAbacPolicyCommandHandler, DeletePermissionCommandHandler,
        DeletePermissionGroupCommandHandler, DeleteRoleCommandHandler,
        EvaluateAbacPoliciesCommandHandler, LogoutCommandHandler, RefreshTokenCommandHandler,
        RemovePermissionsFromRoleCommandHandler, RemoveRolesFromUserCommandHandler,
        ResetPasswordCommandHandler, SetParentRoleCommandHandler, ToggleUserLockCommandHandler,
        UpdateAbacPolicyCommandHandler, UpdatePermissionCommandHandler,
        UpdatePermissionGroupCommandHandler, UpdateRoleCommandHandler,
        UpdateUserProfileCommandHandler, ValidateTokenCommandHandler,
    },
    commands::{
        AssignAbacPolicyToUserCommand, AssignPermissionsToRoleCommand, AssignRolesCommand,
        AuthenticateUserCommand, ChangePasswordCommand, CreateAbacPolicyCommand,
        CreatePermissionCommand, CreatePermissionGroupCommand, CreateRoleCommand,
        CreateUserCommand, DeleteAbacPolicyCommand, DeletePermissionCommand,
        DeletePermissionGroupCommand, DeleteRoleCommand, EvaluateAbacPoliciesCommand,
        LogoutCommand, RefreshTokenCommand, RemovePermissionsFromRoleCommand,
        RemoveRolesFromUserCommand, ResetPasswordCommand, SetParentRoleCommand,
        ToggleUserLockCommand, UpdateAbacPolicyCommand, UpdatePermissionCommand,
        UpdatePermissionGroupCommand, UpdateRoleCommand, UpdateUserProfileCommand,
        ValidateTokenCommand,
    },
    queries::{
        CheckPermissionQuery, CheckUserPermissionQuery, GetPermissionByIdQuery,
        GetPermissionGroupQuery, GetPermissionsForUserQuery, GetPermissionsInGroupQuery,
        GetRoleByIdQuery, GetRoleHierarchyQuery, GetRolePermissionsQuery, GetRolesForUserQuery,
        GetUserAuditEventsQuery, GetUserByIdQuery, ListAbacPoliciesQuery,
        ListPermissionGroupsQuery, ListPermissionsQuery, ListRoleHierarchiesQuery, ListRolesQuery,
        ListUsersQuery,
    },
    query_bus::QueryBus,
    query_handlers::{
        CheckPermissionQueryHandler, CheckUserPermissionQueryHandler,
        GetPermissionByIdQueryHandler, GetPermissionGroupQueryHandler,
        GetPermissionsForUserQueryHandler, GetPermissionsInGroupQueryHandler,
        GetRoleByIdQueryHandler, GetRoleHierarchyQueryHandler, GetRolePermissionsQueryHandler,
        GetRolesForUserQueryHandler, GetUserAuditEventsQueryHandler, GetUserByIdQueryHandler,
        ListAbacPoliciesQueryHandler, ListPermissionGroupsQueryHandler,
        ListPermissionsQueryHandler, ListRoleHierarchiesQueryHandler, ListRolesQueryHandler,
        ListUsersQueryHandler,
    },
    services::{AuthorizationService, PasswordResetService, PasswordService, TokenService},
};
use infrastructure::{
    AbacPolicyRepository, PermissionGroupRepository, PermissionRepository,
    PostgresAbacPolicyRepository, PostgresPermissionGroupRepository, PostgresPermissionRepository,
    PostgresRefreshTokenRepository, PostgresRoleRepository, PostgresUserRepository,
    RefreshTokenRepository, RoleRepository, UserRepository,
};
use interface::AppState;
use sqlx::PgPool;
use std::sync::Arc;

// ============================================================================
// CONFIGURATION STRUCTURES
// ============================================================================

/// Application configuration with all environment variables
#[derive(Debug, Clone, PartialEq)]
pub struct AppConfig {
    pub database_url: String,
    pub http_host: String,
    pub http_port: String,
    pub api_mode: String,
}

impl AppConfig {
    /// Creates a new AppConfig from environment variables
    pub fn from_env() -> Result<Self, ConfigError> {
        let database_url = std::env::var("DATABASE_URL")
            .unwrap_or_else(|_| "postgresql://test:test@localhost:5432/testdb".to_string());

        let http_host = std::env::var("HTTP_HOST").unwrap_or_else(|_| "127.0.0.1".to_string());
        let http_port = std::env::var("HTTP_PORT").unwrap_or_else(|_| "8080".to_string());
        let api_mode = std::env::var("API_MODE").unwrap_or_else(|_| "both".to_string());

        Ok(AppConfig {
            database_url,
            http_host,
            http_port,
            api_mode,
        })
    }

    /// Creates an AppConfig with custom values (useful for testing)
    pub fn new(
        database_url: String,
        http_host: String,
        http_port: String,
        api_mode: String,
    ) -> Self {
        Self {
            database_url,
            http_host,
            http_port,
            api_mode,
        }
    }

    /// Creates the HTTP address string from host and port
    pub fn http_address(&self) -> String {
        format!("{}:{}", self.http_host, self.http_port)
    }

    /// Determines the server type based on API mode
    pub fn server_type(&self) -> &'static str {
        match self.api_mode.as_str() {
            "http" => "http_server",
            "grpc" => "grpc_server",
            "both" => "both_server",
            _ => "default_server",
        }
    }
}

/// Configuration error types
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("Missing required environment variable: {0}")]
    MissingRequired(String),
    #[error("Invalid configuration: {0}")]
    Invalid(String),
}

// ============================================================================
// APPLICATION BUILDER
// ============================================================================

/// Builder for creating application state with better testability
#[derive(Debug, Default)]
pub struct AppStateBuilder {
    pool: Option<PgPool>,
    config: Option<AppConfig>,
}

impl AppStateBuilder {
    /// Creates a new AppStateBuilder
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the database pool
    pub fn with_pool(mut self, pool: PgPool) -> Self {
        self.pool = Some(pool);
        self
    }

    /// Sets the configuration
    pub fn with_config(mut self, config: AppConfig) -> Self {
        self.config = Some(config);
        self
    }

    /// Builds the application state
    pub async fn build(self) -> Result<Arc<AppState>, AppError> {
        let pool = self.pool.ok_or(AppError::MissingPool)?;

        // Create repositories
        let user_repo =
            Arc::new(PostgresUserRepository::new(pool.clone())) as Arc<dyn UserRepository>;
        let refresh_token_repo = Arc::new(PostgresRefreshTokenRepository::new(pool.clone()))
            as Arc<dyn RefreshTokenRepository>;
        let role_repo =
            Arc::new(PostgresRoleRepository::new(pool.clone())) as Arc<dyn RoleRepository>;
        let permission_repo = Arc::new(PostgresPermissionRepository::new(pool.clone()))
            as Arc<dyn PermissionRepository>;
        let permission_group_repo = Arc::new(PostgresPermissionGroupRepository::new(pool.clone()))
            as Arc<dyn PermissionGroupRepository>;
        let abac_policy_repo = Arc::new(PostgresAbacPolicyRepository::new(pool.clone()))
            as Arc<dyn AbacPolicyRepository>;

        // Create services
        let token_service = Arc::new(TokenService);
        let password_service = Arc::new(PasswordService);
        let password_reset_service = Arc::new(PasswordResetService);
        let authorization_service = Arc::new(AuthorizationService);

        // Create CQRS buses
        let command_bus = Arc::new(CommandBus::new());
        let query_bus = Arc::new(QueryBus::new());

        // Register command handlers
        Self::register_command_handlers(
            &command_bus,
            &user_repo,
            &role_repo,
            &permission_repo,
            &permission_group_repo,
            &abac_policy_repo,
            &refresh_token_repo,
        )
        .await;

        // Register query handlers
        Self::register_query_handlers(
            &query_bus,
            &user_repo,
            &role_repo,
            &permission_repo,
            &permission_group_repo,
            &abac_policy_repo,
        )
        .await;

        // Create and return AppState
        Ok(Arc::new(AppState {
            user_repo,
            role_repo,
            permission_repo,
            abac_policy_repo,
            permission_group_repo,
            refresh_token_repo,
            token_service,
            password_service,
            password_reset_service,
            authorization_service,
            command_bus,
            query_bus,
        }))
    }

    /// Registers all command handlers
    async fn register_command_handlers(
        command_bus: &Arc<CommandBus>,
        user_repo: &Arc<dyn UserRepository>,
        role_repo: &Arc<dyn RoleRepository>,
        permission_repo: &Arc<dyn PermissionRepository>,
        permission_group_repo: &Arc<dyn PermissionGroupRepository>,
        abac_policy_repo: &Arc<dyn AbacPolicyRepository>,
        refresh_token_repo: &Arc<dyn RefreshTokenRepository>,
    ) {
        command_bus
            .register_handler::<AuthenticateUserCommand, _>(AuthenticateUserCommandHandler::new(
                user_repo.clone(),
            ))
            .await;

        command_bus
            .register_handler::<CreateUserCommand, _>(CreateUserCommandHandler::new(
                user_repo.clone(),
                role_repo.clone(),
            ))
            .await;

        command_bus
            .register_handler::<ChangePasswordCommand, _>(ChangePasswordCommandHandler::new(
                user_repo.clone(),
            ))
            .await;

        command_bus
            .register_handler::<AssignRolesCommand, _>(AssignRolesCommandHandler::new(
                role_repo.clone(),
                user_repo.clone(),
            ))
            .await;

        command_bus
            .register_handler::<CreatePermissionCommand, _>(CreatePermissionCommandHandler::new(
                permission_repo.clone(),
                permission_group_repo.clone(),
            ))
            .await;

        command_bus
            .register_handler::<DeletePermissionCommand, _>(DeletePermissionCommandHandler::new(
                permission_repo.clone(),
            ))
            .await;

        command_bus
            .register_handler::<RemovePermissionsFromRoleCommand, _>(
                RemovePermissionsFromRoleCommandHandler::new(
                    role_repo.clone(),
                    permission_repo.clone(),
                ),
            )
            .await;

        command_bus
            .register_handler::<RemoveRolesFromUserCommand, _>(
                RemoveRolesFromUserCommandHandler::new(role_repo.clone(), user_repo.clone()),
            )
            .await;

        command_bus
            .register_handler::<DeleteRoleCommand, _>(DeleteRoleCommandHandler::new(
                role_repo.clone(),
            ))
            .await;

        command_bus
            .register_handler::<CreateAbacPolicyCommand, _>(CreateAbacPolicyCommandHandler::new(
                abac_policy_repo.clone(),
            ))
            .await;

        command_bus
            .register_handler::<UpdateAbacPolicyCommand, _>(UpdateAbacPolicyCommandHandler::new(
                abac_policy_repo.clone(),
            ))
            .await;

        command_bus
            .register_handler::<DeleteAbacPolicyCommand, _>(DeleteAbacPolicyCommandHandler::new(
                abac_policy_repo.clone(),
            ))
            .await;

        command_bus
            .register_handler::<AssignAbacPolicyToUserCommand, _>(
                AssignAbacPolicyToUserCommandHandler::new(abac_policy_repo.clone()),
            )
            .await;

        command_bus
            .register_handler::<CreatePermissionGroupCommand, _>(
                CreatePermissionGroupCommandHandler::new(permission_group_repo.clone()),
            )
            .await;

        command_bus
            .register_handler::<UpdatePermissionGroupCommand, _>(
                UpdatePermissionGroupCommandHandler::new(permission_group_repo.clone()),
            )
            .await;

        command_bus
            .register_handler::<DeletePermissionGroupCommand, _>(
                DeletePermissionGroupCommandHandler::new(permission_group_repo.clone()),
            )
            .await;

        command_bus
            .register_handler::<CreateRoleCommand, _>(CreateRoleCommandHandler::new(
                role_repo.clone(),
            ))
            .await;

        command_bus
            .register_handler::<AssignPermissionsToRoleCommand, _>(
                AssignPermissionsToRoleCommandHandler::new(
                    role_repo.clone(),
                    permission_repo.clone(),
                ),
            )
            .await;

        command_bus
            .register_handler::<UpdateUserProfileCommand, _>(UpdateUserProfileCommandHandler::new(
                user_repo.clone(),
            ))
            .await;

        command_bus
            .register_handler::<ToggleUserLockCommand, _>(ToggleUserLockCommandHandler::new(
                user_repo.clone(),
            ))
            .await;

        command_bus
            .register_handler::<ResetPasswordCommand, _>(ResetPasswordCommandHandler::new(
                user_repo.clone(),
            ))
            .await;

        command_bus
            .register_handler::<ValidateTokenCommand, _>(ValidateTokenCommandHandler::new())
            .await;

        command_bus
            .register_handler::<RefreshTokenCommand, _>(RefreshTokenCommandHandler::new(
                user_repo.clone(),
                refresh_token_repo.clone(),
            ))
            .await;

        command_bus
            .register_handler::<LogoutCommand, _>(LogoutCommandHandler::new(
                refresh_token_repo.clone(),
            ))
            .await;

        command_bus
            .register_handler::<EvaluateAbacPoliciesCommand, _>(
                EvaluateAbacPoliciesCommandHandler::new(abac_policy_repo.clone()),
            )
            .await;

        command_bus
            .register_handler::<SetParentRoleCommand, _>(SetParentRoleCommandHandler::new(
                role_repo.clone(),
            ))
            .await;

        command_bus
            .register_handler::<UpdateRoleCommand, _>(UpdateRoleCommandHandler::new(
                role_repo.clone(),
            ))
            .await;

        command_bus
            .register_handler::<UpdatePermissionCommand, _>(UpdatePermissionCommandHandler::new(
                permission_repo.clone(),
            ))
            .await;
    }

    /// Registers all query handlers
    async fn register_query_handlers(
        query_bus: &Arc<QueryBus>,
        user_repo: &Arc<dyn UserRepository>,
        role_repo: &Arc<dyn RoleRepository>,
        permission_repo: &Arc<dyn PermissionRepository>,
        permission_group_repo: &Arc<dyn PermissionGroupRepository>,
        abac_policy_repo: &Arc<dyn AbacPolicyRepository>,
    ) {
        query_bus
            .register_handler::<GetUserByIdQuery, _>(GetUserByIdQueryHandler::new(
                user_repo.clone(),
                role_repo.clone(),
                permission_repo.clone(),
            ))
            .await;

        query_bus
            .register_handler::<CheckPermissionQuery, _>(CheckPermissionQueryHandler::new(
                role_repo.clone(),
                permission_repo.clone(),
                abac_policy_repo.clone(),
            ))
            .await;

        query_bus
            .register_handler::<GetRolesForUserQuery, _>(GetRolesForUserQueryHandler::new(
                role_repo.clone(),
            ))
            .await;

        query_bus
            .register_handler::<CheckUserPermissionQuery, _>(CheckUserPermissionQueryHandler::new(
                role_repo.clone(),
                permission_repo.clone(),
                abac_policy_repo.clone(),
            ))
            .await;

        query_bus
            .register_handler::<ListUsersQuery, _>(ListUsersQueryHandler::new(
                user_repo.clone(),
                role_repo.clone(),
            ))
            .await;

        query_bus
            .register_handler::<ListRolesQuery, _>(ListRolesQueryHandler::new(
                role_repo.clone(),
                permission_repo.clone(),
            ))
            .await;

        query_bus
            .register_handler::<ListPermissionsQuery, _>(ListPermissionsQueryHandler::new(
                permission_repo.clone(),
                permission_group_repo.clone(),
            ))
            .await;

        query_bus
            .register_handler::<GetPermissionsForUserQuery, _>(
                GetPermissionsForUserQueryHandler::new(
                    role_repo.clone(),
                    permission_repo.clone(),
                    abac_policy_repo.clone(),
                ),
            )
            .await;

        query_bus
            .register_handler::<GetUserAuditEventsQuery, _>(GetUserAuditEventsQueryHandler::new())
            .await;

        query_bus
            .register_handler::<ListAbacPoliciesQuery, _>(ListAbacPoliciesQueryHandler::new(
                abac_policy_repo.clone(),
            ))
            .await;

        query_bus
            .register_handler::<ListPermissionGroupsQuery, _>(
                ListPermissionGroupsQueryHandler::new(permission_group_repo.clone()),
            )
            .await;

        query_bus
            .register_handler::<GetPermissionGroupQuery, _>(GetPermissionGroupQueryHandler::new(
                permission_group_repo.clone(),
            ))
            .await;

        query_bus
            .register_handler::<GetRoleHierarchyQuery, _>(GetRoleHierarchyQueryHandler::new(
                role_repo.clone(),
            ))
            .await;

        query_bus
            .register_handler::<ListRoleHierarchiesQuery, _>(ListRoleHierarchiesQueryHandler::new(
                role_repo.clone(),
            ))
            .await;

        query_bus
            .register_handler::<GetPermissionsInGroupQuery, _>(
                GetPermissionsInGroupQueryHandler::new(permission_group_repo.clone()),
            )
            .await;

        query_bus
            .register_handler::<GetRolePermissionsQuery, _>(GetRolePermissionsQueryHandler::new(
                permission_repo.clone(),
            ))
            .await;

        query_bus
            .register_handler::<GetRoleByIdQuery, _>(GetRoleByIdQueryHandler::new(
                role_repo.clone(),
                permission_repo.clone(),
            ))
            .await;

        query_bus
            .register_handler::<GetPermissionByIdQuery, _>(GetPermissionByIdQueryHandler::new(
                permission_repo.clone(),
            ))
            .await;
    }
}

/// Application error types
#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("Missing database pool")]
    MissingPool,
    #[error("Configuration error: {0}")]
    Config(#[from] ConfigError),
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),
    #[error("Initialization error: {0}")]
    Initialization(String),
}

// ============================================================================
// TESTING UTILITIES
// ============================================================================

#[cfg(test)]
pub mod test_helpers {
    use super::*;
    use sqlx::PgPool;

    /// Creates a test configuration
    pub fn create_test_config() -> AppConfig {
        AppConfig::new(
            "postgresql://test:test@localhost:5432/testdb".to_string(),
            "127.0.0.1".to_string(),
            "8080".to_string(),
            "both".to_string(),
        )
    }

    /// Creates a test application state with in-memory repositories
    pub async fn create_test_app_state() -> Arc<AppState> {
        use crate::test_utils::create_test_app_state as create_in_memory_app_state;
        create_in_memory_app_state().await
    }

    /// Creates a test application state with database pool
    pub async fn create_test_app_state_with_pool(pool: PgPool) -> Result<Arc<AppState>, AppError> {
        AppStateBuilder::new()
            .with_pool(pool)
            .with_config(create_test_config())
            .build()
            .await
    }

    /// Sets up test environment variables
    pub fn setup_test_env() {
        unsafe {
            std::env::set_var(
                "DATABASE_URL",
                "postgresql://test:test@localhost:5432/testdb",
            );
            std::env::set_var("HTTP_HOST", "127.0.0.1");
            std::env::set_var("HTTP_PORT", "8080");
            std::env::set_var("API_MODE", "both");
            std::env::set_var("JWT_SECRET", "test-secret-key-for-testing-only");
            std::env::set_var("JWT_EXPIRATION", "1");
            std::env::set_var("JWT_TIME_UNIT", "hours");
        }
    }

    /// Cleans up test environment variables
    pub fn cleanup_test_env() {
        unsafe {
            std::env::remove_var("DATABASE_URL");
            std::env::remove_var("HTTP_HOST");
            std::env::remove_var("HTTP_PORT");
            std::env::remove_var("API_MODE");
            std::env::remove_var("JWT_SECRET");
            std::env::remove_var("JWT_EXPIRATION");
            std::env::remove_var("JWT_TIME_UNIT");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::PgPool;

    #[test]
    fn test_app_config_new() {
        let config = AppConfig::new(
            "test_url".to_string(),
            "test_host".to_string(),
            "test_port".to_string(),
            "test_mode".to_string(),
        );

        assert_eq!(config.database_url, "test_url");
        assert_eq!(config.http_host, "test_host");
        assert_eq!(config.http_port, "test_port");
        assert_eq!(config.api_mode, "test_mode");
    }

    #[test]
    fn test_app_config_http_address() {
        let config = AppConfig::new(
            "test_url".to_string(),
            "localhost".to_string(),
            "8080".to_string(),
            "both".to_string(),
        );

        assert_eq!(config.http_address(), "localhost:8080");
    }

    #[test]
    fn test_app_config_server_type() {
        let config = AppConfig::new(
            "test_url".to_string(),
            "test_host".to_string(),
            "test_port".to_string(),
            "http".to_string(),
        );
        assert_eq!(config.server_type(), "http_server");

        let config = AppConfig::new(
            "test_url".to_string(),
            "test_host".to_string(),
            "test_port".to_string(),
            "grpc".to_string(),
        );
        assert_eq!(config.server_type(), "grpc_server");

        let config = AppConfig::new(
            "test_url".to_string(),
            "test_host".to_string(),
            "test_port".to_string(),
            "both".to_string(),
        );
        assert_eq!(config.server_type(), "both_server");

        let config = AppConfig::new(
            "test_url".to_string(),
            "test_host".to_string(),
            "test_port".to_string(),
            "invalid".to_string(),
        );
        assert_eq!(config.server_type(), "default_server");
    }

    #[test]
    fn test_app_config_from_env() {
        test_helpers::setup_test_env();

        let config = AppConfig::from_env().unwrap();
        assert_eq!(
            config.database_url,
            "postgresql://test:test@localhost:5432/testdb"
        );
        assert_eq!(config.http_host, "127.0.0.1");
        assert_eq!(config.http_port, "8080");
        assert_eq!(config.api_mode, "both");

        test_helpers::cleanup_test_env();
    }

    #[test]
    fn test_app_config_from_env_with_defaults() {
        // Set only the required DATABASE_URL
        unsafe {
            std::env::set_var(
                "DATABASE_URL",
                "postgresql://test:test@localhost:5432/testdb",
            );
            std::env::remove_var("HTTP_HOST");
            std::env::remove_var("HTTP_PORT");
            std::env::remove_var("API_MODE");
        }

        let config = AppConfig::from_env().unwrap();
        assert_eq!(
            config.database_url,
            "postgresql://test:test@localhost:5432/testdb"
        );
        assert_eq!(config.http_host, "127.0.0.1"); // default value
        assert_eq!(config.http_port, "8080"); // default value
        assert_eq!(config.api_mode, "both"); // default value

        // Clean up
        unsafe {
            std::env::remove_var("DATABASE_URL");
        }
    }

    #[test]
    fn test_app_config_from_env_missing_required() {
        test_helpers::cleanup_test_env();

        let result = AppConfig::from_env();
        assert!(matches!(result, Err(ConfigError::MissingRequired(_))));
    }

    #[test]
    fn test_app_state_builder_new() {
        let builder = AppStateBuilder::new();
        assert!(builder.pool.is_none());
        assert!(builder.config.is_none());
    }

    #[test]
    fn test_app_state_builder_default() {
        let builder = AppStateBuilder::default();
        assert!(builder.pool.is_none());
        assert!(builder.config.is_none());
    }

    #[tokio::test]
    async fn test_app_state_builder_with_pool() {
        let pool = PgPool::connect_lazy("postgresql://test:test@localhost:5432/testdb").unwrap();
        let builder = AppStateBuilder::new().with_pool(pool);
        assert!(builder.pool.is_some());
        assert!(builder.config.is_none());
    }

    #[test]
    fn test_app_state_builder_with_config() {
        let config = AppConfig::new(
            "test_url".to_string(),
            "test_host".to_string(),
            "test_port".to_string(),
            "test_mode".to_string(),
        );

        let builder = AppStateBuilder::new().with_config(config.clone());
        assert!(builder.config.is_some());
        assert_eq!(builder.config.unwrap(), config);
    }

    #[tokio::test]
    async fn test_app_state_builder_chaining() {
        let config = AppConfig::new(
            "test_url".to_string(),
            "test_host".to_string(),
            "test_port".to_string(),
            "test_mode".to_string(),
        );
        let pool = PgPool::connect_lazy("postgresql://test:test@localhost:5432/testdb").unwrap();

        let builder = AppStateBuilder::new()
            .with_config(config.clone())
            .with_pool(pool);

        assert!(builder.pool.is_some());
        assert!(builder.config.is_some());
        assert_eq!(builder.config.unwrap(), config);
    }

    #[tokio::test]
    async fn test_app_state_builder_build_missing_pool() {
        let builder = AppStateBuilder::new();
        let result = builder.build().await;
        assert!(matches!(result, Err(AppError::MissingPool)));
    }

    #[tokio::test]
    async fn test_app_state_builder_build_success() {
        let pool = PgPool::connect_lazy("postgresql://test:test@localhost:5432/testdb").unwrap();
        let config = AppConfig::new(
            "postgresql://test:test@localhost:5432/testdb".to_string(),
            "127.0.0.1".to_string(),
            "8080".to_string(),
            "both".to_string(),
        );

        let result = AppStateBuilder::new()
            .with_pool(pool)
            .with_config(config)
            .build()
            .await;

        assert!(result.is_ok());
        let app_state = result.unwrap();

        // Verify all components are initialized
        assert!(Arc::ptr_eq(&app_state.user_repo, &app_state.user_repo));
        assert!(Arc::ptr_eq(&app_state.role_repo, &app_state.role_repo));
        assert!(Arc::ptr_eq(
            &app_state.permission_repo,
            &app_state.permission_repo
        ));
        assert!(Arc::ptr_eq(
            &app_state.abac_policy_repo,
            &app_state.abac_policy_repo
        ));
        assert!(Arc::ptr_eq(
            &app_state.permission_group_repo,
            &app_state.permission_group_repo
        ));
        assert!(Arc::ptr_eq(
            &app_state.refresh_token_repo,
            &app_state.refresh_token_repo
        ));
        assert!(Arc::ptr_eq(
            &app_state.token_service,
            &app_state.token_service
        ));
        assert!(Arc::ptr_eq(
            &app_state.password_service,
            &app_state.password_service
        ));
        assert!(Arc::ptr_eq(
            &app_state.password_reset_service,
            &app_state.password_reset_service
        ));
        assert!(Arc::ptr_eq(
            &app_state.authorization_service,
            &app_state.authorization_service
        ));
        assert!(Arc::ptr_eq(&app_state.command_bus, &app_state.command_bus));
        assert!(Arc::ptr_eq(&app_state.query_bus, &app_state.query_bus));
    }

    #[test]
    fn test_config_error_display() {
        let error = ConfigError::MissingRequired("DATABASE_URL".to_string());
        assert_eq!(
            error.to_string(),
            "Missing required environment variable: DATABASE_URL"
        );

        let error = ConfigError::Invalid("Invalid database URL".to_string());
        assert_eq!(
            error.to_string(),
            "Invalid configuration: Invalid database URL"
        );
    }

    #[test]
    fn test_app_error_display() {
        let error = AppError::MissingPool;
        assert_eq!(error.to_string(), "Missing database pool");

        let error = AppError::Config(ConfigError::MissingRequired("DATABASE_URL".to_string()));
        assert_eq!(
            error.to_string(),
            "Configuration error: Missing required environment variable: DATABASE_URL"
        );

        let error = AppError::Database(sqlx::Error::Configuration("test error".into()));
        assert!(error.to_string().contains("Database error:"));

        let error = AppError::Initialization("Failed to start server".to_string());
        assert_eq!(
            error.to_string(),
            "Initialization error: Failed to start server"
        );
    }

    #[test]
    fn test_app_error_from_config_error() {
        let config_error = ConfigError::MissingRequired("TEST".to_string());
        let app_error: AppError = config_error.into();
        match app_error {
            AppError::Config(ConfigError::MissingRequired(msg)) => {
                assert_eq!(msg, "TEST");
            }
            _ => panic!("Expected ConfigError variant"),
        }
    }

    #[test]
    fn test_app_error_from_sqlx_error() {
        let sqlx_error = sqlx::Error::Configuration("test config error".into());
        let app_error: AppError = sqlx_error.into();
        match app_error {
            AppError::Database(_) => {}
            _ => panic!("Expected DatabaseError variant"),
        }
    }

    #[test]
    fn test_test_helpers_create_test_config() {
        let config = test_helpers::create_test_config();
        assert_eq!(
            config.database_url,
            "postgresql://test:test@localhost:5432/testdb"
        );
        assert_eq!(config.http_host, "127.0.0.1");
        assert_eq!(config.http_port, "8080");
        assert_eq!(config.api_mode, "both");
    }

    #[test]
    fn test_test_helpers_setup_and_cleanup_env() {
        // Test setup
        test_helpers::setup_test_env();
        assert_eq!(
            std::env::var("DATABASE_URL").unwrap(),
            "postgresql://test:test@localhost:5432/testdb"
        );
        assert_eq!(std::env::var("HTTP_HOST").unwrap(), "127.0.0.1");
        assert_eq!(std::env::var("HTTP_PORT").unwrap(), "8080");
        assert_eq!(std::env::var("API_MODE").unwrap(), "both");
        assert_eq!(
            std::env::var("JWT_SECRET").unwrap(),
            "test-secret-key-for-testing-only"
        );
        assert_eq!(std::env::var("JWT_EXPIRATION").unwrap(), "1");
        assert_eq!(std::env::var("JWT_TIME_UNIT").unwrap(), "hours");

        // Test cleanup
        test_helpers::cleanup_test_env();
        assert!(std::env::var("DATABASE_URL").is_err());
        assert!(std::env::var("HTTP_HOST").is_err());
        assert!(std::env::var("HTTP_PORT").is_err());
        assert!(std::env::var("API_MODE").is_err());
        assert!(std::env::var("JWT_SECRET").is_err());
        assert!(std::env::var("JWT_EXPIRATION").is_err());
        assert!(std::env::var("JWT_TIME_UNIT").is_err());
    }

    #[tokio::test]
    async fn test_test_helpers_create_test_app_state() {
        let app_state = test_helpers::create_test_app_state().await;
        assert!(Arc::ptr_eq(&app_state.user_repo, &app_state.user_repo));
        assert!(Arc::ptr_eq(&app_state.role_repo, &app_state.role_repo));
        assert!(Arc::ptr_eq(
            &app_state.permission_repo,
            &app_state.permission_repo
        ));
        assert!(Arc::ptr_eq(
            &app_state.abac_policy_repo,
            &app_state.abac_policy_repo
        ));
        assert!(Arc::ptr_eq(
            &app_state.permission_group_repo,
            &app_state.permission_group_repo
        ));
        assert!(Arc::ptr_eq(
            &app_state.refresh_token_repo,
            &app_state.refresh_token_repo
        ));
        assert!(Arc::ptr_eq(
            &app_state.token_service,
            &app_state.token_service
        ));
        assert!(Arc::ptr_eq(
            &app_state.password_service,
            &app_state.password_service
        ));
        assert!(Arc::ptr_eq(
            &app_state.password_reset_service,
            &app_state.password_reset_service
        ));
        assert!(Arc::ptr_eq(
            &app_state.authorization_service,
            &app_state.authorization_service
        ));
        assert!(Arc::ptr_eq(&app_state.command_bus, &app_state.command_bus));
        assert!(Arc::ptr_eq(&app_state.query_bus, &app_state.query_bus));
    }

    #[tokio::test]
    async fn test_test_helpers_create_test_app_state_with_pool() {
        let pool = PgPool::connect_lazy("postgresql://test:test@localhost:5432/testdb").unwrap();
        let result = test_helpers::create_test_app_state_with_pool(pool).await;
        assert!(result.is_ok());

        let app_state = result.unwrap();
        assert!(Arc::ptr_eq(&app_state.user_repo, &app_state.user_repo));
        assert!(Arc::ptr_eq(&app_state.role_repo, &app_state.role_repo));
        assert!(Arc::ptr_eq(
            &app_state.permission_repo,
            &app_state.permission_repo
        ));
        assert!(Arc::ptr_eq(
            &app_state.abac_policy_repo,
            &app_state.abac_policy_repo
        ));
        assert!(Arc::ptr_eq(
            &app_state.permission_group_repo,
            &app_state.permission_group_repo
        ));
        assert!(Arc::ptr_eq(
            &app_state.refresh_token_repo,
            &app_state.refresh_token_repo
        ));
        assert!(Arc::ptr_eq(
            &app_state.token_service,
            &app_state.token_service
        ));
        assert!(Arc::ptr_eq(
            &app_state.password_service,
            &app_state.password_service
        ));
        assert!(Arc::ptr_eq(
            &app_state.password_reset_service,
            &app_state.password_reset_service
        ));
        assert!(Arc::ptr_eq(
            &app_state.authorization_service,
            &app_state.authorization_service
        ));
        assert!(Arc::ptr_eq(&app_state.command_bus, &app_state.command_bus));
        assert!(Arc::ptr_eq(&app_state.query_bus, &app_state.query_bus));
    }

    #[test]
    fn test_app_config_partial_eq() {
        let config1 = AppConfig::new(
            "test_url".to_string(),
            "test_host".to_string(),
            "test_port".to_string(),
            "test_mode".to_string(),
        );
        let config2 = AppConfig::new(
            "test_url".to_string(),
            "test_host".to_string(),
            "test_port".to_string(),
            "test_mode".to_string(),
        );
        let config3 = AppConfig::new(
            "different_url".to_string(),
            "test_host".to_string(),
            "test_port".to_string(),
            "test_mode".to_string(),
        );

        assert_eq!(config1, config2);
        assert_ne!(config1, config3);
    }

    #[test]
    fn test_app_config_debug() {
        let config = AppConfig::new(
            "test_url".to_string(),
            "test_host".to_string(),
            "test_port".to_string(),
            "test_mode".to_string(),
        );
        let debug_str = format!("{config:?}");
        assert!(debug_str.contains("test_url"));
        assert!(debug_str.contains("test_host"));
        assert!(debug_str.contains("test_port"));
        assert!(debug_str.contains("test_mode"));
    }

    #[test]
    fn test_app_config_clone() {
        let config = AppConfig::new(
            "test_url".to_string(),
            "test_host".to_string(),
            "test_port".to_string(),
            "test_mode".to_string(),
        );
        let cloned_config = config.clone();
        assert_eq!(config, cloned_config);
    }

    #[test]
    fn test_app_state_builder_debug() {
        let builder = AppStateBuilder::new();
        let debug_str = format!("{builder:?}");
        assert!(debug_str.contains("AppStateBuilder"));
    }

    #[test]
    fn test_error_conversions() {
        // Test ConfigError to AppError conversion
        let config_error = ConfigError::MissingRequired("TEST".to_string());
        let app_error: AppError = config_error.into();
        match app_error {
            AppError::Config(ConfigError::MissingRequired(msg)) => {
                assert_eq!(msg, "TEST");
            }
            _ => panic!("Expected ConfigError variant"),
        }

        // Test sqlx::Error to AppError conversion
        let sqlx_error = sqlx::Error::Configuration("test config error".into());
        let app_error: AppError = sqlx_error.into();
        match app_error {
            AppError::Database(_) => {}
            _ => panic!("Expected DatabaseError variant"),
        }
    }
}
