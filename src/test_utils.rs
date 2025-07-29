use crate::application::{
    command_bus::CommandBus, query_bus::QueryBus, services::AuthorizationService,
    services::PasswordResetService, services::PasswordService, services::TokenService,
};
use crate::domain::{
    abac_policy::{AbacCondition, AbacEffect, AbacPolicy, ConflictResolutionStrategy},
    permission::Permission,
    permission_group::PermissionGroup,
    role::Role,
    user::User,
};
use crate::infrastructure::{
    AbacPolicyRepository, InMemoryAbacPolicyRepository, InMemoryPermissionGroupRepository,
    InMemoryPermissionRepository, InMemoryRefreshTokenRepository, InMemoryRoleRepository,
    InMemoryUserRepository, PermissionGroupRepository, PermissionRepository, RoleRepository,
};
use crate::interface::app_state::AppState;
use bcrypt::hash;
use std::sync::Arc;

// Type aliases to reduce complexity
type TestData = (
    Vec<User>,
    Vec<Role>,
    Vec<Permission>,
    Vec<PermissionGroup>,
    Vec<AbacPolicy>,
);
type TestRepositories = (
    Arc<InMemoryUserRepository>,
    Arc<InMemoryRoleRepository>,
    Arc<InMemoryPermissionRepository>,
    Arc<InMemoryAbacPolicyRepository>,
    Arc<InMemoryPermissionGroupRepository>,
    Arc<InMemoryRefreshTokenRepository>,
);

/// Sets up test environment variables for JWT and other services
pub fn setup_test_env() {
    unsafe {
        std::env::set_var("JWT_SECRET", "test-secret-key-for-testing-only");
        std::env::set_var("JWT_EXPIRATION", "1");
        std::env::set_var("JWT_TIME_UNIT", "hours");
        std::env::set_var("REFRESH_TOKEN_EXPIRATION", "86400");
    }
}

/// Creates a test user with default values
pub fn create_test_user() -> User {
    let password_hash = hash("password", 4).unwrap(); // Use cost 4 for faster tests
    User {
        id: uuid::Uuid::new_v4().to_string(),
        email: "test@example.com".to_string(),
        password_hash,
        roles: vec!["admin".to_string()],
        is_locked: false,
        failed_login_attempts: 0,
    }
}

/// Creates a test user with custom values
pub fn create_test_user_with_custom_values(
    id: &str,
    email: &str,
    password: &str,
    roles: Vec<String>,
    is_locked: bool,
) -> User {
    let password_hash = hash(password, 4).unwrap();
    User {
        id: id.to_string(),
        email: email.to_string(),
        password_hash,
        roles,
        is_locked,
        failed_login_attempts: 0,
    }
}

/// Creates an admin test user with admin role
pub fn create_admin_test_user() -> User {
    create_test_user_with_custom_values(
        "admin1",
        "admin@example.com",
        "password123",
        vec!["admin".to_string()],
        false,
    )
}

/// Creates a user with RBAC management permissions
pub fn create_rbac_manager_user() -> User {
    create_test_user_with_custom_values(
        "rbac-manager",
        "rbac-manager@example.com",
        "password123",
        vec!["rbac-manager".to_string()],
        false,
    )
}

/// Creates a user without permissions
pub fn create_user_without_permissions() -> User {
    create_test_user_with_custom_values(
        "user-without-permissions",
        "user-without-permissions@example.com",
        "password",
        vec![],
        false,
    )
}

/// Creates a test role
pub fn create_test_role(id: &str, name: &str, _description: &str) -> Role {
    Role {
        id: id.to_string(),
        name: name.to_string(),
        permissions: vec![],
        parent_role_id: None,
    }
}

/// Creates an admin role with full permissions
pub fn create_admin_role() -> Role {
    let mut role = create_test_role("admin-role", "admin", "Administrator role with full access");
    role.permissions = vec![
        "rbac:manage".to_string(),
        "abac:manage".to_string(),
        "users:manage".to_string(),
        "roles:manage".to_string(),
        "permissions:manage".to_string(),
        "permission-groups:manage".to_string(),
    ];
    role
}

/// Creates a RBAC manager role
pub fn create_rbac_manager_role() -> Role {
    let mut role = create_test_role("rbac-manager-role", "rbac-manager", "RBAC management role");
    role.permissions = vec![
        "rbac:manage".to_string(),
        "roles:manage".to_string(),
        "permissions:manage".to_string(),
        "permission-groups:manage".to_string(),
    ];
    role
}

/// Creates a user role
pub fn create_user_role() -> Role {
    create_test_role("user-role", "user", "Standard user role")
}

/// Creates a test permission
pub fn create_test_permission(
    id: &str,
    name: &str,
    description: &str,
    _resource: &str,
    _action: &str,
) -> Permission {
    Permission {
        id: id.to_string(),
        name: name.to_string(),
        description: Some(description.to_string()),
        group_id: None,
        metadata: serde_json::Value::Null,
        is_active: true,
    }
}

/// Creates a read permission
pub fn create_read_permission(resource: &str) -> Permission {
    create_test_permission(
        &format!("read-{resource}"),
        &format!("read_{resource}"),
        &format!("Read access to {resource}"),
        resource,
        "read",
    )
}

/// Creates a write permission
pub fn create_write_permission(resource: &str) -> Permission {
    create_test_permission(
        &format!("write-{resource}"),
        &format!("write_{resource}"),
        &format!("Write access to {resource}"),
        resource,
        "write",
    )
}

/// Creates RBAC management permissions
pub fn create_rbac_permissions() -> Vec<Permission> {
    vec![
        create_test_permission(
            "rbac:manage",
            "rbac:manage",
            "Manage RBAC system",
            "rbac",
            "manage",
        ),
        create_test_permission(
            "roles:manage",
            "roles:manage",
            "Manage roles",
            "roles",
            "manage",
        ),
        create_test_permission(
            "permissions:manage",
            "permissions:manage",
            "Manage permissions",
            "permissions",
            "manage",
        ),
        create_test_permission(
            "permission-groups:manage",
            "permission-groups:manage",
            "Manage permission groups",
            "permission-groups",
            "manage",
        ),
        create_test_permission(
            "abac:manage",
            "abac:manage",
            "Manage ABAC policies",
            "abac",
            "manage",
        ),
        create_test_permission(
            "users:manage",
            "users:manage",
            "Manage users",
            "users",
            "manage",
        ),
    ]
}

/// Creates a test permission group
pub fn create_test_permission_group(id: &str, name: &str, description: &str) -> PermissionGroup {
    PermissionGroup {
        id: id.to_string(),
        name: name.to_string(),
        description: Some(description.to_string()),
        category: None,
        metadata: serde_json::Value::Null,
        is_active: true,
    }
}

/// Creates a user management permission group
pub fn create_user_management_group() -> PermissionGroup {
    create_test_permission_group(
        "user-management",
        "User Management",
        "Permissions for managing users",
    )
}

/// Creates a test ABAC policy
pub fn create_test_abac_policy(
    id: &str,
    name: &str,
    _description: &str,
    effect: AbacEffect,
    conditions: Vec<AbacCondition>,
) -> AbacPolicy {
    AbacPolicy {
        id: id.to_string(),
        name: name.to_string(),
        effect,
        conditions,
        priority: Some(1),
        conflict_resolution: Some(ConflictResolutionStrategy::DenyOverrides),
    }
}

/// Creates a simple ABAC policy for time-based access
pub fn create_time_based_policy() -> AbacPolicy {
    let conditions = vec![
        AbacCondition {
            attribute: "time.hour".to_string(),
            operator: "gte".to_string(),
            value: "9".to_string(),
        },
        AbacCondition {
            attribute: "time.hour".to_string(),
            operator: "lte".to_string(),
            value: "17".to_string(),
        },
    ];

    create_test_abac_policy(
        "time-based-access",
        "Time-based Access Control",
        "Allow access only during business hours",
        AbacEffect::Allow,
        conditions,
    )
}

/// Creates test data for comprehensive testing
pub fn create_comprehensive_test_data() -> TestData {
    let users = vec![
        create_admin_test_user(),
        create_rbac_manager_user(),
        create_user_without_permissions(),
        create_test_user_with_custom_values(
            "moderator1",
            "moderator@example.com",
            "password",
            vec!["moderator-role".to_string()],
            false,
        ),
    ];

    let roles = vec![
        create_admin_role(),
        create_rbac_manager_role(),
        create_user_role(),
        create_test_role("moderator-role", "moderator", "Moderator role"),
    ];

    let permission_groups = vec![
        create_user_management_group(),
        create_test_permission_group(
            "content-management",
            "Content Management",
            "Content management permissions",
        ),
    ];

    let mut permissions = vec![
        create_read_permission("users"),
        create_write_permission("users"),
        create_read_permission("roles"),
        create_write_permission("roles"),
        create_read_permission("content"),
        create_write_permission("content"),
    ];

    // Add RBAC management permissions
    permissions.extend(create_rbac_permissions());

    let abac_policies = vec![
        create_time_based_policy(),
        create_test_abac_policy(
            "admin-only",
            "Admin Only Access",
            "Restrict access to admin users only",
            AbacEffect::Allow,
            vec![AbacCondition {
                attribute: "user.roles".to_string(),
                operator: "contains".to_string(),
                value: "admin".to_string(),
            }],
        ),
    ];

    (users, roles, permissions, permission_groups, abac_policies)
}

/// Creates a test database pool for PostgreSQL tests
pub async fn create_test_pool() -> sqlx::PgPool {
    let database_url = std::env::var("DATABASE_URL").unwrap_or_else(|_| {
        "postgres://test_user:test_pass@localhost:5433/test_auth_db".to_string()
    });

    sqlx::PgPool::connect(&database_url)
        .await
        .expect("Failed to create test database pool")
}

/// Creates test repositories with comprehensive test data
pub async fn create_test_repositories_with_comprehensive_data() -> TestRepositories {
    let (users, roles, permissions, permission_groups, abac_policies) =
        create_comprehensive_test_data();

    let user_repo = Arc::new(InMemoryUserRepository::new(users.clone()));
    let role_repo = Arc::new(InMemoryRoleRepository::new());
    let permission_repo = Arc::new(InMemoryPermissionRepository::new());
    let abac_policy_repo = Arc::new(InMemoryAbacPolicyRepository::new());
    let permission_group_repo = Arc::new(InMemoryPermissionGroupRepository::new());
    let refresh_token_repo = Arc::new(InMemoryRefreshTokenRepository::new());

    // First create all permissions
    let mut permission_map = std::collections::HashMap::new();
    for permission in permissions {
        let created_permission = permission_repo
            .create_permission(&permission.name)
            .await
            .unwrap();
        permission_map.insert(permission.name.clone(), created_permission.id.clone());
    }

    // Then create roles and assign permissions
    let mut role_map = std::collections::HashMap::new();
    for role in roles {
        let created_role = role_repo.create_role(&role.name).await;
        role_map.insert(role.name.clone(), created_role.id.clone());
        // Assign permissions to the role
        for permission_name in &role.permissions {
            if let Some(permission_id) = permission_map.get(permission_name) {
                permission_repo
                    .assign_permission(&created_role.id, permission_id)
                    .await
                    .unwrap();
            }
        }
    }

    // Assign roles to users
    for user in users {
        for role_name in &user.roles {
            if let Some(role_id) = role_map.get(role_name) {
                role_repo.assign_role(&user.id, role_id).await;
            }
        }
    }

    for policy in abac_policies {
        abac_policy_repo.create_policy(policy).await.unwrap();
    }

    for group in permission_groups {
        permission_group_repo.create_group(group).await.unwrap();
    }

    (
        user_repo,
        role_repo,
        permission_repo,
        abac_policy_repo,
        permission_group_repo,
        refresh_token_repo,
    )
}

/// Creates basic test repositories with given users
fn create_basic_test_repositories(users: Vec<User>) -> TestRepositories {
    (
        Arc::new(InMemoryUserRepository::new(users)),
        Arc::new(InMemoryRoleRepository::new()),
        Arc::new(InMemoryPermissionRepository::new()),
        Arc::new(InMemoryAbacPolicyRepository::new()),
        Arc::new(InMemoryPermissionGroupRepository::new()),
        Arc::new(InMemoryRefreshTokenRepository::new()),
    )
}

/// Creates test repositories with a single user
pub fn create_test_repositories_with_user(user: User) -> TestRepositories {
    create_basic_test_repositories(vec![user])
}

/// Generates a valid JWT token for testing
pub async fn generate_valid_token(user: &User, app_state: &AppState) -> String {
    setup_test_env();
    let (access_token, _refresh_token) = app_state
        .token_service
        .issue_tokens(user, &app_state.refresh_token_repo)
        .await
        .expect("Failed to generate tokens");

    access_token
}

/// Creates a JWT token with custom expiration time
fn create_jwt_token_with_expiration(
    user_id: &str,
    roles: &[&str],
    expiration_offset: chrono::Duration,
) -> String {
    use jsonwebtoken::{EncodingKey, Header, encode};
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Serialize, Deserialize)]
    struct Claims {
        sub: String,
        exp: usize,
        iat: usize,
        roles: Vec<String>,
    }

    setup_test_env();

    let now = chrono::Utc::now();
    let exp = (now + expiration_offset).timestamp() as usize;
    let iat = now.timestamp() as usize;

    let claims = Claims {
        sub: user_id.to_string(),
        exp,
        iat,
        roles: roles.iter().map(|s| s.to_string()).collect(),
    };

    let secret = std::env::var("JWT_SECRET")
        .unwrap_or_else(|_| "test-secret-key-for-testing-only".to_string());
    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret.as_ref()),
    )
    .expect("Failed to create JWT token")
}

/// Creates a JWT token with custom secret
fn create_jwt_token_with_secret(user_id: &str, roles: &[&str], secret: &str) -> String {
    use jsonwebtoken::{EncodingKey, Header, encode};
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Serialize, Deserialize)]
    struct Claims {
        sub: String,
        exp: usize,
        iat: usize,
        roles: Vec<String>,
    }

    setup_test_env();

    let now = chrono::Utc::now();
    let exp = (now + chrono::Duration::hours(1)).timestamp() as usize;
    let iat = now.timestamp() as usize;

    let claims = Claims {
        sub: user_id.to_string(),
        exp,
        iat,
        roles: roles.iter().map(|s| s.to_string()).collect(),
    };

    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret.as_ref()),
    )
    .expect("Failed to create JWT token")
}

/// Creates a test JWT token for testing purposes
pub fn create_test_jwt_token(user_id: &str, roles: &[&str]) -> String {
    create_jwt_token_with_expiration(user_id, roles, chrono::Duration::hours(1))
}

/// Creates an expired JWT token for testing
pub fn create_expired_test_jwt_token(user_id: &str, roles: &[&str]) -> String {
    create_jwt_token_with_expiration(user_id, roles, -chrono::Duration::hours(2))
}

/// Creates a JWT token with invalid signature for testing
pub fn create_invalid_signature_test_jwt_token(user_id: &str, roles: &[&str]) -> String {
    create_jwt_token_with_secret(user_id, roles, "wrong-secret-key-for-invalid-signature")
}

/// Registers common command handlers
async fn register_common_command_handlers(
    command_bus: &Arc<CommandBus>,
    user_repo: &Arc<InMemoryUserRepository>,
    role_repo: &Arc<InMemoryRoleRepository>,
    permission_repo: &Arc<InMemoryPermissionRepository>,
    permission_group_repo: &Arc<InMemoryPermissionGroupRepository>,
    abac_policy_repo: &Arc<InMemoryAbacPolicyRepository>,
) {
    command_bus
        .register_handler::<crate::application::commands::AuthenticateUserCommand, _>(
            crate::application::command_handlers::AuthenticateUserCommandHandler::new(
                user_repo.clone(),
            ),
        )
        .await;

    command_bus
        .register_handler::<crate::application::commands::CreateUserCommand, _>(
            crate::application::command_handlers::CreateUserCommandHandler::new(
                user_repo.clone(),
                role_repo.clone(),
            ),
        )
        .await;

    command_bus
        .register_handler::<crate::application::commands::ChangePasswordCommand, _>(
            crate::application::command_handlers::ChangePasswordCommandHandler::new(
                user_repo.clone(),
            ),
        )
        .await;

    command_bus
        .register_handler::<crate::application::commands::CreateRoleCommand, _>(
            crate::application::command_handlers::CreateRoleCommandHandler::new(role_repo.clone()),
        )
        .await;

    command_bus
        .register_handler::<crate::application::commands::CreatePermissionCommand, _>(
            crate::application::command_handlers::CreatePermissionCommandHandler::new(
                permission_repo.clone(),
                permission_group_repo.clone(),
            ),
        )
        .await;

    command_bus
        .register_handler::<crate::application::commands::CreatePermissionGroupCommand, _>(
            crate::application::command_handlers::CreatePermissionGroupCommandHandler::new(
                permission_group_repo.clone(),
            ),
        )
        .await;

    command_bus
        .register_handler::<crate::application::commands::UpdateRoleCommand, _>(
            crate::application::command_handlers::UpdateRoleCommandHandler::new(role_repo.clone()),
        )
        .await;

    command_bus
        .register_handler::<crate::application::commands::UpdatePermissionCommand, _>(
            crate::application::command_handlers::UpdatePermissionCommandHandler::new(
                permission_repo.clone(),
            ),
        )
        .await;

    command_bus
        .register_handler::<crate::application::commands::DeleteRoleCommand, _>(
            crate::application::command_handlers::DeleteRoleCommandHandler::new(role_repo.clone()),
        )
        .await;

    command_bus
        .register_handler::<crate::application::commands::DeletePermissionCommand, _>(
            crate::application::command_handlers::DeletePermissionCommandHandler::new(
                permission_repo.clone(),
            ),
        )
        .await;

    command_bus
        .register_handler::<crate::application::commands::RemoveRolesFromUserCommand, _>(
            crate::application::command_handlers::RemoveRolesFromUserCommandHandler::new(
                role_repo.clone(),
                user_repo.clone(),
            ),
        )
        .await;

    command_bus
        .register_handler::<crate::application::commands::RemovePermissionsFromRoleCommand, _>(
            crate::application::command_handlers::RemovePermissionsFromRoleCommandHandler::new(
                role_repo.clone(),
                permission_repo.clone(),
            ),
        )
        .await;

    command_bus
        .register_handler::<crate::application::commands::UpdatePermissionGroupCommand, _>(
            crate::application::command_handlers::UpdatePermissionGroupCommandHandler::new(
                permission_group_repo.clone(),
            ),
        )
        .await;

    command_bus
        .register_handler::<crate::application::commands::DeletePermissionGroupCommand, _>(
            crate::application::command_handlers::DeletePermissionGroupCommandHandler::new(
                permission_group_repo.clone(),
            ),
        )
        .await;

    command_bus
        .register_handler::<crate::application::commands::UpdateAbacPolicyCommand, _>(
            crate::application::command_handlers::UpdateAbacPolicyCommandHandler::new(
                abac_policy_repo.clone(),
            ),
        )
        .await;

    command_bus
        .register_handler::<crate::application::commands::DeleteAbacPolicyCommand, _>(
            crate::application::command_handlers::DeleteAbacPolicyCommandHandler::new(
                abac_policy_repo.clone(),
            ),
        )
        .await;

    command_bus
        .register_handler::<crate::application::commands::AssignAbacPolicyToUserCommand, _>(
            crate::application::command_handlers::AssignAbacPolicyToUserCommandHandler::new(
                abac_policy_repo.clone(),
            ),
        )
        .await;

    command_bus
        .register_handler::<crate::application::commands::SetParentRoleCommand, _>(
            crate::application::command_handlers::SetParentRoleCommandHandler::new(
                role_repo.clone(),
            ),
        )
        .await;
}

/// Registers common query handlers
async fn register_common_query_handlers(
    query_bus: &Arc<QueryBus>,
    user_repo: &Arc<InMemoryUserRepository>,
    role_repo: &Arc<InMemoryRoleRepository>,
    permission_repo: &Arc<InMemoryPermissionRepository>,
    permission_group_repo: &Arc<InMemoryPermissionGroupRepository>,
    abac_policy_repo: &Arc<InMemoryAbacPolicyRepository>,
) {
    query_bus
        .register_handler::<crate::application::queries::CheckPermissionQuery, _>(
            crate::application::query_handlers::CheckPermissionQueryHandler::new(
                role_repo.clone(),
                permission_repo.clone(),
                abac_policy_repo.clone(),
            ),
        )
        .await;

    query_bus
        .register_handler::<crate::application::queries::ListRolesQuery, _>(
            crate::application::query_handlers::ListRolesQueryHandler::new(
                role_repo.clone(),
                permission_repo.clone(),
            ),
        )
        .await;

    query_bus
        .register_handler::<crate::application::queries::ListPermissionsQuery, _>(
            crate::application::query_handlers::ListPermissionsQueryHandler::new(
                permission_repo.clone(),
                permission_group_repo.clone(),
            ),
        )
        .await;

    query_bus
        .register_handler::<crate::application::queries::GetUserByIdQuery, _>(
            crate::application::query_handlers::GetUserByIdQueryHandler::new(
                user_repo.clone(),
                role_repo.clone(),
                permission_repo.clone(),
            ),
        )
        .await;

    query_bus
        .register_handler::<crate::application::queries::ListUsersQuery, _>(
            crate::application::query_handlers::ListUsersQueryHandler::new(
                user_repo.clone(),
                role_repo.clone(),
            ),
        )
        .await;

    query_bus
        .register_handler::<crate::application::queries::GetRoleByIdQuery, _>(
            crate::application::query_handlers::GetRoleByIdQueryHandler::new(
                role_repo.clone(),
                permission_repo.clone(),
            ),
        )
        .await;

    query_bus
        .register_handler::<crate::application::queries::ListRoleHierarchiesQuery, _>(
            crate::application::query_handlers::ListRoleHierarchiesQueryHandler::new(
                role_repo.clone(),
            ),
        )
        .await;

    query_bus
        .register_handler::<crate::application::queries::GetRoleHierarchyQuery, _>(
            crate::application::query_handlers::GetRoleHierarchyQueryHandler::new(
                role_repo.clone(),
            ),
        )
        .await;

    query_bus
        .register_handler::<crate::application::queries::GetRolesForUserQuery, _>(
            crate::application::query_handlers::GetRolesForUserQueryHandler::new(role_repo.clone()),
        )
        .await;

    query_bus
        .register_handler::<crate::application::queries::GetRolePermissionsQuery, _>(
            crate::application::query_handlers::GetRolePermissionsQueryHandler::new(
                permission_repo.clone(),
            ),
        )
        .await;

    query_bus
        .register_handler::<crate::application::queries::GetPermissionByIdQuery, _>(
            crate::application::query_handlers::GetPermissionByIdQueryHandler::new(
                permission_repo.clone(),
            ),
        )
        .await;

    query_bus
        .register_handler::<crate::application::queries::ListAbacPoliciesQuery, _>(
            crate::application::query_handlers::ListAbacPoliciesQueryHandler::new(
                abac_policy_repo.clone(),
            ),
        )
        .await;

    query_bus
        .register_handler::<crate::application::queries::ListPermissionGroupsQuery, _>(
            crate::application::query_handlers::ListPermissionGroupsQueryHandler::new(
                permission_group_repo.clone(),
            ),
        )
        .await;

    query_bus
        .register_handler::<crate::application::queries::GetPermissionGroupQuery, _>(
            crate::application::query_handlers::GetPermissionGroupQueryHandler::new(
                permission_group_repo.clone(),
            ),
        )
        .await;
}

/// Creates a complete test app state with comprehensive test data
pub async fn create_test_app_state_with_comprehensive_data() -> Arc<AppState> {
    setup_test_env();

    let (
        user_repo,
        role_repo,
        permission_repo,
        abac_policy_repo,
        permission_group_repo,
        refresh_token_repo,
    ) = create_test_repositories_with_comprehensive_data().await;

    let token_service = Arc::new(TokenService);
    let password_service = Arc::new(PasswordService);
    let password_reset_service = Arc::new(PasswordResetService);
    let authorization_service = Arc::new(AuthorizationService);

    let command_bus = Arc::new(CommandBus::new());
    let query_bus = Arc::new(QueryBus::new());

    // Register command and query handlers
    register_common_command_handlers(
        &command_bus,
        &user_repo,
        &role_repo,
        &permission_repo,
        &permission_group_repo,
        &abac_policy_repo,
    )
    .await;

    register_common_query_handlers(
        &query_bus,
        &user_repo,
        &role_repo,
        &permission_repo,
        &permission_group_repo,
        &abac_policy_repo,
    )
    .await;

    Arc::new(AppState {
        user_repo,
        refresh_token_repo,
        role_repo,
        permission_repo,
        abac_policy_repo,
        permission_group_repo,
        token_service,
        password_service,
        password_reset_service,
        authorization_service,
        command_bus,
        query_bus,
    })
}

/// Creates a complete test app state with all services and repositories
pub async fn create_test_app_state() -> Arc<AppState> {
    setup_test_env();

    let test_user = create_test_user();
    let (
        user_repo,
        role_repo,
        permission_repo,
        abac_policy_repo,
        permission_group_repo,
        refresh_token_repo,
    ) = create_test_repositories_with_user(test_user);

    let token_service = Arc::new(TokenService);
    let password_service = Arc::new(PasswordService);
    let password_reset_service = Arc::new(PasswordResetService);
    let authorization_service = Arc::new(AuthorizationService);

    let command_bus = Arc::new(CommandBus::new());
    let query_bus = Arc::new(QueryBus::new());

    // Register command and query handlers
    register_common_command_handlers(
        &command_bus,
        &user_repo,
        &role_repo,
        &permission_repo,
        &permission_group_repo,
        &abac_policy_repo,
    )
    .await;

    register_common_query_handlers(
        &query_bus,
        &user_repo,
        &role_repo,
        &permission_repo,
        &permission_group_repo,
        &abac_policy_repo,
    )
    .await;

    Arc::new(AppState {
        user_repo,
        refresh_token_repo,
        role_repo,
        permission_repo,
        abac_policy_repo,
        permission_group_repo,
        token_service,
        password_service,
        password_reset_service,
        authorization_service,
        command_bus,
        query_bus,
    })
}
