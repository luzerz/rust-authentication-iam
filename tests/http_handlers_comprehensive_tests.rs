use authentication_service::{
    application::{command_bus::CommandBus, query_bus::QueryBus, services::*},
    domain::{
        abac_policy::{AbacCondition, AbacEffect, AbacPolicy, ConflictResolutionStrategy},
        user::User,
    },
    infrastructure::{
        InMemoryAbacPolicyRepository, InMemoryPermissionGroupRepository,
        InMemoryPermissionRepository, InMemoryRoleRepository, InMemoryUserRepository,
        PermissionGroupRepository, PermissionRepository, RoleRepository,
    },
    interface::{AppState, *},
};
use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode},
};
use bcrypt::{DEFAULT_COST, hash};
use serde_json::json;
use std::sync::Arc;
use tower::util::ServiceExt;

// Helper function to create test user
fn create_test_user() -> User {
    User {
        id: "user1".to_string(),
        email: "test@example.com".to_string(),
        password_hash: hash("password", 4).unwrap(), // Use cost 4 for faster tests
        roles: vec!["admin".to_string()],
        is_locked: false,
        failed_login_attempts: 0,
    }
}

// Helper function to create user without permissions
fn create_user_without_permissions() -> User {
    User {
        id: "user-without-permissions".to_string(),
        email: "user-without-permissions@example.com".to_string(),
        password_hash: hash("password", 4).unwrap(), // Use cost 4 for faster tests
        roles: vec![], // No roles, so no permissions
        is_locked: false,
        failed_login_attempts: 0,
    }
}

// Helper function to create app state with admin user and permissions
async fn create_app_state_with_admin() -> Arc<AppState> {
    unsafe {
        std::env::set_var("JWT_SECRET", "test-secret-key-for-testing-only");
        std::env::set_var("JWT_EXPIRATION", "1");
        std::env::set_var("JWT_TIME_UNIT", "hours");
    }

    let test_user = create_test_user();
    let user_without_permissions = create_user_without_permissions();
    let user_repo = Arc::new(InMemoryUserRepository::new(vec![
        test_user.clone(),
        user_without_permissions.clone(),
    ]));
    let role_repo = Arc::new(InMemoryRoleRepository::new());
    let permission_repo = Arc::new(InMemoryPermissionRepository::new());
    let abac_policy_repo = Arc::new(InMemoryAbacPolicyRepository::new());
    let permission_group_repo = Arc::new(InMemoryPermissionGroupRepository::new());

    // Create a test permission group with ID "group1"
    let test_group = authentication_service::domain::permission_group::PermissionGroup {
        id: "group1".to_string(),
        name: "test-group".to_string(),
        description: Some("Test permission group".to_string()),
        category: Some("test".to_string()),
        metadata: serde_json::json!({"version": "1.0"}),
        is_active: true,
    };
    permission_group_repo
        .create_group(test_group)
        .await
        .unwrap();

    let refresh_token_repo = Arc::new(MockRefreshTokenRepository::new());

    let token_service = Arc::new(TokenService);
    let password_service = Arc::new(PasswordService);
    let password_reset_service = Arc::new(PasswordResetService);
    let authorization_service = Arc::new(AuthorizationService);

    // Create CQRS buses
    let command_bus = Arc::new(CommandBus::new());
    let query_bus = Arc::new(QueryBus::new());

    // Register command handlers
    command_bus
        .register_handler::<authentication_service::application::commands::AuthenticateUserCommand, _>(
            authentication_service::application::command_handlers::AuthenticateUserCommandHandler::new(
                user_repo.clone(),
            ),
        )
        .await;

    command_bus
        .register_handler::<authentication_service::application::commands::CreateUserCommand, _>(
            authentication_service::application::command_handlers::CreateUserCommandHandler::new(
                user_repo.clone(),
                role_repo.clone(),
            ),
        )
        .await;

    command_bus
        .register_handler::<authentication_service::application::commands::CreateRoleCommand, _>(
            authentication_service::application::command_handlers::CreateRoleCommandHandler::new(
                role_repo.clone(),
            ),
        )
        .await;

    command_bus.register_handler::<authentication_service::application::commands::CreatePermissionCommand, _>(
        authentication_service::application::command_handlers::CreatePermissionCommandHandler::new(permission_repo.clone(), permission_group_repo.clone()),
    ).await;

    command_bus.register_handler::<authentication_service::application::commands::CreateAbacPolicyCommand, _>(
        authentication_service::application::command_handlers::CreateAbacPolicyCommandHandler::new(abac_policy_repo.clone()),
    ).await;

    command_bus.register_handler::<authentication_service::application::commands::CreatePermissionGroupCommand, _>(
        authentication_service::application::command_handlers::CreatePermissionGroupCommandHandler::new(permission_group_repo.clone()),
    ).await;

    command_bus.register_handler::<authentication_service::application::commands::ChangePasswordCommand, _>(
        authentication_service::application::command_handlers::ChangePasswordCommandHandler::new(user_repo.clone()),
    ).await;

    command_bus
        .register_handler::<authentication_service::application::commands::ResetPasswordCommand, _>(
            authentication_service::application::command_handlers::ResetPasswordCommandHandler::new(
                user_repo.clone(),
            ),
        )
        .await;

    command_bus
        .register_handler::<authentication_service::application::commands::AssignRolesCommand, _>(
            authentication_service::application::command_handlers::AssignRolesCommandHandler::new(
                role_repo.clone(),
                user_repo.clone(),
            ),
        )
        .await;

    command_bus
        .register_handler::<authentication_service::application::commands::RemoveRolesFromUserCommand, _>(
            authentication_service::application::command_handlers::RemoveRolesFromUserCommandHandler::new(
                role_repo.clone(),
                user_repo.clone(),
            ),
        )
        .await;

    command_bus.register_handler::<authentication_service::application::commands::AssignPermissionsToRoleCommand, _>(
        authentication_service::application::command_handlers::AssignPermissionsToRoleCommandHandler::new(role_repo.clone(), permission_repo.clone()),
    ).await;

    command_bus.register_handler::<authentication_service::application::commands::RemovePermissionsFromRoleCommand, _>(
        authentication_service::application::command_handlers::RemovePermissionsFromRoleCommandHandler::new(role_repo.clone(), permission_repo.clone()),
    ).await;

    command_bus.register_handler::<authentication_service::application::commands::DeletePermissionCommand, _>(
        authentication_service::application::command_handlers::DeletePermissionCommandHandler::new(permission_repo.clone()),
    ).await;

    command_bus
        .register_handler::<authentication_service::application::commands::DeleteRoleCommand, _>(
            authentication_service::application::command_handlers::DeleteRoleCommandHandler::new(
                role_repo.clone(),
            ),
        )
        .await;

    command_bus.register_handler::<authentication_service::application::commands::EvaluateAbacPoliciesCommand, _>(
        authentication_service::application::command_handlers::EvaluateAbacPoliciesCommandHandler::new(abac_policy_repo.clone()),
    ).await;

    command_bus.register_handler::<authentication_service::application::commands::DeleteAbacPolicyCommand, _>(
        authentication_service::application::command_handlers::DeleteAbacPolicyCommandHandler::new(abac_policy_repo.clone()),
    ).await;

    command_bus.register_handler::<authentication_service::application::commands::UpdateAbacPolicyCommand, _>(
        authentication_service::application::command_handlers::UpdateAbacPolicyCommandHandler::new(abac_policy_repo.clone()),
    ).await;

    command_bus.register_handler::<authentication_service::application::commands::AssignAbacPolicyToUserCommand, _>(
        authentication_service::application::command_handlers::AssignAbacPolicyToUserCommandHandler::new(abac_policy_repo.clone()),
    ).await;

    command_bus.register_handler::<authentication_service::application::commands::UpdatePermissionGroupCommand, _>(
        authentication_service::application::command_handlers::UpdatePermissionGroupCommandHandler::new(permission_group_repo.clone()),
    ).await;

    command_bus.register_handler::<authentication_service::application::commands::DeletePermissionGroupCommand, _>(
        authentication_service::application::command_handlers::DeletePermissionGroupCommandHandler::new(permission_group_repo.clone()),
    ).await;

    command_bus
        .register_handler::<authentication_service::application::commands::SetParentRoleCommand, _>(
            authentication_service::application::command_handlers::SetParentRoleCommandHandler::new(
                role_repo.clone(),
            ),
        )
        .await;

    command_bus
        .register_handler::<authentication_service::application::commands::UpdateRoleCommand, _>(
            authentication_service::application::command_handlers::UpdateRoleCommandHandler::new(
                role_repo.clone(),
            ),
        )
        .await;

    command_bus.register_handler::<authentication_service::application::commands::UpdatePermissionCommand, _>(
        authentication_service::application::command_handlers::UpdatePermissionCommandHandler::new(permission_repo.clone()),
    ).await;

    // Register query handlers
    query_bus
        .register_handler::<authentication_service::application::queries::ListRolesQuery, _>(
            authentication_service::application::query_handlers::ListRolesQueryHandler::new(
                role_repo.clone(),
                permission_repo.clone(),
            ),
        )
        .await;

    query_bus
        .register_handler::<authentication_service::application::queries::ListPermissionsQuery, _>(
            authentication_service::application::query_handlers::ListPermissionsQueryHandler::new(
                permission_repo.clone(),
                permission_group_repo.clone(),
            ),
        )
        .await;

    query_bus
        .register_handler::<authentication_service::application::queries::ListAbacPoliciesQuery, _>(
            authentication_service::application::query_handlers::ListAbacPoliciesQueryHandler::new(
                abac_policy_repo.clone(),
            ),
        )
        .await;

    query_bus.register_handler::<authentication_service::application::queries::ListPermissionGroupsQuery, _>(
        authentication_service::application::query_handlers::ListPermissionGroupsQueryHandler::new(permission_group_repo.clone()),
    ).await;

    query_bus.register_handler::<authentication_service::application::queries::ListRoleHierarchiesQuery, _>(
        authentication_service::application::query_handlers::ListRoleHierarchiesQueryHandler::new(role_repo.clone()),
    ).await;

    query_bus
        .register_handler::<authentication_service::application::queries::GetRoleHierarchyQuery, _>(
            authentication_service::application::query_handlers::GetRoleHierarchyQueryHandler::new(
                role_repo.clone(),
            ),
        )
        .await;

    query_bus
        .register_handler::<authentication_service::application::queries::GetRolePermissionsQuery, _>(
            authentication_service::application::query_handlers::GetRolePermissionsQueryHandler::new(
                permission_repo.clone(),
            ),
        )
        .await;

    query_bus
        .register_handler::<authentication_service::application::queries::GetRoleByIdQuery, _>(
            authentication_service::application::query_handlers::GetRoleByIdQueryHandler::new(
                role_repo.clone(),
                permission_repo.clone(),
            ),
        )
        .await;

    query_bus
        .register_handler::<authentication_service::application::queries::GetPermissionByIdQuery, _>(
            authentication_service::application::query_handlers::GetPermissionByIdQueryHandler::new(
                permission_repo.clone(),
            ),
        )
        .await;

    query_bus
        .register_handler::<authentication_service::application::queries::GetPermissionGroupQuery, _>(
            authentication_service::application::query_handlers::GetPermissionGroupQueryHandler::new(
                permission_group_repo.clone(),
            ),
        )
        .await;

    query_bus
        .register_handler::<authentication_service::application::queries::GetPermissionsInGroupQuery, _>(
            authentication_service::application::query_handlers::GetPermissionsInGroupQueryHandler::new(
                permission_group_repo.clone(),
            ),
        )
        .await;

    query_bus
        .register_handler::<authentication_service::application::queries::CheckPermissionQuery, _>(
            authentication_service::application::query_handlers::CheckPermissionQueryHandler::new(
                role_repo.clone(),
                permission_repo.clone(),
                abac_policy_repo.clone(),
            ),
        )
        .await;

    // Create admin role and rbac:manage permission after all handlers are registered
    let admin_role = role_repo.create_role("admin").await;
    let rbac_permission = permission_repo
        .create_permission("rbac:manage")
        .await
        .unwrap();
    permission_repo
        .assign_permission(&admin_role.id, &rbac_permission.id)
        .await
        .unwrap();
    role_repo.assign_role("user1", &admin_role.id).await;

    Arc::new(AppState {
        user_repo,
        role_repo,
        permission_repo,
        permission_group_repo,
        abac_policy_repo,
        refresh_token_repo,
        token_service,
        password_service,
        password_reset_service,
        authorization_service,
        command_bus,
        query_bus,
    })
}

// Mock refresh token repository
struct MockRefreshTokenRepository {
    revoked: std::sync::Mutex<std::collections::HashSet<String>>,
}

impl MockRefreshTokenRepository {
    fn new() -> Self {
        Self {
            revoked: std::sync::Mutex::new(std::collections::HashSet::new()),
        }
    }
}

#[async_trait::async_trait]
impl authentication_service::infrastructure::RefreshTokenRepository for MockRefreshTokenRepository {
    async fn insert(
        &self,
        _token: authentication_service::application::services::RefreshToken,
    ) -> Result<(), sqlx::Error> {
        Ok(())
    }

    async fn revoke(&self, jti: &str) -> Result<(), sqlx::Error> {
        self.revoked.lock().unwrap().insert(jti.to_string());
        Ok(())
    }

    async fn is_valid(&self, jti: &str) -> Result<bool, sqlx::Error> {
        Ok(!self.revoked.lock().unwrap().contains(jti))
    }
}

// Helper function to create router with all handlers
fn create_test_router(state: Arc<AppState>) -> Router {
    Router::new()
        // Auth routes
        .route("/auth/login", axum::routing::post(login_handler))
        .route("/auth/register", axum::routing::post(register_user_handler))
        .route(
            "/auth/validate-token",
            axum::routing::post(validate_token_handler),
        )
        .route(
            "/auth/refresh-token",
            axum::routing::post(refresh_token_handler),
        )
        .route("/auth/logout", axum::routing::post(logout_handler))
        .route(
            "/auth/password-change",
            axum::routing::post(change_password_handler),
        )
        .route(
            "/auth/password-reset",
            axum::routing::post(request_password_reset_handler),
        )
        .route(
            "/auth/password-reset-confirm",
            axum::routing::post(confirm_password_reset_handler),
        )
        // RBAC routes
        .route("/rbac/roles", axum::routing::post(create_role_handler))
        .route("/rbac/roles", axum::routing::get(list_roles_handler))
        .route(
            "/rbac/roles/{role_id}",
            axum::routing::get(get_role_handler),
        )
        .route(
            "/rbac/roles/{role_id}",
            axum::routing::put(update_role_handler),
        )
        .route(
            "/rbac/roles/{role_id}",
            axum::routing::delete(delete_role_handler),
        )
        .route(
            "/rbac/roles/assign",
            axum::routing::post(assign_role_handler),
        )
        .route(
            "/rbac/roles/remove",
            axum::routing::post(remove_role_handler),
        )
        .route(
            "/rbac/roles/{role_id}/parent",
            axum::routing::put(set_parent_role_handler),
        )
        .route(
            "/rbac/roles/{role_id}/hierarchy",
            axum::routing::get(get_role_hierarchy_handler),
        )
        .route(
            "/rbac/roles/hierarchy",
            axum::routing::post(create_role_hierarchy_handler),
        )
        .route(
            "/rbac/roles/hierarchies",
            axum::routing::get(list_role_hierarchies_handler),
        )
        .route(
            "/rbac/roles/{role_id}/permissions",
            axum::routing::get(list_role_permissions_handler),
        )
        .route(
            "/rbac/permissions",
            axum::routing::post(create_permission_handler),
        )
        .route(
            "/rbac/permissions",
            axum::routing::get(list_permissions_handler),
        )
        .route(
            "/rbac/permissions/{permission_id}",
            axum::routing::get(get_permission_handler),
        )
        .route(
            "/rbac/permissions/{permission_id}",
            axum::routing::put(update_permission_handler),
        )
        .route(
            "/rbac/permissions/{permission_id}",
            axum::routing::delete(delete_permission_handler),
        )
        .route(
            "/rbac/permissions/assign",
            axum::routing::post(assign_permission_handler),
        )
        .route(
            "/rbac/permissions/remove",
            axum::routing::post(remove_permission_handler),
        )
        // User management routes
        .route(
            "/users/{user_id}/roles",
            axum::routing::get(list_user_roles_handler),
        )
        .route(
            "/users/{user_id}/effective-permissions",
            axum::routing::get(get_effective_permissions_handler),
        )
        // ABAC routes
        .route(
            "/abac/policies",
            axum::routing::post(create_abac_policy_handler),
        )
        .route(
            "/abac/policies",
            axum::routing::get(list_abac_policies_handler),
        )
        .route(
            "/abac/policies/{policy_id}",
            axum::routing::put(update_abac_policy_handler),
        )
        .route(
            "/abac/policies/{policy_id}",
            axum::routing::delete(delete_abac_policy_handler),
        )
        .route(
            "/abac/policies/assign",
            axum::routing::post(assign_abac_policy_handler),
        )
        .route(
            "/abac/evaluate",
            axum::routing::post(evaluate_abac_policies_handler),
        )
        // Permission groups routes
        .route(
            "/permission-groups",
            axum::routing::post(create_permission_group_handler),
        )
        .route(
            "/permission-groups",
            axum::routing::get(list_permission_groups_handler),
        )
        .route(
            "/permission-groups/{group_id}",
            axum::routing::get(get_permission_group_handler),
        )
        .route(
            "/permission-groups/{group_id}",
            axum::routing::put(update_permission_group_handler),
        )
        .route(
            "/permission-groups/{group_id}",
            axum::routing::delete(delete_permission_group_handler),
        )
        .route(
            "/permission-groups/{group_id}/permissions",
            axum::routing::get(get_permissions_in_group_handler),
        )
        .with_state(state)
}

#[tokio::test]
async fn test_auth_handlers_comprehensive() {
    let state = create_app_state_with_admin().await;
    let app = create_test_router(state);

    // Test login handler
    let login_payload = json!({
        "email": "test@example.com",
        "password": "password"
    });

    let request = Request::builder()
        .method("POST")
        .uri("/auth/login")
        .header("content-type", "application/json")
        .body(Body::from(login_payload.to_string()))
        .unwrap();

    let response = app.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // Test register handler
    let register_payload = json!({
        "email": "newuser@example.com",
        "password": "newpassword"
    });

    let request = Request::builder()
        .method("POST")
        .uri("/auth/register")
        .header("content-type", "application/json")
        .body(Body::from(register_payload.to_string()))
        .unwrap();

    let response = app.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);

    // Test validate token handler
    let validate_payload = json!({
        "token": "invalid-token"
    });

    let request = Request::builder()
        .method("POST")
        .uri("/auth/validate-token")
        .header("content-type", "application/json")
        .body(Body::from(validate_payload.to_string()))
        .unwrap();

    let response = app.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // Test password reset request
    let reset_payload = json!({
        "email": "test@example.com"
    });

    let request = Request::builder()
        .method("POST")
        .uri("/auth/password-reset")
        .header("content-type", "application/json")
        .body(Body::from(reset_payload.to_string()))
        .unwrap();

    let response = app.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // Test password reset confirm
    let confirm_payload = json!({
        "reset_token": "reset-token",
        "new_password": "newpassword123"
    });

    let request = Request::builder()
        .method("POST")
        .uri("/auth/password-reset-confirm")
        .header("content-type", "application/json")
        .body(Body::from(confirm_payload.to_string()))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn test_rbac_handlers_comprehensive() {
    let state = create_app_state_with_admin().await;

    // Set up permissions for the test user
    let role_repo = &state.role_repo;
    let permission_repo = &state.permission_repo;

    let admin_role = role_repo.create_role("admin").await;
    let rbac_manage_perm = permission_repo
        .create_permission("rbac:manage")
        .await
        .unwrap();
    let rbac_read_perm = permission_repo
        .create_permission("rbac:read")
        .await
        .unwrap();

    permission_repo
        .assign_permission(&admin_role.id, &rbac_manage_perm.id)
        .await
        .unwrap();
    permission_repo
        .assign_permission(&admin_role.id, &rbac_read_perm.id)
        .await
        .unwrap();
    role_repo.assign_role("user1", &admin_role.id).await;

    // Create additional test role and permission for testing
    let test_role = role_repo.create_role("test-role").await;
    let test_perm = permission_repo
        .create_permission("test:permission")
        .await
        .unwrap();

    // Create a valid JWT token for the test user
    let user: User = User {
        id: "user1".to_string(),
        email: "test@example.com".to_string(),
        password_hash: hash("password", DEFAULT_COST).unwrap(),
        roles: vec!["admin".to_string()],
        is_locked: false,
        failed_login_attempts: 0,
    };
    let (valid_token, _) = state
        .token_service
        .issue_tokens(&user, &state.refresh_token_repo)
        .await
        .unwrap();

    // Create parent role before moving state
    let parent_role = role_repo.create_role("parent-role").await;

    let app = create_test_router(state);

    // Test create role
    println!("Testing create role...");
    let create_role_payload = json!({
        "name": "test-role"
    });

    let request = Request::builder()
        .method("POST")
        .uri("/rbac/roles")
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {}", valid_token))
        .header("x-user-id", "user1")
        .body(Body::from(create_role_payload.to_string()))
        .unwrap();

    let response = app.clone().oneshot(request).await.unwrap();
    println!("Create role status: {}", response.status());
    assert_eq!(response.status(), StatusCode::CREATED);

    // Test list roles
    println!("Testing list roles...");
    let request = Request::builder()
        .method("GET")
        .uri("/rbac/roles")
        .body(Body::empty())
        .unwrap();

    let response = app.clone().oneshot(request).await.unwrap();
    println!("List roles status: {}", response.status());
    assert_eq!(response.status(), StatusCode::OK);

    // Test create permission
    println!("Testing create permission...");
    let create_perm_payload = json!({
        "name": "test:permission"
    });

    let request = Request::builder()
        .method("POST")
        .uri("/rbac/permissions")
        .header("content-type", "application/json")
        .header("x-user-id", "user1")
        .body(Body::from(create_perm_payload.to_string()))
        .unwrap();

    let response = app.clone().oneshot(request).await.unwrap();
    println!("Create permission status: {}", response.status());
    assert_eq!(response.status(), StatusCode::CREATED);

    // Test list permissions
    println!("Testing list permissions...");
    let request = Request::builder()
        .method("GET")
        .uri("/rbac/permissions")
        .body(Body::empty())
        .unwrap();

    let response = app.clone().oneshot(request).await.unwrap();
    println!("List permissions status: {}", response.status());
    assert_eq!(response.status(), StatusCode::OK);

    // Test assign role
    println!("Testing assign role...");
    let assign_role_payload = json!({
        "user_id": "user1",
        "role_id": test_role.id
    });

    let request = Request::builder()
        .method("POST")
        .uri("/rbac/roles/assign")
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {}", valid_token))
        .header("x-user-id", "user1")
        .body(Body::from(assign_role_payload.to_string()))
        .unwrap();

    let response = app.clone().oneshot(request).await.unwrap();
    println!("Assign role status: {}", response.status());
    assert_eq!(response.status(), StatusCode::OK);

    // Test assign permission
    println!("Testing assign permission...");
    let assign_perm_payload = json!({
        "role_id": test_role.id,
        "permission_id": test_perm.id
    });

    let request = Request::builder()
        .method("POST")
        .uri("/rbac/permissions/assign")
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {}", valid_token))
        .header("x-user-id", "user1")
        .body(Body::from(assign_perm_payload.to_string()))
        .unwrap();

    let response = app.clone().oneshot(request).await.unwrap();
    println!("Assign permission status: {}", response.status());
    assert_eq!(response.status(), StatusCode::OK);

    // Test get role
    println!("Testing get role...");
    let request = Request::builder()
        .method("GET")
        .uri(format!("/rbac/roles/{}", test_role.id))
        .header("authorization", format!("Bearer {}", valid_token))
        .header("x-user-id", "user1")
        .body(Body::empty())
        .unwrap();

    let response = app.clone().oneshot(request).await.unwrap();
    println!("Get role status: {}", response.status());
    assert_eq!(response.status(), StatusCode::OK);

    // Test get permission
    println!("Testing get permission...");
    let request = Request::builder()
        .method("GET")
        .uri(format!("/rbac/permissions/{}", test_perm.id))
        .header("authorization", format!("Bearer {}", valid_token))
        .header("x-user-id", "user1")
        .body(Body::empty())
        .unwrap();

    let response = app.clone().oneshot(request).await.unwrap();
    println!("Get permission status: {}", response.status());
    assert_eq!(response.status(), StatusCode::OK);

    // Test update role
    println!("Testing update role...");
    let update_role_payload = json!({
        "name": "updated-test-role"
    });

    let request = Request::builder()
        .method("PUT")
        .uri(format!("/rbac/roles/{}", test_role.id))
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {}", valid_token))
        .header("x-user-id", "user1")
        .body(Body::from(update_role_payload.to_string()))
        .unwrap();

    let response = app.clone().oneshot(request).await.unwrap();
    println!("Update role status: {}", response.status());
    assert_eq!(response.status(), StatusCode::OK);

    // Test update permission
    println!("Testing update permission...");
    let update_perm_payload = json!({
        "name": "updated:permission"
    });

    let request = Request::builder()
        .method("PUT")
        .uri(format!("/rbac/permissions/{}", test_perm.id))
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {}", valid_token))
        .header("x-user-id", "user1")
        .body(Body::from(update_perm_payload.to_string()))
        .unwrap();

    let response = app.clone().oneshot(request).await.unwrap();
    println!("Update permission status: {}", response.status());
    assert_eq!(response.status(), StatusCode::OK);

    // Test list role permissions
    println!("Testing list role permissions...");
    let request = Request::builder()
        .method("GET")
        .uri(format!("/rbac/roles/{}/permissions", test_role.id))
        .header("authorization", format!("Bearer {}", valid_token))
        .header("x-user-id", "user1")
        .body(Body::empty())
        .unwrap();

    let response = app.clone().oneshot(request).await.unwrap();
    println!("List role permissions status: {}", response.status());
    assert_eq!(response.status(), StatusCode::OK);

    // Test create role hierarchy
    println!("Testing create role hierarchy...");
    let parent_role_payload = json!({
        "parent_role_id": parent_role.id,
        "child_role_id": test_role.id
    });

    let request = Request::builder()
        .method("POST")
        .uri("/rbac/roles/hierarchy")
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {}", valid_token))
        .header("x-user-id", "user1")
        .body(Body::from(parent_role_payload.to_string()))
        .unwrap();

    let response = app.clone().oneshot(request).await.unwrap();
    println!("Create role hierarchy status: {}", response.status());
    assert_eq!(response.status(), StatusCode::OK);

    // Test get role hierarchy
    println!("Testing get role hierarchy...");
    let request = Request::builder()
        .method("GET")
        .uri(format!("/rbac/roles/{}/hierarchy", test_role.id))
        .header("authorization", format!("Bearer {}", valid_token))
        .header("x-user-id", "user1")
        .body(Body::empty())
        .unwrap();

    let response = app.clone().oneshot(request).await.unwrap();
    println!("Get role hierarchy status: {}", response.status());
    assert_eq!(response.status(), StatusCode::OK);

    // Test list role hierarchies
    println!("Testing list role hierarchies...");
    let request = Request::builder()
        .method("GET")
        .uri("/rbac/roles/hierarchies")
        .header("authorization", format!("Bearer {}", valid_token))
        .header("x-user-id", "user1")
        .body(Body::empty())
        .unwrap();

    let response = app.clone().oneshot(request).await.unwrap();
    println!("List role hierarchies status: {}", response.status());
    assert_eq!(response.status(), StatusCode::OK);

    // Test get role permissions
    println!("Testing get role permissions...");
    let request = Request::builder()
        .method("GET")
        .uri(format!("/rbac/roles/{}/permissions", test_role.id))
        .header("authorization", format!("Bearer {}", valid_token))
        .header("x-user-id", "user1")
        .body(Body::empty())
        .unwrap();

    let response = app.clone().oneshot(request).await.unwrap();
    println!("Get role permissions status: {}", response.status());
    assert_eq!(response.status(), StatusCode::OK);

    // Test remove role
    println!("Testing remove role...");
    let remove_role_payload = json!({
        "user_id": "user1",
        "role_id": test_role.id
    });

    let request = Request::builder()
        .method("POST")
        .uri("/rbac/roles/remove")
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {}", valid_token))
        .header("x-user-id", "user1")
        .body(Body::from(remove_role_payload.to_string()))
        .unwrap();

    let response = app.clone().oneshot(request).await.unwrap();
    println!("Remove role status: {}", response.status());
    assert_eq!(response.status(), StatusCode::OK);

    // Test remove permission
    println!("Testing remove permission...");
    let remove_perm_payload = json!({
        "role_id": test_role.id,
        "permission_id": test_perm.id
    });

    let request = Request::builder()
        .method("POST")
        .uri("/rbac/permissions/remove")
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {}", valid_token))
        .header("x-user-id", "user1")
        .body(Body::from(remove_perm_payload.to_string()))
        .unwrap();

    let response = app.clone().oneshot(request).await.unwrap();
    println!("Remove permission status: {}", response.status());
    assert_eq!(response.status(), StatusCode::OK);

    // Test delete permission
    println!("Testing delete permission...");
    let request = Request::builder()
        .method("DELETE")
        .uri(format!("/rbac/permissions/{}", test_perm.id))
        .header("authorization", format!("Bearer {}", valid_token))
        .header("x-user-id", "user1")
        .body(Body::empty())
        .unwrap();

    let response = app.clone().oneshot(request).await.unwrap();
    println!("Delete permission status: {}", response.status());
    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    // Test delete role
    println!("Testing delete role...");
    let request = Request::builder()
        .method("DELETE")
        .uri(format!("/rbac/roles/{}", test_role.id))
        .header("authorization", format!("Bearer {}", valid_token))
        .header("x-user-id", "user1")
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    println!("Delete role status: {}", response.status());
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn test_user_management_handlers_comprehensive() {
    let state = create_app_state_with_admin().await;

    // Set up permissions for the test user
    let role_repo = &state.role_repo;
    let permission_repo = &state.permission_repo;

    let admin_role = role_repo.create_role("admin").await;
    let rbac_read_perm = permission_repo
        .create_permission("rbac:read")
        .await
        .unwrap();
    permission_repo
        .assign_permission(&admin_role.id, &rbac_read_perm.id)
        .await
        .unwrap();
    role_repo.assign_role("user1", &admin_role.id).await;

    let app = create_test_router(state);

    // Test get user roles
    let request = Request::builder()
        .method("GET")
        .uri("/users/user1/roles")
        .header("x-user-id", "user1")
        .body(Body::empty())
        .unwrap();

    let response = app.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // Test get effective permissions
    let request = Request::builder()
        .method("GET")
        .uri("/users/user1/effective-permissions")
        .header("x-user-id", "user1")
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_abac_handlers_comprehensive() {
    let state = create_app_state_with_admin().await;

    // Set up permissions for the test user
    let role_repo = &state.role_repo;
    let permission_repo = &state.permission_repo;

    let admin_role = role_repo.create_role("admin").await;
    let rbac_manage_perm = permission_repo
        .create_permission("rbac:manage")
        .await
        .unwrap();
    let rbac_read_perm = permission_repo
        .create_permission("rbac:read")
        .await
        .unwrap();

    permission_repo
        .assign_permission(&admin_role.id, &rbac_manage_perm.id)
        .await
        .unwrap();
    permission_repo
        .assign_permission(&admin_role.id, &rbac_read_perm.id)
        .await
        .unwrap();
    role_repo.assign_role("user1", &admin_role.id).await;

    // Create a test ABAC policy first
    let test_policy = state
        .abac_policy_repo
        .create_policy(AbacPolicy {
            id: uuid::Uuid::new_v4().to_string(),
            name: "test-policy".to_string(),
            effect: AbacEffect::Allow,
            conditions: vec![AbacCondition {
                attribute: "user.role".to_string(),
                operator: "equals".to_string(),
                value: "admin".to_string(),
            }],
            priority: Some(100),
            conflict_resolution: Some(ConflictResolutionStrategy::DenyOverrides),
        })
        .await
        .unwrap();

    let app = create_test_router(state);

    // Test create ABAC policy
    let create_policy_payload = json!({
        "name": "test-policy",
        "effect": "Allow",
        "conditions": [
            {
                "attribute": "user.role",
                "operator": "equals",
                "value": "admin"
            }
        ],
        "priority": 100,
        "conflict_resolution": "deny_overrides"
    });

    println!("Testing create ABAC policy...");
    let request = Request::builder()
        .method("POST")
        .uri("/abac/policies")
        .header("content-type", "application/json")
        .header("x-user-id", "user1")
        .body(Body::from(create_policy_payload.to_string()))
        .unwrap();

    let response = app.clone().oneshot(request).await.unwrap();
    println!("Create ABAC policy status: {}", response.status());
    assert_eq!(response.status(), StatusCode::CREATED);

    // Test list ABAC policies
    println!("Testing list ABAC policies...");
    let request = Request::builder()
        .method("GET")
        .uri("/abac/policies")
        .header("x-user-id", "user1")
        .body(Body::empty())
        .unwrap();

    let response = app.clone().oneshot(request).await.unwrap();
    println!("List ABAC policies status: {}", response.status());
    assert_eq!(response.status(), StatusCode::OK);

    // Test update ABAC policy
    let update_policy_payload = json!({
        "name": "updated-policy",
        "effect": "Deny",
        "conditions": [
            {
                "attribute": "user.role",
                "operator": "equals",
                "value": "user"
            }
        ],
        "priority": 200,
        "conflict_resolution": "allow_overrides"
    });

    println!("Testing update ABAC policy...");
    let request = Request::builder()
        .method("PUT")
        .uri(format!("/abac/policies/{}", test_policy.id))
        .header("content-type", "application/json")
        .header("x-user-id", "user1")
        .body(Body::from(update_policy_payload.to_string()))
        .unwrap();

    let response = app.clone().oneshot(request).await.unwrap();
    println!("Update ABAC policy status: {}", response.status());
    assert_eq!(response.status(), StatusCode::OK);

    // Test assign ABAC policy
    let assign_policy_payload = json!({
        "target_type": "user",
        "target_id": "user1",
        "policy_id": test_policy.id
    });

    println!("Testing assign ABAC policy...");
    let request = Request::builder()
        .method("POST")
        .uri("/abac/policies/assign")
        .header("content-type", "application/json")
        .header("x-user-id", "user1")
        .body(Body::from(assign_policy_payload.to_string()))
        .unwrap();

    let response = app.clone().oneshot(request).await.unwrap();
    println!("Assign ABAC policy status: {}", response.status());
    assert_eq!(response.status(), StatusCode::OK);

    // Test evaluate ABAC policies
    let evaluate_payload = json!({
        "user_id": "user1",
        "permission_name": "read:resource",
        "attributes": {
            "user.role": "admin",
            "resource.type": "document"
        }
    });

    let request = Request::builder()
        .method("POST")
        .uri("/abac/evaluate")
        .header("content-type", "application/json")
        .header("x-user-id", "user1")
        .body(Body::from(evaluate_payload.to_string()))
        .unwrap();

    let response = app.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // Test delete ABAC policy
    let request = Request::builder()
        .method("DELETE")
        .uri(format!("/abac/policies/{}", test_policy.id))
        .header("x-user-id", "user1")
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn test_permission_group_handlers_comprehensive() {
    let state = create_app_state_with_admin().await;
    let app = create_test_router(state);

    // Test create permission group
    let create_group_payload = json!({
        "name": "test-group",
        "description": "Test permission group",
        "category": "test",
        "metadata": {
            "version": "1.0"
        }
    });

    println!("Testing create permission group...");
    let request = Request::builder()
        .method("POST")
        .uri("/permission-groups")
        .header("content-type", "application/json")
        .header("x-user-id", "user1")
        .body(Body::from(create_group_payload.to_string()))
        .unwrap();

    let response = app.clone().oneshot(request).await.unwrap();
    println!("Create permission group status: {}", response.status());
    assert_eq!(response.status(), StatusCode::CREATED);

    // Test list permission groups
    println!("Testing list permission groups...");
    let request = Request::builder()
        .method("GET")
        .uri("/permission-groups")
        .header("x-user-id", "user1")
        .body(Body::empty())
        .unwrap();

    let response = app.clone().oneshot(request).await.unwrap();
    println!("List permission groups status: {}", response.status());
    assert_eq!(response.status(), StatusCode::OK);

    // Test get permission group
    println!("Testing get permission group...");
    let request = Request::builder()
        .method("GET")
        .uri("/permission-groups/group1")
        .header("x-user-id", "user1")
        .body(Body::empty())
        .unwrap();

    let response = app.clone().oneshot(request).await.unwrap();
    println!("Get permission group status: {}", response.status());
    assert_eq!(response.status(), StatusCode::OK);

    // Test update permission group
    let update_group_payload = json!({
        "name": "updated-group",
        "description": "Updated permission group",
        "category": "updated",
        "is_active": false
    });

    println!("Testing update permission group...");
    let request = Request::builder()
        .method("PUT")
        .uri("/permission-groups/group1")
        .header("content-type", "application/json")
        .header("x-user-id", "user1")
        .body(Body::from(update_group_payload.to_string()))
        .unwrap();

    let response = app.clone().oneshot(request).await.unwrap();
    println!("Update permission group status: {}", response.status());
    assert_eq!(response.status(), StatusCode::OK);

    // Test get permissions in group
    println!("Testing get permissions in group...");
    let request = Request::builder()
        .method("GET")
        .uri("/permission-groups/group1/permissions")
        .header("x-user-id", "user1")
        .body(Body::empty())
        .unwrap();

    let response = app.clone().oneshot(request).await.unwrap();
    println!("Get permissions in group status: {}", response.status());
    assert_eq!(response.status(), StatusCode::OK);

    // Test delete permission group
    println!("Testing delete permission group...");
    let request = Request::builder()
        .method("DELETE")
        .uri("/permission-groups/group1")
        .header("x-user-id", "user1")
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    println!("Delete permission group status: {}", response.status());
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn test_error_handling_comprehensive() {
    let state = create_app_state_with_admin().await;
    let app = create_test_router(state);

    // Test invalid login
    let invalid_login_payload = json!({
        "email": "nonexistent@example.com",
        "password": "wrongpassword"
    });

    let request = Request::builder()
        .method("POST")
        .uri("/auth/login")
        .header("content-type", "application/json")
        .body(Body::from(invalid_login_payload.to_string()))
        .unwrap();

    let response = app.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    // Test duplicate user registration
    let duplicate_user_payload = json!({
        "email": "test@example.com",
        "password": "password"
    });

    let request = Request::builder()
        .method("POST")
        .uri("/auth/register")
        .header("content-type", "application/json")
        .body(Body::from(duplicate_user_payload.to_string()))
        .unwrap();

    let response = app.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::CONFLICT);

    // Test invalid token validation
    let invalid_token_payload = json!({
        "token": "invalid.jwt.token"
    });

    let request = Request::builder()
        .method("POST")
        .uri("/auth/validate-token")
        .header("content-type", "application/json")
        .body(Body::from(invalid_token_payload.to_string()))
        .unwrap();

    let response = app.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // Test refresh token with invalid token
    let invalid_refresh_payload = json!({
        "refresh_token": "invalid.refresh.token"
    });

    let request = Request::builder()
        .method("POST")
        .uri("/auth/refresh-token")
        .header("content-type", "application/json")
        .body(Body::from(invalid_refresh_payload.to_string()))
        .unwrap();

    let response = app.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    // Test logout with invalid token
    let invalid_logout_payload = json!({
        "refresh_token": "invalid.refresh.token"
    });

    let request = Request::builder()
        .method("POST")
        .uri("/auth/logout")
        .header("content-type", "application/json")
        .body(Body::from(invalid_logout_payload.to_string()))
        .unwrap();

    let response = app.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    // Test insufficient permissions
    let request = Request::builder()
        .method("DELETE")
        .uri("/rbac/roles/test-role")
        .header("x-user-id", "user-without-permissions")
        .body(Body::empty())
        .unwrap();

    let response = app.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    // Test invalid ABAC policy effect
    let invalid_abac_payload = json!({
        "name": "invalid-policy",
        "effect": "InvalidEffect",
        "conditions": []
    });

    let request = Request::builder()
        .method("POST")
        .uri("/abac/policies")
        .header("content-type", "application/json")
        .header("x-user-id", "user1")
        .body(Body::from(invalid_abac_payload.to_string()))
        .unwrap();

    let response = app.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    // Test invalid target type for ABAC policy assignment
    let invalid_assign_payload = json!({
        "target_type": "invalid",
        "target_id": "user1",
        "policy_id": "policy1"
    });

    let request = Request::builder()
        .method("POST")
        .uri("/abac/policies/assign")
        .header("content-type", "application/json")
        .header("x-user-id", "user1")
        .body(Body::from(invalid_assign_payload.to_string()))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}
