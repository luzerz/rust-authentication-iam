use authentication_service::{
    application::{
        command_bus::CommandBus, commands::LoginUserCommand, query_bus::QueryBus, services::*,
    },
    domain::{
        abac_policy::{AbacCondition, AbacEffect, AbacPolicy, ConflictResolutionStrategy},
        permission_group::PermissionGroup,
        user::User,
    },
    infrastructure::{
        InMemoryAbacPolicyRepository, InMemoryPermissionGroupRepository,
        InMemoryPermissionRepository, InMemoryRoleRepository, InMemoryUserRepository,
    },
    interface::AppState,
};
use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode},
};
use bcrypt::{DEFAULT_COST, hash};
use chrono::Utc;
use serde_json::json;
use std::sync::Arc;
use tower::util::ServiceExt;

// Mock refresh token repository for testing
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

// Helper function to create a test user
fn create_test_user() -> User {
    User {
        id: "user1".to_string(),
        email: "test@example.com".to_string(),
        password_hash: hash("password", DEFAULT_COST).unwrap(),
        roles: vec!["user".to_string()],
        is_locked: false,
        failed_login_attempts: 0,
    }
}

// Helper function to create app state
fn create_app_state() -> Arc<AppState> {
    let test_user = create_test_user();
    let user_repo = Arc::new(InMemoryUserRepository::new(vec![test_user.clone()]));
    let role_repo = Arc::new(InMemoryRoleRepository::new());
    let permission_repo = Arc::new(InMemoryPermissionRepository::new());
    let abac_policy_repo = Arc::new(InMemoryAbacPolicyRepository::new());
    let permission_group_repo = Arc::new(InMemoryPermissionGroupRepository::new());
    let refresh_token_repo = Arc::new(MockRefreshTokenRepository::new());

    let token_service = Arc::new(TokenService);
    let password_service = Arc::new(PasswordService);
    let password_reset_service = Arc::new(PasswordResetService);
    let authorization_service = Arc::new(AuthorizationService);

    let app_state = Arc::new(AppState {
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
        command_bus: Arc::new(CommandBus::new()),
        query_bus: Arc::new(QueryBus::new()),
    });

    app_state
}

// Helper function to create router
fn test_abac_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route(
            "/abac/policies",
            axum::routing::post(
                authentication_service::interface::http_handlers::create_abac_policy_handler,
            ),
        )
        .route(
            "/abac/policies",
            axum::routing::get(
                authentication_service::interface::http_handlers::list_abac_policies_handler,
            ),
        )
        .route(
            "/abac/policies/{id}",
            axum::routing::delete(
                authentication_service::interface::http_handlers::delete_abac_policy_handler,
            ),
        )
        .with_state(state)
}

#[tokio::test]
async fn test_user_authentication_flow() {
    unsafe {
        std::env::set_var("JWT_SECRET", "test-secret-key-for-testing-only");
    }
    let state = create_app_state();
    let command = LoginUserCommand {
        email: "test@example.com".to_string(),
        password: "password".to_string(),
        command_id: "123".to_string(),
        timestamp: Utc::now(),
        ip_address: Some("127.0.0.1".to_string()),
        user_agent: Some("test-agent".to_string()),
    };

    let result = state.command_bus.execute(command).await;

    match result {
        Ok(result_box) => {
            if let Ok(result_box) = result_box.downcast::<(String, String)>() {
                let (access_token, refresh_token) = *result_box;
                assert!(!access_token.is_empty());
                assert!(!refresh_token.is_empty());
            } else {
                panic!("Invalid result type from login command");
            }
        }
        Err(e) => {
            println!("Authentication failed with error: {:?}", e);
            panic!("Authentication should succeed");
        }
    }
}

#[tokio::test]
async fn test_role_management_flow() {
    let state = create_app_state();
    let role_repo = &state.role_repo;

    // Create roles
    let admin_role = role_repo.create_role("admin").await;
    let user_role = role_repo.create_role("user").await;

    // List roles
    let roles = role_repo.list_roles().await;
    assert_eq!(roles.len(), 2);
    assert!(roles.iter().any(|r| r.name == "admin"));
    assert!(roles.iter().any(|r| r.name == "user"));

    // Assign role to user
    role_repo.assign_role("user1", &admin_role.id).await;

    // Get user roles
    let user_roles = role_repo.get_roles_for_user("user1").await.unwrap();
    assert_eq!(user_roles.len(), 1);
    assert_eq!(user_roles[0].name, "admin");

    // Remove role from user
    role_repo.remove_role("user1", &admin_role.id).await;
    let user_roles_after_remove = role_repo.get_roles_for_user("user1").await.unwrap();
    assert_eq!(user_roles_after_remove.len(), 0);

    // Delete role
    role_repo.delete_role(&user_role.id).await;
    let roles_after_delete = role_repo.list_roles().await;
    assert_eq!(roles_after_delete.len(), 1);
}

#[tokio::test]
async fn test_permission_management_flow() {
    let state = create_app_state();
    let permission_repo = &state.permission_repo;
    let role_repo = &state.role_repo;

    // Create permissions
    let read_perm = permission_repo.create_permission("read").await.unwrap();
    let write_perm = permission_repo.create_permission("write").await.unwrap();

    // Create role
    let admin_role = role_repo.create_role("admin").await;

    // Assign permissions to role
    permission_repo
        .assign_permission(&admin_role.id, &read_perm.id)
        .await
        .unwrap();
    permission_repo
        .assign_permission(&admin_role.id, &write_perm.id)
        .await
        .unwrap();

    // Check if role has permissions
    let has_read = permission_repo
        .role_has_permission(&admin_role.id, &read_perm.id)
        .await
        .unwrap();
    assert!(has_read);

    // Get permissions for role
    let role_permissions = permission_repo
        .get_permissions_for_role(&admin_role.id)
        .await
        .unwrap();
    assert_eq!(role_permissions.len(), 2);

    // Remove permission from role
    permission_repo
        .remove_permission(&admin_role.id, &write_perm.id)
        .await
        .unwrap();

    let role_permissions_after_remove = permission_repo
        .get_permissions_for_role(&admin_role.id)
        .await
        .unwrap();
    assert_eq!(role_permissions_after_remove.len(), 1);

    // Delete permission
    permission_repo
        .delete_permission(&read_perm.id)
        .await
        .unwrap();
    let all_permissions = permission_repo.list_permissions().await.unwrap();
    assert_eq!(all_permissions.len(), 1);
}

#[tokio::test]
async fn test_abac_policy_management_flow() {
    let state = create_app_state();
    let abac_repo = &state.abac_policy_repo;

    // Create ABAC policy
    let policy = AbacPolicy {
        id: "policy1".to_string(),
        name: "Test Policy".to_string(),
        effect: AbacEffect::Allow,
        conditions: vec![AbacCondition {
            attribute: "user.role".to_string(),
            operator: "equals".to_string(),
            value: "admin".to_string(),
        }],
        priority: Some(100),
        conflict_resolution: Some(ConflictResolutionStrategy::DenyOverrides),
    };

    let created_policy = abac_repo.create_policy(policy).await.unwrap();
    assert_eq!(created_policy.name, "Test Policy");

    // Get policy
    let retrieved_policy = abac_repo
        .get_policy(&created_policy.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(retrieved_policy.name, "Test Policy");

    // Update policy
    let mut updated_policy = retrieved_policy.clone();
    updated_policy.name = "Updated Policy".to_string();
    let updated = abac_repo
        .update_policy(&created_policy.id, updated_policy)
        .await
        .unwrap();
    assert_eq!(updated.name, "Updated Policy");

    // List policies
    let policies = abac_repo.list_policies().await.unwrap();
    assert_eq!(policies.len(), 1);

    // Assign policy to user
    abac_repo
        .assign_policy_to_user("user1", &created_policy.id)
        .await
        .unwrap();

    // Get policies for user
    let user_policies = abac_repo.get_policies_for_user("user1").await.unwrap();
    assert_eq!(user_policies.len(), 1);

    // Delete policy
    abac_repo.delete_policy(&created_policy.id).await.unwrap();
    let policies_after_delete = abac_repo.list_policies().await.unwrap();
    assert_eq!(policies_after_delete.len(), 0);
}

#[tokio::test]
async fn test_abac_policy_http_endpoints() {
    unsafe {
        std::env::set_var("JWT_SECRET", "test-secret-key-for-testing-only");
    }
    let state = create_app_state();

    // Create a role and permission for the test user
    let role_repo = &state.role_repo;
    let permission_repo = &state.permission_repo;

    let admin_role = role_repo.create_role("admin").await;
    let rbac_manage_perm = permission_repo
        .create_permission("rbac:manage")
        .await
        .unwrap();
    permission_repo
        .assign_permission(&admin_role.id, &rbac_manage_perm.id)
        .await
        .unwrap();
    role_repo.assign_role("user1", &admin_role.id).await;

    let app = test_abac_router(state);

    // Test create policy
    let create_payload = json!({
        "name": "Test Policy",
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

    let request = Request::builder()
        .method("POST")
        .uri("/abac/policies")
        .header("content-type", "application/json")
        .header("x-user-id", "user1")
        .body(Body::from(create_payload.to_string()))
        .unwrap();

    let response = app.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);

    // Test list policies
    let request = Request::builder()
        .method("GET")
        .uri("/abac/policies")
        .header("x-user-id", "user1")
        .body(Body::empty())
        .unwrap();

    let response = app.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // Test delete policy (we need to get the policy ID from the create response)
    let request = Request::builder()
        .method("DELETE")
        .uri("/abac/policies/policy1")
        .header("x-user-id", "user1")
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn test_permission_group_management_flow() {
    let state = create_app_state();
    let group_repo = &state.permission_group_repo;

    // Create permission group
    let mut group = PermissionGroup::new("group1".to_string(), "Test Group".to_string());
    group = group.with_description("A test permission group".to_string());
    group = group.with_category("test".to_string());

    let created_group = group_repo.create_group(group).await.unwrap();
    assert_eq!(created_group.name, "Test Group");

    // Get group
    let retrieved_group = group_repo
        .get_group(&created_group.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(retrieved_group.name, "Test Group");

    // Update group
    let mut updated_group = retrieved_group.clone();
    updated_group.name = "updated_group".to_string();
    group_repo.update_group(&updated_group).await.unwrap();

    // Verify update
    let updated = group_repo
        .get_group(&updated_group.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(updated.name, "updated_group");

    // List groups
    let groups = group_repo.list_groups().await.unwrap();
    assert_eq!(groups.len(), 1);

    // Delete group
    group_repo.delete_group(&created_group.id).await.unwrap();
    let groups_after_delete = group_repo.list_groups().await.unwrap();
    assert_eq!(groups_after_delete.len(), 0);
}

#[tokio::test]
async fn test_user_registration_flow() {
    let state = create_app_state();
    let command = LoginUserCommand {
        email: "newuser@example.com".to_string(),
        password: "newpassword".to_string(),
        command_id: "123".to_string(),
        timestamp: Utc::now(),
        ip_address: Some("127.0.0.1".to_string()),
        user_agent: Some("test-agent".to_string()),
    };

    let result = state.command_bus.execute(command).await;

    // This should fail because the user doesn't exist
    assert!(result.is_err());
}

#[tokio::test]
async fn test_permission_group_flow() {
    let state = create_app_state();
    let group_repo = &state.permission_group_repo;

    // Create a permission group
    let group = PermissionGroup::new("group1".to_string(), "Test Group".to_string());
    let created_group = group_repo.create_group(group).await.unwrap();

    // Verify the group was created
    assert_eq!(created_group.name, "Test Group");
    assert!(created_group.is_active);

    // Get the group
    let retrieved_group = group_repo
        .get_group(&created_group.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(retrieved_group.id, created_group.id);

    // List all groups
    let groups = group_repo.list_groups().await.unwrap();
    assert_eq!(groups.len(), 1);
    assert_eq!(groups[0].name, "Test Group");
}
