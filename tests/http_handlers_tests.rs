use authentication_service::{
    application::{
        command_bus::CommandBus,
        query_bus::QueryBus,
        services::{AuthorizationService, PasswordResetService, PasswordService, TokenService},
    },
    domain::user::User,
    infrastructure::{
        AbacPolicyRepository, InMemoryAbacPolicyRepository, InMemoryPermissionGroupRepository,
        InMemoryPermissionRepository, InMemoryRefreshTokenRepository, InMemoryRoleRepository,
        InMemoryUserRepository, PermissionRepository, RoleRepository,
    },
    interface::{AppState, *},
};
use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use bcrypt::{DEFAULT_COST, hash};
use std::sync::Arc;
use tower::ServiceExt;

fn setup_test_env() {
    unsafe {
        std::env::set_var("JWT_SECRET", "test-secret-key-for-testing-only");
        std::env::set_var("JWT_EXPIRATION", "1");
        std::env::set_var("JWT_TIME_UNIT", "hours");
    }
}

async fn mock_app_state() -> AppState {
    setup_test_env();

    // Create a test user with hashed password
    let password_hash = hash("password", DEFAULT_COST).unwrap();
    let test_user = User {
        id: "user1".to_string(),
        email: "user@example.com".to_string(),
        password_hash,
        roles: vec!["user".to_string()],
        is_locked: false,
        failed_login_attempts: 0,
    };

    let user_repo = Arc::new(InMemoryUserRepository::new(vec![test_user]))
        as Arc<dyn authentication_service::infrastructure::UserRepository>;
    let refresh_token_repo = Arc::new(InMemoryRefreshTokenRepository::new())
        as Arc<dyn authentication_service::infrastructure::RefreshTokenRepository>;
    let role_repo: Arc<dyn RoleRepository> = Arc::new(InMemoryRoleRepository::new());
    let abac_policy_repo: Arc<dyn AbacPolicyRepository> =
        Arc::new(InMemoryAbacPolicyRepository::new());
    let permission_repo: Arc<dyn PermissionRepository> =
        Arc::new(InMemoryPermissionRepository::new());
    let permission_group_repo = Arc::new(InMemoryPermissionGroupRepository::new());
    let token_service = Arc::new(TokenService);
    let password_service = Arc::new(PasswordService);

    // Create CQRS buses
    let command_bus = Arc::new(CommandBus::new());
    let query_bus = Arc::new(QueryBus::new());

    // Register essential command handlers
    command_bus
        .register_handler::<authentication_service::application::commands::AuthenticateUserCommand, _>(
            authentication_service::application::command_handlers::AuthenticateUserCommandHandler::new(
                user_repo.clone(),
            ),
        )
        .await;

    // Register essential query handlers
    query_bus
        .register_handler::<authentication_service::application::queries::CheckPermissionQuery, _>(
            authentication_service::application::query_handlers::CheckPermissionQueryHandler::new(
                role_repo.clone(),
                permission_repo.clone(),
                abac_policy_repo.clone(),
            ),
        )
        .await;

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

    AppState {
        user_repo,
        role_repo,
        permission_repo,
        abac_policy_repo,
        permission_group_repo,
        refresh_token_repo,
        token_service,
        password_service,
        password_reset_service: Arc::new(PasswordResetService),
        authorization_service: Arc::new(AuthorizationService),
        command_bus,
        query_bus,
    }
}

#[tokio::test]
async fn test_login_handler_success() {
    let state = mock_app_state().await;
    let app = Router::new()
        .route("/v1/iam/auth/login", axum::routing::post(login_handler))
        .with_state(Arc::new(state));
    let payload = LoginRequest {
        email: "user@example.com".to_string(),
        password: "password".to_string(),
    };
    let req = Request::builder()
        .method("POST")
        .uri("/v1/iam/auth/login")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&payload).unwrap()))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_login_handler_invalid_credentials() {
    let state = mock_app_state().await;
    let app = Router::new()
        .route("/v1/iam/auth/login", axum::routing::post(login_handler))
        .with_state(Arc::new(state));
    let payload = LoginRequest {
        email: "user@example.com".to_string(),
        password: "wrongpassword".to_string(),
    };
    let req = Request::builder()
        .method("POST")
        .uri("/v1/iam/auth/login")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&payload).unwrap()))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_validate_token_handler_missing_token() {
    let state = mock_app_state().await;
    let app = Router::new()
        .route(
            "/v1/iam/validate-token",
            axum::routing::post(validate_token_handler),
        )
        .with_state(Arc::new(state));
    let payload = ValidateTokenRequest {
        token: "".to_string(),
    };
    let req = Request::builder()
        .method("POST")
        .uri("/v1/iam/validate-token")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&payload).unwrap()))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Parse response body to check valid: false
    let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let response: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(response["valid"], false);
}

#[tokio::test]
async fn test_refresh_token_handler_invalid_token() {
    let state = mock_app_state().await;
    let app = Router::new()
        .route(
            "/v1/iam/refresh-token",
            axum::routing::post(refresh_token_handler),
        )
        .with_state(Arc::new(state));
    let payload = RefreshTokenRequest {
        refresh_token: "invalid".to_string(),
    };
    let req = Request::builder()
        .method("POST")
        .uri("/v1/iam/refresh-token")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&payload).unwrap()))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_logout_handler_invalid_token() {
    let state = mock_app_state().await;
    let app = Router::new()
        .route("/v1/iam/auth/logout", axum::routing::post(logout_handler))
        .with_state(Arc::new(state));
    let payload = LogoutRequest {
        refresh_token: "invalid".to_string(),
    };
    let req = Request::builder()
        .method("POST")
        .uri("/v1/iam/auth/logout")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&payload).unwrap()))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_create_role_handler() {
    let state = mock_app_state().await;

    // Create a valid JWT token for testing
    let token_service = TokenService;
    let test_user = User {
        id: "user1".to_string(),
        email: "user@example.com".to_string(),
        password_hash: "".to_string(),
        roles: vec!["user".to_string()],
        is_locked: false,
        failed_login_attempts: 0,
    };
    let refresh_token_repo = Arc::new(InMemoryRefreshTokenRepository::new());
    let (access_token, _) = token_service
        .issue_tokens(&test_user, &refresh_token_repo)
        .await
        .unwrap();

    let app = Router::new()
        .route("/v1/iam/roles", axum::routing::post(create_role_handler))
        .with_state(Arc::new(state));
    let payload = CreateRoleRequest {
        name: "test_role".to_string(),
    };
    let req = Request::builder()
        .method("POST")
        .uri("/v1/iam/roles")
        .header("content-type", "application/json")
        .header("x-user-id", "user1")
        .header("authorization", format!("Bearer {}", access_token))
        .body(Body::from(serde_json::to_vec(&payload).unwrap()))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    // Handler requires authentication and rbac:manage permission, so expect 403
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn test_list_roles_handler() {
    let state = mock_app_state().await;
    let app = Router::new()
        .route("/v1/iam/roles", axum::routing::get(list_roles_handler))
        .with_state(Arc::new(state));
    let req = Request::builder()
        .method("GET")
        .uri("/v1/iam/roles")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_delete_role_handler() {
    let state = mock_app_state().await;
    let app = Router::new()
        .route(
            "/v1/iam/roles/{role_id}",
            axum::routing::delete(delete_role_handler),
        )
        .with_state(Arc::new(state));
    let req = Request::builder()
        .method("DELETE")
        .uri("/v1/iam/roles/test_role")
        .header("x-user-id", "user1")
        .header("authorization", "Bearer test-token")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    // Handler requires rbac:manage permission, so expect 403
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn test_assign_role_handler() {
    let state = mock_app_state().await;
    let app = Router::new()
        .route(
            "/v1/iam/roles/assign",
            axum::routing::post(assign_role_handler),
        )
        .with_state(Arc::new(state));
    let payload = AssignRoleRequest {
        user_id: "user1".to_string(),
        role_id: "test_role".to_string(),
    };
    let req = Request::builder()
        .method("POST")
        .uri("/v1/iam/roles/assign")
        .header("content-type", "application/json")
        .header("x-user-id", "user1")
        .header("authorization", "Bearer test-token")
        .body(Body::from(serde_json::to_vec(&payload).unwrap()))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    // Handler requires rbac:manage permission, so expect 403
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn test_remove_role_handler() {
    let state = mock_app_state().await;
    let app = Router::new()
        .route(
            "/v1/iam/roles/remove",
            axum::routing::post(remove_role_handler),
        )
        .with_state(Arc::new(state));
    let payload = RemoveRoleRequest {
        user_id: "user1".to_string(),
        role_id: "test_role".to_string(),
    };
    let req = Request::builder()
        .method("POST")
        .uri("/v1/iam/roles/remove")
        .header("content-type", "application/json")
        .header("x-user-id", "user1")
        .header("authorization", "Bearer test-token")
        .body(Body::from(serde_json::to_vec(&payload).unwrap()))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    // Handler requires rbac:manage permission, so expect 403
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn test_create_permission_handler() {
    let state = mock_app_state().await;
    let app = Router::new()
        .route(
            "/v1/iam/permissions",
            axum::routing::post(create_permission_handler),
        )
        .with_state(Arc::new(state));
    let payload = CreatePermissionRequest {
        name: "test_permission".to_string(),
    };
    let req = Request::builder()
        .method("POST")
        .uri("/v1/iam/permissions")
        .header("content-type", "application/json")
        .header("x-user-id", "user1")
        .header("authorization", "Bearer test-token")
        .body(Body::from(serde_json::to_vec(&payload).unwrap()))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    // Handler requires rbac:manage permission, so expect 403
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn test_list_permissions_handler() {
    let state = mock_app_state().await;
    let app = Router::new()
        .route(
            "/v1/iam/permissions",
            axum::routing::get(list_permissions_handler),
        )
        .with_state(Arc::new(state));
    let req = Request::builder()
        .method("GET")
        .uri("/v1/iam/permissions")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_delete_permission_handler() {
    let state = mock_app_state().await;
    let app = Router::new()
        .route(
            "/v1/iam/permissions/{permission_id}",
            axum::routing::delete(delete_permission_handler),
        )
        .with_state(Arc::new(state));
    let req = Request::builder()
        .method("DELETE")
        .uri("/v1/iam/permissions/test_permission")
        .header("x-user-id", "user1")
        .header("authorization", "Bearer test-token")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    // Handler requires rbac:manage permission, so expect 403
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn test_assign_permission_handler() {
    let state = mock_app_state().await;
    let app = Router::new()
        .route(
            "/v1/iam/permissions/assign",
            axum::routing::post(assign_permission_handler),
        )
        .with_state(Arc::new(state));
    let payload = AssignPermissionRequest {
        role_id: "test_role".to_string(),
        permission_id: "test_permission".to_string(),
    };
    let req = Request::builder()
        .method("POST")
        .uri("/v1/iam/permissions/assign")
        .header("content-type", "application/json")
        .header("x-user-id", "user1")
        .header("authorization", "Bearer test-token")
        .body(Body::from(serde_json::to_vec(&payload).unwrap()))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    // Handler requires rbac:manage permission, so expect 403
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn test_remove_permission_handler() {
    let state = mock_app_state().await;
    let app = Router::new()
        .route(
            "/v1/iam/permissions/remove",
            axum::routing::post(remove_permission_handler),
        )
        .with_state(Arc::new(state));
    let payload = RemovePermissionRequest {
        role_id: "test_role".to_string(),
        permission_id: "test_permission".to_string(),
    };
    let req = Request::builder()
        .method("POST")
        .uri("/v1/iam/permissions/remove")
        .header("content-type", "application/json")
        .header("x-user-id", "user1")
        .header("authorization", "Bearer test-token")
        .body(Body::from(serde_json::to_vec(&payload).unwrap()))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    // Handler requires rbac:manage permission, so expect 403
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn test_create_abac_policy_handler() {
    let state = mock_app_state().await;
    let app = Router::new()
        .route(
            "/v1/iam/abac-policies",
            axum::routing::post(create_abac_policy_handler),
        )
        .with_state(Arc::new(state));
    let payload = AbacPolicyRequest {
        name: "test_policy".to_string(),
        effect: "allow".to_string(),
        conditions: vec![],
        priority: Some(50),
        conflict_resolution: Some("deny_overrides".to_string()),
    };
    let req = Request::builder()
        .method("POST")
        .uri("/v1/iam/abac-policies")
        .header("content-type", "application/json")
        .header("x-user-id", "user1")
        .header("authorization", "Bearer test-token")
        .body(Body::from(serde_json::to_vec(&payload).unwrap()))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    // Handler requires rbac:manage permission, so expect 403
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn test_list_abac_policies_handler() {
    let state = mock_app_state().await;
    let app = Router::new()
        .route(
            "/v1/iam/abac-policies",
            axum::routing::get(list_abac_policies_handler),
        )
        .with_state(Arc::new(state));
    let req = Request::builder()
        .method("GET")
        .uri("/v1/iam/abac-policies")
        .header("x-user-id", "user1")
        .header("authorization", "Bearer test-token")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    // Handler requires rbac:manage permission, so expect 403
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn test_delete_abac_policy_handler() {
    let state = mock_app_state().await;
    let app = Router::new()
        .route(
            "/v1/iam/abac-policies/{policy_id}",
            axum::routing::delete(delete_abac_policy_handler),
        )
        .with_state(Arc::new(state));
    let req = Request::builder()
        .method("DELETE")
        .uri("/v1/iam/abac-policies/test_policy")
        .header("x-user-id", "user1")
        .header("authorization", "Bearer test-token")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    // Handler requires rbac:manage permission, so expect 403
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn test_assign_abac_policy_handler() {
    let state = mock_app_state().await;
    let app = Router::new()
        .route(
            "/v1/iam/abac-policies/assign",
            axum::routing::post(assign_abac_policy_handler),
        )
        .with_state(Arc::new(state));
    let payload = AssignAbacPolicyRequest {
        target_type: "user".to_string(),
        target_id: "user1".to_string(),
        policy_id: "test_policy".to_string(),
    };
    let req = Request::builder()
        .method("POST")
        .uri("/v1/iam/abac-policies/assign")
        .header("content-type", "application/json")
        .header("x-user-id", "user1")
        .header("authorization", "Bearer test-token")
        .body(Body::from(serde_json::to_vec(&payload).unwrap()))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    // Handler requires rbac:manage permission, so expect 403
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}
