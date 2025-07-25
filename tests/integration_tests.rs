use async_trait::async_trait;
use authentication_service::application::services::{
    AuthService, AuthZService, PasswordService, TokenService,
};
use authentication_service::domain::abac_policy::{AbacCondition, AbacEffect, AbacPolicy};
use authentication_service::infrastructure::AbacPolicyRepository;
use authentication_service::infrastructure::InMemoryAbacPolicyRepository;
use authentication_service::infrastructure::RefreshTokenRepository;
use authentication_service::infrastructure::{
    InMemoryPermissionRepository, InMemoryRoleRepository,
};
use authentication_service::infrastructure::{
    PermissionRepository, RoleRepository, UserRepository,
};
use authentication_service::interface::{
    AbacConditionDto, AbacPolicyRequest, AppState, AssignAbacPolicyRequest,
    assign_abac_policy_handler, create_abac_policy_handler, delete_abac_policy_handler,
    list_abac_policies_handler,
};
use authentication_service::{
    application::{handlers::*, services::*},
    domain::user::User,
    infrastructure::InMemoryUserRepository,
};
use axum::{Router, routing::delete, routing::get, routing::post};
use bcrypt::{DEFAULT_COST, hash};
use std::collections::HashSet;
use std::sync::Arc;
use tokio::net::TcpListener;

// Mock RefreshTokenRepository for testing
struct MockRefreshTokenRepository {
    revoked: std::sync::Mutex<HashSet<String>>,
}

impl MockRefreshTokenRepository {
    fn new() -> Self {
        Self {
            revoked: std::sync::Mutex::new(HashSet::new()),
        }
    }
}

#[async_trait]
impl RefreshTokenRepository for MockRefreshTokenRepository {
    async fn insert(
        &self,
        _: authentication_service::application::services::RefreshToken,
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

#[tokio::test]
async fn test_full_login_flow() {
    // Set up test environment
    unsafe {
        std::env::set_var("JWT_SECRET", "test-secret-key-for-testing-only");
    }

    // Create test user
    let password_hash = hash("password123", DEFAULT_COST).unwrap();
    let test_user = User {
        id: "user1".to_string(),
        email: "test@example.com".to_string(),
        password_hash,
        roles: vec!["user".to_string()],
        is_locked: false,
    };

    // Create repositories
    let user_repo = Arc::new(InMemoryUserRepository::new(vec![test_user]));
    let refresh_token_repo = Arc::new(MockRefreshTokenRepository::new());

    // Create services
    let auth_service = AuthService;
    let token_service = TokenService;
    let password_service = PasswordService;
    let handler = LoginUserHandler;

    // Test login command
    let cmd = authentication_service::application::commands::LoginUserCommand {
        email: "test@example.com".to_string(),
        password: "password123".to_string(),
    };

    // Execute login
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

    // Verify tokens are generated
    assert!(!access_token.is_empty());
    assert!(!refresh_token.is_empty());
    assert_ne!(access_token, refresh_token);

    // Verify access token can be validated
    let claims = token_service.validate_token(&access_token).unwrap();
    assert_eq!(claims.sub, "user1");
    assert_eq!(claims.roles, vec!["user".to_string()]);
}

#[tokio::test]
async fn test_login_flow_invalid_credentials() {
    // Create test user
    let password_hash = hash("password123", DEFAULT_COST).unwrap();
    let test_user = User {
        id: "user1".to_string(),
        email: "test@example.com".to_string(),
        password_hash,
        roles: vec!["user".to_string()],
        is_locked: false,
    };

    // Create repositories
    let user_repo = Arc::new(InMemoryUserRepository::new(vec![test_user]));
    let refresh_token_repo = Arc::new(MockRefreshTokenRepository::new());

    // Create services
    let auth_service = AuthService;
    let token_service = TokenService;
    let password_service = PasswordService;
    let handler = LoginUserHandler;

    // Test login command with wrong password
    let cmd = authentication_service::application::commands::LoginUserCommand {
        email: "test@example.com".to_string(),
        password: "wrongpassword".to_string(),
    };

    // Execute login
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
async fn test_login_flow_locked_account() {
    // Create locked test user
    let password_hash = hash("password123", DEFAULT_COST).unwrap();
    let locked_user = User {
        id: "locked_user".to_string(),
        email: "locked@example.com".to_string(),
        password_hash,
        roles: vec!["user".to_string()],
        is_locked: true,
    };

    // Create repositories
    let user_repo = Arc::new(InMemoryUserRepository::new(vec![locked_user]));
    let refresh_token_repo = Arc::new(MockRefreshTokenRepository::new());

    // Create services
    let auth_service = AuthService;
    let token_service = TokenService;
    let password_service = PasswordService;
    let handler = LoginUserHandler;

    // Test login command
    let cmd = authentication_service::application::commands::LoginUserCommand {
        email: "locked@example.com".to_string(),
        password: "password123".to_string(),
    };

    // Execute login
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

#[tokio::test]
async fn test_token_refresh_flow() {
    // Set up test environment
    unsafe {
        std::env::set_var("JWT_SECRET", "test-secret-key-for-testing-only");
    }

    // Create test user
    let password_hash = hash("password123", DEFAULT_COST).unwrap();
    let test_user = User {
        id: "user1".to_string(),
        email: "test@example.com".to_string(),
        password_hash,
        roles: vec!["user".to_string()],
        is_locked: false,
    };

    // Create repositories
    let refresh_token_repo = Arc::new(MockRefreshTokenRepository::new());

    // Create services
    let token_service = TokenService;

    // Issue initial tokens
    let (access_token1, refresh_token) = token_service
        .issue_tokens(&test_user, refresh_token_repo.clone())
        .await;

    // Refresh tokens
    let result = token_service
        .refresh_tokens(&refresh_token, &test_user, refresh_token_repo)
        .await;
    assert!(result.is_ok());

    let (access_token2, _) = result.unwrap();

    // Verify new tokens are different
    assert_ne!(access_token1, access_token2);
    assert!(!access_token2.is_empty());

    // Verify new access token is valid
    let claims = token_service.validate_token(&access_token2).unwrap();
    assert_eq!(claims.sub, "user1");
}

#[tokio::test]
async fn test_logout_revokes_refresh_token() {
    // Set up test environment
    unsafe {
        std::env::set_var("JWT_SECRET", "test-secret-key-for-testing-only");
    }

    // Create test user
    let password_hash = hash("password123", DEFAULT_COST).unwrap();
    let test_user = User {
        id: "user1".to_string(),
        email: "test@example.com".to_string(),
        password_hash,
        roles: vec!["user".to_string()],
        is_locked: false,
    };
    let user_repo = Arc::new(InMemoryUserRepository::new(vec![test_user.clone()]));
    let refresh_token_repo = Arc::new(MockRefreshTokenRepository::new());
    let auth_service = AuthService;
    let token_service = TokenService;
    let password_service = PasswordService;
    let handler = LoginUserHandler;

    // Login to get tokens
    let cmd = authentication_service::application::commands::LoginUserCommand {
        email: "test@example.com".to_string(),
        password: "password123".to_string(),
    };
    let (_, refresh_token) = handler
        .handle(
            cmd,
            &auth_service,
            &token_service,
            &password_service,
            user_repo.clone(),
            refresh_token_repo.clone(),
        )
        .await
        .unwrap();

    // Simulate logout (revoke refresh token)
    let claims = token_service.validate_token(&refresh_token).unwrap();
    let _ = refresh_token_repo.revoke(&claims.jti).await;

    // Try to use the revoked refresh token for refresh (should fail)
    let result = token_service
        .refresh_tokens(&refresh_token, &test_user, refresh_token_repo.clone())
        .await;
    assert!(result.is_err());
}

#[test]
fn test_password_service() {
    let password_service = PasswordService;

    // Create user with known password hash
    let user = User {
        id: "user1".to_string(),
        email: "test@example.com".to_string(),
        password_hash: hash("testpassword", DEFAULT_COST).unwrap(),
        roles: vec!["user".to_string()],
        is_locked: false,
    };

    // Test correct password
    assert!(password_service.verify(&user, "testpassword"));

    // Test incorrect password
    assert!(!password_service.verify(&user, "wrongpassword"));
}

#[tokio::test]
async fn test_token_validation() {
    // Set up test environment
    unsafe {
        std::env::set_var("JWT_SECRET", "test-secret-key-for-testing-only");
    }

    let token_service = TokenService;

    // Create test user
    let user = User {
        id: "user1".to_string(),
        email: "test@example.com".to_string(),
        password_hash: "hash".to_string(),
        roles: vec!["admin".to_string(), "user".to_string()],
        is_locked: false,
    };

    // Create a valid token
    let refresh_token_repo = Arc::new(MockRefreshTokenRepository::new());
    let (access_token, _) = token_service.issue_tokens(&user, refresh_token_repo).await;

    // Validate the token
    let claims = token_service.validate_token(&access_token).unwrap();
    assert_eq!(claims.sub, "user1");
    assert_eq!(claims.roles, vec!["admin".to_string(), "user".to_string()]);

    // Test invalid token
    let result = token_service.validate_token("invalid.token.here");
    assert!(result.is_err());
}

#[test]
fn test_user_domain_logic() {
    let mut user = User {
        id: "user1".to_string(),
        email: "test@example.com".to_string(),
        password_hash: "hash".to_string(),
        roles: vec![],
        is_locked: false,
    };

    // Test role management
    user.add_role("admin".to_string());
    assert_eq!(user.roles.len(), 1);
    assert!(user.roles.contains(&"admin".to_string()));

    user.add_role("user".to_string());
    assert_eq!(user.roles.len(), 2);
    assert!(user.roles.contains(&"user".to_string()));

    user.remove_role("admin");
    assert_eq!(user.roles.len(), 1);
    assert!(!user.roles.contains(&"admin".to_string()));
    assert!(user.roles.contains(&"user".to_string()));

    // Test account locking
    assert!(!user.is_account_locked());
    user.lock_account();
    assert!(user.is_account_locked());
    user.unlock_account();
    assert!(!user.is_account_locked());

    // Test password verification
    let password_hash = hash("testpassword", DEFAULT_COST).unwrap();
    user.password_hash = password_hash;
    assert!(user.verify_password("testpassword").unwrap());
    assert!(!user.verify_password("wrongpassword").unwrap());
}

#[tokio::test]
async fn test_abac_policy_crud_and_assignment() {
    // Set up ABAC repo
    let abac_repo = InMemoryAbacPolicyRepository::new();

    // Create a policy
    let policy = AbacPolicy {
        id: "policy1".to_string(),
        name: "can_view_reports".to_string(),
        effect: AbacEffect::Allow,
        conditions: vec![AbacCondition {
            attribute: "department".to_string(),
            operator: "eq".to_string(),
            value: "finance".to_string(),
        }],
    };
    let created = abac_repo.create_policy(policy.clone()).await.unwrap();
    assert_eq!(created.name, "can_view_reports");

    // List policies
    let policies = abac_repo.list_policies().await.unwrap();
    assert_eq!(policies.len(), 1);
    assert_eq!(policies[0].id, "policy1");

    // Assign to user
    abac_repo
        .assign_policy_to_user("user1", "policy1")
        .await
        .unwrap();
    let user_policies = abac_repo.get_policies_for_user("user1").await.unwrap();
    assert_eq!(user_policies.len(), 1);
    assert_eq!(user_policies[0].id, "policy1");

    // Assign to role
    abac_repo
        .assign_policy_to_role("role1", "policy1")
        .await
        .unwrap();
    let role_policies = abac_repo.get_policies_for_role("role1").await.unwrap();
    assert_eq!(role_policies.len(), 1);
    assert_eq!(role_policies[0].id, "policy1");

    // Delete policy
    abac_repo.delete_policy("policy1").await.unwrap();
    let policies = abac_repo.list_policies().await.unwrap();
    assert!(policies.is_empty());
    let user_policies = abac_repo.get_policies_for_user("user1").await.unwrap();
    assert!(user_policies.is_empty());
    let role_policies = abac_repo.get_policies_for_role("role1").await.unwrap();
    assert!(role_policies.is_empty());
}

fn test_abac_router(state: AppState) -> Router {
    Router::new()
        .route("/iam/abac/policies", post(create_abac_policy_handler))
        .route("/iam/abac/policies", get(list_abac_policies_handler))
        .route(
            "/iam/abac/policies/{policy_id}",
            delete(delete_abac_policy_handler),
        )
        .route("/iam/abac/assign", post(assign_abac_policy_handler))
        .with_state(state)
}

#[tokio::test]
async fn test_abac_policy_http_endpoints() {
    // Set up in-memory state
    let user_id = "admin1".to_string();
    let user = authentication_service::domain::user::User {
        id: user_id.clone(),
        email: "admin@example.com".to_string(),
        password_hash: "irrelevant".to_string(),
        roles: vec!["admin".to_string()],
        is_locked: false,
    };
    // rbac:manage role
    let role_repo = InMemoryRoleRepository::new();
    let perm_repo = InMemoryPermissionRepository::new();
    let rbac_manage_perm = perm_repo.create_permission("rbac:manage").await.unwrap();
    let admin_role = role_repo.create_role("admin").await;
    role_repo.assign_role(&user_id, &admin_role.id).await;
    perm_repo
        .assign_permission(&admin_role.id, &rbac_manage_perm.id)
        .await
        .unwrap();

    let abac_repo = Arc::new(InMemoryAbacPolicyRepository::new()) as Arc<dyn AbacPolicyRepository>;
    let role_repo = Arc::new(role_repo) as Arc<dyn RoleRepository>;
    let perm_repo = Arc::new(perm_repo) as Arc<dyn PermissionRepository>;
    let user_repo =
        Arc::new(InMemoryUserRepository::new(vec![user.clone()])) as Arc<dyn UserRepository>;
    let authz_service = Arc::new(AuthZService {
        role_repo: role_repo.clone(),
        permission_repo: perm_repo.clone(),
        abac_repo: abac_repo.clone(),
    });
    let state = AppState {
        user_repo,
        refresh_token_repo: Arc::new(MockRefreshTokenRepository::new()),
        auth_service: Arc::new(AuthService),
        token_service: Arc::new(TokenService),
        password_service: Arc::new(PasswordService),
        handler: Arc::new(LoginUserHandler),
        role_repo,
        permission_repo: perm_repo,
        abac_policy_repo: abac_repo,
        authz_service,
    };
    let app = test_abac_router(state.clone());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app.into_make_service())
            .await
            .unwrap();
    });
    let client = reqwest::Client::new();
    // Helper: set x-user-id header
    let user_header = ("x-user-id", user_id.as_str());
    // Create policy
    let req = AbacPolicyRequest {
        name: "can_view_reports".to_string(),
        effect: "Allow".to_string(),
        conditions: vec![AbacConditionDto {
            attribute: "department".to_string(),
            operator: "eq".to_string(),
            value: "finance".to_string(),
        }],
    };
    let resp = client
        .post(format!("http://{addr}/iam/abac/policies"))
        .header(user_header.0, user_header.1)
        .json(&req)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);
    let policy: serde_json::Value = resp.json().await.unwrap();
    let policy_id = policy["id"].as_str().unwrap();
    // List policies
    let resp = client
        .get(format!("http://{addr}/iam/abac/policies"))
        .header(user_header.0, user_header.1)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let list: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(list["policies"].as_array().unwrap().len(), 1);
    // Assign policy to user
    let assign_req = AssignAbacPolicyRequest {
        target_type: "user".to_string(),
        target_id: user_id.clone(),
        policy_id: policy_id.to_string(),
    };
    let resp = client
        .post(format!("http://{addr}/iam/abac/assign"))
        .header(user_header.0, user_header.1)
        .json(&assign_req)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    // Delete policy
    let resp = client
        .delete(format!("http://{addr}/iam/abac/policies/{policy_id}"))
        .header(user_header.0, user_header.1)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204);
    // Permission enforcement: no x-user-id
    let resp = client
        .post(format!("http://{addr}/iam/abac/policies"))
        .json(&req)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
}
