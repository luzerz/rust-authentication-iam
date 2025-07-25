use authentication_service::infrastructure::{
    InMemoryUserRepository, InMemoryRefreshTokenRepository, InMemoryRoleRepository, 
    InMemoryAbacPolicyRepository, InMemoryPermissionRepository, UserRepository, 
    RefreshTokenRepository, RoleRepository, AbacPolicyRepository, PermissionRepository
};
use authentication_service::domain::user::User;
use authentication_service::domain::abac_policy::{AbacPolicy, AbacEffect, AbacCondition};
use bcrypt::{DEFAULT_COST, hash};

#[tokio::test]
async fn test_in_memory_user_repository_find_by_email() {
    let password_hash = hash("password", DEFAULT_COST).unwrap();
    let user = User {
        id: "user1".to_string(),
        email: "user@example.com".to_string(),
        password_hash,
        roles: vec![],
        is_locked: false,
    };
    let repo = InMemoryUserRepository::new(vec![user.clone()]);
    let found = repo.find_by_email("user@example.com").await;
    assert!(found.is_some());
    let found = found.unwrap();
    assert_eq!(found.email, "user@example.com");
    assert!(repo.find_by_email("notfound@example.com").await.is_none());
}

#[tokio::test]
async fn test_in_memory_refresh_token_repository() {
    let repo = InMemoryRefreshTokenRepository::new();
    let token = authentication_service::application::services::RefreshToken {
        jti: "token1".to_string(),
        user_id: "user1".to_string(),
        expires_at: chrono::Utc::now().naive_utc(),
        revoked: false,
    };
    assert_eq!(repo.is_valid("token1").await.unwrap(), false);
    repo.insert(token).await.unwrap();
    assert_eq!(repo.is_valid("token1").await.unwrap(), true);
    repo.revoke("token1").await.unwrap();
    assert_eq!(repo.is_valid("token1").await.unwrap(), false);
}

#[tokio::test]
async fn test_in_memory_role_repository_create_and_list() {
    let repo = InMemoryRoleRepository::new();
    let role = repo.create_role("admin").await;
    assert_eq!(role.name, "admin");
    let roles = repo.list_roles().await;
    assert!(roles.iter().any(|r| r.name == "admin"));
}

#[tokio::test]
async fn test_in_memory_permission_repository_create_and_list() {
    let repo = InMemoryPermissionRepository::new();
    let perm = repo.create_permission("read").await.unwrap();
    assert_eq!(perm.name, "read");
    let perms = repo.list_permissions().await.unwrap();
    assert!(perms.iter().any(|p| p.name == "read"));
}

#[tokio::test]
async fn test_in_memory_abac_policy_repository_create_and_list() {
    let repo = InMemoryAbacPolicyRepository::new();
    let policy = AbacPolicy {
        id: "policy1".to_string(),
        name: "test_policy".to_string(),
        effect: AbacEffect::Allow,
        conditions: vec![AbacCondition {
            attribute: "user.role".to_string(),
            operator: "eq".to_string(),
            value: "admin".to_string(),
        }],
    };
    let created = repo.create_policy(policy.clone()).await.unwrap();
    assert_eq!(created.name, "test_policy");
    let policies = repo.list_policies().await.unwrap();
    assert!(policies.iter().any(|p| p.name == "test_policy"));
} 