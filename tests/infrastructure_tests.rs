use authentication_service::domain::abac_policy::{AbacCondition, AbacEffect, AbacPolicy};
use authentication_service::domain::user::User;
use authentication_service::infrastructure::{
    AbacPolicyRepository, InMemoryAbacPolicyRepository, InMemoryPermissionRepository,
    InMemoryRefreshTokenRepository, InMemoryRoleRepository, InMemoryUserRepository,
    PermissionRepository, PostgresPermissionRepository, PostgresUserRepository,
    RefreshTokenRepository, RoleRepository, UserRepository,
};
use bcrypt::{DEFAULT_COST, hash};
use sqlx::PgPool;

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

#[tokio::test]
async fn test_postgres_permission_repository() {
    // Skip if no database connection available
    let database_url = std::env::var("DATABASE_URL").ok();
    if database_url.is_none() {
        eprintln!("Skipping PostgresPermissionRepository tests - no DATABASE_URL");
        return;
    }

    let pool = PgPool::connect(&database_url.unwrap()).await.unwrap();

    // Clean up any existing test data
    sqlx::query("DELETE FROM role_permissions WHERE permission_id LIKE 'test_%'")
        .execute(&pool)
        .await
        .ok();
    sqlx::query("DELETE FROM permissions WHERE id LIKE 'test_%'")
        .execute(&pool)
        .await
        .ok();

    let repo = PostgresPermissionRepository::new(pool.clone());

    // Test create_permission
    let permission_name = format!(
        "test_read_{}",
        uuid::Uuid::new_v4().to_string().split('-').next().unwrap()
    );
    let permission = repo.create_permission(&permission_name).await.unwrap();
    assert_eq!(permission.name, permission_name);
    assert!(!permission.id.is_empty());

    // Test list_permissions
    let permissions = repo.list_permissions().await.unwrap();
    assert!(permissions.iter().any(|p| p.name == permission_name));

    // Test assign_permission and role_has_permission
    let role_id = format!(
        "test_role_{}",
        uuid::Uuid::new_v4().to_string().split('-').next().unwrap()
    );

    // Create the role first
    let role_name = format!(
        "test_role_{}",
        uuid::Uuid::new_v4().to_string().split('-').next().unwrap()
    );
    sqlx::query("INSERT INTO roles (id, name) VALUES ($1, $2)")
        .bind(&role_id)
        .bind(&role_name)
        .execute(&pool)
        .await
        .unwrap();

    repo.assign_permission(&role_id, &permission.id)
        .await
        .unwrap();
    let has_permission = repo
        .role_has_permission(&role_id, &permission.id)
        .await
        .unwrap();
    assert!(has_permission);

    // Test remove_permission
    repo.remove_permission(&role_id, &permission.id)
        .await
        .unwrap();
    let has_permission = repo
        .role_has_permission(&role_id, &permission.id)
        .await
        .unwrap();
    assert!(!has_permission);

    // Test delete_permission
    repo.delete_permission(&permission.id).await.unwrap();
    let permissions = repo.list_permissions().await.unwrap();
    assert!(!permissions.iter().any(|p| p.id == permission.id));

    // Clean up - only clean up what this test created
    sqlx::query("DELETE FROM role_permissions WHERE permission_id = $1 OR role_id = $2")
        .bind(&permission.id)
        .bind(&role_id)
        .execute(&pool)
        .await
        .ok();
    sqlx::query("DELETE FROM permissions WHERE id = $1")
        .bind(&permission.id)
        .execute(&pool)
        .await
        .ok();
    sqlx::query("DELETE FROM roles WHERE id = $1")
        .bind(&role_id)
        .execute(&pool)
        .await
        .ok();
}

#[tokio::test]
async fn test_postgres_permission_repository_error_handling() {
    // Skip if no database connection available
    let database_url = std::env::var("DATABASE_URL").ok();
    if database_url.is_none() {
        eprintln!("Skipping PostgresPermissionRepository error handling tests - no DATABASE_URL");
        return;
    }

    let pool = PgPool::connect(&database_url.unwrap()).await.unwrap();
    let repo = PostgresPermissionRepository::new(pool.clone());

    // Test role_has_permission with non-existent role and permission
    let has_permission = repo
        .role_has_permission("non_existent_role", "non_existent_permission")
        .await
        .unwrap();
    assert!(!has_permission);

    // Test remove_permission with non-existent role/permission (should not error)
    repo.remove_permission("non_existent_role", "non_existent_permission")
        .await
        .unwrap();

    // Test delete_permission with non-existent permission (should not error)
    repo.delete_permission("non_existent_permission")
        .await
        .unwrap();
}

#[tokio::test]
async fn test_postgres_user_repository() {
    // Skip if no database connection available
    let database_url = std::env::var("DATABASE_URL").ok();
    if database_url.is_none() {
        eprintln!("Skipping PostgresUserRepository tests - no DATABASE_URL");
        return;
    }

    let pool = PgPool::connect(&database_url.unwrap()).await.unwrap();

    // Clean up any existing test data
    sqlx::query("DELETE FROM user_roles WHERE user_id LIKE 'test_%'")
        .execute(&pool)
        .await
        .ok();
    sqlx::query("DELETE FROM users WHERE id LIKE 'test_%'")
        .execute(&pool)
        .await
        .ok();

    let repo = PostgresUserRepository::new(pool.clone());

    // Test find_by_email when user doesn't exist
    let result = repo.find_by_email("nonexistent@example.com").await;
    assert!(result.is_none());

    // Create a test user directly in the database
    let user_id = "test_user_123";
    let email = "test_user@example.com";
    let password_hash = hash("password", DEFAULT_COST).unwrap();

    sqlx::query("INSERT INTO users (id, email, password_hash, is_locked) VALUES ($1, $2, $3, $4)")
        .bind(user_id)
        .bind(email)
        .bind(&password_hash)
        .bind(false)
        .execute(&pool)
        .await
        .unwrap();

    // Test find_by_email when user exists
    let found_user = repo.find_by_email(email).await;
    assert!(found_user.is_some());
    let found_user = found_user.unwrap();
    assert_eq!(found_user.email, email);
    assert_eq!(found_user.id, user_id);
    assert_eq!(found_user.password_hash, password_hash);
    assert!(!found_user.is_locked);

    // Clean up
    sqlx::query("DELETE FROM user_roles WHERE user_id LIKE 'test_%'")
        .execute(&pool)
        .await
        .ok();
    sqlx::query("DELETE FROM users WHERE id LIKE 'test_%'")
        .execute(&pool)
        .await
        .ok();
}

#[tokio::test]
async fn test_postgres_user_repository_with_roles() {
    // Skip if no database connection available
    let database_url = std::env::var("DATABASE_URL").ok();
    if database_url.is_none() {
        eprintln!("Skipping PostgresUserRepository with roles tests - no DATABASE_URL");
        return;
    }

    let pool = PgPool::connect(&database_url.unwrap()).await.unwrap();

    // Clean up any existing test data
    sqlx::query("DELETE FROM user_roles WHERE user_id LIKE 'test_%' OR role_id LIKE 'test_%'")
        .execute(&pool)
        .await
        .ok();
    sqlx::query("DELETE FROM users WHERE id LIKE 'test_%'")
        .execute(&pool)
        .await
        .ok();
    sqlx::query("DELETE FROM roles WHERE id LIKE 'test_%'")
        .execute(&pool)
        .await
        .ok();

    let repo = PostgresUserRepository::new(pool.clone());

    // Create test roles
    let role1_id = format!(
        "test_role_1_{}",
        uuid::Uuid::new_v4().to_string().split('-').next().unwrap()
    );
    let role2_id = format!(
        "test_role_2_{}",
        uuid::Uuid::new_v4().to_string().split('-').next().unwrap()
    );
    let role1_name = format!(
        "admin_{}",
        uuid::Uuid::new_v4().to_string().split('-').next().unwrap()
    );
    let role2_name = format!(
        "user_{}",
        uuid::Uuid::new_v4().to_string().split('-').next().unwrap()
    );

    sqlx::query("INSERT INTO roles (id, name) VALUES ($1, $2), ($3, $4)")
        .bind(&role1_id)
        .bind(&role1_name)
        .bind(&role2_id)
        .bind(&role2_name)
        .execute(&pool)
        .await
        .unwrap();

    // Create a test user
    let user_id = format!(
        "test_user_with_roles_{}",
        uuid::Uuid::new_v4().to_string().split('-').next().unwrap()
    );
    let email = format!(
        "test_user_with_roles_{}@example.com",
        uuid::Uuid::new_v4().to_string().split('-').next().unwrap()
    );
    let password_hash = hash("password", DEFAULT_COST).unwrap();

    sqlx::query("INSERT INTO users (id, email, password_hash, is_locked) VALUES ($1, $2, $3, $4)")
        .bind(&user_id)
        .bind(&email)
        .bind(&password_hash)
        .bind(false)
        .execute(&pool)
        .await
        .unwrap();

    // Assign roles to user
    sqlx::query("INSERT INTO user_roles (user_id, role_id) VALUES ($1, $2), ($1, $3)")
        .bind(&user_id)
        .bind(&role1_id)
        .bind(&role2_id)
        .execute(&pool)
        .await
        .unwrap();

    // Test find_by_email when user exists with roles
    let found_user = repo.find_by_email(&email).await;
    assert!(found_user.is_some());
    let found_user = found_user.unwrap();
    assert_eq!(found_user.email, email);
    assert_eq!(found_user.roles.len(), 2);
    assert!(found_user.roles.contains(&role1_name));
    assert!(found_user.roles.contains(&role2_name));

    // Clean up - only clean up what this test created
    sqlx::query("DELETE FROM user_roles WHERE user_id = $1 OR role_id IN ($2, $3)")
        .bind(&user_id)
        .bind(&role1_id)
        .bind(&role2_id)
        .execute(&pool)
        .await
        .ok();
    sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(&user_id)
        .execute(&pool)
        .await
        .ok();
    sqlx::query("DELETE FROM roles WHERE id IN ($1, $2)")
        .bind(&role1_id)
        .bind(&role2_id)
        .execute(&pool)
        .await
        .ok();
}
