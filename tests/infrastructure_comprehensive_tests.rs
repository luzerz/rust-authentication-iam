use authentication_service::{
    application::services::RefreshToken,
    domain::{abac_policy::*, audit::*, permission_group::*, user::*},
    infrastructure::*,
};
use chrono::Utc;
use serde_json::json;

#[tokio::test]
async fn test_user_repository_comprehensive() {
    let repo = InMemoryUserRepository::new(vec![]);

    // Test create user
    let user = User {
        id: "user1".to_string(),
        email: "test@example.com".to_string(),
        password_hash: "hashed_password".to_string(),
        roles: vec!["admin".to_string()],
        is_locked: false,
        failed_login_attempts: 0,
    };

    let created_user = repo.create_user(user).await.unwrap();
    assert_eq!(created_user.id, "user1");
    assert_eq!(created_user.email, "test@example.com");

    // Test find by id
    let found_user = repo.find_by_id("user1").await.unwrap().unwrap();
    assert_eq!(found_user.id, "user1");

    // Test find by email
    let found_user = repo.find_by_email("test@example.com").await.unwrap();
    assert_eq!(found_user.email, "test@example.com");

    // Test update user
    let mut updated_user = found_user.clone();
    updated_user.is_locked = true;
    repo.update_user(&updated_user).await.unwrap();

    let found_user = repo.find_by_id("user1").await.unwrap().unwrap();
    assert!(found_user.is_locked);

    // Test update password
    repo.update_password("user1", "new_hash").await.unwrap();
    let found_user = repo.find_by_id("user1").await.unwrap().unwrap();
    assert_eq!(found_user.password_hash, "new_hash");

    // Test find non-existent user
    let result = repo.find_by_id("nonexistent").await.unwrap();
    assert!(result.is_none());
}

#[tokio::test]
async fn test_role_repository_comprehensive() {
    let repo = InMemoryRoleRepository::new();

    // Test create role
    let role = repo.create_role("admin").await;
    assert_eq!(role.name, "admin");

    // Test list roles
    let roles = repo.list_roles().await;
    assert_eq!(roles.len(), 1);

    // Test assign role to user
    repo.assign_role("user1", &role.id).await;
    let user_roles = repo.get_roles_for_user("user1").await.unwrap();
    assert_eq!(user_roles.len(), 1);

    // Test remove role from user
    repo.remove_role("user1", &role.id).await;
    let user_roles = repo.get_roles_for_user("user1").await.unwrap();
    assert_eq!(user_roles.len(), 0);

    // Test set parent role
    let child_role = repo.create_role("child").await;
    repo.set_parent_role(&child_role.id, Some(&role.id))
        .await
        .unwrap();
    let inherited_roles = repo.get_inherited_roles(&child_role.id).await.unwrap();
    assert_eq!(inherited_roles.len(), 1);

    // Test cycle detection
    let would_create_cycle = repo
        .would_create_cycle(&role.id, &child_role.id)
        .await
        .unwrap();
    assert!(would_create_cycle);

    // Test delete role
    repo.delete_role(&role.id).await;
    let roles = repo.list_roles().await;
    assert_eq!(roles.len(), 1); // child role still exists
}

#[tokio::test]
async fn test_permission_repository_comprehensive() {
    let repo = InMemoryPermissionRepository::new();

    // Test create permission
    let permission = repo.create_permission("read:users").await.unwrap();
    assert_eq!(permission.name, "read:users");

    // Test get permission
    let found_permission = repo.get_permission(&permission.id).await.unwrap().unwrap();
    assert_eq!(found_permission.name, "read:users");

    // Test list permissions
    let permissions = repo.list_permissions().await.unwrap();
    assert_eq!(permissions.len(), 1);

    // Test assign permission to role
    repo.assign_permission("role1", &permission.id)
        .await
        .unwrap();
    let role_permissions = repo.get_permissions_for_role("role1").await.unwrap();
    assert_eq!(role_permissions.len(), 1);

    // Test role has permission
    let has_permission = repo
        .role_has_permission("role1", &permission.id)
        .await
        .unwrap();
    assert!(has_permission);

    // Test remove permission from role
    repo.remove_permission("role1", &permission.id)
        .await
        .unwrap();
    let role_permissions = repo.get_permissions_for_role("role1").await.unwrap();
    assert_eq!(role_permissions.len(), 0);

    // Test delete permission
    repo.delete_permission(&permission.id).await.unwrap();
    let permissions = repo.list_permissions().await.unwrap();
    assert_eq!(permissions.len(), 0);
}

#[tokio::test]
async fn test_abac_policy_repository_comprehensive() {
    let repo = InMemoryAbacPolicyRepository::new();

    // Test create ABAC policy
    let policy = AbacPolicy {
        id: "policy1".to_string(),
        name: "test-policy".to_string(),
        effect: AbacEffect::Allow,
        conditions: vec![AbacCondition {
            attribute: "user.role".to_string(),
            operator: "equals".to_string(),
            value: "admin".to_string(),
        }],
        priority: Some(100),
        conflict_resolution: Some(ConflictResolutionStrategy::DenyOverrides),
    };

    let created_policy = repo.create_policy(policy).await.unwrap();
    assert_eq!(created_policy.name, "test-policy");

    // Test get policy
    let found_policy = repo.get_policy("policy1").await.unwrap().unwrap();
    assert_eq!(found_policy.name, "test-policy");

    // Test list policies
    let policies = repo.list_policies().await.unwrap();
    assert_eq!(policies.len(), 1);

    // Test update policy
    let mut updated_policy = found_policy.clone();
    updated_policy.name = "updated-policy".to_string();
    let updated = repo.update_policy("policy1", updated_policy).await.unwrap();
    assert_eq!(updated.name, "updated-policy");

    // Test assign policy to user
    repo.assign_policy_to_user("user1", "policy1")
        .await
        .unwrap();
    let user_policies = repo.get_policies_for_user("user1").await.unwrap();
    assert_eq!(user_policies.len(), 1);

    // Test assign policy to role
    repo.assign_policy_to_role("role1", "policy1")
        .await
        .unwrap();
    let role_policies = repo.get_policies_for_role("role1").await.unwrap();
    assert_eq!(role_policies.len(), 1);

    // Test delete policy
    repo.delete_policy("policy1").await.unwrap();
    let policies = repo.list_policies().await.unwrap();
    assert_eq!(policies.len(), 0);
}

#[tokio::test]
async fn test_permission_group_repository_comprehensive() {
    let repo = InMemoryPermissionGroupRepository::new();

    // Test create permission group
    let group = PermissionGroup {
        id: "group1".to_string(),
        name: "test-group".to_string(),
        description: Some("Test group".to_string()),
        category: Some("test".to_string()),
        is_active: true,
        metadata: json!({"version": "1.0"}),
    };

    let created_group = repo.create_group(group).await.unwrap();
    assert_eq!(created_group.name, "test-group");

    // Test get group
    let found_group = repo.get_group("group1").await.unwrap().unwrap();
    assert_eq!(found_group.name, "test-group");

    // Test list groups
    let groups = repo.list_groups().await.unwrap();
    assert_eq!(groups.len(), 1);

    // Test update group
    let mut updated_group = found_group.clone();
    updated_group.name = "updated-group".to_string();
    repo.update_group(&updated_group).await.unwrap();

    // Test delete group
    repo.delete_group("group1").await.unwrap();
    let groups = repo.list_groups().await.unwrap();
    assert_eq!(groups.len(), 0);
}

#[tokio::test]
async fn test_audit_repository_comprehensive() {
    let repo = InMemoryAuditRepository::new();

    // Test create audit event
    let event = AuditEvent::new(
        AuditEventType::Login,
        Some("user1".to_string()),
        json!({"action": "login", "method": "password"}),
        true,
    );

    repo.log_event(event).await.unwrap();

    // Test get events for user
    let user_events = repo.get_events_for_user("user1", Some(10)).await.unwrap();
    assert_eq!(user_events.len(), 1);

    // Test get events by type
    let events = repo.get_events_by_type("Login", Some(10)).await.unwrap();
    assert_eq!(events.len(), 1);

    // Test get recent events
    let events = repo.get_recent_events(Some(10)).await.unwrap();
    assert_eq!(events.len(), 1);
}

#[tokio::test]
async fn test_refresh_token_repository_comprehensive() {
    let repo = InMemoryRefreshTokenRepository::new();

    // Test insert token
    let token = RefreshToken {
        jti: "token1".to_string(),
        user_id: "user1".to_string(),
        expires_at: Utc::now() + chrono::Duration::hours(24),
    };

    repo.insert(token).await.unwrap();

    // Test is valid
    let is_valid = repo.is_valid("token1").await.unwrap();
    assert!(is_valid);

    // Test revoke token
    repo.revoke("token1").await.unwrap();
    let is_valid = repo.is_valid("token1").await.unwrap();
    assert!(!is_valid);

    // Test non-existent token
    let is_valid = repo.is_valid("nonexistent").await.unwrap();
    assert!(!is_valid);
}

#[tokio::test]
async fn test_repository_error_handling() {
    let user_repo = InMemoryUserRepository::new(vec![]);
    let permission_repo = InMemoryPermissionRepository::new();
    let abac_repo = InMemoryAbacPolicyRepository::new();
    let group_repo = InMemoryPermissionGroupRepository::new();

    // Test find non-existent entities
    assert!(user_repo.find_by_id("nonexistent").await.unwrap().is_none());
    assert!(
        permission_repo
            .get_permission("nonexistent")
            .await
            .unwrap()
            .is_none()
    );
    assert!(abac_repo.get_policy("nonexistent").await.unwrap().is_none());
    assert!(group_repo.get_group("nonexistent").await.unwrap().is_none());

    // Test update non-existent entities
    let user = User {
        id: "nonexistent".to_string(),
        email: "test@example.com".to_string(),
        password_hash: "hash".to_string(),
        roles: vec![],
        is_locked: false,
        failed_login_attempts: 0,
    };
    assert!(user_repo.update_user(&user).await.is_ok());
}

#[tokio::test]
async fn test_repository_edge_cases() {
    let user_repo = InMemoryUserRepository::new(vec![]);
    let role_repo = InMemoryRoleRepository::new();
    let permission_repo = InMemoryPermissionRepository::new();

    // Test create duplicate users
    let user1 = User {
        id: "user1".to_string(),
        email: "test@example.com".to_string(),
        password_hash: "hash1".to_string(),
        roles: vec![],
        is_locked: false,
        failed_login_attempts: 0,
    };
    let user2 = User {
        id: "user2".to_string(),
        email: "test2@example.com".to_string(), // Different email
        password_hash: "hash2".to_string(),
        roles: vec![],
        is_locked: false,
        failed_login_attempts: 0,
    };

    user_repo.create_user(user1).await.unwrap();
    user_repo.create_user(user2).await.unwrap(); // Should succeed with different email

    // Test create duplicate roles
    let role1 = role_repo.create_role("admin").await;
    let role2 = role_repo.create_role("admin").await;
    assert_eq!(role1.name, role2.name);

    // Test create permissions
    let perm1 = permission_repo.create_permission("read").await.unwrap();
    let perm2 = permission_repo.create_permission("write").await.unwrap();
    assert_eq!(perm1.name, "read");
    assert_eq!(perm2.name, "write");
}

#[tokio::test]
async fn test_repository_concurrent_access() {
    use std::sync::Arc;
    use tokio::task;

    let user_repo = Arc::new(InMemoryUserRepository::new(vec![]));
    let role_repo = Arc::new(InMemoryRoleRepository::new());

    // Test concurrent user creation
    let handles: Vec<_> = (0..10)
        .map(|i| {
            let repo = user_repo.clone();
            task::spawn(async move {
                let user = User {
                    id: format!("user{}", i),
                    email: format!("user{}@example.com", i),
                    password_hash: "hash".to_string(),
                    roles: vec![],
                    is_locked: false,
                    failed_login_attempts: 0,
                };
                repo.create_user(user).await
            })
        })
        .collect();

    for handle in handles {
        assert!(handle.await.unwrap().is_ok());
    }

    // Test concurrent role creation
    let handles: Vec<_> = (0..5)
        .map(|i| {
            let repo = role_repo.clone();
            task::spawn(async move { repo.create_role(&format!("role{}", i)).await })
        })
        .collect();

    for handle in handles {
        assert!(handle.await.unwrap().name.starts_with("role"));
    }

    let roles = role_repo.list_roles().await;
    assert_eq!(roles.len(), 5);
}

#[tokio::test]
async fn test_repository_integration_scenarios() {
    // Test user-role-permission integration
    let user_repo = InMemoryUserRepository::new(vec![]);
    let role_repo = InMemoryRoleRepository::new();
    let permission_repo = InMemoryPermissionRepository::new();

    // Create a user
    let user = User {
        id: "user1".to_string(),
        email: "admin@example.com".to_string(),
        password_hash: "hash".to_string(),
        roles: vec![],
        is_locked: false,
        failed_login_attempts: 0,
    };
    user_repo.create_user(user).await.unwrap();

    // Create a role
    let role = role_repo.create_role("admin").await;

    // Create a permission
    let permission = permission_repo
        .create_permission("read:users")
        .await
        .unwrap();

    // Assign role to user
    role_repo.assign_role("user1", &role.id).await;

    // Assign permission to role
    permission_repo
        .assign_permission(&role.id, &permission.id)
        .await
        .unwrap();

    // Verify the relationships
    let user_roles = role_repo.get_roles_for_user("user1").await.unwrap();
    assert_eq!(user_roles.len(), 1);
    assert_eq!(user_roles[0].name, "admin");

    let role_permissions = permission_repo
        .get_permissions_for_role(&role.id)
        .await
        .unwrap();
    assert_eq!(role_permissions.len(), 1);
    assert_eq!(role_permissions[0].name, "read:users");

    // Test permission checking
    let has_permission = permission_repo
        .role_has_permission(&role.id, &permission.id)
        .await
        .unwrap();
    assert!(has_permission);
}

#[tokio::test]
async fn test_abac_policy_evaluation_scenarios() {
    let abac_repo = InMemoryAbacPolicyRepository::new();

    // Create a policy that allows admin access
    let policy = AbacPolicy {
        id: "policy1".to_string(),
        name: "admin_access".to_string(),
        effect: AbacEffect::Allow,
        conditions: vec![AbacCondition {
            attribute: "user.role".to_string(),
            operator: "equals".to_string(),
            value: "admin".to_string(),
        }],
        priority: Some(50),
        conflict_resolution: Some(ConflictResolutionStrategy::DenyOverrides),
    };

    abac_repo.create_policy(policy).await.unwrap();

    // Assign policy to user
    abac_repo
        .assign_policy_to_user("user1", "policy1")
        .await
        .unwrap();

    // Verify policy assignment
    let user_policies = abac_repo.get_policies_for_user("user1").await.unwrap();
    assert_eq!(user_policies.len(), 1);
    assert_eq!(user_policies[0].name, "admin_access");

    // Test policy evaluation (this would typically be done by the AuthZService)
    let policies = abac_repo.list_policies().await.unwrap();
    assert_eq!(policies.len(), 1);
    assert_eq!(policies[0].name, "admin_access");
}

#[tokio::test]
async fn test_audit_trail_scenarios() {
    let audit_repo = InMemoryAuditRepository::new();
    let user_repo = InMemoryUserRepository::new(vec![]);

    // Create a user
    let user = User {
        id: "user1".to_string(),
        email: "test@example.com".to_string(),
        password_hash: "hash".to_string(),
        roles: vec![],
        is_locked: false,
        failed_login_attempts: 0,
    };
    user_repo.create_user(user).await.unwrap();

    // Create audit events for user actions
    let login_event = AuditEvent::new(
        AuditEventType::Login,
        Some("user1".to_string()),
        json!({"action": "login"}),
        true,
    );

    audit_repo.log_event(login_event).await.unwrap();

    // Verify audit trail
    let events = audit_repo
        .get_events_for_user("user1", Some(10))
        .await
        .unwrap();
    assert_eq!(events.len(), 1);
    assert!(matches!(events[0].event_type, AuditEventType::Login));
    assert_eq!(events[0].user_id, Some("user1".to_string()));
}
