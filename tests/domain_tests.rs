use authentication_service::domain::{
    abac_policy::AbacPolicy, permission::Permission, role::Role, token::Token, user::User,
};
use bcrypt::{DEFAULT_COST, hash};
use chrono::{Duration, Utc};

#[test]
fn test_token_creation_and_validation() {
    // Test access token creation
    let access_token = Token {
        token: "access_token_123".to_string(),
        user_id: "user1".to_string(),
        expires_at: Utc::now() + Duration::hours(1),
        token_type: authentication_service::domain::token::TokenType::Access,
    };
    assert_eq!(access_token.user_id, "user1");
    assert!(access_token.is_access());
    assert!(!access_token.is_refresh());

    // Test refresh token creation
    let refresh_token = Token {
        token: "refresh_token_456".to_string(),
        user_id: "user1".to_string(),
        expires_at: Utc::now() + Duration::hours(24),
        token_type: authentication_service::domain::token::TokenType::Refresh,
    };
    assert_eq!(refresh_token.user_id, "user1");
    assert!(refresh_token.is_refresh());
    assert!(!refresh_token.is_access());

    // Test token expiration
    let mut token = Token {
        token: "test_token".to_string(),
        user_id: "user1".to_string(),
        expires_at: Utc::now() + Duration::hours(1),
        token_type: authentication_service::domain::token::TokenType::Access,
    };
    assert!(!token.is_expired());

    // Set token to expired
    token.expires_at = Utc::now() - Duration::hours(1);
    assert!(token.is_expired());

    // Set token to future
    token.expires_at = Utc::now() + Duration::hours(1);
    assert!(!token.is_expired());
}

#[test]
fn test_permission_creation_and_validation() {
    // Test permission creation
    let permission = Permission::new("perm1".to_string(), "read".to_string());
    assert_eq!(permission.name, "read");
    assert_eq!(permission.id, "perm1");

    // Test permission with different name
    let permission = Permission::new("perm2".to_string(), "write".to_string());
    assert_eq!(permission.name, "write");
    assert_eq!(permission.id, "perm2");

    // Test permission ID uniqueness
    let permission1 = Permission::new("perm1".to_string(), "read".to_string());
    let permission2 = Permission::new("perm2".to_string(), "write".to_string());
    assert_ne!(permission1.id, permission2.id);
}

#[test]
fn test_user_creation_and_validation() {
    let password_hash = hash("password", DEFAULT_COST).unwrap();

    // Test user creation
    let user = User {
        id: "user1".to_string(),
        email: "user@example.com".to_string(),
        password_hash: password_hash.clone(),
        roles: vec![],
        is_locked: false,
    };
    assert_eq!(user.email, "user@example.com");
    assert_eq!(user.password_hash, password_hash);
    assert!(user.roles.is_empty());
    assert!(!user.is_locked);
    assert!(!user.id.is_empty());

    // Test user with roles
    let mut user = User {
        id: "user2".to_string(),
        email: "admin@example.com".to_string(),
        password_hash: password_hash.clone(),
        roles: vec![],
        is_locked: false,
    };
    user.add_role("admin".to_string());
    user.add_role("user".to_string());
    assert_eq!(user.roles.len(), 2);
    assert!(user.roles.contains(&"admin".to_string()));
    assert!(user.roles.contains(&"user".to_string()));

    // Test duplicate role addition
    user.add_role("admin".to_string());
    assert_eq!(user.roles.len(), 2); // Should not add duplicate

    // Test role removal
    user.remove_role("user");
    assert_eq!(user.roles.len(), 1);
    assert!(user.roles.contains(&"admin".to_string()));
    assert!(!user.roles.contains(&"user".to_string()));

    // Test removing non-existent role
    user.remove_role("nonexistent");
    assert_eq!(user.roles.len(), 1); // Should not change

    // Test account locking
    user.lock_account();
    assert!(user.is_locked);

    user.unlock_account();
    assert!(!user.is_locked);

    // Test password verification
    assert!(user.verify_password("password").unwrap());
    assert!(!user.verify_password("wrongpassword").unwrap());
}

#[test]
fn test_role_creation_and_validation() {
    // Test role creation
    let role = Role {
        id: "role1".to_string(),
        name: "admin".to_string(),
        permissions: vec![],
    };
    assert_eq!(role.name, "admin");
    assert!(role.permissions.is_empty());
    assert!(!role.id.is_empty());

    // Test role with permissions
    let mut role = Role {
        id: "role2".to_string(),
        name: "moderator".to_string(),
        permissions: vec![],
    };
    role.add_permission("read".to_string());
    role.add_permission("write".to_string());
    assert_eq!(role.permissions.len(), 2);
    assert!(role.permissions.contains(&"read".to_string()));
    assert!(role.permissions.contains(&"write".to_string()));

    // Test duplicate permission addition
    role.add_permission("read".to_string());
    assert_eq!(role.permissions.len(), 2); // Should not add duplicate

    // Test permission removal
    role.remove_permission("write");
    assert_eq!(role.permissions.len(), 1);
    assert!(role.permissions.contains(&"read".to_string()));
    assert!(!role.permissions.contains(&"write".to_string()));

    // Test removing non-existent permission
    role.remove_permission("nonexistent");
    assert_eq!(role.permissions.len(), 1); // Should not change

    // Test role ID uniqueness
    let role1 = Role {
        id: "role1".to_string(),
        name: "admin".to_string(),
        permissions: vec![],
    };
    let role2 = Role {
        id: "role2".to_string(),
        name: "user".to_string(),
        permissions: vec![],
    };
    assert_ne!(role1.id, role2.id);
}

#[test]
fn test_abac_policy_creation_and_validation() {
    // Test ABAC policy creation
    let conditions = vec![
        authentication_service::domain::abac_policy::AbacCondition {
            attribute: "user.role".to_string(),
            operator: "equals".to_string(),
            value: "admin".to_string(),
        },
        authentication_service::domain::abac_policy::AbacCondition {
            attribute: "resource.type".to_string(),
            operator: "equals".to_string(),
            value: "sensitive".to_string(),
        },
    ];

    let policy = AbacPolicy {
        id: "policy1".to_string(),
        name: "admin_access".to_string(),
        effect: authentication_service::domain::abac_policy::AbacEffect::Allow,
        conditions: conditions.clone(),
    };
    assert_eq!(policy.name, "admin_access");
    assert_eq!(policy.conditions.len(), 2);
    assert!(!policy.id.is_empty());

    // Test policy with deny effect
    let policy = AbacPolicy {
        id: "policy2".to_string(),
        name: "restricted_access".to_string(),
        effect: authentication_service::domain::abac_policy::AbacEffect::Deny,
        conditions: vec![],
    };
    assert!(policy.conditions.is_empty());

    // Test policy ID uniqueness
    let policy1 = AbacPolicy {
        id: "policy1".to_string(),
        name: "policy1".to_string(),
        effect: authentication_service::domain::abac_policy::AbacEffect::Allow,
        conditions: vec![],
    };
    let policy2 = AbacPolicy {
        id: "policy2".to_string(),
        name: "policy2".to_string(),
        effect: authentication_service::domain::abac_policy::AbacEffect::Allow,
        conditions: vec![],
    };
    assert_ne!(policy1.id, policy2.id);
}

#[test]
fn test_abac_condition_creation() {
    let condition = authentication_service::domain::abac_policy::AbacCondition {
        attribute: "user.department".to_string(),
        operator: "in".to_string(),
        value: "engineering,product".to_string(),
    };

    assert_eq!(condition.attribute, "user.department");
    assert_eq!(condition.operator, "in");
    assert_eq!(condition.value, "engineering,product");
}

#[test]
fn test_user_clone_and_debug() {
    let password_hash = hash("password", DEFAULT_COST).unwrap();
    let user = User {
        id: "user1".to_string(),
        email: "user@example.com".to_string(),
        password_hash: password_hash.clone(),
        roles: vec![],
        is_locked: false,
    };

    // Test cloning
    let cloned_user = user.clone();
    assert_eq!(user.id, cloned_user.id);
    assert_eq!(user.email, cloned_user.email);
    assert_eq!(user.password_hash, cloned_user.password_hash);
    assert_eq!(user.roles, cloned_user.roles);
    assert_eq!(user.is_locked, cloned_user.is_locked);

    // Test debug formatting
    let debug_str = format!("{:?}", user);
    assert!(debug_str.contains("User"));
    assert!(debug_str.contains("user@example.com"));
}

#[test]
fn test_role_clone_and_debug() {
    let mut role = Role {
        id: "role1".to_string(),
        name: "admin".to_string(),
        permissions: vec![],
    };
    role.add_permission("read".to_string());
    role.add_permission("write".to_string());

    // Test cloning
    let cloned_role = role.clone();
    assert_eq!(role.id, cloned_role.id);
    assert_eq!(role.name, cloned_role.name);
    assert_eq!(role.permissions, cloned_role.permissions);

    // Note: Role doesn't implement Debug, so we skip debug formatting test
}

#[test]
fn test_permission_clone() {
    let permission = Permission::new("perm1".to_string(), "read".to_string());

    // Test cloning
    let cloned_permission = permission.clone();
    assert_eq!(permission.id, cloned_permission.id);
    assert_eq!(permission.name, cloned_permission.name);

    // Note: Permission doesn't implement Debug, so we skip debug formatting test
}

#[test]
fn test_token_clone() {
    let token = Token {
        token: "test_token".to_string(),
        user_id: "user1".to_string(),
        expires_at: Utc::now() + Duration::hours(1),
        token_type: authentication_service::domain::token::TokenType::Access,
    };

    // Test cloning
    let cloned_token = token.clone();
    assert_eq!(token.user_id, cloned_token.user_id);
    assert_eq!(token.expires_at, cloned_token.expires_at);
    // Note: TokenType doesn't implement PartialEq, so we skip that comparison

    // Note: Token doesn't implement Debug, so we skip debug formatting test
}

#[test]
fn test_abac_policy_clone_and_debug() {
    let conditions = vec![authentication_service::domain::abac_policy::AbacCondition {
        attribute: "user.role".to_string(),
        operator: "equals".to_string(),
        value: "admin".to_string(),
    }];

    let policy = AbacPolicy {
        id: "policy1".to_string(),
        name: "admin_policy".to_string(),
        effect: authentication_service::domain::abac_policy::AbacEffect::Allow,
        conditions: conditions.clone(),
    };

    // Test cloning
    let cloned_policy = policy.clone();
    assert_eq!(policy.id, cloned_policy.id);
    assert_eq!(policy.name, cloned_policy.name);
    assert_eq!(policy.conditions.len(), cloned_policy.conditions.len());

    // Test debug formatting
    let debug_str = format!("{:?}", policy);
    assert!(debug_str.contains("AbacPolicy"));
    assert!(debug_str.contains("admin_policy"));
}
