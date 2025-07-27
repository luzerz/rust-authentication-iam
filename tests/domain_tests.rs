use authentication_service::domain::{
    abac_policy::{AbacCondition, AbacEffect, AbacPolicy},
    audit::{AuditEvent, AuditEventType},
    permission::Permission,
    permission_group::PermissionGroup,
    role::Role,
    user::User,
};
use bcrypt::{DEFAULT_COST, hash};
use serde_json::json;

// ===== USER DOMAIN TESTS =====

#[test]
fn test_user_creation_and_validation() {
    let password_hash = hash("password123", DEFAULT_COST).unwrap();
    let user = User {
        id: "user1".to_string(),
        email: "test@example.com".to_string(),
        password_hash: password_hash.clone(),
        roles: vec!["user".to_string()],
        is_locked: false,
        failed_login_attempts: 0,
    };

    assert_eq!(user.id, "user1");
    assert_eq!(user.email, "test@example.com");
    assert_eq!(user.password_hash, password_hash);
    assert_eq!(user.roles, vec!["user".to_string()]);
    assert!(!user.is_locked);
    assert_eq!(user.failed_login_attempts, 0);
}

#[test]
fn test_user_with_multiple_roles() {
    let password_hash = hash("password123", DEFAULT_COST).unwrap();
    let user = User {
        id: "admin1".to_string(),
        email: "admin@example.com".to_string(),
        password_hash,
        roles: vec![
            "admin".to_string(),
            "user".to_string(),
            "moderator".to_string(),
        ],
        is_locked: false,
        failed_login_attempts: 0,
    };

    assert_eq!(user.roles.len(), 3);
    assert!(user.roles.contains(&"admin".to_string()));
    assert!(user.roles.contains(&"user".to_string()));
    assert!(user.roles.contains(&"moderator".to_string()));
}

#[test]
fn test_locked_user() {
    let password_hash = hash("password123", DEFAULT_COST).unwrap();
    let user = User {
        id: "locked1".to_string(),
        email: "locked@example.com".to_string(),
        password_hash,
        roles: vec![],
        is_locked: true,
        failed_login_attempts: 5,
    };

    assert!(user.is_locked);
    assert_eq!(user.failed_login_attempts, 5);
}

// ===== ROLE DOMAIN TESTS =====

#[test]
fn test_role_creation() {
    let role = Role {
        id: "role1".to_string(),
        name: "admin".to_string(),
        permissions: vec!["read".to_string(), "write".to_string()],
        parent_role_id: None,
    };

    assert_eq!(role.id, "role1");
    assert_eq!(role.name, "admin");
    assert_eq!(
        role.permissions,
        vec!["read".to_string(), "write".to_string()]
    );
    assert!(role.parent_role_id.is_none());
}

#[test]
fn test_role_with_parent() {
    let role = Role {
        id: "child_role".to_string(),
        name: "moderator".to_string(),
        permissions: vec!["read".to_string()],
        parent_role_id: Some("parent_role".to_string()),
    };

    assert_eq!(role.parent_role_id, Some("parent_role".to_string()));
}

#[test]
fn test_role_hierarchy() {
    let parent_role = Role {
        id: "parent".to_string(),
        name: "admin".to_string(),
        permissions: vec!["read".to_string(), "write".to_string()],
        parent_role_id: None,
    };

    let child_role = Role {
        id: "child".to_string(),
        name: "moderator".to_string(),
        permissions: vec!["read".to_string()],
        parent_role_id: Some(parent_role.id.clone()),
    };

    assert_eq!(child_role.parent_role_id, Some(parent_role.id));
}

// ===== PERMISSION DOMAIN TESTS =====

#[test]
fn test_permission_creation() {
    let permission = Permission {
        id: "perm1".to_string(),
        name: "read_users".to_string(),
        description: Some("Read user information".to_string()),
        group_id: None,
        metadata: json!({}),
        is_active: true,
    };

    assert_eq!(permission.id, "perm1");
    assert_eq!(permission.name, "read_users");
    assert_eq!(
        permission.description,
        Some("Read user information".to_string())
    );
    assert!(permission.group_id.is_none());
    assert_eq!(permission.metadata, json!({}));
    assert!(permission.is_active);
}

#[test]
fn test_permission_without_description() {
    let permission = Permission {
        id: "perm2".to_string(),
        name: "write_users".to_string(),
        description: None,
        group_id: None,
        metadata: json!({}),
        is_active: true,
    };

    assert!(permission.description.is_none());
    assert!(permission.group_id.is_none());
    assert!(permission.is_active);
}

// ===== PERMISSION GROUP DOMAIN TESTS =====

#[test]
fn test_permission_group_creation() {
    let group = PermissionGroup {
        id: "group1".to_string(),
        name: "user_management".to_string(),
        description: Some("Permissions for managing users".to_string()),
        category: Some("administration".to_string()),
        metadata: json!({"version": "1.0", "priority": "high"}),
        is_active: true,
    };

    assert_eq!(group.id, "group1");
    assert_eq!(group.name, "user_management");
    assert_eq!(
        group.description,
        Some("Permissions for managing users".to_string())
    );
    assert_eq!(group.category, Some("administration".to_string()));
    assert_eq!(
        group.metadata,
        json!({"version": "1.0", "priority": "high"})
    );
    assert!(group.is_active);
}

#[test]
fn test_inactive_permission_group() {
    let group = PermissionGroup {
        id: "group2".to_string(),
        name: "deprecated_group".to_string(),
        description: None,
        category: None,
        metadata: json!({}),
        is_active: false,
    };

    assert!(!group.is_active);
    assert!(group.description.is_none());
    assert!(group.category.is_none());
}

// ===== ABAC POLICY DOMAIN TESTS =====

#[test]
fn test_abac_policy_creation() {
    let condition = AbacCondition {
        attribute: "user.role".to_string(),
        operator: "equals".to_string(),
        value: "admin".to_string(),
    };

    let policy = AbacPolicy {
        id: "policy1".to_string(),
        name: "admin_access".to_string(),
        effect: AbacEffect::Allow,
        conditions: vec![condition],
        priority: Some(100),
        conflict_resolution: None,
    };

    assert_eq!(policy.id, "policy1");
    assert_eq!(policy.name, "admin_access");
    assert_eq!(policy.conditions.len(), 1);
    assert!(matches!(policy.effect, AbacEffect::Allow));
    assert_eq!(policy.priority, Some(100));
}

#[test]
fn test_abac_policy_with_multiple_conditions() {
    let condition1 = AbacCondition {
        attribute: "user.role".to_string(),
        operator: "equals".to_string(),
        value: "admin".to_string(),
    };

    let condition2 = AbacCondition {
        attribute: "resource.type".to_string(),
        operator: "in".to_string(),
        value: "users,roles,permissions".to_string(),
    };

    let policy = AbacPolicy {
        id: "policy2".to_string(),
        name: "admin_resource_access".to_string(),
        effect: AbacEffect::Deny,
        conditions: vec![condition1, condition2],
        priority: Some(50),
        conflict_resolution: None,
    };

    assert_eq!(policy.conditions.len(), 2);
    assert!(matches!(policy.effect, AbacEffect::Deny));
    assert_eq!(policy.priority, Some(50));
}

#[test]
fn test_abac_condition_operators() {
    let equals_condition = AbacCondition {
        attribute: "user.id".to_string(),
        operator: "equals".to_string(),
        value: "user123".to_string(),
    };

    let in_condition = AbacCondition {
        attribute: "user.roles".to_string(),
        operator: "in".to_string(),
        value: "admin,moderator".to_string(),
    };

    let greater_condition = AbacCondition {
        attribute: "user.age".to_string(),
        operator: "greater_than".to_string(),
        value: "18".to_string(),
    };

    assert_eq!(equals_condition.operator, "equals");
    assert_eq!(in_condition.operator, "in");
    assert_eq!(greater_condition.operator, "greater_than");
}

// ===== AUDIT EVENT DOMAIN TESTS =====

#[test]
fn test_audit_event_creation() {
    let details = json!({
        "action": "login",
        "method": "password",
        "ip": "192.168.1.1"
    });

    let event = AuditEvent::new(
        AuditEventType::Login,
        Some("user123".to_string()),
        details.clone(),
        true,
    );

    assert_eq!(event.user_id, Some("user123".to_string()));
    assert!(event.success);
    assert!(event.error_message.is_none());
    assert_eq!(event.details, details);
    assert!(matches!(event.event_type, AuditEventType::Login));
}

#[test]
fn test_audit_event_with_error() {
    let details = json!({
        "action": "login",
        "method": "password"
    });

    let event = AuditEvent::new(
        AuditEventType::FailedLogin,
        Some("user123".to_string()),
        details,
        true,
    )
    .with_error("Invalid credentials".to_string());

    assert!(!event.success);
    assert_eq!(event.error_message, Some("Invalid credentials".to_string()));
    assert!(matches!(event.event_type, AuditEventType::FailedLogin));
}

#[test]
fn test_audit_event_with_context() {
    let details = json!({
        "action": "login",
        "method": "password"
    });

    let event = AuditEvent::new(
        AuditEventType::Login,
        Some("user123".to_string()),
        details,
        true,
    )
    .with_context(
        Some("192.168.1.1".to_string()),
        Some("Mozilla/5.0 (Windows NT 10.0; Win64; x64)".to_string()),
    );

    assert_eq!(event.ip_address, Some("192.168.1.1".to_string()));
    assert_eq!(
        event.user_agent,
        Some("Mozilla/5.0 (Windows NT 10.0; Win64; x64)".to_string())
    );
}

#[test]
fn test_audit_event_types() {
    let login_event = AuditEvent::new(
        AuditEventType::Login,
        Some("user123".to_string()),
        json!({}),
        true,
    );
    assert!(matches!(login_event.event_type, AuditEventType::Login));

    let logout_event = AuditEvent::new(
        AuditEventType::Logout,
        Some("user123".to_string()),
        json!({}),
        true,
    );
    assert!(matches!(logout_event.event_type, AuditEventType::Logout));

    let token_refresh_event = AuditEvent::new(
        AuditEventType::TokenRefresh,
        Some("user123".to_string()),
        json!({}),
        true,
    );
    assert!(matches!(
        token_refresh_event.event_type,
        AuditEventType::TokenRefresh
    ));

    let password_change_event = AuditEvent::new(
        AuditEventType::PasswordChange,
        Some("user123".to_string()),
        json!({}),
        true,
    );
    assert!(matches!(
        password_change_event.event_type,
        AuditEventType::PasswordChange
    ));
}

// ===== INTEGRATION TESTS =====

#[test]
fn test_user_with_roles_and_permissions() {
    // Create a user with roles
    let user = User {
        id: "user1".to_string(),
        email: "test@example.com".to_string(),
        password_hash: hash("password", DEFAULT_COST).unwrap(),
        roles: vec!["admin".to_string(), "user".to_string()],
        is_locked: false,
        failed_login_attempts: 0,
    };

    // Create roles
    let admin_role = Role {
        id: "admin".to_string(),
        name: "admin".to_string(),
        permissions: vec!["read_all".to_string(), "write_all".to_string()],
        parent_role_id: None,
    };

    let user_role = Role {
        id: "user".to_string(),
        name: "user".to_string(),
        permissions: vec!["read_own".to_string()],
        parent_role_id: None,
    };

    // Verify user has expected roles
    assert!(user.roles.contains(&"admin".to_string()));
    assert!(user.roles.contains(&"user".to_string()));

    // Verify roles have expected permissions
    assert!(admin_role.permissions.contains(&"read_all".to_string()));
    assert!(admin_role.permissions.contains(&"write_all".to_string()));
    assert!(user_role.permissions.contains(&"read_own".to_string()));
}

#[test]
fn test_abac_policy_evaluation_scenario() {
    // Create an ABAC policy for admin access
    let admin_condition = AbacCondition {
        attribute: "user.roles".to_string(),
        operator: "contains".to_string(),
        value: "admin".to_string(),
    };

    let admin_policy = AbacPolicy {
        id: "admin_policy".to_string(),
        name: "admin_access".to_string(),
        effect: AbacEffect::Allow,
        conditions: vec![admin_condition],
        priority: Some(100),
        conflict_resolution: None,
    };

    // Create a deny policy for locked accounts
    let locked_condition = AbacCondition {
        attribute: "user.is_locked".to_string(),
        operator: "equals".to_string(),
        value: "true".to_string(),
    };

    let locked_policy = AbacPolicy {
        id: "locked_policy".to_string(),
        name: "deny_locked_users".to_string(),
        effect: AbacEffect::Deny,
        conditions: vec![locked_condition],
        priority: Some(200), // Higher priority
        conflict_resolution: None,
    };

    // Verify policy structure
    assert!(matches!(admin_policy.effect, AbacEffect::Allow));
    assert!(matches!(locked_policy.effect, AbacEffect::Deny));
    assert!(locked_policy.priority > admin_policy.priority);
}

#[test]
fn test_audit_trail_scenario() {
    // Simulate a user login session
    let user_id = "user123".to_string();

    // Login event
    let login_event = AuditEvent::new(
        AuditEventType::Login,
        Some(user_id.clone()),
        json!({
            "method": "password",
            "ip": "192.168.1.1"
        }),
        true,
    )
    .with_context(
        Some("192.168.1.1".to_string()),
        Some("Mozilla/5.0".to_string()),
    );

    // Token refresh event
    let refresh_event = AuditEvent::new(
        AuditEventType::TokenRefresh,
        Some(user_id.clone()),
        json!({
            "token_type": "access_token",
            "expires_in": 3600
        }),
        true,
    );

    // Logout event
    let logout_event = AuditEvent::new(
        AuditEventType::Logout,
        Some(user_id.clone()),
        json!({
            "reason": "user_initiated"
        }),
        true,
    );

    // Verify all events belong to the same user
    assert_eq!(login_event.user_id, Some(user_id.clone()));
    assert_eq!(refresh_event.user_id, Some(user_id.clone()));
    assert_eq!(logout_event.user_id, Some(user_id));

    // Verify all events are successful
    assert!(login_event.success);
    assert!(refresh_event.success);
    assert!(logout_event.success);

    // Verify event types
    assert!(matches!(login_event.event_type, AuditEventType::Login));
    assert!(matches!(
        refresh_event.event_type,
        AuditEventType::TokenRefresh
    ));
    assert!(matches!(logout_event.event_type, AuditEventType::Logout));
}
