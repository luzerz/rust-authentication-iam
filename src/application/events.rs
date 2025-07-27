use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Base trait for all domain events
pub trait DomainEvent: Send + Sync {
    fn event_id(&self) -> &str;
    fn aggregate_id(&self) -> &str;
    fn occurred_at(&self) -> DateTime<Utc>;
    fn event_type(&self) -> &str;
}

/// User-related domain events
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserCreatedEvent {
    pub event_id: String,
    pub aggregate_id: String,
    pub occurred_at: DateTime<Utc>,
    pub email: String,
    pub user_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserLoggedInEvent {
    pub event_id: String,
    pub aggregate_id: String,
    pub occurred_at: DateTime<Utc>,
    pub user_id: String,
    pub email: String,
    pub ip_address: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserLoginFailedEvent {
    pub event_id: String,
    pub aggregate_id: String,
    pub occurred_at: DateTime<Utc>,
    pub email: String,
    pub reason: String,
    pub ip_address: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserAccountLockedEvent {
    pub event_id: String,
    pub aggregate_id: String,
    pub occurred_at: DateTime<Utc>,
    pub user_id: String,
    pub email: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserPasswordChangedEvent {
    pub event_id: String,
    pub aggregate_id: String,
    pub occurred_at: DateTime<Utc>,
    pub user_id: String,
    pub email: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserRolesAssignedEvent {
    pub event_id: String,
    pub aggregate_id: String,
    pub occurred_at: DateTime<Utc>,
    pub user_id: String,
    pub role_ids: Vec<String>,
}

/// Role-related domain events
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoleCreatedEvent {
    pub event_id: String,
    pub aggregate_id: String,
    pub occurred_at: DateTime<Utc>,
    pub role_id: String,
    pub role_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PermissionAssignedToRoleEvent {
    pub event_id: String,
    pub aggregate_id: String,
    pub occurred_at: DateTime<Utc>,
    pub role_id: String,
    pub permission_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PermissionCreatedEvent {
    pub event_id: String,
    pub aggregate_id: String,
    pub occurred_at: DateTime<Utc>,
    pub permission_id: String,
    pub permission_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PermissionDeletedEvent {
    pub event_id: String,
    pub aggregate_id: String,
    pub occurred_at: DateTime<Utc>,
    pub permission_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PermissionsRemovedFromRoleEvent {
    pub event_id: String,
    pub aggregate_id: String,
    pub occurred_at: DateTime<Utc>,
    pub role_id: String,
    pub permission_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RolesRemovedFromUserEvent {
    pub event_id: String,
    pub aggregate_id: String,
    pub occurred_at: DateTime<Utc>,
    pub user_id: String,
    pub role_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoleDeletedEvent {
    pub event_id: String,
    pub aggregate_id: String,
    pub occurred_at: DateTime<Utc>,
    pub role_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AbacPolicyCreatedEvent {
    pub event_id: String,
    pub aggregate_id: String,
    pub occurred_at: DateTime<Utc>,
    pub policy_id: String,
    pub policy_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AbacPolicyUpdatedEvent {
    pub event_id: String,
    pub aggregate_id: String,
    pub occurred_at: DateTime<Utc>,
    pub policy_id: String,
    pub policy_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AbacPolicyDeletedEvent {
    pub event_id: String,
    pub aggregate_id: String,
    pub occurred_at: DateTime<Utc>,
    pub policy_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AbacPolicyAssignedToUserEvent {
    pub event_id: String,
    pub aggregate_id: String,
    pub occurred_at: DateTime<Utc>,
    pub policy_id: String,
    pub user_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PermissionGroupCreatedEvent {
    pub event_id: String,
    pub aggregate_id: String,
    pub occurred_at: DateTime<Utc>,
    pub group_id: String,
    pub group_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PermissionGroupUpdatedEvent {
    pub event_id: String,
    pub aggregate_id: String,
    pub occurred_at: DateTime<Utc>,
    pub group_id: String,
    pub group_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PermissionGroupDeletedEvent {
    pub event_id: String,
    pub aggregate_id: String,
    pub occurred_at: DateTime<Utc>,
    pub group_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PermissionsAssignedToRoleEvent {
    pub event_id: String,
    pub aggregate_id: String,
    pub occurred_at: DateTime<Utc>,
    pub role_id: String,
    pub permission_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserProfileUpdatedEvent {
    pub event_id: String,
    pub aggregate_id: String,
    pub occurred_at: DateTime<Utc>,
    pub user_id: String,
    pub user_email: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserLockToggledEvent {
    pub event_id: String,
    pub aggregate_id: String,
    pub occurred_at: DateTime<Utc>,
    pub user_id: String,
    pub locked: bool,
    pub reason: Option<String>,
}

/// Event when a token is refreshed
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenRefreshedEvent {
    pub event_id: String,
    pub aggregate_id: String,
    pub occurred_at: DateTime<Utc>,
    pub user_id: String,
    pub user_email: String,
}

/// Event when a user logs out
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserLoggedOutEvent {
    pub event_id: String,
    pub aggregate_id: String,
    pub occurred_at: DateTime<Utc>,
    pub user_id: String,
}

pub struct PermissionCheckedEvent {
    pub event_id: String,
    pub aggregate_id: String,
    pub occurred_at: DateTime<Utc>,
    pub user_id: String,
    pub permission_name: String,
    pub allowed: bool,
}

/// Event factory functions
pub struct EventFactory;

impl EventFactory {
    pub fn user_created(user_id: String, email: String) -> UserCreatedEvent {
        UserCreatedEvent {
            event_id: Uuid::new_v4().to_string(),
            aggregate_id: user_id.clone(),
            occurred_at: Utc::now(),
            email,
            user_id,
        }
    }

    pub fn user_logged_in(
        user_id: String,
        email: String,
        ip_address: Option<String>,
    ) -> UserLoggedInEvent {
        UserLoggedInEvent {
            event_id: Uuid::new_v4().to_string(),
            aggregate_id: user_id.clone(),
            occurred_at: Utc::now(),
            user_id,
            email,
            ip_address,
        }
    }

    pub fn user_login_failed(
        email: String,
        reason: String,
        ip_address: Option<String>,
    ) -> UserLoginFailedEvent {
        UserLoginFailedEvent {
            event_id: Uuid::new_v4().to_string(),
            aggregate_id: email.clone(),
            occurred_at: Utc::now(),
            email,
            reason,
            ip_address,
        }
    }

    pub fn user_account_locked(
        user_id: String,
        email: String,
        reason: String,
    ) -> UserAccountLockedEvent {
        UserAccountLockedEvent {
            event_id: Uuid::new_v4().to_string(),
            aggregate_id: user_id.clone(),
            occurred_at: Utc::now(),
            user_id,
            email,
            reason,
        }
    }

    pub fn user_password_changed(user_id: String, email: String) -> UserPasswordChangedEvent {
        UserPasswordChangedEvent {
            event_id: Uuid::new_v4().to_string(),
            aggregate_id: user_id.clone(),
            occurred_at: Utc::now(),
            user_id,
            email,
        }
    }

    pub fn user_roles_assigned(user_id: String, role_ids: Vec<String>) -> UserRolesAssignedEvent {
        UserRolesAssignedEvent {
            event_id: Uuid::new_v4().to_string(),
            aggregate_id: user_id.clone(),
            occurred_at: Utc::now(),
            user_id,
            role_ids,
        }
    }

    pub fn role_created(role_id: String, role_name: String) -> RoleCreatedEvent {
        RoleCreatedEvent {
            event_id: Uuid::new_v4().to_string(),
            aggregate_id: role_id.clone(),
            occurred_at: Utc::now(),
            role_id,
            role_name,
        }
    }

    pub fn permission_assigned_to_role(
        role_id: String,
        permission_id: String,
    ) -> PermissionAssignedToRoleEvent {
        PermissionAssignedToRoleEvent {
            event_id: Uuid::new_v4().to_string(),
            aggregate_id: role_id.clone(),
            occurred_at: Utc::now(),
            role_id,
            permission_id,
        }
    }

    pub fn permission_created(
        permission_id: String,
        permission_name: String,
    ) -> PermissionCreatedEvent {
        PermissionCreatedEvent {
            event_id: Uuid::new_v4().to_string(),
            aggregate_id: permission_id.clone(),
            occurred_at: Utc::now(),
            permission_id,
            permission_name,
        }
    }

    pub fn permission_deleted(permission_id: String) -> PermissionDeletedEvent {
        PermissionDeletedEvent {
            event_id: Uuid::new_v4().to_string(),
            aggregate_id: permission_id.clone(),
            occurred_at: Utc::now(),
            permission_id,
        }
    }

    pub fn permissions_removed_from_role(
        role_id: String,
        permission_ids: Vec<String>,
    ) -> PermissionsRemovedFromRoleEvent {
        PermissionsRemovedFromRoleEvent {
            event_id: Uuid::new_v4().to_string(),
            aggregate_id: role_id.clone(),
            occurred_at: Utc::now(),
            role_id,
            permission_ids,
        }
    }

    pub fn roles_removed_from_user(
        user_id: String,
        role_ids: Vec<String>,
    ) -> RolesRemovedFromUserEvent {
        RolesRemovedFromUserEvent {
            event_id: Uuid::new_v4().to_string(),
            aggregate_id: user_id.clone(),
            occurred_at: Utc::now(),
            user_id,
            role_ids,
        }
    }

    pub fn role_deleted(role_id: String) -> RoleDeletedEvent {
        RoleDeletedEvent {
            event_id: Uuid::new_v4().to_string(),
            aggregate_id: role_id.clone(),
            occurred_at: Utc::now(),
            role_id,
        }
    }

    pub fn abac_policy_created(policy_id: String, policy_name: String) -> AbacPolicyCreatedEvent {
        AbacPolicyCreatedEvent {
            event_id: Uuid::new_v4().to_string(),
            aggregate_id: policy_id.clone(),
            occurred_at: Utc::now(),
            policy_id,
            policy_name,
        }
    }

    pub fn abac_policy_updated(policy_id: String, policy_name: String) -> AbacPolicyUpdatedEvent {
        AbacPolicyUpdatedEvent {
            event_id: Uuid::new_v4().to_string(),
            aggregate_id: policy_id.clone(),
            occurred_at: Utc::now(),
            policy_id,
            policy_name,
        }
    }

    pub fn abac_policy_deleted(policy_id: String) -> AbacPolicyDeletedEvent {
        AbacPolicyDeletedEvent {
            event_id: Uuid::new_v4().to_string(),
            aggregate_id: policy_id.clone(),
            occurred_at: Utc::now(),
            policy_id,
        }
    }

    pub fn abac_policy_assigned_to_user(
        policy_id: String,
        user_id: String,
    ) -> AbacPolicyAssignedToUserEvent {
        AbacPolicyAssignedToUserEvent {
            event_id: Uuid::new_v4().to_string(),
            aggregate_id: policy_id.clone(),
            occurred_at: Utc::now(),
            policy_id,
            user_id,
        }
    }

    pub fn permission_group_created(
        group_id: String,
        group_name: String,
    ) -> PermissionGroupCreatedEvent {
        PermissionGroupCreatedEvent {
            event_id: Uuid::new_v4().to_string(),
            aggregate_id: group_id.clone(),
            occurred_at: Utc::now(),
            group_id,
            group_name,
        }
    }

    pub fn permission_group_updated(
        group_id: String,
        group_name: String,
    ) -> PermissionGroupUpdatedEvent {
        PermissionGroupUpdatedEvent {
            event_id: Uuid::new_v4().to_string(),
            aggregate_id: group_id.clone(),
            occurred_at: Utc::now(),
            group_id,
            group_name,
        }
    }

    pub fn permission_group_deleted(group_id: String) -> PermissionGroupDeletedEvent {
        PermissionGroupDeletedEvent {
            event_id: Uuid::new_v4().to_string(),
            aggregate_id: group_id.clone(),
            occurred_at: Utc::now(),
            group_id,
        }
    }

    pub fn permissions_assigned_to_role(
        role_id: String,
        permission_ids: Vec<String>,
    ) -> PermissionsAssignedToRoleEvent {
        PermissionsAssignedToRoleEvent {
            event_id: Uuid::new_v4().to_string(),
            aggregate_id: role_id.clone(),
            occurred_at: Utc::now(),
            role_id,
            permission_ids,
        }
    }

    pub fn user_profile_updated(user_id: String, user_email: String) -> UserProfileUpdatedEvent {
        UserProfileUpdatedEvent {
            event_id: Uuid::new_v4().to_string(),
            aggregate_id: user_id.clone(),
            occurred_at: Utc::now(),
            user_id,
            user_email,
        }
    }

    pub fn user_lock_toggled(
        user_id: String,
        locked: bool,
        reason: Option<String>,
    ) -> UserLockToggledEvent {
        UserLockToggledEvent {
            event_id: Uuid::new_v4().to_string(),
            aggregate_id: user_id.clone(),
            occurred_at: Utc::now(),
            user_id,
            locked,
            reason,
        }
    }

    pub fn token_refreshed(user_id: String, user_email: String) -> TokenRefreshedEvent {
        TokenRefreshedEvent {
            event_id: Uuid::new_v4().to_string(),
            aggregate_id: user_id.clone(),
            occurred_at: Utc::now(),
            user_id,
            user_email,
        }
    }

    pub fn user_logged_out(user_id: String) -> UserLoggedOutEvent {
        UserLoggedOutEvent {
            event_id: Uuid::new_v4().to_string(),
            aggregate_id: user_id.clone(),
            occurred_at: Utc::now(),
            user_id,
        }
    }

    pub fn permission_checked(
        user_id: String,
        permission_name: String,
        allowed: bool,
    ) -> PermissionCheckedEvent {
        PermissionCheckedEvent {
            event_id: Uuid::new_v4().to_string(),
            aggregate_id: user_id.clone(),
            occurred_at: Utc::now(),
            user_id,
            permission_name,
            allowed,
        }
    }
}

/// Implement DomainEvent trait for all events
impl DomainEvent for UserCreatedEvent {
    fn event_id(&self) -> &str {
        &self.event_id
    }
    fn aggregate_id(&self) -> &str {
        &self.aggregate_id
    }
    fn occurred_at(&self) -> DateTime<Utc> {
        self.occurred_at
    }
    fn event_type(&self) -> &str {
        "UserCreated"
    }
}

impl DomainEvent for UserLoggedInEvent {
    fn event_id(&self) -> &str {
        &self.event_id
    }
    fn aggregate_id(&self) -> &str {
        &self.aggregate_id
    }
    fn occurred_at(&self) -> DateTime<Utc> {
        self.occurred_at
    }
    fn event_type(&self) -> &str {
        "UserLoggedIn"
    }
}

impl DomainEvent for UserLoginFailedEvent {
    fn event_id(&self) -> &str {
        &self.event_id
    }
    fn aggregate_id(&self) -> &str {
        &self.aggregate_id
    }
    fn occurred_at(&self) -> DateTime<Utc> {
        self.occurred_at
    }
    fn event_type(&self) -> &str {
        "UserLoginFailed"
    }
}

impl DomainEvent for UserAccountLockedEvent {
    fn event_id(&self) -> &str {
        &self.event_id
    }
    fn aggregate_id(&self) -> &str {
        &self.aggregate_id
    }
    fn occurred_at(&self) -> DateTime<Utc> {
        self.occurred_at
    }
    fn event_type(&self) -> &str {
        "UserAccountLocked"
    }
}

impl DomainEvent for UserPasswordChangedEvent {
    fn event_id(&self) -> &str {
        &self.event_id
    }
    fn aggregate_id(&self) -> &str {
        &self.aggregate_id
    }
    fn occurred_at(&self) -> DateTime<Utc> {
        self.occurred_at
    }
    fn event_type(&self) -> &str {
        "UserPasswordChanged"
    }
}

impl DomainEvent for UserRolesAssignedEvent {
    fn event_id(&self) -> &str {
        &self.event_id
    }
    fn aggregate_id(&self) -> &str {
        &self.aggregate_id
    }
    fn occurred_at(&self) -> DateTime<Utc> {
        self.occurred_at
    }
    fn event_type(&self) -> &str {
        "UserRolesAssigned"
    }
}

impl DomainEvent for RoleCreatedEvent {
    fn event_id(&self) -> &str {
        &self.event_id
    }
    fn aggregate_id(&self) -> &str {
        &self.aggregate_id
    }
    fn occurred_at(&self) -> DateTime<Utc> {
        self.occurred_at
    }
    fn event_type(&self) -> &str {
        "RoleCreated"
    }
}

impl DomainEvent for PermissionAssignedToRoleEvent {
    fn event_id(&self) -> &str {
        &self.event_id
    }
    fn aggregate_id(&self) -> &str {
        &self.aggregate_id
    }
    fn occurred_at(&self) -> DateTime<Utc> {
        self.occurred_at
    }
    fn event_type(&self) -> &str {
        "PermissionAssignedToRole"
    }
}

impl DomainEvent for PermissionCreatedEvent {
    fn event_id(&self) -> &str {
        &self.event_id
    }
    fn aggregate_id(&self) -> &str {
        &self.aggregate_id
    }
    fn occurred_at(&self) -> DateTime<Utc> {
        self.occurred_at
    }
    fn event_type(&self) -> &str {
        "PermissionCreated"
    }
}

impl DomainEvent for PermissionDeletedEvent {
    fn event_id(&self) -> &str {
        &self.event_id
    }
    fn aggregate_id(&self) -> &str {
        &self.aggregate_id
    }
    fn occurred_at(&self) -> DateTime<Utc> {
        self.occurred_at
    }
    fn event_type(&self) -> &str {
        "PermissionDeleted"
    }
}

impl DomainEvent for PermissionsRemovedFromRoleEvent {
    fn event_id(&self) -> &str {
        &self.event_id
    }
    fn aggregate_id(&self) -> &str {
        &self.aggregate_id
    }
    fn occurred_at(&self) -> DateTime<Utc> {
        self.occurred_at
    }
    fn event_type(&self) -> &str {
        "PermissionsRemovedFromRole"
    }
}

impl DomainEvent for RolesRemovedFromUserEvent {
    fn event_id(&self) -> &str {
        &self.event_id
    }
    fn aggregate_id(&self) -> &str {
        &self.aggregate_id
    }
    fn occurred_at(&self) -> DateTime<Utc> {
        self.occurred_at
    }
    fn event_type(&self) -> &str {
        "RolesRemovedFromUser"
    }
}

impl DomainEvent for RoleDeletedEvent {
    fn event_id(&self) -> &str {
        &self.event_id
    }
    fn aggregate_id(&self) -> &str {
        &self.aggregate_id
    }
    fn occurred_at(&self) -> DateTime<Utc> {
        self.occurred_at
    }
    fn event_type(&self) -> &str {
        "RoleDeleted"
    }
}

impl DomainEvent for AbacPolicyCreatedEvent {
    fn event_id(&self) -> &str {
        &self.event_id
    }
    fn aggregate_id(&self) -> &str {
        &self.aggregate_id
    }
    fn occurred_at(&self) -> DateTime<Utc> {
        self.occurred_at
    }
    fn event_type(&self) -> &str {
        "AbacPolicyCreated"
    }
}

impl DomainEvent for AbacPolicyUpdatedEvent {
    fn event_id(&self) -> &str {
        &self.event_id
    }
    fn aggregate_id(&self) -> &str {
        &self.aggregate_id
    }
    fn occurred_at(&self) -> DateTime<Utc> {
        self.occurred_at
    }
    fn event_type(&self) -> &str {
        "AbacPolicyUpdated"
    }
}

impl DomainEvent for AbacPolicyDeletedEvent {
    fn event_id(&self) -> &str {
        &self.event_id
    }
    fn aggregate_id(&self) -> &str {
        &self.aggregate_id
    }
    fn occurred_at(&self) -> DateTime<Utc> {
        self.occurred_at
    }
    fn event_type(&self) -> &str {
        "AbacPolicyDeleted"
    }
}

impl DomainEvent for AbacPolicyAssignedToUserEvent {
    fn event_id(&self) -> &str {
        &self.event_id
    }
    fn aggregate_id(&self) -> &str {
        &self.aggregate_id
    }
    fn occurred_at(&self) -> DateTime<Utc> {
        self.occurred_at
    }
    fn event_type(&self) -> &str {
        "AbacPolicyAssignedToUser"
    }
}

impl DomainEvent for PermissionGroupCreatedEvent {
    fn event_id(&self) -> &str {
        &self.event_id
    }
    fn aggregate_id(&self) -> &str {
        &self.aggregate_id
    }
    fn occurred_at(&self) -> DateTime<Utc> {
        self.occurred_at
    }
    fn event_type(&self) -> &str {
        "PermissionGroupCreated"
    }
}

impl DomainEvent for PermissionGroupUpdatedEvent {
    fn event_id(&self) -> &str {
        &self.event_id
    }
    fn aggregate_id(&self) -> &str {
        &self.aggregate_id
    }
    fn occurred_at(&self) -> DateTime<Utc> {
        self.occurred_at
    }
    fn event_type(&self) -> &str {
        "PermissionGroupUpdated"
    }
}

impl DomainEvent for PermissionGroupDeletedEvent {
    fn event_id(&self) -> &str {
        &self.event_id
    }
    fn aggregate_id(&self) -> &str {
        &self.aggregate_id
    }
    fn occurred_at(&self) -> DateTime<Utc> {
        self.occurred_at
    }
    fn event_type(&self) -> &str {
        "PermissionGroupDeleted"
    }
}

impl DomainEvent for PermissionsAssignedToRoleEvent {
    fn event_id(&self) -> &str {
        &self.event_id
    }
    fn aggregate_id(&self) -> &str {
        &self.aggregate_id
    }
    fn occurred_at(&self) -> DateTime<Utc> {
        self.occurred_at
    }
    fn event_type(&self) -> &str {
        "PermissionsAssignedToRole"
    }
}

impl DomainEvent for UserProfileUpdatedEvent {
    fn event_id(&self) -> &str {
        &self.event_id
    }
    fn aggregate_id(&self) -> &str {
        &self.aggregate_id
    }
    fn occurred_at(&self) -> DateTime<Utc> {
        self.occurred_at
    }
    fn event_type(&self) -> &str {
        "UserProfileUpdated"
    }
}

impl DomainEvent for UserLockToggledEvent {
    fn event_id(&self) -> &str {
        &self.event_id
    }
    fn aggregate_id(&self) -> &str {
        &self.aggregate_id
    }
    fn occurred_at(&self) -> DateTime<Utc> {
        self.occurred_at
    }
    fn event_type(&self) -> &str {
        "UserLockToggled"
    }
}

impl DomainEvent for TokenRefreshedEvent {
    fn event_id(&self) -> &str {
        &self.event_id
    }
    fn aggregate_id(&self) -> &str {
        &self.aggregate_id
    }
    fn occurred_at(&self) -> DateTime<Utc> {
        self.occurred_at
    }
    fn event_type(&self) -> &str {
        "TokenRefreshed"
    }
}

impl DomainEvent for UserLoggedOutEvent {
    fn event_id(&self) -> &str {
        &self.event_id
    }
    fn aggregate_id(&self) -> &str {
        &self.aggregate_id
    }
    fn occurred_at(&self) -> DateTime<Utc> {
        self.occurred_at
    }
    fn event_type(&self) -> &str {
        "UserLoggedOut"
    }
}

impl DomainEvent for PermissionCheckedEvent {
    fn event_id(&self) -> &str {
        &self.event_id
    }
    fn aggregate_id(&self) -> &str {
        &self.aggregate_id
    }
    fn occurred_at(&self) -> DateTime<Utc> {
        self.occurred_at
    }
    fn event_type(&self) -> &str {
        "PermissionChecked"
    }
}

/// Event handler trait
#[async_trait::async_trait]
pub trait EventHandler<E: DomainEvent>: Send + Sync {
    async fn handle(&self, event: &E) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;
}

/// Event store trait for persisting events
#[async_trait::async_trait]
pub trait EventStore: Send + Sync {
    async fn store_event(
        &self,
        event: &dyn DomainEvent,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;
    async fn get_events_for_aggregate(
        &self,
        aggregate_id: &str,
    ) -> Result<Vec<Box<dyn DomainEvent>>, Box<dyn std::error::Error + Send + Sync>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_user_created_event() {
        let event = EventFactory::user_created("user1".to_string(), "test@example.com".to_string());

        assert_eq!(event.event_type(), "UserCreated");
        assert_eq!(event.aggregate_id(), "user1");
        assert_eq!(event.email, "test@example.com");
        assert!(!event.event_id.is_empty());
    }

    #[test]
    fn test_user_logged_in_event() {
        let event = EventFactory::user_logged_in(
            "user1".to_string(),
            "test@example.com".to_string(),
            Some("192.168.1.1".to_string()),
        );

        assert_eq!(event.event_type(), "UserLoggedIn");
        assert_eq!(event.user_id, "user1");
        assert_eq!(event.email, "test@example.com");
        assert_eq!(event.ip_address, Some("192.168.1.1".to_string()));
    }
}
