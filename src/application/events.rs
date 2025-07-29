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

#[derive(Debug, Clone, Serialize, Deserialize)]
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

    #[test]
    fn test_user_login_failed_event() {
        let event = EventFactory::user_login_failed(
            "test@example.com".to_string(),
            "Invalid password".to_string(),
            Some("192.168.1.1".to_string()),
        );

        assert_eq!(event.event_type(), "UserLoginFailed");
        assert_eq!(event.email, "test@example.com");
        assert_eq!(event.reason, "Invalid password");
        assert_eq!(event.ip_address, Some("192.168.1.1".to_string()));
    }

    #[test]
    fn test_user_account_locked_event() {
        let event = EventFactory::user_account_locked(
            "user1".to_string(),
            "test@example.com".to_string(),
            "Too many failed attempts".to_string(),
        );

        assert_eq!(event.event_type(), "UserAccountLocked");
        assert_eq!(event.user_id, "user1");
        assert_eq!(event.email, "test@example.com");
        assert_eq!(event.reason, "Too many failed attempts");
    }

    #[test]
    fn test_user_password_changed_event() {
        let event = EventFactory::user_password_changed("user1".to_string(), "test@example.com".to_string());

        assert_eq!(event.event_type(), "UserPasswordChanged");
        assert_eq!(event.user_id, "user1");
        assert_eq!(event.email, "test@example.com");
    }

    #[test]
    fn test_user_roles_assigned_event() {
        let role_ids = vec!["role1".to_string(), "role2".to_string()];
        let event = EventFactory::user_roles_assigned("user1".to_string(), role_ids.clone());

        assert_eq!(event.event_type(), "UserRolesAssigned");
        assert_eq!(event.user_id, "user1");
        assert_eq!(event.role_ids, role_ids);
    }

    #[test]
    fn test_role_created_event() {
        let event = EventFactory::role_created("role1".to_string(), "Admin Role".to_string());

        assert_eq!(event.event_type(), "RoleCreated");
        assert_eq!(event.role_id, "role1");
        assert_eq!(event.role_name, "Admin Role");
    }

    #[test]
    fn test_permission_assigned_to_role_event() {
        let event = EventFactory::permission_assigned_to_role("role1".to_string(), "perm1".to_string());

        assert_eq!(event.event_type(), "PermissionAssignedToRole");
        assert_eq!(event.role_id, "role1");
        assert_eq!(event.permission_id, "perm1");
    }

    #[test]
    fn test_permission_created_event() {
        let event = EventFactory::permission_created("perm1".to_string(), "read_users".to_string());

        assert_eq!(event.event_type(), "PermissionCreated");
        assert_eq!(event.permission_id, "perm1");
        assert_eq!(event.permission_name, "read_users");
    }

    #[test]
    fn test_permission_deleted_event() {
        let event = EventFactory::permission_deleted("perm1".to_string());

        assert_eq!(event.event_type(), "PermissionDeleted");
        assert_eq!(event.permission_id, "perm1");
    }

    #[test]
    fn test_permissions_removed_from_role_event() {
        let permission_ids = vec!["perm1".to_string(), "perm2".to_string()];
        let event = EventFactory::permissions_removed_from_role("role1".to_string(), permission_ids.clone());

        assert_eq!(event.event_type(), "PermissionsRemovedFromRole");
        assert_eq!(event.role_id, "role1");
        assert_eq!(event.permission_ids, permission_ids);
    }

    #[test]
    fn test_roles_removed_from_user_event() {
        let role_ids = vec!["role1".to_string(), "role2".to_string()];
        let event = EventFactory::roles_removed_from_user("user1".to_string(), role_ids.clone());

        assert_eq!(event.event_type(), "RolesRemovedFromUser");
        assert_eq!(event.user_id, "user1");
        assert_eq!(event.role_ids, role_ids);
    }

    #[test]
    fn test_role_deleted_event() {
        let event = EventFactory::role_deleted("role1".to_string());

        assert_eq!(event.event_type(), "RoleDeleted");
        assert_eq!(event.role_id, "role1");
    }

    #[test]
    fn test_abac_policy_created_event() {
        let event = EventFactory::abac_policy_created("policy1".to_string(), "Time-based Access".to_string());

        assert_eq!(event.event_type(), "AbacPolicyCreated");
        assert_eq!(event.policy_id, "policy1");
        assert_eq!(event.policy_name, "Time-based Access");
    }

    #[test]
    fn test_abac_policy_updated_event() {
        let event = EventFactory::abac_policy_updated("policy1".to_string(), "Updated Policy".to_string());

        assert_eq!(event.event_type(), "AbacPolicyUpdated");
        assert_eq!(event.policy_id, "policy1");
        assert_eq!(event.policy_name, "Updated Policy");
    }

    #[test]
    fn test_abac_policy_deleted_event() {
        let event = EventFactory::abac_policy_deleted("policy1".to_string());

        assert_eq!(event.event_type(), "AbacPolicyDeleted");
        assert_eq!(event.policy_id, "policy1");
    }

    #[test]
    fn test_abac_policy_assigned_to_user_event() {
        let event = EventFactory::abac_policy_assigned_to_user("policy1".to_string(), "user1".to_string());

        assert_eq!(event.event_type(), "AbacPolicyAssignedToUser");
        assert_eq!(event.policy_id, "policy1");
        assert_eq!(event.user_id, "user1");
    }

    #[test]
    fn test_permission_group_created_event() {
        let event = EventFactory::permission_group_created("group1".to_string(), "User Management".to_string());

        assert_eq!(event.event_type(), "PermissionGroupCreated");
        assert_eq!(event.group_id, "group1");
        assert_eq!(event.group_name, "User Management");
    }

    #[test]
    fn test_permission_group_updated_event() {
        let event = EventFactory::permission_group_updated("group1".to_string(), "Updated Group".to_string());

        assert_eq!(event.event_type(), "PermissionGroupUpdated");
        assert_eq!(event.group_id, "group1");
        assert_eq!(event.group_name, "Updated Group");
    }

    #[test]
    fn test_permission_group_deleted_event() {
        let event = EventFactory::permission_group_deleted("group1".to_string());

        assert_eq!(event.event_type(), "PermissionGroupDeleted");
        assert_eq!(event.group_id, "group1");
    }

    #[test]
    fn test_permissions_assigned_to_role_event() {
        let permission_ids = vec!["perm1".to_string(), "perm2".to_string()];
        let event = EventFactory::permissions_assigned_to_role("role1".to_string(), permission_ids.clone());

        assert_eq!(event.event_type(), "PermissionsAssignedToRole");
        assert_eq!(event.role_id, "role1");
        assert_eq!(event.permission_ids, permission_ids);
    }

    #[test]
    fn test_user_profile_updated_event() {
        let event = EventFactory::user_profile_updated("user1".to_string(), "new@example.com".to_string());

        assert_eq!(event.event_type(), "UserProfileUpdated");
        assert_eq!(event.user_id, "user1");
        assert_eq!(event.user_email, "new@example.com");
    }

    #[test]
    fn test_user_lock_toggled_event() {
        let event = EventFactory::user_lock_toggled(
            "user1".to_string(),
            true,
            Some("Suspicious activity".to_string()),
        );

        assert_eq!(event.event_type(), "UserLockToggled");
        assert_eq!(event.user_id, "user1");
        assert_eq!(event.locked, true);
        assert_eq!(event.reason, Some("Suspicious activity".to_string()));
    }

    #[test]
    fn test_token_refreshed_event() {
        let event = EventFactory::token_refreshed("user1".to_string(), "test@example.com".to_string());

        assert_eq!(event.event_type(), "TokenRefreshed");
        assert_eq!(event.user_id, "user1");
        assert_eq!(event.user_email, "test@example.com");
    }

    #[test]
    fn test_user_logged_out_event() {
        let event = EventFactory::user_logged_out("user1".to_string());

        assert_eq!(event.event_type(), "UserLoggedOut");
        assert_eq!(event.user_id, "user1");
    }

    #[test]
    fn test_permission_checked_event() {
        let event = EventFactory::permission_checked("user1".to_string(), "read_users".to_string(), true);

        assert_eq!(event.event_type(), "PermissionChecked");
        assert_eq!(event.user_id, "user1");
        assert_eq!(event.permission_name, "read_users");
        assert_eq!(event.allowed, true);
    }

    #[test]
    fn test_domain_event_trait_implementations() {
        // Test that all events implement DomainEvent trait correctly
        let events: Vec<Box<dyn DomainEvent>> = vec![
            Box::new(EventFactory::user_created("user1".to_string(), "test@example.com".to_string())),
            Box::new(EventFactory::user_logged_in("user1".to_string(), "test@example.com".to_string(), None)),
            Box::new(EventFactory::user_login_failed("test@example.com".to_string(), "Invalid password".to_string(), None)),
            Box::new(EventFactory::user_account_locked("user1".to_string(), "test@example.com".to_string(), "Locked".to_string())),
            Box::new(EventFactory::user_password_changed("user1".to_string(), "test@example.com".to_string())),
            Box::new(EventFactory::user_roles_assigned("user1".to_string(), vec!["role1".to_string()])),
            Box::new(EventFactory::role_created("role1".to_string(), "Admin".to_string())),
            Box::new(EventFactory::permission_assigned_to_role("role1".to_string(), "perm1".to_string())),
            Box::new(EventFactory::permission_created("perm1".to_string(), "read_users".to_string())),
            Box::new(EventFactory::permission_deleted("perm1".to_string())),
            Box::new(EventFactory::permissions_removed_from_role("role1".to_string(), vec!["perm1".to_string()])),
            Box::new(EventFactory::roles_removed_from_user("user1".to_string(), vec!["role1".to_string()])),
            Box::new(EventFactory::role_deleted("role1".to_string())),
            Box::new(EventFactory::abac_policy_created("policy1".to_string(), "Policy".to_string())),
            Box::new(EventFactory::abac_policy_updated("policy1".to_string(), "Updated Policy".to_string())),
            Box::new(EventFactory::abac_policy_deleted("policy1".to_string())),
            Box::new(EventFactory::abac_policy_assigned_to_user("policy1".to_string(), "user1".to_string())),
            Box::new(EventFactory::permission_group_created("group1".to_string(), "Group".to_string())),
            Box::new(EventFactory::permission_group_updated("group1".to_string(), "Updated Group".to_string())),
            Box::new(EventFactory::permission_group_deleted("group1".to_string())),
            Box::new(EventFactory::permissions_assigned_to_role("role1".to_string(), vec!["perm1".to_string()])),
            Box::new(EventFactory::user_profile_updated("user1".to_string(), "test@example.com".to_string())),
            Box::new(EventFactory::user_lock_toggled("user1".to_string(), true, None)),
            Box::new(EventFactory::token_refreshed("user1".to_string(), "test@example.com".to_string())),
            Box::new(EventFactory::user_logged_out("user1".to_string())),
            Box::new(EventFactory::permission_checked("user1".to_string(), "read_users".to_string(), true)),
        ];

        for event in events {
            assert!(!event.event_id().is_empty());
            assert!(!event.aggregate_id().is_empty());
            assert!(!event.event_type().is_empty());
            // occurred_at should be a valid timestamp
            let _timestamp = event.occurred_at();
        }
    }
}
