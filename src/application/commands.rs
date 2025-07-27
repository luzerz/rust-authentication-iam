use crate::domain::abac_policy::AbacCondition;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Base trait for all commands
pub trait Command: Send + Sync {
    fn command_id(&self) -> &str;
    fn timestamp(&self) -> DateTime<Utc>;
    fn user_id(&self) -> Option<&str>;
}

/// Command to log in a user
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginUserCommand {
    pub command_id: String,
    pub timestamp: DateTime<Utc>,
    pub email: String,
    pub password: String,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
}

/// Command to change a user's password
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChangePasswordCommand {
    pub command_id: String,
    pub timestamp: DateTime<Utc>,
    pub user_id: String,
    pub current_password: String,
    pub new_password: String,
    pub require_current_password: bool,
}

/// Command to reset a user's password
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResetPasswordCommand {
    pub command_id: String,
    pub timestamp: DateTime<Utc>,
    pub reset_token: String,
    pub new_password: String,
    pub ip_address: Option<String>,
}

/// Command to assign roles to a user
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssignRolesCommand {
    pub command_id: String,
    pub timestamp: DateTime<Utc>,
    pub user_id: String,
    pub role_ids: Vec<String>,
    pub assigned_by: Option<String>,
}

/// Command to create a new user
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateUserCommand {
    pub command_id: String,
    pub timestamp: DateTime<Utc>,
    pub email: String,
    pub password: String,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub role_ids: Vec<String>,
    pub created_by: Option<String>,
}

/// Command to update user profile
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateUserProfileCommand {
    pub command_id: String,
    pub timestamp: DateTime<Utc>,
    pub user_id: String,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub email: Option<String>,
    pub updated_by: Option<String>,
}

/// Command to lock/unlock user account
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToggleUserLockCommand {
    pub command_id: String,
    pub timestamp: DateTime<Utc>,
    pub user_id: String,
    pub lock: bool,
    pub reason: Option<String>,
    pub executed_by: Option<String>,
}

/// Command to create a new role
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateRoleCommand {
    pub command_id: String,
    pub timestamp: DateTime<Utc>,
    pub name: String,
    pub description: Option<String>,
    pub parent_role_id: Option<String>,
    pub created_by: Option<String>,
}

/// Command to assign permissions to a role
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssignPermissionsToRoleCommand {
    pub command_id: String,
    pub timestamp: DateTime<Utc>,
    pub role_id: String,
    pub permission_ids: Vec<String>,
    pub assigned_by: Option<String>,
}

/// Command to create a permission
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreatePermissionCommand {
    pub command_id: String,
    pub timestamp: DateTime<Utc>,
    pub name: String,
    pub description: Option<String>,
    pub group_id: Option<String>,
    pub created_by: Option<String>,
}

/// Command to delete a permission
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeletePermissionCommand {
    pub command_id: String,
    pub timestamp: DateTime<Utc>,
    pub permission_id: String,
    pub deleted_by: Option<String>,
}

/// Command to remove permissions from a role
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemovePermissionsFromRoleCommand {
    pub command_id: String,
    pub timestamp: DateTime<Utc>,
    pub role_id: String,
    pub permission_ids: Vec<String>,
    pub removed_by: Option<String>,
}

/// Command to remove roles from a user
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoveRolesFromUserCommand {
    pub command_id: String,
    pub timestamp: DateTime<Utc>,
    pub user_id: String,
    pub role_ids: Vec<String>,
    pub removed_by: Option<String>,
}

/// Command to delete a role
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeleteRoleCommand {
    pub command_id: String,
    pub timestamp: DateTime<Utc>,
    pub role_id: String,
    pub deleted_by: Option<String>,
}

/// Command to update a role
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateRoleCommand {
    pub command_id: String,
    pub timestamp: DateTime<Utc>,
    pub role_id: String,
    pub name: String,
    pub updated_by: Option<String>,
}

/// Command to update a permission
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdatePermissionCommand {
    pub command_id: String,
    pub timestamp: DateTime<Utc>,
    pub permission_id: String,
    pub name: String,
    pub updated_by: Option<String>,
}

/// Command to create an ABAC policy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateAbacPolicyCommand {
    pub command_id: String,
    pub timestamp: DateTime<Utc>,
    pub name: String,
    pub description: Option<String>,
    pub effect: String,
    pub conditions: Vec<AbacCondition>,
    pub priority: i32,
    pub created_by: Option<String>,
}

/// Command to update an ABAC policy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateAbacPolicyCommand {
    pub command_id: String,
    pub timestamp: DateTime<Utc>,
    pub policy_id: String,
    pub name: Option<String>,
    pub description: Option<String>,
    pub effect: Option<String>,
    pub conditions: Option<Vec<AbacCondition>>,
    pub priority: Option<i32>,
    pub updated_by: Option<String>,
}

/// Command to delete an ABAC policy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeleteAbacPolicyCommand {
    pub command_id: String,
    pub timestamp: DateTime<Utc>,
    pub policy_id: String,
    pub deleted_by: Option<String>,
}

/// Command to assign ABAC policy to user
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssignAbacPolicyToUserCommand {
    pub command_id: String,
    pub timestamp: DateTime<Utc>,
    pub policy_id: String,
    pub user_id: String,
    pub assigned_by: Option<String>,
}

/// Command to create a permission group
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreatePermissionGroupCommand {
    pub command_id: String,
    pub timestamp: DateTime<Utc>,
    pub name: String,
    pub description: Option<String>,
    pub category: Option<String>,
    pub created_by: Option<String>,
}

/// Command to update a permission group
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdatePermissionGroupCommand {
    pub command_id: String,
    pub timestamp: DateTime<Utc>,
    pub group_id: String,
    pub name: Option<String>,
    pub description: Option<String>,
    pub category: Option<String>,
    pub metadata: Option<serde_json::Value>,
    pub is_active: Option<bool>,
    pub updated_by: Option<String>,
}

/// Command to delete a permission group
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeletePermissionGroupCommand {
    pub command_id: String,
    pub timestamp: DateTime<Utc>,
    pub group_id: String,
    pub deleted_by: Option<String>,
}

/// Command to validate a token
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidateTokenCommand {
    pub command_id: String,
    pub timestamp: DateTime<Utc>,
    pub token: String,
}

/// Command to refresh a token
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefreshTokenCommand {
    pub command_id: String,
    pub timestamp: DateTime<Utc>,
    pub refresh_token: String,
    pub user_id: String,
}

/// Command to logout a user
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogoutCommand {
    pub command_id: String,
    pub timestamp: DateTime<Utc>,
    pub refresh_token: String,
    pub user_id: String,
}

/// Command to evaluate ABAC policies
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvaluateAbacPoliciesCommand {
    pub command_id: String,
    pub timestamp: DateTime<Utc>,
    pub user_id: String,
    pub permission_name: String,
    pub attributes: serde_json::Value,
    pub evaluated_by: Option<String>,
}

/// Command to set parent role
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetParentRoleCommand {
    pub command_id: String,
    pub timestamp: DateTime<Utc>,
    pub role_id: String,
    pub parent_role_id: Option<String>,
    pub set_by: Option<String>,
}

/// Command to authenticate a user
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticateUserCommand {
    pub command_id: String,
    pub timestamp: DateTime<Utc>,
    pub email: String,
    pub password: String,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
}

/// Command to check a permission
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckPermissionCommand {
    pub command_id: String,
    pub timestamp: DateTime<Utc>,
    pub user_id: String,
    pub permission_name: String,
    pub user_attributes: Option<std::collections::HashMap<String, String>>,
}

/// Command factory for creating commands with proper defaults
pub struct CommandFactory;

impl CommandFactory {
    pub fn login_user(
        email: String,
        password: String,
        ip_address: Option<String>,
        user_agent: Option<String>,
    ) -> LoginUserCommand {
        LoginUserCommand {
            command_id: Uuid::new_v4().to_string(),
            timestamp: Utc::now(),
            email,
            password,
            ip_address,
            user_agent,
        }
    }

    pub fn change_password(
        user_id: String,
        current_password: String,
        new_password: String,
        require_current_password: bool,
    ) -> ChangePasswordCommand {
        ChangePasswordCommand {
            command_id: Uuid::new_v4().to_string(),
            timestamp: Utc::now(),
            user_id,
            current_password,
            new_password,
            require_current_password,
        }
    }

    pub fn reset_password(
        reset_token: String,
        new_password: String,
        ip_address: Option<String>,
    ) -> ResetPasswordCommand {
        ResetPasswordCommand {
            command_id: Uuid::new_v4().to_string(),
            timestamp: Utc::now(),
            reset_token,
            new_password,
            ip_address,
        }
    }

    pub fn assign_roles(
        user_id: String,
        role_ids: Vec<String>,
        assigned_by: Option<String>,
    ) -> AssignRolesCommand {
        AssignRolesCommand {
            command_id: Uuid::new_v4().to_string(),
            timestamp: Utc::now(),
            user_id,
            role_ids,
            assigned_by,
        }
    }

    pub fn create_user(
        email: String,
        password: String,
        first_name: Option<String>,
        last_name: Option<String>,
        role_ids: Vec<String>,
        created_by: Option<String>,
    ) -> CreateUserCommand {
        CreateUserCommand {
            command_id: Uuid::new_v4().to_string(),
            timestamp: Utc::now(),
            email,
            password,
            first_name,
            last_name,
            role_ids,
            created_by,
        }
    }

    pub fn update_user_profile(
        user_id: String,
        first_name: Option<String>,
        last_name: Option<String>,
        email: Option<String>,
        updated_by: Option<String>,
    ) -> UpdateUserProfileCommand {
        UpdateUserProfileCommand {
            command_id: Uuid::new_v4().to_string(),
            timestamp: Utc::now(),
            user_id,
            first_name,
            last_name,
            email,
            updated_by,
        }
    }

    pub fn toggle_user_lock(
        user_id: String,
        lock: bool,
        reason: Option<String>,
        executed_by: Option<String>,
    ) -> ToggleUserLockCommand {
        ToggleUserLockCommand {
            command_id: Uuid::new_v4().to_string(),
            timestamp: Utc::now(),
            user_id,
            lock,
            reason,
            executed_by,
        }
    }

    pub fn create_role(
        name: String,
        description: Option<String>,
        parent_role_id: Option<String>,
        created_by: Option<String>,
    ) -> CreateRoleCommand {
        CreateRoleCommand {
            command_id: Uuid::new_v4().to_string(),
            timestamp: Utc::now(),
            name,
            description,
            parent_role_id,
            created_by,
        }
    }

    pub fn assign_permissions_to_role(
        role_id: String,
        permission_ids: Vec<String>,
        assigned_by: Option<String>,
    ) -> AssignPermissionsToRoleCommand {
        AssignPermissionsToRoleCommand {
            command_id: Uuid::new_v4().to_string(),
            timestamp: Utc::now(),
            role_id,
            permission_ids,
            assigned_by,
        }
    }

    pub fn create_permission(
        name: String,
        description: Option<String>,
        group_id: Option<String>,
        created_by: Option<String>,
    ) -> CreatePermissionCommand {
        CreatePermissionCommand {
            command_id: Uuid::new_v4().to_string(),
            timestamp: Utc::now(),
            name,
            description,
            group_id,
            created_by,
        }
    }

    pub fn delete_permission(
        permission_id: String,
        deleted_by: Option<String>,
    ) -> DeletePermissionCommand {
        DeletePermissionCommand {
            command_id: Uuid::new_v4().to_string(),
            timestamp: Utc::now(),
            permission_id,
            deleted_by,
        }
    }

    pub fn remove_permissions_from_role(
        role_id: String,
        permission_ids: Vec<String>,
        removed_by: Option<String>,
    ) -> RemovePermissionsFromRoleCommand {
        RemovePermissionsFromRoleCommand {
            command_id: Uuid::new_v4().to_string(),
            timestamp: Utc::now(),
            role_id,
            permission_ids,
            removed_by,
        }
    }

    pub fn remove_roles_from_user(
        user_id: String,
        role_ids: Vec<String>,
        removed_by: Option<String>,
    ) -> RemoveRolesFromUserCommand {
        RemoveRolesFromUserCommand {
            command_id: Uuid::new_v4().to_string(),
            timestamp: Utc::now(),
            user_id,
            role_ids,
            removed_by,
        }
    }

    pub fn delete_role(role_id: String, deleted_by: Option<String>) -> DeleteRoleCommand {
        DeleteRoleCommand {
            command_id: Uuid::new_v4().to_string(),
            timestamp: Utc::now(),
            role_id,
            deleted_by,
        }
    }

    pub fn update_role(
        role_id: String,
        name: String,
        updated_by: Option<String>,
    ) -> UpdateRoleCommand {
        UpdateRoleCommand {
            command_id: Uuid::new_v4().to_string(),
            timestamp: Utc::now(),
            role_id,
            name,
            updated_by,
        }
    }

    pub fn update_permission(
        permission_id: String,
        name: String,
        updated_by: Option<String>,
    ) -> UpdatePermissionCommand {
        UpdatePermissionCommand {
            command_id: Uuid::new_v4().to_string(),
            timestamp: Utc::now(),
            permission_id,
            name,
            updated_by,
        }
    }

    pub fn create_abac_policy(
        name: String,
        description: Option<String>,
        effect: String,
        conditions: Vec<AbacCondition>,
        priority: i32,
        created_by: Option<String>,
    ) -> CreateAbacPolicyCommand {
        CreateAbacPolicyCommand {
            command_id: Uuid::new_v4().to_string(),
            timestamp: Utc::now(),
            name,
            description,
            effect,
            conditions,
            priority,
            created_by,
        }
    }

    pub fn update_abac_policy(
        policy_id: String,
        name: Option<String>,
        description: Option<String>,
        effect: Option<String>,
        conditions: Option<Vec<AbacCondition>>,
        priority: Option<i32>,
        updated_by: Option<String>,
    ) -> UpdateAbacPolicyCommand {
        UpdateAbacPolicyCommand {
            command_id: Uuid::new_v4().to_string(),
            timestamp: Utc::now(),
            policy_id,
            name,
            description,
            effect,
            conditions,
            priority,
            updated_by,
        }
    }

    pub fn delete_abac_policy(
        policy_id: String,
        deleted_by: Option<String>,
    ) -> DeleteAbacPolicyCommand {
        DeleteAbacPolicyCommand {
            command_id: Uuid::new_v4().to_string(),
            timestamp: Utc::now(),
            policy_id,
            deleted_by,
        }
    }

    pub fn assign_abac_policy_to_user(
        policy_id: String,
        user_id: String,
        assigned_by: Option<String>,
    ) -> AssignAbacPolicyToUserCommand {
        AssignAbacPolicyToUserCommand {
            command_id: Uuid::new_v4().to_string(),
            timestamp: Utc::now(),
            policy_id,
            user_id,
            assigned_by,
        }
    }

    pub fn create_permission_group(
        name: String,
        description: Option<String>,
        category: Option<String>,
        created_by: Option<String>,
    ) -> CreatePermissionGroupCommand {
        CreatePermissionGroupCommand {
            command_id: Uuid::new_v4().to_string(),
            timestamp: Utc::now(),
            name,
            description,
            category,
            created_by,
        }
    }

    pub fn update_permission_group(
        group_id: String,
        name: Option<String>,
        description: Option<String>,
        category: Option<String>,
        metadata: Option<serde_json::Value>,
        is_active: Option<bool>,
        updated_by: Option<String>,
    ) -> UpdatePermissionGroupCommand {
        UpdatePermissionGroupCommand {
            command_id: Uuid::new_v4().to_string(),
            timestamp: Utc::now(),
            group_id,
            name,
            description,
            category,
            metadata,
            is_active,
            updated_by,
        }
    }

    pub fn authenticate_user(
        email: String,
        password: String,
        ip_address: Option<String>,
        user_agent: Option<String>,
    ) -> AuthenticateUserCommand {
        AuthenticateUserCommand {
            command_id: Uuid::new_v4().to_string(),
            timestamp: Utc::now(),
            email,
            password,
            ip_address,
            user_agent,
        }
    }

    pub fn check_permission(
        user_id: String,
        permission_name: String,
        user_attributes: Option<std::collections::HashMap<String, String>>,
    ) -> CheckPermissionCommand {
        CheckPermissionCommand {
            command_id: Uuid::new_v4().to_string(),
            timestamp: Utc::now(),
            user_id,
            permission_name,
            user_attributes,
        }
    }

    pub fn delete_permission_group(
        group_id: String,
        deleted_by: Option<String>,
    ) -> DeletePermissionGroupCommand {
        DeletePermissionGroupCommand {
            command_id: Uuid::new_v4().to_string(),
            timestamp: Utc::now(),
            group_id,
            deleted_by,
        }
    }

    pub fn validate_token(token: String) -> ValidateTokenCommand {
        ValidateTokenCommand {
            command_id: Uuid::new_v4().to_string(),
            timestamp: Utc::now(),
            token,
        }
    }

    pub fn refresh_token(refresh_token: String, user_id: String) -> RefreshTokenCommand {
        RefreshTokenCommand {
            command_id: Uuid::new_v4().to_string(),
            timestamp: Utc::now(),
            refresh_token,
            user_id,
        }
    }

    pub fn logout(refresh_token: String, user_id: String) -> LogoutCommand {
        LogoutCommand {
            command_id: Uuid::new_v4().to_string(),
            timestamp: Utc::now(),
            refresh_token,
            user_id,
        }
    }

    pub fn evaluate_abac_policies(
        user_id: String,
        permission_name: String,
        attributes: serde_json::Value,
        evaluated_by: Option<String>,
    ) -> EvaluateAbacPoliciesCommand {
        EvaluateAbacPoliciesCommand {
            command_id: Uuid::new_v4().to_string(),
            timestamp: Utc::now(),
            user_id,
            permission_name,
            attributes,
            evaluated_by,
        }
    }

    pub fn set_parent_role(
        role_id: String,
        parent_role_id: Option<String>,
        set_by: Option<String>,
    ) -> SetParentRoleCommand {
        SetParentRoleCommand {
            command_id: Uuid::new_v4().to_string(),
            timestamp: Utc::now(),
            role_id,
            parent_role_id,
            set_by,
        }
    }
}

/// Implement Command trait for all commands
impl Command for LoginUserCommand {
    fn command_id(&self) -> &str {
        &self.command_id
    }
    fn timestamp(&self) -> DateTime<Utc> {
        self.timestamp
    }
    fn user_id(&self) -> Option<&str> {
        None
    } // Login doesn't have a user_id yet
}

impl Command for ChangePasswordCommand {
    fn command_id(&self) -> &str {
        &self.command_id
    }
    fn timestamp(&self) -> DateTime<Utc> {
        self.timestamp
    }
    fn user_id(&self) -> Option<&str> {
        Some(&self.user_id)
    }
}

impl Command for ResetPasswordCommand {
    fn command_id(&self) -> &str {
        &self.command_id
    }
    fn timestamp(&self) -> DateTime<Utc> {
        self.timestamp
    }
    fn user_id(&self) -> Option<&str> {
        None
    } // Reset doesn't have user_id yet
}

impl Command for AssignRolesCommand {
    fn command_id(&self) -> &str {
        &self.command_id
    }
    fn timestamp(&self) -> DateTime<Utc> {
        self.timestamp
    }
    fn user_id(&self) -> Option<&str> {
        Some(&self.user_id)
    }
}

impl Command for CreateUserCommand {
    fn command_id(&self) -> &str {
        &self.command_id
    }
    fn timestamp(&self) -> DateTime<Utc> {
        self.timestamp
    }
    fn user_id(&self) -> Option<&str> {
        None
    } // Create doesn't have user_id yet
}

impl Command for UpdateUserProfileCommand {
    fn command_id(&self) -> &str {
        &self.command_id
    }
    fn timestamp(&self) -> DateTime<Utc> {
        self.timestamp
    }
    fn user_id(&self) -> Option<&str> {
        Some(&self.user_id)
    }
}

impl Command for ToggleUserLockCommand {
    fn command_id(&self) -> &str {
        &self.command_id
    }
    fn timestamp(&self) -> DateTime<Utc> {
        self.timestamp
    }
    fn user_id(&self) -> Option<&str> {
        Some(&self.user_id)
    }
}

impl Command for CreateRoleCommand {
    fn command_id(&self) -> &str {
        &self.command_id
    }
    fn timestamp(&self) -> DateTime<Utc> {
        self.timestamp
    }
    fn user_id(&self) -> Option<&str> {
        None
    } // Role creation doesn't have user_id
}

impl Command for AssignPermissionsToRoleCommand {
    fn command_id(&self) -> &str {
        &self.command_id
    }
    fn timestamp(&self) -> DateTime<Utc> {
        self.timestamp
    }
    fn user_id(&self) -> Option<&str> {
        None
    } // Permission assignment doesn't have user_id
}

impl Command for CreatePermissionCommand {
    fn command_id(&self) -> &str {
        &self.command_id
    }
    fn timestamp(&self) -> DateTime<Utc> {
        self.timestamp
    }
    fn user_id(&self) -> Option<&str> {
        None
    } // Permission creation doesn't have user_id
}

impl Command for DeletePermissionCommand {
    fn command_id(&self) -> &str {
        &self.command_id
    }
    fn timestamp(&self) -> DateTime<Utc> {
        self.timestamp
    }
    fn user_id(&self) -> Option<&str> {
        None
    } // Permission deletion doesn't have user_id
}

impl Command for RemovePermissionsFromRoleCommand {
    fn command_id(&self) -> &str {
        &self.command_id
    }
    fn timestamp(&self) -> DateTime<Utc> {
        self.timestamp
    }
    fn user_id(&self) -> Option<&str> {
        None
    } // Permission removal doesn't have user_id
}

impl Command for RemoveRolesFromUserCommand {
    fn command_id(&self) -> &str {
        &self.command_id
    }
    fn timestamp(&self) -> DateTime<Utc> {
        self.timestamp
    }
    fn user_id(&self) -> Option<&str> {
        Some(&self.user_id)
    }
}

impl Command for DeleteRoleCommand {
    fn command_id(&self) -> &str {
        &self.command_id
    }
    fn timestamp(&self) -> DateTime<Utc> {
        self.timestamp
    }
    fn user_id(&self) -> Option<&str> {
        None
    } // Role deletion doesn't have user_id
}

impl Command for UpdateRoleCommand {
    fn command_id(&self) -> &str {
        &self.command_id
    }
    fn timestamp(&self) -> DateTime<Utc> {
        self.timestamp
    }
    fn user_id(&self) -> Option<&str> {
        None
    } // Role update doesn't have user_id
}

impl Command for UpdatePermissionCommand {
    fn command_id(&self) -> &str {
        &self.command_id
    }
    fn timestamp(&self) -> DateTime<Utc> {
        self.timestamp
    }
    fn user_id(&self) -> Option<&str> {
        None
    } // Permission update doesn't have user_id
}

impl Command for CreateAbacPolicyCommand {
    fn command_id(&self) -> &str {
        &self.command_id
    }
    fn timestamp(&self) -> DateTime<Utc> {
        self.timestamp
    }
    fn user_id(&self) -> Option<&str> {
        None
    } // Policy creation doesn't have user_id
}

impl Command for UpdateAbacPolicyCommand {
    fn command_id(&self) -> &str {
        &self.command_id
    }
    fn timestamp(&self) -> DateTime<Utc> {
        self.timestamp
    }
    fn user_id(&self) -> Option<&str> {
        None
    } // Policy update doesn't have user_id
}

impl Command for DeleteAbacPolicyCommand {
    fn command_id(&self) -> &str {
        &self.command_id
    }
    fn timestamp(&self) -> DateTime<Utc> {
        self.timestamp
    }
    fn user_id(&self) -> Option<&str> {
        None
    } // Policy deletion doesn't have user_id
}

impl Command for AssignAbacPolicyToUserCommand {
    fn command_id(&self) -> &str {
        &self.command_id
    }
    fn timestamp(&self) -> DateTime<Utc> {
        self.timestamp
    }
    fn user_id(&self) -> Option<&str> {
        Some(&self.user_id)
    }
}

impl Command for CreatePermissionGroupCommand {
    fn command_id(&self) -> &str {
        &self.command_id
    }
    fn timestamp(&self) -> DateTime<Utc> {
        self.timestamp
    }
    fn user_id(&self) -> Option<&str> {
        None
    } // Group creation doesn't have user_id
}

impl Command for UpdatePermissionGroupCommand {
    fn command_id(&self) -> &str {
        &self.command_id
    }
    fn timestamp(&self) -> DateTime<Utc> {
        self.timestamp
    }
    fn user_id(&self) -> Option<&str> {
        None
    } // Group update doesn't have user_id
}

impl Command for DeletePermissionGroupCommand {
    fn command_id(&self) -> &str {
        &self.command_id
    }
    fn timestamp(&self) -> DateTime<Utc> {
        self.timestamp
    }
    fn user_id(&self) -> Option<&str> {
        None
    } // Group deletion doesn't have user_id
}

impl Command for ValidateTokenCommand {
    fn command_id(&self) -> &str {
        &self.command_id
    }
    fn timestamp(&self) -> DateTime<Utc> {
        self.timestamp
    }
    fn user_id(&self) -> Option<&str> {
        None
    } // Token validation doesn't have user_id yet
}

impl Command for RefreshTokenCommand {
    fn command_id(&self) -> &str {
        &self.command_id
    }
    fn timestamp(&self) -> DateTime<Utc> {
        self.timestamp
    }
    fn user_id(&self) -> Option<&str> {
        Some(&self.user_id)
    }
}

impl Command for LogoutCommand {
    fn command_id(&self) -> &str {
        &self.command_id
    }
    fn timestamp(&self) -> DateTime<Utc> {
        self.timestamp
    }
    fn user_id(&self) -> Option<&str> {
        Some(&self.user_id)
    }
}

impl Command for EvaluateAbacPoliciesCommand {
    fn command_id(&self) -> &str {
        &self.command_id
    }
    fn timestamp(&self) -> DateTime<Utc> {
        self.timestamp
    }
    fn user_id(&self) -> Option<&str> {
        Some(&self.user_id)
    }
}

impl Command for SetParentRoleCommand {
    fn command_id(&self) -> &str {
        &self.command_id
    }
    fn timestamp(&self) -> DateTime<Utc> {
        self.timestamp
    }
    fn user_id(&self) -> Option<&str> {
        None
    } // Role operations don't have user_id
}

impl Command for AuthenticateUserCommand {
    fn command_id(&self) -> &str {
        &self.command_id
    }
    fn timestamp(&self) -> DateTime<Utc> {
        self.timestamp
    }
    fn user_id(&self) -> Option<&str> {
        None
    } // Authentication doesn't have user_id
}

impl Command for CheckPermissionCommand {
    fn command_id(&self) -> &str {
        &self.command_id
    }
    fn timestamp(&self) -> DateTime<Utc> {
        self.timestamp
    }
    fn user_id(&self) -> Option<&str> {
        Some(&self.user_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_login_command_creation() {
        let command = CommandFactory::login_user(
            "test@example.com".to_string(),
            "password123".to_string(),
            Some("192.168.1.1".to_string()),
            Some("Mozilla/5.0".to_string()),
        );

        assert_eq!(command.email, "test@example.com");
        assert_eq!(command.password, "password123");
        assert_eq!(command.ip_address, Some("192.168.1.1".to_string()));
        assert_eq!(command.user_agent, Some("Mozilla/5.0".to_string()));
        assert!(!command.command_id.is_empty());
    }

    #[test]
    fn test_change_password_command_creation() {
        let command = CommandFactory::change_password(
            "user1".to_string(),
            "oldpass".to_string(),
            "newpass".to_string(),
            true,
        );

        assert_eq!(command.user_id, "user1");
        assert_eq!(command.current_password, "oldpass");
        assert_eq!(command.new_password, "newpass");
        assert!(command.require_current_password);
        assert!(!command.command_id.is_empty());
    }

    #[test]
    fn test_create_user_command_creation() {
        let command = CommandFactory::create_user(
            "newuser@example.com".to_string(),
            "password123".to_string(),
            Some("John".to_string()),
            Some("Doe".to_string()),
            vec!["user".to_string()],
            Some("admin".to_string()),
        );

        assert_eq!(command.email, "newuser@example.com");
        assert_eq!(command.password, "password123");
        assert_eq!(command.first_name, Some("John".to_string()));
        assert_eq!(command.last_name, Some("Doe".to_string()));
        assert_eq!(command.role_ids, vec!["user".to_string()]);
        assert_eq!(command.created_by, Some("admin".to_string()));
        assert!(!command.command_id.is_empty());
    }

    #[test]
    fn test_command_trait_implementation() {
        let command = CommandFactory::login_user(
            "test@example.com".to_string(),
            "password123".to_string(),
            None,
            None,
        );

        assert!(!command.command_id().is_empty());
        assert!(command.timestamp() <= Utc::now());
        assert!(command.user_id().is_none()); // Login doesn't have user_id yet
    }
}
