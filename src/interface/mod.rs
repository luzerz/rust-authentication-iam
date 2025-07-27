// Interface layer: HTTP/GRPC APIs, controllers, DTOs

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

#[derive(Serialize, Deserialize, ToSchema)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

#[derive(Serialize, ToSchema)]
pub struct LoginResponse {
    pub access_token: String,
    pub refresh_token: String,
}

#[derive(Serialize, Deserialize, ToSchema)]
pub struct ValidateTokenRequest {
    pub token: String,
}

#[derive(Serialize, ToSchema)]
pub struct ValidateTokenResponse {
    pub valid: bool,
    pub user_id: String,
    pub roles: Vec<String>,
}

#[derive(Serialize, Deserialize, ToSchema)]
pub struct RefreshTokenRequest {
    pub refresh_token: String,
}

#[derive(Serialize, ToSchema)]
pub struct RefreshTokenResponse {
    pub access_token: String,
    pub refresh_token: String,
}

#[derive(Serialize, Deserialize, ToSchema)]
pub struct LogoutRequest {
    pub refresh_token: String,
}

#[derive(Serialize, ToSchema)]
pub struct LogoutResponse {
    pub success: bool,
}

#[derive(Serialize, Deserialize, ToSchema)]
pub struct CreateRoleRequest {
    pub name: String,
}

#[derive(Serialize, Deserialize, ToSchema)]
pub struct UpdateRoleRequest {
    pub name: String,
}

#[derive(Serialize, Deserialize, ToSchema, Debug)]
pub struct RoleResponse {
    pub id: String,
    pub name: String,
    pub permissions: Vec<String>,
    pub parent_role_id: Option<String>,
}

#[derive(Serialize, ToSchema)]
pub struct RolesListResponse {
    pub roles: Vec<RoleResponse>,
}

#[derive(Serialize, Deserialize, ToSchema)]
pub struct AssignRoleRequest {
    pub user_id: String,
    pub role_id: String,
}

#[derive(Serialize, Deserialize, ToSchema)]
pub struct RemoveRoleRequest {
    pub user_id: String,
    pub role_id: String,
}

#[derive(serde::Serialize, serde::Deserialize, utoipa::ToSchema)]
pub struct SetParentRoleRequest {
    pub role_id: String,
    pub parent_role_id: Option<String>, // None to remove parent
}

#[derive(serde::Serialize, serde::Deserialize, utoipa::ToSchema)]
pub struct CreateRoleHierarchyRequest {
    pub parent_role_id: String,
    pub child_role_id: String,
}

#[derive(Serialize, ToSchema, Debug)]
pub struct RoleHierarchyResponse {
    pub role_id: String,
    pub role_name: String,
    pub parent_role_id: Option<String>,
    pub parent_role_name: Option<String>,
    pub inherited_roles: Vec<RoleResponse>,
}

#[derive(Serialize, ToSchema)]
pub struct RoleHierarchyListResponse {
    pub hierarchies: Vec<RoleHierarchyResponse>,
}

#[derive(Serialize, ToSchema)]
pub struct UserRolesResponse {
    pub user_id: String,
    pub roles: Vec<RoleResponse>,
}

#[derive(Serialize, ToSchema)]
pub struct EffectivePermissionsResponse {
    pub user_id: String,
    pub permissions: Vec<PermissionResponse>,
}

#[derive(Serialize, ToSchema)]
pub struct RolePermissionsResponse {
    pub role_id: String,
    pub permissions: Vec<PermissionResponse>,
}

#[derive(Serialize, Deserialize, ToSchema)]
pub struct CreatePermissionRequest {
    pub name: String,
}

#[derive(Serialize, Deserialize, ToSchema)]
pub struct UpdatePermissionRequest {
    pub name: String,
}

#[derive(Serialize, ToSchema)]
pub struct PermissionResponse {
    pub id: String,
    pub name: String,
}

#[derive(Serialize, ToSchema)]
pub struct PermissionsListResponse {
    pub permissions: Vec<PermissionResponse>,
}

#[derive(Serialize, Deserialize, ToSchema)]
pub struct AssignPermissionRequest {
    pub role_id: String,
    pub permission_id: String,
}

#[derive(Serialize, Deserialize, ToSchema)]
pub struct RemovePermissionRequest {
    pub role_id: String,
    pub permission_id: String,
}

#[derive(serde::Serialize, serde::Deserialize, utoipa::ToSchema)]
pub struct AbacPolicyRequest {
    pub name: String,
    pub effect: String, // "Allow" or "Deny"
    pub conditions: Vec<AbacConditionDto>,
    pub priority: Option<i32>, // 1-100, higher = more important
    pub conflict_resolution: Option<String>, // "deny_overrides", "allow_overrides", "priority_wins", "first_match"
}

#[derive(serde::Serialize, serde::Deserialize, utoipa::ToSchema)]
pub struct UpdateAbacPolicyRequest {
    pub name: Option<String>,
    pub effect: Option<String>, // "Allow" or "Deny"
    pub conditions: Option<Vec<AbacConditionDto>>,
    pub priority: Option<i32>, // 1-100, higher = more important
    pub conflict_resolution: Option<String>, // "deny_overrides", "allow_overrides", "priority_wins", "first_match"
}

#[derive(Clone, serde::Serialize, serde::Deserialize, utoipa::ToSchema)]
pub struct AbacConditionDto {
    pub attribute: String,
    pub operator: String,
    pub value: String,
}

#[derive(serde::Serialize, serde::Deserialize, utoipa::ToSchema)]
pub struct AbacPolicyResponse {
    pub id: String,
    pub name: String,
    pub effect: String,
    pub conditions: Vec<AbacConditionDto>,
    pub priority: i32,
    pub conflict_resolution: String,
}

#[derive(serde::Serialize, serde::Deserialize, utoipa::ToSchema)]
pub struct AbacPolicyListResponse {
    pub policies: Vec<AbacPolicyResponse>,
}

#[derive(serde::Serialize, serde::Deserialize, utoipa::ToSchema)]
pub struct AssignAbacPolicyRequest {
    pub target_type: String, // "user" or "role"
    pub target_id: String,
    pub policy_id: String,
}

#[derive(serde::Serialize, serde::Deserialize, utoipa::ToSchema)]
pub struct AbacEvaluationRequest {
    pub user_id: String,
    pub permission_name: String,
    pub attributes: std::collections::HashMap<String, String>,
}

#[derive(serde::Serialize, serde::Deserialize, utoipa::ToSchema)]
pub struct AbacEvaluationResponse {
    pub user_id: String,
    pub permission_name: String,
    pub allowed: bool,
    pub evaluated_policies: Vec<AbacPolicyEvaluationResult>,
    pub reason: String,
}

#[derive(Clone, serde::Serialize, serde::Deserialize, utoipa::ToSchema)]
pub struct AbacPolicyEvaluationResult {
    pub policy_id: String,
    pub policy_name: String,
    pub effect: String,
    pub priority: i32,
    pub conflict_resolution: String,
    pub matched: bool,
    pub matched_conditions: Vec<AbacConditionDto>,
    pub unmatched_conditions: Vec<AbacConditionDto>,
    pub applied: bool, // Whether this policy was actually applied in the final decision
}

#[derive(Serialize, Deserialize, ToSchema)]
pub struct UserRegistrationRequest {
    pub email: String,
    pub password: String,
    pub name: Option<String>,
}

#[derive(Serialize, ToSchema)]
pub struct UserRegistrationResponse {
    pub user_id: String,
    pub email: String,
    pub message: String,
}

#[derive(Serialize, Deserialize, ToSchema)]
pub struct PasswordChangeRequest {
    pub current_password: String,
    pub new_password: String,
}

#[derive(Serialize, Deserialize, ToSchema)]
pub struct PasswordResetRequest {
    pub email: String,
}

#[derive(Serialize, Deserialize, ToSchema)]
pub struct PasswordResetConfirmRequest {
    pub reset_token: String,
    pub new_password: String,
}

#[derive(Serialize, ToSchema)]
pub struct PasswordResetResponse {
    pub message: String,
}

#[derive(serde::Serialize, serde::Deserialize, utoipa::ToSchema)]
pub struct ErrorResponse {
    pub error: String,
}

// Permission group DTOs
#[derive(serde::Serialize, serde::Deserialize, utoipa::ToSchema)]
pub struct CreatePermissionGroupRequest {
    pub name: String,
    pub description: Option<String>,
    pub category: Option<String>,
    pub metadata: Option<serde_json::Value>,
}

#[derive(serde::Serialize, serde::Deserialize, utoipa::ToSchema)]
pub struct UpdatePermissionGroupRequest {
    pub name: Option<String>,
    pub description: Option<String>,
    pub category: Option<String>,
    pub metadata: Option<serde_json::Value>,
    pub is_active: Option<bool>,
}

#[derive(serde::Serialize, utoipa::ToSchema)]
pub struct PermissionGroupResponse {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub category: Option<String>,
    pub metadata: serde_json::Value,
    pub is_active: bool,
    pub permission_count: usize,
}

#[derive(serde::Serialize, utoipa::ToSchema)]
pub struct PermissionGroupListResponse {
    pub groups: Vec<PermissionGroupResponse>,
    pub total: usize,
}

pub mod app_state;
pub mod http_handlers;

pub use app_state::AppState;
pub use http_handlers::{
    assign_abac_policy_handler, assign_permission_handler, assign_role_handler,
    change_password_handler, confirm_password_reset_handler, create_abac_policy_handler,
    create_permission_group_handler, create_permission_handler, create_role_handler,
    create_role_hierarchy_handler, delete_abac_policy_handler, delete_permission_group_handler,
    delete_permission_handler, delete_role_handler, evaluate_abac_policies_handler,
    get_effective_permissions_handler, get_permission_group_handler, get_permission_handler,
    get_permissions_in_group_handler, get_role_handler, get_role_hierarchy_handler,
    list_abac_policies_handler, list_permission_groups_handler, list_permissions_handler,
    list_role_hierarchies_handler, list_role_permissions_handler, list_roles_handler,
    list_user_roles_handler, login_handler, logout_handler, refresh_token_handler,
    register_user_handler, remove_permission_handler, remove_role_handler,
    request_password_reset_handler, set_parent_role_handler, update_abac_policy_handler,
    update_permission_group_handler, update_permission_handler, update_role_handler,
    validate_token_handler,
};
