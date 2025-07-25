// Interface layer: HTTP/GRPC APIs, controllers, DTOs

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

#[derive(Deserialize, ToSchema)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

#[derive(Serialize, ToSchema)]
pub struct LoginResponse {
    pub access_token: String,
    pub refresh_token: String,
}

#[derive(Deserialize, ToSchema)]
pub struct ValidateTokenRequest {
    pub token: String,
}

#[derive(Serialize, ToSchema)]
pub struct ValidateTokenResponse {
    pub valid: bool,
    pub user_id: String,
    pub roles: Vec<String>,
}

#[derive(Deserialize, ToSchema)]
pub struct RefreshTokenRequest {
    pub refresh_token: String,
}

#[derive(Serialize, ToSchema)]
pub struct RefreshTokenResponse {
    pub access_token: String,
    pub refresh_token: String,
}

#[derive(Deserialize, ToSchema)]
pub struct LogoutRequest {
    pub refresh_token: String,
}

#[derive(Serialize, ToSchema)]
pub struct LogoutResponse {
    pub success: bool,
}

#[derive(Deserialize, ToSchema)]
pub struct CreateRoleRequest {
    pub name: String,
}

#[derive(Serialize, ToSchema)]
pub struct RoleResponse {
    pub id: String,
    pub name: String,
    pub permissions: Vec<String>,
}

#[derive(Serialize, ToSchema)]
pub struct RolesListResponse {
    pub roles: Vec<RoleResponse>,
}

#[derive(Deserialize, ToSchema)]
pub struct AssignRoleRequest {
    pub user_id: String,
    pub role_id: String,
}

#[derive(Deserialize, ToSchema)]
pub struct RemoveRoleRequest {
    pub user_id: String,
    pub role_id: String,
}

#[derive(Deserialize, ToSchema)]
pub struct CreatePermissionRequest {
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

#[derive(Deserialize, ToSchema)]
pub struct AssignPermissionRequest {
    pub role_id: String,
    pub permission_id: String,
}

#[derive(Deserialize, ToSchema)]
pub struct RemovePermissionRequest {
    pub role_id: String,
    pub permission_id: String,
}

#[derive(serde::Serialize, serde::Deserialize, utoipa::ToSchema)]
pub struct AbacPolicyRequest {
    pub name: String,
    pub effect: String, // "Allow" or "Deny"
    pub conditions: Vec<AbacConditionDto>,
}

#[derive(serde::Serialize, serde::Deserialize, utoipa::ToSchema)]
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
pub struct ErrorResponse {
    pub error: String,
}

pub mod app_state;
pub mod http_handlers;

pub use app_state::AppState;
pub use http_handlers::{
    assign_abac_policy_handler, assign_permission_handler, assign_role_handler,
    create_abac_policy_handler, create_permission_handler, create_role_handler,
    delete_abac_policy_handler, delete_permission_handler, delete_role_handler,
    list_abac_policies_handler, list_permissions_handler, list_roles_handler, login_handler,
    logout_handler, refresh_token_handler, remove_permission_handler, remove_role_handler,
    validate_token_handler,
};
