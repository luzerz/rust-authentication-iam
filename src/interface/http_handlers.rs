use crate::application::services::Claims;
use crate::interface::app_state::AppState;
use axum::extract::{FromRequestParts, State};
use axum::http::{StatusCode, request::Parts};
use axum::response::IntoResponse;

use crate::interface::{
    AbacConditionDto, AbacEvaluationRequest, AbacEvaluationResponse, AbacPolicyListResponse,
    AbacPolicyRequest, AbacPolicyResponse, AssignAbacPolicyRequest, AssignPermissionRequest,
    AssignRoleRequest, CreatePermissionGroupRequest, CreatePermissionRequest, CreateRoleRequest,
    EffectivePermissionsResponse, ErrorResponse, LoginRequest, LoginResponse, LogoutRequest,
    LogoutResponse, PasswordChangeRequest, PasswordResetConfirmRequest, PasswordResetRequest,
    PasswordResetResponse, PermissionGroupListResponse, PermissionGroupResponse,
    PermissionResponse, PermissionsListResponse, RefreshTokenRequest, RefreshTokenResponse,
    RemovePermissionRequest, RemoveRoleRequest, RoleHierarchyListResponse, RoleHierarchyResponse,
    RolePermissionsResponse, RoleResponse, RolesListResponse, SetParentRoleRequest,
    UpdateAbacPolicyRequest, UpdatePermissionGroupRequest, UserRegistrationRequest,
    UserRegistrationResponse, UserRolesResponse, ValidateTokenRequest, ValidateTokenResponse,
};
use axum::Json;
use std::ops::Deref;
use std::sync::Arc;

pub struct RequirePermission {
    pub user_id: String,
}

impl<S> FromRequestParts<S> for RequirePermission
where
    S: Send + Sync,
{
    type Rejection = (axum::http::StatusCode, &'static str);
    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let user_id = parts
            .headers
            .get("x-user-id")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string())
            .ok_or((axum::http::StatusCode::UNAUTHORIZED, "Missing user id"))?;
        Ok(RequirePermission { user_id })
    }
}

pub struct AuthenticatedUser {
    pub user_id: String,
    pub roles: Vec<String>,
    pub claims: Claims,
}

impl<S> FromRequestParts<S> for AuthenticatedUser
where
    S: Deref<Target = AppState> + Send + Sync + 'static,
{
    type Rejection = (StatusCode, &'static str);
    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let app_state: &AppState = state.deref();
        let auth_header = parts
            .headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .ok_or((StatusCode::UNAUTHORIZED, "Missing Authorization header"))?;
        let token = auth_header
            .strip_prefix("Bearer ")
            .ok_or((StatusCode::UNAUTHORIZED, "Invalid Authorization header"))?;
        let claims = app_state
            .token_service
            .validate_token(token)
            .map_err(|_| (StatusCode::UNAUTHORIZED, "Invalid or expired token"))?;
        Ok(AuthenticatedUser {
            user_id: claims.sub.clone(),
            roles: claims.roles.clone(),
            claims,
        })
    }
}

// --- AUTH HANDLERS ---

#[axum::debug_handler]
#[utoipa::path(
    post,
    path = "/v1/iam/auth/login",
    request_body = LoginRequest,
    responses(
        (status = 200, description = "Login successful", body = LoginResponse),
        (status = 401, description = "Login failed", body = ErrorResponse),
    ),
    tags = ["Auth"],
    description = "Authenticate user and return access/refresh tokens."
)]
pub async fn login_handler(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<LoginRequest>,
) -> impl IntoResponse {
    let cmd = crate::application::commands::LoginUserCommand {
        email: payload.email.clone(),
        password: payload.password,
    };
    let result = state
        .handler
        .handle(
            cmd,
            &state.auth_service,
            &state.token_service,
            &state.password_service,
            state.user_repo.clone(),
            state.refresh_token_repo.clone(),
        )
        .await;
    match result {
        Ok((access_token, refresh_token)) => Json(LoginResponse {
            access_token,
            refresh_token,
        })
        .into_response(),
        Err(e) => (
            axum::http::StatusCode::UNAUTHORIZED,
            format!("Login failed: {e:?}"),
        )
            .into_response(),
    }
}

#[axum::debug_handler]
#[utoipa::path(
    get,
    path = "/v1/iam/roles/{role_id}/permissions",
    responses(
        (status = 200, description = "Role permissions retrieved", body = RolePermissionsResponse),
        (status = 403, description = "Insufficient permissions", body = ErrorResponse),
    ),
    tags = ["RBAC"],
    description = "Get all permissions assigned to a specific role. Requires rbac:read permission."
)]
pub async fn list_role_permissions_handler(
    State(state): State<Arc<AppState>>,
    RequirePermission {
        user_id: requesting_user,
    }: RequirePermission,
    Path(role_id): Path<String>,
) -> impl IntoResponse {
    let allowed = state
        .authz_service
        .user_has_permission(&requesting_user, "rbac:read", None)
        .await
        .unwrap_or(false);
    if !allowed {
        return (
            axum::http::StatusCode::FORBIDDEN,
            "Insufficient permissions",
        )
            .into_response();
    }

    let permissions = match state
        .permission_repo
        .get_permissions_for_role(&role_id)
        .await
    {
        Ok(permissions) => permissions,
        Err(_) => {
            return (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to retrieve role permissions",
            )
                .into_response();
        }
    };

    let permission_responses: Vec<PermissionResponse> = permissions
        .into_iter()
        .map(|permission| PermissionResponse {
            id: permission.id,
            name: permission.name,
        })
        .collect();

    let resp = RolePermissionsResponse {
        role_id,
        permissions: permission_responses,
    };
    Json(resp).into_response()
}

#[axum::debug_handler]
#[utoipa::path(
    get,
    path = "/v1/iam/users/{user_id}/roles",
    responses(
        (status = 200, description = "User roles retrieved", body = UserRolesResponse),
        (status = 403, description = "Insufficient permissions", body = ErrorResponse),
    ),
    tags = ["RBAC"],
    description = "Get all roles assigned to a specific user. Requires rbac:read permission."
)]
pub async fn list_user_roles_handler(
    State(state): State<Arc<AppState>>,
    RequirePermission {
        user_id: requesting_user,
    }: RequirePermission,
    Path(target_user_id): Path<String>,
) -> impl IntoResponse {
    let allowed = state
        .authz_service
        .user_has_permission(&requesting_user, "rbac:read", None)
        .await
        .unwrap_or(false);
    if !allowed {
        return (
            axum::http::StatusCode::FORBIDDEN,
            "Insufficient permissions",
        )
            .into_response();
    }

    let roles = match state.role_repo.get_roles_for_user(&target_user_id).await {
        Ok(roles) => roles,
        Err(_) => {
            return (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to retrieve user roles",
            )
                .into_response();
        }
    };

    let role_responses: Vec<RoleResponse> = roles
        .into_iter()
        .map(|role| RoleResponse {
            id: role.id,
            name: role.name,
            permissions: role.permissions, // Just return the permission IDs
            parent_role_id: role.parent_role_id,
        })
        .collect();

    let resp = UserRolesResponse {
        user_id: target_user_id,
        roles: role_responses,
    };
    Json(resp).into_response()
}

#[axum::debug_handler]
#[utoipa::path(
    get,
    path = "/v1/iam/users/{user_id}/effective-permissions",
    responses(
        (status = 200, description = "Effective permissions retrieved", body = EffectivePermissionsResponse),
        (status = 403, description = "Insufficient permissions", body = ErrorResponse),
    ),
    tags = ["RBAC"],
    description = "Get all effective permissions for a specific user (including permissions from roles). Requires rbac:read permission."
)]
pub async fn get_effective_permissions_handler(
    State(state): State<Arc<AppState>>,
    RequirePermission {
        user_id: requesting_user,
    }: RequirePermission,
    Path(target_user_id): Path<String>,
) -> impl IntoResponse {
    let allowed = state
        .authz_service
        .user_has_permission(&requesting_user, "rbac:read", None)
        .await
        .unwrap_or(false);
    if !allowed {
        return (
            axum::http::StatusCode::FORBIDDEN,
            "Insufficient permissions",
        )
            .into_response();
    }

    // Get user's roles
    let roles = match state.role_repo.get_roles_for_user(&target_user_id).await {
        Ok(roles) => roles,
        Err(_) => {
            return (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to retrieve user roles",
            )
                .into_response();
        }
    };

    // Collect all permission IDs from roles
    let mut all_permission_ids = std::collections::HashSet::new();
    for role in roles {
        for permission_id in role.permissions {
            all_permission_ids.insert(permission_id);
        }
    }

    // Fetch permission details for all IDs
    let mut permission_responses = Vec::new();
    for permission_id in all_permission_ids {
        if let Ok(Some(permission)) = state.permission_repo.get_permission(&permission_id).await {
            permission_responses.push(PermissionResponse {
                id: permission.id,
                name: permission.name,
            });
        }
    }

    let resp = EffectivePermissionsResponse {
        user_id: target_user_id,
        permissions: permission_responses,
    };
    Json(resp).into_response()
}

#[axum::debug_handler]
#[utoipa::path(
    post,
    path = "/v1/iam/auth/validate-token",
    request_body = ValidateTokenRequest,
    responses(
        (status = 200, description = "Token valid", body = ValidateTokenResponse),
        (status = 401, description = "Token invalid", body = ErrorResponse),
    ),
    tags = ["Auth"],
    description = "Validate a JWT access token and return claims."
)]
pub async fn validate_token_handler(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<ValidateTokenRequest>,
) -> impl IntoResponse {
    let result = state.token_service.validate_token(&payload.token);
    match result {
        Ok(claims) => Json(ValidateTokenResponse {
            valid: true,
            user_id: claims.sub,
            roles: claims.roles,
        })
        .into_response(),
        Err(_) => Json(ValidateTokenResponse {
            valid: false,
            user_id: String::new(),
            roles: Vec::new(),
        })
        .into_response(),
    }
}

#[axum::debug_handler]
#[utoipa::path(
    post,
    path = "/v1/iam/auth/refresh-token",
    request_body = RefreshTokenRequest,
    responses(
        (status = 200, description = "Token refreshed", body = RefreshTokenResponse),
        (status = 401, description = "Invalid refresh token", body = ErrorResponse),
    ),
    tags = ["Auth"],
    description = "Refresh access and refresh tokens using a valid refresh token."
)]
pub async fn refresh_token_handler(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<RefreshTokenRequest>,
) -> impl IntoResponse {
    let result = state.token_service.validate_token(&payload.refresh_token);
    match result {
        Ok(claims) => {
            let user_id = claims.sub;
            let user = state.user_repo.find_by_email(&user_id).await;
            if let Some(user) = user {
                match state
                    .token_service
                    .refresh_tokens(
                        &payload.refresh_token,
                        &user,
                        state.refresh_token_repo.clone(),
                    )
                    .await
                {
                    Ok((access_token, refresh_token)) => Json(RefreshTokenResponse {
                        access_token,
                        refresh_token,
                    })
                    .into_response(),
                    Err(_) => (
                        axum::http::StatusCode::UNAUTHORIZED,
                        "Invalid refresh token",
                    )
                        .into_response(),
                }
            } else {
                (axum::http::StatusCode::UNAUTHORIZED, "User not found").into_response()
            }
        }
        Err(_) => (
            axum::http::StatusCode::UNAUTHORIZED,
            "Invalid refresh token",
        )
            .into_response(),
    }
}

#[axum::debug_handler]
#[utoipa::path(
    post,
    path = "/v1/iam/auth/logout",
    request_body = LogoutRequest,
    responses(
        (status = 200, description = "Logout successful", body = LogoutResponse),
        (status = 401, description = "Invalid refresh token", body = ErrorResponse),
    ),
    tags = ["Auth"],
    description = "Logout user and revoke refresh token."
)]
pub async fn logout_handler(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<LogoutRequest>,
) -> impl IntoResponse {
    let result = state.token_service.validate_token(&payload.refresh_token);
    match result {
        Ok(claims) => {
            let _ = state.refresh_token_repo.revoke(&claims.jti).await;
            Json(LogoutResponse { success: true }).into_response()
        }
        Err(_) => (
            axum::http::StatusCode::UNAUTHORIZED,
            "Invalid refresh token",
        )
            .into_response(),
    }
}

// --- RBAC HANDLERS ---

use axum::extract::Path;

#[axum::debug_handler]
#[utoipa::path(
    post,
    path = "/v1/iam/rbac/roles",
    request_body = CreateRoleRequest,
    responses(
        (status = 201, description = "Role created", body = RoleResponse),
        (status = 403, description = "Insufficient permissions", body = ErrorResponse),
    ),
    tags = ["RBAC"],
    description = "Create a new role. Requires rbac:manage permission."
)]
pub async fn create_role_handler(
    State(state): State<Arc<AppState>>,
    _auth: AuthenticatedUser, // Require JWT auth
    RequirePermission { user_id }: RequirePermission,
    Json(payload): Json<CreateRoleRequest>,
) -> impl IntoResponse {
    let allowed = state
        .authz_service
        .user_has_permission(&user_id, "rbac:manage", None)
        .await
        .unwrap_or(false);
    if !allowed {
        return (
            axum::http::StatusCode::FORBIDDEN,
            "Insufficient permissions",
        )
            .into_response();
    }
    let role = state.role_repo.create_role(&payload.name).await;
    (
        axum::http::StatusCode::CREATED,
        Json(RoleResponse {
            id: role.id,
            name: role.name,
            permissions: role.permissions,
            parent_role_id: role.parent_role_id,
        }),
    )
        .into_response()
}

#[axum::debug_handler]
#[utoipa::path(
    get,
    path = "/v1/iam/rbac/roles",
    responses(
        (status = 200, description = "List of roles", body = RolesListResponse),
    ),
    tags = ["RBAC"],
    description = "List all roles."
)]
pub async fn list_roles_handler(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let roles = state.role_repo.list_roles().await;
    let roles = roles
        .into_iter()
        .map(|role| RoleResponse {
            id: role.id,
            name: role.name,
            permissions: role.permissions,
            parent_role_id: role.parent_role_id,
        })
        .collect();
    Json(RolesListResponse { roles }).into_response()
}

#[axum::debug_handler]
#[utoipa::path(
    delete,
    path = "/v1/iam/rbac/roles/{role_id}",
    responses(
        (status = 204, description = "Role deleted"),
        (status = 403, description = "Insufficient permissions", body = ErrorResponse),
    ),
    tags = ["RBAC"],
    description = "Delete a role by ID. Requires rbac:manage permission."
)]
pub async fn delete_role_handler(
    State(state): State<Arc<AppState>>,
    RequirePermission { user_id }: RequirePermission,
    Path(role_id): Path<String>,
) -> impl IntoResponse {
    let allowed = state
        .authz_service
        .user_has_permission(&user_id, "rbac:manage", None)
        .await
        .unwrap_or(false);
    if !allowed {
        return (
            axum::http::StatusCode::FORBIDDEN,
            "Insufficient permissions",
        )
            .into_response();
    }
    state.role_repo.delete_role(&role_id).await;
    axum::http::StatusCode::NO_CONTENT.into_response()
}

#[axum::debug_handler]
#[utoipa::path(
    post,
    path = "/v1/iam/rbac/roles/assign",
    request_body = AssignRoleRequest,
    responses(
        (status = 200, description = "Role assigned"),
        (status = 403, description = "Insufficient permissions", body = ErrorResponse),
    ),
    tags = ["RBAC"],
    description = "Assign a role to a user. Requires rbac:manage permission."
)]
pub async fn assign_role_handler(
    State(state): State<Arc<AppState>>,
    RequirePermission { user_id }: RequirePermission,
    Json(payload): Json<AssignRoleRequest>,
) -> impl IntoResponse {
    let allowed = state
        .authz_service
        .user_has_permission(&user_id, "rbac:manage", None)
        .await
        .unwrap_or(false);
    if !allowed {
        return (
            axum::http::StatusCode::FORBIDDEN,
            "Insufficient permissions",
        )
            .into_response();
    }
    state
        .role_repo
        .assign_role(&payload.user_id, &payload.role_id)
        .await;
    axum::http::StatusCode::OK.into_response()
}

#[axum::debug_handler]
#[utoipa::path(
    post,
    path = "/v1/iam/rbac/roles/remove",
    request_body = RemoveRoleRequest,
    responses(
        (status = 200, description = "Role removed"),
        (status = 403, description = "Insufficient permissions", body = ErrorResponse),
    ),
    tags = ["RBAC"],
    description = "Remove a role from a user. Requires rbac:manage permission."
)]
pub async fn remove_role_handler(
    State(state): State<Arc<AppState>>,
    RequirePermission { user_id }: RequirePermission,
    Json(payload): Json<RemoveRoleRequest>,
) -> impl IntoResponse {
    let allowed = state
        .authz_service
        .user_has_permission(&user_id, "rbac:manage", None)
        .await
        .unwrap_or(false);
    if !allowed {
        return (
            axum::http::StatusCode::FORBIDDEN,
            "Insufficient permissions",
        )
            .into_response();
    }
    state
        .role_repo
        .remove_role(&payload.user_id, &payload.role_id)
        .await;
    axum::http::StatusCode::OK.into_response()
}

#[axum::debug_handler]
#[utoipa::path(
    post,
    path = "/v1/iam/rbac/permissions",
    request_body = CreatePermissionRequest,
    responses(
        (status = 201, description = "Permission created", body = PermissionResponse),
        (status = 403, description = "Insufficient permissions", body = ErrorResponse),
    ),
    tags = ["RBAC"],
    description = "Create a new permission. Requires rbac:manage permission."
)]
pub async fn create_permission_handler(
    State(state): State<Arc<AppState>>,
    RequirePermission { user_id }: RequirePermission,
    Json(payload): Json<CreatePermissionRequest>,
) -> impl IntoResponse {
    let allowed = state
        .authz_service
        .user_has_permission(&user_id, "rbac:manage", None)
        .await
        .unwrap_or(false);
    if !allowed {
        return (
            axum::http::StatusCode::FORBIDDEN,
            "Insufficient permissions",
        )
            .into_response();
    }
    let perm = state
        .permission_repo
        .create_permission(&payload.name)
        .await
        .unwrap();
    (
        axum::http::StatusCode::CREATED,
        Json(PermissionResponse {
            id: perm.id,
            name: perm.name,
        }),
    )
        .into_response()
}

#[axum::debug_handler]
#[utoipa::path(
    get,
    path = "/v1/iam/rbac/permissions",
    responses(
        (status = 200, description = "List of permissions", body = PermissionsListResponse),
    ),
    tags = ["RBAC"],
    description = "List all permissions."
)]
pub async fn list_permissions_handler(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let perms = state
        .permission_repo
        .list_permissions()
        .await
        .unwrap_or_default();
    let permissions = perms
        .into_iter()
        .map(|p| PermissionResponse {
            id: p.id,
            name: p.name,
        })
        .collect();
    Json(PermissionsListResponse { permissions }).into_response()
}

#[axum::debug_handler]
#[utoipa::path(
    delete,
    path = "/v1/iam/rbac/permissions/{permission_id}",
    responses(
        (status = 204, description = "Permission deleted"),
        (status = 403, description = "Insufficient permissions", body = ErrorResponse),
    ),
    tags = ["RBAC"],
    description = "Delete a permission by ID. Requires rbac:manage permission."
)]
pub async fn delete_permission_handler(
    State(state): State<Arc<AppState>>,
    RequirePermission { user_id }: RequirePermission,
    Path(permission_id): Path<String>,
) -> impl IntoResponse {
    let allowed = state
        .authz_service
        .user_has_permission(&user_id, "rbac:manage", None)
        .await
        .unwrap_or(false);
    if !allowed {
        return (
            axum::http::StatusCode::FORBIDDEN,
            "Insufficient permissions",
        )
            .into_response();
    }
    state
        .permission_repo
        .delete_permission(&permission_id)
        .await
        .unwrap();
    axum::http::StatusCode::NO_CONTENT.into_response()
}

#[axum::debug_handler]
#[utoipa::path(
    post,
    path = "/v1/iam/rbac/permissions/assign",
    request_body = AssignPermissionRequest,
    responses(
        (status = 200, description = "Permission assigned"),
        (status = 403, description = "Insufficient permissions", body = ErrorResponse),
    ),
    tags = ["RBAC"],
    description = "Assign a permission to a role. Requires rbac:manage permission."
)]
pub async fn assign_permission_handler(
    State(state): State<Arc<AppState>>,
    RequirePermission { user_id }: RequirePermission,
    Json(payload): Json<AssignPermissionRequest>,
) -> impl IntoResponse {
    let allowed = state
        .authz_service
        .user_has_permission(&user_id, "rbac:manage", None)
        .await
        .unwrap_or(false);
    if !allowed {
        return (
            axum::http::StatusCode::FORBIDDEN,
            "Insufficient permissions",
        )
            .into_response();
    }
    state
        .permission_repo
        .assign_permission(&payload.role_id, &payload.permission_id)
        .await
        .unwrap();
    axum::http::StatusCode::OK.into_response()
}

#[axum::debug_handler]
#[utoipa::path(
    post,
    path = "/v1/iam/rbac/permissions/remove",
    request_body = RemovePermissionRequest,
    responses(
        (status = 200, description = "Permission removed"),
        (status = 403, description = "Insufficient permissions", body = ErrorResponse),
    ),
    tags = ["RBAC"],
    description = "Remove a permission from a role. Requires rbac:manage permission."
)]
pub async fn remove_permission_handler(
    State(state): State<Arc<AppState>>,
    RequirePermission { user_id }: RequirePermission,
    Json(payload): Json<RemovePermissionRequest>,
) -> impl IntoResponse {
    let allowed = state
        .authz_service
        .user_has_permission(&user_id, "rbac:manage", None)
        .await
        .unwrap_or(false);
    if !allowed {
        return (
            axum::http::StatusCode::FORBIDDEN,
            "Insufficient permissions",
        )
            .into_response();
    }
    state
        .permission_repo
        .remove_permission(&payload.role_id, &payload.permission_id)
        .await
        .unwrap();
    axum::http::StatusCode::OK.into_response()
}

// --- ABAC HANDLERS ---

#[axum::debug_handler]
#[utoipa::path(
    post,
    path = "/v1/iam/abac/policies",
    request_body = AbacPolicyRequest,
    responses(
        (status = 201, description = "Policy created", body = AbacPolicyResponse),
        (status = 403, description = "Insufficient permissions", body = ErrorResponse),
    ),
    tags = ["ABAC"],
    description = "Create a new ABAC policy. Requires rbac:manage permission."
)]
pub async fn create_abac_policy_handler(
    State(state): State<Arc<AppState>>,
    RequirePermission { user_id }: RequirePermission,
    Json(payload): Json<AbacPolicyRequest>,
) -> impl IntoResponse {
    let allowed = state
        .authz_service
        .user_has_permission(&user_id, "rbac:manage", None)
        .await
        .unwrap_or(false);
    if !allowed {
        return (
            axum::http::StatusCode::FORBIDDEN,
            "Insufficient permissions",
        )
            .into_response();
    }
    let id = uuid::Uuid::new_v4().to_string();
    let effect = match payload.effect.as_str() {
        "Allow" => crate::domain::abac_policy::AbacEffect::Allow,
        "Deny" => crate::domain::abac_policy::AbacEffect::Deny,
        _ => return (axum::http::StatusCode::BAD_REQUEST, "Invalid effect").into_response(),
    };
    let conditions = payload
        .conditions
        .into_iter()
        .map(|c| crate::domain::abac_policy::AbacCondition {
            attribute: c.attribute,
            operator: c.operator,
            value: c.value,
        })
        .collect();
    let policy = crate::domain::abac_policy::AbacPolicy {
        id: id.clone(),
        name: payload.name,
        effect,
        conditions,
        priority: payload.priority,
        conflict_resolution: payload
            .conflict_resolution
            .as_ref()
            .map(|s| match s.as_str() {
                "deny_overrides" => {
                    crate::domain::abac_policy::ConflictResolutionStrategy::DenyOverrides
                }
                "allow_overrides" => {
                    crate::domain::abac_policy::ConflictResolutionStrategy::AllowOverrides
                }
                "priority_wins" => {
                    crate::domain::abac_policy::ConflictResolutionStrategy::PriorityWins
                }
                "first_match" => crate::domain::abac_policy::ConflictResolutionStrategy::FirstMatch,
                _ => crate::domain::abac_policy::ConflictResolutionStrategy::DenyOverrides, // Default
            }),
    };
    let created = state.abac_policy_repo.create_policy(policy).await.unwrap();
    let resp = AbacPolicyResponse {
        id: created.id,
        name: created.name,
        effect: match created.effect {
            crate::domain::abac_policy::AbacEffect::Allow => "Allow".to_string(),
            crate::domain::abac_policy::AbacEffect::Deny => "Deny".to_string(),
        },
        conditions: created
            .conditions
            .into_iter()
            .map(|c| AbacConditionDto {
                attribute: c.attribute,
                operator: c.operator,
                value: c.value,
            })
            .collect(),
        priority: created.priority.unwrap_or(50),
        conflict_resolution: match created
            .conflict_resolution
            .as_ref()
            .unwrap_or(&crate::domain::abac_policy::ConflictResolutionStrategy::DenyOverrides)
        {
            crate::domain::abac_policy::ConflictResolutionStrategy::DenyOverrides => {
                "deny_overrides".to_string()
            }
            crate::domain::abac_policy::ConflictResolutionStrategy::AllowOverrides => {
                "allow_overrides".to_string()
            }
            crate::domain::abac_policy::ConflictResolutionStrategy::PriorityWins => {
                "priority_wins".to_string()
            }
            crate::domain::abac_policy::ConflictResolutionStrategy::FirstMatch => {
                "first_match".to_string()
            }
        },
    };
    (axum::http::StatusCode::CREATED, Json(resp)).into_response()
}

#[axum::debug_handler]
#[utoipa::path(
    put,
    path = "/v1/iam/abac/policies/{policy_id}",
    request_body = UpdateAbacPolicyRequest,
    responses(
        (status = 200, description = "Policy updated", body = AbacPolicyResponse),
        (status = 403, description = "Insufficient permissions", body = ErrorResponse),
        (status = 404, description = "Policy not found", body = ErrorResponse),
    ),
    tags = ["ABAC"],
    description = "Update an existing ABAC policy. Requires rbac:manage permission."
)]
pub async fn update_abac_policy_handler(
    State(state): State<Arc<AppState>>,
    RequirePermission { user_id }: RequirePermission,
    Path(policy_id): Path<String>,
    Json(payload): Json<UpdateAbacPolicyRequest>,
) -> impl IntoResponse {
    let allowed = state
        .authz_service
        .user_has_permission(&user_id, "rbac:manage", None)
        .await
        .unwrap_or(false);
    if !allowed {
        return (
            axum::http::StatusCode::FORBIDDEN,
            "Insufficient permissions",
        )
            .into_response();
    }

    // Get the existing policy
    let existing_policy = match state.abac_policy_repo.get_policy(&policy_id).await {
        Ok(Some(policy)) => policy,
        Ok(None) => {
            return (axum::http::StatusCode::NOT_FOUND, "Policy not found").into_response();
        }
        Err(_) => {
            return (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to retrieve policy",
            )
                .into_response();
        }
    };

    // Create updated policy with new values or keep existing ones
    let updated_policy = crate::domain::abac_policy::AbacPolicy {
        id: policy_id.clone(),
        name: payload.name.unwrap_or(existing_policy.name),
        effect: if let Some(effect_str) = payload.effect {
            match effect_str.as_str() {
                "Allow" => crate::domain::abac_policy::AbacEffect::Allow,
                "Deny" => crate::domain::abac_policy::AbacEffect::Deny,
                _ => {
                    return (axum::http::StatusCode::BAD_REQUEST, "Invalid effect").into_response();
                }
            }
        } else {
            existing_policy.effect
        },
        conditions: payload
            .conditions
            .map(|conditions| {
                conditions
                    .into_iter()
                    .map(|c| crate::domain::abac_policy::AbacCondition {
                        attribute: c.attribute,
                        operator: c.operator,
                        value: c.value,
                    })
                    .collect()
            })
            .unwrap_or(existing_policy.conditions),
        priority: payload.priority.or(existing_policy.priority),
        conflict_resolution: payload
            .conflict_resolution
            .as_ref()
            .map(|s| match s.as_str() {
                "deny_overrides" => {
                    crate::domain::abac_policy::ConflictResolutionStrategy::DenyOverrides
                }
                "allow_overrides" => {
                    crate::domain::abac_policy::ConflictResolutionStrategy::AllowOverrides
                }
                "priority_wins" => {
                    crate::domain::abac_policy::ConflictResolutionStrategy::PriorityWins
                }
                "first_match" => crate::domain::abac_policy::ConflictResolutionStrategy::FirstMatch,
                _ => crate::domain::abac_policy::ConflictResolutionStrategy::DenyOverrides, // Default
            })
            .or(existing_policy.conflict_resolution),
    };

    // Update the policy
    let updated_policy = match state
        .abac_policy_repo
        .update_policy(&policy_id, updated_policy)
        .await
    {
        Ok(policy) => policy,
        Err(_) => {
            return (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to update policy",
            )
                .into_response();
        }
    };

    let resp = AbacPolicyResponse {
        id: updated_policy.id,
        name: updated_policy.name,
        effect: match updated_policy.effect {
            crate::domain::abac_policy::AbacEffect::Allow => "Allow".to_string(),
            crate::domain::abac_policy::AbacEffect::Deny => "Deny".to_string(),
        },
        conditions: updated_policy
            .conditions
            .into_iter()
            .map(|c| AbacConditionDto {
                attribute: c.attribute,
                operator: c.operator,
                value: c.value,
            })
            .collect(),
        priority: updated_policy.priority.unwrap_or(50),
        conflict_resolution: match updated_policy
            .conflict_resolution
            .as_ref()
            .unwrap_or(&crate::domain::abac_policy::ConflictResolutionStrategy::DenyOverrides)
        {
            crate::domain::abac_policy::ConflictResolutionStrategy::DenyOverrides => {
                "deny_overrides".to_string()
            }
            crate::domain::abac_policy::ConflictResolutionStrategy::AllowOverrides => {
                "allow_overrides".to_string()
            }
            crate::domain::abac_policy::ConflictResolutionStrategy::PriorityWins => {
                "priority_wins".to_string()
            }
            crate::domain::abac_policy::ConflictResolutionStrategy::FirstMatch => {
                "first_match".to_string()
            }
        },
    };
    Json(resp).into_response()
}

#[axum::debug_handler]
#[utoipa::path(
    get,
    path = "/v1/iam/abac/policies",
    responses(
        (status = 200, description = "List of policies", body = AbacPolicyListResponse),
    ),
    tags = ["ABAC"],
    description = "List all ABAC policies."
)]
pub async fn list_abac_policies_handler(
    State(state): State<Arc<AppState>>,
    RequirePermission { user_id }: RequirePermission,
) -> impl IntoResponse {
    let allowed = state
        .authz_service
        .user_has_permission(&user_id, "rbac:manage", None)
        .await
        .unwrap_or(false);
    if !allowed {
        return (
            axum::http::StatusCode::FORBIDDEN,
            "Insufficient permissions",
        )
            .into_response();
    }
    let policies = state
        .abac_policy_repo
        .list_policies()
        .await
        .unwrap_or_default();
    let resp = AbacPolicyListResponse {
        policies: policies
            .into_iter()
            .map(|p| AbacPolicyResponse {
                id: p.id,
                name: p.name,
                effect: match p.effect {
                    crate::domain::abac_policy::AbacEffect::Allow => "Allow".to_string(),
                    crate::domain::abac_policy::AbacEffect::Deny => "Deny".to_string(),
                },
                conditions: p
                    .conditions
                    .into_iter()
                    .map(|c| AbacConditionDto {
                        attribute: c.attribute,
                        operator: c.operator,
                        value: c.value,
                    })
                    .collect(),
                priority: p.priority.unwrap_or(50),
                conflict_resolution: match p.conflict_resolution.as_ref().unwrap_or(
                    &crate::domain::abac_policy::ConflictResolutionStrategy::DenyOverrides,
                ) {
                    crate::domain::abac_policy::ConflictResolutionStrategy::DenyOverrides => {
                        "deny_overrides".to_string()
                    }
                    crate::domain::abac_policy::ConflictResolutionStrategy::AllowOverrides => {
                        "allow_overrides".to_string()
                    }
                    crate::domain::abac_policy::ConflictResolutionStrategy::PriorityWins => {
                        "priority_wins".to_string()
                    }
                    crate::domain::abac_policy::ConflictResolutionStrategy::FirstMatch => {
                        "first_match".to_string()
                    }
                },
            })
            .collect(),
    };
    Json(resp).into_response()
}

#[axum::debug_handler]
#[utoipa::path(
    delete,
    path = "/v1/iam/abac/policies/{policy_id}",
    responses(
        (status = 204, description = "Policy deleted"),
        (status = 403, description = "Insufficient permissions", body = ErrorResponse),
    ),
    tags = ["ABAC"],
    description = "Delete an ABAC policy by ID. Requires rbac:manage permission."
)]
pub async fn delete_abac_policy_handler(
    State(state): State<Arc<AppState>>,
    RequirePermission { user_id }: RequirePermission,
    Path(policy_id): Path<String>,
) -> impl IntoResponse {
    let allowed = state
        .authz_service
        .user_has_permission(&user_id, "rbac:manage", None)
        .await
        .unwrap_or(false);
    if !allowed {
        return (
            axum::http::StatusCode::FORBIDDEN,
            "Insufficient permissions",
        )
            .into_response();
    }
    state
        .abac_policy_repo
        .delete_policy(&policy_id)
        .await
        .unwrap();
    axum::http::StatusCode::NO_CONTENT.into_response()
}

#[axum::debug_handler]
#[utoipa::path(
    post,
    path = "/v1/iam/abac/policies/assign",
    request_body = AssignAbacPolicyRequest,
    responses(
        (status = 200, description = "Policy assigned"),
        (status = 403, description = "Insufficient permissions", body = ErrorResponse),
    ),
    tags = ["ABAC"],
    description = "Assign an ABAC policy to a user or role. Requires rbac:manage permission."
)]
pub async fn assign_abac_policy_handler(
    State(state): State<Arc<AppState>>,
    RequirePermission { user_id }: RequirePermission,
    Json(payload): Json<AssignAbacPolicyRequest>,
) -> impl IntoResponse {
    let allowed = state
        .authz_service
        .user_has_permission(&user_id, "rbac:manage", None)
        .await
        .unwrap_or(false);
    if !allowed {
        return (
            axum::http::StatusCode::FORBIDDEN,
            "Insufficient permissions",
        )
            .into_response();
    }
    let result = match payload.target_type.as_str() {
        "user" => {
            state
                .abac_policy_repo
                .assign_policy_to_user(&payload.target_id, &payload.policy_id)
                .await
        }
        "role" => {
            state
                .abac_policy_repo
                .assign_policy_to_role(&payload.target_id, &payload.policy_id)
                .await
        }
        _ => return (axum::http::StatusCode::BAD_REQUEST, "Invalid target_type").into_response(),
    };
    match result {
        Ok(_) => axum::http::StatusCode::OK.into_response(),
        Err(_) => (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            "Assignment failed",
        )
            .into_response(),
    }
}

#[axum::debug_handler]
#[utoipa::path(
    post,
    path = "/v1/iam/abac/evaluate",
    request_body = AbacEvaluationRequest,
    responses(
        (status = 200, description = "Policy evaluation completed", body = AbacEvaluationResponse),
        (status = 403, description = "Insufficient permissions", body = ErrorResponse),
    ),
    tags = ["ABAC"],
    description = "Evaluate ABAC policies for a user with given attributes. Requires rbac:read permission."
)]
pub async fn evaluate_abac_policies_handler(
    State(state): State<Arc<AppState>>,
    RequirePermission { user_id }: RequirePermission,
    Json(payload): Json<AbacEvaluationRequest>,
) -> impl IntoResponse {
    let allowed = state
        .authz_service
        .user_has_permission(&user_id, "rbac:read", None)
        .await
        .unwrap_or(false);
    if !allowed {
        return (
            axum::http::StatusCode::FORBIDDEN,
            "Insufficient permissions",
        )
            .into_response();
    }

    // Evaluate the ABAC policies
    let evaluation_result = match state
        .authz_service
        .evaluate_abac_policies(
            &payload.user_id,
            &payload.permission_name,
            &payload.attributes,
        )
        .await
    {
        Ok(result) => result,
        Err(_) => {
            return (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to evaluate policies",
            )
                .into_response();
        }
    };

    Json(evaluation_result).into_response()
}

// --- ROLE HIERARCHY HANDLERS ---

#[axum::debug_handler]
#[utoipa::path(
    put,
    path = "/v1/iam/roles/{role_id}/parent",
    request_body = SetParentRoleRequest,
    responses(
        (status = 200, description = "Parent role set successfully"),
        (status = 400, description = "Invalid request or circular reference", body = ErrorResponse),
        (status = 403, description = "Insufficient permissions", body = ErrorResponse),
        (status = 404, description = "Role not found", body = ErrorResponse),
    ),
    tags = ["RBAC"],
    description = "Set or remove the parent role for a role. Requires rbac:manage permission."
)]
pub async fn set_parent_role_handler(
    State(state): State<Arc<AppState>>,
    RequirePermission { user_id }: RequirePermission,
    Path(role_id): Path<String>,
    Json(payload): Json<SetParentRoleRequest>,
) -> impl IntoResponse {
    let allowed = state
        .authz_service
        .user_has_permission(&user_id, "rbac:manage", None)
        .await
        .unwrap_or(false);
    if !allowed {
        return (
            axum::http::StatusCode::FORBIDDEN,
            "Insufficient permissions",
        )
            .into_response();
    }

    match state
        .role_repo
        .set_parent_role(&role_id, payload.parent_role_id.as_deref())
        .await
    {
        Ok(_) => axum::http::StatusCode::OK.into_response(),
        Err(e) => {
            let error_msg = e.to_string();
            if error_msg.contains("Circular reference") || error_msg.contains("circular") {
                (
                    axum::http::StatusCode::BAD_REQUEST,
                    Json(ErrorResponse {
                        error: "Circular reference detected".to_string(),
                    }),
                )
                    .into_response()
            } else if error_msg.contains("not found") {
                (
                    axum::http::StatusCode::NOT_FOUND,
                    Json(ErrorResponse {
                        error: "Role not found".to_string(),
                    }),
                )
                    .into_response()
            } else {
                (
                    axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ErrorResponse {
                        error: "Failed to set parent role".to_string(),
                    }),
                )
                    .into_response()
            }
        }
    }
}

#[axum::debug_handler]
#[utoipa::path(
    get,
    path = "/v1/iam/roles/{role_id}/hierarchy",
    responses(
        (status = 200, description = "Role hierarchy retrieved", body = RoleHierarchyResponse),
        (status = 403, description = "Insufficient permissions", body = ErrorResponse),
        (status = 404, description = "Role not found", body = ErrorResponse),
    ),
    tags = ["RBAC"],
    description = "Get the role hierarchy including parent and inherited roles. Requires rbac:read permission."
)]
pub async fn get_role_hierarchy_handler(
    State(state): State<Arc<AppState>>,
    RequirePermission { user_id }: RequirePermission,
    Path(role_id): Path<String>,
) -> impl IntoResponse {
    let allowed = state
        .authz_service
        .user_has_permission(&user_id, "rbac:read", None)
        .await
        .unwrap_or(false);
    if !allowed {
        return (
            axum::http::StatusCode::FORBIDDEN,
            "Insufficient permissions",
        )
            .into_response();
    }

    // Get the role details
    let roles = state.role_repo.list_roles().await;
    let role = roles.iter().find(|r| r.id == role_id);

    if role.is_none() {
        return (
            axum::http::StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "Role not found".to_string(),
            }),
        )
            .into_response();
    }

    let role = role.unwrap();

    // Get inherited roles
    let inherited_roles = match state.role_repo.get_inherited_roles(&role_id).await {
        Ok(roles) => roles,
        Err(_) => {
            return (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Failed to get inherited roles".to_string(),
                }),
            )
                .into_response();
        }
    };

    // Get parent role name if exists
    let parent_role_name = if let Some(parent_id) = &role.parent_role_id {
        roles
            .iter()
            .find(|r| r.id == *parent_id)
            .map(|r| r.name.clone())
    } else {
        None
    };

    // Convert inherited roles to RoleResponse
    let inherited_role_responses: Vec<RoleResponse> = inherited_roles
        .into_iter()
        .map(|r| RoleResponse {
            id: r.id,
            name: r.name,
            permissions: r.permissions,
            parent_role_id: r.parent_role_id,
        })
        .collect();

    let response = RoleHierarchyResponse {
        role_id: role.id.clone(),
        role_name: role.name.clone(),
        parent_role_id: role.parent_role_id.clone(),
        parent_role_name,
        inherited_roles: inherited_role_responses,
    };

    Json(response).into_response()
}

#[axum::debug_handler]
#[utoipa::path(
    get,
    path = "/v1/iam/roles/hierarchies",
    responses(
        (status = 200, description = "All role hierarchies retrieved", body = RoleHierarchyListResponse),
        (status = 403, description = "Insufficient permissions", body = ErrorResponse),
    ),
    tags = ["RBAC"],
    description = "Get all role hierarchies. Requires rbac:read permission."
)]
pub async fn list_role_hierarchies_handler(
    State(state): State<Arc<AppState>>,
    RequirePermission { user_id }: RequirePermission,
) -> impl IntoResponse {
    let allowed = state
        .authz_service
        .user_has_permission(&user_id, "rbac:read", None)
        .await
        .unwrap_or(false);
    if !allowed {
        return (
            axum::http::StatusCode::FORBIDDEN,
            "Insufficient permissions",
        )
            .into_response();
    }

    let roles = state.role_repo.list_roles().await;
    let mut hierarchies = Vec::new();

    for role in &roles {
        let inherited_roles = match state.role_repo.get_inherited_roles(&role.id).await {
            Ok(roles) => roles,
            Err(_) => continue, // Skip this role if we can't get inherited roles
        };

        let parent_role_name = if let Some(parent_id) = &role.parent_role_id {
            roles
                .iter()
                .find(|r| r.id == *parent_id)
                .map(|r| r.name.clone())
        } else {
            None
        };

        let inherited_role_responses: Vec<RoleResponse> = inherited_roles
            .into_iter()
            .map(|r| RoleResponse {
                id: r.id,
                name: r.name,
                permissions: r.permissions,
                parent_role_id: r.parent_role_id,
            })
            .collect();

        hierarchies.push(RoleHierarchyResponse {
            role_id: role.id.clone(),
            role_name: role.name.clone(),
            parent_role_id: role.parent_role_id.clone(),
            parent_role_name,
            inherited_roles: inherited_role_responses,
        });
    }

    Json(RoleHierarchyListResponse { hierarchies }).into_response()
}

// --- USER MANAGEMENT HANDLERS ---

#[axum::debug_handler]
#[utoipa::path(
    post,
    path = "/v1/iam/auth/register",
    request_body = UserRegistrationRequest,
    responses(
        (status = 201, description = "User registered successfully", body = UserRegistrationResponse),
        (status = 400, description = "Invalid request data", body = ErrorResponse),
        (status = 409, description = "User already exists", body = ErrorResponse),
    ),
    tags = ["Auth"],
    description = "Register a new user account."
)]
pub async fn register_user_handler(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<UserRegistrationRequest>,
) -> impl IntoResponse {
    // Check if user already exists
    if let Some(_existing_user) = state.user_repo.find_by_email(&payload.email).await {
        return (
            axum::http::StatusCode::CONFLICT,
            Json(ErrorResponse {
                error: "User with this email already exists".to_string(),
            }),
        )
            .into_response();
    }

    // Create new user
    let user_id = uuid::Uuid::new_v4().to_string();
    let password_hash = match bcrypt::hash(&payload.password, bcrypt::DEFAULT_COST) {
        Ok(hash) => hash,
        Err(_) => {
            return (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Failed to hash password".to_string(),
                }),
            )
                .into_response();
        }
    };

    let user = crate::domain::user::User::new(user_id, payload.email.clone(), password_hash);

    // Store user in database
    let created_user = match state.user_repo.create_user(user).await {
        Ok(user) => user,
        Err(_) => {
            return (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Failed to create user".to_string(),
                }),
            )
                .into_response();
        }
    };

    let response = UserRegistrationResponse {
        user_id: created_user.id.clone(),
        email: created_user.email.clone(),
        message: "User registered successfully".to_string(),
    };

    (axum::http::StatusCode::CREATED, Json(response)).into_response()
}

#[axum::debug_handler]
#[utoipa::path(
    post,
    path = "/v1/iam/auth/password-change",
    request_body = PasswordChangeRequest,
    responses(
        (status = 204, description = "Password changed successfully"),
        (status = 400, description = "Invalid current password or weak new password", body = ErrorResponse),
        (status = 401, description = "Unauthorized", body = ErrorResponse),
    ),
    tags = ["Auth"],
    description = "Change user password. Requires authentication."
)]
pub async fn change_password_handler(
    State(state): State<Arc<AppState>>,
    _auth: AuthenticatedUser,
    RequirePermission { user_id }: RequirePermission,
    Json(payload): Json<PasswordChangeRequest>,
) -> impl IntoResponse {
    // Get user from database
    let user = match state.user_repo.find_by_email(&user_id).await {
        Some(user) => user,
        None => {
            return (
                axum::http::StatusCode::NOT_FOUND,
                Json(ErrorResponse {
                    error: "User not found".to_string(),
                }),
            )
                .into_response();
        }
    };

    // Verify current password
    if !state
        .password_service
        .verify(&user, &payload.current_password)
    {
        return (
            axum::http::StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Invalid current password".to_string(),
            }),
        )
            .into_response();
    }

    // Validate new password strength (basic validation)
    if payload.new_password.len() < 8 {
        return (
            axum::http::StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "New password must be at least 8 characters long".to_string(),
            }),
        )
            .into_response();
    }

    // Hash the new password
    let new_password_hash = match bcrypt::hash(&payload.new_password, bcrypt::DEFAULT_COST) {
        Ok(hash) => hash,
        Err(_) => {
            return (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Failed to hash new password".to_string(),
                }),
            )
                .into_response();
        }
    };

    // Update the user's password in the database
    if state
        .user_repo
        .update_password(&user.id, &new_password_hash)
        .await
        .is_err()
    {
        return (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Failed to update password".to_string(),
            }),
        )
            .into_response();
    }

    // TODO: Revoke all existing refresh tokens for the user
    // TODO: Log the password change event

    axum::http::StatusCode::NO_CONTENT.into_response()
}

#[axum::debug_handler]
#[utoipa::path(
    post,
    path = "/v1/iam/auth/password-reset",
    request_body = PasswordResetRequest,
    responses(
        (status = 200, description = "Password reset email sent", body = PasswordResetResponse),
        (status = 404, description = "User not found", body = ErrorResponse),
    ),
    tags = ["Auth"],
    description = "Request a password reset email."
)]
pub async fn request_password_reset_handler(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<PasswordResetRequest>,
) -> impl IntoResponse {
    // Check if user exists
    if state
        .user_repo
        .find_by_email(&payload.email)
        .await
        .is_none()
    {
        return (
            axum::http::StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "User not found".to_string(),
            }),
        )
            .into_response();
    }

    // Generate reset token (this would need to be implemented)
    // In a real implementation, you would:
    // 1. Generate a secure reset token
    // 2. Store it in the database with expiration
    // 3. Send an email with the reset link
    // 4. Log the password reset request

    let response = PasswordResetResponse {
        message: "If a user with this email exists, a password reset link has been sent"
            .to_string(),
    };

    Json(response).into_response()
}

#[axum::debug_handler]
#[utoipa::path(
    post,
    path = "/v1/iam/auth/password-reset-confirm",
    request_body = PasswordResetConfirmRequest,
    responses(
        (status = 204, description = "Password reset successfully"),
        (status = 400, description = "Invalid or expired reset token", body = ErrorResponse),
    ),
    tags = ["Auth"],
    description = "Confirm password reset with token."
)]
pub async fn confirm_password_reset_handler(
    State(_state): State<Arc<AppState>>,
    Json(_payload): Json<PasswordResetConfirmRequest>,
) -> impl IntoResponse {
    // Validate reset token and get user (this would need to be implemented)
    // In a real implementation, you would:
    // 1. Validate the reset token
    // 2. Check if it's expired
    // 3. Get the associated user
    // 4. Update the password
    // 5. Revoke all existing refresh tokens
    // 6. Delete the reset token
    // 7. Log the password reset

    // For now, we'll just return success
    axum::http::StatusCode::NO_CONTENT.into_response()
}

#[axum::debug_handler]
#[utoipa::path(
    post,
    path = "/v1/iam/permission-groups",
    request_body = CreatePermissionGroupRequest,
    responses(
        (status = 201, description = "Permission group created successfully", body = PermissionGroupResponse),
        (status = 400, description = "Invalid request", body = ErrorResponse),
        (status = 401, description = "Unauthorized", body = ErrorResponse),
    ),
    tags = ["Permission Groups"],
    description = "Create a new permission group."
)]
pub async fn create_permission_group_handler(
    State(state): State<Arc<AppState>>,
    RequirePermission { user_id: _ }: RequirePermission,
    Json(payload): Json<CreatePermissionGroupRequest>,
) -> impl IntoResponse {
    let group_id = uuid::Uuid::new_v4().to_string();

    let mut group = crate::domain::permission_group::PermissionGroup::new(group_id, payload.name);

    if let Some(description) = payload.description {
        group = group.with_description(description);
    }

    if let Some(category) = payload.category {
        group = group.with_category(category);
    }

    if let Some(metadata) = payload.metadata {
        group = group.with_metadata(metadata);
    }

    match state.permission_group_repo.create_group(group).await {
        Ok(created_group) => {
            let response = PermissionGroupResponse {
                id: created_group.id,
                name: created_group.name,
                description: created_group.description,
                category: created_group.category,
                metadata: created_group.metadata,
                is_active: created_group.is_active,
                permission_count: 0, // Will be calculated separately if needed
            };

            (axum::http::StatusCode::CREATED, Json(response)).into_response()
        }
        Err(_) => (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Failed to create permission group".to_string(),
            }),
        )
            .into_response(),
    }
}

#[axum::debug_handler]
#[utoipa::path(
    get,
    path = "/v1/iam/permission-groups",
    responses(
        (status = 200, description = "List of permission groups", body = PermissionGroupListResponse),
        (status = 401, description = "Unauthorized", body = ErrorResponse),
    ),
    tags = ["Permission Groups"],
    description = "List all permission groups."
)]
pub async fn list_permission_groups_handler(
    State(state): State<Arc<AppState>>,
    RequirePermission { user_id: _ }: RequirePermission,
) -> impl IntoResponse {
    match state.permission_group_repo.list_groups().await {
        Ok(groups) => {
            let group_responses: Vec<PermissionGroupResponse> = groups
                .into_iter()
                .map(|group| PermissionGroupResponse {
                    id: group.id,
                    name: group.name,
                    description: group.description,
                    category: group.category,
                    metadata: group.metadata,
                    is_active: group.is_active,
                    permission_count: 0, // TODO: Calculate actual permission count
                })
                .collect();

            let total = group_responses.len();
            let response = PermissionGroupListResponse {
                groups: group_responses,
                total,
            };

            Json(response).into_response()
        }
        Err(_) => (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Failed to list permission groups".to_string(),
            }),
        )
            .into_response(),
    }
}

#[axum::debug_handler]
#[utoipa::path(
    get,
    path = "/v1/iam/permission-groups/{group_id}",
    responses(
        (status = 200, description = "Permission group details", body = PermissionGroupResponse),
        (status = 404, description = "Permission group not found", body = ErrorResponse),
        (status = 401, description = "Unauthorized", body = ErrorResponse),
    ),
    tags = ["Permission Groups"],
    description = "Get permission group details."
)]
pub async fn get_permission_group_handler(
    State(state): State<Arc<AppState>>,
    RequirePermission { user_id: _ }: RequirePermission,
    Path(group_id): Path<String>,
) -> impl IntoResponse {
    match state.permission_group_repo.get_group(&group_id).await {
        Ok(Some(group)) => {
            let response = PermissionGroupResponse {
                id: group.id,
                name: group.name,
                description: group.description,
                category: group.category,
                metadata: group.metadata,
                is_active: group.is_active,
                permission_count: 0, // TODO: Calculate actual permission count
            };

            Json(response).into_response()
        }
        Ok(None) => (
            axum::http::StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "Permission group not found".to_string(),
            }),
        )
            .into_response(),
        Err(_) => (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Failed to get permission group".to_string(),
            }),
        )
            .into_response(),
    }
}

#[axum::debug_handler]
#[utoipa::path(
    put,
    path = "/v1/iam/permission-groups/{group_id}",
    request_body = UpdatePermissionGroupRequest,
    responses(
        (status = 200, description = "Permission group updated successfully", body = PermissionGroupResponse),
        (status = 404, description = "Permission group not found", body = ErrorResponse),
        (status = 400, description = "Invalid request", body = ErrorResponse),
        (status = 401, description = "Unauthorized", body = ErrorResponse),
    ),
    tags = ["Permission Groups"],
    description = "Update permission group."
)]
pub async fn update_permission_group_handler(
    State(state): State<Arc<AppState>>,
    RequirePermission { user_id: _ }: RequirePermission,
    Path(group_id): Path<String>,
    Json(payload): Json<UpdatePermissionGroupRequest>,
) -> impl IntoResponse {
    // First get the existing group
    let existing_group = match state.permission_group_repo.get_group(&group_id).await {
        Ok(Some(group)) => group,
        Ok(None) => {
            return (
                axum::http::StatusCode::NOT_FOUND,
                Json(ErrorResponse {
                    error: "Permission group not found".to_string(),
                }),
            )
                .into_response();
        }
        Err(_) => {
            return (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Failed to get permission group".to_string(),
                }),
            )
                .into_response();
        }
    };

    // Update the group with new values
    let mut updated_group = existing_group;

    if let Some(name) = payload.name {
        updated_group.name = name;
    }

    if let Some(description) = payload.description {
        updated_group.description = Some(description);
    }

    if let Some(category) = payload.category {
        updated_group.category = Some(category);
    }

    if let Some(metadata) = payload.metadata {
        updated_group.metadata = metadata;
    }

    if let Some(is_active) = payload.is_active {
        updated_group.set_active_status(is_active);
    }

    // Save the updated group
    match state
        .permission_group_repo
        .update_group(&updated_group)
        .await
    {
        Ok(_) => {
            let response = PermissionGroupResponse {
                id: updated_group.id,
                name: updated_group.name,
                description: updated_group.description,
                category: updated_group.category,
                metadata: updated_group.metadata,
                is_active: updated_group.is_active,
                permission_count: 0, // TODO: Calculate actual permission count
            };

            Json(response).into_response()
        }
        Err(_) => (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Failed to update permission group".to_string(),
            }),
        )
            .into_response(),
    }
}

#[axum::debug_handler]
#[utoipa::path(
    delete,
    path = "/v1/iam/permission-groups/{group_id}",
    responses(
        (status = 204, description = "Permission group deleted successfully"),
        (status = 404, description = "Permission group not found", body = ErrorResponse),
        (status = 401, description = "Unauthorized", body = ErrorResponse),
    ),
    tags = ["Permission Groups"],
    description = "Delete permission group."
)]
pub async fn delete_permission_group_handler(
    State(state): State<Arc<AppState>>,
    RequirePermission { user_id: _ }: RequirePermission,
    Path(group_id): Path<String>,
) -> impl IntoResponse {
    match state.permission_group_repo.delete_group(&group_id).await {
        Ok(_) => axum::http::StatusCode::NO_CONTENT.into_response(),
        Err(_) => (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Failed to delete permission group".to_string(),
            }),
        )
            .into_response(),
    }
}

#[axum::debug_handler]
#[utoipa::path(
    get,
    path = "/v1/iam/permission-groups/{group_id}/permissions",
    responses(
        (status = 200, description = "List of permissions in group", body = PermissionsListResponse),
        (status = 404, description = "Permission group not found", body = ErrorResponse),
        (status = 401, description = "Unauthorized", body = ErrorResponse),
    ),
    tags = ["Permission Groups"],
    description = "Get permissions in a group."
)]
pub async fn get_permissions_in_group_handler(
    State(state): State<Arc<AppState>>,
    RequirePermission { user_id: _ }: RequirePermission,
    Path(group_id): Path<String>,
) -> impl IntoResponse {
    match state
        .permission_group_repo
        .get_permissions_in_group(&group_id)
        .await
    {
        Ok(permissions) => {
            let permission_responses: Vec<PermissionResponse> = permissions
                .into_iter()
                .map(|perm| PermissionResponse {
                    id: perm.id,
                    name: perm.name,
                })
                .collect();

            let response = PermissionsListResponse {
                permissions: permission_responses,
            };

            Json(response).into_response()
        }
        Err(_) => (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Failed to get permissions in group".to_string(),
            }),
        )
            .into_response(),
    }
}
