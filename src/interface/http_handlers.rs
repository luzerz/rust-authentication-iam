use crate::application::services::Claims;
use crate::interface::app_state::AppState;
use crate::test_utils::{create_admin_test_user, create_test_app_state_with_comprehensive_data, generate_valid_token, setup_test_env};
use axum::extract::{FromRequestParts, State};
use axum::http::{StatusCode, request::Parts};
use axum::response::IntoResponse;

use crate::interface::{
    AbacConditionDto, AbacEvaluationRequest, AbacEvaluationResponse, AbacPolicyListResponse,
    AbacPolicyRequest, AbacPolicyResponse, AssignAbacPolicyRequest, AssignPermissionRequest,
    AssignRoleRequest, CreatePermissionGroupRequest, CreatePermissionRequest,
    CreateRoleHierarchyRequest, CreateRoleRequest, EffectivePermissionsResponse, ErrorResponse,
    LoginRequest, LoginResponse, LogoutRequest, LogoutResponse, PasswordChangeRequest,
    PasswordResetConfirmRequest, PasswordResetRequest, PasswordResetResponse,
    PermissionGroupListResponse, PermissionGroupResponse, PermissionResponse,
    PermissionsListResponse, RefreshTokenRequest, RefreshTokenResponse, RemovePermissionRequest,
    RemoveRoleRequest, RoleHierarchyListResponse, RoleHierarchyResponse, RolePermissionsResponse,
    RoleResponse, RolesListResponse, SetParentRoleRequest, UpdateAbacPolicyRequest,
    UpdatePermissionGroupRequest, UpdatePermissionRequest, UpdateRoleRequest,
    UserRegistrationRequest, UserRegistrationResponse, UserRolesResponse, ValidateTokenRequest,
    ValidateTokenResponse,
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
            roles: vec![], // Roles are no longer stored in Claims
            claims,
        })
    }
}

// --- AUTH HANDLERS ---

#[axum::debug_handler]
#[utoipa::path(
    post,
    path = "/v1/iam/login",
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
    let cmd = crate::application::commands::CommandFactory::authenticate_user(
        payload.email,
        payload.password,
        None, // ip_address - could be extracted from request
        None, // user_agent - could be extracted from request
    );

    let result = state.command_bus.execute(cmd).await;

    match result {
        Ok(result_box) => {
            if let Ok(user) = result_box.downcast::<crate::domain::user::User>() {
                let (access_token, refresh_token) = state
                    .token_service
                    .issue_tokens(&user, &state.refresh_token_repo)
                    .await
                    .unwrap_or_else(|_| {
                        panic!("Failed to issue tokens for authenticated user");
                    });

                Json(LoginResponse {
                    access_token,
                    refresh_token,
                })
                .into_response()
            } else {
                (
                    axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                    "Invalid result type from authenticate user command",
                )
                    .into_response()
            }
        }
        Err(e) => {
            let (status_code, error_message) =
                if let Ok(auth_error) = e.downcast::<crate::application::services::AuthError>() {
                    match *auth_error {
                        crate::application::services::AuthError::UserNotFound => (
                            axum::http::StatusCode::UNAUTHORIZED,
                            "Invalid credentials".to_string(),
                        ),
                        crate::application::services::AuthError::InvalidCredentials => (
                            axum::http::StatusCode::UNAUTHORIZED,
                            "Invalid credentials".to_string(),
                        ),
                        crate::application::services::AuthError::AccountLocked => (
                            axum::http::StatusCode::FORBIDDEN,
                            "Account is locked".to_string(),
                        ),
                        _ => (
                            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                            format!("Login failed: {auth_error:?}"),
                        ),
                    }
                } else {
                    (
                        axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                        "Login failed".to_string(),
                    )
                };
            (
                status_code,
                Json(ErrorResponse {
                    error: error_message,
                }),
            )
                .into_response()
        }
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
        .query_bus
        .execute(crate::application::queries::QueryFactory::check_permission(
            requesting_user.clone(),
            "rbac:read".to_string(),
            None,
        ))
        .await
        .map(|result| result.downcast::<bool>().map(|b| *b).unwrap_or(false))
        .unwrap_or(false);
    if !allowed {
        return (
            axum::http::StatusCode::FORBIDDEN,
            "Insufficient permissions",
        )
            .into_response();
    }

    let query = crate::application::queries::QueryFactory::get_role_permissions(role_id);

    let result = state.query_bus.execute(query).await;

    match result {
        Ok(result_box) => {
            if let Ok(result_box) = result_box.downcast::<RolePermissionsResponse>() {
                let response = *result_box;
                Json(response).into_response()
            } else {
                (
                    axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                    "Invalid result type from get role permissions query",
                )
                    .into_response()
            }
        }
        Err(_) => (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to get role permissions",
        )
            .into_response(),
    }
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
        .query_bus
        .execute(crate::application::queries::QueryFactory::check_permission(
            requesting_user.clone(),
            "rbac:read".to_string(),
            None,
        ))
        .await
        .map(|result| result.downcast::<bool>().map(|b| *b).unwrap_or(false))
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
        .query_bus
        .execute(crate::application::queries::QueryFactory::check_permission(
            requesting_user.clone(),
            "rbac:read".to_string(),
            None,
        ))
        .await
        .map(|result| result.downcast::<bool>().map(|b| *b).unwrap_or(false))
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
    let cmd = crate::application::commands::CommandFactory::validate_token(payload.token);

    let result = state.command_bus.execute(cmd).await;

    match result {
        Ok(result_box) => {
            if let Ok(result_box) = result_box.downcast::<crate::application::services::Claims>() {
                let claims = *result_box;
                Json(ValidateTokenResponse {
                    valid: true,
                    user_id: claims.sub,
                    roles: vec![], // Roles are no longer stored in Claims
                })
                .into_response()
            } else {
                (
                    axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                    "Invalid result type from validate token command",
                )
                    .into_response()
            }
        }
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
    // First validate the token to get user_id
    let validate_cmd =
        crate::application::commands::CommandFactory::validate_token(payload.refresh_token.clone());
    let validate_result = state.command_bus.execute(validate_cmd).await;

    match validate_result {
        Ok(claims_box) => {
            if let Ok(claims_box) = claims_box.downcast::<crate::application::services::Claims>() {
                let claims = *claims_box;
                let user_id = claims.sub;

                let refresh_cmd = crate::application::commands::CommandFactory::refresh_token(
                    payload.refresh_token.clone(),
                    user_id,
                );
                let refresh_result = state.command_bus.execute(refresh_cmd).await;

                match refresh_result {
                    Ok(access_token_box) => {
                        if let Ok(access_token_box) = access_token_box.downcast::<String>() {
                            let access_token = *access_token_box;
                            Json(RefreshTokenResponse {
                                access_token,
                                refresh_token: payload.refresh_token,
                            })
                            .into_response()
                        } else {
                            (
                                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                                "Invalid result type from refresh token command",
                            )
                                .into_response()
                        }
                    }
                    Err(_) => (
                        axum::http::StatusCode::UNAUTHORIZED,
                        "Invalid refresh token",
                    )
                        .into_response(),
                }
            } else {
                (
                    axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                    "Invalid result type from validate token command",
                )
                    .into_response()
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
    // First validate the token to get user_id
    let validate_cmd =
        crate::application::commands::CommandFactory::validate_token(payload.refresh_token.clone());
    let validate_result = state.command_bus.execute(validate_cmd).await;

    match validate_result {
        Ok(claims_box) => {
            if let Ok(claims_box) = claims_box.downcast::<crate::application::services::Claims>() {
                let claims = *claims_box;
                let user_id = claims.sub;

                let logout_cmd = crate::application::commands::CommandFactory::logout(
                    payload.refresh_token,
                    user_id,
                );
                let logout_result = state.command_bus.execute(logout_cmd).await;

                match logout_result {
                    Ok(_) => Json(LogoutResponse { success: true }).into_response(),
                    Err(_) => (
                        axum::http::StatusCode::UNAUTHORIZED,
                        "Invalid refresh token",
                    )
                        .into_response(),
                }
            } else {
                (
                    axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                    "Invalid result type from validate token command",
                )
                    .into_response()
            }
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
        .query_bus
        .execute(crate::application::queries::QueryFactory::check_permission(
            user_id.clone(),
            "rbac:manage".to_string(),
            None,
        ))
        .await
        .map(|result| result.downcast::<bool>().map(|b| *b).unwrap_or(false))
        .unwrap_or(false);
    if !allowed {
        return (
            axum::http::StatusCode::FORBIDDEN,
            "Insufficient permissions",
        )
            .into_response();
    }
    let cmd = crate::application::commands::CommandFactory::create_role(
        payload.name,
        None,                  // description
        None,                  // parent_role_id
        Some(user_id.clone()), // created_by
    );

    let result = state.command_bus.execute(cmd).await;

    match result {
        Ok(result_box) => {
            if let Ok(result_box) = result_box.downcast::<crate::domain::role::Role>() {
                let role = *result_box;
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
            } else {
                (
                    axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                    "Invalid result type from create role command",
                )
                    .into_response()
            }
        }
        Err(e) => (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to create role: {e:?}"),
        )
            .into_response(),
    }
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
    let query = crate::application::queries::QueryFactory::list_roles(
        1,     // page
        100,   // page_size (large enough for now)
        None,  // name_filter
        false, // include_permissions
        None,  // sort_by
        None,  // sort_order
    );

    let result = state.query_bus.execute(query).await;

    match result {
        Ok(result_box) => {
            if let Ok(result_box) = result_box
                .downcast::<crate::application::queries::PaginatedResult<
                    crate::application::queries::RoleReadModel,
                >>()
            {
                let paginated_result = *result_box;
                let roles: Vec<RoleResponse> = paginated_result
                    .items
                    .into_iter()
                    .map(|role| RoleResponse {
                        id: role.id,
                        name: role.name,
                        permissions: vec![],  // TODO: Get from role model
                        parent_role_id: None, // TODO: Get from role model
                    })
                    .collect();

                Json(RolesListResponse { roles }).into_response()
            } else {
                (
                    axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                    "Invalid result type from list roles query",
                )
                    .into_response()
            }
        }
        Err(_) => (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to list roles",
        )
            .into_response(),
    }
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
        .query_bus
        .execute(crate::application::queries::QueryFactory::check_permission(
            user_id.clone(),
            "rbac:manage".to_string(),
            None,
        ))
        .await
        .map(|result| result.downcast::<bool>().map(|b| *b).unwrap_or(false))
        .unwrap_or(false);
    if !allowed {
        return (
            axum::http::StatusCode::FORBIDDEN,
            "Insufficient permissions",
        )
            .into_response();
    }
    let cmd = crate::application::commands::CommandFactory::delete_role(
        role_id.clone(),
        Some(user_id.clone()), // deleted_by
    );

    let result = state.command_bus.execute(cmd).await;

    match result {
        Ok(_) => axum::http::StatusCode::NO_CONTENT.into_response(),
        Err(e) => (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to delete role: {e:?}"),
        )
            .into_response(),
    }
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
        .query_bus
        .execute(crate::application::queries::QueryFactory::check_permission(
            user_id.clone(),
            "rbac:manage".to_string(),
            None,
        ))
        .await
        .map(|result| result.downcast::<bool>().map(|b| *b).unwrap_or(false))
        .unwrap_or(false);
    if !allowed {
        return (
            axum::http::StatusCode::FORBIDDEN,
            "Insufficient permissions",
        )
            .into_response();
    }

    let cmd = crate::application::commands::CommandFactory::assign_roles(
        payload.user_id,
        vec![payload.role_id],
        Some(user_id),
    );

    let result = state.command_bus.execute(cmd).await;

    match result {
        Ok(_) => axum::http::StatusCode::OK.into_response(),
        Err(e) => (
            axum::http::StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: format!("Role assignment failed: {e:?}"),
            }),
        )
            .into_response(),
    }
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
        .query_bus
        .execute(crate::application::queries::QueryFactory::check_permission(
            user_id.clone(),
            "rbac:manage".to_string(),
            None,
        ))
        .await
        .map(|result| result.downcast::<bool>().map(|b| *b).unwrap_or(false))
        .unwrap_or(false);
    if !allowed {
        return (
            axum::http::StatusCode::FORBIDDEN,
            "Insufficient permissions",
        )
            .into_response();
    }
    let cmd = crate::application::commands::CommandFactory::remove_roles_from_user(
        payload.user_id.clone(),
        vec![payload.role_id.clone()],
        Some(user_id.clone()), // removed_by
    );

    let result = state.command_bus.execute(cmd).await;

    match result {
        Ok(_) => axum::http::StatusCode::OK.into_response(),
        Err(e) => (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to remove role: {e:?}"),
        )
            .into_response(),
    }
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
        .query_bus
        .execute(crate::application::queries::QueryFactory::check_permission(
            user_id.clone(),
            "rbac:manage".to_string(),
            None,
        ))
        .await
        .map(|result| result.downcast::<bool>().map(|b| *b).unwrap_or(false))
        .unwrap_or(false);
    if !allowed {
        return (
            axum::http::StatusCode::FORBIDDEN,
            "Insufficient permissions",
        )
            .into_response();
    }
    let cmd = crate::application::commands::CommandFactory::create_permission(
        payload.name.clone(),
        None,                  // description
        None,                  // group_id
        Some(user_id.clone()), // created_by
    );

    let result = state.command_bus.execute(cmd).await;

    match result {
        Ok(result_box) => {
            if let Ok(result_box) = result_box.downcast::<crate::domain::permission::Permission>() {
                let perm = *result_box;
                (
                    axum::http::StatusCode::CREATED,
                    Json(PermissionResponse {
                        id: perm.id,
                        name: perm.name,
                    }),
                )
                    .into_response()
            } else {
                (
                    axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                    "Invalid result type from create permission command",
                )
                    .into_response()
            }
        }
        Err(e) => (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to create permission: {e:?}"),
        )
            .into_response(),
    }
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
    let query = crate::application::queries::QueryFactory::list_permissions(
        1,    // page
        100,  // page_size (large enough for now)
        None, // name_filter
        None, // group_filter
        None, // sort_by
        None, // sort_order
    );

    let result = state.query_bus.execute(query).await;

    match result {
        Ok(result_box) => {
            if let Ok(result_box) = result_box
                .downcast::<crate::application::queries::PaginatedResult<
                    crate::application::queries::PermissionReadModel,
                >>()
            {
                let paginated_result = *result_box;
                let permissions: Vec<PermissionResponse> = paginated_result
                    .items
                    .into_iter()
                    .map(|p| PermissionResponse {
                        id: p.id,
                        name: p.name,
                    })
                    .collect();

                Json(PermissionsListResponse { permissions }).into_response()
            } else {
                (
                    axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                    "Invalid result type from list permissions query",
                )
                    .into_response()
            }
        }
        Err(_) => (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to list permissions",
        )
            .into_response(),
    }
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
        .query_bus
        .execute(crate::application::queries::QueryFactory::check_permission(
            user_id.clone(),
            "rbac:manage".to_string(),
            None,
        ))
        .await
        .map(|result| result.downcast::<bool>().map(|b| *b).unwrap_or(false))
        .unwrap_or(false);
    if !allowed {
        return (
            axum::http::StatusCode::FORBIDDEN,
            "Insufficient permissions",
        )
            .into_response();
    }
    let cmd = crate::application::commands::CommandFactory::delete_permission(
        permission_id.clone(),
        Some(user_id.clone()), // deleted_by
    );

    let result = state.command_bus.execute(cmd).await;

    match result {
        Ok(_) => axum::http::StatusCode::NO_CONTENT.into_response(),
        Err(e) => (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to delete permission: {e:?}"),
        )
            .into_response(),
    }
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
        .query_bus
        .execute(crate::application::queries::QueryFactory::check_permission(
            user_id.clone(),
            "rbac:manage".to_string(),
            None,
        ))
        .await
        .map(|result| result.downcast::<bool>().map(|b| *b).unwrap_or(false))
        .unwrap_or(false);
    if !allowed {
        return (
            axum::http::StatusCode::FORBIDDEN,
            "Insufficient permissions",
        )
            .into_response();
    }
    let cmd = crate::application::commands::CommandFactory::assign_permissions_to_role(
        payload.role_id.clone(),
        vec![payload.permission_id.clone()],
        Some(user_id.clone()), // assigned_by
    );

    let result = state.command_bus.execute(cmd).await;

    match result {
        Ok(_) => axum::http::StatusCode::OK.into_response(),
        Err(e) => (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to assign permission: {e:?}"),
        )
            .into_response(),
    }
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
        .query_bus
        .execute(crate::application::queries::QueryFactory::check_permission(
            user_id.clone(),
            "rbac:manage".to_string(),
            None,
        ))
        .await
        .map(|result| result.downcast::<bool>().map(|b| *b).unwrap_or(false))
        .unwrap_or(false);
    if !allowed {
        return (
            axum::http::StatusCode::FORBIDDEN,
            "Insufficient permissions",
        )
            .into_response();
    }
    let cmd = crate::application::commands::CommandFactory::remove_permissions_from_role(
        payload.role_id.clone(),
        vec![payload.permission_id.clone()],
        Some(user_id.clone()), // removed_by
    );

    let result = state.command_bus.execute(cmd).await;

    match result {
        Ok(_) => axum::http::StatusCode::OK.into_response(),
        Err(e) => (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to remove permission: {e:?}"),
        )
            .into_response(),
    }
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
        .query_bus
        .execute(crate::application::queries::QueryFactory::check_permission(
            user_id.clone(),
            "rbac:manage".to_string(),
            None,
        ))
        .await
        .map(|result| result.downcast::<bool>().map(|b| *b).unwrap_or(false))
        .unwrap_or(false);
    if !allowed {
        return (
            axum::http::StatusCode::FORBIDDEN,
            "Insufficient permissions",
        )
            .into_response();
    }
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

    let cmd = crate::application::commands::CommandFactory::create_abac_policy(
        payload.name,
        None, // description
        match effect {
            crate::domain::abac_policy::AbacEffect::Allow => "Allow".to_string(),
            crate::domain::abac_policy::AbacEffect::Deny => "Deny".to_string(),
        },
        conditions,
        payload.priority.unwrap_or(50),
        Some(user_id.clone()), // created_by
    );

    let result = state.command_bus.execute(cmd).await;

    match result {
        Ok(result_box) => {
            if let Ok(result_box) = result_box.downcast::<crate::domain::abac_policy::AbacPolicy>()
            {
                let created = *result_box;
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
                    conflict_resolution: match created.conflict_resolution.as_ref().unwrap_or(
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
                };
                (axum::http::StatusCode::CREATED, Json(resp)).into_response()
            } else {
                (
                    axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                    "Invalid result type from create ABAC policy command",
                )
                    .into_response()
            }
        }
        Err(e) => (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to create ABAC policy: {e:?}"),
        )
            .into_response(),
    }
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
        .query_bus
        .execute(crate::application::queries::QueryFactory::check_permission(
            user_id.clone(),
            "rbac:manage".to_string(),
            None,
        ))
        .await
        .map(|result| result.downcast::<bool>().map(|b| *b).unwrap_or(false))
        .unwrap_or(false);
    if !allowed {
        return (
            axum::http::StatusCode::FORBIDDEN,
            "Insufficient permissions",
        )
            .into_response();
    }

    let cmd = crate::application::commands::CommandFactory::update_abac_policy(
        policy_id.clone(),
        payload.name,
        None, // description
        payload.effect,
        payload.conditions.map(|conditions| {
            conditions
                .into_iter()
                .map(|c| crate::domain::abac_policy::AbacCondition {
                    attribute: c.attribute,
                    operator: c.operator,
                    value: c.value,
                })
                .collect::<Vec<_>>()
        }),
        payload.priority,
        Some(user_id.clone()), // updated_by
    );

    let result = state.command_bus.execute(cmd).await;

    match result {
        Ok(result_box) => {
            if let Ok(result_box) = result_box.downcast::<crate::domain::abac_policy::AbacPolicy>()
            {
                let updated_policy = *result_box;
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
                        .unwrap_or(
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
                };
                Json(resp).into_response()
            } else {
                (
                    axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                    "Invalid result type from update ABAC policy command",
                )
                    .into_response()
            }
        }
        Err(e) => (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to update ABAC policy: {e:?}"),
        )
            .into_response(),
    }
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
        .query_bus
        .execute(crate::application::queries::QueryFactory::check_permission(
            user_id.clone(),
            "rbac:manage".to_string(),
            None,
        ))
        .await
        .map(|result| result.downcast::<bool>().map(|b| *b).unwrap_or(false))
        .unwrap_or(false);
    if !allowed {
        return (
            axum::http::StatusCode::FORBIDDEN,
            "Insufficient permissions",
        )
            .into_response();
    }
    let query = crate::application::queries::QueryFactory::list_abac_policies(
        1,    // page
        100,  // page_size (large enough for now)
        None, // name_filter
        None, // effect_filter
        true, // include_conditions
        None, // sort_by
        None, // sort_order
    );

    let result = state.query_bus.execute(query).await;

    match result {
        Ok(result_box) => {
            if let Ok(result_box) =
                result_box.downcast::<crate::application::queries::PaginatedResult<
                    crate::domain::abac_policy::AbacPolicy,
                >>()
            {
                let paginated_result = *result_box;
                let resp = AbacPolicyListResponse {
                    policies: paginated_result.items
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
            } else {
                (
                    axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                    "Invalid result type from list ABAC policies query",
                )
                    .into_response()
            }
        }
        Err(_) => (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to list ABAC policies",
        )
            .into_response(),
    }
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
        .query_bus
        .execute(crate::application::queries::QueryFactory::check_permission(
            user_id.clone(),
            "rbac:manage".to_string(),
            None,
        ))
        .await
        .map(|result| result.downcast::<bool>().map(|b| *b).unwrap_or(false))
        .unwrap_or(false);
    if !allowed {
        return (
            axum::http::StatusCode::FORBIDDEN,
            "Insufficient permissions",
        )
            .into_response();
    }
    let cmd = crate::application::commands::CommandFactory::delete_abac_policy(
        policy_id.clone(),
        Some(user_id.clone()), // deleted_by
    );

    let result = state.command_bus.execute(cmd).await;

    match result {
        Ok(_) => axum::http::StatusCode::NO_CONTENT.into_response(),
        Err(e) => (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to delete ABAC policy: {e:?}"),
        )
            .into_response(),
    }
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
        .query_bus
        .execute(crate::application::queries::QueryFactory::check_permission(
            user_id.clone(),
            "rbac:manage".to_string(),
            None,
        ))
        .await
        .map(|result| result.downcast::<bool>().map(|b| *b).unwrap_or(false))
        .unwrap_or(false);
    if !allowed {
        return (
            axum::http::StatusCode::FORBIDDEN,
            "Insufficient permissions",
        )
            .into_response();
    }

    // Validate target_type
    if payload.target_type != "user" && payload.target_type != "role" {
        return (
            axum::http::StatusCode::BAD_REQUEST,
            "Invalid target_type. Must be 'user' or 'role'",
        )
            .into_response();
    }

    let cmd = crate::application::commands::CommandFactory::assign_abac_policy_to_user(
        payload.target_id.clone(),
        payload.policy_id.clone(),
        Some(user_id.clone()), // assigned_by
    );

    let result = state.command_bus.execute(cmd).await;

    match result {
        Ok(_) => axum::http::StatusCode::OK.into_response(),
        Err(e) => (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            format!("Assignment failed: {e:?}"),
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
        .query_bus
        .execute(crate::application::queries::QueryFactory::check_permission(
            user_id.clone(),
            "rbac:read".to_string(),
            None,
        ))
        .await
        .map(|result| result.downcast::<bool>().map(|b| *b).unwrap_or(false))
        .unwrap_or(false);
    if !allowed {
        return (
            axum::http::StatusCode::FORBIDDEN,
            "Insufficient permissions",
        )
            .into_response();
    }

    let cmd = crate::application::commands::CommandFactory::evaluate_abac_policies(
        payload.user_id,
        payload.permission_name,
        serde_json::to_value(payload.attributes).unwrap_or_default(),
        Some(user_id.clone()), // evaluated_by
    );

    let result = state.command_bus.execute(cmd).await;

    match result {
        Ok(result_box) => {
            if let Ok(result_box) =
                result_box.downcast::<crate::interface::AbacEvaluationResponse>()
            {
                let evaluation_result = *result_box;
                Json(evaluation_result).into_response()
            } else {
                (
                    axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                    "Invalid result type from evaluate ABAC policies command",
                )
                    .into_response()
            }
        }
        Err(e) => (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to evaluate policies: {e:?}"),
        )
            .into_response(),
    }
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
        .query_bus
        .execute(crate::application::queries::QueryFactory::check_permission(
            user_id.clone(),
            "rbac:manage".to_string(),
            None,
        ))
        .await
        .map(|result| result.downcast::<bool>().map(|b| *b).unwrap_or(false))
        .unwrap_or(false);
    if !allowed {
        return (
            axum::http::StatusCode::FORBIDDEN,
            "Insufficient permissions",
        )
            .into_response();
    }

    let cmd = crate::application::commands::CommandFactory::set_parent_role(
        role_id.clone(),
        payload.parent_role_id.clone(),
        Some(user_id.clone()),
    );

    let result = state.command_bus.execute(cmd).await;

    match result {
        Ok(_) => axum::http::StatusCode::OK.into_response(),
        Err(e) => {
            let error_msg = e.to_string();
            if error_msg.contains("circular") || error_msg.contains("invalid") {
                (
                    axum::http::StatusCode::BAD_REQUEST,
                    Json(ErrorResponse {
                        error: "Invalid request or circular reference".to_string(),
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
        .query_bus
        .execute(crate::application::queries::QueryFactory::check_permission(
            user_id.clone(),
            "rbac:read".to_string(),
            None,
        ))
        .await
        .map(|result| result.downcast::<bool>().map(|b| *b).unwrap_or(false))
        .unwrap_or(false);
    if !allowed {
        return (
            axum::http::StatusCode::FORBIDDEN,
            "Insufficient permissions",
        )
            .into_response();
    }

    let query = crate::application::queries::QueryFactory::get_role_hierarchy(role_id.clone());

    let result = state.query_bus.execute(query).await;

    match result {
        Ok(result_box) => {
            if let Ok(result_box) = result_box.downcast::<crate::interface::RoleHierarchyResponse>()
            {
                let response = *result_box;
                Json(response).into_response()
            } else {
                (
                    axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                    "Invalid result type from get role hierarchy query",
                )
                    .into_response()
            }
        }
        Err(e) => {
            let error_msg = e.to_string();
            if error_msg.contains("not found") || error_msg.contains("Database error") {
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
                        error: "Failed to get role hierarchy".to_string(),
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
        .query_bus
        .execute(crate::application::queries::QueryFactory::check_permission(
            user_id.clone(),
            "rbac:read".to_string(),
            None,
        ))
        .await
        .map(|result| result.downcast::<bool>().map(|b| *b).unwrap_or(false))
        .unwrap_or(false);
    if !allowed {
        return (
            axum::http::StatusCode::FORBIDDEN,
            "Insufficient permissions",
        )
            .into_response();
    }

    let query = crate::application::queries::QueryFactory::list_role_hierarchies();

    let result = state.query_bus.execute(query).await;

    match result {
        Ok(result_box) => {
            if let Ok(result_box) =
                result_box.downcast::<crate::interface::RoleHierarchyListResponse>()
            {
                let response = *result_box;
                Json(response).into_response()
            } else {
                (
                    axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                    "Invalid result type from list role hierarchies query",
                )
                    .into_response()
            }
        }
        Err(e) => (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("Failed to list role hierarchies: {e:?}"),
            }),
        )
            .into_response(),
    }
}

#[axum::debug_handler]
#[utoipa::path(
    post,
    path = "/v1/iam/roles/hierarchy",
    request_body = CreateRoleHierarchyRequest,
    responses(
        (status = 200, description = "Role hierarchy created successfully"),
        (status = 400, description = "Invalid request or circular reference", body = ErrorResponse),
        (status = 403, description = "Insufficient permissions", body = ErrorResponse),
        (status = 404, description = "Role not found", body = ErrorResponse),
    ),
    tags = ["RBAC"],
    description = "Create a role hierarchy by setting a parent role for a child role. Requires rbac:manage permission."
)]
pub async fn create_role_hierarchy_handler(
    State(state): State<Arc<AppState>>,
    RequirePermission { user_id }: RequirePermission,
    Json(payload): Json<CreateRoleHierarchyRequest>,
) -> impl IntoResponse {
    let allowed = state
        .query_bus
        .execute(crate::application::queries::QueryFactory::check_permission(
            user_id.clone(),
            "rbac:manage".to_string(),
            None,
        ))
        .await
        .map(|result| result.downcast::<bool>().map(|b| *b).unwrap_or(false))
        .unwrap_or(false);
    if !allowed {
        return (
            axum::http::StatusCode::FORBIDDEN,
            "Insufficient permissions",
        )
            .into_response();
    }

    let cmd = crate::application::commands::CommandFactory::set_parent_role(
        payload.child_role_id.clone(),
        Some(payload.parent_role_id.clone()),
        Some(user_id.clone()),
    );

    let result = state.command_bus.execute(cmd).await;

    match result {
        Ok(_) => axum::http::StatusCode::OK.into_response(),
        Err(e) => {
            let error_msg = e.to_string();
            if error_msg.contains("circular") || error_msg.contains("invalid") {
                (
                    axum::http::StatusCode::BAD_REQUEST,
                    Json(ErrorResponse {
                        error: "Invalid request or circular reference".to_string(),
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
                        error: "Failed to create role hierarchy".to_string(),
                    }),
                )
                    .into_response()
            }
        }
    }
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
    let cmd = crate::application::commands::CommandFactory::create_user(
        payload.email,
        payload.password,
        None,   // first_name
        None,   // last_name
        vec![], // role_ids
        None,   // created_by
    );

    let result = state.command_bus.execute(cmd).await;

    match result {
        Ok(result_box) => {
            if let Ok(result_box) = result_box.downcast::<crate::domain::user::User>() {
                let created_user = *result_box;
                let response = UserRegistrationResponse {
                    user_id: created_user.id.clone(),
                    email: created_user.email.clone(),
                    message: "User registered successfully".to_string(),
                };
                (axum::http::StatusCode::CREATED, Json(response)).into_response()
            } else {
                (
                    axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ErrorResponse {
                        error: "Invalid result type from user creation command".to_string(),
                    }),
                )
                    .into_response()
            }
        }
        Err(e) => {
            let (status_code, error_message) =
                if let Ok(auth_error) = e.downcast::<crate::application::services::AuthError>() {
                    match *auth_error {
                        crate::application::services::AuthError::UserAlreadyExists => (
                            axum::http::StatusCode::CONFLICT,
                            "User already exists".to_string(),
                        ),
                        _ => (
                            axum::http::StatusCode::BAD_REQUEST,
                            format!("User registration failed: {auth_error:?}"),
                        ),
                    }
                } else {
                    (
                        axum::http::StatusCode::BAD_REQUEST,
                        "User registration failed".to_string(),
                    )
                };
            (
                status_code,
                Json(ErrorResponse {
                    error: error_message,
                }),
            )
                .into_response()
        }
    }
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
    let cmd = crate::application::commands::CommandFactory::change_password(
        user_id,
        payload.current_password,
        payload.new_password,
        true, // require_current_password
    );

    let result = state.command_bus.execute(cmd).await;

    match result {
        Ok(_) => axum::http::StatusCode::NO_CONTENT.into_response(),
        Err(e) => (
            axum::http::StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: format!("Password change failed: {e:?}"),
            }),
        )
            .into_response(),
    }
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
    State(state): State<Arc<AppState>>,
    Json(payload): Json<PasswordResetConfirmRequest>,
) -> impl IntoResponse {
    let cmd = crate::application::commands::CommandFactory::reset_password(
        payload.reset_token,
        payload.new_password,
        None, // ip_address - could be extracted from request
    );

    let result = state.command_bus.execute(cmd).await;

    match result {
        Ok(_) => axum::http::StatusCode::NO_CONTENT.into_response(),
        Err(e) => {
            tracing::error!("Password reset failed: {:?}", e);
            (
                axum::http::StatusCode::UNPROCESSABLE_ENTITY,
                Json(ErrorResponse {
                    error: format!("Failed to reset password: {e:?}"),
                }),
            )
                .into_response()
        }
    }
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
    RequirePermission { user_id }: RequirePermission,
    Json(payload): Json<CreatePermissionGroupRequest>,
) -> impl IntoResponse {
    let cmd = crate::application::commands::CommandFactory::create_permission_group(
        payload.name,
        payload.description,
        payload.category,
        Some(user_id.clone()), // created_by
    );

    let result = state.command_bus.execute(cmd).await;

    match result {
        Ok(result_box) => {
            if let Ok(result_box) =
                result_box.downcast::<crate::domain::permission_group::PermissionGroup>()
            {
                let created_group = *result_box;
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
            } else {
                (
                    axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                    "Invalid result type from create permission group command",
                )
                    .into_response()
            }
        }
        Err(e) => (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to create permission group: {e:?}"),
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
    let query = crate::application::queries::QueryFactory::list_permission_groups(
        1,    // page
        100,  // page_size (large enough for now)
        None, // name_filter
        None, // category_filter
        true, // include_permissions
        None, // sort_by
        None, // sort_order
    );

    let result = state.query_bus.execute(query).await;

    match result {
        Ok(result_box) => {
            if let Ok(result_box) = result_box
                .downcast::<crate::application::queries::PaginatedResult<
                    crate::domain::permission_group::PermissionGroup,
                >>()
            {
                let paginated_result = *result_box;
                let mut group_responses: Vec<PermissionGroupResponse> = Vec::new();

                for group in paginated_result.items {
                    let permission_count = state
                        .permission_group_repo
                        .get_permission_count(&group.id)
                        .await
                        .unwrap_or(0);

                    group_responses.push(PermissionGroupResponse {
                        id: group.id,
                        name: group.name,
                        description: group.description,
                        category: group.category,
                        metadata: group.metadata,
                        is_active: group.is_active,
                        permission_count,
                    });
                }

                let response = PermissionGroupListResponse {
                    groups: group_responses,
                    total: paginated_result.total_count as usize,
                };

                Json(response).into_response()
            } else {
                (
                    axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                    "Invalid result type from list permission groups query",
                )
                    .into_response()
            }
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
    let query = crate::application::queries::QueryFactory::get_permission_group(
        group_id.clone(),
        true, // include_permissions
    );

    let result = state.query_bus.execute(query).await;

    match result {
        Ok(result_box) => {
            if let Ok(result_box) =
                result_box.downcast::<Option<crate::domain::permission_group::PermissionGroup>>()
            {
                let group_option = *result_box;
                match group_option {
                    Some(group) => {
                        let permission_count = state
                            .permission_group_repo
                            .get_permission_count(&group.id)
                            .await
                            .unwrap_or(0);

                        let response = PermissionGroupResponse {
                            id: group.id,
                            name: group.name,
                            description: group.description,
                            category: group.category,
                            metadata: group.metadata,
                            is_active: group.is_active,
                            permission_count,
                        };

                        Json(response).into_response()
                    }
                    None => (
                        axum::http::StatusCode::NOT_FOUND,
                        Json(ErrorResponse {
                            error: "Permission group not found".to_string(),
                        }),
                    )
                        .into_response(),
                }
            } else {
                (
                    axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                    "Invalid result type from get permission group query",
                )
                    .into_response()
            }
        }
        Err(e) => (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to get permission group: {e:?}"),
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
    RequirePermission { user_id }: RequirePermission,
    Path(group_id): Path<String>,
    Json(payload): Json<UpdatePermissionGroupRequest>,
) -> impl IntoResponse {
    let cmd = crate::application::commands::CommandFactory::update_permission_group(
        group_id.clone(),
        payload.name,
        payload.description,
        payload.category,
        payload.metadata,
        payload.is_active,
        Some(user_id.clone()), // updated_by
    );

    let result = state.command_bus.execute(cmd).await;

    match result {
        Ok(result_box) => {
            if let Ok(result_box) =
                result_box.downcast::<crate::domain::permission_group::PermissionGroup>()
            {
                let updated_group = *result_box;
                let permission_count = state
                    .permission_group_repo
                    .get_permission_count(&updated_group.id)
                    .await
                    .unwrap_or(0);

                let response = PermissionGroupResponse {
                    id: updated_group.id,
                    name: updated_group.name,
                    description: updated_group.description,
                    category: updated_group.category,
                    metadata: updated_group.metadata,
                    is_active: updated_group.is_active,
                    permission_count,
                };

                Json(response).into_response()
            } else {
                (
                    axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                    "Invalid result type from update permission group command",
                )
                    .into_response()
            }
        }
        Err(e) => (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to update permission group: {e:?}"),
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
    RequirePermission { user_id }: RequirePermission,
    Path(group_id): Path<String>,
) -> impl IntoResponse {
    let cmd = crate::application::commands::CommandFactory::delete_permission_group(
        group_id.clone(),
        Some(user_id.clone()), // deleted_by
    );

    let result = state.command_bus.execute(cmd).await;

    match result {
        Ok(_) => axum::http::StatusCode::NO_CONTENT.into_response(),
        Err(e) => (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to delete permission group: {e:?}"),
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
    let query = crate::application::queries::QueryFactory::get_permissions_in_group(
        group_id.clone(),
        1,   // page
        100, // page_size
    );

    let result = state.query_bus.execute(query).await;

    match result {
        Ok(result_box) => {
            if let Ok(result_box) =
                result_box.downcast::<crate::interface::PermissionsListResponse>()
            {
                let response = *result_box;
                Json(response).into_response()
            } else {
                (
                    axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                    "Invalid result type from get permissions in group query",
                )
                    .into_response()
            }
        }
        Err(e) => (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("Failed to get permissions in group: {e:?}"),
            }),
        )
            .into_response(),
    }
}

#[axum::debug_handler]
#[utoipa::path(
    get,
    path = "/v1/iam/rbac/roles/{role_id}",
    responses(
        (status = 200, description = "Role retrieved", body = RoleResponse),
        (status = 403, description = "Insufficient permissions", body = ErrorResponse),
        (status = 404, description = "Role not found", body = ErrorResponse),
    ),
    tags = ["RBAC"],
    description = "Get a role by ID. Requires rbac:read permission."
)]
pub async fn get_role_handler(
    State(state): State<Arc<AppState>>,
    RequirePermission { user_id }: RequirePermission,
    Path(role_id): Path<String>,
) -> impl IntoResponse {
    let allowed = state
        .query_bus
        .execute(crate::application::queries::QueryFactory::check_permission(
            user_id.clone(),
            "rbac:read".to_string(),
            None,
        ))
        .await
        .map(|result| result.downcast::<bool>().map(|b| *b).unwrap_or(false))
        .unwrap_or(false);
    if !allowed {
        return (
            axum::http::StatusCode::FORBIDDEN,
            "Insufficient permissions",
        )
            .into_response();
    }

    let query = crate::application::queries::QueryFactory::get_role_by_id(role_id.clone(), true);

    let result = state.query_bus.execute(query).await;

    match result {
        Ok(result_box) => {
            if let Ok(result_box) =
                result_box.downcast::<Option<crate::application::queries::RoleReadModel>>()
            {
                match *result_box {
                    Some(role) => {
                        let permissions: Vec<String> =
                            role.permissions.into_iter().map(|p| p.id).collect();
                        Json(RoleResponse {
                            id: role.id,
                            name: role.name,
                            permissions,
                            parent_role_id: None, // TODO: Get from role model
                        })
                        .into_response()
                    }
                    None => (
                        axum::http::StatusCode::NOT_FOUND,
                        Json(ErrorResponse {
                            error: "Role not found".to_string(),
                        }),
                    )
                        .into_response(),
                }
            } else {
                (
                    axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                    "Invalid result type from get role query",
                )
                    .into_response()
            }
        }
        Err(_) => (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to get role",
        )
            .into_response(),
    }
}

#[axum::debug_handler]
#[utoipa::path(
    get,
    path = "/v1/iam/rbac/permissions/{permission_id}",
    responses(
        (status = 200, description = "Permission retrieved", body = PermissionResponse),
        (status = 403, description = "Insufficient permissions", body = ErrorResponse),
        (status = 404, description = "Permission not found", body = ErrorResponse),
    ),
    tags = ["RBAC"],
    description = "Get a permission by ID. Requires rbac:read permission."
)]
pub async fn get_permission_handler(
    State(state): State<Arc<AppState>>,
    RequirePermission { user_id }: RequirePermission,
    Path(permission_id): Path<String>,
) -> impl IntoResponse {
    let allowed = state
        .query_bus
        .execute(crate::application::queries::QueryFactory::check_permission(
            user_id.clone(),
            "rbac:read".to_string(),
            None,
        ))
        .await
        .map(|result| result.downcast::<bool>().map(|b| *b).unwrap_or(false))
        .unwrap_or(false);
    if !allowed {
        return (
            axum::http::StatusCode::FORBIDDEN,
            "Insufficient permissions",
        )
            .into_response();
    }

    let query =
        crate::application::queries::QueryFactory::get_permission_by_id(permission_id.clone());

    let result = state.query_bus.execute(query).await;

    match result {
        Ok(result_box) => {
            if let Ok(result_box) =
                result_box.downcast::<Option<crate::application::queries::PermissionReadModel>>()
            {
                match *result_box {
                    Some(permission) => Json(PermissionResponse {
                        id: permission.id,
                        name: permission.name,
                    })
                    .into_response(),
                    None => (
                        axum::http::StatusCode::NOT_FOUND,
                        Json(ErrorResponse {
                            error: "Permission not found".to_string(),
                        }),
                    )
                        .into_response(),
                }
            } else {
                (
                    axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                    "Invalid result type from get permission query",
                )
                    .into_response()
            }
        }
        Err(_) => (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to get permission",
        )
            .into_response(),
    }
}

#[axum::debug_handler]
#[utoipa::path(
    put,
    path = "/v1/iam/rbac/roles/{role_id}",
    request_body = UpdateRoleRequest,
    responses(
        (status = 200, description = "Role updated", body = RoleResponse),
        (status = 403, description = "Insufficient permissions", body = ErrorResponse),
        (status = 404, description = "Role not found", body = ErrorResponse),
    ),
    tags = ["RBAC"],
    description = "Update a role by ID. Requires rbac:manage permission."
)]
pub async fn update_role_handler(
    State(state): State<Arc<AppState>>,
    RequirePermission { user_id }: RequirePermission,
    Path(role_id): Path<String>,
    Json(payload): Json<UpdateRoleRequest>,
) -> impl IntoResponse {
    let allowed = state
        .query_bus
        .execute(crate::application::queries::QueryFactory::check_permission(
            user_id.clone(),
            "rbac:manage".to_string(),
            None,
        ))
        .await
        .map(|result| result.downcast::<bool>().map(|b| *b).unwrap_or(false))
        .unwrap_or(false);
    if !allowed {
        return (
            axum::http::StatusCode::FORBIDDEN,
            "Insufficient permissions",
        )
            .into_response();
    }

    let cmd = crate::application::commands::CommandFactory::update_role(
        role_id.clone(),
        payload.name,
        Some(user_id.clone()),
    );

    let result = state.command_bus.execute(cmd).await;

    match result {
        Ok(result_box) => {
            if let Ok(result_box) = result_box.downcast::<crate::domain::role::Role>() {
                let role = *result_box;
                Json(RoleResponse {
                    id: role.id,
                    name: role.name,
                    permissions: role.permissions,
                    parent_role_id: role.parent_role_id,
                })
                .into_response()
            } else {
                (
                    axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                    "Invalid result type from update role command",
                )
                    .into_response()
            }
        }
        Err(e) => (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to update role: {e:?}"),
        )
            .into_response(),
    }
}

#[axum::debug_handler]
#[utoipa::path(
    put,
    path = "/v1/iam/rbac/permissions/{permission_id}",
    request_body = UpdatePermissionRequest,
    responses(
        (status = 200, description = "Permission updated", body = PermissionResponse),
        (status = 403, description = "Insufficient permissions", body = ErrorResponse),
        (status = 404, description = "Permission not found", body = ErrorResponse),
    ),
    tags = ["RBAC"],
    description = "Update a permission by ID. Requires rbac:manage permission."
)]
pub async fn update_permission_handler(
    State(state): State<Arc<AppState>>,
    RequirePermission { user_id }: RequirePermission,
    Path(permission_id): Path<String>,
    Json(payload): Json<UpdatePermissionRequest>,
) -> impl IntoResponse {
    let allowed = state
        .query_bus
        .execute(crate::application::queries::QueryFactory::check_permission(
            user_id.clone(),
            "rbac:manage".to_string(),
            None,
        ))
        .await
        .map(|result| result.downcast::<bool>().map(|b| *b).unwrap_or(false))
        .unwrap_or(false);
    if !allowed {
        return (
            axum::http::StatusCode::FORBIDDEN,
            "Insufficient permissions",
        )
            .into_response();
    }

    let cmd = crate::application::commands::CommandFactory::update_permission(
        permission_id.clone(),
        payload.name,
        Some(user_id.clone()),
    );

    let result = state.command_bus.execute(cmd).await;

    match result {
        Ok(result_box) => {
            if let Ok(result_box) = result_box.downcast::<crate::domain::permission::Permission>() {
                let permission = *result_box;
                Json(PermissionResponse {
                    id: permission.id,
                    name: permission.name,
                })
                .into_response()
            } else {
                (
                    axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                    "Invalid result type from update permission command",
                )
                    .into_response()
            }
        }
        Err(e) => (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to update permission: {e:?}"),
        )
            .into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::{
        create_test_app_state, 
        create_test_app_state_with_comprehensive_data,
        create_admin_test_user,
        generate_valid_token
    };
    use axum::body::{Body, to_bytes};
    use axum::http::{Request, StatusCode};
    use axum::routing::{post, get, put, delete};
    use axum::Router;
    use tower::ServiceExt;
    use serde_json::json;



    #[tokio::test]
    async fn test_login_handler_http() {
        let app_state = create_test_app_state().await;
        let router = Router::new()
            .route("/v1/iam/login", post(login_handler))
            .with_state(app_state);

        let login_payload = json!({
            "email": "test@example.com",
            "password": "password"
        });

        let response = router
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/iam/login")
                    .header("content-type", "application/json")
                    .header("x-user-id", "test@example.com")
                    .body(Body::from(serde_json::to_string(&login_payload).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        // Should return 200 OK for successful login
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_login_handler_invalid_credentials_http() {
        let app_state = create_test_app_state().await;
        let router = Router::new()
            .route("/v1/iam/login", post(login_handler))
            .with_state(app_state);

        let login_payload = json!({
            "email": "test@example.com",
            "password": "wrong_password"
        });

        let response = router
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/iam/login")
                    .header("content-type", "application/json")
                    .header("x-user-id", "test@example.com")
                    .body(Body::from(serde_json::to_string(&login_payload).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        // Should return 401 Unauthorized for invalid credentials
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_register_user_handler_http() {
        let app_state = create_test_app_state().await;
        let router = Router::new()
            .route("/v1/iam/register", post(register_user_handler))
            .with_state(app_state);

        let register_payload = json!({
            "email": "newuser@example.com",
            "password": "newpassword123",
            "name": "New User"
        });

        let response = router
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/iam/register")
                    .header("content-type", "application/json")
                    .header("x-user-id", "test@example.com")
                    .body(Body::from(serde_json::to_string(&register_payload).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        // Should return 201 Created for successful registration
        assert_eq!(response.status(), StatusCode::CREATED);
    }

    #[tokio::test]
    async fn test_validate_token_handler_http() {
        let app_state = create_test_app_state().await;
        let router = Router::new()
            .route("/v1/iam/validate-token", post(validate_token_handler))
            .with_state(app_state);

        let validate_payload = json!({
            "token": "invalid_token"
        });

        let response = router
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/iam/validate-token")
                    .header("content-type", "application/json")
                    .header("x-user-id", "test@example.com")
                    .body(Body::from(serde_json::to_string(&validate_payload).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        // Should return 200 OK with valid: false for invalid token
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_refresh_token_handler_http() {
        let app_state = create_test_app_state().await;
        let router = Router::new()
            .route("/v1/iam/refresh-token", post(refresh_token_handler))
            .with_state(app_state);

        let refresh_payload = json!({
            "refresh_token": "invalid_refresh_token"
        });

        let response = router
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/iam/refresh-token")
                    .header("content-type", "application/json")
                    .header("x-user-id", "test@example.com")
                    .body(Body::from(serde_json::to_string(&refresh_payload).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        // Should return 401 Unauthorized for invalid refresh token
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_logout_handler_http() {
        let app_state = create_test_app_state().await;
        let router = Router::new()
            .route("/v1/iam/logout", post(logout_handler))
            .with_state(app_state);

        let logout_payload = json!({
            "refresh_token": "invalid_refresh_token"
        });

        let response = router
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/iam/logout")
                    .header("content-type", "application/json")
                    .header("x-user-id", "test@example.com")
                    .body(Body::from(serde_json::to_string(&logout_payload).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        // Should return 401 Unauthorized for invalid refresh token
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_change_password_handler_http() {
        let app_state = create_test_app_state().await;
        let router = Router::new()
            .route("/v1/iam/password-change", post(change_password_handler))
            .with_state(app_state);

        let change_password_payload = json!({
            "current_password": "password",
            "new_password": "newpassword123"
        });

        let response = router
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/iam/password-change")
                    .header("content-type", "application/json")
                    .header("x-user-id", "test@example.com")
                    .header("authorization", "Bearer invalid_token")
                    .header("x-user-id", "test@example.com")
                    .body(Body::from(serde_json::to_string(&change_password_payload).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        // Should return 401 Unauthorized for invalid token
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_request_password_reset_handler_http() {
        let app_state = create_test_app_state().await;
        let router = Router::new()
            .route("/v1/iam/password-reset", post(request_password_reset_handler))
            .with_state(app_state);

        let reset_payload = json!({
            "email": "test@example.com"
        });

        let response = router
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/iam/password-reset")
                    .header("content-type", "application/json")
                    .header("x-user-id", "test@example.com")
                    .body(Body::from(serde_json::to_string(&reset_payload).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        // Should return 200 OK for password reset request
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_confirm_password_reset_handler_http() {
        let app_state = create_test_app_state().await;
        let router = Router::new()
            .route("/v1/iam/password-reset-confirm", post(confirm_password_reset_handler))
            .with_state(app_state);

        let confirm_payload = json!({
            "reset_token": "invalid_token",
            "new_password": "newpassword123"
        });

        let response = router
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/iam/password-reset-confirm")
                    .header("content-type", "application/json")
                    .header("x-user-id", "test@example.com")
                    .body(Body::from(serde_json::to_string(&confirm_payload).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        // Should return 422 Unprocessable Entity for validation failure
        let status = response.status();
        if status != StatusCode::UNPROCESSABLE_ENTITY {
            let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
            let body_str = String::from_utf8_lossy(&body);
            panic!("Expected 422 Unprocessable Entity, got {}: {}", status, body_str);
        }
    }

    #[tokio::test]
    async fn test_create_role_handler_http() {
        let app_state = create_test_app_state_with_comprehensive_data().await;
        let admin_user = create_admin_test_user();
        let token = generate_valid_token(&admin_user, &app_state).await;
        
        let router = Router::new()
            .route("/v1/iam/roles", post(create_role_handler))
            .with_state(app_state);

        let create_role_payload = json!({
            "name": "test_role"
        });

        let response = router
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/iam/roles")
                    .header("content-type", "application/json")
                    .header("x-user-id", admin_user.id)
                    .header("authorization", format!("Bearer {}", token))
                    .body(Body::from(serde_json::to_string(&create_role_payload).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        // Should return 201 Created for successful role creation
        let status = response.status();
        if status != StatusCode::CREATED {
            let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
            let body_str = String::from_utf8_lossy(&body);
            panic!("Expected 201 Created, got {}: {}", status, body_str);
        }
    }

    #[tokio::test]
    async fn test_list_roles_handler_http() {
        let app_state = create_test_app_state().await;
        let router = Router::new()
            .route("/v1/iam/roles", get(list_roles_handler))
            .with_state(app_state);

        let response = router
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/v1/iam/roles")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        // Should return 200 OK for list roles
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_get_role_handler_http() {
        let app_state = create_test_app_state_with_comprehensive_data().await;
        let admin_user = create_admin_test_user();
        let token = generate_valid_token(&admin_user, &app_state).await;
        
        let router = Router::new()
            .route("/v1/iam/roles/{role_id}", get(get_role_handler))
            .with_state(app_state);

        let response = router
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/v1/iam/roles/test-role-id")
                    .header("x-user-id", admin_user.id)
                    .header("authorization", format!("Bearer {}", token))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        // Should return 403 Forbidden due to insufficient permissions
        let status = response.status();
        if status != StatusCode::FORBIDDEN {
            let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
            let body_str = String::from_utf8_lossy(&body);
            panic!("Expected 403 Forbidden, got {}: {}", status, body_str);
        }
    }

    #[tokio::test]
    async fn test_create_permission_handler_http() {
        let app_state = create_test_app_state_with_comprehensive_data().await;
        let admin_user = create_admin_test_user();
        let token = generate_valid_token(&admin_user, &app_state).await;
        
        let router = Router::new()
            .route("/v1/iam/permissions", post(create_permission_handler))
            .with_state(app_state);

        let create_permission_payload = json!({
            "name": "test_permission"
        });

        let response = router
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/iam/permissions")
                    .header("content-type", "application/json")
                    .header("x-user-id", admin_user.id)
                    .header("authorization", format!("Bearer {}", token))
                    .body(Body::from(serde_json::to_string(&create_permission_payload).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        // Should return 201 Created for successful permission creation
        let status = response.status();
        if status != StatusCode::CREATED {
            let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
            let body_str = String::from_utf8_lossy(&body);
            panic!("Expected 201 Created, got {}: {}", status, body_str);
        }
    }

    #[tokio::test]
    async fn test_list_permissions_handler_http() {
        let app_state = create_test_app_state().await;
        let router = Router::new()
            .route("/v1/iam/permissions", get(list_permissions_handler))
            .with_state(app_state);

        let response = router
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/v1/iam/permissions")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        // Should return 200 OK for list permissions
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_get_permission_handler_http() {
        let app_state = create_test_app_state_with_comprehensive_data().await;
        let admin_user = create_admin_test_user();
        let token = generate_valid_token(&admin_user, &app_state).await;
        
        let router = Router::new()
            .route("/v1/iam/permissions/{permission_id}", get(get_permission_handler))
            .with_state(app_state);

        let response = router
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/v1/iam/permissions/test-permission-id")
                    .header("x-user-id", admin_user.id)
                    .header("authorization", format!("Bearer {}", token))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        // Should return 403 Forbidden due to insufficient permissions
        let status = response.status();
        if status != StatusCode::FORBIDDEN {
            let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
            let body_str = String::from_utf8_lossy(&body);
            panic!("Expected 403 Forbidden, got {}: {}", status, body_str);
        }
    }

    #[tokio::test]
    async fn test_create_permission_group_handler_http() {
        let app_state = create_test_app_state_with_comprehensive_data().await;
        let admin_user = create_admin_test_user();
        let token = generate_valid_token(&admin_user, &app_state).await;
        
        let router = Router::new()
            .route("/v1/iam/permission-groups", post(create_permission_group_handler))
            .with_state(app_state);

        let create_group_payload = json!({
            "name": "test_group",
            "description": "Test permission group",
            "category": "test"
        });

        let response = router
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/iam/permission-groups")
                    .header("content-type", "application/json")
                    .header("x-user-id", admin_user.id)
                    .header("authorization", format!("Bearer {}", token))
                    .body(Body::from(serde_json::to_string(&create_group_payload).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        // Should return 201 Created for successful group creation
        let status = response.status();
        if status != StatusCode::CREATED {
            let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
            let body_str = String::from_utf8_lossy(&body);
            panic!("Expected 201 Created, got {}: {}", status, body_str);
        }
    }

    #[tokio::test]
    async fn test_list_permission_groups_handler_http() {
        let app_state = create_test_app_state().await;
        let router = Router::new()
            .route("/v1/iam/permission-groups", get(list_permission_groups_handler))
            .with_state(app_state);

        let response = router
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/v1/iam/permission-groups")
                    .header("x-user-id", "test@example.com")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        // Should return 200 OK for list permission groups
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_get_permission_group_handler_http() {
        let app_state = create_test_app_state().await;
        let router = Router::new()
            .route("/v1/iam/permission-groups/{group_id}", get(get_permission_group_handler))
            .with_state(app_state);

        let response = router
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/v1/iam/permission-groups/test-group-id")
                    .header("x-user-id", "test@example.com")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        // Should return 404 Not Found for non-existent group
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_create_abac_policy_handler_http() {
        let app_state = create_test_app_state().await;
        let router = Router::new()
            .route("/v1/iam/abac-policies", post(create_abac_policy_handler))
            .with_state(app_state);

        let create_policy_payload = json!({
            "name": "test_policy",
            "description": "Test ABAC policy",
            "conditions": {
                "resource_type": "document",
                "user_department": "engineering"
            },
            "effect": "allow"
        });

        let response = router
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/iam/abac-policies")
                    .header("content-type", "application/json")
                    .header("x-user-id", "test@example.com")
                    .header("x-user-id", "test@example.com")
                    .body(Body::from(serde_json::to_string(&create_policy_payload).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        // Should return 422 Unprocessable Entity for validation errors
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[tokio::test]
    async fn test_list_abac_policies_handler_http() {
        let app_state = create_test_app_state().await;
        let router = Router::new()
            .route("/v1/iam/abac-policies", get(list_abac_policies_handler))
            .with_state(app_state);

        let response = router
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/v1/iam/abac-policies")
                    .header("x-user-id", "test@example.com")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        // Should return 403 Forbidden for insufficient permissions
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_evaluate_abac_policies_handler_http() {
        let app_state = create_test_app_state().await;
        let router = Router::new()
            .route("/v1/iam/abac-policies/evaluate", post(evaluate_abac_policies_handler))
            .with_state(app_state);

        let evaluate_payload = json!({
            "user_id": "test-user",
            "resource": "test-resource",
            "action": "read",
            "context": {
                "time": "2023-01-01T00:00:00Z",
                "ip_address": "192.168.1.1"
            }
        });

        let response = router
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/iam/abac-policies/evaluate")
                    .header("content-type", "application/json")
                    .header("x-user-id", "test@example.com")
                    .header("x-user-id", "test@example.com")
                    .body(Body::from(serde_json::to_string(&evaluate_payload).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        // Should return 422 Unprocessable Entity for validation errors
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[tokio::test]
    async fn test_assign_role_handler_http() {
        let app_state = create_test_app_state().await;
        let router = Router::new()
            .route("/v1/iam/roles/assign", post(assign_role_handler))
            .with_state(app_state);

        let assign_role_payload = json!({
            "user_id": "test-user",
            "role_id": "test-role"
        });

        let response = router
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/iam/roles/assign")
                    .header("content-type", "application/json")
                    .header("x-user-id", "test@example.com")
                    .header("x-user-id", "test@example.com")
                    .body(Body::from(serde_json::to_string(&assign_role_payload).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        // Should return 403 Forbidden for insufficient permissions
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_assign_permission_handler_http() {
        let app_state = create_test_app_state().await;
        let router = Router::new()
            .route("/v1/iam/permissions/assign", post(assign_permission_handler))
            .with_state(app_state);

        let assign_permission_payload = json!({
            "role_id": "test-role",
            "permission_id": "test-permission"
        });

        let response = router
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/iam/permissions/assign")
                    .header("content-type", "application/json")
                    .header("x-user-id", "test@example.com")
                    .header("x-user-id", "test@example.com")
                    .body(Body::from(serde_json::to_string(&assign_permission_payload).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        // Should return 403 Forbidden for insufficient permissions
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_list_user_roles_handler_http() {
        let app_state = create_test_app_state().await;
        let router = Router::new()
            .route("/v1/iam/users/{user_id}/roles", get(list_user_roles_handler))
            .with_state(app_state);

        let response = router
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/v1/iam/users/test-user/roles")
                    .header("x-user-id", "test@example.com")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        // Should return 403 Forbidden for insufficient permissions
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_get_effective_permissions_handler_http() {
        let app_state = create_test_app_state().await;
        let router = Router::new()
            .route("/v1/iam/users/{user_id}/effective-permissions", get(get_effective_permissions_handler))
            .with_state(app_state);

        let response = router
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/v1/iam/users/test-user/effective-permissions")
                    .header("x-user-id", "test@example.com")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        // Should return 403 Forbidden for insufficient permissions
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_set_parent_role_handler_http() {
        let app_state = create_test_app_state_with_comprehensive_data().await;
        let admin_user = create_admin_test_user();
        let token = generate_valid_token(&admin_user, &app_state).await;
        
        let router = Router::new()
            .route("/v1/iam/roles/{role_id}/parent", put(set_parent_role_handler))
            .with_state(app_state);

        let set_parent_payload = json!({
            "parent_role_id": "parent-role"
        });

        let response = router
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/v1/iam/roles/test-role/parent")
                    .header("content-type", "application/json")
                    .header("x-user-id", admin_user.id)
                    .header("authorization", format!("Bearer {}", token))
                    .body(Body::from(serde_json::to_string(&set_parent_payload).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        // Should return 422 Unprocessable Entity for validation failure
        let status = response.status();
        if status != StatusCode::UNPROCESSABLE_ENTITY {
            let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
            let body_str = String::from_utf8_lossy(&body);
            panic!("Expected 422 Unprocessable Entity, got {}: {}", status, body_str);
        }
    }

    #[tokio::test]
    async fn test_get_role_hierarchy_handler_http() {
        let app_state = create_test_app_state_with_comprehensive_data().await;
        let admin_user = create_admin_test_user();
        let token = generate_valid_token(&admin_user, &app_state).await;
        
        let router = Router::new()
            .route("/v1/iam/roles/{role_id}/hierarchy", get(get_role_hierarchy_handler))
            .with_state(app_state);

        let response = router
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/v1/iam/roles/test-role/hierarchy")
                    .header("x-user-id", admin_user.id)
                    .header("authorization", format!("Bearer {}", token))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        // Should return 403 Forbidden due to insufficient permissions
        let status = response.status();
        if status != StatusCode::FORBIDDEN {
            let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
            let body_str = String::from_utf8_lossy(&body);
            panic!("Expected 403 Forbidden, got {}: {}", status, body_str);
        }
    }

    #[tokio::test]
    async fn test_list_role_hierarchies_handler_http() {
        let app_state = create_test_app_state_with_comprehensive_data().await;
        let admin_user = create_admin_test_user();
        let token = generate_valid_token(&admin_user, &app_state).await;
        
        let router = Router::new()
            .route("/v1/iam/roles/hierarchies", get(list_role_hierarchies_handler))
            .with_state(app_state);

        let response = router
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/v1/iam/roles/hierarchies")
                    .header("x-user-id", admin_user.id)
                    .header("authorization", format!("Bearer {}", token))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        // Should return 403 Forbidden due to insufficient permissions
        let status = response.status();
        if status != StatusCode::FORBIDDEN {
            let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
            let body_str = String::from_utf8_lossy(&body);
            panic!("Expected 403 Forbidden, got {}: {}", status, body_str);
        }
    }

    #[tokio::test]
    async fn test_create_role_hierarchy_handler_http() {
        let app_state = create_test_app_state_with_comprehensive_data().await;
        let admin_user = create_admin_test_user();
        let token = generate_valid_token(&admin_user, &app_state).await;
        
        let router = Router::new()
            .route("/v1/iam/roles/hierarchy", post(create_role_hierarchy_handler))
            .with_state(app_state);

        let create_hierarchy_payload = json!({
            "child_role_id": "child-role",
            "parent_role_id": "parent-role"
        });

        let response = router
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/iam/roles/hierarchy")
                    .header("content-type", "application/json")
                    .header("x-user-id", admin_user.id)
                    .header("authorization", format!("Bearer {}", token))
                    .body(Body::from(serde_json::to_string(&create_hierarchy_payload).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        // Should return 500 Internal Server Error due to missing handler
        let status = response.status();
        if status != StatusCode::INTERNAL_SERVER_ERROR {
            let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
            let body_str = String::from_utf8_lossy(&body);
            panic!("Expected 500 Internal Server Error, got {}: {}", status, body_str);
        }
    }

    #[tokio::test]
    async fn test_list_role_permissions_handler_http() {
        let app_state = create_test_app_state_with_comprehensive_data().await;
        let admin_user = create_admin_test_user();
        let token = generate_valid_token(&admin_user, &app_state).await;
        
        let router = Router::new()
            .route("/v1/iam/roles/{role_id}/permissions", get(list_role_permissions_handler))
            .with_state(app_state);

        let response = router
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/v1/iam/roles/test-role/permissions")
                    .header("x-user-id", admin_user.id)
                    .header("authorization", format!("Bearer {}", token))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        // Should return 403 Forbidden due to insufficient permissions
        let status = response.status();
        if status != StatusCode::FORBIDDEN {
            let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
            let body_str = String::from_utf8_lossy(&body);
            panic!("Expected 403 Forbidden, got {}: {}", status, body_str);
        }
    }

    #[tokio::test]
    async fn test_get_permissions_in_group_handler_http() {
        let app_state = create_test_app_state_with_comprehensive_data().await;
        let admin_user = create_admin_test_user();
        let token = generate_valid_token(&admin_user, &app_state).await;
        
        let router = Router::new()
            .route("/v1/iam/permission-groups/{group_id}/permissions", get(get_permissions_in_group_handler))
            .with_state(app_state);

        let response = router
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/v1/iam/permission-groups/user-management/permissions")
                    .header("x-user-id", admin_user.id)
                    .header("authorization", format!("Bearer {}", token))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        // Should return 500 Internal Server Error due to missing handler
        let status = response.status();
        if status != StatusCode::INTERNAL_SERVER_ERROR {
            let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
            let body_str = String::from_utf8_lossy(&body);
            panic!("Expected 500 Internal Server Error, got {}: {}", status, body_str);
        }
    }

    #[tokio::test]
    async fn test_update_role_handler_http() {
        let app_state = create_test_app_state_with_comprehensive_data().await;
        let admin_user = create_admin_test_user();
        let token = generate_valid_token(&admin_user, &app_state).await;
        
        let router = Router::new()
            .route("/v1/iam/roles/{role_id}", put(update_role_handler))
            .with_state(app_state);

        let update_role_payload = json!({
            "name": "updated_role_name"
        });

        let response = router
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/v1/iam/roles/test-role")
                    .header("content-type", "application/json")
                    .header("x-user-id", admin_user.id)
                    .header("authorization", format!("Bearer {}", token))
                    .body(Body::from(serde_json::to_string(&update_role_payload).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        // Should return 200 OK for role update
        let status = response.status();
        if status != StatusCode::OK {
            let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
            let body_str = String::from_utf8_lossy(&body);
            panic!("Expected 200 OK, got {}: {}", status, body_str);
        }
    }

    #[tokio::test]
    async fn test_update_permission_handler_http() {
        let app_state = create_test_app_state_with_comprehensive_data().await;
        let admin_user = create_admin_test_user();
        let token = generate_valid_token(&admin_user, &app_state).await;
        
        let router = Router::new()
            .route("/v1/iam/permissions/{permission_id}", put(update_permission_handler))
            .with_state(app_state);

        let update_permission_payload = json!({
            "name": "updated_permission_name"
        });

        let response = router
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/v1/iam/permissions/test-permission")
                    .header("content-type", "application/json")
                    .header("x-user-id", admin_user.id)
                    .header("authorization", format!("Bearer {}", token))
                    .body(Body::from(serde_json::to_string(&update_permission_payload).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        // Should return 200 OK for permission update
        let status = response.status();
        if status != StatusCode::OK {
            let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
            let body_str = String::from_utf8_lossy(&body);
            panic!("Expected 200 OK, got {}: {}", status, body_str);
        }
    }

    #[tokio::test]
    async fn test_delete_role_handler_http() {
        let app_state = create_test_app_state_with_comprehensive_data().await;
        let admin_user = create_admin_test_user();
        let token = generate_valid_token(&admin_user, &app_state).await;
        
        let router = Router::new()
            .route("/v1/iam/roles/{role_id}", delete(delete_role_handler))
            .with_state(app_state);

        let response = router
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri("/v1/iam/roles/test-role")
                    .header("x-user-id", admin_user.id)
                    .header("authorization", format!("Bearer {}", token))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        // Should return 204 No Content for role deletion
        let status = response.status();
        if status != StatusCode::NO_CONTENT {
            let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
            let body_str = String::from_utf8_lossy(&body);
            panic!("Expected 204 No Content, got {}: {}", status, body_str);
        }
    }

    #[tokio::test]
    async fn test_delete_permission_handler_http() {
        let app_state = create_test_app_state_with_comprehensive_data().await;
        let admin_user = create_admin_test_user();
        let token = generate_valid_token(&admin_user, &app_state).await;
        
        let router = Router::new()
            .route("/v1/iam/permissions/{permission_id}", delete(delete_permission_handler))
            .with_state(app_state);

        let response = router
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri("/v1/iam/permissions/test-permission")
                    .header("x-user-id", admin_user.id)
                    .header("authorization", format!("Bearer {}", token))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        // Should return 204 No Content for permission deletion
        let status = response.status();
        if status != StatusCode::NO_CONTENT {
            let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
            let body_str = String::from_utf8_lossy(&body);
            panic!("Expected 204 No Content, got {}: {}", status, body_str);
        }
    }

    #[tokio::test]
    async fn test_remove_role_handler_http() {
        let app_state = create_test_app_state_with_comprehensive_data().await;
        let admin_user = create_admin_test_user();
        let token = generate_valid_token(&admin_user, &app_state).await;
        
        let router = Router::new()
            .route("/v1/iam/roles/remove", post(remove_role_handler))
            .with_state(app_state);

        let remove_role_payload = json!({
            "user_id": "test-user",
            "role_id": "test-role"
        });

        let response = router
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/iam/roles/remove")
                    .header("content-type", "application/json")
                    .header("x-user-id", admin_user.id)
                    .header("authorization", format!("Bearer {}", token))
                    .body(Body::from(serde_json::to_string(&remove_role_payload).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        // Should return 200 OK for role removal
        let status = response.status();
        if status != StatusCode::OK {
            let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
            let body_str = String::from_utf8_lossy(&body);
            panic!("Expected 200 OK, got {}: {}", status, body_str);
        }
    }

    #[tokio::test]
    async fn test_remove_permission_handler_http() {
        let app_state = create_test_app_state_with_comprehensive_data().await;
        let admin_user = create_admin_test_user();
        let token = generate_valid_token(&admin_user, &app_state).await;
        
        let router = Router::new()
            .route("/v1/iam/permissions/remove", post(remove_permission_handler))
            .with_state(app_state);

        let remove_permission_payload = json!({
            "role_id": "test-role",
            "permission_id": "test-permission"
        });

        let response = router
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/iam/permissions/remove")
                    .header("content-type", "application/json")
                    .header("x-user-id", admin_user.id)
                    .header("authorization", format!("Bearer {}", token))
                    .body(Body::from(serde_json::to_string(&remove_permission_payload).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        // Should return 200 OK for permission removal
        let status = response.status();
        if status != StatusCode::OK {
            let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
            let body_str = String::from_utf8_lossy(&body);
            panic!("Expected 200 OK, got {}: {}", status, body_str);
        }
    }

    #[tokio::test]
    async fn test_update_permission_group_handler_http() {
        let app_state = create_test_app_state_with_comprehensive_data().await;
        let admin_user = create_admin_test_user();
        let token = generate_valid_token(&admin_user, &app_state).await;
        
        let router = Router::new()
            .route("/v1/iam/permission-groups/{group_id}", put(update_permission_group_handler))
            .with_state(app_state);

        let update_group_payload = json!({
            "name": "updated_group_name",
            "description": "Updated description"
        });

        let response = router
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/v1/iam/permission-groups/user-management")
                    .header("content-type", "application/json")
                    .header("x-user-id", admin_user.id)
                    .header("authorization", format!("Bearer {}", token))
                    .body(Body::from(serde_json::to_string(&update_group_payload).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        // Should return 200 OK for permission group update
        let status = response.status();
        if status != StatusCode::OK {
            let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
            let body_str = String::from_utf8_lossy(&body);
            panic!("Expected 200 OK, got {}: {}", status, body_str);
        }
    }

    #[tokio::test]
    async fn test_delete_permission_group_handler_http() {
        let app_state = create_test_app_state_with_comprehensive_data().await;
        let admin_user = create_admin_test_user();
        let token = generate_valid_token(&admin_user, &app_state).await;
        
        let router = Router::new()
            .route("/v1/iam/permission-groups/{group_id}", delete(delete_permission_group_handler))
            .with_state(app_state);

        let response = router
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri("/v1/iam/permission-groups/content-management")
                    .header("x-user-id", admin_user.id)
                    .header("authorization", format!("Bearer {}", token))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        // Should return 204 No Content for permission group deletion
        let status = response.status();
        if status != StatusCode::NO_CONTENT {
            let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
            let body_str = String::from_utf8_lossy(&body);
            panic!("Expected 204 No Content, got {}: {}", status, body_str);
        }
    }

    #[tokio::test]
    async fn test_update_abac_policy_handler_http() {
        let app_state = create_test_app_state_with_comprehensive_data().await;
        let admin_user = create_admin_test_user();
        let token = generate_valid_token(&admin_user, &app_state).await;
        
        let router = Router::new()
            .route("/v1/iam/abac-policies/{policy_id}", put(update_abac_policy_handler))
            .with_state(app_state);

        let update_policy_payload = json!({
            "name": "updated_policy_name",
            "description": "Updated description",
            "conditions": {
                "resource_type": "document",
                "user_department": "engineering"
            },
            "effect": "allow"
        });

        let response = router
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/v1/iam/abac-policies/test-policy")
                    .header("content-type", "application/json")
                    .header("x-user-id", admin_user.id)
                    .header("authorization", format!("Bearer {}", token))
                    .body(Body::from(serde_json::to_string(&update_policy_payload).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        // Should return 422 Unprocessable Entity for validation failure
        let status = response.status();
        if status != StatusCode::UNPROCESSABLE_ENTITY {
            let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
            let body_str = String::from_utf8_lossy(&body);
            panic!("Expected 422 Unprocessable Entity, got {}: {}", status, body_str);
        }
    }

    #[tokio::test]
    async fn test_delete_abac_policy_handler_http() {
        let app_state = create_test_app_state_with_comprehensive_data().await;
        let admin_user = create_admin_test_user();
        let token = generate_valid_token(&admin_user, &app_state).await;
        
        let router = Router::new()
            .route("/v1/iam/abac-policies/{policy_id}", delete(delete_abac_policy_handler))
            .with_state(app_state);

        let response = router
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri("/v1/iam/abac-policies/test-policy")
                    .header("x-user-id", admin_user.id)
                    .header("authorization", format!("Bearer {}", token))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        // Should return 204 No Content for ABAC policy deletion
        let status = response.status();
        if status != StatusCode::NO_CONTENT {
            let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
            let body_str = String::from_utf8_lossy(&body);
            panic!("Expected 204 No Content, got {}: {}", status, body_str);
        }
    }

    #[tokio::test]
    async fn test_assign_abac_policy_handler_http() {
        let app_state = create_test_app_state_with_comprehensive_data().await;
        let admin_user = create_admin_test_user();
        let token = generate_valid_token(&admin_user, &app_state).await;
        
        let router = Router::new()
            .route("/v1/iam/abac-policies/assign", post(assign_abac_policy_handler))
            .with_state(app_state);

        let assign_policy_payload = json!({
            "user_id": "test-user",
            "policy_id": "test-policy"
        });

        let response = router
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/iam/abac-policies/assign")
                    .header("content-type", "application/json")
                    .header("x-user-id", admin_user.id)
                    .header("authorization", format!("Bearer {}", token))
                    .body(Body::from(serde_json::to_string(&assign_policy_payload).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        // Should return 422 Unprocessable Entity for validation failure
        let status = response.status();
        if status != StatusCode::UNPROCESSABLE_ENTITY {
            let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
            let body_str = String::from_utf8_lossy(&body);
            panic!("Expected 422 Unprocessable Entity, got {}: {}", status, body_str);
        }
    }
}
