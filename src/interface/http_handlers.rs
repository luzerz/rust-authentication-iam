use axum::{extract::State, Json, response::IntoResponse};
use crate::interface::*;
use crate::interface::app_state::AppState;
use tracing::{info, error};
use axum::{extract::FromRequestParts, http::request::Parts, http::{Request, StatusCode}, middleware::Next, response::Response, body::Body};

pub struct RequirePermission {
    pub user_id: String,
}

impl<S> FromRequestParts<S> for RequirePermission
where
    S: Send + Sync,
{
    type Rejection = (axum::http::StatusCode, &'static str);
    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let user_id = parts.headers.get("x-user-id")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string())
            .ok_or((axum::http::StatusCode::UNAUTHORIZED, "Missing user id"))?;
        Ok(RequirePermission { user_id })
    }
}

pub struct AuthenticatedUser {
    pub user_id: String,
}

impl<S> FromRequestParts<S> for AuthenticatedUser
where
    S: Send + Sync,
{
    type Rejection = (StatusCode, &'static str);
    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let auth_header = parts.headers.get("authorization")
            .and_then(|v| v.to_str().ok())
            .ok_or((StatusCode::UNAUTHORIZED, "Missing Authorization header"))?;
        // Expect "Bearer <token>"
        let _token = auth_header.strip_prefix("Bearer ").ok_or((StatusCode::UNAUTHORIZED, "Invalid Authorization header"))?;
        // Validate JWT using TokenService from state (requires downcasting state to AppState)
        // For demo, just accept any token and set user_id to "demo_user"
        // In real code, extract AppState and call state.token_service.validate_token(token)
        let user_id = "demo_user".to_string();
        Ok(AuthenticatedUser { user_id })
    }
}

pub async fn jwt_auth_middleware(
    req: Request<Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    let auth_header = req.headers().get("authorization")
        .and_then(|v| v.to_str().ok());
    if let Some(auth_header) = auth_header {
        if auth_header.starts_with("Bearer ") {
            // Optionally, validate JWT here
            return Ok(next.run(req).await);
        }
    }
    Err(StatusCode::UNAUTHORIZED)
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
    State(state): State<AppState>,
    Json(payload): Json<LoginRequest>,
) -> impl IntoResponse {
    info!(email = %payload.email, event = "login_request_start");
    let cmd = crate::application::commands::LoginUserCommand {
        email: payload.email.clone(),
        password: payload.password,
    };
    let result = state.handler
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
        Ok((access_token, refresh_token)) => {
            info!(email = %payload.email, event = "login_success");
            Json(LoginResponse { access_token, refresh_token }).into_response()
        }
        Err(e) => {
            error!(email = %payload.email, error = ?e, event = "login_error");
            (axum::http::StatusCode::UNAUTHORIZED, format!("Login failed: {e:?}")).into_response()
        }
    }
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
    State(state): State<AppState>,
    Json(payload): Json<ValidateTokenRequest>,
) -> impl IntoResponse {
    let result = state.token_service.validate_token(&payload.token);
    match result {
        Ok(claims) => Json(ValidateTokenResponse {
            valid: true,
            user_id: claims.sub,
            roles: claims.roles,
        }).into_response(),
        Err(_) => Json(ValidateTokenResponse {
            valid: false,
            user_id: String::new(),
            roles: Vec::new(),
        }).into_response(),
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
    State(state): State<AppState>,
    Json(payload): Json<RefreshTokenRequest>,
) -> impl IntoResponse {
    let result = state.token_service.validate_token(&payload.refresh_token);
    match result {
        Ok(claims) => {
            let user_id = claims.sub;
            let user = state.user_repo
                .find_by_email(&user_id)
                .await;
            if let Some(user) = user {
                match state.token_service.refresh_tokens(&payload.refresh_token, &user, state.refresh_token_repo.clone()).await {
                    Ok((access_token, refresh_token)) => Json(RefreshTokenResponse { access_token, refresh_token }).into_response(),
                    Err(_) => (axum::http::StatusCode::UNAUTHORIZED, "Invalid refresh token").into_response(),
                }
            } else {
                (axum::http::StatusCode::UNAUTHORIZED, "User not found").into_response()
            }
        }
        Err(_) => (axum::http::StatusCode::UNAUTHORIZED, "Invalid refresh token").into_response(),
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
    State(state): State<AppState>,
    Json(payload): Json<LogoutRequest>,
) -> impl IntoResponse {
    let result = state.token_service.validate_token(&payload.refresh_token);
    match result {
        Ok(claims) => {
            let _ = state.refresh_token_repo.revoke(&claims.jti).await;
            Json(LogoutResponse { success: true }).into_response()
        }
        Err(_) => (axum::http::StatusCode::UNAUTHORIZED, "Invalid refresh token").into_response(),
    }
}

// --- RBAC HANDLERS ---

use axum::{extract::Path};

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
    State(state): State<AppState>,
    _auth: AuthenticatedUser, // Require JWT auth
    RequirePermission { user_id }: RequirePermission,
    Json(payload): Json<CreateRoleRequest>,
) -> impl IntoResponse {
    let allowed = state.authz_service.user_has_permission(&user_id, "rbac:manage", None).await.unwrap_or(false);
    if !allowed {
        return (axum::http::StatusCode::FORBIDDEN, "Insufficient permissions").into_response();
    }
    let role = state.role_repo.create_role(&payload.name).await;
    (axum::http::StatusCode::CREATED, Json(RoleResponse {
        id: role.id,
        name: role.name,
        permissions: role.permissions,
    })).into_response()
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
pub async fn list_roles_handler(
    State(state): State<AppState>,
) -> impl IntoResponse {
    let roles = state.role_repo.list_roles().await;
    let roles = roles.into_iter().map(|role| RoleResponse {
        id: role.id,
        name: role.name,
        permissions: role.permissions,
    }).collect();
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
    State(state): State<AppState>,
    RequirePermission { user_id }: RequirePermission,
    Path(role_id): Path<String>,
) -> impl IntoResponse {
    let allowed = state.authz_service.user_has_permission(&user_id, "rbac:manage", None).await.unwrap_or(false);
    if !allowed {
        return (axum::http::StatusCode::FORBIDDEN, "Insufficient permissions").into_response();
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
    State(state): State<AppState>,
    RequirePermission { user_id }: RequirePermission,
    Json(payload): Json<AssignRoleRequest>,
) -> impl IntoResponse {
    let allowed = state.authz_service.user_has_permission(&user_id, "rbac:manage", None).await.unwrap_or(false);
    if !allowed {
        return (axum::http::StatusCode::FORBIDDEN, "Insufficient permissions").into_response();
    }
    state.role_repo.assign_role(&payload.user_id, &payload.role_id).await;
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
    State(state): State<AppState>,
    RequirePermission { user_id }: RequirePermission,
    Json(payload): Json<RemoveRoleRequest>,
) -> impl IntoResponse {
    let allowed = state.authz_service.user_has_permission(&user_id, "rbac:manage", None).await.unwrap_or(false);
    if !allowed {
        return (axum::http::StatusCode::FORBIDDEN, "Insufficient permissions").into_response();
    }
    state.role_repo.remove_role(&payload.user_id, &payload.role_id).await;
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
    State(state): State<AppState>,
    RequirePermission { user_id }: RequirePermission,
    Json(payload): Json<CreatePermissionRequest>,
) -> impl IntoResponse {
    let allowed = state.authz_service.user_has_permission(&user_id, "rbac:manage", None).await.unwrap_or(false);
    if !allowed {
        return (axum::http::StatusCode::FORBIDDEN, "Insufficient permissions").into_response();
    }
    let perm = state.permission_repo.create_permission(&payload.name).await.unwrap();
    (axum::http::StatusCode::CREATED, Json(PermissionResponse {
        id: perm.id,
        name: perm.name,
    })).into_response()
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
pub async fn list_permissions_handler(
    State(state): State<AppState>,
) -> impl IntoResponse {
    let perms = state.permission_repo.list_permissions().await.unwrap_or_default();
    let permissions = perms.into_iter().map(|p| PermissionResponse { id: p.id, name: p.name }).collect();
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
    State(state): State<AppState>,
    RequirePermission { user_id }: RequirePermission,
    Path(permission_id): Path<String>,
) -> impl IntoResponse {
    let allowed = state.authz_service.user_has_permission(&user_id, "rbac:manage", None).await.unwrap_or(false);
    if !allowed {
        return (axum::http::StatusCode::FORBIDDEN, "Insufficient permissions").into_response();
    }
    state.permission_repo.delete_permission(&permission_id).await.unwrap();
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
    State(state): State<AppState>,
    RequirePermission { user_id }: RequirePermission,
    Json(payload): Json<AssignPermissionRequest>,
) -> impl IntoResponse {
    let allowed = state.authz_service.user_has_permission(&user_id, "rbac:manage", None).await.unwrap_or(false);
    if !allowed {
        return (axum::http::StatusCode::FORBIDDEN, "Insufficient permissions").into_response();
    }
    state.permission_repo.assign_permission(&payload.role_id, &payload.permission_id).await.unwrap();
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
    State(state): State<AppState>,
    RequirePermission { user_id }: RequirePermission,
    Json(payload): Json<RemovePermissionRequest>,
) -> impl IntoResponse {
    let allowed = state.authz_service.user_has_permission(&user_id, "rbac:manage", None).await.unwrap_or(false);
    if !allowed {
        return (axum::http::StatusCode::FORBIDDEN, "Insufficient permissions").into_response();
    }
    state.permission_repo.remove_permission(&payload.role_id, &payload.permission_id).await.unwrap();
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
    State(state): State<AppState>,
    RequirePermission { user_id }: RequirePermission,
    Json(payload): Json<AbacPolicyRequest>,
) -> impl IntoResponse {
    let allowed = state.authz_service.user_has_permission(&user_id, "rbac:manage", None).await.unwrap_or(false);
    if !allowed {
        return (axum::http::StatusCode::FORBIDDEN, "Insufficient permissions").into_response();
    }
    let id = uuid::Uuid::new_v4().to_string();
    let effect = match payload.effect.as_str() {
        "Allow" => crate::domain::abac_policy::AbacEffect::Allow,
        "Deny" => crate::domain::abac_policy::AbacEffect::Deny,
        _ => return (axum::http::StatusCode::BAD_REQUEST, "Invalid effect").into_response(),
    };
    let conditions = payload.conditions.into_iter().map(|c| crate::domain::abac_policy::AbacCondition {
        attribute: c.attribute,
        operator: c.operator,
        value: c.value,
    }).collect();
    let policy = crate::domain::abac_policy::AbacPolicy {
        id: id.clone(),
        name: payload.name,
        effect,
        conditions,
    };
    let created = state.abac_policy_repo.create_policy(policy).await.unwrap();
    let resp = AbacPolicyResponse {
        id: created.id,
        name: created.name,
        effect: match created.effect { crate::domain::abac_policy::AbacEffect::Allow => "Allow".to_string(), crate::domain::abac_policy::AbacEffect::Deny => "Deny".to_string() },
        conditions: created.conditions.into_iter().map(|c| AbacConditionDto { attribute: c.attribute, operator: c.operator, value: c.value }).collect(),
    };
    (axum::http::StatusCode::CREATED, Json(resp)).into_response()
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
    State(state): State<AppState>,
    RequirePermission { user_id }: RequirePermission,
) -> impl IntoResponse {
    let allowed = state.authz_service.user_has_permission(&user_id, "rbac:manage", None).await.unwrap_or(false);
    if !allowed {
        return (axum::http::StatusCode::FORBIDDEN, "Insufficient permissions").into_response();
    }
    let policies = state.abac_policy_repo.list_policies().await.unwrap_or_default();
    let resp = AbacPolicyListResponse {
        policies: policies.into_iter().map(|p| AbacPolicyResponse {
            id: p.id,
            name: p.name,
            effect: match p.effect { crate::domain::abac_policy::AbacEffect::Allow => "Allow".to_string(), crate::domain::abac_policy::AbacEffect::Deny => "Deny".to_string() },
            conditions: p.conditions.into_iter().map(|c| AbacConditionDto { attribute: c.attribute, operator: c.operator, value: c.value }).collect(),
        }).collect(),
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
    State(state): State<AppState>,
    RequirePermission { user_id }: RequirePermission,
    Path(policy_id): Path<String>,
) -> impl IntoResponse {
    let allowed = state.authz_service.user_has_permission(&user_id, "rbac:manage", None).await.unwrap_or(false);
    if !allowed {
        return (axum::http::StatusCode::FORBIDDEN, "Insufficient permissions").into_response();
    }
    state.abac_policy_repo.delete_policy(&policy_id).await.unwrap();
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
    State(state): State<AppState>,
    RequirePermission { user_id }: RequirePermission,
    Json(payload): Json<AssignAbacPolicyRequest>,
) -> impl IntoResponse {
    let allowed = state.authz_service.user_has_permission(&user_id, "rbac:manage", None).await.unwrap_or(false);
    if !allowed {
        return (axum::http::StatusCode::FORBIDDEN, "Insufficient permissions").into_response();
    }
    let result = match payload.target_type.as_str() {
        "user" => state.abac_policy_repo.assign_policy_to_user(&payload.target_id, &payload.policy_id).await,
        "role" => state.abac_policy_repo.assign_policy_to_role(&payload.target_id, &payload.policy_id).await,
        _ => return (axum::http::StatusCode::BAD_REQUEST, "Invalid target_type").into_response(),
    };
    match result {
        Ok(_) => axum::http::StatusCode::OK.into_response(),
        Err(_) => (axum::http::StatusCode::INTERNAL_SERVER_ERROR, "Assignment failed").into_response(),
    }
} 