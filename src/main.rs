use authentication_service::application::{
    command_bus::CommandBus,
    command_handlers::{
        AssignAbacPolicyToUserCommandHandler, AssignPermissionsToRoleCommandHandler,
        AssignRolesCommandHandler, AuthenticateUserCommandHandler, ChangePasswordCommandHandler,
        CreateAbacPolicyCommandHandler, CreatePermissionCommandHandler,
        CreatePermissionGroupCommandHandler, CreateRoleCommandHandler, CreateUserCommandHandler,
        DeleteAbacPolicyCommandHandler, DeletePermissionCommandHandler,
        DeletePermissionGroupCommandHandler, DeleteRoleCommandHandler,
        EvaluateAbacPoliciesCommandHandler, LogoutCommandHandler, RefreshTokenCommandHandler,
        RemovePermissionsFromRoleCommandHandler, RemoveRolesFromUserCommandHandler,
        ResetPasswordCommandHandler, SetParentRoleCommandHandler, ToggleUserLockCommandHandler,
        UpdateAbacPolicyCommandHandler, UpdatePermissionCommandHandler,
        UpdatePermissionGroupCommandHandler, UpdateRoleCommandHandler,
        UpdateUserProfileCommandHandler, ValidateTokenCommandHandler,
    },
    commands::{
        AssignAbacPolicyToUserCommand, AssignPermissionsToRoleCommand, AssignRolesCommand,
        AuthenticateUserCommand, ChangePasswordCommand, CreateAbacPolicyCommand,
        CreatePermissionCommand, CreatePermissionGroupCommand, CreateRoleCommand,
        CreateUserCommand, DeleteAbacPolicyCommand, DeletePermissionCommand,
        DeletePermissionGroupCommand, DeleteRoleCommand, EvaluateAbacPoliciesCommand,
        LogoutCommand, RefreshTokenCommand, RemovePermissionsFromRoleCommand,
        RemoveRolesFromUserCommand, ResetPasswordCommand, SetParentRoleCommand,
        ToggleUserLockCommand, UpdateAbacPolicyCommand, UpdatePermissionCommand,
        UpdatePermissionGroupCommand, UpdateRoleCommand, UpdateUserProfileCommand,
        ValidateTokenCommand,
    },
    queries::{
        CheckPermissionQuery, CheckUserPermissionQuery, GetPermissionByIdQuery,
        GetPermissionGroupQuery, GetPermissionsForUserQuery, GetPermissionsInGroupQuery,
        GetRoleByIdQuery, GetRoleHierarchyQuery, GetRolePermissionsQuery, GetRolesForUserQuery,
        GetUserAuditEventsQuery, GetUserByIdQuery, ListAbacPoliciesQuery,
        ListPermissionGroupsQuery, ListPermissionsQuery, ListRoleHierarchiesQuery, ListRolesQuery,
        ListUsersQuery,
    },
    query_bus::QueryBus,
    query_handlers::{
        CheckPermissionQueryHandler, CheckUserPermissionQueryHandler,
        GetPermissionByIdQueryHandler, GetPermissionGroupQueryHandler,
        GetPermissionsForUserQueryHandler, GetPermissionsInGroupQueryHandler,
        GetRoleByIdQueryHandler, GetRoleHierarchyQueryHandler, GetRolePermissionsQueryHandler,
        GetRolesForUserQueryHandler, GetUserAuditEventsQueryHandler, GetUserByIdQueryHandler,
        ListAbacPoliciesQueryHandler, ListPermissionGroupsQueryHandler,
        ListPermissionsQueryHandler, ListRoleHierarchiesQueryHandler, ListRolesQueryHandler,
        ListUsersQueryHandler,
    },
    services::{AuthorizationService, PasswordResetService, PasswordService, TokenService},
};
use authentication_service::infrastructure::{
    AbacPolicyRepository, PermissionGroupRepository, PermissionRepository,
    PostgresAbacPolicyRepository, PostgresPermissionGroupRepository, PostgresPermissionRepository,
    PostgresRefreshTokenRepository, PostgresRoleRepository, PostgresUserRepository,
    RefreshTokenRepository, RoleRepository, UserRepository,
};
use authentication_service::interface::{
    AbacConditionDto,
    AbacEvaluationRequest,
    AbacEvaluationResponse,
    AbacPolicyEvaluationResult,
    AbacPolicyListResponse,
    AbacPolicyRequest,
    AbacPolicyResponse,
    AppState,
    AssignAbacPolicyRequest,
    AssignPermissionRequest,
    AssignRoleRequest,
    CreatePermissionGroupRequest,
    CreatePermissionRequest,
    CreateRoleRequest,
    EffectivePermissionsResponse,
    // DTOs
    LoginRequest,
    LoginResponse,
    LogoutRequest,
    LogoutResponse,
    PermissionGroupListResponse,
    PermissionGroupResponse,
    PermissionResponse,
    PermissionsListResponse,
    RefreshTokenRequest,
    RefreshTokenResponse,
    RemovePermissionRequest,
    RemoveRoleRequest,
    RolePermissionsResponse,
    RoleResponse,
    RolesListResponse,
    UpdateAbacPolicyRequest,
    UpdatePermissionGroupRequest,
    UserRolesResponse,
    ValidateTokenRequest,
    ValidateTokenResponse,
    assign_abac_policy_handler,
    assign_permission_handler,
    assign_role_handler,
    change_password_handler,
    confirm_password_reset_handler,
    create_abac_policy_handler,
    create_permission_group_handler,
    create_permission_handler,
    create_role_handler,
    create_role_hierarchy_handler,
    delete_abac_policy_handler,
    delete_permission_group_handler,
    delete_permission_handler,
    delete_role_handler,
    evaluate_abac_policies_handler,
    get_effective_permissions_handler,
    get_permission_group_handler,
    get_permission_handler,
    get_permissions_in_group_handler,
    get_role_handler,
    get_role_hierarchy_handler,
    list_abac_policies_handler,
    list_permission_groups_handler,
    list_permissions_handler,
    list_role_hierarchies_handler,
    list_role_permissions_handler,
    list_roles_handler,
    list_user_roles_handler,
    login_handler,
    logout_handler,
    refresh_token_handler,
    register_user_handler,
    remove_permission_handler,
    remove_role_handler,
    request_password_reset_handler,
    set_parent_role_handler,
    update_abac_policy_handler,
    update_permission_group_handler,
    update_permission_handler,
    update_role_handler,
    validate_token_handler,
};
use axum::{Router, routing::post};
use axum::{extract::FromRequestParts, http::request::Parts};
use dotenvy::dotenv;
use sqlx::PgPool;
use std::env;
use std::sync::Arc;
use tokio::net::TcpListener;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(
        authentication_service::interface::http_handlers::login_handler,
        authentication_service::interface::http_handlers::validate_token_handler,
        authentication_service::interface::http_handlers::refresh_token_handler,
        authentication_service::interface::http_handlers::logout_handler,
        authentication_service::interface::http_handlers::create_role_handler,
        authentication_service::interface::http_handlers::list_roles_handler,
        authentication_service::interface::http_handlers::delete_role_handler,
        authentication_service::interface::http_handlers::assign_role_handler,
        authentication_service::interface::http_handlers::remove_role_handler,
        authentication_service::interface::http_handlers::set_parent_role_handler,
        authentication_service::interface::http_handlers::get_role_hierarchy_handler,
        authentication_service::interface::http_handlers::list_role_hierarchies_handler,
        authentication_service::interface::http_handlers::list_user_roles_handler,
        authentication_service::interface::http_handlers::get_effective_permissions_handler,
        authentication_service::interface::http_handlers::list_role_permissions_handler,
        authentication_service::interface::http_handlers::create_permission_handler,
        authentication_service::interface::http_handlers::list_permissions_handler,
        authentication_service::interface::http_handlers::delete_permission_handler,
        authentication_service::interface::http_handlers::assign_permission_handler,
        authentication_service::interface::http_handlers::remove_permission_handler,
        authentication_service::interface::http_handlers::create_permission_group_handler,
        authentication_service::interface::http_handlers::list_permission_groups_handler,
        authentication_service::interface::http_handlers::get_permission_group_handler,
        authentication_service::interface::http_handlers::update_permission_group_handler,
        authentication_service::interface::http_handlers::delete_permission_group_handler,
        authentication_service::interface::http_handlers::get_permissions_in_group_handler,
        authentication_service::interface::http_handlers::create_abac_policy_handler,
        authentication_service::interface::http_handlers::list_abac_policies_handler,
        authentication_service::interface::http_handlers::update_abac_policy_handler,
        authentication_service::interface::http_handlers::delete_abac_policy_handler,
        authentication_service::interface::http_handlers::assign_abac_policy_handler,
        authentication_service::interface::http_handlers::evaluate_abac_policies_handler,
    ),
    components(schemas(
        LoginRequest, LoginResponse, ValidateTokenRequest, ValidateTokenResponse, RefreshTokenRequest, RefreshTokenResponse, LogoutRequest, LogoutResponse,
        CreateRoleRequest, RoleResponse, RolesListResponse, AssignRoleRequest, RemoveRoleRequest, UserRolesResponse, EffectivePermissionsResponse, RolePermissionsResponse, CreatePermissionRequest, PermissionResponse, PermissionsListResponse, AssignPermissionRequest, RemovePermissionRequest, CreatePermissionGroupRequest, UpdatePermissionGroupRequest, PermissionGroupResponse, PermissionGroupListResponse, AbacPolicyRequest, UpdateAbacPolicyRequest, AbacPolicyResponse, AbacPolicyListResponse, AssignAbacPolicyRequest, AbacConditionDto, AbacEvaluationRequest, AbacEvaluationResponse, AbacPolicyEvaluationResult
    )),
    tags(
        (name = "Auth", description = "Authentication endpoints"),
        (name = "RBAC", description = "Role-based access control endpoints"),
        (name = "Permission Groups", description = "Permission group management endpoints"),
        (name = "ABAC", description = "Attribute-based access control endpoints")
    ),
    security((), ("bearerAuth" = [])),
    modifiers(&SecurityAddon)
)]
pub struct ApiDoc;

// Add a security scheme modifier
pub struct SecurityAddon;

impl utoipa::Modify for SecurityAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        use utoipa::openapi::security::{HttpAuthScheme, HttpBuilder, SecurityScheme};
        openapi.components.as_mut().unwrap().add_security_scheme(
            "bearerAuth",
            SecurityScheme::Http(
                HttpBuilder::new()
                    .scheme(HttpAuthScheme::Bearer)
                    .bearer_format("JWT")
                    .build(),
            ),
        );
    }
}

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

fn init_tracing() {
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::from_default_env())
        .with(tracing_subscriber::fmt::layer())
        .init();
}

#[tokio::main]
async fn main() {
    dotenv().ok();
    init_tracing();
    let db_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let pool = PgPool::connect(&db_url)
        .await
        .expect("Failed to connect to DB");
    let user_repo = Arc::new(PostgresUserRepository::new(pool.clone())) as Arc<dyn UserRepository>;
    let refresh_token_repo = Arc::new(PostgresRefreshTokenRepository::new(pool.clone()))
        as Arc<dyn RefreshTokenRepository>;
    let token_service = Arc::new(TokenService);
    let password_service = Arc::new(PasswordService);
    let password_reset_service = Arc::new(PasswordResetService);
    let authorization_service = Arc::new(AuthorizationService);

    let role_repo = Arc::new(PostgresRoleRepository::new(pool.clone())) as Arc<dyn RoleRepository>;
    let permission_repo =
        Arc::new(PostgresPermissionRepository::new(pool.clone())) as Arc<dyn PermissionRepository>;
    let permission_group_repo = Arc::new(PostgresPermissionGroupRepository::new(pool.clone()))
        as Arc<dyn PermissionGroupRepository>;
    let abac_policy_repo =
        Arc::new(PostgresAbacPolicyRepository::new(pool.clone())) as Arc<dyn AbacPolicyRepository>;

    // Create CQRS buses
    let command_bus = Arc::new(CommandBus::new());
    let query_bus = Arc::new(QueryBus::new());

    // Register command handlers
    command_bus
        .register_handler::<AuthenticateUserCommand, _>(AuthenticateUserCommandHandler::new(
            user_repo.clone(),
        ))
        .await;

    command_bus
        .register_handler::<CreateUserCommand, _>(CreateUserCommandHandler::new(
            user_repo.clone(),
            role_repo.clone(),
        ))
        .await;

    command_bus
        .register_handler::<ChangePasswordCommand, _>(ChangePasswordCommandHandler::new(
            user_repo.clone(),
        ))
        .await;

    command_bus
        .register_handler::<AssignRolesCommand, _>(AssignRolesCommandHandler::new(
            role_repo.clone(),
            user_repo.clone(),
        ))
        .await;

    command_bus
        .register_handler::<CreatePermissionCommand, _>(CreatePermissionCommandHandler::new(
            permission_repo.clone(),
            permission_group_repo.clone(),
        ))
        .await;

    command_bus
        .register_handler::<DeletePermissionCommand, _>(DeletePermissionCommandHandler::new(
            permission_repo.clone(),
        ))
        .await;

    command_bus
        .register_handler::<RemovePermissionsFromRoleCommand, _>(
            RemovePermissionsFromRoleCommandHandler::new(
                role_repo.clone(),
                permission_repo.clone(),
            ),
        )
        .await;

    command_bus
        .register_handler::<RemoveRolesFromUserCommand, _>(RemoveRolesFromUserCommandHandler::new(
            role_repo.clone(),
            user_repo.clone(),
        ))
        .await;

    command_bus
        .register_handler::<DeleteRoleCommand, _>(DeleteRoleCommandHandler::new(role_repo.clone()))
        .await;

    command_bus
        .register_handler::<CreateAbacPolicyCommand, _>(CreateAbacPolicyCommandHandler::new(
            abac_policy_repo.clone(),
        ))
        .await;

    command_bus
        .register_handler::<UpdateAbacPolicyCommand, _>(UpdateAbacPolicyCommandHandler::new(
            abac_policy_repo.clone(),
        ))
        .await;

    command_bus
        .register_handler::<DeleteAbacPolicyCommand, _>(DeleteAbacPolicyCommandHandler::new(
            abac_policy_repo.clone(),
        ))
        .await;

    command_bus
        .register_handler::<AssignAbacPolicyToUserCommand, _>(
            AssignAbacPolicyToUserCommandHandler::new(abac_policy_repo.clone()),
        )
        .await;

    command_bus
        .register_handler::<CreatePermissionGroupCommand, _>(
            CreatePermissionGroupCommandHandler::new(permission_group_repo.clone()),
        )
        .await;

    command_bus
        .register_handler::<UpdatePermissionGroupCommand, _>(
            UpdatePermissionGroupCommandHandler::new(permission_group_repo.clone()),
        )
        .await;

    command_bus
        .register_handler::<DeletePermissionGroupCommand, _>(
            DeletePermissionGroupCommandHandler::new(permission_group_repo.clone()),
        )
        .await;

    command_bus
        .register_handler::<CreateRoleCommand, _>(CreateRoleCommandHandler::new(role_repo.clone()))
        .await;

    command_bus
        .register_handler::<AssignPermissionsToRoleCommand, _>(
            AssignPermissionsToRoleCommandHandler::new(role_repo.clone(), permission_repo.clone()),
        )
        .await;

    command_bus
        .register_handler::<UpdateUserProfileCommand, _>(UpdateUserProfileCommandHandler::new(
            user_repo.clone(),
        ))
        .await;

    command_bus
        .register_handler::<ToggleUserLockCommand, _>(ToggleUserLockCommandHandler::new(
            user_repo.clone(),
        ))
        .await;

    command_bus
        .register_handler::<ResetPasswordCommand, _>(ResetPasswordCommandHandler::new(
            user_repo.clone(),
        ))
        .await;

    command_bus
        .register_handler::<ValidateTokenCommand, _>(ValidateTokenCommandHandler::new())
        .await;

    command_bus
        .register_handler::<RefreshTokenCommand, _>(RefreshTokenCommandHandler::new(
            user_repo.clone(),
            refresh_token_repo.clone(),
        ))
        .await;

    command_bus
        .register_handler::<LogoutCommand, _>(LogoutCommandHandler::new(refresh_token_repo.clone()))
        .await;

    command_bus
        .register_handler::<EvaluateAbacPoliciesCommand, _>(
            EvaluateAbacPoliciesCommandHandler::new(abac_policy_repo.clone()),
        )
        .await;

    command_bus
        .register_handler::<SetParentRoleCommand, _>(SetParentRoleCommandHandler::new(
            role_repo.clone(),
        ))
        .await;

    command_bus
        .register_handler::<UpdateRoleCommand, _>(UpdateRoleCommandHandler::new(role_repo.clone()))
        .await;

    command_bus
        .register_handler::<UpdatePermissionCommand, _>(UpdatePermissionCommandHandler::new(
            permission_repo.clone(),
        ))
        .await;

    // Register query handlers
    query_bus
        .register_handler::<GetUserByIdQuery, _>(GetUserByIdQueryHandler::new(
            user_repo.clone(),
            role_repo.clone(),
            permission_repo.clone(),
        ))
        .await;

    query_bus
        .register_handler::<CheckPermissionQuery, _>(CheckPermissionQueryHandler::new(
            role_repo.clone(),
            permission_repo.clone(),
            abac_policy_repo.clone(),
        ))
        .await;

    query_bus
        .register_handler::<GetUserByIdQuery, _>(GetUserByIdQueryHandler::new(
            user_repo.clone(),
            role_repo.clone(),
            permission_repo.clone(),
        ))
        .await;

    query_bus
        .register_handler::<GetRolesForUserQuery, _>(GetRolesForUserQueryHandler::new(
            role_repo.clone(),
        ))
        .await;

    query_bus
        .register_handler::<CheckUserPermissionQuery, _>(CheckUserPermissionQueryHandler::new(
            role_repo.clone(),
            permission_repo.clone(),
            abac_policy_repo.clone(),
        ))
        .await;

    query_bus
        .register_handler::<ListUsersQuery, _>(ListUsersQueryHandler::new(
            user_repo.clone(),
            role_repo.clone(),
        ))
        .await;

    query_bus
        .register_handler::<ListRolesQuery, _>(ListRolesQueryHandler::new(
            role_repo.clone(),
            permission_repo.clone(),
        ))
        .await;

    query_bus
        .register_handler::<ListPermissionsQuery, _>(ListPermissionsQueryHandler::new(
            permission_repo.clone(),
            permission_group_repo.clone(),
        ))
        .await;

    query_bus
        .register_handler::<GetPermissionsForUserQuery, _>(GetPermissionsForUserQueryHandler::new(
            role_repo.clone(),
            permission_repo.clone(),
            abac_policy_repo.clone(),
        ))
        .await;

    query_bus
        .register_handler::<GetUserAuditEventsQuery, _>(GetUserAuditEventsQueryHandler::new())
        .await;

    query_bus
        .register_handler::<ListAbacPoliciesQuery, _>(ListAbacPoliciesQueryHandler::new(
            abac_policy_repo.clone(),
        ))
        .await;

    query_bus
        .register_handler::<ListPermissionGroupsQuery, _>(ListPermissionGroupsQueryHandler::new(
            permission_group_repo.clone(),
        ))
        .await;

    query_bus
        .register_handler::<GetPermissionGroupQuery, _>(GetPermissionGroupQueryHandler::new(
            permission_group_repo.clone(),
        ))
        .await;

    query_bus
        .register_handler::<GetRoleHierarchyQuery, _>(GetRoleHierarchyQueryHandler::new(
            role_repo.clone(),
        ))
        .await;

    query_bus
        .register_handler::<ListRoleHierarchiesQuery, _>(ListRoleHierarchiesQueryHandler::new(
            role_repo.clone(),
        ))
        .await;

    query_bus
        .register_handler::<GetPermissionsInGroupQuery, _>(GetPermissionsInGroupQueryHandler::new(
            permission_group_repo.clone(),
        ))
        .await;

    query_bus
        .register_handler::<GetRolePermissionsQuery, _>(GetRolePermissionsQueryHandler::new(
            permission_repo.clone(),
        ))
        .await;

    query_bus
        .register_handler::<GetRoleByIdQuery, _>(GetRoleByIdQueryHandler::new(
            role_repo.clone(),
            permission_repo.clone(),
        ))
        .await;

    query_bus
        .register_handler::<GetPermissionByIdQuery, _>(GetPermissionByIdQueryHandler::new(
            permission_repo.clone(),
        ))
        .await;

    let app_state = Arc::new(AppState {
        user_repo,
        role_repo,
        permission_repo,
        abac_policy_repo,
        permission_group_repo,
        refresh_token_repo,
        token_service,
        password_service,
        password_reset_service,
        authorization_service,
        command_bus,
        query_bus,
    });

    let http_host = env::var("HTTP_HOST").unwrap_or_else(|_| "127.0.0.1".to_string());
    let http_port = env::var("HTTP_PORT").unwrap_or_else(|_| "8080".to_string());
    let http_addr = format!("{http_host}:{http_port}");

    let api_mode = env::var("API_MODE").unwrap_or_else(|_| "both".to_string());

    let openapi = ApiDoc::openapi();
    let http_server = async {
        let v1_routes = Router::new()
            .route("/iam/login", post(login_handler))
            .route("/iam/register", post(register_user_handler))
            .route("/iam/validate-token", post(validate_token_handler))
            .route("/iam/refresh-token", post(refresh_token_handler))
            .route("/iam/logout", post(logout_handler))
            .route("/iam/password-change", post(change_password_handler))
            .route("/iam/password-reset", post(request_password_reset_handler))
            .route(
                "/iam/password-reset-confirm",
                post(confirm_password_reset_handler),
            )
            .route("/iam/roles", post(create_role_handler))
            .route("/iam/roles", axum::routing::get(list_roles_handler))
            .route("/iam/roles/{role_id}", axum::routing::get(get_role_handler))
            .route(
                "/iam/roles/{role_id}",
                axum::routing::put(update_role_handler),
            )
            .route(
                "/iam/roles/{role_id}",
                axum::routing::delete(delete_role_handler),
            )
            .route(
                "/iam/roles/{role_id}/permissions",
                axum::routing::get(list_role_permissions_handler),
            )
            .route(
                "/iam/roles/{role_id}/parent",
                axum::routing::put(set_parent_role_handler),
            )
            .route(
                "/iam/roles/{role_id}/hierarchy",
                axum::routing::get(get_role_hierarchy_handler),
            )
            .route("/iam/roles/hierarchy", post(create_role_hierarchy_handler))
            .route(
                "/iam/roles/hierarchies",
                axum::routing::get(list_role_hierarchies_handler),
            )
            .route("/iam/roles/assign", post(assign_role_handler))
            .route("/iam/roles/remove", post(remove_role_handler))
            .route(
                "/iam/users/{user_id}/roles",
                axum::routing::get(list_user_roles_handler),
            )
            .route(
                "/iam/users/{user_id}/effective-permissions",
                axum::routing::get(get_effective_permissions_handler),
            )
            .route("/iam/permissions", post(create_permission_handler))
            .route(
                "/iam/permissions",
                axum::routing::get(list_permissions_handler),
            )
            .route(
                "/iam/permissions/{permission_id}",
                axum::routing::get(get_permission_handler),
            )
            .route(
                "/iam/permissions/{permission_id}",
                axum::routing::put(update_permission_handler),
            )
            .route(
                "/iam/permissions/{permission_id}",
                axum::routing::delete(delete_permission_handler),
            )
            .route("/iam/permissions/assign", post(assign_permission_handler))
            .route("/iam/permissions/remove", post(remove_permission_handler))
            .route(
                "/iam/permission-groups",
                post(create_permission_group_handler),
            )
            .route(
                "/iam/permission-groups",
                axum::routing::get(list_permission_groups_handler),
            )
            .route(
                "/iam/permission-groups/{group_id}",
                axum::routing::get(get_permission_group_handler),
            )
            .route(
                "/iam/permission-groups/{group_id}",
                axum::routing::put(update_permission_group_handler),
            )
            .route(
                "/iam/permission-groups/{group_id}",
                axum::routing::delete(delete_permission_group_handler),
            )
            .route(
                "/iam/permission-groups/{group_id}/permissions",
                axum::routing::get(get_permissions_in_group_handler),
            )
            .route("/iam/abac/policies", post(create_abac_policy_handler))
            .route(
                "/iam/abac/policies",
                axum::routing::get(list_abac_policies_handler),
            )
            .route(
                "/iam/abac/policies/{policy_id}",
                axum::routing::put(update_abac_policy_handler),
            )
            .route(
                "/iam/abac/policies/{policy_id}",
                axum::routing::delete(delete_abac_policy_handler),
            )
            .route("/iam/abac/assign", post(assign_abac_policy_handler))
            .route("/iam/abac/evaluate", post(evaluate_abac_policies_handler));
        let app = Router::new()
            .nest("/v1", v1_routes)
            .merge(SwaggerUi::new("/swagger").url("/openapi.json", openapi.clone()))
            .with_state(app_state);
        let listener = TcpListener::bind(&http_addr).await.expect("Failed to bind");
        println!("HTTP server running at http://{http_addr}");
        axum::serve(listener, app).await.unwrap();
    };

    match api_mode.as_str() {
        "http" => http_server.await,
        _ => http_server.await,
    }
}
