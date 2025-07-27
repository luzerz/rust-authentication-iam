use crate::application::services::{
    AuthorizationService, PasswordResetService, PasswordService, TokenService,
};
use crate::infrastructure::{
    AbacPolicyRepository, PermissionGroupRepository, PermissionRepository, RefreshTokenRepository,
    RoleRepository, UserRepository,
};
use std::sync::Arc;

#[derive(Clone)]
pub struct AppState {
    pub user_repo: Arc<dyn UserRepository + Send + Sync>,
    pub role_repo: Arc<dyn RoleRepository + Send + Sync>,
    pub permission_repo: Arc<dyn PermissionRepository + Send + Sync>,
    pub abac_policy_repo: Arc<dyn AbacPolicyRepository + Send + Sync>,
    pub permission_group_repo: Arc<dyn PermissionGroupRepository + Send + Sync>,
    pub refresh_token_repo: Arc<dyn RefreshTokenRepository + Send + Sync>,
    pub token_service: Arc<TokenService>,
    pub password_service: Arc<PasswordService>,
    pub password_reset_service: Arc<PasswordResetService>,
    pub authorization_service: Arc<AuthorizationService>,
    pub command_bus: Arc<crate::application::command_bus::CommandBus>,
    pub query_bus: Arc<crate::application::query_bus::QueryBus>,
}
