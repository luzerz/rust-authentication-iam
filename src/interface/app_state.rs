use crate::application::handlers::LoginUserHandler;
use crate::application::services::{AuthService, AuthZService, PasswordService, TokenService};
use crate::infrastructure::{
    AbacPolicyRepository, PermissionGroupRepository, PermissionRepository, RefreshTokenRepository,
    RoleRepository, UserRepository,
};
use std::sync::Arc;

#[derive(Clone)]
pub struct AppState {
    pub user_repo: Arc<dyn UserRepository>,
    pub refresh_token_repo: Arc<dyn RefreshTokenRepository>,
    pub auth_service: Arc<AuthService>,
    pub token_service: Arc<TokenService>,
    pub password_service: Arc<PasswordService>,
    pub handler: Arc<LoginUserHandler>,
    pub role_repo: Arc<dyn RoleRepository>,
    pub permission_repo: Arc<dyn PermissionRepository>,
    pub permission_group_repo: Arc<dyn PermissionGroupRepository>,
    pub abac_policy_repo: Arc<dyn AbacPolicyRepository>,
    pub authz_service: Arc<AuthZService>,
}
