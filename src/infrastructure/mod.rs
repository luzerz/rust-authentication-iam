use crate::domain::abac_policy::AbacPolicy;
use crate::domain::permission::Permission;
use crate::domain::role::Role;
use async_trait::async_trait;
use sqlx::Error;
pub type RepoResult<T> = Result<T, Error>;

// Infrastructure layer: database, external services, adapters
pub mod user_repository;
pub use user_repository::InMemoryRefreshTokenRepository;
pub use user_repository::InMemoryUserRepository;
pub use user_repository::PostgresRefreshTokenRepository;
pub use user_repository::PostgresUserRepository;
pub use user_repository::RefreshTokenRepository;

#[async_trait]
pub trait UserRepository: Send + Sync {
    async fn find_by_email(&self, email: &str) -> Option<crate::domain::user::User>;
    async fn create_user(
        &self,
        user: crate::domain::user::User,
    ) -> RepoResult<crate::domain::user::User>;
    async fn update_user(&self, user: &crate::domain::user::User) -> RepoResult<()>;
    async fn update_password(&self, user_id: &str, new_password_hash: &str) -> RepoResult<()>;
    async fn find_by_id(&self, user_id: &str) -> RepoResult<Option<crate::domain::user::User>>;
}

#[async_trait]
pub trait RoleRepository: Send + Sync {
    async fn create_role(&self, name: &str) -> Role;
    async fn list_roles(&self) -> Vec<Role>;
    async fn delete_role(&self, role_id: &str);
    async fn assign_role(&self, user_id: &str, role_id: &str);
    async fn remove_role(&self, user_id: &str, role_id: &str);
    async fn get_roles_for_user(&self, user_id: &str) -> RepoResult<Vec<Role>>;
    async fn set_parent_role(&self, role_id: &str, parent_role_id: Option<&str>) -> RepoResult<()>;
    async fn get_inherited_roles(&self, role_id: &str) -> RepoResult<Vec<Role>>;
    async fn would_create_cycle(&self, role_id: &str, new_parent_id: &str) -> RepoResult<bool>;
}

#[async_trait]
pub trait PermissionRepository: Send + Sync {
    async fn create_permission(
        &self,
        name: &str,
    ) -> RepoResult<crate::domain::permission::Permission>;
    async fn get_permission(
        &self,
        permission_id: &str,
    ) -> RepoResult<Option<crate::domain::permission::Permission>>;
    async fn list_permissions(&self) -> RepoResult<Vec<crate::domain::permission::Permission>>;
    async fn delete_permission(&self, permission_id: &str) -> RepoResult<()>;
    async fn assign_permission(&self, role_id: &str, permission_id: &str) -> RepoResult<()>;
    async fn remove_permission(&self, role_id: &str, permission_id: &str) -> RepoResult<()>;
    async fn role_has_permission(&self, role_id: &str, permission_id: &str) -> RepoResult<bool>;
    async fn get_permissions_for_role(
        &self,
        role_id: &str,
    ) -> RepoResult<Vec<crate::domain::permission::Permission>>;
}

#[async_trait]
pub trait AbacPolicyRepository: Send + Sync {
    async fn create_policy(&self, policy: AbacPolicy) -> RepoResult<AbacPolicy>;
    async fn get_policy(&self, policy_id: &str) -> RepoResult<Option<AbacPolicy>>;
    async fn update_policy(&self, policy_id: &str, policy: AbacPolicy) -> RepoResult<AbacPolicy>;
    async fn list_policies(&self) -> RepoResult<Vec<AbacPolicy>>;
    async fn delete_policy(&self, policy_id: &str) -> RepoResult<()>;
    async fn assign_policy_to_user(&self, user_id: &str, policy_id: &str) -> RepoResult<()>;
    async fn assign_policy_to_role(&self, role_id: &str, policy_id: &str) -> RepoResult<()>;
    async fn get_policies_for_user(&self, user_id: &str) -> RepoResult<Vec<AbacPolicy>>;
    async fn get_policies_for_role(&self, role_id: &str) -> RepoResult<Vec<AbacPolicy>>;
}

pub mod audit_repository;
pub use audit_repository::{AuditRepository, InMemoryAuditRepository, PostgresAuditRepository};

pub mod permission_repository;
pub use permission_repository::PostgresPermissionRepository;

pub mod permission_group_repository;
pub use permission_group_repository::{
    InMemoryPermissionGroupRepository, PermissionGroupRepository, PostgresPermissionGroupRepository,
};

pub mod role_repository;
pub use role_repository::PostgresRoleRepository;

pub mod abac_policy_repository;
pub use abac_policy_repository::{InMemoryAbacPolicyRepository, PostgresAbacPolicyRepository};

pub struct InMemoryRoleRepository {
    pub roles: std::sync::Mutex<Vec<Role>>,
    pub user_roles: std::sync::Mutex<Vec<(String, String)>>, // (user_id, role_id)
}

impl InMemoryRoleRepository {
    pub fn new() -> Self {
        Self {
            roles: std::sync::Mutex::new(vec![]),
            user_roles: std::sync::Mutex::new(vec![]),
        }
    }
}

impl Default for InMemoryRoleRepository {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl RoleRepository for InMemoryRoleRepository {
    async fn create_role(&self, name: &str) -> Role {
        let role = Role {
            id: uuid::Uuid::new_v4().to_string(),
            name: name.to_string(),
            permissions: vec![],
            parent_role_id: None,
        };
        self.roles.lock().unwrap().push(role.clone());
        role
    }
    async fn list_roles(&self) -> Vec<Role> {
        self.roles.lock().unwrap().clone()
    }
    async fn delete_role(&self, role_id: &str) {
        self.roles.lock().unwrap().retain(|r| r.id != role_id);
        self.user_roles
            .lock()
            .unwrap()
            .retain(|(_, rid)| rid != role_id);
    }
    async fn assign_role(&self, user_id: &str, role_id: &str) {
        let mut user_roles = self.user_roles.lock().unwrap();
        if !user_roles
            .iter()
            .any(|(uid, rid)| uid == user_id && rid == role_id)
        {
            user_roles.push((user_id.to_string(), role_id.to_string()));
        }
    }
    async fn remove_role(&self, user_id: &str, role_id: &str) {
        self.user_roles
            .lock()
            .unwrap()
            .retain(|(uid, rid)| !(uid == user_id && rid == role_id));
    }
    async fn get_roles_for_user(&self, user_id: &str) -> RepoResult<Vec<Role>> {
        let user_roles = self.user_roles.lock().unwrap();
        let roles = self.roles.lock().unwrap();
        let mut result = vec![];
        for (uid, rid) in user_roles.iter() {
            if uid == user_id {
                if let Some(role) = roles.iter().find(|r| &r.id == rid) {
                    result.push(role.clone());
                }
            }
        }
        Ok(result)
    }

    async fn set_parent_role(&self, role_id: &str, parent_role_id: Option<&str>) -> RepoResult<()> {
        let mut roles = self.roles.lock().unwrap();
        if let Some(role) = roles.iter_mut().find(|r| r.id == role_id) {
            role.set_parent_role(parent_role_id.map(|s| s.to_string()));
            Ok(())
        } else {
            Err(sqlx::Error::RowNotFound)
        }
    }

    async fn get_inherited_roles(&self, role_id: &str) -> RepoResult<Vec<Role>> {
        let roles = self.roles.lock().unwrap();
        let mut inherited_roles = Vec::new();
        let mut current_role_id = role_id;

        while let Some(role) = roles.iter().find(|r| r.id == current_role_id) {
            if let Some(parent_id) = &role.parent_role_id {
                if let Some(parent_role) = roles.iter().find(|r| r.id == *parent_id) {
                    inherited_roles.push(parent_role.clone());
                    current_role_id = parent_id;
                } else {
                    break;
                }
            } else {
                break;
            }
        }

        Ok(inherited_roles)
    }

    async fn would_create_cycle(&self, role_id: &str, new_parent_id: &str) -> RepoResult<bool> {
        let roles = self.roles.lock().unwrap();
        let mut current_id = new_parent_id;

        while let Some(role) = roles.iter().find(|r| r.id == current_id) {
            if let Some(parent_id) = &role.parent_role_id {
                if parent_id == role_id {
                    return Ok(true);
                }
                current_id = parent_id;
            } else {
                break;
            }
        }

        Ok(false)
    }
}

pub struct InMemoryPermissionRepository {
    pub permissions: std::sync::Mutex<Vec<Permission>>,
    pub role_permissions: std::sync::Mutex<Vec<(String, String)>>, // (role_id, permission_id)
}

impl InMemoryPermissionRepository {
    pub fn new() -> Self {
        Self {
            permissions: std::sync::Mutex::new(vec![]),
            role_permissions: std::sync::Mutex::new(vec![]),
        }
    }
}

impl Default for InMemoryPermissionRepository {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl PermissionRepository for InMemoryPermissionRepository {
    async fn create_permission(&self, name: &str) -> RepoResult<Permission> {
        let permission = Permission {
            id: uuid::Uuid::new_v4().to_string(),
            name: name.to_string(),
            description: None,
            group_id: None,
            metadata: serde_json::json!({}),
            is_active: true,
        };
        self.permissions.lock().unwrap().push(permission.clone());
        Ok(permission)
    }
    async fn get_permission(&self, permission_id: &str) -> RepoResult<Option<Permission>> {
        let permissions = self.permissions.lock().unwrap();
        Ok(permissions.iter().find(|p| p.id == permission_id).cloned())
    }
    async fn list_permissions(&self) -> RepoResult<Vec<Permission>> {
        Ok(self.permissions.lock().unwrap().clone())
    }
    async fn delete_permission(&self, permission_id: &str) -> RepoResult<()> {
        self.permissions
            .lock()
            .unwrap()
            .retain(|p| p.id != permission_id);
        self.role_permissions
            .lock()
            .unwrap()
            .retain(|(_, pid)| pid != permission_id);
        Ok(())
    }
    async fn assign_permission(&self, role_id: &str, permission_id: &str) -> RepoResult<()> {
        let mut role_permissions = self.role_permissions.lock().unwrap();
        if !role_permissions
            .iter()
            .any(|(rid, pid)| rid == role_id && pid == permission_id)
        {
            role_permissions.push((role_id.to_string(), permission_id.to_string()));
        }
        Ok(())
    }
    async fn remove_permission(&self, role_id: &str, permission_id: &str) -> RepoResult<()> {
        self.role_permissions
            .lock()
            .unwrap()
            .retain(|(rid, pid)| !(rid == role_id && pid == permission_id));
        Ok(())
    }
    async fn role_has_permission(&self, role_id: &str, permission_id: &str) -> RepoResult<bool> {
        let role_permissions = self.role_permissions.lock().unwrap();
        Ok(role_permissions
            .iter()
            .any(|(rid, pid)| rid == role_id && pid == permission_id))
    }
    async fn get_permissions_for_role(&self, role_id: &str) -> RepoResult<Vec<Permission>> {
        let role_permissions = self.role_permissions.lock().unwrap();
        let permissions = self.permissions.lock().unwrap();
        let mut result = vec![];
        for (rid, pid) in role_permissions.iter() {
            if rid == role_id {
                if let Some(permission) = permissions.iter().find(|p| &p.id == pid) {
                    result.push(permission.clone());
                }
            }
        }
        Ok(result)
    }
}
