use super::queries::{
    CheckPermissionQuery, CheckUserPermissionQuery, GetPermissionByIdQuery,
    GetPermissionGroupQuery, GetPermissionsForUserQuery, GetPermissionsInGroupQuery,
    GetRoleByIdQuery, GetRoleHierarchyQuery, GetRolePermissionsQuery, GetRolesForUserQuery,
    GetUserAuditEventsQuery, GetUserByIdQuery, ListAbacPoliciesQuery, ListPermissionGroupsQuery,
    ListPermissionsQuery, ListRoleHierarchiesQuery, ListRolesQuery, ListUsersQuery,
    PaginatedResult, PermissionReadModel, RoleReadModel, UserReadModel,
};
use super::query_bus::QueryHandler;
use super::services::{AuthError, AuthorizationService};
use crate::infrastructure::{
    AbacPolicyRepository, PermissionGroupRepository, PermissionRepository, RoleRepository,
    UserRepository,
};
use async_trait::async_trait;
use chrono::Utc;
use std::sync::Arc;
use tracing::instrument;

// ============================================================================
// QUERY HANDLERS
// ============================================================================

/// Get user by ID query handler
pub struct GetUserByIdQueryHandler {
    user_repo: Arc<dyn UserRepository + Send + Sync>,
    role_repo: Arc<dyn RoleRepository + Send + Sync>,
    permission_repo: Arc<dyn PermissionRepository + Send + Sync>,
}

impl GetUserByIdQueryHandler {
    pub fn new(
        user_repo: Arc<dyn UserRepository + Send + Sync>,
        role_repo: Arc<dyn RoleRepository + Send + Sync>,
        permission_repo: Arc<dyn PermissionRepository + Send + Sync>,
    ) -> Self {
        Self {
            user_repo,
            role_repo,
            permission_repo,
        }
    }
}

#[async_trait]
impl QueryHandler<GetUserByIdQuery> for GetUserByIdQueryHandler {
    type Result = Option<UserReadModel>;
    type Error = AuthError;

    #[instrument(name = "get_user_by_id_query_handler", skip(self, query))]
    async fn handle(&self, query: GetUserByIdQuery) -> Result<Self::Result, Self::Error> {
        let user = self
            .user_repo
            .find_by_id(&query.user_id)
            .await
            .map_err(|_| AuthError::DatabaseError)?;

        if let Some(user) = user {
            let mut roles = Vec::new();
            let permissions = Vec::new();

            if query.include_roles {
                let user_roles = self
                    .role_repo
                    .get_roles_for_user(&query.user_id)
                    .await
                    .map_err(|_| AuthError::DatabaseError)?;

                for role in user_roles {
                    let mut role_permissions = Vec::new();
                    if query.include_permissions {
                        let perms = self
                            .permission_repo
                            .get_permissions_for_role(&role.id)
                            .await
                            .map_err(|_| AuthError::DatabaseError)?;
                        role_permissions = perms
                            .into_iter()
                            .map(|p| PermissionReadModel {
                                id: p.id,
                                name: p.name,
                                description: p.description,
                                group_name: p.group_id,
                                metadata: p.metadata,
                            })
                            .collect();
                    }

                    roles.push(RoleReadModel {
                        id: role.id,
                        name: role.name,
                        description: None, // Would need to extend domain model
                        parent_role: None, // Would need to implement hierarchy
                        permissions: role_permissions,
                    });
                }
            }

            let read_model = UserReadModel {
                id: user.id,
                email: user.email,
                first_name: None, // Would need to extend domain model
                last_name: None,  // Would need to extend domain model
                is_locked: user.is_locked,
                failed_login_attempts: user.failed_login_attempts,
                created_at: Utc::now(), // Would need to extend domain model
                last_login_at: None,    // Would need to extend domain model
                roles,
                permissions,
            };

            Ok(Some(read_model))
        } else {
            Ok(None)
        }
    }
}

/// Get roles for user query handler
pub struct GetRolesForUserQueryHandler {
    role_repo: Arc<dyn RoleRepository + Send + Sync>,
}

impl GetRolesForUserQueryHandler {
    pub fn new(role_repo: Arc<dyn RoleRepository + Send + Sync>) -> Self {
        Self { role_repo }
    }
}

#[async_trait]
impl QueryHandler<GetRolesForUserQuery> for GetRolesForUserQueryHandler {
    type Result = Vec<RoleReadModel>;
    type Error = AuthError;

    #[instrument(name = "get_roles_for_user_query_handler", skip(self, query))]
    async fn handle(&self, query: GetRolesForUserQuery) -> Result<Self::Result, Self::Error> {
        let roles = self
            .role_repo
            .get_roles_for_user(&query.user_id)
            .await
            .map_err(|_| AuthError::DatabaseError)?;

        let mut result = Vec::new();
        for role in roles {
            if query.include_inherited {
                let _inherited = self
                    .role_repo
                    .get_inherited_roles(&role.id)
                    .await
                    .map_err(|_| AuthError::DatabaseError)?;
                // TODO: Use inherited roles when needed
            }

            result.push(RoleReadModel {
                id: role.id,
                name: role.name,
                description: None,
                parent_role: None,
                permissions: Vec::new(),
            });
        }

        Ok(result)
    }
}

/// Check user permission query handler
pub struct CheckUserPermissionQueryHandler {
    role_repo: Arc<dyn RoleRepository + Send + Sync>,
    permission_repo: Arc<dyn PermissionRepository + Send + Sync>,
    abac_repo: Arc<dyn AbacPolicyRepository + Send + Sync>,
}

impl CheckUserPermissionQueryHandler {
    pub fn new(
        role_repo: Arc<dyn RoleRepository + Send + Sync>,
        permission_repo: Arc<dyn PermissionRepository + Send + Sync>,
        abac_repo: Arc<dyn AbacPolicyRepository + Send + Sync>,
    ) -> Self {
        Self {
            role_repo,
            permission_repo,
            abac_repo,
        }
    }
}

#[async_trait]
impl QueryHandler<CheckUserPermissionQuery> for CheckUserPermissionQueryHandler {
    type Result = bool;
    type Error = AuthError;

    #[instrument(name = "check_user_permission_query_handler", skip(self, query))]
    async fn handle(&self, query: CheckUserPermissionQuery) -> Result<Self::Result, Self::Error> {
        let user_attrs = if let Some(context) = query.resource_context {
            // Convert context to user attributes (simplified)
            let mut attrs = std::collections::HashMap::new();
            if let Some(obj) = context.as_object() {
                for (key, value) in obj {
                    attrs.insert(key.clone(), value.to_string());
                }
            }
            Some(attrs)
        } else {
            None
        };

        let auth_service = AuthorizationService;
        auth_service
            .user_has_permission(
                &query.user_id,
                &query.permission_name,
                user_attrs.as_ref(),
                &self.role_repo,
                &self.permission_repo,
                &self.abac_repo,
            )
            .await
    }
}

/// Check permission query handler
pub struct CheckPermissionQueryHandler {
    authorization_service: AuthorizationService,
    role_repo: Arc<dyn RoleRepository + Send + Sync>,
    permission_repo: Arc<dyn PermissionRepository + Send + Sync>,
    abac_repo: Arc<dyn AbacPolicyRepository + Send + Sync>,
}

impl CheckPermissionQueryHandler {
    pub fn new(
        role_repo: Arc<dyn RoleRepository + Send + Sync>,
        permission_repo: Arc<dyn PermissionRepository + Send + Sync>,
        abac_repo: Arc<dyn AbacPolicyRepository + Send + Sync>,
    ) -> Self {
        Self {
            authorization_service: AuthorizationService,
            role_repo,
            permission_repo,
            abac_repo,
        }
    }
}

#[async_trait]
impl QueryHandler<CheckPermissionQuery> for CheckPermissionQueryHandler {
    type Result = bool;
    type Error = AuthError;

    #[instrument(name = "check_permission_query_handler", skip(self, query))]
    async fn handle(&self, query: CheckPermissionQuery) -> Result<Self::Result, Self::Error> {
        self.authorization_service
            .user_has_permission(
                &query.user_id,
                &query.permission_name,
                query.user_attributes.as_ref(),
                &self.role_repo,
                &self.permission_repo,
                &self.abac_repo,
            )
            .await
    }
}

/// List users query handler
pub struct ListUsersQueryHandler {
    _user_repo: Arc<dyn UserRepository + Send + Sync>,
    _role_repo: Arc<dyn RoleRepository + Send + Sync>,
}

impl ListUsersQueryHandler {
    pub fn new(
        user_repo: Arc<dyn UserRepository + Send + Sync>,
        role_repo: Arc<dyn RoleRepository + Send + Sync>,
    ) -> Self {
        Self {
            _user_repo: user_repo,
            _role_repo: role_repo,
        }
    }
}

#[async_trait]
impl QueryHandler<ListUsersQuery> for ListUsersQueryHandler {
    type Result = PaginatedResult<UserReadModel>;
    type Error = AuthError;

    #[instrument(name = "list_users_query_handler", skip(self, query))]
    async fn handle(&self, query: ListUsersQuery) -> Result<Self::Result, Self::Error> {
        // TODO: Implement proper pagination and filtering
        // For now, return empty result
        let users = Vec::new();
        let total_count = 0;

        Ok(PaginatedResult::new(
            users,
            total_count,
            query.page,
            query.page_size,
        ))
    }
}

/// List roles query handler
pub struct ListRolesQueryHandler {
    role_repo: Arc<dyn RoleRepository + Send + Sync>,
    _permission_repo: Arc<dyn PermissionRepository + Send + Sync>,
}

impl ListRolesQueryHandler {
    pub fn new(
        role_repo: Arc<dyn RoleRepository + Send + Sync>,
        permission_repo: Arc<dyn PermissionRepository + Send + Sync>,
    ) -> Self {
        Self {
            role_repo,
            _permission_repo: permission_repo,
        }
    }
}

#[async_trait]
impl QueryHandler<ListRolesQuery> for ListRolesQueryHandler {
    type Result = PaginatedResult<RoleReadModel>;
    type Error = AuthError;

    #[instrument(name = "list_roles_query_handler", skip(self, query))]
    async fn handle(&self, query: ListRolesQuery) -> Result<Self::Result, Self::Error> {
        let roles = self.role_repo.list_roles().await;

        let role_read_models: Vec<RoleReadModel> = roles
            .into_iter()
            .map(|role| {
                RoleReadModel {
                    id: role.id,
                    name: role.name,
                    description: None, // Role model doesn't have description field
                    parent_role: None, // TODO: Implement parent role lookup
                    permissions: Vec::new(), // TODO: Implement permissions lookup if include_permissions is true
                }
            })
            .collect();

        let total_count = role_read_models.len() as u64;
        Ok(PaginatedResult::new(
            role_read_models,
            total_count,
            query.page,
            query.page_size,
        ))
    }
}

/// List permissions query handler
pub struct ListPermissionsQueryHandler {
    permission_repo: Arc<dyn PermissionRepository + Send + Sync>,
    _permission_group_repo: Arc<dyn PermissionGroupRepository + Send + Sync>,
}

impl ListPermissionsQueryHandler {
    pub fn new(
        permission_repo: Arc<dyn PermissionRepository + Send + Sync>,
        permission_group_repo: Arc<dyn PermissionGroupRepository + Send + Sync>,
    ) -> Self {
        Self {
            permission_repo,
            _permission_group_repo: permission_group_repo,
        }
    }
}

#[async_trait]
impl QueryHandler<ListPermissionsQuery> for ListPermissionsQueryHandler {
    type Result = PaginatedResult<PermissionReadModel>;
    type Error = AuthError;

    #[instrument(name = "list_permissions_query_handler", skip(self, query))]
    async fn handle(&self, query: ListPermissionsQuery) -> Result<Self::Result, Self::Error> {
        let permissions = self
            .permission_repo
            .list_permissions()
            .await
            .map_err(|_| AuthError::DatabaseError)?;

        let permission_read_models: Vec<PermissionReadModel> = permissions
            .into_iter()
            .map(|permission| {
                PermissionReadModel {
                    id: permission.id,
                    name: permission.name,
                    description: permission.description,
                    group_name: None, // TODO: Implement group name lookup
                    metadata: serde_json::Value::Null, // TODO: Implement metadata
                }
            })
            .collect();

        let total_count = permission_read_models.len() as u64;
        Ok(PaginatedResult::new(
            permission_read_models,
            total_count,
            query.page,
            query.page_size,
        ))
    }
}

/// Get permissions for user query handler
pub struct GetPermissionsForUserQueryHandler {
    role_repo: Arc<dyn RoleRepository + Send + Sync>,
    permission_repo: Arc<dyn PermissionRepository + Send + Sync>,
    _abac_repo: Arc<dyn AbacPolicyRepository + Send + Sync>,
}

impl GetPermissionsForUserQueryHandler {
    pub fn new(
        role_repo: Arc<dyn RoleRepository + Send + Sync>,
        permission_repo: Arc<dyn PermissionRepository + Send + Sync>,
        abac_repo: Arc<dyn AbacPolicyRepository + Send + Sync>,
    ) -> Self {
        Self {
            role_repo,
            permission_repo,
            _abac_repo: abac_repo,
        }
    }
}

#[async_trait]
impl QueryHandler<GetPermissionsForUserQuery> for GetPermissionsForUserQueryHandler {
    type Result = Vec<PermissionReadModel>;
    type Error = AuthError;

    #[instrument(name = "get_permissions_for_user_query_handler", skip(self, query))]
    async fn handle(&self, query: GetPermissionsForUserQuery) -> Result<Self::Result, Self::Error> {
        // Get user roles
        let roles = self
            .role_repo
            .get_roles_for_user(&query.user_id)
            .await
            .map_err(|_| AuthError::DatabaseError)?;

        let mut all_permissions = Vec::new();

        // Get permissions from roles
        for role in roles {
            let role_permissions = self
                .permission_repo
                .get_permissions_for_role(&role.id)
                .await
                .map_err(|_| AuthError::DatabaseError)?;

            for permission in role_permissions {
                all_permissions.push(PermissionReadModel {
                    id: permission.id,
                    name: permission.name,
                    description: permission.description,
                    group_name: None,
                    metadata: serde_json::Value::Null,
                });
            }
        }

        // TODO: Add ABAC permissions if include_abac is true

        Ok(all_permissions)
    }
}

/// Get user audit events query handler
pub struct GetUserAuditEventsQueryHandler {
    // TODO: Add audit repository when implemented
}

impl GetUserAuditEventsQueryHandler {
    pub fn new() -> Self {
        Self {}
    }
}

impl Default for GetUserAuditEventsQueryHandler {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl QueryHandler<GetUserAuditEventsQuery> for GetUserAuditEventsQueryHandler {
    type Result = PaginatedResult<serde_json::Value>; // TODO: Define proper audit event type
    type Error = AuthError;

    #[instrument(name = "get_user_audit_events_query_handler", skip(self, query))]
    async fn handle(&self, query: GetUserAuditEventsQuery) -> Result<Self::Result, Self::Error> {
        // TODO: Implement audit events retrieval when audit repository is implemented
        let events = Vec::new();
        let total_count = 0;

        Ok(PaginatedResult::new(
            events,
            total_count,
            query.page,
            query.page_size,
        ))
    }
}

/// List ABAC policies query handler
pub struct ListAbacPoliciesQueryHandler {
    abac_policy_repo: Arc<dyn AbacPolicyRepository + Send + Sync>,
}

impl ListAbacPoliciesQueryHandler {
    pub fn new(abac_policy_repo: Arc<dyn AbacPolicyRepository + Send + Sync>) -> Self {
        Self { abac_policy_repo }
    }
}

#[async_trait]
impl QueryHandler<ListAbacPoliciesQuery> for ListAbacPoliciesQueryHandler {
    type Result = PaginatedResult<crate::domain::abac_policy::AbacPolicy>;
    type Error = AuthError;

    #[instrument(name = "list_abac_policies_query_handler", skip(self, query))]
    async fn handle(&self, query: ListAbacPoliciesQuery) -> Result<Self::Result, Self::Error> {
        let policies = self
            .abac_policy_repo
            .list_policies()
            .await
            .map_err(|_| AuthError::DatabaseError)?;

        let total_count = policies.len() as u64;
        Ok(PaginatedResult::new(
            policies,
            total_count,
            query.page.try_into().unwrap(),
            query.page_size.try_into().unwrap(),
        ))
    }
}

/// List permission groups query handler
pub struct ListPermissionGroupsQueryHandler {
    permission_group_repo: Arc<dyn PermissionGroupRepository + Send + Sync>,
}

impl ListPermissionGroupsQueryHandler {
    pub fn new(permission_group_repo: Arc<dyn PermissionGroupRepository + Send + Sync>) -> Self {
        Self {
            permission_group_repo,
        }
    }
}

#[async_trait]
impl QueryHandler<ListPermissionGroupsQuery> for ListPermissionGroupsQueryHandler {
    type Result = PaginatedResult<crate::domain::permission_group::PermissionGroup>;
    type Error = AuthError;

    #[instrument(name = "list_permission_groups_query_handler", skip(self, query))]
    async fn handle(&self, query: ListPermissionGroupsQuery) -> Result<Self::Result, Self::Error> {
        let groups = self
            .permission_group_repo
            .list_groups()
            .await
            .map_err(|_| AuthError::DatabaseError)?;

        let total_count = groups.len() as u64;
        Ok(PaginatedResult::new(
            groups,
            total_count,
            query.page.try_into().unwrap(),
            query.page_size.try_into().unwrap(),
        ))
    }
}

/// Get permission group query handler
pub struct GetPermissionGroupQueryHandler {
    permission_group_repo: Arc<dyn PermissionGroupRepository + Send + Sync>,
}

impl GetPermissionGroupQueryHandler {
    pub fn new(permission_group_repo: Arc<dyn PermissionGroupRepository + Send + Sync>) -> Self {
        Self {
            permission_group_repo,
        }
    }
}

#[async_trait]
impl QueryHandler<GetPermissionGroupQuery> for GetPermissionGroupQueryHandler {
    type Result = Option<crate::domain::permission_group::PermissionGroup>;
    type Error = AuthError;

    #[instrument(name = "get_permission_group_query_handler", skip(self, query))]
    async fn handle(&self, query: GetPermissionGroupQuery) -> Result<Self::Result, Self::Error> {
        let group = self
            .permission_group_repo
            .get_group(&query.group_id)
            .await
            .map_err(|_| AuthError::DatabaseError)?;

        Ok(group)
    }
}

/// Get role hierarchy query handler
pub struct GetRoleHierarchyQueryHandler {
    role_repo: Arc<dyn RoleRepository + Send + Sync>,
}

impl GetRoleHierarchyQueryHandler {
    pub fn new(role_repo: Arc<dyn RoleRepository + Send + Sync>) -> Self {
        Self { role_repo }
    }
}

#[async_trait]
impl QueryHandler<GetRoleHierarchyQuery> for GetRoleHierarchyQueryHandler {
    type Result = crate::interface::RoleHierarchyResponse;
    type Error = AuthError;

    #[instrument(name = "get_role_hierarchy_query_handler", skip(self, query))]
    async fn handle(&self, query: GetRoleHierarchyQuery) -> Result<Self::Result, Self::Error> {
        // Get the role details
        let roles = self.role_repo.list_roles().await;

        let role = roles
            .iter()
            .find(|r| r.id == query.role_id)
            .ok_or(AuthError::UserNotFound)?;

        // Get inherited roles
        let inherited_roles = self
            .role_repo
            .get_inherited_roles(&query.role_id)
            .await
            .map_err(|_| AuthError::DatabaseError)?;

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
        let inherited_role_responses: Vec<crate::interface::RoleResponse> = inherited_roles
            .into_iter()
            .map(|r| crate::interface::RoleResponse {
                id: r.id,
                name: r.name,
                permissions: r.permissions,
                parent_role_id: r.parent_role_id,
            })
            .collect();

        let response = crate::interface::RoleHierarchyResponse {
            role_id: role.id.clone(),
            role_name: role.name.clone(),
            parent_role_id: role.parent_role_id.clone(),
            parent_role_name,
            inherited_roles: inherited_role_responses,
        };

        Ok(response)
    }
}

/// List role hierarchies query handler
pub struct ListRoleHierarchiesQueryHandler {
    role_repo: Arc<dyn RoleRepository + Send + Sync>,
}

impl ListRoleHierarchiesQueryHandler {
    pub fn new(role_repo: Arc<dyn RoleRepository + Send + Sync>) -> Self {
        Self { role_repo }
    }
}

#[async_trait]
impl QueryHandler<ListRoleHierarchiesQuery> for ListRoleHierarchiesQueryHandler {
    type Result = crate::interface::RoleHierarchyListResponse;
    type Error = AuthError;

    #[instrument(name = "list_role_hierarchies_query_handler", skip(self))]
    async fn handle(&self, _query: ListRoleHierarchiesQuery) -> Result<Self::Result, Self::Error> {
        let roles = self.role_repo.list_roles().await;
        let mut hierarchies = Vec::new();

        for role in &roles {
            let inherited_roles = match self.role_repo.get_inherited_roles(&role.id).await {
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

            let inherited_role_responses: Vec<crate::interface::RoleResponse> = inherited_roles
                .into_iter()
                .map(|r| crate::interface::RoleResponse {
                    id: r.id,
                    name: r.name,
                    permissions: r.permissions,
                    parent_role_id: r.parent_role_id,
                })
                .collect();

            hierarchies.push(crate::interface::RoleHierarchyResponse {
                role_id: role.id.clone(),
                role_name: role.name.clone(),
                parent_role_id: role.parent_role_id.clone(),
                parent_role_name,
                inherited_roles: inherited_role_responses,
            });
        }

        Ok(crate::interface::RoleHierarchyListResponse { hierarchies })
    }
}

/// Get permissions in group query handler
pub struct GetPermissionsInGroupQueryHandler {
    permission_group_repo: Arc<dyn PermissionGroupRepository + Send + Sync>,
}

impl GetPermissionsInGroupQueryHandler {
    pub fn new(permission_group_repo: Arc<dyn PermissionGroupRepository + Send + Sync>) -> Self {
        Self {
            permission_group_repo,
        }
    }
}

#[async_trait]
impl QueryHandler<GetPermissionsInGroupQuery> for GetPermissionsInGroupQueryHandler {
    type Result = crate::interface::PermissionsListResponse;
    type Error = AuthError;

    #[instrument(name = "get_permissions_in_group_query_handler", skip(self, query))]
    async fn handle(&self, query: GetPermissionsInGroupQuery) -> Result<Self::Result, Self::Error> {
        let permissions = self
            .permission_group_repo
            .get_permissions_in_group(&query.group_id)
            .await
            .map_err(|_| AuthError::DatabaseError)?;

        let permission_responses: Vec<crate::interface::PermissionResponse> = permissions
            .into_iter()
            .map(|perm| crate::interface::PermissionResponse {
                id: perm.id,
                name: perm.name,
            })
            .collect();

        Ok(crate::interface::PermissionsListResponse {
            permissions: permission_responses,
        })
    }
}

/// Get role permissions query handler
pub struct GetRolePermissionsQueryHandler {
    permission_repo: Arc<dyn PermissionRepository + Send + Sync>,
}

impl GetRolePermissionsQueryHandler {
    pub fn new(permission_repo: Arc<dyn PermissionRepository + Send + Sync>) -> Self {
        Self { permission_repo }
    }
}

#[async_trait]
impl QueryHandler<GetRolePermissionsQuery> for GetRolePermissionsQueryHandler {
    type Result = crate::interface::RolePermissionsResponse;
    type Error = AuthError;

    #[instrument(name = "get_role_permissions_query_handler", skip(self, query))]
    async fn handle(&self, query: GetRolePermissionsQuery) -> Result<Self::Result, Self::Error> {
        let permissions = self
            .permission_repo
            .get_permissions_for_role(&query.role_id)
            .await
            .map_err(|_| AuthError::DatabaseError)?;

        let permission_responses: Vec<crate::interface::PermissionResponse> = permissions
            .into_iter()
            .map(|permission| crate::interface::PermissionResponse {
                id: permission.id,
                name: permission.name,
            })
            .collect();

        Ok(crate::interface::RolePermissionsResponse {
            role_id: query.role_id,
            permissions: permission_responses,
        })
    }
}

/// Get role by ID query handler
pub struct GetRoleByIdQueryHandler {
    role_repo: Arc<dyn RoleRepository + Send + Sync>,
    permission_repo: Arc<dyn PermissionRepository + Send + Sync>,
}

impl GetRoleByIdQueryHandler {
    pub fn new(
        role_repo: Arc<dyn RoleRepository + Send + Sync>,
        permission_repo: Arc<dyn PermissionRepository + Send + Sync>,
    ) -> Self {
        Self {
            role_repo,
            permission_repo,
        }
    }
}

#[async_trait]
impl QueryHandler<GetRoleByIdQuery> for GetRoleByIdQueryHandler {
    type Result = Option<RoleReadModel>;
    type Error = AuthError;

    #[instrument(name = "get_role_by_id_query_handler", skip(self, query))]
    async fn handle(&self, query: GetRoleByIdQuery) -> Result<Self::Result, Self::Error> {
        let roles = self.role_repo.list_roles().await;

        let role = roles
            .into_iter()
            .find(|r| r.id == query.role_id)
            .ok_or(AuthError::UserNotFound)?;

        let mut permissions = Vec::new();
        if query.include_permissions {
            let perms = self
                .permission_repo
                .get_permissions_for_role(&role.id)
                .await
                .map_err(|_| AuthError::DatabaseError)?;

            permissions = perms
                .into_iter()
                .map(|p| PermissionReadModel {
                    id: p.id,
                    name: p.name,
                    description: p.description,
                    group_name: p.group_id,
                    metadata: p.metadata,
                })
                .collect();
        }

        let read_model = RoleReadModel {
            id: role.id,
            name: role.name,
            description: None, // Role model doesn't have description field
            parent_role: None, // TODO: Implement parent role lookup
            permissions,
        };

        Ok(Some(read_model))
    }
}

/// Get permission by ID query handler
pub struct GetPermissionByIdQueryHandler {
    permission_repo: Arc<dyn PermissionRepository + Send + Sync>,
}

impl GetPermissionByIdQueryHandler {
    pub fn new(permission_repo: Arc<dyn PermissionRepository + Send + Sync>) -> Self {
        Self { permission_repo }
    }
}

#[async_trait]
impl QueryHandler<GetPermissionByIdQuery> for GetPermissionByIdQueryHandler {
    type Result = Option<PermissionReadModel>;
    type Error = AuthError;

    #[instrument(name = "get_permission_by_id_query_handler", skip(self, query))]
    async fn handle(&self, query: GetPermissionByIdQuery) -> Result<Self::Result, Self::Error> {
        let permission = self
            .permission_repo
            .get_permission(&query.permission_id)
            .await
            .map_err(|_| AuthError::DatabaseError)?;

        match permission {
            Some(perm) => {
                let read_model = PermissionReadModel {
                    id: perm.id,
                    name: perm.name,
                    description: perm.description,
                    group_name: perm.group_id,
                    metadata: perm.metadata,
                };
                Ok(Some(read_model))
            }
            None => Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::application::queries::QueryFactory;
    use crate::domain::user::User;
    use crate::infrastructure::{
        InMemoryAbacPolicyRepository, InMemoryPermissionGroupRepository, InMemoryPermissionRepository,
        InMemoryRoleRepository, InMemoryUserRepository,
    };

    use std::collections::HashMap;
    use std::sync::Arc;

    fn setup_test_env() {
        unsafe {
            std::env::set_var("JWT_SECRET", "test-secret-key-for-testing-only");
        }
    }

    #[tokio::test]
    async fn test_get_user_by_id_query_handler_success() {
        setup_test_env();

        let password_hash = bcrypt::hash("password123", 4).unwrap(); // Use cost 4 for faster tests
        let user = User {
            id: "user1".to_string(),
            email: "test@example.com".to_string(),
            password_hash,
            roles: vec![],
            is_locked: false,
            failed_login_attempts: 0,
        };

        let user_repo = Arc::new(InMemoryUserRepository::new(vec![user]));
        let role_repo = Arc::new(InMemoryRoleRepository::new());
        let permission_repo = Arc::new(InMemoryPermissionRepository::new());

        // Create role and assign to user
        let admin_role = role_repo.create_role("admin").await;
        role_repo.assign_role("user1", &admin_role.id).await;

        let handler = GetUserByIdQueryHandler::new(user_repo, role_repo, permission_repo);

        let query = QueryFactory::get_user_by_id(
            "user1".to_string(),
            true,
            false,
        );

        let result = handler.handle(query).await;
        assert!(result.is_ok());
        let user_read_model = result.unwrap();
        assert!(user_read_model.is_some());
        let user_read_model = user_read_model.unwrap();
        assert_eq!(user_read_model.id, "user1");
        assert_eq!(user_read_model.email, "test@example.com");
        assert_eq!(user_read_model.roles.len(), 1);
    }

    #[tokio::test]
    async fn test_get_user_by_id_query_handler_user_not_found() {
        setup_test_env();

        let user_repo = Arc::new(InMemoryUserRepository::new(vec![]));
        let role_repo = Arc::new(InMemoryRoleRepository::new());
        let permission_repo = Arc::new(InMemoryPermissionRepository::new());

        let handler = GetUserByIdQueryHandler::new(user_repo, role_repo, permission_repo);

        let query = QueryFactory::get_user_by_id(
            "nonexistent".to_string(),
            false,
            false,
        );

        let result = handler.handle(query).await;
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_get_roles_for_user_query_handler_success() {
        setup_test_env();

        let role_repo = Arc::new(InMemoryRoleRepository::new());
        let admin_role = role_repo.create_role("admin").await;
        let user_role = role_repo.create_role("user").await;

        // Assign roles to user
        role_repo.assign_role("user1", &admin_role.id).await;
        role_repo.assign_role("user1", &user_role.id).await;

        let handler = GetRolesForUserQueryHandler::new(role_repo);

        let query = QueryFactory::get_roles_for_user(
            "user1".to_string(),
            false,
        );

        let result = handler.handle(query).await;
        assert!(result.is_ok());
        let roles = result.unwrap();
        assert_eq!(roles.len(), 2); // Both roles are returned
    }

    #[tokio::test]
    async fn test_check_user_permission_query_handler_success() {
        setup_test_env();

        let role_repo = Arc::new(InMemoryRoleRepository::new());
        let permission_repo = Arc::new(InMemoryPermissionRepository::new());
        let abac_repo = Arc::new(InMemoryAbacPolicyRepository::new());

        let handler = CheckUserPermissionQueryHandler::new(role_repo, permission_repo, abac_repo);

        let query = QueryFactory::check_user_permission(
            "user1".to_string(),
            "read".to_string(),
            None,
        );

        let result = handler.handle(query).await;
        assert!(result.is_ok());
        // Should return false for non-existent user
        assert!(!result.unwrap());
    }

    #[tokio::test]
    async fn test_check_permission_query_handler_success() {
        setup_test_env();

        let role_repo = Arc::new(InMemoryRoleRepository::new());
        let permission_repo = Arc::new(InMemoryPermissionRepository::new());
        let abac_repo = Arc::new(InMemoryAbacPolicyRepository::new());

        let handler = CheckPermissionQueryHandler::new(role_repo, permission_repo, abac_repo);

        let query = QueryFactory::check_permission(
            "user1".to_string(),
            "read".to_string(),
            None,
        );

        let result = handler.handle(query).await;
        assert!(result.is_ok());
        // Should return false for non-existent user
        assert!(!result.unwrap());
    }

    #[tokio::test]
    async fn test_list_users_query_handler_success() {
        setup_test_env();

        let user_repo = Arc::new(InMemoryUserRepository::new(vec![]));
        let role_repo = Arc::new(InMemoryRoleRepository::new());

        let handler = ListUsersQueryHandler::new(user_repo, role_repo);

        let query = QueryFactory::list_users(
            1,
            10,
            None,
            None,
            None,
            None,
            None,
        );

        let result = handler.handle(query).await;
        assert!(result.is_ok());
        let paginated_result = result.unwrap();
        assert_eq!(paginated_result.items.len(), 0);
        assert_eq!(paginated_result.total_count, 0);
    }

    #[tokio::test]
    async fn test_list_roles_query_handler_success() {
        setup_test_env();

        let role_repo = Arc::new(InMemoryRoleRepository::new());
        let permission_repo = Arc::new(InMemoryPermissionRepository::new());

        // Create some roles
        role_repo.create_role("admin").await;
        role_repo.create_role("user").await;

        let handler = ListRolesQueryHandler::new(role_repo, permission_repo);

        let query = QueryFactory::list_roles(
            1,
            10,
            None,
            false,
            None,
            None,
        );

        let result = handler.handle(query).await;
        assert!(result.is_ok());
        let paginated_result = result.unwrap();
        assert_eq!(paginated_result.items.len(), 2);
        assert_eq!(paginated_result.total_count, 2);
    }

    #[tokio::test]
    async fn test_list_permissions_query_handler_success() {
        setup_test_env();

        let permission_repo = Arc::new(InMemoryPermissionRepository::new());
        let permission_group_repo = Arc::new(InMemoryPermissionGroupRepository::new());

        let handler = ListPermissionsQueryHandler::new(permission_repo, permission_group_repo);

        let query = QueryFactory::list_permissions(
            1,
            10,
            None,
            None,
            None,
            None,
        );

        let result = handler.handle(query).await;
        assert!(result.is_ok());
        let paginated_result = result.unwrap();
        assert_eq!(paginated_result.items.len(), 0);
        assert_eq!(paginated_result.total_count, 0);
    }

    #[tokio::test]
    async fn test_get_permissions_for_user_query_handler_success() {
        setup_test_env();

        let role_repo = Arc::new(InMemoryRoleRepository::new());
        let permission_repo = Arc::new(InMemoryPermissionRepository::new());
        let abac_repo = Arc::new(InMemoryAbacPolicyRepository::new());

        let handler = GetPermissionsForUserQueryHandler::new(role_repo, permission_repo, abac_repo);

        let query = QueryFactory::get_permissions_for_user(
            "user1".to_string(),
            false,
            false,
        );

        let result = handler.handle(query).await;
        assert!(result.is_ok());
        let permissions = result.unwrap();
        assert_eq!(permissions.len(), 0); // No roles assigned to user
    }

    #[tokio::test]
    async fn test_get_user_audit_events_query_handler_success() {
        setup_test_env();

        let handler = GetUserAuditEventsQueryHandler::new();

        let query = QueryFactory::get_user_audit_events(
            "user1".to_string(),
            1,
            10,
            None,
            None,
            None,
        );

        let result = handler.handle(query).await;
        assert!(result.is_ok());
        let paginated_result = result.unwrap();
        assert_eq!(paginated_result.items.len(), 0);
        assert_eq!(paginated_result.total_count, 0);
    }

    #[tokio::test]
    async fn test_list_abac_policies_query_handler_success() {
        setup_test_env();

        let abac_policy_repo = Arc::new(InMemoryAbacPolicyRepository::new());

        let handler = ListAbacPoliciesQueryHandler::new(abac_policy_repo);

        let query = QueryFactory::list_abac_policies(
            1,
            10,
            None,
            None,
            false,
            None,
            None,
        );

        let result = handler.handle(query).await;
        assert!(result.is_ok());
        let paginated_result = result.unwrap();
        assert_eq!(paginated_result.items.len(), 0);
        assert_eq!(paginated_result.total_count, 0);
    }

    #[tokio::test]
    async fn test_list_permission_groups_query_handler_success() {
        setup_test_env();

        let permission_group_repo = Arc::new(InMemoryPermissionGroupRepository::new());

        let handler = ListPermissionGroupsQueryHandler::new(permission_group_repo);

        let query = QueryFactory::list_permission_groups(
            1,
            10,
            None,
            None,
            false,
            None,
            None,
        );

        let result = handler.handle(query).await;
        assert!(result.is_ok());
        let paginated_result = result.unwrap();
        assert_eq!(paginated_result.items.len(), 0);
        assert_eq!(paginated_result.total_count, 0);
    }

    #[tokio::test]
    async fn test_get_permission_group_query_handler_success() {
        setup_test_env();

        let permission_group_repo = Arc::new(InMemoryPermissionGroupRepository::new());

        let handler = GetPermissionGroupQueryHandler::new(permission_group_repo);

        let query = QueryFactory::get_permission_group(
            "group1".to_string(),
            false,
        );

        let result = handler.handle(query).await;
        assert!(result.is_ok());
        assert!(result.unwrap().is_none()); // Group doesn't exist
    }

    #[tokio::test]
    async fn test_get_role_hierarchy_query_handler_success() {
        setup_test_env();

        let role_repo = Arc::new(InMemoryRoleRepository::new());
        let admin_role = role_repo.create_role("admin").await;

        let handler = GetRoleHierarchyQueryHandler::new(role_repo);

        let query = QueryFactory::get_role_hierarchy(
            admin_role.id.clone(),
        );

        let result = handler.handle(query).await;
        assert!(result.is_ok());
        let hierarchy = result.unwrap();
        assert_eq!(hierarchy.role_id, admin_role.id);
        assert_eq!(hierarchy.role_name, "admin");
    }

    #[tokio::test]
    async fn test_get_role_hierarchy_query_handler_role_not_found() {
        setup_test_env();

        let role_repo = Arc::new(InMemoryRoleRepository::new());

        let handler = GetRoleHierarchyQueryHandler::new(role_repo);

        let query = QueryFactory::get_role_hierarchy(
            "nonexistent".to_string(),
        );

        let result = handler.handle(query).await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AuthError::UserNotFound));
    }

    #[tokio::test]
    async fn test_list_role_hierarchies_query_handler_success() {
        setup_test_env();

        let role_repo = Arc::new(InMemoryRoleRepository::new());
        role_repo.create_role("admin").await;
        role_repo.create_role("user").await;

        let handler = ListRoleHierarchiesQueryHandler::new(role_repo);

        let query = QueryFactory::list_role_hierarchies();

        let result = handler.handle(query).await;
        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(response.hierarchies.len(), 2);
    }

    #[tokio::test]
    async fn test_get_permissions_in_group_query_handler_success() {
        setup_test_env();

        let permission_group_repo = Arc::new(InMemoryPermissionGroupRepository::new());

        let handler = GetPermissionsInGroupQueryHandler::new(permission_group_repo);

        let query = QueryFactory::get_permissions_in_group(
            "group1".to_string(),
            1,
            10,
        );

        let result = handler.handle(query).await;
        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(response.permissions.len(), 0);
    }

    #[tokio::test]
    async fn test_get_role_permissions_query_handler_success() {
        setup_test_env();

        let permission_repo = Arc::new(InMemoryPermissionRepository::new());

        let handler = GetRolePermissionsQueryHandler::new(permission_repo);

        let query = QueryFactory::get_role_permissions(
            "role1".to_string(),
        );

        let result = handler.handle(query).await;
        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(response.role_id, "role1");
        assert_eq!(response.permissions.len(), 0);
    }

    #[tokio::test]
    async fn test_get_role_by_id_query_handler_success() {
        setup_test_env();

        let role_repo = Arc::new(InMemoryRoleRepository::new());
        let permission_repo = Arc::new(InMemoryPermissionRepository::new());

        let admin_role = role_repo.create_role("admin").await;

        let handler = GetRoleByIdQueryHandler::new(role_repo, permission_repo);

        let query = QueryFactory::get_role_by_id(
            admin_role.id.clone(),
            false,
        );

        let result = handler.handle(query).await;
        assert!(result.is_ok());
        let role_read_model = result.unwrap();
        assert!(role_read_model.is_some());
        let role_read_model = role_read_model.unwrap();
        assert_eq!(role_read_model.id, admin_role.id);
        assert_eq!(role_read_model.name, "admin");
    }

    #[tokio::test]
    async fn test_get_role_by_id_query_handler_role_not_found() {
        setup_test_env();

        let role_repo = Arc::new(InMemoryRoleRepository::new());
        let permission_repo = Arc::new(InMemoryPermissionRepository::new());

        let handler = GetRoleByIdQueryHandler::new(role_repo, permission_repo);

        let query = QueryFactory::get_role_by_id(
            "nonexistent".to_string(),
            false,
        );

        let result = handler.handle(query).await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AuthError::UserNotFound));
    }

    #[tokio::test]
    async fn test_get_permission_by_id_query_handler_success() {
        setup_test_env();

        let permission_repo = Arc::new(InMemoryPermissionRepository::new());

        let handler = GetPermissionByIdQueryHandler::new(permission_repo);

        let query = QueryFactory::get_permission_by_id(
            "perm1".to_string(),
        );

        let result = handler.handle(query).await;
        assert!(result.is_ok());
        assert!(result.unwrap().is_none()); // Permission doesn't exist
    }

    #[tokio::test]
    async fn test_check_user_permission_query_handler_with_context() {
        setup_test_env();

        let role_repo = Arc::new(InMemoryRoleRepository::new());
        let permission_repo = Arc::new(InMemoryPermissionRepository::new());
        let abac_repo = Arc::new(InMemoryAbacPolicyRepository::new());

        let handler = CheckUserPermissionQueryHandler::new(role_repo, permission_repo, abac_repo);

        let mut context = HashMap::new();
        context.insert("resource_type".to_string(), serde_json::Value::String("document".to_string()));
        context.insert("user_department".to_string(), serde_json::Value::String("engineering".to_string()));

        let query = QueryFactory::check_user_permission(
            "user1".to_string(),
            "read".to_string(),
            Some(serde_json::Value::Object(context.into_iter().collect())),
        );

        let result = handler.handle(query).await;
        assert!(result.is_ok());
        assert!(!result.unwrap()); // Should return false for non-existent user
    }
}
