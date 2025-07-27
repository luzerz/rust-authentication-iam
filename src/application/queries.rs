use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Base trait for all queries
pub trait Query: Send + Sync {
    fn query_id(&self) -> &str;
    fn timestamp(&self) -> DateTime<Utc>;
    fn user_id(&self) -> Option<&str>;
}

/// Query to get a user by ID
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetUserByIdQuery {
    pub query_id: String,
    pub timestamp: DateTime<Utc>,
    pub user_id: String,
    pub include_roles: bool,
    pub include_permissions: bool,
}

/// Query to get roles for a user
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetRolesForUserQuery {
    pub query_id: String,
    pub timestamp: DateTime<Utc>,
    pub user_id: String,
    pub include_inherited: bool,
}

/// Query to get permissions for a user
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetPermissionsForUserQuery {
    pub query_id: String,
    pub timestamp: DateTime<Utc>,
    pub user_id: String,
    pub include_inherited: bool,
    pub include_abac: bool,
}

/// Query to list users with filtering and pagination
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListUsersQuery {
    pub query_id: String,
    pub timestamp: DateTime<Utc>,
    pub page: u32,
    pub page_size: u32,
    pub email_filter: Option<String>,
    pub role_filter: Option<String>,
    pub is_locked_filter: Option<bool>,
    pub sort_by: Option<String>,
    pub sort_order: Option<SortOrder>,
}

/// Query to list roles with filtering and pagination
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListRolesQuery {
    pub query_id: String,
    pub timestamp: DateTime<Utc>,
    pub page: u32,
    pub page_size: u32,
    pub name_filter: Option<String>,
    pub include_permissions: bool,
    pub sort_by: Option<String>,
    pub sort_order: Option<SortOrder>,
}

/// Query to list permissions with filtering and pagination
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListPermissionsQuery {
    pub query_id: String,
    pub timestamp: DateTime<Utc>,
    pub page: u32,
    pub page_size: u32,
    pub name_filter: Option<String>,
    pub group_filter: Option<String>,
    pub sort_by: Option<String>,
    pub sort_order: Option<SortOrder>,
}

/// Query to check if user has specific permission
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckUserPermissionQuery {
    pub query_id: String,
    pub timestamp: DateTime<Utc>,
    pub user_id: String,
    pub permission_name: String,
    pub resource_context: Option<serde_json::Value>,
}

/// Query to get user audit events
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetUserAuditEventsQuery {
    pub query_id: String,
    pub timestamp: DateTime<Utc>,
    pub user_id: String,
    pub page: u32,
    pub page_size: u32,
    pub event_type_filter: Option<String>,
    pub date_from: Option<DateTime<Utc>>,
    pub date_to: Option<DateTime<Utc>>,
}

/// Query to list ABAC policies
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListAbacPoliciesQuery {
    pub query_id: String,
    pub timestamp: DateTime<Utc>,
    pub page: u64,
    pub page_size: u64,
    pub name_filter: Option<String>,
    pub effect_filter: Option<String>,
    pub include_conditions: bool,
    pub sort_by: Option<String>,
    pub sort_order: Option<SortOrder>,
}

/// Query to list permission groups
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListPermissionGroupsQuery {
    pub query_id: String,
    pub timestamp: DateTime<Utc>,
    pub page: u64,
    pub page_size: u64,
    pub name_filter: Option<String>,
    pub category_filter: Option<String>,
    pub include_permissions: bool,
    pub sort_by: Option<String>,
    pub sort_order: Option<SortOrder>,
}

/// Sort order enum
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum SortOrder {
    Asc,
    Desc,
}

/// Query factory for creating queries with proper defaults
pub struct QueryFactory;

impl QueryFactory {
    pub fn get_user_by_id(
        user_id: String,
        include_roles: bool,
        include_permissions: bool,
    ) -> GetUserByIdQuery {
        GetUserByIdQuery {
            query_id: Uuid::new_v4().to_string(),
            timestamp: Utc::now(),
            user_id,
            include_roles,
            include_permissions,
        }
    }

    pub fn get_roles_for_user(user_id: String, include_inherited: bool) -> GetRolesForUserQuery {
        GetRolesForUserQuery {
            query_id: Uuid::new_v4().to_string(),
            timestamp: Utc::now(),
            user_id,
            include_inherited,
        }
    }

    pub fn get_permissions_for_user(
        user_id: String,
        include_inherited: bool,
        include_abac: bool,
    ) -> GetPermissionsForUserQuery {
        GetPermissionsForUserQuery {
            query_id: Uuid::new_v4().to_string(),
            timestamp: Utc::now(),
            user_id,
            include_inherited,
            include_abac,
        }
    }

    pub fn list_users(
        page: u32,
        page_size: u32,
        email_filter: Option<String>,
        role_filter: Option<String>,
        is_locked_filter: Option<bool>,
        sort_by: Option<String>,
        sort_order: Option<SortOrder>,
    ) -> ListUsersQuery {
        ListUsersQuery {
            query_id: Uuid::new_v4().to_string(),
            timestamp: Utc::now(),
            page,
            page_size,
            email_filter,
            role_filter,
            is_locked_filter,
            sort_by,
            sort_order,
        }
    }

    pub fn list_roles(
        page: u32,
        page_size: u32,
        name_filter: Option<String>,
        include_permissions: bool,
        sort_by: Option<String>,
        sort_order: Option<SortOrder>,
    ) -> ListRolesQuery {
        ListRolesQuery {
            query_id: Uuid::new_v4().to_string(),
            timestamp: Utc::now(),
            page,
            page_size,
            name_filter,
            include_permissions,
            sort_by,
            sort_order,
        }
    }

    pub fn list_permissions(
        page: u32,
        page_size: u32,
        name_filter: Option<String>,
        group_filter: Option<String>,
        sort_by: Option<String>,
        sort_order: Option<SortOrder>,
    ) -> ListPermissionsQuery {
        ListPermissionsQuery {
            query_id: Uuid::new_v4().to_string(),
            timestamp: Utc::now(),
            page,
            page_size,
            name_filter,
            group_filter,
            sort_by,
            sort_order,
        }
    }

    pub fn check_user_permission(
        user_id: String,
        permission_name: String,
        resource_context: Option<serde_json::Value>,
    ) -> CheckUserPermissionQuery {
        CheckUserPermissionQuery {
            query_id: Uuid::new_v4().to_string(),
            timestamp: Utc::now(),
            user_id,
            permission_name,
            resource_context,
        }
    }

    pub fn get_user_audit_events(
        user_id: String,
        page: u32,
        page_size: u32,
        event_type_filter: Option<String>,
        date_from: Option<DateTime<Utc>>,
        date_to: Option<DateTime<Utc>>,
    ) -> GetUserAuditEventsQuery {
        GetUserAuditEventsQuery {
            query_id: Uuid::new_v4().to_string(),
            timestamp: Utc::now(),
            user_id,
            page,
            page_size,
            event_type_filter,
            date_from,
            date_to,
        }
    }

    pub fn list_abac_policies(
        page: u64,
        page_size: u64,
        name_filter: Option<String>,
        effect_filter: Option<String>,
        include_conditions: bool,
        sort_by: Option<String>,
        sort_order: Option<SortOrder>,
    ) -> ListAbacPoliciesQuery {
        ListAbacPoliciesQuery {
            query_id: Uuid::new_v4().to_string(),
            timestamp: Utc::now(),
            page,
            page_size,
            name_filter,
            effect_filter,
            include_conditions,
            sort_by,
            sort_order,
        }
    }

    pub fn list_permission_groups(
        page: u64,
        page_size: u64,
        name_filter: Option<String>,
        category_filter: Option<String>,
        include_permissions: bool,
        sort_by: Option<String>,
        sort_order: Option<SortOrder>,
    ) -> ListPermissionGroupsQuery {
        ListPermissionGroupsQuery {
            query_id: Uuid::new_v4().to_string(),
            timestamp: Utc::now(),
            page,
            page_size,
            name_filter,
            category_filter,
            include_permissions,
            sort_by,
            sort_order,
        }
    }

    pub fn get_permission_group(
        group_id: String,
        include_permissions: bool,
    ) -> GetPermissionGroupQuery {
        GetPermissionGroupQuery {
            query_id: Uuid::new_v4().to_string(),
            timestamp: Utc::now(),
            group_id,
            include_permissions,
        }
    }

    pub fn get_role_hierarchy(role_id: String) -> GetRoleHierarchyQuery {
        GetRoleHierarchyQuery {
            query_id: Uuid::new_v4().to_string(),
            timestamp: Utc::now(),
            role_id,
        }
    }

    pub fn list_role_hierarchies() -> ListRoleHierarchiesQuery {
        ListRoleHierarchiesQuery {
            query_id: Uuid::new_v4().to_string(),
            timestamp: Utc::now(),
        }
    }

    pub fn get_permissions_in_group(
        group_id: String,
        page: i32,
        page_size: i32,
    ) -> GetPermissionsInGroupQuery {
        GetPermissionsInGroupQuery {
            query_id: Uuid::new_v4().to_string(),
            timestamp: Utc::now(),
            group_id,
            page,
            page_size,
        }
    }

    pub fn check_permission(
        user_id: String,
        permission_name: String,
        user_attributes: Option<std::collections::HashMap<String, String>>,
    ) -> CheckPermissionQuery {
        CheckPermissionQuery {
            query_id: Uuid::new_v4().to_string(),
            timestamp: Utc::now(),
            user_id,
            permission_name,
            user_attributes,
        }
    }

    pub fn get_role_permissions(role_id: String) -> GetRolePermissionsQuery {
        GetRolePermissionsQuery {
            query_id: Uuid::new_v4().to_string(),
            timestamp: Utc::now(),
            role_id,
        }
    }

    pub fn get_role_by_id(role_id: String, include_permissions: bool) -> GetRoleByIdQuery {
        GetRoleByIdQuery {
            query_id: Uuid::new_v4().to_string(),
            timestamp: Utc::now(),
            role_id,
            include_permissions,
        }
    }

    pub fn get_permission_by_id(permission_id: String) -> GetPermissionByIdQuery {
        GetPermissionByIdQuery {
            query_id: Uuid::new_v4().to_string(),
            timestamp: Utc::now(),
            permission_id,
        }
    }
}

/// Implement Query trait for all queries
impl Query for GetUserByIdQuery {
    fn query_id(&self) -> &str {
        &self.query_id
    }
    fn timestamp(&self) -> DateTime<Utc> {
        self.timestamp
    }
    fn user_id(&self) -> Option<&str> {
        Some(&self.user_id)
    }
}

impl Query for GetRolesForUserQuery {
    fn query_id(&self) -> &str {
        &self.query_id
    }
    fn timestamp(&self) -> DateTime<Utc> {
        self.timestamp
    }
    fn user_id(&self) -> Option<&str> {
        Some(&self.user_id)
    }
}

impl Query for GetPermissionsForUserQuery {
    fn query_id(&self) -> &str {
        &self.query_id
    }
    fn timestamp(&self) -> DateTime<Utc> {
        self.timestamp
    }
    fn user_id(&self) -> Option<&str> {
        Some(&self.user_id)
    }
}

impl Query for ListUsersQuery {
    fn query_id(&self) -> &str {
        &self.query_id
    }
    fn timestamp(&self) -> DateTime<Utc> {
        self.timestamp
    }
    fn user_id(&self) -> Option<&str> {
        None
    } // List queries don't have specific user_id
}

impl Query for ListRolesQuery {
    fn query_id(&self) -> &str {
        &self.query_id
    }
    fn timestamp(&self) -> DateTime<Utc> {
        self.timestamp
    }
    fn user_id(&self) -> Option<&str> {
        None
    } // List queries don't have specific user_id
}

impl Query for ListPermissionsQuery {
    fn query_id(&self) -> &str {
        &self.query_id
    }
    fn timestamp(&self) -> DateTime<Utc> {
        self.timestamp
    }
    fn user_id(&self) -> Option<&str> {
        None
    } // List queries don't have specific user_id
}

impl Query for CheckUserPermissionQuery {
    fn query_id(&self) -> &str {
        &self.query_id
    }
    fn timestamp(&self) -> DateTime<Utc> {
        self.timestamp
    }
    fn user_id(&self) -> Option<&str> {
        Some(&self.user_id)
    }
}

impl Query for GetUserAuditEventsQuery {
    fn query_id(&self) -> &str {
        &self.query_id
    }
    fn timestamp(&self) -> DateTime<Utc> {
        self.timestamp
    }
    fn user_id(&self) -> Option<&str> {
        Some(&self.user_id)
    }
}

impl Query for ListAbacPoliciesQuery {
    fn query_id(&self) -> &str {
        &self.query_id
    }
    fn timestamp(&self) -> DateTime<Utc> {
        self.timestamp
    }
    fn user_id(&self) -> Option<&str> {
        None
    } // List queries don't have user_id
}

impl Query for ListPermissionGroupsQuery {
    fn query_id(&self) -> &str {
        &self.query_id
    }
    fn timestamp(&self) -> DateTime<Utc> {
        self.timestamp
    }
    fn user_id(&self) -> Option<&str> {
        None
    } // List queries don't have user_id
}

impl Query for GetPermissionGroupQuery {
    fn query_id(&self) -> &str {
        &self.query_id
    }
    fn timestamp(&self) -> DateTime<Utc> {
        self.timestamp
    }
    fn user_id(&self) -> Option<&str> {
        None
    } // Get queries don't have user_id
}

impl Query for GetRoleHierarchyQuery {
    fn query_id(&self) -> &str {
        &self.query_id
    }
    fn timestamp(&self) -> DateTime<Utc> {
        self.timestamp
    }
    fn user_id(&self) -> Option<&str> {
        None
    } // Get queries don't have user_id
}

impl Query for ListRoleHierarchiesQuery {
    fn query_id(&self) -> &str {
        &self.query_id
    }
    fn timestamp(&self) -> DateTime<Utc> {
        self.timestamp
    }
    fn user_id(&self) -> Option<&str> {
        None
    } // List queries don't have user_id
}

impl Query for GetPermissionsInGroupQuery {
    fn query_id(&self) -> &str {
        &self.query_id
    }
    fn timestamp(&self) -> DateTime<Utc> {
        self.timestamp
    }
    fn user_id(&self) -> Option<&str> {
        None
    } // Get queries don't have user_id
}

impl Query for CheckPermissionQuery {
    fn query_id(&self) -> &str {
        &self.query_id
    }
    fn timestamp(&self) -> DateTime<Utc> {
        self.timestamp
    }
    fn user_id(&self) -> Option<&str> {
        Some(&self.user_id)
    }
}

impl Query for GetRolePermissionsQuery {
    fn query_id(&self) -> &str {
        &self.query_id
    }
    fn timestamp(&self) -> DateTime<Utc> {
        self.timestamp
    }
    fn user_id(&self) -> Option<&str> {
        None
    } // Get queries don't have user_id
}

impl Query for GetRoleByIdQuery {
    fn query_id(&self) -> &str {
        &self.query_id
    }
    fn timestamp(&self) -> DateTime<Utc> {
        self.timestamp
    }
    fn user_id(&self) -> Option<&str> {
        None
    } // Get queries don't have user_id
}

impl Query for GetPermissionByIdQuery {
    fn query_id(&self) -> &str {
        &self.query_id
    }
    fn timestamp(&self) -> DateTime<Utc> {
        self.timestamp
    }
    fn user_id(&self) -> Option<&str> {
        None
    } // Get queries don't have user_id
}

/// Read model DTOs for optimized query responses
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserReadModel {
    pub id: String,
    pub email: String,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub is_locked: bool,
    pub failed_login_attempts: u32,
    pub created_at: DateTime<Utc>,
    pub last_login_at: Option<DateTime<Utc>>,
    pub roles: Vec<RoleReadModel>,
    pub permissions: Vec<PermissionReadModel>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoleReadModel {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub parent_role: Option<Box<RoleReadModel>>,
    pub permissions: Vec<PermissionReadModel>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PermissionReadModel {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub group_name: Option<String>,
    pub metadata: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaginatedResult<T> {
    pub items: Vec<T>,
    pub total_count: u64,
    pub page: u32,
    pub page_size: u32,
    pub total_pages: u32,
    pub has_next: bool,
    pub has_previous: bool,
}

impl<T> PaginatedResult<T> {
    pub fn new(items: Vec<T>, total_count: u64, page: u32, page_size: u32) -> Self {
        let total_pages = (total_count as f64 / page_size as f64).ceil() as u32;
        let has_next = page < total_pages;
        let has_previous = page > 1;

        Self {
            items,
            total_count,
            page,
            page_size,
            total_pages,
            has_next,
            has_previous,
        }
    }
}

/// Query to get a permission group by ID
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetPermissionGroupQuery {
    pub query_id: String,
    pub timestamp: DateTime<Utc>,
    pub group_id: String,
    pub include_permissions: bool,
}

/// Query to get role hierarchy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetRoleHierarchyQuery {
    pub query_id: String,
    pub timestamp: DateTime<Utc>,
    pub role_id: String,
}

/// Query to list all role hierarchies
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListRoleHierarchiesQuery {
    pub query_id: String,
    pub timestamp: DateTime<Utc>,
}

/// Query to get permissions in a group
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetPermissionsInGroupQuery {
    pub query_id: String,
    pub timestamp: DateTime<Utc>,
    pub group_id: String,
    pub page: i32,
    pub page_size: i32,
}

/// Query to check a permission
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckPermissionQuery {
    pub query_id: String,
    pub timestamp: DateTime<Utc>,
    pub user_id: String,
    pub permission_name: String,
    pub user_attributes: Option<std::collections::HashMap<String, String>>,
}

/// Query to get permissions for a role
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetRolePermissionsQuery {
    pub query_id: String,
    pub timestamp: DateTime<Utc>,
    pub role_id: String,
}

/// Query to get a role by ID
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetRoleByIdQuery {
    pub query_id: String,
    pub timestamp: DateTime<Utc>,
    pub role_id: String,
    pub include_permissions: bool,
}

/// Query to get a permission by ID
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetPermissionByIdQuery {
    pub query_id: String,
    pub timestamp: DateTime<Utc>,
    pub permission_id: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_user_by_id_query_creation() {
        let query = QueryFactory::get_user_by_id("user1".to_string(), true, false);

        assert_eq!(query.user_id, "user1");
        assert!(query.include_roles);
        assert!(!query.include_permissions);
        assert!(!query.query_id.is_empty());
    }

    #[test]
    fn test_list_users_query_creation() {
        let query = QueryFactory::list_users(
            1,
            10,
            Some("test@example.com".to_string()),
            Some("admin".to_string()),
            Some(false),
            Some("email".to_string()),
            Some(SortOrder::Asc),
        );

        assert_eq!(query.page, 1);
        assert_eq!(query.page_size, 10);
        assert_eq!(query.email_filter, Some("test@example.com".to_string()));
        assert_eq!(query.role_filter, Some("admin".to_string()));
        assert_eq!(query.is_locked_filter, Some(false));
        assert_eq!(query.sort_by, Some("email".to_string()));
        assert_eq!(query.sort_order, Some(SortOrder::Asc));
        assert!(!query.query_id.is_empty());
    }

    #[test]
    fn test_query_trait_implementation() {
        let query = QueryFactory::get_user_by_id("user1".to_string(), true, true);

        assert!(!query.query_id().is_empty());
        assert!(query.timestamp() <= Utc::now());
        assert_eq!(query.user_id(), Some("user1"));
    }

    #[test]
    fn test_paginated_result() {
        let items = vec![1, 2, 3, 4, 5];
        let result = PaginatedResult::new(items, 25, 1, 10);

        assert_eq!(result.items.len(), 5);
        assert_eq!(result.total_count, 25);
        assert_eq!(result.page, 1);
        assert_eq!(result.page_size, 10);
        assert_eq!(result.total_pages, 3);
        assert!(result.has_next);
        assert!(!result.has_previous);
    }
}
