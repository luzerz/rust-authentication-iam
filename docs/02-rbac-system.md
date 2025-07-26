# RBAC (Role-Based Access Control) System Documentation

## Overview

The RBAC system provides a comprehensive role-based access control mechanism with user-role assignments, role-permission assignments, and effective permission calculation. It follows the NIST RBAC model with support for role hierarchies and permission inheritance.

## Core Components

### 1. Domain Models

#### User
```rust
pub struct User {
    pub id: String,
    pub username: String,
    pub email: String,
    pub password_hash: String,
    pub roles: Vec<String>, // Role IDs
    pub status: AccountStatus,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}
```

#### Role
```rust
pub struct Role {
    pub id: String,
    pub name: String,
    pub permissions: Vec<String>, // Permission IDs
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}
```

#### Permission
```rust
pub struct Permission {
    pub id: String,
    pub name: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}
```

### 2. RBAC Service (`AuthZService`)

#### Key Methods

```rust
// Check if user has specific permission
async fn user_has_permission(
    &self,
    user_id: &str,
    permission_name: &str,
    user_attrs: Option<&HashMap<String, String>>,
) -> Result<bool, sqlx::Error>

// Get all roles for a user
async fn get_roles_for_user(&self, user_id: &str) -> Result<Vec<Role>, sqlx::Error>

// Get effective permissions for a user
async fn get_effective_permissions(&self, user_id: &str) -> Result<Vec<Permission>, sqlx::Error>
```

## API Endpoints

### Role Management

#### 1. Create Role
```http
POST /v1/iam/roles
Authorization: Bearer <access_token>
X-User-Id: <requesting_user_id>
Content-Type: application/json

{
  "name": "admin"
}
```

**Response:**
```json
{
  "id": "role123",
  "name": "admin",
  "permissions": [],
  "created_at": "2024-01-15T10:30:00Z",
  "updated_at": "2024-01-15T10:30:00Z"
}
```

#### 2. List Roles
```http
GET /v1/iam/roles
Authorization: Bearer <access_token>
```

**Response:**
```json
{
  "roles": [
    {
      "id": "role123",
      "name": "admin",
      "permissions": []
    },
    {
      "id": "role456",
      "name": "user",
      "permissions": []
    }
  ]
}
```

#### 3. Delete Role
```http
DELETE /v1/iam/roles/{role_id}
Authorization: Bearer <access_token>
X-User-Id: <requesting_user_id>
```

### User-Role Assignment

#### 1. Assign Role to User
```http
POST /v1/iam/roles/assign
Authorization: Bearer <access_token>
X-User-Id: <requesting_user_id>
Content-Type: application/json

{
  "user_id": "user123",
  "role_id": "role456"
}
```

#### 2. Remove Role from User
```http
POST /v1/iam/roles/remove
Authorization: Bearer <access_token>
X-User-Id: <requesting_user_id>
Content-Type: application/json

{
  "user_id": "user123",
  "role_id": "role456"
}
```

#### 3. List User Roles
```http
GET /v1/iam/users/{user_id}/roles
Authorization: Bearer <access_token>
X-User-Id: <requesting_user_id>
```

**Response:**
```json
{
  "user_id": "user123",
  "roles": [
    {
      "id": "role123",
      "name": "admin"
    },
    {
      "id": "role456",
      "name": "user"
    }
  ]
}
```

### Permission Management

#### 1. Create Permission
```http
POST /v1/iam/permissions
Authorization: Bearer <access_token>
X-User-Id: <requesting_user_id>
Content-Type: application/json

{
  "name": "users:read"
}
```

**Response:**
```json
{
  "id": "perm123",
  "name": "users:read",
  "created_at": "2024-01-15T10:30:00Z",
  "updated_at": "2024-01-15T10:30:00Z"
}
```

#### 2. List Permissions
```http
GET /v1/iam/permissions
Authorization: Bearer <access_token>
```

**Response:**
```json
{
  "permissions": [
    {
      "id": "perm123",
      "name": "users:read"
    },
    {
      "id": "perm456",
      "name": "users:write"
    }
  ]
}
```

#### 3. Delete Permission
```http
DELETE /v1/iam/permissions/{permission_id}
Authorization: Bearer <access_token>
X-User-Id: <requesting_user_id>
```

### Role-Permission Assignment

#### 1. Assign Permission to Role
```http
POST /v1/iam/permissions/assign
Authorization: Bearer <access_token>
X-User-Id: <requesting_user_id>
Content-Type: application/json

{
  "role_id": "role123",
  "permission_id": "perm456"
}
```

#### 2. Remove Permission from Role
```http
POST /v1/iam/permissions/remove
Authorization: Bearer <access_token>
X-User-Id: <requesting_user_id>
Content-Type: application/json

{
  "role_id": "role123",
  "permission_id": "perm456"
}
```

#### 3. List Role Permissions
```http
GET /v1/iam/roles/{role_id}/permissions
Authorization: Bearer <access_token>
X-User-Id: <requesting_user_id>
```

**Response:**
```json
{
  "role_id": "role123",
  "permissions": [
    {
      "id": "perm123",
      "name": "users:read"
    },
    {
      "id": "perm456",
      "name": "users:write"
    }
  ]
}
```

### Effective Permissions

#### Get User's Effective Permissions
```http
GET /v1/iam/users/{user_id}/effective-permissions
Authorization: Bearer <access_token>
X-User-Id: <requesting_user_id>
```

**Response:**
```json
{
  "user_id": "user123",
  "effective_permissions": [
    {
      "id": "perm123",
      "name": "users:read",
      "granted_by": "admin"
    },
    {
      "id": "perm456",
      "name": "users:write",
      "granted_by": "admin"
    },
    {
      "id": "perm789",
      "name": "reports:read",
      "granted_by": "user"
    }
  ]
}
```

## Permission Checking

### 1. Middleware Integration

The RBAC system integrates with Axum middleware for automatic permission checking:

```rust
// Require specific permission for endpoint access
pub struct RequirePermission {
    pub user_id: String,
}

// Extract user ID from JWT token and check permissions
impl<S> FromRequestParts<S> for RequirePermission {
    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        // Extract user from JWT token
        // Check if user has required permission
        // Return user_id if authorized
    }
}
```

### 2. Usage in Handlers

```rust
pub async fn protected_endpoint(
    State(state): State<Arc<AppState>>,
    RequirePermission { user_id }: RequirePermission,
) -> impl IntoResponse {
    // Handler logic here
    // User is guaranteed to have required permission
}
```

### 3. Programmatic Permission Checking

```rust
// Check if user has specific permission
let has_permission = state
    .authz_service
    .user_has_permission(&user_id, "users:read", None)
    .await?;

if has_permission {
    // Allow access
} else {
    // Deny access
}
```

## Database Schema

### Users Table
```sql
CREATE TABLE users (
    id TEXT PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
```

### Roles Table
```sql
CREATE TABLE roles (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
```

### Permissions Table
```sql
CREATE TABLE permissions (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
```

### User-Role Assignments
```sql
CREATE TABLE user_roles (
    user_id TEXT NOT NULL,
    role_id TEXT NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    PRIMARY KEY (user_id, role_id),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE
);
```

### Role-Permission Assignments
```sql
CREATE TABLE role_permissions (
    role_id TEXT NOT NULL,
    permission_id TEXT NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    PRIMARY KEY (role_id, permission_id),
    FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE,
    FOREIGN KEY (permission_id) REFERENCES permissions(id) ON DELETE CASCADE
);
```

## Permission Naming Convention

### Recommended Format
```
<resource>:<action>
```

### Examples
- `users:read` - Read user data
- `users:write` - Create/update user data
- `users:delete` - Delete user data
- `reports:read` - Read reports
- `admin:manage` - Administrative operations
- `rbac:manage` - RBAC management operations

### Hierarchical Permissions
- `users:*` - All user operations
- `admin:*` - All administrative operations
- `*:read` - All read operations

## Security Features

### 1. Permission Inheritance
- Users inherit permissions from all assigned roles
- Effective permissions are calculated dynamically
- No permission duplication across roles

### 2. Role-Based Authorization
- All endpoints require specific permissions
- JWT tokens include user roles for quick validation
- Database-backed permission verification

### 3. Audit Trail
- All role and permission assignments logged
- User permission changes tracked
- Role creation and deletion audited

### 4. Least Privilege Principle
- Users only get permissions through role assignments
- No direct permission grants to users
- Role-based permission aggregation

## Best Practices

### 1. Role Design
- Create roles based on job functions
- Use descriptive role names
- Keep roles focused and specific
- Avoid role proliferation

### 2. Permission Design
- Use consistent naming conventions
- Group related permissions
- Implement hierarchical permissions
- Document permission purposes

### 3. User Management
- Assign roles based on job requirements
- Regular role reviews and audits
- Implement role approval workflows
- Monitor permission usage

### 4. Security
- Regular permission audits
- Implement role-based access reviews
- Monitor for privilege escalation
- Use principle of least privilege

## Testing

### Unit Tests
- Role creation and management
- Permission assignment and removal
- User-role assignment logic
- Effective permission calculation

### Integration Tests
- Complete RBAC workflows
- Permission checking scenarios
- Role hierarchy testing
- Database persistence

### Security Tests
- Permission bypass attempts
- Role escalation testing
- Authorization edge cases
- Access control validation

## Monitoring and Observability

### Metrics
- Permission check success/failure rates
- Role assignment patterns
- Permission usage statistics
- Authorization decision times

### Logging
- All permission checks
- Role assignment changes
- Permission modifications
- Authorization failures

### Alerts
- Unusual permission patterns
- Role assignment spikes
- Authorization failures
- Security violations 