# API Reference Documentation

## Overview

The authentication service provides a comprehensive REST API for identity and access management. All endpoints (except authentication endpoints) require JWT authentication via the `Authorization: Bearer <token>` header.

## Base URL
```
http://localhost:8080/v1
```

## Authentication

### Headers
- `Authorization: Bearer <access_token>` - Required for protected endpoints
- `X-User-Id: <user_id>` - Required for operations that need to identify the requesting user
- `Content-Type: application/json` - For POST/PUT requests

## Authentication Endpoints

### Login
Authenticate a user and receive access and refresh tokens.

```http
POST /v1/iam/login
Content-Type: application/json

{
  "username": "user@example.com",
  "password": "secure_password"
}
```

**Response:**
```json
{
  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
  "refresh_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
  "token_type": "Bearer",
  "expires_in": 900
}
```

**Error Responses:**
- `401 Unauthorized` - Invalid credentials
- `423 Locked` - Account locked due to failed attempts

### Validate Token
Validate an access token and get user information.

```http
POST /v1/iam/validate-token
Content-Type: application/json

{
  "token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..."
}
```

**Response:**
```json
{
  "valid": true,
  "user_id": "user123",
  "roles": ["admin", "user"],
  "expires_at": "2024-01-15T10:30:00Z"
}
```

### Refresh Token
Get a new access token using a refresh token.

```http
POST /v1/iam/refresh-token
Content-Type: application/json

{
  "refresh_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..."
}
```

**Response:**
```json
{
  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
  "refresh_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
  "token_type": "Bearer",
  "expires_in": 900
}
```

### Logout
Revoke a refresh token.

```http
POST /v1/iam/logout
Authorization: Bearer <access_token>
Content-Type: application/json

{
  "refresh_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..."
}
```

**Response:**
```json
{
  "message": "Successfully logged out"
}
```

## RBAC Endpoints

### Role Management

#### Create Role
Create a new role.

```http
POST /v1/iam/roles
Authorization: Bearer <access_token>
X-User-Id: <requesting_user_id>
Content-Type: application/json

{
  "name": "admin"
}
```

**Required Permission:** `rbac:manage`

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

#### List Roles
Get all roles.

```http
GET /v1/iam/roles
Authorization: Bearer <access_token>
```

**Required Permission:** `rbac:read`

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

#### Delete Role
Delete a role.

```http
DELETE /v1/iam/roles/{role_id}
Authorization: Bearer <access_token>
X-User-Id: <requesting_user_id>
```

**Required Permission:** `rbac:manage`

### User-Role Assignment

#### Assign Role to User
Assign a role to a user.

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

**Required Permission:** `rbac:manage`

#### Remove Role from User
Remove a role from a user.

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

**Required Permission:** `rbac:manage`

#### List User Roles
Get all roles assigned to a user.

```http
GET /v1/iam/users/{user_id}/roles
Authorization: Bearer <access_token>
X-User-Id: <requesting_user_id>
```

**Required Permission:** `rbac:read`

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

#### Create Permission
Create a new permission.

```http
POST /v1/iam/permissions
Authorization: Bearer <access_token>
X-User-Id: <requesting_user_id>
Content-Type: application/json

{
  "name": "users:read"
}
```

**Required Permission:** `rbac:manage`

**Response:**
```json
{
  "id": "perm123",
  "name": "users:read",
  "created_at": "2024-01-15T10:30:00Z",
  "updated_at": "2024-01-15T10:30:00Z"
}
```

#### List Permissions
Get all permissions.

```http
GET /v1/iam/permissions
Authorization: Bearer <access_token>
```

**Required Permission:** `rbac:read`

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

#### Delete Permission
Delete a permission.

```http
DELETE /v1/iam/permissions/{permission_id}
Authorization: Bearer <access_token>
X-User-Id: <requesting_user_id>
```

**Required Permission:** `rbac:manage`

### Role-Permission Assignment

#### Assign Permission to Role
Assign a permission to a role.

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

**Required Permission:** `rbac:manage`

#### Remove Permission from Role
Remove a permission from a role.

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

**Required Permission:** `rbac:manage`

#### List Role Permissions
Get all permissions assigned to a role.

```http
GET /v1/iam/roles/{role_id}/permissions
Authorization: Bearer <access_token>
X-User-Id: <requesting_user_id>
```

**Required Permission:** `rbac:read`

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
Get all effective permissions for a user (inherited from roles).

```http
GET /v1/iam/users/{user_id}/effective-permissions
Authorization: Bearer <access_token>
X-User-Id: <requesting_user_id>
```

**Required Permission:** `rbac:read`

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

## ABAC Endpoints

### Policy Management

#### Create ABAC Policy
Create a new ABAC policy.

```http
POST /v1/iam/abac/policies
Authorization: Bearer <access_token>
X-User-Id: <requesting_user_id>
Content-Type: application/json

{
  "name": "engineering_access",
  "effect": "Allow",
  "priority": 75,
  "conflict_resolution": "deny_overrides",
  "conditions": [
    {
      "attribute": "department",
      "operator": "eq",
      "value": "engineering"
    },
    {
      "attribute": "role",
      "operator": "in",
      "value": "admin,developer"
    }
  ]
}
```

**Required Permission:** `rbac:manage`

**Response:**
```json
{
  "id": "policy123",
  "name": "engineering_access",
  "effect": "Allow",
  "priority": 75,
  "conflict_resolution": "deny_overrides",
  "conditions": [
    {
      "attribute": "department",
      "operator": "eq",
      "value": "engineering"
    },
    {
      "attribute": "role",
      "operator": "in",
      "value": "admin,developer"
    }
  ]
}
```

#### Update ABAC Policy
Update an existing ABAC policy.

```http
PUT /v1/iam/abac/policies/{policy_id}
Authorization: Bearer <access_token>
X-User-Id: <requesting_user_id>
Content-Type: application/json

{
  "name": "engineering_access_v2",
  "priority": 80,
  "conditions": [
    {
      "attribute": "department",
      "operator": "eq",
      "value": "engineering"
    },
    {
      "attribute": "security_level",
      "operator": "gte",
      "value": "3"
    }
  ]
}
```

**Required Permission:** `rbac:manage`

#### List ABAC Policies
Get all ABAC policies.

```http
GET /v1/iam/abac/policies
Authorization: Bearer <access_token>
```

**Required Permission:** `rbac:read`

**Response:**
```json
{
  "policies": [
    {
      "id": "policy123",
      "name": "engineering_access",
      "effect": "Allow",
      "priority": 75,
      "conflict_resolution": "deny_overrides",
      "conditions": [...]
    }
  ]
}
```

#### Delete ABAC Policy
Delete an ABAC policy.

```http
DELETE /v1/iam/abac/policies/{policy_id}
Authorization: Bearer <access_token>
X-User-Id: <requesting_user_id>
```

**Required Permission:** `rbac:manage`

### Policy Assignment

#### Assign Policy to User/Role
Assign an ABAC policy to a user or role.

```http
POST /v1/iam/abac/assign
Authorization: Bearer <access_token>
X-User-Id: <requesting_user_id>
Content-Type: application/json

{
  "target_type": "user",
  "target_id": "user123",
  "policy_id": "policy456"
}
```

**Required Permission:** `rbac:manage`

### Policy Evaluation

#### Evaluate ABAC Policies
Evaluate ABAC policies for a user with given attributes.

```http
POST /v1/iam/abac/evaluate
Authorization: Bearer <access_token>
X-User-Id: <requesting_user_id>
Content-Type: application/json

{
  "user_id": "user123",
  "permission_name": "access_system",
  "attributes": {
    "department": "engineering",
    "role": "admin",
    "security_level": "4",
    "location": "office",
    "time": "09:30"
  }
}
```

**Required Permission:** `rbac:read`

**Response:**
```json
{
  "user_id": "user123",
  "permission_name": "access_system",
  "allowed": true,
  "reason": "Policy 'engineering_access' applied with effect 'Allow'",
  "evaluated_policies": [
    {
      "policy_id": "policy123",
      "policy_name": "engineering_access",
      "effect": "Allow",
      "priority": 75,
      "conflict_resolution": "deny_overrides",
      "matched": true,
      "applied": true,
      "matched_conditions": [
        {
          "attribute": "department",
          "operator": "eq",
          "value": "engineering"
        },
        {
          "attribute": "role",
          "operator": "in",
          "value": "admin,developer"
        }
      ],
      "unmatched_conditions": []
    }
  ]
}
```

## Data Types

### User
```json
{
  "id": "string",
  "username": "string",
  "email": "string",
  "password_hash": "string",
  "roles": ["string"],
  "status": "active|locked|suspended",
  "created_at": "datetime",
  "updated_at": "datetime"
}
```

### Role
```json
{
  "id": "string",
  "name": "string",
  "permissions": ["string"],
  "created_at": "datetime",
  "updated_at": "datetime"
}
```

### Permission
```json
{
  "id": "string",
  "name": "string",
  "created_at": "datetime",
  "updated_at": "datetime"
}
```

### ABAC Policy
```json
{
  "id": "string",
  "name": "string",
  "effect": "Allow|Deny",
  "priority": "integer (1-100)",
  "conflict_resolution": "deny_overrides|allow_overrides|priority_wins|first_match",
  "conditions": [
    {
      "attribute": "string",
      "operator": "string",
      "value": "string"
    }
  ]
}
```

### ABAC Condition
```json
{
  "attribute": "string",
  "operator": "eq|ne|in|gt|lt|gte|lte|contains|starts_with|ends_with",
  "value": "string"
}
```

## Error Responses

### Standard Error Format
```json
{
  "error": "string",
  "code": "string",
  "details": "object (optional)"
}
```

### Common Error Codes

#### Authentication Errors
- `AUTH_001` - Invalid credentials
- `AUTH_002` - Account locked
- `AUTH_003` - Token expired
- `AUTH_004` - Invalid token
- `AUTH_005` - Insufficient permissions

#### Validation Errors
- `VAL_001` - Required field missing
- `VAL_002` - Invalid field format
- `VAL_003` - Field value out of range
- `VAL_004` - Duplicate value

#### Resource Errors
- `RES_001` - Resource not found
- `RES_002` - Resource already exists
- `RES_003` - Resource in use
- `RES_004` - Resource conflict

#### System Errors
- `SYS_001` - Internal server error
- `SYS_002` - Database error
- `SYS_003` - Service unavailable
- `SYS_004` - Configuration error

### HTTP Status Codes

- `200 OK` - Request successful
- `201 Created` - Resource created successfully
- `400 Bad Request` - Invalid request data
- `401 Unauthorized` - Authentication required
- `403 Forbidden` - Insufficient permissions
- `404 Not Found` - Resource not found
- `409 Conflict` - Resource conflict
- `423 Locked` - Account locked
- `500 Internal Server Error` - Server error

## Rate Limiting

The API implements rate limiting to prevent abuse:

- **Authentication endpoints**: 5 requests per minute per IP
- **Protected endpoints**: 100 requests per minute per user
- **Admin endpoints**: 50 requests per minute per user

Rate limit headers are included in responses:
- `X-RateLimit-Limit` - Request limit per window
- `X-RateLimit-Remaining` - Remaining requests in current window
- `X-RateLimit-Reset` - Time when the rate limit resets

## Pagination

List endpoints support pagination:

```http
GET /v1/iam/roles?page=1&limit=10
```

**Response:**
```json
{
  "roles": [...],
  "pagination": {
    "page": 1,
    "limit": 10,
    "total": 25,
    "pages": 3
  }
}
```

## Filtering and Sorting

List endpoints support filtering and sorting:

```http
GET /v1/iam/roles?sort=name&order=asc&filter=admin
```

**Supported Parameters:**
- `sort` - Field to sort by (name, created_at, etc.)
- `order` - Sort order (asc, desc)
- `filter` - Text filter for name fields

## Webhooks

The API supports webhooks for real-time notifications:

```http
POST /v1/iam/webhooks
Authorization: Bearer <access_token>
Content-Type: application/json

{
  "url": "https://example.com/webhook",
  "events": ["user.created", "role.assigned"],
  "secret": "webhook_secret"
}
```

**Supported Events:**
- `user.created` - User account created
- `user.updated` - User account updated
- `user.locked` - User account locked
- `role.created` - Role created
- `role.assigned` - Role assigned to user
- `permission.created` - Permission created
- `policy.created` - ABAC policy created
- `policy.evaluated` - ABAC policy evaluated

## OpenAPI/Swagger

Interactive API documentation is available at:
```
http://localhost:8080/swagger
```

The OpenAPI specification is available at:
```
http://localhost:8080/swagger.json
```

## SDKs and Libraries

### Rust
```rust
use authentication_service_client::Client;

let client = Client::new("http://localhost:8080");
let response = client.login("user@example.com", "password").await?;
```

### JavaScript/TypeScript
```javascript
import { AuthClient } from '@auth-service/client';

const client = new AuthClient('http://localhost:8080');
const response = await client.login('user@example.com', 'password');
```

### Python
```python
from auth_service_client import AuthClient

client = AuthClient('http://localhost:8080')
response = client.login('user@example.com', 'password')
```

## Examples

### Complete Authentication Flow
```bash
# 1. Login
curl -X POST http://localhost:8080/v1/iam/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin@example.com", "password": "password123"}'

# 2. Use access token
curl -X GET http://localhost:8080/v1/iam/roles \
  -H "Authorization: Bearer <access_token>"

# 3. Refresh token when needed
curl -X POST http://localhost:8080/v1/iam/refresh-token \
  -H "Content-Type: application/json" \
  -d '{"refresh_token": "<refresh_token>"}'

# 4. Logout
curl -X POST http://localhost:8080/v1/iam/logout \
  -H "Authorization: Bearer <access_token>" \
  -H "Content-Type: application/json" \
  -d '{"refresh_token": "<refresh_token>"}'
```

### RBAC Management
```bash
# Create role
curl -X POST http://localhost:8080/v1/iam/roles \
  -H "Authorization: Bearer <access_token>" \
  -H "X-User-Id: admin123" \
  -H "Content-Type: application/json" \
  -d '{"name": "developer"}'

# Assign role to user
curl -X POST http://localhost:8080/v1/iam/roles/assign \
  -H "Authorization: Bearer <access_token>" \
  -H "X-User-Id: admin123" \
  -H "Content-Type: application/json" \
  -d '{"user_id": "user123", "role_id": "role456"}'

# Get user's effective permissions
curl -X GET http://localhost:8080/v1/iam/users/user123/effective-permissions \
  -H "Authorization: Bearer <access_token>" \
  -H "X-User-Id: admin123"
```

### ABAC Policy Management
```bash
# Create ABAC policy
curl -X POST http://localhost:8080/v1/iam/abac/policies \
  -H "Authorization: Bearer <access_token>" \
  -H "X-User-Id: admin123" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "engineering_access",
    "effect": "Allow",
    "priority": 75,
    "conflict_resolution": "deny_overrides",
    "conditions": [
      {
        "attribute": "department",
        "operator": "eq",
        "value": "engineering"
      }
    ]
  }'

# Evaluate policies
curl -X POST http://localhost:8080/v1/iam/abac/evaluate \
  -H "Authorization: Bearer <access_token>" \
  -H "X-User-Id: admin123" \
  -H "Content-Type: application/json" \
  -d '{
    "user_id": "user123",
    "permission_name": "access_system",
    "attributes": {
      "department": "engineering",
      "role": "developer"
    }
  }'
``` 