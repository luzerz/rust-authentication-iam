# Authentication System Documentation

## Overview

The authentication service provides a comprehensive JWT-based authentication system with refresh token support, account security features, and robust token management.

## Core Components

### 1. JWT Token System

#### Access Tokens
- **Algorithm**: HS256 (HMAC SHA-256)
- **Expiration**: Configurable (default: 15 minutes)
- **Claims**: User ID, roles, permissions, JTI (JWT ID), issued/expiration times
- **Security**: Signed with secret key, includes JTI for revocation tracking

#### Refresh Tokens
- **Purpose**: Secure token renewal without re-authentication
- **Storage**: Database-backed with revocation support
- **Expiration**: Longer lifespan than access tokens (default: 7 days)
- **Security**: Unique JTI, database tracking, revocation capability

### 2. Token Service (`TokenService`)

#### Key Methods

```rust
// Issue new access and refresh tokens
async fn issue_tokens(&self, user_id: &str, roles: &[String]) -> Result<TokenPair, TokenError>

// Validate access token
async fn validate_token(&self, token: &str) -> Result<Claims, TokenError>

// Refresh access token using refresh token
async fn refresh_token(&self, refresh_token: &str) -> Result<TokenPair, TokenError>

// Revoke refresh token
async fn revoke_token(&self, refresh_token: &str) -> Result<(), TokenError>
```

#### Token Claims Structure

```rust
pub struct Claims {
    pub sub: String,        // User ID
    pub roles: Vec<String>, // User roles
    pub jti: String,        // JWT ID for revocation
    pub iat: i64,          // Issued at
    pub exp: i64,          // Expiration time
}
```

### 3. Password Security

#### Password Service (`PasswordService`)

```rust
// Hash password with bcrypt
async fn hash_password(&self, password: &str) -> Result<String, PasswordError>

// Verify password against hash
async fn verify_password(&self, password: &str, hash: &str) -> Result<bool, PasswordError>
```

**Security Features:**
- **Algorithm**: bcrypt with configurable cost factor
- **Salt**: Automatically generated per password
- **Timing Attack Protection**: Constant-time comparison

### 4. Account Security

#### Account Locking
- **Failed Login Attempts**: Configurable threshold (default: 5)
- **Lock Duration**: Temporary lock with automatic unlock
- **Permanent Lock**: After excessive failed attempts
- **Audit Trail**: All login attempts logged

#### User Account States
```rust
pub enum AccountStatus {
    Active,
    Locked { reason: String, locked_until: Option<DateTime<Utc>> },
    Suspended { reason: String },
}
```

## API Endpoints

### Authentication Endpoints

#### 1. Login
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

#### 2. Token Validation
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

#### 3. Token Refresh
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

#### 4. Logout
```http
POST /v1/iam/logout
Authorization: Bearer <access_token>
Content-Type: application/json

{
  "refresh_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..."
}
```

## Security Features

### 1. Token Security
- **JTI Tracking**: Each token has unique JWT ID for revocation
- **Database Storage**: Refresh tokens stored in database for revocation
- **Automatic Cleanup**: Expired tokens automatically removed
- **Revocation Support**: Immediate token invalidation

### 2. Password Security
- **Bcrypt Hashing**: Industry-standard password hashing
- **Salt Generation**: Unique salt per password
- **Cost Factor**: Configurable bcrypt rounds (default: 12)
- **Timing Protection**: Constant-time comparison prevents timing attacks

### 3. Account Protection
- **Brute Force Protection**: Account locking after failed attempts
- **Temporary Locks**: Automatic unlock after timeout
- **Permanent Suspension**: For excessive violations
- **Audit Logging**: All authentication events logged

### 4. JWT Security
- **Signature Verification**: HMAC SHA-256 signatures
- **Expiration Validation**: Automatic token expiration
- **Claim Validation**: User ID, roles, and permissions validation
- **Revocation Checking**: Database verification for refresh tokens

## Configuration

### Environment Variables

```bash
# JWT Configuration
JWT_SECRET_KEY=your-secret-key-here
JWT_ACCESS_TOKEN_EXPIRY=900  # 15 minutes
JWT_REFRESH_TOKEN_EXPIRY=604800  # 7 days

# Password Security
BCRYPT_COST=12

# Account Security
MAX_LOGIN_ATTEMPTS=5
ACCOUNT_LOCK_DURATION=900  # 15 minutes

# Database
DATABASE_URL=postgresql://user:pass@localhost:5432/auth_db
```

## Error Handling

### Common Error Responses

#### Invalid Credentials
```json
{
  "error": "Invalid credentials",
  "code": "AUTH_001"
}
```

#### Account Locked
```json
{
  "error": "Account locked due to multiple failed attempts",
  "code": "AUTH_002",
  "locked_until": "2024-01-15T10:45:00Z"
}
```

#### Token Expired
```json
{
  "error": "Token has expired",
  "code": "AUTH_003"
}
```

#### Invalid Token
```json
{
  "error": "Invalid or malformed token",
  "code": "AUTH_004"
}
```

## Best Practices

### 1. Token Management
- Store refresh tokens securely (HTTP-only cookies)
- Implement automatic token refresh
- Handle token expiration gracefully
- Log out users on security events

### 2. Password Security
- Enforce strong password policies
- Use HTTPS for all authentication requests
- Implement rate limiting on login endpoints
- Monitor for suspicious login patterns

### 3. Account Security
- Implement progressive delays for failed attempts
- Send security notifications for account locks
- Provide account recovery mechanisms
- Regular security audits and monitoring

## Testing

### Unit Tests
- Token generation and validation
- Password hashing and verification
- Account locking mechanisms
- Error handling scenarios

### Integration Tests
- Complete authentication flows
- Token refresh scenarios
- Account security features
- Database persistence

### Security Tests
- Brute force protection
- Token revocation
- Password strength validation
- Session management

## Monitoring and Observability

### Metrics
- Authentication success/failure rates
- Token refresh patterns
- Account lock events
- Password reset requests

### Logging
- All authentication events
- Security violations
- Token operations
- Account status changes

### Alerts
- Unusual login patterns
- Account lock spikes
- Token validation failures
- Security violations 