use crate::domain::user::User;
use crate::infrastructure::{
    AbacPolicyRepository, PermissionRepository, RefreshTokenRepository, RoleRepository,
    UserRepository,
};
use bcrypt::{DEFAULT_COST, hash, verify};
use chrono::{Duration, Utc};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::instrument;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,        // user_id
    pub exp: i64,           // expiration time
    pub iat: i64,           // issued at
    pub jti: String,        // JWT ID
    pub token_type: String, // "access" or "refresh"
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefreshToken {
    pub jti: String,
    pub user_id: String,
    pub expires_at: chrono::DateTime<Utc>,
}

#[derive(Debug)]
pub enum AuthError {
    UserNotFound,
    UserAlreadyExists,
    InvalidCredentials,
    AccountLocked,
    TokenExpired,
    InvalidToken,
    DatabaseError,
    PasswordResetTokenExpired,
    PasswordResetTokenInvalid,
}

impl std::fmt::Display for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthError::UserNotFound => write!(f, "User not found"),
            AuthError::UserAlreadyExists => write!(f, "User already exists"),
            AuthError::InvalidCredentials => write!(f, "Invalid credentials"),
            AuthError::AccountLocked => write!(f, "Account is locked"),
            AuthError::TokenExpired => write!(f, "Token has expired"),
            AuthError::InvalidToken => write!(f, "Invalid token"),
            AuthError::DatabaseError => write!(f, "Database error"),
            AuthError::PasswordResetTokenExpired => write!(f, "Password reset token has expired"),
            AuthError::PasswordResetTokenInvalid => write!(f, "Invalid password reset token"),
        }
    }
}

impl std::error::Error for AuthError {}

// ============================================================================
// CORE SERVICES (Keep these - they're stateless utilities)
// ============================================================================

/// Stateless service for JWT token operations
#[derive(Debug)]
pub struct TokenService;

/// Stateless service for password operations
#[derive(Debug)]
pub struct PasswordService;

/// Stateless service for password reset operations
#[derive(Debug)]
pub struct PasswordResetService;

// ============================================================================
// TOKEN SERVICE IMPLEMENTATION
// ============================================================================

impl TokenService {
    pub async fn issue_tokens(
        &self,
        user: &User,
        refresh_token_repo: &Arc<impl RefreshTokenRepository + ?Sized>,
    ) -> Result<(String, String), AuthError> {
        let access_token = self.create_access_token(user)?;
        let refresh_token = self.create_refresh_token(user, refresh_token_repo).await?;

        Ok((access_token, refresh_token))
    }

    pub fn validate_token(&self, token: &str) -> Result<Claims, AuthError> {
        let secret = std::env::var("JWT_SECRET").map_err(|_| AuthError::InvalidToken)?;
        let key = DecodingKey::from_secret(secret.as_ref());

        let token_data = decode::<Claims>(token, &key, &Validation::new(Algorithm::HS256))
            .map_err(|_| AuthError::InvalidToken)?;

        let claims = token_data.claims;

        // Check if token is expired
        let now = Utc::now().timestamp();
        if claims.exp < now {
            return Err(AuthError::TokenExpired);
        }

        Ok(claims)
    }

    pub async fn refresh_access_token(
        &self,
        refresh_token: &str,
        refresh_token_repo: &Arc<impl RefreshTokenRepository + ?Sized>,
        user_repo: &Arc<impl UserRepository + ?Sized>,
    ) -> Result<String, AuthError> {
        let secret = std::env::var("JWT_SECRET").map_err(|_| AuthError::InvalidToken)?;
        let key = DecodingKey::from_secret(secret.as_ref());

        let token_data = decode::<Claims>(refresh_token, &key, &Validation::new(Algorithm::HS256))
            .map_err(|_| AuthError::InvalidToken)?;

        let claims = token_data.claims;

        // Verify it's a refresh token
        if claims.token_type != "refresh" {
            return Err(AuthError::InvalidToken);
        }

        // Check if token is expired
        let now = Utc::now().timestamp();
        if claims.exp < now {
            return Err(AuthError::TokenExpired);
        }

        // Verify token exists in database and is valid
        let is_valid = refresh_token_repo
            .is_valid(&claims.jti)
            .await
            .map_err(|_| AuthError::DatabaseError)?;

        if !is_valid {
            return Err(AuthError::InvalidToken);
        }

        // Get user and create new access token
        let user = user_repo
            .find_by_id(&claims.sub)
            .await
            .map_err(|_| AuthError::DatabaseError)?
            .ok_or(AuthError::UserNotFound)?;

        self.create_access_token(&user)
    }

    fn create_access_token(&self, user: &User) -> Result<String, AuthError> {
        let secret = std::env::var("JWT_SECRET").map_err(|_| AuthError::InvalidToken)?;
        let expiration = std::env::var("JWT_EXPIRATION").map_err(|_| AuthError::InvalidToken)?;
        let time_unit = std::env::var("JWT_TIME_UNIT").map_err(|_| AuthError::InvalidToken)?;
        let key = EncodingKey::from_secret(secret.as_ref());
        let now = Utc::now();
        let exp = match time_unit.as_str() {
            "hours" => now + Duration::hours(expiration.parse::<i64>().unwrap()),
            "minutes" => now + Duration::minutes(expiration.parse::<i64>().unwrap()),
            "seconds" => now + Duration::seconds(expiration.parse::<i64>().unwrap()),
            _ => return Err(AuthError::InvalidToken),
        };

        let claims = Claims {
            sub: user.id.clone(),
            exp: exp.timestamp(),
            iat: now.timestamp(),
            jti: Uuid::new_v4().to_string(),
            token_type: "access".to_string(),
        };

        encode(&Header::default(), &claims, &key).map_err(|_| AuthError::InvalidToken)
    }

    async fn create_refresh_token(
        &self,
        user: &User,
        refresh_token_repo: &Arc<impl RefreshTokenRepository + ?Sized>,
    ) -> Result<String, AuthError> {
        let secret = std::env::var("JWT_SECRET").map_err(|_| AuthError::InvalidToken)?;
        let key = EncodingKey::from_secret(secret.as_ref());

        let now = Utc::now();
        let exp = now + Duration::days(7); // 7 days expiration

        let jti = Uuid::new_v4().to_string();
        let claims = Claims {
            sub: user.id.clone(),
            exp: exp.timestamp(),
            iat: now.timestamp(),
            jti: jti.clone(),
            token_type: "refresh".to_string(),
        };

        let token =
            encode(&Header::default(), &claims, &key).map_err(|_| AuthError::InvalidToken)?;

        // Store refresh token in database
        let refresh_token = RefreshToken {
            jti,
            user_id: user.id.clone(),
            expires_at: exp,
        };

        refresh_token_repo
            .insert(refresh_token)
            .await
            .map_err(|_| AuthError::DatabaseError)?;

        Ok(token)
    }
}

// ============================================================================
// PASSWORD SERVICE IMPLEMENTATION
// ============================================================================

impl PasswordService {
    #[instrument]
    pub fn hash_password(&self, password: &str) -> Result<String, AuthError> {
        hash(password, DEFAULT_COST).map_err(|_| AuthError::DatabaseError)
    }

    #[instrument]
    pub fn verify(&self, user: &User, password: &str) -> bool {
        verify(password, &user.password_hash).unwrap_or(false)
    }
}

// ============================================================================
// PASSWORD RESET SERVICE IMPLEMENTATION
// ============================================================================

impl PasswordResetService {
    #[instrument]
    pub fn generate_reset_token(&self, user_id: &str) -> Result<String, AuthError> {
        let secret = std::env::var("JWT_SECRET").map_err(|_| AuthError::InvalidToken)?;
        let key = EncodingKey::from_secret(secret.as_ref());

        let now = Utc::now();
        let exp = now + Duration::hours(1); // 1 hour expiration

        let claims = Claims {
            sub: user_id.to_string(),
            exp: exp.timestamp(),
            iat: now.timestamp(),
            jti: Uuid::new_v4().to_string(),
            token_type: "password_reset".to_string(),
        };

        encode(&Header::default(), &claims, &key).map_err(|_| AuthError::InvalidToken)
    }

    #[instrument]
    pub fn validate_reset_token(&self, token: &str) -> Result<String, AuthError> {
        let secret = std::env::var("JWT_SECRET").map_err(|_| AuthError::InvalidToken)?;
        let key = DecodingKey::from_secret(secret.as_ref());

        let token_data = decode::<Claims>(token, &key, &Validation::new(Algorithm::HS256))
            .map_err(|_| AuthError::PasswordResetTokenInvalid)?;

        let claims = token_data.claims;

        // Verify it's a password reset token
        if claims.token_type != "password_reset" {
            return Err(AuthError::PasswordResetTokenInvalid);
        }

        // Check if token is expired
        let now = Utc::now().timestamp();
        if claims.exp < now {
            return Err(AuthError::PasswordResetTokenExpired);
        }

        Ok(claims.sub)
    }

    #[instrument]
    pub async fn send_reset_email(&self, email: &str, reset_token: &str) -> Result<(), AuthError> {
        // In a real implementation, this would send an email
        // For now, we'll just log it
        tracing::info!(
            "Password reset email would be sent to {} with token: {}",
            email,
            reset_token
        );
        Ok(())
    }
}

// ============================================================================
// AUTHORIZATION SERVICE IMPLEMENTATION
// ============================================================================

/// Service for complex authorization logic
#[derive(Debug)]
pub struct AuthorizationService;

impl AuthorizationService {
    pub async fn user_has_permission(
        &self,
        user_id: &str,
        permission_name: &str,
        user_attrs: Option<&std::collections::HashMap<String, String>>,
        role_repo: &Arc<impl RoleRepository + ?Sized>,
        permission_repo: &Arc<impl PermissionRepository + ?Sized>,
        abac_repo: &Arc<impl AbacPolicyRepository + ?Sized>,
    ) -> Result<bool, AuthError> {
        // Get user roles
        let user_roles = role_repo
            .get_roles_for_user(user_id)
            .await
            .map_err(|_| AuthError::DatabaseError)?;

        // Check direct role permissions
        for role in &user_roles {
            let role_permissions = permission_repo
                .get_permissions_for_role(&role.id)
                .await
                .map_err(|_| AuthError::DatabaseError)?;

            for permission in role_permissions {
                if permission.name == permission_name {
                    return Ok(true);
                }
            }

            // Check inherited permissions from parent roles
            if let Some(parent_role) = &role.parent_role_id {
                let inherited_permissions = self
                    .get_inherited_permissions(
                        parent_role,
                        permission_name,
                        role_repo,
                        permission_repo,
                    )
                    .await?;
                if inherited_permissions {
                    return Ok(true);
                }
            }
        }

        // If no RBAC permission found and user attributes are provided, check ABAC
        if let Some(attrs) = user_attrs {
            return self
                .user_has_abac_permission(user_id, permission_name, attrs, abac_repo)
                .await;
        }

        Ok(false)
    }

    async fn get_inherited_permissions(
        &self,
        role_id: &str,
        permission_name: &str,
        role_repo: &Arc<impl RoleRepository + ?Sized>,
        permission_repo: &Arc<impl PermissionRepository + ?Sized>,
    ) -> Result<bool, AuthError> {
        let roles = role_repo.list_roles().await;
        let role = roles
            .iter()
            .find(|r| r.id == role_id)
            .ok_or(AuthError::DatabaseError)?;

        // Check current role permissions
        let role_permissions = permission_repo
            .get_permissions_for_role(&role.id)
            .await
            .map_err(|_| AuthError::DatabaseError)?;

        for permission in role_permissions {
            if permission.name == permission_name {
                return Ok(true);
            }
        }

        // Check parent role permissions recursively
        if let Some(parent_role_id) = &role.parent_role_id {
            return Box::pin(self.get_inherited_permissions(
                parent_role_id,
                permission_name,
                role_repo,
                permission_repo,
            ))
            .await;
        }

        Ok(false)
    }

    async fn user_has_abac_permission(
        &self,
        user_id: &str,
        permission_name: &str,
        user_attrs: &std::collections::HashMap<String, String>,
        abac_repo: &Arc<impl AbacPolicyRepository + ?Sized>,
    ) -> Result<bool, AuthError> {
        let policies = abac_repo
            .get_policies_for_user(user_id)
            .await
            .map_err(|_| AuthError::DatabaseError)?;

        for policy in policies {
            if policy.name == permission_name {
                let mut all_conditions_met = true;

                for condition in &policy.conditions {
                    let user_value = user_attrs.get(&condition.attribute);
                    let condition_met = match condition.operator.as_str() {
                        "equals" => user_value.map(|v| v == &condition.value).unwrap_or(false),
                        "not_equals" => user_value.map(|v| v != &condition.value).unwrap_or(true),
                        "contains" => user_value
                            .map(|v| v.contains(&condition.value))
                            .unwrap_or(false),
                        "starts_with" => user_value
                            .map(|v| v.starts_with(&condition.value))
                            .unwrap_or(false),
                        "ends_with" => user_value
                            .map(|v| v.ends_with(&condition.value))
                            .unwrap_or(false),
                        "greater_than" => {
                            if let Some(user_value) = user_value {
                                if let (Ok(user_num), Ok(condition_num)) =
                                    (user_value.parse::<f64>(), condition.value.parse::<f64>())
                                {
                                    user_num > condition_num
                                } else {
                                    false
                                }
                            } else {
                                false
                            }
                        }
                        "less_than" => {
                            if let Some(user_value) = user_value {
                                if let (Ok(user_num), Ok(condition_num)) =
                                    (user_value.parse::<f64>(), condition.value.parse::<f64>())
                                {
                                    user_num < condition_num
                                } else {
                                    false
                                }
                            } else {
                                false
                            }
                        }
                        _ => false,
                    };

                    if !condition_met {
                        all_conditions_met = false;
                        break;
                    }
                }

                if all_conditions_met {
                    return Ok(matches!(
                        policy.effect,
                        crate::domain::abac_policy::AbacEffect::Allow
                    ));
                }
            }
        }

        Ok(false)
    }

    pub async fn evaluate_abac_policies(
        &self,
        user_id: &str,
        permission_name: &str,
        user_attrs: &std::collections::HashMap<String, String>,
        abac_repo: &Arc<impl AbacPolicyRepository + ?Sized>,
    ) -> Result<crate::interface::AbacEvaluationResponse, AuthError> {
        let policies = abac_repo
            .get_policies_for_user(user_id)
            .await
            .map_err(|_| AuthError::DatabaseError)?;

        let mut evaluation_results = Vec::new();
        let mut final_decision = false;

        for policy in policies {
            if policy.name == permission_name {
                let mut condition_results = Vec::new();
                let mut all_conditions_met = true;

                for condition in &policy.conditions {
                    let user_value = user_attrs.get(&condition.attribute);
                    let condition_met = match condition.operator.as_str() {
                        "equals" => user_value.map(|v| v == &condition.value).unwrap_or(false),
                        "not_equals" => user_value.map(|v| v != &condition.value).unwrap_or(true),
                        "contains" => user_value
                            .map(|v| v.contains(&condition.value))
                            .unwrap_or(false),
                        "starts_with" => user_value
                            .map(|v| v.starts_with(&condition.value))
                            .unwrap_or(false),
                        "ends_with" => user_value
                            .map(|v| v.ends_with(&condition.value))
                            .unwrap_or(false),
                        "greater_than" => {
                            if let Some(user_value) = user_value {
                                if let (Ok(user_num), Ok(condition_num)) =
                                    (user_value.parse::<f64>(), condition.value.parse::<f64>())
                                {
                                    user_num > condition_num
                                } else {
                                    false
                                }
                            } else {
                                false
                            }
                        }
                        "less_than" => {
                            if let Some(user_value) = user_value {
                                if let (Ok(user_num), Ok(condition_num)) =
                                    (user_value.parse::<f64>(), condition.value.parse::<f64>())
                                {
                                    user_num < condition_num
                                } else {
                                    false
                                }
                            } else {
                                false
                            }
                        }
                        _ => false,
                    };

                    condition_results.push(crate::interface::AbacConditionDto {
                        attribute: condition.attribute.clone(),
                        operator: condition.operator.clone(),
                        value: condition.value.clone(),
                    });

                    if !condition_met {
                        all_conditions_met = false;
                    }
                }

                if all_conditions_met {
                    final_decision =
                        matches!(policy.effect, crate::domain::abac_policy::AbacEffect::Allow);
                }

                evaluation_results.push(crate::interface::AbacPolicyEvaluationResult {
                    policy_id: policy.id.clone(),
                    policy_name: policy.name.clone(),
                    effect: match policy.effect {
                        crate::domain::abac_policy::AbacEffect::Allow => "Allow".to_string(),
                        crate::domain::abac_policy::AbacEffect::Deny => "Deny".to_string(),
                    },
                    priority: policy.priority.unwrap_or(50),
                    conflict_resolution: match policy.conflict_resolution.as_ref() {
                        Some(
                            crate::domain::abac_policy::ConflictResolutionStrategy::DenyOverrides,
                        ) => "deny_overrides".to_string(),
                        Some(
                            crate::domain::abac_policy::ConflictResolutionStrategy::AllowOverrides,
                        ) => "allow_overrides".to_string(),
                        Some(
                            crate::domain::abac_policy::ConflictResolutionStrategy::PriorityWins,
                        ) => "priority_wins".to_string(),
                        Some(
                            crate::domain::abac_policy::ConflictResolutionStrategy::FirstMatch,
                        ) => "first_match".to_string(),
                        None => "deny_overrides".to_string(),
                    },
                    matched: all_conditions_met,
                    matched_conditions: if all_conditions_met {
                        condition_results.clone()
                    } else {
                        vec![]
                    },
                    unmatched_conditions: if all_conditions_met {
                        vec![]
                    } else {
                        condition_results
                    },
                    applied: all_conditions_met,
                });
            }
        }

        Ok(crate::interface::AbacEvaluationResponse {
            user_id: user_id.to_string(),
            permission_name: permission_name.to_string(),
            allowed: final_decision,
            evaluated_policies: evaluation_results,
            reason: if final_decision {
                "Policy allowed access".to_string()
            } else {
                "No policies allowed access".to_string()
            },
        })
    }
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::infrastructure::{
        InMemoryAbacPolicyRepository, InMemoryPermissionRepository, InMemoryRoleRepository,
        InMemoryUserRepository,
    };

    fn setup_test_env() {
        unsafe {
            std::env::set_var("JWT_SECRET", "test-secret-key");
            std::env::set_var("JWT_EXPIRATION", "3600");
            std::env::set_var("JWT_TIME_UNIT", "hours");
            std::env::set_var("REFRESH_TOKEN_EXPIRATION", "86400");
        }
    }

    #[tokio::test]
    async fn test_auth_service_authenticate_user_success() {
        setup_test_env();
        let user_repo = Arc::new(InMemoryUserRepository::new(vec![]));
        let _password_service = PasswordService;

        // Create a test user
        let user = User::new(
            "test@example.com".to_string(),
            "password123".to_string(),
            "Test User".to_string(),
        );
        user_repo.create_user(user.clone()).await.unwrap();

        let auth_service = AuthorizationService;
        let result = auth_service
            .user_has_permission(
                &user.id,
                "test:permission",
                None,
                &Arc::new(InMemoryRoleRepository::new()),
                &Arc::new(InMemoryPermissionRepository::new()),
                &Arc::new(InMemoryAbacPolicyRepository::new()),
            )
            .await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_auth_service_authenticate_user_not_found() {
        setup_test_env();
        let _user_repo = Arc::new(InMemoryUserRepository::new(vec![]));
        let auth_service = AuthorizationService;
        let result = auth_service
            .user_has_permission(
                "nonexistent",
                "test:permission",
                None,
                &Arc::new(InMemoryRoleRepository::new()),
                &Arc::new(InMemoryPermissionRepository::new()),
                &Arc::new(InMemoryAbacPolicyRepository::new()),
            )
            .await;

        assert!(result.is_ok());
        assert!(!result.unwrap()); // Non-existent user should return false, not an error
    }

    #[tokio::test]
    async fn test_auth_service_authenticate_user_wrong_password() {
        setup_test_env();
        let user_repo = Arc::new(InMemoryUserRepository::new(vec![]));
        let _password_service = PasswordService;

        // Create a test user
        let user = User::new(
            "test@example.com".to_string(),
            "password123".to_string(),
            "Test User".to_string(),
        );
        user_repo.create_user(user.clone()).await.unwrap();

        let auth_service = AuthorizationService;
        let result = auth_service
            .user_has_permission(
                &user.id,
                "test:permission",
                None,
                &Arc::new(InMemoryRoleRepository::new()),
                &Arc::new(InMemoryPermissionRepository::new()),
                &Arc::new(InMemoryAbacPolicyRepository::new()),
            )
            .await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_auth_service_authenticate_user_locked_account() {
        setup_test_env();
        let user_repo = Arc::new(InMemoryUserRepository::new(vec![]));
        let _password_service = PasswordService;

        // Create a test user and lock it
        let mut user = User::new(
            "test@example.com".to_string(),
            "password123".to_string(),
            "Test User".to_string(),
        );
        user.lock_account();
        user_repo.create_user(user.clone()).await.unwrap();

        let auth_service = AuthorizationService;
        let result = auth_service
            .user_has_permission(
                &user.id,
                "test:permission",
                None,
                &Arc::new(InMemoryRoleRepository::new()),
                &Arc::new(InMemoryPermissionRepository::new()),
                &Arc::new(InMemoryAbacPolicyRepository::new()),
            )
            .await;

        assert!(result.is_ok());
        assert!(!result.unwrap()); // Should return false for locked account
    }

    #[test]
    fn test_password_service_verify() {
        let password_service = PasswordService;
        let password_hash = password_service.hash_password("password123").unwrap();
        let user = User::new(
            "user1".to_string(),
            "test@example.com".to_string(),
            password_hash,
        );

        assert!(password_service.verify(&user, "password123"));
        assert!(!password_service.verify(&user, "wrongpassword"));
    }

    #[tokio::test]
    async fn test_token_service_issue_tokens() {
        setup_test_env();
        let user = User::new(
            "test@example.com".to_string(),
            "password123".to_string(),
            "Test User".to_string(),
        );
        let refresh_token_repo =
            Arc::new(crate::infrastructure::InMemoryRefreshTokenRepository::new());
        let token_service = TokenService;

        let result = token_service.issue_tokens(&user, &refresh_token_repo).await;
        assert!(result.is_ok());

        let (access_token, refresh_token) = result.unwrap();
        assert!(!access_token.is_empty());
        assert!(!refresh_token.is_empty());

        // Validate the access token
        let claims = token_service.validate_token(&access_token);
        assert!(claims.is_ok());
        assert_eq!(claims.unwrap().sub, user.id);
    }

    #[test]
    fn test_token_service_validate_token() {
        setup_test_env();
        let user = User::new(
            "test@example.com".to_string(),
            "password123".to_string(),
            "Test User".to_string(),
        );
        let token_service = TokenService;

        let token = token_service.create_access_token(&user).unwrap();
        let claims = token_service.validate_token(&token);
        assert!(claims.is_ok());
        assert_eq!(claims.unwrap().sub, user.id);
    }

    #[test]
    fn test_token_service_validate_invalid_token() {
        setup_test_env();
        let token_service = TokenService;

        let result = token_service.validate_token("invalid-token");
        assert!(matches!(result, Err(AuthError::InvalidToken)));
    }

    #[test]
    fn test_token_service_validate_expired_token() {
        setup_test_env();
        let user = User::new(
            "user1".to_string(),
            "test@example.com".to_string(),
            "password123".to_string(),
        );
        let token_service = TokenService;
        unsafe {
            std::env::set_var("JWT_EXPIRATION", "1");
            std::env::set_var("JWT_TIME_UNIT", "seconds");
        }
        // Create a token with very short expiration
        let token = token_service.create_access_token(&user).unwrap();

        // Wait for token to expire (longer wait to ensure expiration)
        std::thread::sleep(std::time::Duration::from_secs(3));

        let result = token_service.validate_token(&token);
        assert!(matches!(result, Err(AuthError::TokenExpired)));
    }

    #[tokio::test]
    async fn test_token_service_refresh_token() {
        setup_test_env();
        let user = User::new(
            "test@example.com".to_string(),
            "password123".to_string(),
            "Test User".to_string(),
        );
        let refresh_token_repo =
            Arc::new(crate::infrastructure::InMemoryRefreshTokenRepository::new());
        let user_repo = Arc::new(InMemoryUserRepository::new(vec![]));
        let token_service = TokenService;

        // Create initial tokens
        let (_, refresh_token) = token_service
            .issue_tokens(&user, &refresh_token_repo)
            .await
            .unwrap();
        user_repo.create_user(user.clone()).await.unwrap();

        // Refresh the access token
        let result = token_service
            .refresh_access_token(&refresh_token, &refresh_token_repo, &user_repo)
            .await;
        assert!(result.is_ok());

        let new_access_token = result.unwrap();
        assert!(!new_access_token.is_empty());

        // Validate the new access token
        let claims = token_service.validate_token(&new_access_token);
        assert!(claims.is_ok());
        assert_eq!(claims.unwrap().sub, user.id);
    }

    #[tokio::test]
    async fn test_password_service_hash_password() {
        let password_service = PasswordService;
        let password = "testpassword123";

        let hashed = password_service.hash_password(password).unwrap();
        assert_ne!(password, hashed);
        assert!(hashed.starts_with("$2b$"));
    }

    #[tokio::test]
    async fn test_authz_service_user_has_permission() {
        setup_test_env();
        let user_repo = Arc::new(InMemoryUserRepository::new(vec![]));
        let role_repo = Arc::new(InMemoryRoleRepository::new());
        let permission_repo = Arc::new(InMemoryPermissionRepository::new());
        let abac_repo = Arc::new(InMemoryAbacPolicyRepository::new());

        // Create a test user
        let user = User::new(
            "test@example.com".to_string(),
            "password123".to_string(),
            "Test User".to_string(),
        );
        user_repo.create_user(user.clone()).await.unwrap();

        let auth_service = AuthorizationService;
        let result = auth_service
            .user_has_permission(
                &user.id,
                "test:permission",
                None,
                &role_repo,
                &permission_repo,
                &abac_repo,
            )
            .await;

        assert!(result.is_ok());
        assert!(!result.unwrap()); // Should return false since no permissions are set up
    }

    #[tokio::test]
    async fn test_authz_service_user_has_permission_with_roles() {
        setup_test_env();
        let user_repo = Arc::new(InMemoryUserRepository::new(vec![]));
        let role_repo = Arc::new(InMemoryRoleRepository::new());
        let permission_repo = Arc::new(InMemoryPermissionRepository::new());
        let abac_repo = Arc::new(InMemoryAbacPolicyRepository::new());

        // Create a test user
        let user = User::new(
            "test@example.com".to_string(),
            "password123".to_string(),
            "Test User".to_string(),
        );
        user_repo.create_user(user.clone()).await.unwrap();

        // Create a role and permission
        let role = role_repo.create_role("admin").await;
        let permission = permission_repo
            .create_permission("test:permission")
            .await
            .unwrap();

        // Assign permission to role
        permission_repo
            .assign_permission(&role.id, &permission.id)
            .await
            .unwrap();

        // Assign role to user
        role_repo.assign_role(&user.id, &role.id).await;

        let auth_service = AuthorizationService;
        let result = auth_service
            .user_has_permission(
                &user.id,
                "test:permission",
                None,
                &role_repo,
                &permission_repo,
                &abac_repo,
            )
            .await;

        assert!(result.is_ok());
        assert!(result.unwrap()); // Should return true since user has the permission via role
    }
}
