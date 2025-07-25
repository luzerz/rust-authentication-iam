use crate::domain::user::User;
use crate::infrastructure::AbacPolicyRepository;
use crate::infrastructure::RefreshTokenRepository;
use crate::infrastructure::UserRepository;
use chrono::{Duration, Utc};
use jsonwebtoken::{
    Algorithm, DecodingKey, EncodingKey, Header, TokenData, Validation, decode, encode,
    errors::Error as JwtError,
};
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use std::env;
use std::sync::Arc;
use tracing::{error, info, instrument};
use uuid::Uuid;

static JWT_SECRET: Lazy<Vec<u8>> = Lazy::new(|| {
    env::var("JWT_SECRET")
        .expect("JWT_SECRET must be set")
        .into_bytes()
});
const ACCESS_TOKEN_EXP_MIN: i64 = 15;
const REFRESH_TOKEN_EXP_MIN: i64 = 60 * 24 * 7; // 7 days

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Claims {
    pub sub: String,
    pub exp: usize,
    pub roles: Vec<String>,
    pub jti: String,
}

#[derive(Debug)]
pub struct RefreshToken {
    pub jti: String,
    pub user_id: String,
    pub expires_at: chrono::NaiveDateTime,
    pub revoked: bool,
}

pub struct AuthService;
pub struct PasswordService;
pub struct TokenService;
pub struct RoleService;

impl AuthService {
    /// Authenticates a user by email and password. Returns user if successful.
    #[instrument(
        name = "authenticate_user",
        skip(self, user_repo, password_service),
        fields(email)
    )]
    pub async fn authenticate_user(
        &self,
        email: &str,
        password: &str,
        user_repo: Arc<dyn UserRepository>,
        password_service: &PasswordService,
    ) -> Result<User, AuthError> {
        info!("Looking up user");
        let user = user_repo
            .find_by_email(email)
            .await
            .ok_or(AuthError::InvalidCredentials)?;
        if user.is_account_locked() {
            error!(user_id = %user.id, "Account is locked");
            return Err(AuthError::AccountLocked);
        }
        if !password_service.verify(&user, password) {
            error!(user_id = %user.id, "Invalid credentials");
            return Err(AuthError::InvalidCredentials);
        }
        info!(user_id = %user.id, "User authenticated");
        Ok(user)
    }
}

impl PasswordService {
    /// Verifies a plaintext password against the user's hash.
    pub fn verify(&self, user: &User, password: &str) -> bool {
        user.verify_password(password).unwrap_or(false)
    }
}

impl TokenService {
    /// Issues a new JWT access token and refresh token for the user, and stores the refresh token in the DB.
    #[instrument(name = "issue_tokens", skip(self, user, refresh_token_repo))]
    pub async fn issue_tokens(
        &self,
        user: &User,
        refresh_token_repo: Arc<dyn RefreshTokenRepository>,
    ) -> (String, String) {
        info!(user_id = %user.id, "Generating tokens");
        let now = Utc::now();
        let access_jti = Uuid::new_v4().to_string();
        let refresh_jti = Uuid::new_v4().to_string();
        let access_claims = Claims {
            sub: user.id.clone(),
            exp: (now + Duration::minutes(ACCESS_TOKEN_EXP_MIN)).timestamp() as usize,
            roles: user.roles.clone(),
            jti: access_jti.clone(),
        };
        let refresh_claims = Claims {
            sub: user.id.clone(),
            exp: (now + Duration::minutes(REFRESH_TOKEN_EXP_MIN)).timestamp() as usize,
            roles: vec![],
            jti: refresh_jti.clone(),
        };
        let access_token = encode(
            &Header::new(Algorithm::HS256),
            &access_claims,
            &EncodingKey::from_secret(&JWT_SECRET),
        )
        .unwrap();
        let refresh_token = encode(
            &Header::new(Algorithm::HS256),
            &refresh_claims,
            &EncodingKey::from_secret(&JWT_SECRET),
        )
        .unwrap();
        // Store refresh token in DB
        let refresh_token_record = RefreshToken {
            jti: refresh_jti.clone(),
            user_id: user.id.clone(),
            expires_at: (now + Duration::minutes(REFRESH_TOKEN_EXP_MIN)).naive_utc(),
            revoked: false,
        };
        let _ = refresh_token_repo.insert(refresh_token_record).await;
        info!(user_id = %user.id, "Tokens stored in DB");
        (access_token, refresh_token)
    }

    /// Validates a JWT and returns claims if valid.
    #[instrument(name = "validate_token", skip(self))]
    pub fn validate_token(&self, token: &str) -> Result<Claims, JwtError> {
        info!("Validating token");
        let token_data: TokenData<Claims> = decode(
            token,
            &DecodingKey::from_secret(&JWT_SECRET),
            &Validation::new(Algorithm::HS256),
        )?;
        info!(user_id = %token_data.claims.sub, "Token valid");
        Ok(token_data.claims)
    }

    /// Validates a refresh token and issues new tokens if valid, checking the DB.
    #[instrument(name = "refresh_tokens", skip(self, user, refresh_token_repo))]
    pub async fn refresh_tokens(
        &self,
        refresh_token: &str,
        user: &User,
        refresh_token_repo: Arc<dyn RefreshTokenRepository>,
    ) -> Result<(String, String), JwtError> {
        info!(user_id = %user.id, "Refreshing tokens");
        let claims = self.validate_token(refresh_token)?;
        // Check DB for validity
        if !refresh_token_repo
            .is_valid(&claims.jti)
            .await
            .unwrap_or(false)
        {
            error!(user_id = %user.id, "Refresh token is invalid or revoked");
            return Err(JwtError::from(
                jsonwebtoken::errors::ErrorKind::InvalidToken,
            ));
        }
        // Optionally, revoke the old token (rotation)
        let _ = refresh_token_repo.revoke(&claims.jti).await;
        info!(user_id = %user.id, "Old refresh token revoked, issuing new tokens");
        Ok(self.issue_tokens(user, refresh_token_repo).await)
    }
}

#[derive(Debug)]
pub enum AuthError {
    InvalidCredentials,
    AccountLocked,
    Other(String),
}

pub struct AuthZService {
    pub role_repo: Arc<dyn crate::infrastructure::RoleRepository>,
    pub permission_repo: Arc<dyn crate::infrastructure::PermissionRepository>,
    pub abac_repo: Arc<dyn AbacPolicyRepository>,
}

impl AuthZService {
    pub async fn user_has_permission(
        &self,
        user_id: &str,
        permission_name: &str,
        user_attrs: Option<&std::collections::HashMap<String, String>>,
    ) -> Result<bool, sqlx::Error> {
        // RBAC check with role inheritance
        let roles = self.role_repo.get_roles_for_user(user_id).await?;
        let perms = self.permission_repo.list_permissions().await?;

        // Check direct role permissions
        for role in &roles {
            for perm in &perms {
                if perm.name == permission_name {
                    let assigned = self
                        .permission_repo
                        .role_has_permission(&role.id, &perm.id)
                        .await?;
                    if assigned {
                        return Ok(true);
                    }
                }
            }
        }

        // Check inherited role permissions
        for role in &roles {
            let inherited_roles = self.role_repo.get_inherited_roles(&role.id).await?;
            for inherited_role in &inherited_roles {
                for perm in &perms {
                    if perm.name == permission_name {
                        let assigned = self
                            .permission_repo
                            .role_has_permission(&inherited_role.id, &perm.id)
                            .await?;
                        if assigned {
                            return Ok(true);
                        }
                    }
                }
            }
        }

        // ABAC check
        if let Some(attrs) = user_attrs {
            if self
                .user_has_abac_permission(user_id, permission_name, attrs)
                .await?
            {
                return Ok(true);
            }
        }
        Ok(false)
    }

    pub async fn user_has_abac_permission(
        &self,
        user_id: &str,
        permission_name: &str,
        user_attrs: &std::collections::HashMap<String, String>,
    ) -> Result<bool, sqlx::Error> {
        use crate::domain::abac_policy::AbacEffect;
        let policies = self.abac_repo.get_policies_for_user(user_id).await?;
        for policy in &policies {
            // For now, assume policy name == permission_name (can be extended)
            if policy.name == permission_name {
                let mut all_match = true;
                for cond in &policy.conditions {
                    let val = user_attrs.get(&cond.attribute);
                    match (val, cond.operator.as_str()) {
                        (Some(v), "eq") if v == &cond.value => {}
                        (Some(v), "ne") if v != &cond.value => {}
                        // Extend with more operators as needed
                        _ => {
                            all_match = false;
                            break;
                        }
                    }
                }
                if all_match {
                    return Ok(matches!(policy.effect, AbacEffect::Allow));
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
    ) -> Result<crate::interface::AbacEvaluationResponse, sqlx::Error> {
        use crate::domain::abac_policy::{AbacEffect, ConflictResolutionStrategy};
        use crate::interface::{AbacConditionDto, AbacPolicyEvaluationResult};

        let policies = self.abac_repo.get_policies_for_user(user_id).await?;
        let mut evaluated_policies = Vec::new();
        let mut matching_policies = Vec::new();

        // First pass: evaluate all policies and collect matching ones
        for policy in &policies {
            // Check if policy name matches permission (can be extended for more complex matching)
            if policy.name == permission_name {
                let mut matched_conditions = Vec::new();
                let mut unmatched_conditions = Vec::new();
                let mut all_match = true;

                for cond in &policy.conditions {
                    let val = user_attrs.get(&cond.attribute);
                    let condition_dto = AbacConditionDto {
                        attribute: cond.attribute.clone(),
                        operator: cond.operator.clone(),
                        value: cond.value.clone(),
                    };

                    match (val, cond.operator.as_str()) {
                        (Some(v), "eq") if v == &cond.value => {
                            matched_conditions.push(condition_dto);
                        }
                        (Some(v), "ne") if v != &cond.value => {
                            matched_conditions.push(condition_dto);
                        }
                        (Some(v), "in") => {
                            // Check if value is in comma-separated list
                            let values: Vec<&str> = cond.value.split(',').collect();
                            if values.contains(&v.as_str()) {
                                matched_conditions.push(condition_dto);
                            } else {
                                unmatched_conditions.push(condition_dto);
                                all_match = false;
                            }
                        }
                        (Some(v), "gt") => {
                            // Numeric comparison
                            if let (Ok(attr_val), Ok(cond_val)) =
                                (v.parse::<f64>(), cond.value.parse::<f64>())
                            {
                                if attr_val > cond_val {
                                    matched_conditions.push(condition_dto);
                                } else {
                                    unmatched_conditions.push(condition_dto);
                                    all_match = false;
                                }
                            } else {
                                unmatched_conditions.push(condition_dto);
                                all_match = false;
                            }
                        }
                        (Some(v), "lt") => {
                            // Numeric comparison
                            if let (Ok(attr_val), Ok(cond_val)) =
                                (v.parse::<f64>(), cond.value.parse::<f64>())
                            {
                                if attr_val < cond_val {
                                    matched_conditions.push(condition_dto);
                                } else {
                                    unmatched_conditions.push(condition_dto);
                                    all_match = false;
                                }
                            } else {
                                unmatched_conditions.push(condition_dto);
                                all_match = false;
                            }
                        }
                        (Some(v), "gte") => {
                            // Numeric comparison
                            if let (Ok(attr_val), Ok(cond_val)) =
                                (v.parse::<f64>(), cond.value.parse::<f64>())
                            {
                                if attr_val >= cond_val {
                                    matched_conditions.push(condition_dto);
                                } else {
                                    unmatched_conditions.push(condition_dto);
                                    all_match = false;
                                }
                            } else {
                                unmatched_conditions.push(condition_dto);
                                all_match = false;
                            }
                        }
                        (Some(v), "lte") => {
                            // Numeric comparison
                            if let (Ok(attr_val), Ok(cond_val)) =
                                (v.parse::<f64>(), cond.value.parse::<f64>())
                            {
                                if attr_val <= cond_val {
                                    matched_conditions.push(condition_dto);
                                } else {
                                    unmatched_conditions.push(condition_dto);
                                    all_match = false;
                                }
                            } else {
                                unmatched_conditions.push(condition_dto);
                                all_match = false;
                            }
                        }
                        (Some(v), "contains") => {
                            if v.contains(&cond.value) {
                                matched_conditions.push(condition_dto);
                            } else {
                                unmatched_conditions.push(condition_dto);
                                all_match = false;
                            }
                        }
                        (Some(v), "starts_with") => {
                            if v.starts_with(&cond.value) {
                                matched_conditions.push(condition_dto);
                            } else {
                                unmatched_conditions.push(condition_dto);
                                all_match = false;
                            }
                        }
                        (Some(v), "ends_with") => {
                            if v.ends_with(&cond.value) {
                                matched_conditions.push(condition_dto);
                            } else {
                                unmatched_conditions.push(condition_dto);
                                all_match = false;
                            }
                        }
                        _ => {
                            unmatched_conditions.push(condition_dto);
                            all_match = false;
                        }
                    }
                }

                let effect_str = match policy.effect {
                    AbacEffect::Allow => "Allow",
                    AbacEffect::Deny => "Deny",
                };

                let evaluation_result = AbacPolicyEvaluationResult {
                    policy_id: policy.id.clone(),
                    policy_name: policy.name.clone(),
                    effect: effect_str.to_string(),
                    priority: policy.priority.unwrap_or(50),
                    conflict_resolution: match policy
                        .conflict_resolution
                        .as_ref()
                        .unwrap_or(&ConflictResolutionStrategy::DenyOverrides)
                    {
                        ConflictResolutionStrategy::DenyOverrides => "deny_overrides".to_string(),
                        ConflictResolutionStrategy::AllowOverrides => "allow_overrides".to_string(),
                        ConflictResolutionStrategy::PriorityWins => "priority_wins".to_string(),
                        ConflictResolutionStrategy::FirstMatch => "first_match".to_string(),
                    },
                    matched: all_match,
                    matched_conditions,
                    unmatched_conditions,
                    applied: false, // Will be set later based on conflict resolution
                };

                evaluated_policies.push(evaluation_result.clone());

                if all_match {
                    matching_policies.push((policy, evaluation_result));
                }
            }
        }

        // Second pass: apply conflict resolution strategy
        let (allowed, reason, applied_policy_id) = if matching_policies.is_empty() {
            (false, "No policies matched".to_string(), None)
        } else {
            // Determine which policy to apply based on conflict resolution strategy
            let conflict_strategy = matching_policies[0]
                .0
                .conflict_resolution
                .as_ref()
                .unwrap_or(&ConflictResolutionStrategy::DenyOverrides);

            match conflict_strategy {
                ConflictResolutionStrategy::FirstMatch => {
                    // First matching policy wins (current behavior)
                    let (policy, _eval_result) = &matching_policies[0];
                    let allowed = matches!(policy.effect, AbacEffect::Allow);
                    let reason = format!(
                        "First matching policy '{}' applied with effect '{}'",
                        policy.name,
                        if allowed { "Allow" } else { "Deny" }
                    );
                    (allowed, reason, Some(policy.id.clone()))
                }
                ConflictResolutionStrategy::DenyOverrides => {
                    // Deny policies take precedence over Allow policies
                    let deny_policy = matching_policies
                        .iter()
                        .find(|(p, _)| matches!(p.effect, AbacEffect::Deny));
                    if let Some((policy, _)) = deny_policy {
                        (
                            false,
                            format!("Deny policy '{}' overrides all allow policies", policy.name),
                            Some(policy.id.clone()),
                        )
                    } else {
                        let (policy, _) = &matching_policies[0];
                        (
                            true,
                            format!("Allow policy '{}' applied (no deny policies)", policy.name),
                            Some(policy.id.clone()),
                        )
                    }
                }
                ConflictResolutionStrategy::AllowOverrides => {
                    // Allow policies take precedence over Deny policies
                    let allow_policy = matching_policies
                        .iter()
                        .find(|(p, _)| matches!(p.effect, AbacEffect::Allow));
                    if let Some((policy, _)) = allow_policy {
                        (
                            true,
                            format!("Allow policy '{}' overrides all deny policies", policy.name),
                            Some(policy.id.clone()),
                        )
                    } else {
                        let (policy, _) = &matching_policies[0];
                        (
                            false,
                            format!("Deny policy '{}' applied (no allow policies)", policy.name),
                            Some(policy.id.clone()),
                        )
                    }
                }
                ConflictResolutionStrategy::PriorityWins => {
                    // Higher priority policy wins regardless of effect
                    let highest_priority_policy = matching_policies
                        .iter()
                        .max_by_key(|(p, _)| p.priority.unwrap_or(50))
                        .unwrap();
                    let (policy, _) = highest_priority_policy;
                    let allowed = matches!(policy.effect, AbacEffect::Allow);
                    let reason = format!(
                        "Highest priority policy '{}' (priority: {}) applied with effect '{}'",
                        policy.name,
                        policy.priority.unwrap_or(50),
                        if allowed { "Allow" } else { "Deny" }
                    );
                    (allowed, reason, Some(policy.id.clone()))
                }
            }
        };

        // Mark the applied policy
        for eval_result in &mut evaluated_policies {
            if let Some(applied_id) = &applied_policy_id {
                if eval_result.policy_id == *applied_id {
                    eval_result.applied = true;
                }
            }
        }

        Ok(crate::interface::AbacEvaluationResponse {
            user_id: user_id.to_string(),
            permission_name: permission_name.to_string(),
            allowed,
            evaluated_policies,
            reason,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::user::User;
    use crate::infrastructure::{
        InMemoryAbacPolicyRepository, InMemoryPermissionRepository, InMemoryRefreshTokenRepository,
        InMemoryRoleRepository, InMemoryUserRepository, PermissionRepository, RoleRepository,
    };
    use bcrypt::{DEFAULT_COST, hash};
    use std::sync::Arc;

    // Set up test environment
    fn setup_test_env() {
        unsafe {
            std::env::set_var("JWT_SECRET", "test-secret-key-for-testing-only");
        }
    }

    #[tokio::test]
    async fn test_auth_service_authenticate_user_success() {
        let password_hash = hash("password", DEFAULT_COST).unwrap();
        let user = User {
            id: "user1".to_string(),
            email: "user@example.com".to_string(),
            password_hash,
            roles: vec![],
            is_locked: false,
        };
        let user_repo = Arc::new(InMemoryUserRepository::new(vec![user]));
        let auth_service = AuthService;
        let password_service = PasswordService;
        let result = auth_service
            .authenticate_user("user@example.com", "password", user_repo, &password_service)
            .await;
        assert!(result.is_ok());
        let authenticated_user = result.unwrap();
        assert_eq!(authenticated_user.email, "user@example.com");
    }

    #[tokio::test]
    async fn test_auth_service_authenticate_user_not_found() {
        let user_repo = Arc::new(InMemoryUserRepository::new(vec![]));
        let auth_service = AuthService;
        let password_service = PasswordService;
        let result = auth_service
            .authenticate_user(
                "nonexistent@example.com",
                "password",
                user_repo,
                &password_service,
            )
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_auth_service_authenticate_user_wrong_password() {
        let password_hash = hash("password", DEFAULT_COST).unwrap();
        let user = User {
            id: "user1".to_string(),
            email: "user@example.com".to_string(),
            password_hash,
            roles: vec![],
            is_locked: false,
        };
        let user_repo = Arc::new(InMemoryUserRepository::new(vec![user]));
        let auth_service = AuthService;
        let password_service = PasswordService;
        let result = auth_service
            .authenticate_user(
                "user@example.com",
                "wrongpassword",
                user_repo,
                &password_service,
            )
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_auth_service_authenticate_user_locked_account() {
        let password_hash = hash("password", DEFAULT_COST).unwrap();
        let user = User {
            id: "user1".to_string(),
            email: "user@example.com".to_string(),
            password_hash,
            roles: vec![],
            is_locked: true,
        };
        let user_repo = Arc::new(InMemoryUserRepository::new(vec![user]));
        let auth_service = AuthService;
        let password_service = PasswordService;
        let result = auth_service
            .authenticate_user("user@example.com", "password", user_repo, &password_service)
            .await;
        assert!(result.is_err());
    }

    #[test]
    fn test_password_service_verify() {
        let password_service = PasswordService;
        let user = User {
            id: "user1".to_string(),
            email: "test@example.com".to_string(),
            password_hash: hash("testpassword", DEFAULT_COST).unwrap(),
            roles: vec!["user".to_string()],
            is_locked: false,
        };

        assert!(password_service.verify(&user, "testpassword"));
        assert!(!password_service.verify(&user, "wrongpassword"));
    }

    #[tokio::test]
    async fn test_token_service_issue_tokens() {
        setup_test_env();
        let token_service = TokenService;
        let user = User {
            id: "user1".to_string(),
            email: "test@example.com".to_string(),
            password_hash: "hash".to_string(),
            roles: vec!["user".to_string()],
            is_locked: false,
        };
        let refresh_token_repo = Arc::new(InMemoryRefreshTokenRepository::new());

        let (access_token, refresh_token) =
            token_service.issue_tokens(&user, refresh_token_repo).await;

        assert!(!access_token.is_empty());
        assert!(!refresh_token.is_empty());
        assert_ne!(access_token, refresh_token);
    }

    #[test]
    fn test_token_service_validate_token() {
        setup_test_env();
        let token_service = TokenService;
        let user = User {
            id: "user1".to_string(),
            email: "test@example.com".to_string(),
            password_hash: "hash".to_string(),
            roles: vec!["user".to_string()],
            is_locked: false,
        };

        // Create a token manually for testing
        let now = Utc::now();
        let claims = Claims {
            sub: user.id.clone(),
            exp: (now + Duration::minutes(15)).timestamp() as usize,
            roles: user.roles.clone(),
            jti: Uuid::new_v4().to_string(),
        };
        let token = encode(
            &Header::new(Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(&JWT_SECRET),
        )
        .unwrap();

        let validated_claims = token_service.validate_token(&token).unwrap();

        assert_eq!(validated_claims.sub, "user1");
        assert_eq!(validated_claims.roles, vec!["user".to_string()]);
    }

    #[test]
    fn test_token_service_validate_invalid_token() {
        setup_test_env();
        let token_service = TokenService;
        let invalid_token = "invalid.jwt.token";

        let result = token_service.validate_token(invalid_token);
        assert!(result.is_err());
    }

    #[test]
    fn test_token_service_validate_expired_token() {
        setup_test_env();
        let token_service = TokenService;
        let user = User {
            id: "user1".to_string(),
            email: "test@example.com".to_string(),
            password_hash: "hash".to_string(),
            roles: vec!["user".to_string()],
            is_locked: false,
        };

        // Create a token with expired timestamp (past time)
        let claims = Claims {
            sub: user.id.clone(),
            exp: 1, // Very old timestamp (1970-01-01)
            roles: user.roles.clone(),
            jti: Uuid::new_v4().to_string(),
        };
        let token = encode(
            &Header::new(Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(&JWT_SECRET),
        )
        .unwrap();

        let result = token_service.validate_token(&token);
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_token_service_refresh_token() {
        setup_test_env();
        let token_service = TokenService;
        let user = User {
            id: "user1".to_string(),
            email: "test@example.com".to_string(),
            password_hash: "hash".to_string(),
            roles: vec!["user".to_string()],
            is_locked: false,
        };

        // Test that issue_tokens returns both access and refresh tokens
        let refresh_token_repo = Arc::new(InMemoryRefreshTokenRepository::new());
        let (access_token, refresh_token) =
            token_service.issue_tokens(&user, refresh_token_repo).await;

        assert!(!access_token.is_empty());
        assert!(!refresh_token.is_empty());
        assert_ne!(access_token, refresh_token);
    }

    #[tokio::test]
    async fn test_password_service_hash_password() {
        let password = "testpassword";
        let hash = hash(password, DEFAULT_COST).unwrap();
        assert!(!hash.is_empty());
        assert_ne!(hash, password);
    }

    #[tokio::test]
    async fn test_authz_service_user_has_permission() {
        let role_repo = Arc::new(InMemoryRoleRepository::new());
        let permission_repo = Arc::new(InMemoryPermissionRepository::new());
        let abac_repo = Arc::new(InMemoryAbacPolicyRepository::new());

        let authz_service = AuthZService {
            role_repo,
            permission_repo,
            abac_repo,
        };

        // Test with user that has no roles
        let result = authz_service
            .user_has_permission("user1", "read", None)
            .await;
        assert!(result.is_ok());
        assert!(!result.unwrap());
    }

    #[tokio::test]
    async fn test_authz_service_user_has_permission_with_roles() {
        let role_repo = Arc::new(InMemoryRoleRepository::new());
        let permission_repo = Arc::new(InMemoryPermissionRepository::new());
        let abac_repo = Arc::new(InMemoryAbacPolicyRepository::new());

        let authz_service = AuthZService {
            role_repo: role_repo.clone(),
            permission_repo: permission_repo.clone(),
            abac_repo,
        };

        // Create a role and permission
        let role = role_repo.create_role("admin").await;
        let permission = permission_repo.create_permission("read").await.unwrap();

        // Assign permission to role
        permission_repo
            .assign_permission(&role.id, &permission.id)
            .await
            .unwrap();

        // Assign role to user
        role_repo.assign_role("user1", &role.id).await;

        // Test permission check
        let result = authz_service
            .user_has_permission("user1", "read", None)
            .await;
        assert!(result.is_ok());
        assert!(result.unwrap());
    }
}
