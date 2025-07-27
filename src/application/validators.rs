use crate::infrastructure::UserRepository;
use async_trait::async_trait;
use std::sync::Arc;

/// Validation error types
#[derive(Debug)]
pub enum ValidationError {
    FieldValidation { field: String, message: String },
    BusinessRule { message: String },
    UserNotFound,
    UserAlreadyExists,
    InvalidEmail,
    PasswordTooWeak,
    AccountLocked,
}

impl std::fmt::Display for ValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ValidationError::FieldValidation { field, message } => {
                write!(f, "Field validation failed: {field} - {message}")
            }
            ValidationError::BusinessRule { message } => {
                write!(f, "Business rule violation: {message}")
            }
            ValidationError::UserNotFound => write!(f, "User not found"),
            ValidationError::UserAlreadyExists => write!(f, "User already exists"),
            ValidationError::InvalidEmail => write!(f, "Invalid email format"),
            ValidationError::PasswordTooWeak => write!(f, "Password too weak"),
            ValidationError::AccountLocked => write!(f, "Account is locked"),
        }
    }
}

impl std::error::Error for ValidationError {}

/// Base trait for command validation
#[async_trait]
pub trait CommandValidator<C>: Send + Sync {
    async fn validate(&self, command: &C) -> Result<(), ValidationError>;
}

/// User command validation rules
pub struct UserCommandValidator;

impl UserCommandValidator {
    /// Validates email format
    pub fn validate_email(email: &str) -> Result<(), ValidationError> {
        if !email.contains('@') || !email.contains('.') {
            return Err(ValidationError::FieldValidation {
                field: "email".to_string(),
                message: "Invalid email format".to_string(),
            });
        }
        Ok(())
    }

    /// Validates password strength
    pub fn validate_password(password: &str) -> Result<(), ValidationError> {
        if password.len() < 8 {
            return Err(ValidationError::FieldValidation {
                field: "password".to_string(),
                message: "Password must be at least 8 characters long".to_string(),
            });
        }

        let has_uppercase = password.chars().any(|c| c.is_uppercase());
        let has_lowercase = password.chars().any(|c| c.is_lowercase());
        let has_digit = password.chars().any(|c| c.is_numeric());
        let has_special = password.chars().any(|c| !c.is_alphanumeric());

        if !has_uppercase || !has_lowercase || !has_digit || !has_special {
            return Err(ValidationError::FieldValidation {
                field: "password".to_string(),
                message: "Password must contain uppercase, lowercase, digit, and special character"
                    .to_string(),
            });
        }

        Ok(())
    }

    /// Validates user ID format
    pub fn validate_user_id(user_id: &str) -> Result<(), ValidationError> {
        if user_id.is_empty() {
            return Err(ValidationError::FieldValidation {
                field: "user_id".to_string(),
                message: "User ID cannot be empty".to_string(),
            });
        }
        Ok(())
    }
}

/// Login command validation
pub struct LoginCommandValidator {
    user_repo: Arc<dyn UserRepository + Send + Sync>,
}

impl LoginCommandValidator {
    pub fn new(user_repo: Arc<dyn UserRepository + Send + Sync>) -> Self {
        Self { user_repo }
    }
}

#[async_trait]
impl CommandValidator<crate::application::commands::LoginUserCommand> for LoginCommandValidator {
    async fn validate(
        &self,
        command: &crate::application::commands::LoginUserCommand,
    ) -> Result<(), ValidationError> {
        // Validate email format
        UserCommandValidator::validate_email(&command.email)?;

        // Validate password is not empty
        if command.password.is_empty() {
            return Err(ValidationError::FieldValidation {
                field: "password".to_string(),
                message: "Password cannot be empty".to_string(),
            });
        }

        // Check if user exists
        let user = self.user_repo.find_by_email(&command.email).await;
        if user.is_none() {
            return Err(ValidationError::UserNotFound);
        }

        // Check if account is locked
        if let Some(user) = user {
            if user.is_locked() {
                return Err(ValidationError::AccountLocked);
            }
        }

        Ok(())
    }
}

/// Change password command validation
pub struct ChangePasswordCommandValidator {
    user_repo: Arc<dyn UserRepository + Send + Sync>,
}

impl ChangePasswordCommandValidator {
    pub fn new(user_repo: Arc<dyn UserRepository + Send + Sync>) -> Self {
        Self { user_repo }
    }
}

#[async_trait]
impl CommandValidator<crate::application::commands::ChangePasswordCommand>
    for ChangePasswordCommandValidator
{
    async fn validate(
        &self,
        command: &crate::application::commands::ChangePasswordCommand,
    ) -> Result<(), ValidationError> {
        // Validate user ID
        UserCommandValidator::validate_user_id(&command.user_id)?;

        // Validate current password is not empty
        if command.current_password.is_empty() {
            return Err(ValidationError::FieldValidation {
                field: "current_password".to_string(),
                message: "Current password cannot be empty".to_string(),
            });
        }

        // Validate new password strength
        UserCommandValidator::validate_password(&command.new_password)?;

        // Check if user exists
        let user = self
            .user_repo
            .find_by_id(&command.user_id)
            .await
            .map_err(|_| ValidationError::UserNotFound)?
            .ok_or(ValidationError::UserNotFound)?;

        // Check if account is locked
        if user.is_locked() {
            return Err(ValidationError::AccountLocked);
        }

        Ok(())
    }
}

/// Reset password command validation
pub struct ResetPasswordCommandValidator;

#[async_trait]
impl CommandValidator<crate::application::commands::ResetPasswordCommand>
    for ResetPasswordCommandValidator
{
    async fn validate(
        &self,
        command: &crate::application::commands::ResetPasswordCommand,
    ) -> Result<(), ValidationError> {
        // Validate reset token is not empty
        if command.reset_token.is_empty() {
            return Err(ValidationError::FieldValidation {
                field: "reset_token".to_string(),
                message: "Reset token cannot be empty".to_string(),
            });
        }

        // Validate new password strength
        UserCommandValidator::validate_password(&command.new_password)?;

        Ok(())
    }
}

/// Assign roles command validation
pub struct AssignRolesCommandValidator {
    user_repo: Arc<dyn UserRepository + Send + Sync>,
}

impl AssignRolesCommandValidator {
    pub fn new(user_repo: Arc<dyn UserRepository + Send + Sync>) -> Self {
        Self { user_repo }
    }
}

#[async_trait]
impl CommandValidator<crate::application::commands::AssignRolesCommand>
    for AssignRolesCommandValidator
{
    async fn validate(
        &self,
        command: &crate::application::commands::AssignRolesCommand,
    ) -> Result<(), ValidationError> {
        // Validate user ID
        UserCommandValidator::validate_user_id(&command.user_id)?;

        // Validate role IDs are not empty
        if command.role_ids.is_empty() {
            return Err(ValidationError::FieldValidation {
                field: "role_ids".to_string(),
                message: "At least one role must be assigned".to_string(),
            });
        }

        // Validate each role ID
        for role_id in &command.role_ids {
            if role_id.is_empty() {
                return Err(ValidationError::FieldValidation {
                    field: "role_ids".to_string(),
                    message: "Role ID cannot be empty".to_string(),
                });
            }
        }

        // Check if user exists
        let user = self
            .user_repo
            .find_by_id(&command.user_id)
            .await
            .map_err(|_| ValidationError::UserNotFound)?
            .ok_or(ValidationError::UserNotFound)?;

        // Check if account is locked
        if user.is_locked() {
            return Err(ValidationError::AccountLocked);
        }

        Ok(())
    }
}

/// Validation result wrapper
#[derive(Debug)]
pub struct ValidationResult<T> {
    pub is_valid: bool,
    pub errors: Vec<ValidationError>,
    pub data: Option<T>,
}

impl<T> ValidationResult<T> {
    pub fn success(data: T) -> Self {
        Self {
            is_valid: true,
            errors: Vec::new(),
            data: Some(data),
        }
    }

    pub fn failure(errors: Vec<ValidationError>) -> Self {
        Self {
            is_valid: false,
            errors,
            data: None,
        }
    }

    pub fn add_error(&mut self, error: ValidationError) {
        self.is_valid = false;
        self.errors.push(error);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::application::commands::CommandFactory;
    use crate::domain::user::User;
    use crate::infrastructure::InMemoryUserRepository;
    use bcrypt::{DEFAULT_COST, hash};

    #[tokio::test]
    async fn test_email_validation() {
        assert!(UserCommandValidator::validate_email("test@example.com").is_ok());
        assert!(UserCommandValidator::validate_email("invalid-email").is_err());
        assert!(UserCommandValidator::validate_email("test@").is_err());
    }

    #[tokio::test]
    async fn test_password_validation() {
        assert!(UserCommandValidator::validate_password("StrongPass123!").is_ok());
        assert!(UserCommandValidator::validate_password("weak").is_err());
        assert!(UserCommandValidator::validate_password("nouppercase123!").is_err());
        assert!(UserCommandValidator::validate_password("NOLOWERCASE123!").is_err());
        assert!(UserCommandValidator::validate_password("NoDigits!").is_err());
        assert!(UserCommandValidator::validate_password("NoSpecial123").is_err());
    }

    #[tokio::test]
    async fn test_login_command_validation() {
        let password_hash = hash("password123", DEFAULT_COST).unwrap();
        let user = User {
            id: "user1".to_string(),
            email: "test@example.com".to_string(),
            password_hash,
            roles: vec![],
            is_locked: false,
            failed_login_attempts: 0,
        };

        let user_repo = Arc::new(InMemoryUserRepository::new(vec![user]));
        let validator = LoginCommandValidator::new(user_repo);

        let valid_command = CommandFactory::login_user(
            "test@example.com".to_string(),
            "password123".to_string(),
            None,
            None,
        );

        assert!(validator.validate(&valid_command).await.is_ok());

        let invalid_command = CommandFactory::login_user(
            "invalid-email".to_string(),
            "password123".to_string(),
            None,
            None,
        );

        assert!(validator.validate(&invalid_command).await.is_err());
    }

    #[tokio::test]
    async fn test_change_password_command_validation() {
        let password_hash = hash("oldpassword", DEFAULT_COST).unwrap();
        let user = User {
            id: "user1".to_string(),
            email: "test@example.com".to_string(),
            password_hash,
            roles: vec![],
            is_locked: false,
            failed_login_attempts: 0,
        };

        let user_repo = Arc::new(InMemoryUserRepository::new(vec![user]));
        let validator = ChangePasswordCommandValidator::new(user_repo);

        let valid_command = CommandFactory::change_password(
            "user1".to_string(),
            "oldpassword".to_string(),
            "NewStrongPass123!".to_string(),
            true,
        );

        assert!(validator.validate(&valid_command).await.is_ok());

        let invalid_command = CommandFactory::change_password(
            "user1".to_string(),
            "oldpassword".to_string(),
            "weak".to_string(),
            true,
        );

        assert!(validator.validate(&invalid_command).await.is_err());
    }
}
