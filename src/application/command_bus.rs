use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{RwLock};

/// Command handler trait
#[async_trait]
pub trait CommandHandler<C>: Send + Sync {
    type Result: Send + Sync;
    type Error: std::error::Error + Send + Sync;

    async fn handle(&self, command: C) -> Result<Self::Result, Self::Error>;
}

/// Command bus for handling commands
pub struct CommandBus {
    handlers: Arc<RwLock<HashMap<std::any::TypeId, Box<dyn CommandHandlerBox + Send + Sync>>>>,
    event_store: Option<Arc<dyn crate::application::events::EventStore + Send + Sync>>,
}

/// Boxed command handler for type erasure
#[async_trait]
trait CommandHandlerBox: Send + Sync {
    async fn handle(
        &self,
        command: Box<dyn std::any::Any + Send + Sync>,
    ) -> Result<Box<dyn std::any::Any + Send + Sync>, Box<dyn std::error::Error + Send + Sync>>;
}

impl CommandBus {
    pub fn new() -> Self {
        Self {
            handlers: Arc::new(RwLock::new(HashMap::new())),
            event_store: None,
        }
    }

    pub fn with_event_store(
        event_store: Arc<dyn crate::application::events::EventStore + Send + Sync>,
    ) -> Self {
        Self {
            handlers: Arc::new(RwLock::new(HashMap::new())),
            event_store: Some(event_store),
        }
    }

    /// Register a command handler
    pub async fn register_handler<C, H>(&self, handler: H)
    where
        C: 'static + Send + Sync,
        H: CommandHandler<C> + 'static + Send + Sync,
    {
        let boxed_handler = Box::new(HandlerWrapper::new(handler));
        let type_id = std::any::TypeId::of::<C>();

        let mut handlers = self.handlers.write().await;
        handlers.insert(type_id, boxed_handler);
    }

    /// Execute a command
    pub async fn execute<C>(
        &self,
        command: C,
    ) -> Result<Box<dyn std::any::Any + Send + Sync>, Box<dyn std::error::Error + Send + Sync>>
    where
        C: 'static + Send + Sync,
    {
        let type_id = std::any::TypeId::of::<C>();
        let handlers = self.handlers.read().await;

        if let Some(handler) = handlers.get(&type_id) {
            let boxed_command = Box::new(command);
            handler.handle(boxed_command).await
        } else {
            Err(format!("No handler registered for command type: {type_id:?}").into())
        }
    }

    /// Execute a command and store events
    pub async fn execute_with_events<C>(
        &self,
        command: C,
    ) -> Result<Box<dyn std::any::Any + Send + Sync>, Box<dyn std::error::Error + Send + Sync>>
    where
        C: 'static + Send + Sync,
    {
        let result = self.execute(command).await?;

        // Store events if event store is available
        if let Some(_event_store) = &self.event_store {
            // This would typically be done by the command handler
            // For now, we'll just return the result
        }

        Ok(result)
    }
}

impl Default for CommandBus {
    fn default() -> Self {
        Self::new()
    }
}

/// Wrapper for command handlers to enable type erasure
struct HandlerWrapper<C, H> {
    handler: H,
    _phantom: std::marker::PhantomData<C>,
}

impl<C, H> HandlerWrapper<C, H> {
    fn new(handler: H) -> Self {
        Self {
            handler,
            _phantom: std::marker::PhantomData,
        }
    }
}

#[async_trait]
impl<C, H> CommandHandlerBox for HandlerWrapper<C, H>
where
    C: 'static + Send + Sync,
    H: CommandHandler<C> + Send + Sync,
    <H as CommandHandler<C>>::Result: 'static,
    <H as CommandHandler<C>>::Error: 'static,
{
    async fn handle(
        &self,
        command: Box<dyn std::any::Any + Send + Sync>,
    ) -> Result<Box<dyn std::any::Any + Send + Sync>, Box<dyn std::error::Error + Send + Sync>>
    {
        let command = command
            .downcast::<C>()
            .map_err(|_| "Failed to downcast command")?;

        let result = self
            .handler
            .handle(*command)
            .await
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)?;

        Ok(Box::new(result))
    }
}

/// Command result wrapper
pub struct CommandResult<T> {
    pub success: bool,
    pub data: Option<T>,
    pub error: Option<Box<dyn std::error::Error + Send + Sync>>,
    pub events: Vec<Box<dyn crate::application::events::DomainEvent + Send + Sync>>,
}

impl<T> CommandResult<T> {
    pub fn success(data: T) -> Self {
        Self {
            success: true,
            data: Some(data),
            error: None,
            events: Vec::new(),
        }
    }

    pub fn failure(error: Box<dyn std::error::Error + Send + Sync>) -> Self {
        Self {
            success: false,
            data: None,
            error: Some(error),
            events: Vec::new(),
        }
    }

    pub fn with_events(
        mut self,
        events: Vec<Box<dyn crate::application::events::DomainEvent + Send + Sync>>,
    ) -> Self {
        self.events = events;
        self
    }
}

/// Command execution context
pub struct CommandContext {
    pub user_id: Option<String>,
    pub correlation_id: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

impl CommandContext {
    pub fn new(user_id: Option<String>) -> Self {
        Self {
            user_id,
            correlation_id: uuid::Uuid::new_v4().to_string(),
            timestamp: chrono::Utc::now(),
        }
    }

    pub fn with_correlation_id(mut self, correlation_id: String) -> Self {
        self.correlation_id = correlation_id;
        self
    }
}

/// Command with context
pub struct CommandWithContext<C> {
    pub command: C,
    pub context: CommandContext,
}

impl<C> CommandWithContext<C> {
    pub fn new(command: C, context: CommandContext) -> Self {
        Self { command, context }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::application::commands::{CommandFactory, LoginUserCommand};
    use crate::application::services::{PasswordService, TokenService};
    use crate::infrastructure::{InMemoryRefreshTokenRepository, InMemoryUserRepository, UserRepository};
    use std::sync::Arc;

    // Mock command handler for testing
    struct MockLoginHandler {
        token_service: TokenService,
        password_service: PasswordService,
        user_repo: Arc<InMemoryUserRepository>,
        refresh_token_repo: Arc<InMemoryRefreshTokenRepository>,
    }

    #[async_trait]
    impl CommandHandler<LoginUserCommand> for MockLoginHandler {
        type Result = (String, String); // (access_token, refresh_token)
        type Error = crate::application::services::AuthError;

        async fn handle(&self, command: LoginUserCommand) -> Result<Self::Result, Self::Error> {
            let user = self
                .user_repo
                .find_by_email(&command.email)
                .await
                .ok_or(crate::application::services::AuthError::UserNotFound)?;

            if user.is_locked() {
                return Err(crate::application::services::AuthError::AccountLocked);
            }

            if !self.password_service.verify(&user, &command.password) {
                return Err(crate::application::services::AuthError::InvalidCredentials);
            }

            self.token_service
                .issue_tokens(&user, &self.refresh_token_repo)
                .await
        }
    }

    #[tokio::test]
    async fn test_command_bus_registration_and_execution() {
        let command_bus = CommandBus::new();

        // Set up test environment
        unsafe {
            std::env::set_var("JWT_SECRET", "test-secret-key-for-testing-only");
        }

        // Create a user for testing
        let password_hash = bcrypt::hash("password123", bcrypt::DEFAULT_COST).unwrap();
        let user = crate::domain::user::User {
            id: "user1".to_string(),
            email: "test@example.com".to_string(),
            password_hash,
            roles: vec![],
            is_locked: false,
            failed_login_attempts: 0,
        };
        let user_repo = Arc::new(InMemoryUserRepository::new(vec![user]));
        let refresh_token_repo = Arc::new(InMemoryRefreshTokenRepository::new());

        let handler = MockLoginHandler {
            token_service: TokenService,
            password_service: PasswordService,
            user_repo,
            refresh_token_repo,
        };

        // Register handler
        command_bus.register_handler(handler).await;

        // Execute command
        let command = CommandFactory::login_user(
            "test@example.com".to_string(),
            "password123".to_string(),
            None,
            None,
        );

        let result = command_bus.execute(command).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_command_bus_no_handler() {
        let command_bus = CommandBus::new();

        let command = CommandFactory::login_user(
            "test@example.com".to_string(),
            "password123".to_string(),
            None,
            None,
        );

        let result = command_bus.execute(command).await;
        assert!(result.is_err());
    }
}
