use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Query handler trait
#[async_trait]
pub trait QueryHandler<Q>: Send + Sync {
    type Result: Send + Sync;
    type Error: std::error::Error + Send + Sync;

    async fn handle(&self, query: Q) -> Result<Self::Result, Self::Error>;
}

/// Query bus for handling queries
pub struct QueryBus {
    handlers: Arc<RwLock<HashMap<std::any::TypeId, Box<dyn QueryHandlerBox + Send + Sync>>>>,
}

/// Boxed query handler for type erasure
#[async_trait]
trait QueryHandlerBox: Send + Sync {
    async fn handle(
        &self,
        query: Box<dyn std::any::Any + Send + Sync>,
    ) -> Result<Box<dyn std::any::Any + Send + Sync>, Box<dyn std::error::Error + Send + Sync>>;
}

impl Default for QueryBus {
    fn default() -> Self {
        Self::new()
    }
}

impl QueryBus {
    pub fn new() -> Self {
        Self {
            handlers: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Register a query handler
    pub async fn register_handler<Q, H>(&self, handler: H)
    where
        Q: 'static + Send + Sync,
        H: QueryHandler<Q> + 'static + Send + Sync,
    {
        let boxed_handler = Box::new(QueryHandlerWrapper::new(handler));
        let type_id = std::any::TypeId::of::<Q>();

        let mut handlers = self.handlers.write().await;
        handlers.insert(type_id, boxed_handler);
    }

    /// Execute a query
    pub async fn execute<Q>(
        &self,
        query: Q,
    ) -> Result<Box<dyn std::any::Any + Send + Sync>, Box<dyn std::error::Error + Send + Sync>>
    where
        Q: 'static + Send + Sync,
    {
        let type_id = std::any::TypeId::of::<Q>();
        let handlers = self.handlers.read().await;

        if let Some(handler) = handlers.get(&type_id) {
            let boxed_query = Box::new(query);
            handler.handle(boxed_query).await
        } else {
            Err(format!("No handler registered for query type: {type_id:?}").into())
        }
    }
}

/// Wrapper for query handlers to enable type erasure
struct QueryHandlerWrapper<Q, H> {
    handler: H,
    _phantom: std::marker::PhantomData<Q>,
}

impl<Q, H> QueryHandlerWrapper<Q, H> {
    fn new(handler: H) -> Self {
        Self {
            handler,
            _phantom: std::marker::PhantomData,
        }
    }
}

#[async_trait]
impl<Q, H> QueryHandlerBox for QueryHandlerWrapper<Q, H>
where
    Q: 'static + Send + Sync,
    H: QueryHandler<Q> + Send + Sync,
    <H as QueryHandler<Q>>::Result: 'static,
    <H as QueryHandler<Q>>::Error: 'static,
{
    async fn handle(
        &self,
        query: Box<dyn std::any::Any + Send + Sync>,
    ) -> Result<Box<dyn std::any::Any + Send + Sync>, Box<dyn std::error::Error + Send + Sync>>
    {
        let query = query
            .downcast::<Q>()
            .map_err(|_| "Failed to downcast query")?;

        let result = self
            .handler
            .handle(*query)
            .await
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)?;

        Ok(Box::new(result))
    }
}

/// Query result wrapper
#[derive(Debug)]
pub struct QueryResult<T> {
    pub success: bool,
    pub data: Option<T>,
    pub error: Option<Box<dyn std::error::Error + Send + Sync>>,
}

impl<T> QueryResult<T> {
    pub fn success(data: T) -> Self {
        Self {
            success: true,
            data: Some(data),
            error: None,
        }
    }

    pub fn failure(error: Box<dyn std::error::Error + Send + Sync>) -> Self {
        Self {
            success: false,
            data: None,
            error: Some(error),
        }
    }
}

/// Query execution context
pub struct QueryContext {
    pub user_id: Option<String>,
    pub correlation_id: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

impl QueryContext {
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

/// Query with context
pub struct QueryWithContext<Q> {
    pub query: Q,
    pub context: QueryContext,
}

impl<Q> QueryWithContext<Q> {
    pub fn new(query: Q, context: QueryContext) -> Self {
        Self { query, context }
    }
}

/// Read model trait for optimized query performance
#[async_trait]
pub trait ReadModel: Send + Sync {
    type Query;
    type Result;
    type Error: std::error::Error + Send + Sync;

    async fn query(&self, query: Self::Query) -> Result<Self::Result, Self::Error>;
}

/// Projection trait for building read models from events
#[async_trait]
pub trait Projection: Send + Sync {
    type Event;
    type Error: std::error::Error + Send + Sync;

    async fn project(&self, event: &Self::Event) -> Result<(), Self::Error>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::application::queries::{GetUserByIdQuery, QueryFactory};
    use crate::domain::user::User;
    use crate::infrastructure::{InMemoryUserRepository, UserRepository};
    use std::sync::Arc;

    // Mock query handler for testing
    struct MockGetUserHandler {
        user_repo: Arc<InMemoryUserRepository>,
    }

    #[async_trait]
    impl QueryHandler<GetUserByIdQuery> for MockGetUserHandler {
        type Result = Option<User>;
        type Error = sqlx::Error;

        async fn handle(&self, query: GetUserByIdQuery) -> Result<Self::Result, Self::Error> {
            self.user_repo.find_by_id(&query.user_id).await
        }
    }

    #[tokio::test]
    async fn test_query_bus_registration_and_execution() {
        let query_bus = QueryBus::new();

        let user_repo = Arc::new(InMemoryUserRepository::new(vec![]));
        let handler = MockGetUserHandler { user_repo };

        // Register handler
        query_bus.register_handler(handler).await;

        // Execute query
        let query = QueryFactory::get_user_by_id("user1".to_string(), true, false);

        let result = query_bus.execute(query).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_query_bus_no_handler() {
        let query_bus = QueryBus::new();

        let query = QueryFactory::get_user_by_id("user1".to_string(), true, false);

        let result = query_bus.execute(query).await;
        assert!(result.is_err());
    }
}
