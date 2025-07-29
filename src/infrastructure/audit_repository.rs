use crate::domain::audit::AuditEvent;
use crate::infrastructure::RepoResult;
use async_trait::async_trait;
use sqlx::PgPool;
use tracing::instrument;

#[async_trait]
pub trait AuditRepository: Send + Sync {
    async fn log_event(&self, event: AuditEvent) -> RepoResult<()>;
    async fn get_events_for_user(
        &self,
        user_id: &str,
        limit: Option<i64>,
    ) -> RepoResult<Vec<AuditEvent>>;
    async fn get_events_by_type(
        &self,
        event_type: &str,
        limit: Option<i64>,
    ) -> RepoResult<Vec<AuditEvent>>;
    async fn get_recent_events(&self, limit: Option<i64>) -> RepoResult<Vec<AuditEvent>>;
}

#[derive(Debug, Clone)]
pub struct PostgresAuditRepository {
    pub pool: PgPool,
}

impl PostgresAuditRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl AuditRepository for PostgresAuditRepository {
    #[instrument]
    async fn log_event(&self, event: AuditEvent) -> RepoResult<()> {
        sqlx::query!(
            r#"
            INSERT INTO audit_events (
                id, timestamp, event_type, user_id, ip_address, user_agent, 
                details, success, error_message
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            "#,
            event.id,
            event.timestamp,
            serde_json::to_string(&event.event_type).unwrap_or_default(),
            event.user_id,
            event.ip_address,
            event.user_agent,
            event.details,
            event.success,
            event.error_message,
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    #[instrument]
    async fn get_events_for_user(
        &self,
        user_id: &str,
        limit: Option<i64>,
    ) -> RepoResult<Vec<AuditEvent>> {
        let limit = limit.unwrap_or(100);
        let rows = sqlx::query!(
            r#"
            SELECT id, timestamp, event_type, user_id, ip_address, user_agent, 
                   details, success, error_message
            FROM audit_events 
            WHERE user_id = $1 
            ORDER BY timestamp DESC 
            LIMIT $2
            "#,
            user_id,
            limit
        )
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter()
            .map(|row| {
                let event_type = serde_json::from_str(&row.event_type)
                    .unwrap_or(crate::domain::audit::AuditEventType::SuspiciousActivity);

                Ok(AuditEvent {
                    id: row.id,
                    timestamp: row.timestamp,
                    event_type,
                    user_id: row.user_id,
                    ip_address: row.ip_address,
                    user_agent: row.user_agent,
                    details: row.details,
                    success: row.success,
                    error_message: row.error_message,
                })
            })
            .collect()
    }

    #[instrument]
    async fn get_events_by_type(
        &self,
        event_type: &str,
        limit: Option<i64>,
    ) -> RepoResult<Vec<AuditEvent>> {
        let limit = limit.unwrap_or(100);
        let rows = sqlx::query!(
            r#"
            SELECT id, timestamp, event_type, user_id, ip_address, user_agent, 
                   details, success, error_message
            FROM audit_events 
            WHERE event_type = $1 
            ORDER BY timestamp DESC 
            LIMIT $2
            "#,
            event_type,
            limit
        )
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter()
            .map(|row| {
                let event_type = serde_json::from_str(&row.event_type)
                    .unwrap_or(crate::domain::audit::AuditEventType::SuspiciousActivity);

                Ok(AuditEvent {
                    id: row.id,
                    timestamp: row.timestamp,
                    event_type,
                    user_id: row.user_id,
                    ip_address: row.ip_address,
                    user_agent: row.user_agent,
                    details: row.details,
                    success: row.success,
                    error_message: row.error_message,
                })
            })
            .collect()
    }

    #[instrument]
    async fn get_recent_events(&self, limit: Option<i64>) -> RepoResult<Vec<AuditEvent>> {
        let limit = limit.unwrap_or(100);
        let rows = sqlx::query!(
            r#"
            SELECT id, timestamp, event_type, user_id, ip_address, user_agent, 
                   details, success, error_message
            FROM audit_events 
            ORDER BY timestamp DESC 
            LIMIT $1
            "#,
            limit
        )
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter()
            .map(|row| {
                let event_type = serde_json::from_str(&row.event_type)
                    .unwrap_or(crate::domain::audit::AuditEventType::SuspiciousActivity);

                Ok(AuditEvent {
                    id: row.id,
                    timestamp: row.timestamp,
                    event_type,
                    user_id: row.user_id,
                    ip_address: row.ip_address,
                    user_agent: row.user_agent,
                    details: row.details,
                    success: row.success,
                    error_message: row.error_message,
                })
            })
            .collect()
    }
}

// In-memory implementation for testing
#[derive(Debug)]
pub struct InMemoryAuditRepository {
    pub events: std::sync::Mutex<Vec<AuditEvent>>,
}

impl InMemoryAuditRepository {
    pub fn new() -> Self {
        Self {
            events: std::sync::Mutex::new(Vec::new()),
        }
    }
}

impl Default for InMemoryAuditRepository {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl AuditRepository for InMemoryAuditRepository {
    #[instrument]
    async fn log_event(&self, event: AuditEvent) -> RepoResult<()> {
        let mut events = self.events.lock().unwrap();
        events.push(event);
        Ok(())
    }

    #[instrument]
    async fn get_events_for_user(
        &self,
        user_id: &str,
        limit: Option<i64>,
    ) -> RepoResult<Vec<AuditEvent>> {
        let events = self.events.lock().unwrap();
        let limit = limit.unwrap_or(100) as usize;

        let filtered_events: Vec<AuditEvent> = events
            .iter()
            .filter(|event| event.user_id.as_deref() == Some(user_id))
            .take(limit)
            .cloned()
            .collect();

        Ok(filtered_events)
    }

    #[instrument]
    async fn get_events_by_type(
        &self,
        event_type: &str,
        limit: Option<i64>,
    ) -> RepoResult<Vec<AuditEvent>> {
        let events = self.events.lock().unwrap();
        let limit = limit.unwrap_or(100) as usize;

        let filtered_events: Vec<AuditEvent> = events
            .iter()
            .filter(|event| {
                let event_type_str = format!("{:?}", event.event_type);
                event_type_str == event_type
            })
            .take(limit)
            .cloned()
            .collect();

        Ok(filtered_events)
    }

    #[instrument]
    async fn get_recent_events(&self, limit: Option<i64>) -> RepoResult<Vec<AuditEvent>> {
        let events = self.events.lock().unwrap();
        let limit = limit.unwrap_or(100) as usize;

        let recent_events: Vec<AuditEvent> = events.iter().take(limit).cloned().collect();

        Ok(recent_events)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::audit::{AuditEvent, AuditEventType};
    use chrono::Utc;
    use uuid::Uuid;

    #[tokio::test]
    async fn test_in_memory_audit_repository_log_event() {
        let repo = InMemoryAuditRepository::new();
        
        let event = AuditEvent {
            id: Uuid::new_v4().to_string(),
            timestamp: Utc::now(),
            event_type: AuditEventType::Login,
            user_id: Some("test-user-123".to_string()),
            ip_address: Some("127.0.0.1".to_string()),
            user_agent: Some("test-agent".to_string()),
            details: serde_json::json!({"success": true}),
            success: true,
            error_message: None,
        };

        let result = repo.log_event(event.clone()).await;
        assert!(result.is_ok());

        // Verify the event was stored
        let events = repo.get_events_for_user("test-user-123", Some(10)).await.unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].id, event.id);
    }

    #[tokio::test]
    async fn test_in_memory_audit_repository_get_events_for_user() {
        let repo = InMemoryAuditRepository::new();
        
        // Add multiple events for the same user
        for i in 0..5 {
            let event = AuditEvent {
                id: Uuid::new_v4().to_string(),
                timestamp: Utc::now(),
                event_type: AuditEventType::Login,
                user_id: Some("test-user-123".to_string()),
                ip_address: Some("127.0.0.1".to_string()),
                user_agent: Some("test-agent".to_string()),
                details: serde_json::json!({"index": i}),
                success: true,
                error_message: None,
            };
            repo.log_event(event).await.unwrap();
        }

        // Test getting events for specific user
        let events = repo.get_events_for_user("test-user-123", Some(10)).await.unwrap();
        assert_eq!(events.len(), 5);

        // Test limit
        let events = repo.get_events_for_user("test-user-123", Some(3)).await.unwrap();
        assert_eq!(events.len(), 3);

        // Test default limit
        let events = repo.get_events_for_user("test-user-123", None).await.unwrap();
        assert_eq!(events.len(), 5); // Should return all 5 events
    }

    #[tokio::test]
    async fn test_in_memory_audit_repository_get_events_by_type() {
        let repo = InMemoryAuditRepository::new();
        
        // Add events of different types
        let event_types = vec![
            AuditEventType::Login,
            AuditEventType::Logout,
            AuditEventType::PasswordChange,
            AuditEventType::SuspiciousActivity,
        ];

        for event_type in event_types {
            let event = AuditEvent {
                id: Uuid::new_v4().to_string(),
                timestamp: Utc::now(),
                event_type: event_type.clone(),
                user_id: Some("test-user-123".to_string()),
                ip_address: Some("127.0.0.1".to_string()),
                user_agent: Some("test-agent".to_string()),
                details: serde_json::json!({"type": format!("{:?}", event_type)}),
                success: true,
                error_message: None,
            };
            repo.log_event(event).await.unwrap();
        }

        // Test getting events by type
        let login_events = repo.get_events_by_type("Login", Some(10)).await.unwrap();
        assert_eq!(login_events.len(), 1);
        assert!(matches!(login_events[0].event_type, AuditEventType::Login));

        let logout_events = repo.get_events_by_type("Logout", Some(10)).await.unwrap();
        assert_eq!(logout_events.len(), 1);
        assert!(matches!(logout_events[0].event_type, AuditEventType::Logout));

        // Test limit
        let events = repo.get_events_by_type("Login", Some(1)).await.unwrap();
        assert_eq!(events.len(), 1);

        // Test default limit
        let events = repo.get_events_by_type("Login", None).await.unwrap();
        assert_eq!(events.len(), 1);
    }

    #[tokio::test]
    async fn test_in_memory_audit_repository_get_recent_events() {
        let repo = InMemoryAuditRepository::new();
        
        // Add multiple events
        for i in 0..10 {
            let event = AuditEvent {
                id: Uuid::new_v4().to_string(),
                timestamp: Utc::now(),
                event_type: AuditEventType::Login,
                user_id: Some(format!("user-{}", i)),
                ip_address: Some("127.0.0.1".to_string()),
                user_agent: Some("test-agent".to_string()),
                details: serde_json::json!({"index": i}),
                success: true,
                error_message: None,
            };
            repo.log_event(event).await.unwrap();
        }

        // Test getting recent events with limit
        let events = repo.get_recent_events(Some(5)).await.unwrap();
        assert_eq!(events.len(), 5);

        // Test getting recent events with default limit
        let events = repo.get_recent_events(None).await.unwrap();
        assert_eq!(events.len(), 10); // Should return all events

        // Test getting recent events with limit larger than total events
        let events = repo.get_recent_events(Some(20)).await.unwrap();
        assert_eq!(events.len(), 10);
    }

    #[tokio::test]
    async fn test_in_memory_audit_repository_error_event() {
        let repo = InMemoryAuditRepository::new();
        
        let event = AuditEvent {
            id: Uuid::new_v4().to_string(),
            timestamp: Utc::now(),
            event_type: AuditEventType::SuspiciousActivity,
            user_id: Some("test-user-123".to_string()),
            ip_address: Some("127.0.0.1".to_string()),
            user_agent: Some("test-agent".to_string()),
            details: serde_json::json!({"reason": "multiple_failed_attempts"}),
            success: false,
            error_message: Some("Too many failed login attempts".to_string()),
        };

        let result = repo.log_event(event.clone()).await;
        assert!(result.is_ok());

        // Verify the error event was stored correctly
        let events = repo.get_events_for_user("test-user-123", Some(10)).await.unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].success, false);
        assert_eq!(events[0].error_message, Some("Too many failed login attempts".to_string()));
    }

    #[tokio::test]
    async fn test_in_memory_audit_repository_empty_results() {
        let repo = InMemoryAuditRepository::new();
        
        // Test getting events for non-existent user
        let events = repo.get_events_for_user("non-existent", Some(10)).await.unwrap();
        assert_eq!(events.len(), 0);

        // Test getting events by non-existent type
        let events = repo.get_events_by_type("NonExistentType", Some(10)).await.unwrap();
        assert_eq!(events.len(), 0);

        // Test getting recent events from empty repository
        let events = repo.get_recent_events(Some(10)).await.unwrap();
        assert_eq!(events.len(), 0);
    }

    #[tokio::test]
    async fn test_in_memory_audit_repository_default_implementation() {
        let repo = InMemoryAuditRepository::default();
        
        let event = AuditEvent {
            id: Uuid::new_v4().to_string(),
            timestamp: Utc::now(),
            event_type: AuditEventType::Login,
            user_id: Some("test-user-123".to_string()),
            ip_address: Some("127.0.0.1".to_string()),
            user_agent: Some("test-agent".to_string()),
            details: serde_json::json!({"success": true}),
            success: true,
            error_message: None,
        };

        let result = repo.log_event(event).await;
        assert!(result.is_ok());
    }
}
