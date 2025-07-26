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

        let mut events = Vec::new();
        for row in rows {
            let event_type: crate::domain::audit::AuditEventType =
                serde_json::from_str(&row.event_type)
                    .unwrap_or(crate::domain::audit::AuditEventType::SuspiciousActivity);

            let details: serde_json::Value = row.details;

            events.push(AuditEvent {
                id: row.id,
                timestamp: row.timestamp,
                event_type,
                user_id: row.user_id,
                ip_address: row.ip_address,
                user_agent: row.user_agent,
                details,
                success: row.success,
                error_message: row.error_message,
            });
        }

        Ok(events)
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

        let mut events = Vec::new();
        for row in rows {
            let event_type: crate::domain::audit::AuditEventType =
                serde_json::from_str(&row.event_type)
                    .unwrap_or(crate::domain::audit::AuditEventType::SuspiciousActivity);

            let details: serde_json::Value = row.details;

            events.push(AuditEvent {
                id: row.id,
                timestamp: row.timestamp,
                event_type,
                user_id: row.user_id,
                ip_address: row.ip_address,
                user_agent: row.user_agent,
                details,
                success: row.success,
                error_message: row.error_message,
            });
        }

        Ok(events)
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

        let mut events = Vec::new();
        for row in rows {
            let event_type: crate::domain::audit::AuditEventType =
                serde_json::from_str(&row.event_type)
                    .unwrap_or(crate::domain::audit::AuditEventType::SuspiciousActivity);

            let details: serde_json::Value = row.details;

            events.push(AuditEvent {
                id: row.id,
                timestamp: row.timestamp,
                event_type,
                user_id: row.user_id,
                ip_address: row.ip_address,
                user_agent: row.user_agent,
                details,
                success: row.success,
                error_message: row.error_message,
            });
        }

        Ok(events)
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
                let event_type_str = serde_json::to_string(&event.event_type).unwrap_or_default();
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
