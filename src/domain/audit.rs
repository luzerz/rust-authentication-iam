use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuditEvent {
    pub id: String,
    pub timestamp: DateTime<Utc>,
    pub event_type: AuditEventType,
    pub user_id: Option<String>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub details: serde_json::Value,
    pub success: bool,
    pub error_message: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum AuditEventType {
    Login,
    Logout,
    TokenRefresh,
    TokenRevocation,
    PasswordChange,
    PasswordReset,
    RoleAssignment,
    RoleRemoval,
    PermissionAssignment,
    PermissionRemoval,
    PolicyAssignment,
    PolicyRemoval,
    UserCreation,
    UserDeletion,
    RoleCreation,
    RoleDeletion,
    PolicyCreation,
    PolicyDeletion,
    AuthorizationCheck,
    FailedLogin,
    AccountLocked,
    SuspiciousActivity,
}

impl AuditEvent {
    pub fn new(
        event_type: AuditEventType,
        user_id: Option<String>,
        details: serde_json::Value,
        success: bool,
    ) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            timestamp: Utc::now(),
            event_type,
            user_id,
            ip_address: None,
            user_agent: None,
            details,
            success,
            error_message: None,
        }
    }

    pub fn with_error(mut self, error_message: String) -> Self {
        self.error_message = Some(error_message);
        self.success = false;
        self
    }

    pub fn with_context(mut self, ip_address: Option<String>, user_agent: Option<String>) -> Self {
        self.ip_address = ip_address;
        self.user_agent = user_agent;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_audit_event_creation() {
        let details = serde_json::json!({
            "action": "login",
            "method": "password"
        });

        let event = AuditEvent::new(
            AuditEventType::Login,
            Some("user123".to_string()),
            details,
            true,
        );

        assert_eq!(event.user_id, Some("user123".to_string()));
        assert!(event.success);
        assert!(event.error_message.is_none());
    }

    #[test]
    fn test_audit_event_with_error() {
        let details = serde_json::json!({
            "action": "login",
            "method": "password"
        });

        let event = AuditEvent::new(
            AuditEventType::FailedLogin,
            Some("user123".to_string()),
            details,
            true,
        )
        .with_error("Invalid credentials".to_string());

        assert!(!event.success);
        assert_eq!(event.error_message, Some("Invalid credentials".to_string()));
    }
}
