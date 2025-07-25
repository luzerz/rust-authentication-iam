/// Token value object: represents an authentication or refresh token.
#[derive(Clone)]
pub struct Token {
    pub token: String,
    pub user_id: String,
    pub expires_at: chrono::DateTime<chrono::Utc>,
    pub token_type: TokenType,
}

/// Enum for token type (access or refresh)
#[derive(Clone)]
pub enum TokenType {
    Access,
    Refresh,
}

impl Token {
    /// Returns true if the token is expired.
    pub fn is_expired(&self) -> bool {
        self.expires_at < chrono::Utc::now()
    }

    /// Returns true if the token is an access token.
    pub fn is_access(&self) -> bool {
        matches!(self.token_type, TokenType::Access)
    }

    /// Returns true if the token is a refresh token.
    pub fn is_refresh(&self) -> bool {
        matches!(self.token_type, TokenType::Refresh)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, Utc};

    fn access_token(expires_in_secs: i64) -> Token {
        Token {
            token: "abc".to_string(),
            user_id: "user1".to_string(),
            expires_at: Utc::now() + Duration::seconds(expires_in_secs),
            token_type: TokenType::Access,
        }
    }

    fn refresh_token(expires_in_secs: i64) -> Token {
        Token {
            token: "xyz".to_string(),
            user_id: "user1".to_string(),
            expires_at: Utc::now() + Duration::seconds(expires_in_secs),
            token_type: TokenType::Refresh,
        }
    }

    #[test]
    fn test_is_expired() {
        let t = access_token(10);
        assert!(!t.is_expired());
        let t = access_token(-10);
        assert!(t.is_expired());
    }

    #[test]
    fn test_is_access_and_is_refresh() {
        let t = access_token(10);
        assert!(t.is_access());
        assert!(!t.is_refresh());
        let t = refresh_token(10);
        assert!(!t.is_access());
        assert!(t.is_refresh());
    }
}
