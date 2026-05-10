use chrono::{DateTime, SecondsFormat, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

#[derive(Debug, Clone, FromRow)]
pub struct User {
    pub id: Uuid,
    pub email: String,
    pub password: String,
    pub is_verified: bool,
    pub totp_secret: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, FromRow)]
pub struct Session {
    pub id: Uuid,
    pub user_id: Uuid,
    pub refresh_token: String,
    pub user_agent: Option<String>,
    pub ip: Option<String>,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
pub struct RegisterRequest {
    pub email: String,
    pub password: String,
}

#[derive(Debug, Deserialize)]
pub struct ConfirmRequest {
    pub email: String,
    pub code: String,
}

#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

#[derive(Debug, Deserialize)]
pub struct RefreshRequest {
    pub refresh_token: String,
}

#[derive(Debug, Deserialize)]
pub struct LogoutRequest {
    pub refresh_token: String,
}

#[derive(Debug, Serialize)]
pub struct TokenPairResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_in: i64,
    pub token_type: &'static str,
}

#[derive(Debug, Serialize)]
pub struct SessionView {
    pub id: String,
    pub user_agent: String,
    pub ip: String,
    pub expires_at: String,
    pub created_at: String,
}

impl From<Session> for SessionView {
    fn from(value: Session) -> Self {
        Self {
            id: value.id.to_string(),
            user_agent: value.user_agent.unwrap_or_default(),
            ip: value.ip.unwrap_or_default(),
            expires_at: value
                .expires_at
                .to_rfc3339_opts(SecondsFormat::Secs, true),
            created_at: value
                .created_at
                .to_rfc3339_opts(SecondsFormat::Secs, true),
        }
    }
}
