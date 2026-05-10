use std::time::Duration;

use bcrypt::{hash, verify, DEFAULT_COST};
use chrono::{DateTime, Utc};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use rand::Rng;
use redis::AsyncCommands;
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::{PgPool, Row};
use tracing::warn;
use uuid::Uuid;

use crate::{
    config::JwtConfig,
    error::{AppError, AppResult},
    models::{Session, User},
};

#[derive(Debug, Clone)]
pub struct AuthService {
    pool: PgPool,
    redis: redis::Client,
    jwt: JwtConfig,
    profile_client: Option<ProfileClient>,
}

#[derive(Debug, Clone)]
pub struct ProfileClient {
    base_url: String,
    http_client: reqwest::Client,
}

#[derive(Debug, Clone)]
pub struct TokenPair {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_in: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessClaims {
    pub exp: usize,
    pub iat: usize,
    pub uid: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InternalClaims {
    pub exp: usize,
    pub iat: usize,
    pub sub: String,
}

impl AuthService {
    pub fn new(
        pool: PgPool,
        redis: redis::Client,
        jwt: JwtConfig,
        profile_client: Option<ProfileClient>,
    ) -> Self {
        Self {
            pool,
            redis,
            jwt,
            profile_client,
        }
    }

    pub async fn register(&self, email: &str, password: &str) -> AppResult<String> {
        let hashed = hash(password, DEFAULT_COST)
            .map_err(|err| AppError::log_internal("bcrypt hash", err))?;

        let create_result = sqlx::query_as::<_, User>(
            r#"
            INSERT INTO users (email, password)
            VALUES ($1, $2)
            RETURNING id, email, password, is_verified, totp_secret, created_at, updated_at
            "#,
        )
        .bind(email)
        .bind(hashed)
        .fetch_one(&self.pool)
        .await;

        if let Err(err) = create_result {
            if is_unique_violation(&err) {
                return Err(AppError::conflict("email already registered"));
            }
            return Err(AppError::log_internal("create user", err));
        }

        let code = generate_code(6);
        self.set_email_code(email, &code, self.jwt.email_code_ttl).await?;
        Ok(code)
    }

    pub async fn confirm_email(&self, email: &str, code: &str) -> AppResult<()> {
        let stored = self
            .get_email_code(email)
            .await
            .ok_or_else(|| AppError::unprocessable("invalid or expired code"))?;

        if stored != code {
            return Err(AppError::unprocessable("invalid or expired code"));
        }

        let user = self
            .find_user_by_email(email)
            .await?
            .ok_or_else(|| AppError::internal())?;

        sqlx::query("UPDATE users SET is_verified = TRUE, updated_at = NOW() WHERE id = $1")
            .bind(user.id)
            .execute(&self.pool)
            .await
            .map_err(|err| AppError::log_internal("mark verified", err))?;

        self.delete_email_code(email).await?;

        if let Some(profile_client) = &self.profile_client {
            if let Err(err) = profile_client.create_profile(user.id).await {
                warn!("create profile for {}: {err}", user.id);
            }
        }

        Ok(())
    }

    pub async fn login(
        &self,
        email: &str,
        password: &str,
        user_agent: &str,
        ip: &str,
    ) -> AppResult<TokenPair> {
        let user = self
            .find_user_by_email(email)
            .await?
            .ok_or_else(|| AppError::unauthorized("invalid email or password"))?;

        let is_valid = verify(password, &user.password)
            .map_err(|err| AppError::log_internal("bcrypt verify", err))?;
        if !is_valid {
            return Err(AppError::unauthorized("invalid email or password"));
        }

        if !user.is_verified {
            return Err(AppError::forbidden("email not verified"));
        }

        self.create_session(&user, user_agent, ip).await
    }

    pub async fn logout(&self, refresh_token: &str) -> AppResult<()> {
        sqlx::query("DELETE FROM sessions WHERE refresh_token = $1")
            .bind(refresh_token)
            .execute(&self.pool)
            .await
            .map_err(|err| AppError::log_internal("logout delete session", err))?;
        Ok(())
    }

    pub async fn refresh(
        &self,
        old_refresh_token: &str,
        _user_agent: &str,
        _ip: &str,
    ) -> AppResult<TokenPair> {
        let session = self
            .find_session_by_refresh_token(old_refresh_token)
            .await?
            .ok_or_else(|| AppError::unauthorized("invalid or expired refresh token"))?;

        if Utc::now() > session.expires_at {
            let _ = sqlx::query("DELETE FROM sessions WHERE refresh_token = $1")
                .bind(old_refresh_token)
                .execute(&self.pool)
                .await;
            return Err(AppError::unauthorized("invalid or expired refresh token"));
        }

        let user = self
            .find_user_by_id(session.user_id)
            .await?
            .ok_or_else(|| AppError::internal())?;

        let new_refresh = generate_refresh_token();
        let new_expiry = add_duration(self.jwt.refresh_ttl)?;

        let result = sqlx::query(
            r#"
            UPDATE sessions
            SET refresh_token = $1, expires_at = $2
            WHERE refresh_token = $3
            "#,
        )
        .bind(&new_refresh)
        .bind(new_expiry)
        .bind(old_refresh_token)
        .execute(&self.pool)
        .await
        .map_err(|err| AppError::log_internal("rotate refresh token", err))?;

        if result.rows_affected() == 0 {
            return Err(AppError::unauthorized("invalid or expired refresh token"));
        }

        let access_token = self.generate_access_token(user.id)?;
        Ok(TokenPair {
            access_token,
            refresh_token: new_refresh,
            expires_in: self.jwt.access_ttl.as_secs() as i64,
        })
    }

    pub async fn get_sessions(&self, user_id: Uuid) -> AppResult<Vec<Session>> {
        sqlx::query_as::<_, Session>(
            r#"
            SELECT id, user_id, refresh_token, user_agent, ip, expires_at, created_at
            FROM sessions
            WHERE user_id = $1 AND expires_at > $2
            ORDER BY created_at DESC
            "#,
        )
        .bind(user_id)
        .bind(Utc::now())
        .fetch_all(&self.pool)
        .await
        .map_err(|err| AppError::log_internal("list sessions", err))
    }

    pub async fn revoke_session(&self, session_id: Uuid, user_id: Uuid) -> AppResult<()> {
        let result = sqlx::query("DELETE FROM sessions WHERE id = $1 AND user_id = $2")
            .bind(session_id)
            .bind(user_id)
            .execute(&self.pool)
            .await
            .map_err(|err| AppError::log_internal("delete session", err))?;

        if result.rows_affected() == 0 {
            return Err(AppError::not_found("session not found"));
        }

        Ok(())
    }

    pub fn parse_access_token(&self, token: &str) -> AppResult<AccessClaims> {
        let mut validation = Validation::new(Algorithm::HS256);
        validation.validate_exp = true;

        decode::<AccessClaims>(
            token,
            &DecodingKey::from_secret(self.jwt.access_secret.as_bytes()),
            &validation,
        )
        .map(|data| data.claims)
        .map_err(|_| AppError::unauthorized("invalid or expired token"))
    }

    pub fn generate_internal_token(&self, user_id: Uuid) -> AppResult<String> {
        let now = Utc::now();
        let claims = InternalClaims {
            sub: user_id.to_string(),
            exp: (now.timestamp() + self.jwt.access_ttl.as_secs() as i64) as usize,
            iat: now.timestamp() as usize,
        };

        encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(self.jwt.access_secret.as_bytes()),
        )
        .map_err(|err| AppError::log_internal("generate internal token", err))
    }

    async fn create_session(&self, user: &User, user_agent: &str, ip: &str) -> AppResult<TokenPair> {
        let access_token = self.generate_access_token(user.id)?;
        let refresh_token = generate_refresh_token();
        let expires_at = add_duration(self.jwt.refresh_ttl)?;

        sqlx::query(
            r#"
            INSERT INTO sessions (id, user_id, refresh_token, user_agent, ip, expires_at)
            VALUES ($1, $2, $3, $4, $5, $6)
            "#,
        )
        .bind(Uuid::new_v4())
        .bind(user.id)
        .bind(&refresh_token)
        .bind(user_agent)
        .bind(ip)
        .bind(expires_at)
        .execute(&self.pool)
        .await
        .map_err(|err| AppError::log_internal("create session", err))?;

        Ok(TokenPair {
            access_token,
            refresh_token,
            expires_in: self.jwt.access_ttl.as_secs() as i64,
        })
    }

    fn generate_access_token(&self, user_id: Uuid) -> AppResult<String> {
        let now = Utc::now();
        let claims = AccessClaims {
            uid: user_id.to_string(),
            exp: (now.timestamp() + self.jwt.access_ttl.as_secs() as i64) as usize,
            iat: now.timestamp() as usize,
        };

        encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(self.jwt.access_secret.as_bytes()),
        )
        .map_err(|err| AppError::log_internal("generate access token", err))
    }

    async fn find_user_by_email(&self, email: &str) -> AppResult<Option<User>> {
        sqlx::query_as::<_, User>(
            r#"
            SELECT id, email, password, is_verified, totp_secret, created_at, updated_at
            FROM users
            WHERE email = $1
            "#,
        )
        .bind(email)
        .fetch_optional(&self.pool)
        .await
        .map_err(|err| AppError::log_internal("find user by email", err))
    }

    async fn find_user_by_id(&self, id: Uuid) -> AppResult<Option<User>> {
        sqlx::query_as::<_, User>(
            r#"
            SELECT id, email, password, is_verified, totp_secret, created_at, updated_at
            FROM users
            WHERE id = $1
            "#,
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|err| AppError::log_internal("find user by id", err))
    }

    async fn find_session_by_refresh_token(&self, token: &str) -> AppResult<Option<Session>> {
        sqlx::query_as::<_, Session>(
            r#"
            SELECT id, user_id, refresh_token, user_agent, ip, expires_at, created_at
            FROM sessions
            WHERE refresh_token = $1
            "#,
        )
        .bind(token)
        .fetch_optional(&self.pool)
        .await
        .map_err(|err| AppError::log_internal("find session by refresh token", err))
    }

    async fn set_email_code(&self, email: &str, code: &str, ttl: Duration) -> AppResult<()> {
        let mut conn = self
            .redis
            .get_multiplexed_async_connection()
            .await
            .map_err(|err| AppError::log_internal("redis connect", err))?;

        conn.set_ex(email_confirm_key(email), code, ttl.as_secs().max(1))
            .await
            .map_err(|err| AppError::log_internal("redis set email code", err))
    }

    async fn get_email_code(&self, email: &str) -> Option<String> {
        let mut conn = self.redis.get_multiplexed_async_connection().await.ok()?;
        conn.get(email_confirm_key(email)).await.ok()
    }

    async fn delete_email_code(&self, email: &str) -> AppResult<()> {
        let mut conn = self
            .redis
            .get_multiplexed_async_connection()
            .await
            .map_err(|err| AppError::log_internal("redis connect", err))?;

        let _: i64 = conn
            .del(email_confirm_key(email))
            .await
            .map_err(|err| AppError::log_internal("redis delete email code", err))?;

        Ok(())
    }
}

impl ProfileClient {
    pub fn new(base_url: String) -> Self {
        Self {
            base_url,
            http_client: reqwest::Client::new(),
        }
    }

    pub async fn create_profile(&self, user_id: Uuid) -> Result<(), String> {
        let response = self
            .http_client
            .post(format!(
                "{}/internal/profiles",
                self.base_url.trim_end_matches('/')
            ))
            .json(&json!({ "user_id": user_id.to_string() }))
            .send()
            .await
            .map_err(|err| format!("profile service unavailable: {err}"))?;

        if response.status() == StatusCode::CREATED || response.status() == StatusCode::OK {
            return Ok(());
        }

        Err(format!("profile service returned {}", response.status()))
    }
}

fn email_confirm_key(email: &str) -> String {
    format!("email_confirm:{email}")
}

fn add_duration(duration: Duration) -> AppResult<DateTime<Utc>> {
    chrono::Duration::from_std(duration)
        .map(|delta| Utc::now() + delta)
        .map_err(|err| AppError::log_internal("convert duration", err))
}

fn is_unique_violation(err: &sqlx::Error) -> bool {
    err.as_database_error()
        .and_then(|db_err| db_err.code())
        .as_deref()
        == Some("23505")
}

fn generate_refresh_token() -> String {
    let bytes: [u8; 32] = rand::random();
    hex::encode(bytes)
}

fn generate_code(n: usize) -> String {
    let max = 10_u32.pow(n as u32);
    let num = rand::thread_rng().gen_range(0..max);
    format!("{num:0width$}", width = n)
}
