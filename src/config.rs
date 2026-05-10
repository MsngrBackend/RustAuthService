use std::{env, time::Duration};

#[derive(Debug, Clone)]
pub struct Config {
    pub http: HttpConfig,
    pub postgres: PostgresConfig,
    pub redis: RedisConfig,
    pub jwt: JwtConfig,
    pub services: ServicesConfig,
}

#[derive(Debug, Clone)]
pub struct HttpConfig {
    pub port: String,
}

#[derive(Debug, Clone)]
pub struct PostgresConfig {
    pub host: String,
    pub port: String,
    pub user: String,
    pub password: String,
    pub db_name: String,
    pub ssl_mode: String,
}

impl PostgresConfig {
    pub fn dsn(&self) -> String {
        format!(
            "postgres://{}:{}@{}:{}/{}?sslmode={}",
            self.user, self.password, self.host, self.port, self.db_name, self.ssl_mode
        )
    }
}

#[derive(Debug, Clone)]
pub struct RedisConfig {
    pub addr: String,
    pub password: String,
    pub db: i64,
}

impl RedisConfig {
    pub fn url(&self) -> String {
        if self.addr.starts_with("redis://") || self.addr.starts_with("rediss://") {
            return self.addr.clone();
        }

        let auth = if self.password.is_empty() {
            String::new()
        } else {
            format!(":{}@", self.password)
        };

        format!("redis://{}{}/{}", auth, self.addr, self.db)
    }
}

#[derive(Debug, Clone)]
pub struct JwtConfig {
    pub access_secret: String,
    pub refresh_ttl: Duration,
    pub access_ttl: Duration,
    pub email_code_ttl: Duration,
}

#[derive(Debug, Clone)]
pub struct ServicesConfig {
    pub profile_service_url: String,
    pub message_service_url: String,
}

impl Config {
    pub fn load() -> Result<Self, String> {
        let refresh_ttl =
            humantime::parse_duration(&env_or("JWT_REFRESH_TTL", "720h")).map_err(|err| {
                format!("JWT_REFRESH_TTL: {err}")
            })?;
        let access_ttl =
            humantime::parse_duration(&env_or("JWT_ACCESS_TTL", "15m")).map_err(|err| {
                format!("JWT_ACCESS_TTL: {err}")
            })?;
        let email_code_ttl =
            humantime::parse_duration(&env_or("EMAIL_CODE_TTL", "15m")).map_err(|err| {
                format!("EMAIL_CODE_TTL: {err}")
            })?;

        let redis_db = env_or("REDIS_DB", "0")
            .parse::<i64>()
            .map_err(|err| format!("REDIS_DB: {err}"))?;

        Ok(Self {
            http: HttpConfig {
                port: env_or("HTTP_PORT", "9081"),
            },
            postgres: PostgresConfig {
                host: env_or("POSTGRES_HOST", "localhost"),
                port: env_or("POSTGRES_PORT", "5432"),
                user: env_or("POSTGRES_USER", "postgres"),
                password: env_or("POSTGRES_PASSWORD", "postgres"),
                db_name: env_or("POSTGRES_DB", "auth"),
                ssl_mode: env_or("POSTGRES_SSLMODE", "disable"),
            },
            redis: RedisConfig {
                addr: env_or("REDIS_ADDR", "localhost:7379"),
                password: env_or("REDIS_PASSWORD", ""),
                db: redis_db,
            },
            jwt: JwtConfig {
                access_secret: env_or("JWT_ACCESS_SECRET", "change-me-in-production"),
                refresh_ttl,
                access_ttl,
                email_code_ttl,
            },
            services: ServicesConfig {
                profile_service_url: env_or("PROFILE_SERVICE_URL", "http://profile-service:9082"),
                message_service_url: env_or("MESSAGE_SERVICE_URL", "http://message-service:9000"),
            },
        })
    }
}

fn env_or(key: &str, fallback: &str) -> String {
    env::var(key)
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| fallback.to_string())
}
