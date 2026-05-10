mod auth;
mod config;
mod error;
mod handlers;
mod models;
mod proxy;
mod service;
mod state;

use std::net::SocketAddr;

use axum::{
    middleware,
    routing::{any, delete, get, post},
    Router,
};
use config::Config;
use service::ProfileClient;
use sqlx::postgres::PgPoolOptions;
use state::AppState;
use tower_http::{
    cors::{Any, CorsLayer},
    trace::TraceLayer,
};
use tracing::info;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "auth_service=info,tower_http=info".into()),
        )
        .init();

    let config = Config::load().map_err(|err| format!("config: {err}"))?;

    let pool = PgPoolOptions::new()
        .max_connections(10)
        .connect(&config.postgres.dsn())
        .await
        .map_err(|err| format!("postgres connect: {err}"))?;
    sqlx::query("SELECT 1")
        .execute(&pool)
        .await
        .map_err(|err| format!("postgres ping: {err}"))?;
    info!("postgres: connected");

    let redis_client =
        redis::Client::open(config.redis.url()).map_err(|err| format!("redis create: {err}"))?;
    let mut redis_conn = redis_client
        .get_multiplexed_async_connection()
        .await
        .map_err(|err| format!("redis connect: {err}"))?;
    let _: String = redis::cmd("PING")
        .query_async(&mut redis_conn)
        .await
        .map_err(|err| format!("redis ping: {err}"))?;
    info!("redis: connected");

    let auth = service::AuthService::new(
        pool,
        redis_client,
        config.jwt.clone(),
        Some(ProfileClient::new(
            config.services.profile_service_url.clone(),
        )),
    );

    let proxy_client = reqwest::Client::builder()
        .build()
        .map_err(|err| format!("http client: {err}"))?;

    let state = AppState {
        auth,
        proxy_client,
        profile_service_url: config.services.profile_service_url.clone(),
        message_service_url: config.services.message_service_url.clone(),
    };

    info!("profile proxy -> {}", state.profile_service_url);
    info!("message proxy -> {}", state.message_service_url);

    let protected_auth = Router::new()
        .route("/api/v1/auth/logout", post(handlers::logout))
        .route("/api/v1/auth/sessions", get(handlers::get_sessions))
        .route("/api/v1/auth/sessions/{id}", delete(handlers::revoke_session))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            auth::auth_middleware,
        ));

    let profile_proxy = Router::new()
        .route("/api/v1/profile", any(proxy::profile_proxy))
        .route("/api/v1/profile/{*path}", any(proxy::profile_proxy))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            auth::auth_middleware,
        ));

    let message_proxy = Router::new()
        .route("/api/v1/messages", any(proxy::message_proxy))
        .route("/api/v1/messages/{*path}", any(proxy::message_proxy))
        .route("/ws/{*path}", any(proxy::message_proxy))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            auth::auth_middleware,
        ));

    let app = Router::new()
        .route("/healthz", get(handlers::healthz))
        .route("/api/v1/auth/register", post(handlers::register))
        .route("/api/v1/auth/register/confirm", post(handlers::confirm_email))
        .route("/api/v1/auth/login", post(handlers::login))
        .route("/api/v1/auth/refresh", post(handlers::refresh))
        .merge(protected_auth)
        .merge(profile_proxy)
        .merge(message_proxy)
        .layer(
            CorsLayer::new()
                .allow_origin(Any)
                .allow_methods(Any)
                .allow_headers([
                    http::header::CONTENT_TYPE,
                    http::header::AUTHORIZATION,
                    http::header::HeaderName::from_static("x-user-id"),
                ]),
        )
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    let port: u16 = config
        .http
        .port
        .parse()
        .map_err(|err| format!("HTTP_PORT: {err}"))?;
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    let listener = tokio::net::TcpListener::bind(addr).await?;

    info!("auth service listening on :{}", config.http.port);

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await?;

    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };

    #[cfg(unix)]
    let terminate = async {
        let mut signal =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).ok();
        if let Some(signal) = signal.as_mut() {
            signal.recv().await;
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }

    info!("shutting down...");
}
