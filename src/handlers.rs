use std::net::SocketAddr;

use axum::{
    body::{Body, Bytes},
    extract::{ConnectInfo, Path, Request, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};
use serde::de::DeserializeOwned;
use serde_json::json;
use uuid::Uuid;
use validator::validate_email;

use crate::{
    auth::current_user,
    error::{AppError, AppResult},
    models::{
        ConfirmRequest, LoginRequest, LogoutRequest, RefreshRequest, RegisterRequest, SessionView,
        TokenPairResponse,
    },
    state::AppState,
};

pub async fn healthz() -> impl IntoResponse {
    (StatusCode::OK, Json(json!({ "status": "ok" })))
}

pub async fn register(State(state): State<AppState>, body: Bytes) -> AppResult<impl IntoResponse> {
    let payload: RegisterRequest = parse_json(body)?;
    validate_register(&payload)?;

    let code = state.auth.register(&payload.email, &payload.password).await?;
    Ok((
        StatusCode::CREATED,
        Json(json!({
            "message": "registration successful, check your email",
            "confirm_code": code,
        })),
    ))
}

pub async fn confirm_email(
    State(state): State<AppState>,
    body: Bytes,
) -> AppResult<impl IntoResponse> {
    let payload: ConfirmRequest = parse_json(body)?;
    validate_confirm(&payload)?;

    state.auth.confirm_email(&payload.email, &payload.code).await?;
    Ok((StatusCode::OK, Json(json!({ "message": "email confirmed" }))))
}

pub async fn login(
    State(state): State<AppState>,
    headers: HeaderMap,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    body: Bytes,
) -> AppResult<impl IntoResponse> {
    let payload: LoginRequest = parse_json(body)?;
    validate_login(&payload)?;

    let pair = state
        .auth
        .login(
            &payload.email,
            &payload.password,
            user_agent(&headers),
            &client_ip(&headers, addr),
        )
        .await?;

    Ok((StatusCode::OK, Json(token_pair_response(pair))))
}

pub async fn logout(
    State(state): State<AppState>,
    body: Bytes,
) -> AppResult<impl IntoResponse> {
    let payload: LogoutRequest = parse_json(body)?;
    if payload.refresh_token.trim().is_empty() {
        return Err(AppError::bad_request("refresh_token is required"));
    }

    state.auth.logout(&payload.refresh_token).await?;
    Ok((StatusCode::OK, Json(json!({ "message": "logged out" }))))
}

pub async fn refresh(
    State(state): State<AppState>,
    headers: HeaderMap,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    body: Bytes,
) -> AppResult<impl IntoResponse> {
    let payload: RefreshRequest = parse_json(body)?;
    if payload.refresh_token.trim().is_empty() {
        return Err(AppError::bad_request("refresh_token is required"));
    }

    let pair = state
        .auth
        .refresh(
            &payload.refresh_token,
            user_agent(&headers),
            &client_ip(&headers, addr),
        )
        .await?;

    Ok((StatusCode::OK, Json(token_pair_response(pair))))
}

pub async fn get_sessions(
    State(state): State<AppState>,
    request: Request<Body>,
) -> AppResult<impl IntoResponse> {
    let user = current_user(&request)?;
    let sessions = state.auth.get_sessions(user.user_id).await?;
    let views: Vec<SessionView> = sessions.into_iter().map(SessionView::from).collect();

    Ok((StatusCode::OK, Json(json!({ "sessions": views }))))
}

pub async fn revoke_session(
    State(state): State<AppState>,
    Path(id): Path<String>,
    request: Request<Body>,
) -> AppResult<impl IntoResponse> {
    let user = current_user(&request)?;
    let session_id =
        Uuid::parse_str(&id).map_err(|_| AppError::bad_request("invalid session id"))?;

    state.auth.revoke_session(session_id, user.user_id).await?;
    Ok((StatusCode::OK, Json(json!({ "message": "session revoked" }))))
}

fn parse_json<T: DeserializeOwned>(body: Bytes) -> AppResult<T> {
    serde_json::from_slice::<T>(&body).map_err(|_| AppError::bad_request("invalid request body"))
}

fn token_pair_response(pair: crate::service::TokenPair) -> TokenPairResponse {
    TokenPairResponse {
        access_token: pair.access_token,
        refresh_token: pair.refresh_token,
        expires_in: pair.expires_in,
        token_type: "Bearer",
    }
}

fn validate_register(payload: &RegisterRequest) -> AppResult<()> {
    if payload.email.trim().is_empty() {
        return Err(AppError::bad_request("email is required"));
    }
    if !validate_email(&payload.email) {
        return Err(AppError::bad_request("email must be valid"));
    }
    if payload.password.trim().is_empty() {
        return Err(AppError::bad_request("password is required"));
    }
    if payload.password.chars().count() < 8 {
        return Err(AppError::bad_request("password must be at least 8 characters"));
    }
    Ok(())
}

fn validate_confirm(payload: &ConfirmRequest) -> AppResult<()> {
    if payload.email.trim().is_empty() {
        return Err(AppError::bad_request("email is required"));
    }
    if !validate_email(&payload.email) {
        return Err(AppError::bad_request("email must be valid"));
    }
    if payload.code.len() != 6 {
        return Err(AppError::bad_request("code must be 6 characters"));
    }
    Ok(())
}

fn validate_login(payload: &LoginRequest) -> AppResult<()> {
    if payload.email.trim().is_empty() {
        return Err(AppError::bad_request("email is required"));
    }
    if !validate_email(&payload.email) {
        return Err(AppError::bad_request("email must be valid"));
    }
    if payload.password.trim().is_empty() {
        return Err(AppError::bad_request("password is required"));
    }
    Ok(())
}

fn user_agent(headers: &HeaderMap) -> &str {
    headers
        .get("user-agent")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
}

fn client_ip(headers: &HeaderMap, addr: SocketAddr) -> String {
    if let Some(forwarded) = headers
        .get("x-forwarded-for")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(',').next())
    {
        return forwarded.trim().to_string();
    }

    if let Some(real_ip) = headers
        .get("x-real-ip")
        .and_then(|value| value.to_str().ok())
    {
        return real_ip.to_string();
    }

    addr.ip().to_string()
}
