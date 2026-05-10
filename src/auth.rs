use axum::{
    body::Body,
    extract::{Request, State},
    http::header::AUTHORIZATION,
    middleware::Next,
    response::Response,
};
use url::form_urlencoded;
use uuid::Uuid;

use crate::{
    error::{AppError, AppResult},
    state::AppState,
};

#[derive(Debug, Clone, Copy)]
pub struct AuthenticatedUser {
    pub user_id: Uuid,
}

pub async fn auth_middleware(
    State(state): State<AppState>,
    mut request: Request<Body>,
    next: Next,
) -> AppResult<Response> {
    let token = if let Some(header_value) = request.headers().get(AUTHORIZATION) {
        let value = header_value
            .to_str()
            .map_err(|_| AppError::unauthorized("invalid authorization header format"))?;
        let mut parts = value.splitn(2, ' ');
        match (parts.next(), parts.next()) {
            (Some("Bearer"), Some(token)) if !token.is_empty() => token.to_string(),
            _ => return Err(AppError::unauthorized("invalid authorization header format")),
        }
    } else {
        extract_query_token(request.uri().query())
            .ok_or_else(|| AppError::unauthorized("authorization required"))?
    };

    let claims = state.auth.parse_access_token(&token)?;
    let user_id = Uuid::parse_str(&claims.uid)
        .map_err(|err| AppError::log_internal("parse uid claim", err))?;

    request
        .extensions_mut()
        .insert(AuthenticatedUser { user_id });

    Ok(next.run(request).await)
}

pub fn current_user(request: &Request<Body>) -> AppResult<AuthenticatedUser> {
    request
        .extensions()
        .get::<AuthenticatedUser>()
        .copied()
        .ok_or_else(AppError::internal)
}

fn extract_query_token(query: Option<&str>) -> Option<String> {
    let query = query?;
    form_urlencoded::parse(query.as_bytes())
        .find(|(key, _)| key == "token")
        .map(|(_, value)| value.into_owned())
}
