use axum::{
    body::{to_bytes, Body},
    extract::{ws::{Message, WebSocket, WebSocketUpgrade}, FromRequestParts, Request, State},
    http::{header, HeaderMap, HeaderName, HeaderValue, Uri},
    response::{IntoResponse, Response},
};
use futures_util::{sink::SinkExt, stream::StreamExt};
use tokio_tungstenite::{
    connect_async,
    tungstenite::{self, client::IntoClientRequest},
};
use tracing::warn;
use url::{form_urlencoded, Url};

use crate::{
    auth::current_user,
    error::{AppError, AppResult},
    state::AppState,
};

const MAX_PROXY_BODY_SIZE: usize = 64 * 1024 * 1024;

pub async fn profile_proxy(
    State(state): State<AppState>,
    request: Request<Body>,
) -> AppResult<Response> {
    forward_http(
        &state,
        request,
        &state.profile_service_url,
        "/api/v1/profile",
        "profile service unavailable",
    )
    .await
}

pub async fn message_proxy(
    State(state): State<AppState>,
    request: Request<Body>,
) -> AppResult<Response> {
    if is_websocket_request(request.headers()) {
        return forward_websocket(state, request).await;
    }

    forward_http(
        &state,
        request,
        &state.message_service_url,
        "/api/v1/messages",
        "message service unavailable",
    )
    .await
}

async fn forward_http(
    state: &AppState,
    request: Request<Body>,
    base_url: &str,
    prefix: &str,
    unavailable_message: &'static str,
) -> AppResult<Response> {
    let user = current_user(&request)?;
    let method = request.method().clone();
    let headers = request.headers().clone();
    let target_url = build_http_target(base_url, request.uri(), prefix)?;
    let (_, body) = request.into_parts();
    let body = to_bytes(body, MAX_PROXY_BODY_SIZE)
        .await
        .map_err(|err| AppError::log_internal("read proxy body", err))?;

    let mut builder = state.proxy_client.request(method, target_url);
    copy_request_headers(&mut builder, &headers, user.user_id.to_string())?;

    let response = builder
        .body(body)
        .send()
        .await
        .map_err(|err| {
            warn!("{unavailable_message}: {err}");
            AppError::bad_gateway(unavailable_message)
        })?;

    let status = response.status();
    let headers = response.headers().clone();
    let bytes = response.bytes().await.map_err(|err| {
        warn!("{unavailable_message}: {err}");
        AppError::bad_gateway(unavailable_message)
    })?;

    let mut out = Response::builder().status(status);
    for (name, value) in headers.iter() {
        if !is_hop_by_hop_header(name) {
            out = out.header(name, value);
        }
    }

    out.body(Body::from(bytes))
        .map_err(|err| AppError::log_internal("build proxy response", err))
}

async fn forward_websocket(state: AppState, request: Request<Body>) -> AppResult<Response> {
    let _user = current_user(&request)?;
    let prefix = if request.uri().path().starts_with("/ws") {
        "/ws"
    } else {
        "/api/v1/messages"
    };
    let target_url = build_ws_target(&state.message_service_url, request.uri(), prefix)?;

    let (mut parts, _) = request.into_parts();
    let ws = WebSocketUpgrade::from_request_parts(&mut parts, &())
        .await
        .map_err(|_| AppError::bad_request("websocket upgrade failed"))?;

    Ok(ws
        .on_upgrade(move |socket| async move {
            if let Err(err) = proxy_websocket(socket, target_url).await {
                warn!("message websocket proxy: {err}");
            }
        })
        .into_response())
}

async fn proxy_websocket(socket: WebSocket, target_url: Url) -> Result<(), String> {
    let mut request = target_url
        .as_str()
        .into_client_request()
        .map_err(|err| format!("build websocket request: {err}"))?;
    request
        .headers_mut()
        .insert(header::HOST, HeaderValue::from_str(target_url.host_str().unwrap_or_default()).map_err(|err| err.to_string())?);

    let (server_socket, _) = connect_async(request)
        .await
        .map_err(|err| format!("connect websocket upstream: {err}"))?;

    let (mut client_sender, mut client_receiver) = socket.split();
    let (mut server_sender, mut server_receiver) = server_socket.split();

    let client_to_server = async {
        while let Some(message) = client_receiver.next().await {
            let message = match message {
                Ok(message) => message,
                Err(err) => return Err(format!("read client websocket: {err}")),
            };

            match axum_to_tungstenite(message) {
                Some(message) => {
                    if let Err(err) = server_sender.send(message).await {
                        return Err(format!("write upstream websocket: {err}"));
                    }
                }
                None => break,
            }
        }

        Ok::<(), String>(())
    };

    let server_to_client = async {
        while let Some(message) = server_receiver.next().await {
            let message = match message {
                Ok(message) => message,
                Err(err) => return Err(format!("read upstream websocket: {err}")),
            };

            match tungstenite_to_axum(message) {
                Some(message) => {
                    if let Err(err) = client_sender.send(message).await {
                        return Err(format!("write client websocket: {err}"));
                    }
                }
                None => break,
            }
        }

        Ok::<(), String>(())
    };

    tokio::select! {
        result = client_to_server => result?,
        result = server_to_client => result?,
    }

    Ok(())
}

fn copy_request_headers(
    builder: &mut reqwest::RequestBuilder,
    headers: &HeaderMap,
    user_id: String,
) -> AppResult<()> {
    for (name, value) in headers.iter() {
        if is_hop_by_hop_header(name)
            || *name == header::HOST
            || *name == header::AUTHORIZATION
            || *name == HeaderName::from_static("x-user-id")
        {
            continue;
        }

        *builder = builder.try_clone().ok_or_else(AppError::internal)?
            .header(name, value);
    }

    *builder = builder
        .try_clone()
        .ok_or_else(AppError::internal)?
        .header("x-user-id", user_id);

    Ok(())
}

fn build_http_target(base_url: &str, uri: &Uri, prefix: &str) -> AppResult<Url> {
    let mut url = Url::parse(base_url).map_err(|err| AppError::log_internal("parse target url", err))?;
    let path = strip_prefix(uri.path(), prefix);
    url.set_path(path);
    url.set_query(uri.query());
    Ok(url)
}

fn build_ws_target(base_url: &str, uri: &Uri, prefix: &str) -> AppResult<Url> {
    let mut url = Url::parse(base_url).map_err(|err| AppError::log_internal("parse websocket target url", err))?;
    let scheme = match url.scheme() {
        "http" => "ws",
        "https" => "wss",
        other => other,
    };
    url.set_scheme(scheme)
        .map_err(|_| AppError::log_internal("set websocket scheme", "invalid scheme"))?;
    url.set_path(strip_prefix(uri.path(), prefix));
    url.set_query(filter_token_query(uri.query()).as_deref());
    Ok(url)
}

fn strip_prefix<'a>(path: &'a str, prefix: &str) -> &'a str {
    let stripped = path.strip_prefix(prefix).unwrap_or(path);
    if stripped.is_empty() {
        "/"
    } else {
        stripped
    }
}

fn filter_token_query(query: Option<&str>) -> Option<String> {
    let query = query?;
    let filtered = form_urlencoded::Serializer::new(String::new())
        .extend_pairs(
            form_urlencoded::parse(query.as_bytes()).filter(|(key, _)| key != "token"),
        )
        .finish();

    if filtered.is_empty() {
        None
    } else {
        Some(filtered)
    }
}

fn is_websocket_request(headers: &HeaderMap) -> bool {
    headers
        .get(header::UPGRADE)
        .and_then(|value| value.to_str().ok())
        .map(|value| value.eq_ignore_ascii_case("websocket"))
        .unwrap_or(false)
}

fn is_hop_by_hop_header(name: &HeaderName) -> bool {
    matches!(
        name.as_str(),
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
    )
}

fn axum_to_tungstenite(message: Message) -> Option<tungstenite::Message> {
    match message {
        Message::Text(text) => Some(tungstenite::Message::Text(text)),
        Message::Binary(binary) => Some(tungstenite::Message::Binary(binary)),
        Message::Ping(ping) => Some(tungstenite::Message::Ping(ping)),
        Message::Pong(pong) => Some(tungstenite::Message::Pong(pong)),
        Message::Close(frame) => Some(tungstenite::Message::Close(frame.map(|frame| {
            tungstenite::protocol::CloseFrame {
                code: tungstenite::protocol::frame::coding::CloseCode::from(frame.code),
                reason: frame.reason.to_string().into(),
            }
        }))),
    }
}

fn tungstenite_to_axum(message: tungstenite::Message) -> Option<Message> {
    match message {
        tungstenite::Message::Text(text) => Some(Message::Text(text)),
        tungstenite::Message::Binary(binary) => Some(Message::Binary(binary)),
        tungstenite::Message::Ping(ping) => Some(Message::Ping(ping)),
        tungstenite::Message::Pong(pong) => Some(Message::Pong(pong)),
        tungstenite::Message::Close(frame) => Some(Message::Close(frame.map(|frame| {
            axum::extract::ws::CloseFrame {
                code: u16::from(frame.code),
                reason: frame.reason.to_string().into(),
            }
        }))),
        tungstenite::Message::Frame(_) => None,
    }
}
