use crate::service::AuthService;

#[derive(Clone)]
pub struct AppState {
    pub auth: AuthService,
    pub proxy_client: reqwest::Client,
    pub profile_service_url: String,
    pub message_service_url: String,
}
