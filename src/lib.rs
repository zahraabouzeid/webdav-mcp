pub mod auth;
pub mod config;
pub mod dav;
mod documents;
pub mod error;
mod multistatus;
pub mod network;
pub mod server;

use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError};

use axum::Router;
use axum::body::Body;
use axum::extract::State;
use axum::http::StatusCode;
use axum::http::header::{AUTHORIZATION, WWW_AUTHENTICATE};
use axum::middleware;
use axum::response::{IntoResponse, Response};
use axum::routing::{any, get};
use rmcp::transport::streamable_http_server::session::local::LocalSessionManager;
use rmcp::transport::streamable_http_server::{StreamableHttpServerConfig, StreamableHttpService};

use crate::auth::guard::{self, Guard};
use crate::auth::oauth::{self, OAuth};
use crate::auth::store::Database;
use crate::auth::vault::Vault;
use crate::config::Settings;
use crate::dav::Login;
use crate::error::Result;
use crate::network::{Addresses, Network};
use crate::server::FilesServer;

const MCP_PATH: &str = "/mcp";

pub fn app(settings: &Settings, addresses: Addresses) -> Result<Router> {
    let database = Database::open(&settings.data_dir)?;
    let vault = Vault::open(&settings.data_dir)?;
    let oauth = Arc::new(OAuth::new(database, vault));
    let network = Arc::new(Network::new(addresses));
    let guard = Guard::new(settings.behind_proxy);
    let base = settings.base_url();
    let mcp = Arc::new(ConnectedMcp {
        oauth: oauth.clone(),
        network: network.clone(),
        base: base.clone(),
        config: transport_config(settings),
        services: Mutex::default(),
    });
    Ok(Router::new()
        .route("/health", get(|| async { "ok" }))
        .route(MCP_PATH, any(serve_connection).with_state(mcp))
        .merge(oauth::routes(oauth, network, &base, &guard))
        .layer(middleware::from_fn(guard::security_headers)))
}

fn transport_config(settings: &Settings) -> StreamableHttpServerConfig {
    let config = StreamableHttpServerConfig::default()
        .with_legacy_session_mode(false)
        .with_json_response(true);
    if settings.public_host.is_empty() {
        return config.with_allowed_hosts(Vec::<String>::new());
    }
    let host = &settings.public_host;
    config
        .with_allowed_hosts([host.clone(), "localhost".into(), "127.0.0.1".into()])
        .with_allowed_origins([format!("https://{host}"), "https://claude.ai".into()])
}

type ConnectionService = StreamableHttpService<FilesServer, LocalSessionManager>;

/// Each connection has its own sessions, so a session id works for its connection only.
struct ConnectedMcp {
    oauth: Arc<OAuth>,
    network: Arc<Network>,
    base: String,
    config: StreamableHttpServerConfig,
    services: Mutex<HashMap<String, ConnectionService>>,
}

impl ConnectedMcp {
    fn service_of(&self, connection: &str) -> Result<ConnectionService> {
        let mut services = self.services.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(service) = services.get(connection) {
            return Ok(service.clone());
        }
        let login = Login::from_secret(&self.oauth.secret_of(connection)?)?;
        let server = FilesServer::new(self.network.client(&login)?, login.notes);
        let service = StreamableHttpService::new(
            move || Ok(server.clone()),
            Arc::new(LocalSessionManager::default()),
            self.config.clone(),
        );
        services.insert(connection.to_owned(), service.clone());
        Ok(service)
    }
}

async fn serve_connection(
    State(mcp): State<Arc<ConnectedMcp>>,
    request: axum::extract::Request,
) -> Response {
    let connection = request
        .headers()
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .and_then(|token| mcp.oauth.connection_of(token, oauth::now()));
    let Some(connection) = connection else {
        let challenge = format!(
            "Bearer resource_metadata=\"{}\"",
            oauth::resource_metadata(&mcp.base)
        );
        return (StatusCode::UNAUTHORIZED, [(WWW_AUTHENTICATE, challenge)]).into_response();
    };
    match mcp.service_of(&connection) {
        Ok(service) => service.handle(request).await.map(Body::new),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}
