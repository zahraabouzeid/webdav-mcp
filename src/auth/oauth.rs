//! Sign-in for AI apps: OAuth 2.1 with PKCE. Each connection holds its own
//! encrypted secret, so no accounts are needed. Codes and tokens are stored as
//! fingerprints, so the database alone connects no app.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::{Query, State};
use axum::handler::Handler;
use axum::http::StatusCode;
use axum::http::header::{CACHE_CONTROL, LOCATION};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Form, Json, Router, middleware};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use reqwest::Url;
use rusqlite::{Connection, OptionalExtension, params};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::auth::guard::{self, Guard, Kind};
use crate::auth::page::{self, Connecting};
use crate::auth::store::{Database, sql};
use crate::auth::vault::{Sealed, Vault};
use crate::dav::LoginForm;
use crate::error::{Result as StoreResult, WebdavError};
use crate::network::Network;

const CODE_VALID_SECONDS: u64 = 5 * 60;
pub const ACCESS_VALID_SECONDS: u64 = 60 * 60;
const UNUSED_CONNECTION_SECONDS: u64 = 90 * 24 * 60 * 60;
const UNCONNECTED_APP_SECONDS: u64 = 24 * 60 * 60;
// Writing down every use would cost a write per tool call.
const LAST_USED_STEP_SECONDS: u64 = 60 * 60;
const MAX_UNCONNECTED_APPS: u64 = 1000;
const MAX_REDIRECTS: usize = 5;
const MAX_URI_CHARS: usize = 500;
const MAX_APP_NAME_CHARS: usize = 100;
const NO_SUCH_APP: &str = "The app that sent you here is not known to this server. \
    Add the connector again in your AI app.";

#[derive(Debug, PartialEq, Eq)]
pub enum Refusal {
    Request(String),
    App,
    Grant,
    Server(String),
}

impl From<WebdavError> for Refusal {
    fn from(e: WebdavError) -> Self {
        Self::Server(e.to_string())
    }
}

type Result<T> = std::result::Result<T, Refusal>;

#[derive(Debug)]
pub struct Tokens {
    pub access: String,
    pub refresh: String,
}

pub struct OAuth {
    database: Arc<Database>,
    vault: Vault,
}

pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| since.as_secs())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn random_code() -> StoreResult<String> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes)
        .map_err(|e| WebdavError::new(format!("no random numbers from the system: {e}")))?;
    Ok(hex(&bytes))
}

fn fingerprint(code: &str) -> String {
    hex(&Sha256::digest(code.as_bytes()))
}

fn db<T>(result: rusqlite::Result<T>) -> Result<T> {
    result.map_err(|e| Refusal::Server(sql(e).to_string()))
}

fn store_error(refusal: Refusal) -> WebdavError {
    match refusal {
        Refusal::Server(message) => WebdavError::new(message),
        other => WebdavError::new(format!("{other:?}")),
    }
}

fn forget_expired(connection: &Connection, now: u64) -> Result<()> {
    db(connection.execute_batch(&format!(
        "DELETE FROM authorization_codes WHERE expires <= {now};
         DELETE FROM access_tokens WHERE expires <= {now};
         DELETE FROM connections WHERE last_used + {UNUSED_CONNECTION_SECONDS} <= {now};
         DELETE FROM apps WHERE registered + {UNCONNECTED_APP_SECONDS} <= {now}
             AND NOT EXISTS (SELECT 1 FROM connections WHERE connections.app = apps.id);",
    )))
}

fn allowed_redirect(uri: &str) -> bool {
    let Ok(url) = Url::parse(uri) else {
        return false;
    };
    let loopback = matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"));
    uri.len() <= MAX_URI_CHARS
        && url.fragment().is_none()
        && url.username().is_empty()
        && (url.scheme() == "https" || (url.scheme() == "http" && loopback))
}

fn pkce_text(text: &str) -> bool {
    let allowed = |c: char| c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | '_' | '~');
    (43..=128).contains(&text.len()) && text.chars().all(allowed)
}

pub fn challenge_of(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

fn issue(connection: &Connection, id: &str, now: u64) -> Result<Tokens> {
    let tokens = Tokens {
        access: random_code()?,
        refresh: random_code()?,
    };
    db(connection.execute(
        "INSERT INTO access_tokens (fingerprint, connection, expires) VALUES (?1, ?2, ?3)",
        params![fingerprint(&tokens.access), id, now + ACCESS_VALID_SECONDS],
    ))?;
    db(connection.execute(
        "INSERT INTO refresh_tokens (fingerprint, connection) VALUES (?1, ?2)",
        params![fingerprint(&tokens.refresh), id],
    ))?;
    Ok(tokens)
}

impl OAuth {
    pub fn new(database: Arc<Database>, vault: Vault) -> Self {
        Self { database, vault }
    }

    /// Anyone may register, so an app nobody connects is forgotten after a day.
    pub fn register(&self, name: &str, redirects: &[String], now: u64) -> Result<String> {
        let name = name.trim();
        if name.is_empty() || name.chars().count() > MAX_APP_NAME_CHARS {
            return Err(Refusal::Request(format!(
                "an app name has 1 to {MAX_APP_NAME_CHARS} characters"
            )));
        }
        if redirects.is_empty() || redirects.len() > MAX_REDIRECTS {
            return Err(Refusal::Request(format!(
                "an app has 1 to {MAX_REDIRECTS} redirect URIs"
            )));
        }
        if let Some(refused) = redirects.iter().find(|uri| !allowed_redirect(uri)) {
            return Err(Refusal::Request(format!(
                "redirect URI not allowed: {refused}"
            )));
        }
        let id = random_code()?;
        self.database
            .with(|connection| {
                let transaction = connection.transaction().map_err(sql)?;
                forget_expired(&transaction, now).map_err(store_error)?;
                let waiting: u64 = transaction
                    .query_row(
                        "SELECT count(*) FROM apps WHERE NOT EXISTS
                             (SELECT 1 FROM connections WHERE connections.app = apps.id)",
                        [],
                        |row| row.get(0),
                    )
                    .map_err(sql)?;
                if waiting >= MAX_UNCONNECTED_APPS {
                    return Ok(Err(Refusal::Request(
                        "too many apps are waiting to be connected; try again tomorrow".into(),
                    )));
                }
                transaction
                    .execute(
                        "INSERT INTO apps (id, name, registered) VALUES (?1, ?2, ?3)",
                        params![id, name, now],
                    )
                    .map_err(sql)?;
                for uri in redirects {
                    transaction
                        .execute(
                            "INSERT OR IGNORE INTO app_redirects (app, uri) VALUES (?1, ?2)",
                            params![id, uri],
                        )
                        .map_err(sql)?;
                }
                transaction.commit().map_err(sql)?;
                Ok(Ok(id))
            })
            .map_err(Refusal::from)?
    }

    pub fn app_name(&self, app: &str, redirect: &str) -> Result<String> {
        let name: Option<String> = self.database.with(|connection| {
            connection
                .query_row(
                    "SELECT apps.name FROM apps
                     JOIN app_redirects ON app_redirects.app = apps.id
                     WHERE apps.id = ?1 AND app_redirects.uri = ?2",
                    params![app, redirect],
                    |row| row.get(0),
                )
                .optional()
                .map_err(sql)
        })?;
        name.ok_or(Refusal::App)
    }

    /// The secret waits sealed in the code until the app exchanges it, so a
    /// sign-in that is never finished leaves nothing behind.
    pub fn allow(
        &self,
        app: &str,
        redirect: &str,
        challenge: &str,
        secret: &str,
        now: u64,
    ) -> Result<String> {
        if !pkce_text(challenge) {
            return Err(Refusal::Request("a PKCE code challenge is required".into()));
        }
        self.app_name(app, redirect)?;
        let code = random_code()?;
        let id = random_code()?;
        let sealed = self.vault.seal(&id, secret)?;
        self.database.with(|connection| {
            connection
                .execute(
                    "INSERT INTO authorization_codes
                         (fingerprint, connection, app, redirect, challenge, nonce, sealed, expires)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                    params![
                        fingerprint(&code),
                        id,
                        app,
                        redirect,
                        challenge,
                        sealed.nonce,
                        sealed.text,
                        now + CODE_VALID_SECONDS
                    ],
                )
                .map_err(sql)
        })?;
        Ok(code)
    }

    /// A code works once, even when the attempt fails.
    pub fn exchange(
        &self,
        code: &str,
        app: &str,
        redirect: &str,
        verifier: &str,
        now: u64,
    ) -> Result<Tokens> {
        self.database
            .with(|connection| {
                let transaction = connection.transaction().map_err(sql)?;
                let used = transaction
                    .query_row(
                        "DELETE FROM authorization_codes WHERE fingerprint = ?1
                         RETURNING connection, app, redirect, challenge, nonce, sealed, expires",
                        [fingerprint(code)],
                        |row| {
                            Ok(UsedCode {
                                connection: row.get(0)?,
                                app: row.get(1)?,
                                redirect: row.get(2)?,
                                challenge: row.get(3)?,
                                nonce: row.get(4)?,
                                sealed: row.get(5)?,
                                expires: row.get(6)?,
                            })
                        },
                    )
                    .optional()
                    .map_err(sql)?;
                let tokens = match used {
                    Some(used)
                        if used.expires > now
                            && used.app == app
                            && used.redirect == redirect
                            && pkce_text(verifier)
                            && challenge_of(verifier) == used.challenge =>
                    {
                        transaction
                            .execute(
                                "INSERT INTO connections
                                     (id, app, nonce, sealed, connected, last_used)
                                 VALUES (?1, ?2, ?3, ?4, ?5, ?5)",
                                params![used.connection, app, used.nonce, used.sealed, now],
                            )
                            .map_err(sql)?;
                        issue(&transaction, &used.connection, now)
                    }
                    _ => Err(Refusal::Grant),
                };
                if !matches!(tokens, Err(Refusal::Server(_))) {
                    transaction.commit().map_err(sql)?;
                }
                Ok(tokens)
            })
            .map_err(Refusal::from)?
    }

    pub fn refresh(&self, refresh: &str, app: &str, now: u64) -> Result<Tokens> {
        self.database
            .with(|connection| {
                let transaction = connection.transaction().map_err(sql)?;
                forget_expired(&transaction, now).map_err(store_error)?;
                let id: Option<String> = transaction
                    .query_row(
                        "DELETE FROM refresh_tokens WHERE fingerprint = ?1
                         AND connection IN (SELECT id FROM connections WHERE app = ?2)
                         RETURNING connection",
                        params![fingerprint(refresh), app],
                        |row| row.get(0),
                    )
                    .optional()
                    .map_err(sql)?;
                let tokens = match id {
                    Some(id) => {
                        transaction
                            .execute("DELETE FROM access_tokens WHERE connection = ?1", [&id])
                            .map_err(sql)?;
                        transaction
                            .execute(
                                "UPDATE connections SET last_used = ?2 WHERE id = ?1",
                                params![id, now],
                            )
                            .map_err(sql)?;
                        issue(&transaction, &id, now)
                    }
                    None => Err(Refusal::Grant),
                };
                if !matches!(tokens, Err(Refusal::Server(_))) {
                    transaction.commit().map_err(sql)?;
                }
                Ok(tokens)
            })
            .map_err(Refusal::from)?
    }

    pub fn connection_of(&self, access: &str, now: u64) -> Option<String> {
        let found = self.database.with(|connection| {
            let found: Option<(String, u64)> = connection
                .query_row(
                    "SELECT connections.id, connections.last_used
                     FROM access_tokens JOIN connections ON connections.id = access_tokens.connection
                     WHERE access_tokens.fingerprint = ?1 AND access_tokens.expires > ?2
                         AND connections.last_used + ?3 > ?2",
                    params![fingerprint(access), now, UNUSED_CONNECTION_SECONDS],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()
                .map_err(sql)?;
            if let Some((id, last_used)) = &found
                && now.saturating_sub(*last_used) >= LAST_USED_STEP_SECONDS
            {
                connection
                    .execute(
                        "UPDATE connections SET last_used = ?2 WHERE id = ?1",
                        params![id, now],
                    )
                    .map_err(sql)?;
            }
            Ok(found.map(|(id, _)| id))
        });
        found.ok().flatten()
    }

    pub fn secret_of(&self, id: &str) -> StoreResult<String> {
        let sealed = self.database.with(|connection| {
            connection
                .query_row(
                    "SELECT nonce, sealed FROM connections WHERE id = ?1",
                    [id],
                    |row| {
                        Ok(Sealed {
                            nonce: row.get(0)?,
                            text: row.get(1)?,
                        })
                    },
                )
                .map_err(sql)
        })?;
        self.vault.open_secret(id, &sealed)
    }
}

struct UsedCode {
    connection: String,
    app: String,
    redirect: String,
    challenge: String,
    nonce: Vec<u8>,
    sealed: Vec<u8>,
    expires: u64,
}

#[derive(Clone)]
struct Web {
    oauth: Arc<OAuth>,
    network: Arc<Network>,
    base: Arc<str>,
}

pub fn routes(oauth: Arc<OAuth>, network: Arc<Network>, base: &str, guard: &Arc<Guard>) -> Router {
    let limited = |kind| middleware::from_fn_with_state((guard.clone(), kind), guard::limit);
    Router::new()
        .route("/.well-known/oauth-protected-resource", get(resource))
        .route("/.well-known/oauth-protected-resource/mcp", get(resource))
        .route("/.well-known/oauth-authorization-server", get(issuer))
        .route(
            "/oauth/register",
            post(register).layer(limited(Kind::Registration)),
        )
        .route("/oauth/token", post(token).layer(limited(Kind::Token)))
        .route(
            "/oauth/authorize",
            get(ask)
                .post(answer.layer(limited(Kind::Connect)))
                .layer(middleware::from_fn(guard::same_site)),
        )
        .with_state(Web {
            oauth,
            network,
            base: base.into(),
        })
}

pub fn resource_metadata(base: &str) -> String {
    format!("{base}/.well-known/oauth-protected-resource/mcp")
}

async fn resource(State(web): State<Web>) -> Json<Value> {
    Json(json!({
        "resource": format!("{}/mcp", web.base),
        "authorization_servers": [web.base],
        "bearer_methods_supported": ["header"],
        "resource_name": env!("CARGO_PKG_NAME"),
    }))
}

async fn issuer(State(web): State<Web>) -> Json<Value> {
    let base = &web.base;
    Json(json!({
        "issuer": base,
        "authorization_endpoint": format!("{base}/oauth/authorize"),
        "token_endpoint": format!("{base}/oauth/token"),
        "registration_endpoint": format!("{base}/oauth/register"),
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["none"],
        "authorization_response_iss_parameter_supported": true,
    }))
}

impl IntoResponse for Refusal {
    fn into_response(self) -> Response {
        let (status, error, description) = match self {
            Self::Request(description) => (StatusCode::BAD_REQUEST, "invalid_request", description),
            Self::App => (
                StatusCode::UNAUTHORIZED,
                "invalid_client",
                "unknown app".into(),
            ),
            Self::Grant => (
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                "the code or token is not valid".into(),
            ),
            Self::Server(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "something went wrong on the server".into(),
            ),
        };
        let body = json!({ "error": error, "error_description": description });
        (status, [(CACHE_CONTROL, "no-store")], Json(body)).into_response()
    }
}

#[derive(Deserialize)]
struct Registration {
    client_name: Option<String>,
    #[serde(default)]
    redirect_uris: Vec<String>,
}

async fn register(
    State(web): State<Web>,
    Json(registration): Json<Registration>,
) -> Result<Response> {
    let name = registration
        .client_name
        .filter(|name| !name.trim().is_empty())
        .or_else(|| {
            let first = registration.redirect_uris.first()?;
            Url::parse(first).ok()?.host_str().map(str::to_owned)
        })
        .unwrap_or_default();
    let now = now();
    let id = web
        .oauth
        .register(&name, &registration.redirect_uris, now)?;
    let body = json!({
        "client_id": id,
        "client_id_issued_at": now,
        "client_name": name.trim(),
        "redirect_uris": registration.redirect_uris,
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        "token_endpoint_auth_method": "none",
    });
    Ok((StatusCode::CREATED, Json(body)).into_response())
}

#[derive(Deserialize)]
struct TokenRequest {
    grant_type: String,
    client_id: Option<String>,
    code: Option<String>,
    redirect_uri: Option<String>,
    code_verifier: Option<String>,
    refresh_token: Option<String>,
}

fn required(value: Option<String>, name: &str) -> Result<String> {
    value.ok_or_else(|| Refusal::Request(format!("{name} is missing")))
}

async fn token(State(web): State<Web>, Form(request): Form<TokenRequest>) -> Result<Response> {
    let now = now();
    let app = required(request.client_id, "client_id")?;
    let tokens = match request.grant_type.as_str() {
        "authorization_code" => web.oauth.exchange(
            &required(request.code, "code")?,
            &app,
            &required(request.redirect_uri, "redirect_uri")?,
            &required(request.code_verifier, "code_verifier")?,
            now,
        )?,
        "refresh_token" => web.oauth.refresh(
            &required(request.refresh_token, "refresh_token")?,
            &app,
            now,
        )?,
        _ => {
            let body = json!({ "error": "unsupported_grant_type" });
            return Ok((StatusCode::BAD_REQUEST, Json(body)).into_response());
        }
    };
    let body = json!({
        "access_token": tokens.access,
        "token_type": "Bearer",
        "expires_in": ACCESS_VALID_SECONDS,
        "refresh_token": tokens.refresh,
    });
    Ok(([(CACHE_CONTROL, "no-store")], Json(body)).into_response())
}

#[derive(Deserialize)]
struct Asking {
    client_id: String,
    redirect_uri: String,
    code_challenge: Option<String>,
    code_challenge_method: Option<String>,
    state: Option<String>,
}

#[derive(Deserialize)]
struct Answer {
    client_id: String,
    redirect_uri: String,
    code_challenge: String,
    code_challenge_method: String,
    state: Option<String>,
    #[serde(flatten)]
    login: LoginForm,
    action: String,
}

/// Sends the browser back to the app that asked, with `pairs` added.
fn back_to_app(web: &Web, redirect: &str, state: Option<&str>, pairs: &[(&str, &str)]) -> Response {
    let Ok(mut back) = Url::parse(redirect) else {
        return page::problem(NO_SUCH_APP);
    };
    {
        let mut query = back.query_pairs_mut();
        for (name, value) in pairs {
            query.append_pair(name, value);
        }
        if let Some(state) = state {
            query.append_pair("state", state);
        }
        query.append_pair("iss", &web.base);
    }
    (StatusCode::SEE_OTHER, [(LOCATION, back.as_str())]).into_response()
}

fn host_of(redirect: &str) -> String {
    Url::parse(redirect)
        .ok()
        .and_then(|url| url.host_str().map(str::to_owned))
        .unwrap_or_default()
}

async fn ask(State(web): State<Web>, Query(asking): Query<Asking>) -> Response {
    let Ok(app) = web.oauth.app_name(&asking.client_id, &asking.redirect_uri) else {
        return page::problem(NO_SUCH_APP);
    };
    let state = asking.state.as_deref();
    let challenge = asking.code_challenge.as_deref().unwrap_or_default();
    let method = asking.code_challenge_method.as_deref().unwrap_or_default();
    if method != "S256" || !pkce_text(challenge) {
        let pairs = [
            ("error", "invalid_request"),
            ("error_description", "PKCE with S256 is required"),
        ];
        return back_to_app(&web, &asking.redirect_uri, state, &pairs);
    }
    page::connect(
        &Connecting {
            app: &app,
            app_host: &host_of(&asking.redirect_uri),
            client_id: &asking.client_id,
            redirect_uri: &asking.redirect_uri,
            code_challenge: challenge,
            code_challenge_method: method,
            state,
            login: &LoginForm::default(),
        },
        None,
    )
}

async fn answer(State(web): State<Web>, Form(answer): Form<Answer>) -> Response {
    let Ok(app) = web.oauth.app_name(&answer.client_id, &answer.redirect_uri) else {
        return page::problem(NO_SUCH_APP);
    };
    let state = answer.state.as_deref();
    if answer.action != "allow" {
        let pairs = [("error", "access_denied")];
        return back_to_app(&web, &answer.redirect_uri, state, &pairs);
    }
    if answer.code_challenge_method != "S256" {
        let pairs = [
            ("error", "invalid_request"),
            ("error_description", "PKCE with S256 is required"),
        ];
        return back_to_app(&web, &answer.redirect_uri, state, &pairs);
    }
    let secret = match web.network.check(&answer.login).await {
        Ok(login) => login.to_secret(),
        Err(error) => {
            return page::connect(
                &Connecting {
                    app: &app,
                    app_host: &host_of(&answer.redirect_uri),
                    client_id: &answer.client_id,
                    redirect_uri: &answer.redirect_uri,
                    code_challenge: &answer.code_challenge,
                    code_challenge_method: &answer.code_challenge_method,
                    state,
                    login: &answer.login,
                },
                Some(&error.to_string()),
            );
        }
    };
    match web.oauth.allow(
        &answer.client_id,
        &answer.redirect_uri,
        &answer.code_challenge,
        &secret,
        now(),
    ) {
        Ok(code) => back_to_app(&web, &answer.redirect_uri, state, &[("code", &code)]),
        Err(refusal) => refusal.into_response(),
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;

    use super::*;

    const REDIRECT: &str = "https://claude.ai/api/mcp/auth_callback";
    const VERIFIER: &str = "a-verifier-that-is-long-enough-for-pkce-0123456789";
    const SECRET: &str = "https://calendar.example/secret-feed";
    const DAY: u64 = 24 * 60 * 60;

    struct Server {
        oauth: OAuth,
        folder: PathBuf,
    }

    fn server(name: &str) -> Server {
        let folder =
            std::env::temp_dir().join(format!("webdav-oauth-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&folder);
        let database = Database::open(&folder).expect("database");
        let vault = Vault::open(&folder).expect("vault");
        Server {
            oauth: OAuth::new(database, vault),
            folder,
        }
    }

    impl Server {
        fn connect(&self, now: u64) -> (String, Tokens) {
            let app = self
                .oauth
                .register("Claude", &[REDIRECT.into()], now)
                .expect("register");
            let code = self
                .oauth
                .allow(&app, REDIRECT, &challenge_of(VERIFIER), SECRET, now)
                .expect("allow");
            let tokens = self
                .oauth
                .exchange(&code, &app, REDIRECT, VERIFIER, now)
                .expect("exchange");
            (app, tokens)
        }

        fn done(self) {
            drop(self.oauth);
            fs::remove_dir_all(self.folder).expect("clean up");
        }
    }

    #[test]
    fn only_safe_redirects_can_be_registered() {
        let server = server("register");
        let register = |uris: &[&str]| {
            let uris: Vec<String> = uris.iter().map(|uri| uri.to_string()).collect();
            server.oauth.register("Claude", &uris, 0)
        };
        assert!(register(&[REDIRECT]).is_ok());
        assert!(register(&["http://127.0.0.1:6274/callback"]).is_ok());
        for refused in [
            "http://claude.ai/callback",
            "https://claude.ai/callback#part",
            "https://user@claude.ai/callback",
            "javascript:alert(1)",
            "not a uri",
        ] {
            assert!(
                matches!(register(&[refused]), Err(Refusal::Request(_))),
                "{refused}"
            );
        }
        assert!(register(&[]).is_err());
        assert!(server.oauth.register(" ", &[REDIRECT.into()], 0).is_err());
        server.done();
    }

    #[test]
    fn a_connection_opens_its_own_secret_only_with_a_valid_token() {
        let server = server("flow");
        let (_, tokens) = server.connect(0);
        let id = server.oauth.connection_of(&tokens.access, 1).expect("id");
        assert_eq!(server.oauth.secret_of(&id).expect("secret"), SECRET);
        assert_eq!(server.oauth.connection_of(&tokens.refresh, 1), None);
        assert_eq!(server.oauth.connection_of("made up", 1), None);
        assert_eq!(
            server
                .oauth
                .connection_of(&tokens.access, ACCESS_VALID_SECONDS),
            None
        );
        server.done();
    }

    #[test]
    fn two_connections_keep_their_secrets_apart() {
        let server = server("apart");
        let (app, first) = server.connect(0);
        let code = server
            .oauth
            .allow(&app, REDIRECT, &challenge_of(VERIFIER), "https://other", 0)
            .expect("allow");
        let second = server
            .oauth
            .exchange(&code, &app, REDIRECT, VERIFIER, 0)
            .expect("exchange");
        let secret = |tokens: &Tokens| {
            let id = server.oauth.connection_of(&tokens.access, 1).expect("id");
            server.oauth.secret_of(&id).expect("secret")
        };
        assert_eq!(secret(&first), SECRET);
        assert_eq!(secret(&second), "https://other");
        server.done();
    }

    #[test]
    fn a_code_works_once_and_only_with_its_verifier_and_redirect() {
        let server = server("code");
        let app = server
            .oauth
            .register("Claude", &[REDIRECT.into()], 0)
            .expect("register");
        let challenge = challenge_of(VERIFIER);
        let allow = || {
            server
                .oauth
                .allow(&app, REDIRECT, &challenge, SECRET, 0)
                .expect("allow")
        };
        let wrong = "another-verifier-that-is-long-enough-for-pkce-012345";
        assert_eq!(
            server
                .oauth
                .exchange(&allow(), &app, REDIRECT, wrong, 0)
                .expect_err("refused"),
            Refusal::Grant
        );
        let elsewhere = "https://claude.ai/elsewhere";
        assert!(
            server
                .oauth
                .exchange(&allow(), &app, elsewhere, VERIFIER, 0)
                .is_err()
        );
        let late = allow();
        assert!(
            server
                .oauth
                .exchange(&late, &app, REDIRECT, VERIFIER, CODE_VALID_SECONDS)
                .is_err()
        );

        let code = allow();
        assert!(
            server
                .oauth
                .exchange(&code, &app, REDIRECT, VERIFIER, 0)
                .is_ok()
        );
        assert!(
            server
                .oauth
                .exchange(&code, &app, REDIRECT, VERIFIER, 0)
                .is_err()
        );
        server.done();
    }

    #[test]
    fn a_code_is_only_given_for_a_registered_redirect_and_with_a_challenge() {
        let server = server("allow");
        let app = server
            .oauth
            .register("Claude", &[REDIRECT.into()], 0)
            .expect("register");
        let challenge = challenge_of(VERIFIER);
        let allow = |app: &str, redirect: &str, challenge: &str| {
            server.oauth.allow(app, redirect, challenge, SECRET, 0)
        };
        assert_eq!(
            allow(&app, "https://attacker.example/callback", &challenge).expect_err("refused"),
            Refusal::App
        );
        assert_eq!(
            allow("unknown", REDIRECT, &challenge).expect_err("refused"),
            Refusal::App
        );
        assert!(matches!(
            allow(&app, REDIRECT, ""),
            Err(Refusal::Request(_))
        ));
        server.done();
    }

    #[test]
    fn refreshing_replaces_both_tokens() {
        let server = server("refresh");
        let (app, first) = server.connect(0);
        let second = server
            .oauth
            .refresh(&first.refresh, &app, 10)
            .expect("refresh");
        assert_eq!(server.oauth.connection_of(&first.access, 11), None);
        assert!(server.oauth.connection_of(&second.access, 11).is_some());
        assert_eq!(
            server
                .oauth
                .refresh(&first.refresh, &app, 12)
                .expect_err("refused"),
            Refusal::Grant
        );
        assert!(
            server
                .oauth
                .refresh(&second.refresh, "another app", 12)
                .is_err()
        );
        server.done();
    }

    #[test]
    fn a_connection_unused_for_90_days_ends() {
        let server = server("unused");
        let (app, tokens) = server.connect(0);
        let still = server
            .oauth
            .refresh(&tokens.refresh, &app, 89 * DAY)
            .expect("in time");
        assert!(
            server
                .oauth
                .refresh(&still.refresh, &app, 179 * DAY + 1)
                .is_err()
        );
        server.done();
    }

    #[test]
    fn the_database_holds_no_code_token_or_secret() {
        let server = server("stored");
        let (_, tokens) = server.connect(0);
        let folder = server.folder.clone();
        drop(server.oauth);
        let raw = fs::read(folder.join("webdav-mcp.db")).expect("database file");
        let raw = String::from_utf8_lossy(&raw);
        assert!(!raw.contains(&tokens.access) && !raw.contains(&tokens.refresh));
        assert!(!raw.contains(SECRET));
        fs::remove_dir_all(folder).expect("clean up");
    }
}
