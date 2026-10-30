use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

use axum::Router;
use axum::body::Body;
use axum::extract::Request as ServiceRequest;
use axum::http::{Method, Request, StatusCode, header};
use axum::response::{IntoResponse, Response};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use reqwest::Url;
use serde_json::{Value, json};
use tower::ServiceExt;
use webdav_mcp::app;
use webdav_mcp::auth::oauth::challenge_of;
use webdav_mcp::config::Settings;
use webdav_mcp::network::Addresses;

const REDIRECT: &str = "https://claude.ai/api/mcp/auth_callback";
const VERIFIER: &str = "a-verifier-that-is-long-enough-for-pkce-0123456789";
const HOST: &str = "testserver";
const USER: &str = "someone";
const PASSWORD: &str = "app-password-123";
const PNG: &[u8] = &[0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a, 0xff];

const LISTING: &str = r#"<?xml version="1.0"?>
<d:multistatus xmlns:d="DAV:">
 <d:response><d:href>/dav/Uni/</d:href>
  <d:propstat><d:prop><d:resourcetype><d:collection/></d:resourcetype></d:prop></d:propstat></d:response>
 <d:response><d:href>/dav/Uni/Analysis%20I/</d:href>
  <d:propstat><d:prop><d:resourcetype><d:collection/></d:resourcetype></d:prop></d:propstat></d:response>
 <d:response><d:href>/dav/Uni/notes.md</d:href>
  <d:propstat><d:prop><d:resourcetype/><d:getcontentlength>7</d:getcontentlength></d:prop></d:propstat></d:response>
</d:multistatus>"#;

struct Server {
    router: Router,
    address: String,
    folder: PathBuf,
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.folder);
    }
}

async fn file_service(request: ServiceRequest) -> Response {
    let expected = format!("Basic {}", STANDARD.encode(format!("{USER}:{PASSWORD}")));
    let authorized = request
        .headers()
        .get(header::AUTHORIZATION)
        .is_some_and(|value| value == expected.as_str());
    if !authorized {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let path = request.uri().path().to_owned();
    match (request.method().as_str(), path.as_str()) {
        ("PROPFIND", "/dav/" | "/dav/Uni/") => {
            let status = StatusCode::from_u16(207).expect("a status");
            (status, LISTING).into_response()
        }
        ("GET", "/dav/Uni/notes.md") => "# Notes".into_response(),
        ("GET", "/dav/Uni/picture.png") => PNG.into_response(),
        ("GET", "/dav/Uni/moved.md") => {
            (StatusCode::FOUND, [(header::LOCATION, "/elsewhere")]).into_response()
        }
        _ => StatusCode::NOT_FOUND.into_response(),
    }
}

async fn start(name: &str) -> Server {
    let service = Router::new().fallback(file_service);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("a free port");
    let address = listener.local_addr().expect("an address");
    tokio::spawn(async move { axum::serve(listener, service).await });

    let folder = std::env::temp_dir().join(format!("webdav-flow-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&folder);
    let settings = Settings::from_map(&HashMap::from([
        ("PUBLIC_HOST".to_owned(), HOST.to_owned()),
        ("DATA_DIR".to_owned(), folder.display().to_string()),
    ]))
    .expect("valid settings");
    Server {
        router: app(&settings, Addresses::Any).expect("an app"),
        address: format!("http://{address}/dav"),
        folder,
    }
}

fn encoded(value: &str) -> String {
    Url::parse_with_params("https://x", [("v", value)])
        .expect("url")
        .query()
        .expect("query")["v=".len()..]
        .to_owned()
}

fn form(path: &str, fields: &[(&str, &str)]) -> Request<Body> {
    let body = fields
        .iter()
        .map(|(key, value)| format!("{key}={}", encoded(value)))
        .collect::<Vec<_>>()
        .join("&");
    Request::post(path)
        .header(header::HOST, HOST)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header("sec-fetch-site", "same-origin")
        .body(Body::from(body))
        .expect("a request")
}

impl Server {
    async fn call(&self, request: Request<Body>) -> (StatusCode, axum::http::HeaderMap, String) {
        let response = self
            .router
            .clone()
            .oneshot(request)
            .await
            .expect("a response");
        let status = response.status();
        let headers = response.headers().clone();
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("a body");
        (
            status,
            headers,
            String::from_utf8_lossy(&bytes).into_owned(),
        )
    }

    async fn register(&self) -> String {
        let body = json!({"client_name": "Claude", "redirect_uris": [REDIRECT]});
        let request = Request::post("/oauth/register")
            .header(header::HOST, HOST)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body.to_string()))
            .expect("a request");
        let (status, _, text) = self.call(request).await;
        assert_eq!(status, StatusCode::CREATED, "{text}");
        let answer: Value = serde_json::from_str(&text).expect("json");
        answer["client_id"].as_str().expect("an id").to_owned()
    }

    async fn sign_in(
        &self,
        app: &str,
        address: &str,
        password: &str,
    ) -> (StatusCode, axum::http::HeaderMap, String) {
        let challenge = challenge_of(VERIFIER);
        self.call(form(
            "/oauth/authorize",
            &[
                ("client_id", app),
                ("redirect_uri", REDIRECT),
                ("code_challenge", &challenge),
                ("code_challenge_method", "S256"),
                ("state", "s1"),
                ("address", address),
                ("user", USER),
                ("password", password),
                ("action", "allow"),
            ],
        ))
        .await
    }

    async fn connect(&self) -> String {
        let app = self.register().await;
        let (status, headers, page) = self.sign_in(&app, &self.address, PASSWORD).await;
        assert_eq!(status, StatusCode::SEE_OTHER, "{page}");
        let back = Url::parse(headers[header::LOCATION].to_str().expect("text")).expect("url");
        let pairs: HashMap<_, _> = back.query_pairs().into_owned().collect();
        let (status, _, text) = self
            .call(form(
                "/oauth/token",
                &[
                    ("grant_type", "authorization_code"),
                    ("client_id", &app),
                    ("code", &pairs["code"]),
                    ("redirect_uri", REDIRECT),
                    ("code_verifier", VERIFIER),
                ],
            ))
            .await;
        assert_eq!(status, StatusCode::OK, "{text}");
        let tokens: Value = serde_json::from_str(&text).expect("json");
        tokens["access_token"].as_str().expect("a token").to_owned()
    }

    async fn mcp(&self, token: Option<&str>, method: &str, params: Value) -> (StatusCode, Value) {
        let mut request = Request::builder()
            .method(Method::POST)
            .uri("/mcp")
            .header(header::HOST, HOST)
            .header(header::ACCEPT, "application/json, text/event-stream")
            .header(header::CONTENT_TYPE, "application/json")
            .header("mcp-protocol-version", "2025-06-18");
        if let Some(token) = token {
            request = request.header(header::AUTHORIZATION, format!("Bearer {token}"));
        }
        let body = json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params});
        let (status, _, text) = self
            .call(
                request
                    .body(Body::from(body.to_string()))
                    .expect("a request"),
            )
            .await;
        (status, serde_json::from_str(&text).unwrap_or(Value::Null))
    }

    async fn tool(&self, token: &str, name: &str, arguments: Value) -> Value {
        let params = json!({"name": name, "arguments": arguments});
        let (status, answer) = self.mcp(Some(token), "tools/call", params).await;
        assert_eq!(status, StatusCode::OK, "{answer}");
        answer["result"].clone()
    }
}

#[tokio::test]
async fn nothing_works_without_a_token_and_the_answer_points_to_the_sign_in() {
    let server = start("token").await;
    let request = Request::post("/mcp")
        .header(header::HOST, HOST)
        .body(Body::empty())
        .expect("a request");
    let (status, headers, _) = server.call(request).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let challenge = headers[header::WWW_AUTHENTICATE].to_str().expect("text");
    assert!(
        challenge.contains("oauth-protected-resource"),
        "{challenge}"
    );
}

#[tokio::test]
async fn the_sign_in_page_asks_for_the_login_and_fits_a_phone() {
    let server = start("page").await;
    let app = server.register().await;
    let path = format!(
        "/oauth/authorize?client_id={app}&redirect_uri={}&code_challenge={}&code_challenge_method=S256",
        encoded(REDIRECT),
        challenge_of(VERIFIER)
    );
    let request = Request::get(path)
        .header(header::HOST, HOST)
        .body(Body::empty())
        .expect("a request");
    let (status, _, page) = server.call(request).await;
    assert_eq!(status, StatusCode::OK);
    assert!(page.contains("width=device-width"));
    for field in ["name=\"address\"", "name=\"user\"", "name=\"password\""] {
        assert!(page.contains(field), "{field}");
    }
}

#[tokio::test]
async fn a_wrong_password_stays_on_the_page_and_is_not_sent_back() {
    let server = start("wrong").await;
    let app = server.register().await;
    let address = server.address.clone();
    let (status, _, page) = server.sign_in(&app, &address, "a-wrong-password").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(page.contains("refused this login"), "{page}");
    assert!(!page.contains("a-wrong-password"));
    assert!(page.contains(USER), "the username stays filled in");

    let (status, _, page) = server.sign_in(&app, &address, "").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(page.contains("Enter the address"), "{page}");
}

#[tokio::test]
async fn a_connected_app_lists_and_reads_files() {
    let server = start("read").await;
    let token = server.connect().await;

    let listed = server
        .tool(&token, "list_files", json!({"path": "Uni"}))
        .await;
    assert_eq!(listed["isError"], false, "{listed}");
    let files = listed["structuredContent"]["files"]
        .as_array()
        .expect("files");
    assert_eq!(files.len(), 2);
    assert_eq!(files[0]["path"], "Uni/Analysis I");
    assert_eq!(files[0]["is_dir"], true);
    assert_eq!(files[1]["path"], "Uni/notes.md");
    assert_eq!(files[1]["size"], 7);

    let top = server.tool(&token, "list_files", json!({})).await;
    assert_eq!(top["isError"], false, "{top}");

    let read = server
        .tool(&token, "read_file", json!({"path": "Uni/notes.md"}))
        .await;
    assert_eq!(read["isError"], false, "{read}");
    let text: Value =
        serde_json::from_str(read["content"][0]["text"].as_str().expect("text")).expect("json");
    assert_eq!(text["file"]["text"], "# Notes");
    assert!(
        text["notice"]
            .as_str()
            .expect("a notice")
            .contains("Untrusted")
    );
}

#[tokio::test]
async fn a_picture_comes_back_as_a_picture() {
    let server = start("picture").await;
    let token = server.connect().await;
    let read = server
        .tool(&token, "read_file", json!({"path": "Uni/picture.png"}))
        .await;
    assert_eq!(read["isError"], false, "{read}");
    assert_eq!(read["content"][1]["type"], "image");
    assert_eq!(read["content"][1]["mimeType"], "image/png");
}

#[tokio::test]
async fn bad_paths_and_redirects_are_errors() {
    let server = start("paths").await;
    let token = server.connect().await;
    for (path, expected) in [
        ("Uni/../../other", "must not contain"),
        ("Uni/missing.md", "no such file"),
        ("Uni/moved.md", "No WebDAV"),
    ] {
        let read = server
            .tool(&token, "read_file", json!({"path": path}))
            .await;
        assert_eq!(read["isError"], true, "{read}");
        let text = read["content"][0]["text"].as_str().expect("text");
        assert!(text.contains(expected), "{path}: {text}");
    }
}

#[tokio::test]
async fn the_login_is_not_stored_readable() {
    let server = start("stored").await;
    server.connect().await;
    let mut stored = Vec::new();
    for file in fs::read_dir(&server.folder).expect("a folder") {
        stored.extend(fs::read(file.expect("a file").path()).expect("content"));
    }
    assert!(!String::from_utf8_lossy(&stored).contains(PASSWORD));
}

#[tokio::test]
async fn the_tools_are_read_only() {
    let server = start("tools").await;
    let token = server.connect().await;
    let (_, listed) = server.mcp(Some(&token), "tools/list", json!({})).await;
    let tools = listed["result"]["tools"].as_array().expect("tools");
    assert_eq!(tools.len(), 2);
    for tool in tools {
        assert_eq!(tool["annotations"]["readOnlyHint"], true, "{tool}");
    }
}
