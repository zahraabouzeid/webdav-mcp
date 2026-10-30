//! A read-only WebDAV client: it only ever sends PROPFIND and GET.

use percent_encoding::percent_decode_str;
use reqwest::{Method, Response, Url};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::documents::{self, Document, Request};
use crate::error::{Result, WebdavError};
use crate::multistatus;

const PROPFIND_BODY: &str = r#"<?xml version="1.0"?>
<d:propfind xmlns:d="DAV:"><d:prop>
<d:resourcetype/><d:getcontentlength/><d:getlastmodified/>
</d:prop></d:propfind>"#;
const MAX_LISTING_BYTES: usize = 20 * 1024 * 1024;
const REFUSED: &str = "The file service refused this login. Check the username and the app \
    password, or connect again in the AI app if it has changed.";
const NO_WEBDAV: &str = "No WebDAV file service answered at this address. Check the address.";

/// What someone typed on the sign-in page. Not `Debug`, so the password cannot
/// end up in a log.
#[derive(Default, Deserialize)]
pub struct LoginForm {
    pub address: Option<String>,
    pub user: Option<String>,
    pub password: Option<String>,
}

/// What is stored, encrypted, for one connection. Not `Debug`, like the form.
#[derive(Serialize, Deserialize)]
pub struct Login {
    pub root: String,
    pub user: String,
    pub password: String,
}

impl Login {
    pub fn to_secret(&self) -> String {
        serde_json::to_string(self).expect("a login can be written as JSON")
    }

    pub fn from_secret(secret: &str) -> Result<Self> {
        serde_json::from_str(secret).map_err(|_| WebdavError::new("a stored login is damaged"))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
pub struct FileEntry {
    /// Relative to the top folder, `/`-separated.
    pub path: String,
    pub is_dir: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub modified: Option<String>,
}

pub struct DavClient {
    http: reqwest::Client,
    root: Url,
    user: String,
    password: String,
}

fn network(error: reqwest::Error) -> WebdavError {
    WebdavError::new(format!(
        "The file service could not be reached: {}",
        error.without_url()
    ))
}

impl DavClient {
    pub fn new(http: reqwest::Client, root: Url, user: String, password: String) -> Self {
        Self {
            http,
            root,
            user,
            password,
        }
    }

    /// The URL of a path inside the top folder, and that path normalised.
    fn url_for(&self, path: &str) -> Result<(Url, String)> {
        let segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
        if segments.iter().any(|s| matches!(*s, "." | "..")) {
            return Err(WebdavError::new("A path must not contain `.` or `..`."));
        }
        let mut url = self.root.clone();
        url.path_segments_mut()
            .map_err(|()| WebdavError::new(NO_WEBDAV))?
            .pop_if_empty()
            .extend(&segments);
        Ok((url, segments.join("/")))
    }

    async fn send(&self, method: Method, url: Url, body: Option<&'static str>) -> Result<Response> {
        let mut request = self
            .http
            .request(method, url)
            .basic_auth(&self.user, Some(&self.password));
        if let Some(body) = body {
            request = request
                .header("Depth", "1")
                .header("Content-Type", "application/xml")
                .body(body);
        }
        let response = request.send().await.map_err(network)?;
        match response.status().as_u16() {
            401 | 403 => Err(WebdavError::new(REFUSED)),
            404 => Err(WebdavError::new("There is no such file or folder.")),
            300..=399 | 405 => Err(WebdavError::new(NO_WEBDAV)),
            _ => response.error_for_status().map_err(network),
        }
    }

    async fn body_of(mut response: Response, limit: usize) -> Result<Vec<u8>> {
        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(network)? {
            if body.len() + chunk.len() > limit {
                return Err(WebdavError::new(format!(
                    "This is larger than {} MB.",
                    limit / (1024 * 1024)
                )));
            }
            body.extend_from_slice(&chunk);
        }
        Ok(body)
    }

    pub async fn list(&self, path: &str) -> Result<Vec<FileEntry>> {
        let (mut url, listed) = self.url_for(path)?;
        // Some servers answer a folder without the slash with a redirect.
        url.path_segments_mut()
            .map_err(|()| WebdavError::new(NO_WEBDAV))?
            .pop_if_empty()
            .push("");
        let propfind = Method::from_bytes(b"PROPFIND").expect("PROPFIND is a valid method");
        let response = self.send(propfind, url, Some(PROPFIND_BODY)).await?;
        let body = Self::body_of(response, MAX_LISTING_BYTES).await?;
        let root = percent_decode_str(self.root.path()).decode_utf8_lossy();
        multistatus::parse(&String::from_utf8_lossy(&body), &root, &listed)
            .map_err(|_| WebdavError::new(NO_WEBDAV))
    }

    pub async fn read(
        &self,
        path: &str,
        pages: Option<String>,
        view: documents::View,
        entry: Option<String>,
    ) -> Result<Document> {
        let (url, _) = self.url_for(path)?;
        let response = self.send(Method::GET, url, None).await?;
        documents::check_size(response.content_length().unwrap_or(0))?;
        let bytes = Self::body_of(response, documents::MAX_FILE_BYTES).await?;
        // Reading a large PDF takes a while, so it runs off the request threads.
        tokio::task::spawn_blocking(move || {
            documents::read(
                &bytes,
                Request {
                    pages: pages.as_deref(),
                    view,
                    entry: entry.as_deref(),
                },
            )
        })
        .await
        .map_err(|_| WebdavError::new("This file could not be read."))?
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn client() -> DavClient {
        DavClient::new(
            reqwest::Client::new(),
            Url::parse("https://cloud.example/remote.php/dav/files/ab123456@uni.example/")
                .expect("a URL"),
            "ab123456@uni.example".into(),
            "app-password".into(),
        )
    }

    #[test]
    fn paths_are_encoded_and_stay_inside_the_top_folder() {
        let client = client();
        let (url, listed) = client.url_for("/Uni/Analysis I/").expect("url");
        assert_eq!(
            url.path(),
            "/remote.php/dav/files/ab123456@uni.example/Uni/Analysis%20I"
        );
        assert_eq!(listed, "Uni/Analysis I");
        assert!(client.url_for("Uni/../../other-user").is_err());
        assert!(client.url_for("./Uni").is_err());
    }

    #[test]
    fn a_login_survives_being_stored() {
        let login = Login {
            root: "https://cloud.example/dav/".into(),
            user: "someone".into(),
            password: "app-password".into(),
        };
        let stored = Login::from_secret(&login.to_secret()).expect("a login");
        assert_eq!(stored.password, "app-password");
        assert!(Login::from_secret("damaged").is_err());
    }
}
