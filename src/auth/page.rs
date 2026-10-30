//! The pages where someone connects an LLM client to their files. The HTML is in
//! `templates/`, which also escapes everything that is filled in.

use askama::Template;
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Response};

use crate::dav::LoginForm;

pub struct Connecting<'a> {
    pub server: &'a str,
    pub app: &'a str,
    pub app_host: &'a str,
    pub client_id: &'a str,
    pub redirect_uri: &'a str,
    pub code_challenge: &'a str,
    pub code_challenge_method: &'a str,
    pub state: Option<&'a str>,
    pub login: &'a LoginForm,
}

/// The password is never filled back in, so it has to be typed again after a mistake.
#[derive(Template)]
#[template(path = "connect.html")]
struct ConnectPage<'a> {
    server: &'a str,
    connecting: &'a Connecting<'a>,
    error: Option<&'a str>,
}

#[derive(Template)]
#[template(path = "problem.html")]
struct ProblemPage<'a> {
    server: &'a str,
    message: &'a str,
}

fn answer(status: StatusCode, page: impl Template) -> Response {
    match page.render() {
        Ok(html) => (status, Html(html)).into_response(),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

pub fn connect(connecting: &Connecting, error: Option<&str>) -> Response {
    let status = match error {
        Some(_) => StatusCode::BAD_REQUEST,
        None => StatusCode::OK,
    };
    let page = ConnectPage {
        server: connecting.server,
        connecting,
        error,
    };
    answer(status, page)
}

pub fn problem(server: &str, message: &str) -> Response {
    answer(StatusCode::BAD_REQUEST, ProblemPage { server, message })
}
