//! The page where someone connects an AI app to their files. It has to work on
//! a phone, because that is where many people add a connector.

use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Response};

use crate::dav::LoginForm;

pub struct Connecting<'a> {
    pub app: &'a str,
    pub app_host: &'a str,
    pub client_id: &'a str,
    pub redirect_uri: &'a str,
    pub code_challenge: &'a str,
    pub code_challenge_method: &'a str,
    pub state: Option<&'a str>,
    pub login: &'a LoginForm,
}

const STYLE: &str = "\
:root { color-scheme: light dark; --text: #1a1a1a; --muted: #666; --line: #ccc; --ground: #fff; \
--accent: #1a56db; --on-accent: #fff; --error: #b42318; }
@media (prefers-color-scheme: dark) { :root { --text: #eee; --muted: #aaa; --line: #555; \
--ground: #181818; --accent: #6b9bff; --on-accent: #101010; --error: #ff8a80; } }
* { box-sizing: border-box; }
body { margin: 0; padding: 32px 16px; background: var(--ground); color: var(--text); \
font: 16px/1.5 system-ui, sans-serif; }
main { max-width: 420px; margin: 0 auto; }
h1 { font-size: 24px; margin: 0 0 8px; }
p { margin: 0 0 16px; }
label { display: block; font-weight: 600; margin-bottom: 8px; }
input:not([type=hidden]), textarea { width: 100%; min-height: 48px; padding: 12px; font: inherit; \
border: 1px solid var(--line); border-radius: 8px; background: transparent; color: inherit; \
margin-bottom: 16px; }
.help { color: var(--muted); font-size: 14px; margin: -8px 0 24px; }
.error { color: var(--error); }
button { width: 100%; min-height: 48px; font-size: 16px; font-weight: 600; border-radius: 8px; \
border: 1px solid var(--line); background: transparent; color: inherit; margin-bottom: 12px; }
button.main { background: var(--accent); border-color: var(--accent); color: var(--on-accent); }
";

fn escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            other => out.push(other),
        }
    }
    out
}

fn document(title: &str, body: &str) -> String {
    format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\
         <title>{title}</title><style>{STYLE}</style></head><body><main>{body}</main></body></html>"
    )
}

fn hidden(name: &str, value: &str) -> String {
    format!(
        "<input type=\"hidden\" name=\"{name}\" value=\"{}\">",
        escape(value)
    )
}

/// The password is never sent back, so it has to be typed again after a mistake.
pub fn connect(connecting: &Connecting, error: Option<&str>) -> Response {
    let notice = error
        .map(|error| format!("<p class=\"error\" role=\"alert\">{}</p>", escape(error)))
        .unwrap_or_default();
    let fields = [
        hidden("client_id", connecting.client_id),
        hidden("redirect_uri", connecting.redirect_uri),
        hidden("code_challenge", connecting.code_challenge),
        hidden("code_challenge_method", connecting.code_challenge_method),
        connecting
            .state
            .map(|state| hidden("state", state))
            .unwrap_or_default(),
    ]
    .concat();
    let typed = |value: &Option<String>| escape(value.as_deref().unwrap_or_default());
    let body = format!(
        "<h1>Connect your files</h1>\
         <p><strong>{app}</strong> ({host}) will be able to read your files.</p>\
         {notice}\
         <form method=\"post\" action=\"/oauth/authorize\">{fields}\
         <label for=\"address\">Address of your file service</label>\
         <input id=\"address\" name=\"address\" value=\"{address}\" inputmode=\"url\" \
         autocomplete=\"off\" autocapitalize=\"none\" spellcheck=\"false\" \
         placeholder=\"cloud.example.org\">\
         <p class=\"help\">The address you open it under. For services other than Nextcloud, \
         ownCloud or Sciebo, enter the full WebDAV address.</p>\
         <label for=\"user\">Username</label>\
         <input id=\"user\" name=\"user\" value=\"{user}\" autocomplete=\"off\" \
         autocapitalize=\"none\" spellcheck=\"false\">\
         <label for=\"password\">App password</label>\
         <input id=\"password\" name=\"password\" type=\"password\" autocomplete=\"off\">\
         <p class=\"help\">Create one in the security settings of your file service. It stays \
         encrypted on this server.</p>\
         <label for=\"notes\">Notes for the AI (optional)</label>\
         <textarea id=\"notes\" name=\"notes\" rows=\"3\" \
         placeholder=\"Which folders hold what\">{notes}</textarea>\
         <button class=\"main\" name=\"action\" value=\"allow\">Connect</button>\
         <button name=\"action\" value=\"deny\" formnovalidate>Cancel</button>\
         </form>",
        app = escape(connecting.app),
        host = escape(connecting.app_host),
        address = typed(&connecting.login.address),
        user = typed(&connecting.login.user),
        notes = typed(&connecting.login.notes),
    );
    let status = match error {
        Some(_) => StatusCode::BAD_REQUEST,
        None => StatusCode::OK,
    };
    (status, Html(document("Connect your files", &body))).into_response()
}

pub fn problem(message: &str) -> Response {
    let body = format!("<h1>This link does not work</h1><p>{}</p>", escape(message));
    (
        StatusCode::BAD_REQUEST,
        Html(document("This link does not work", &body)),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_from_an_app_cannot_become_markup() {
        assert_eq!(
            escape("<script>\"a\" & 'b'</script>"),
            "&lt;script&gt;&quot;a&quot; &amp; &#39;b&#39;&lt;/script&gt;"
        );
    }
}
