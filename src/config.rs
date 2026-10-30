use std::collections::HashMap;
use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct Settings {
    pub public_host: String,
    pub behind_proxy: bool,
    pub data_dir: PathBuf,
    pub host: String,
    pub port: u16,
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("PORT must be a number between 1 and 65535, not {0:?}")]
    Port(String),
}

impl Settings {
    pub fn from_env() -> Result<Self, ConfigError> {
        Self::from_map(&std::env::vars().collect())
    }

    pub fn from_map(env: &HashMap<String, String>) -> Result<Self, ConfigError> {
        let value =
            |key: &str, default: &str| env.get(key).cloned().unwrap_or_else(|| default.to_owned());
        let port = value("PORT", "8000");
        Ok(Self {
            public_host: value("PUBLIC_HOST", ""),
            behind_proxy: value("BEHIND_PROXY", "false") == "true",
            data_dir: value("DATA_DIR", "data").into(),
            host: value("HOST", "0.0.0.0"),
            port: port.parse().map_err(|_| ConfigError::Port(port.clone()))?,
        })
    }

    /// The address LLM clients reach this server under.
    pub fn base_url(&self) -> String {
        if self.public_host.is_empty() {
            format!("http://localhost:{}", self.port)
        } else {
            format!("https://{}", self.public_host)
        }
    }
}

pub fn user_agent() -> String {
    format!(
        "{}/{} (+{})",
        env!("CARGO_PKG_NAME"),
        env!("CARGO_PKG_VERSION"),
        env!("CARGO_PKG_REPOSITORY")
    )
}
