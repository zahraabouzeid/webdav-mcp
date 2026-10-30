#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct WebdavError(String);

impl WebdavError {
    pub fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

pub type Result<T> = std::result::Result<T, WebdavError>;

impl From<WebdavError> for String {
    fn from(error: WebdavError) -> Self {
        error.0
    }
}
