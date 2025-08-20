mod base_client;
pub mod config;
pub mod identity;
pub mod nosql;

use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    // Base client errors
    #[error("Header not found: {0}")]
    HeaderNotFound(String),
    #[error("Header type mismatch: {0}")]
    HeaderTypeMismatch(String),
    #[error("Signer error: {0}")]
    Signing(#[from] openssl::error::ErrorStack),

    // Config errors
    #[error("File not found: {0}")]
    FileNotFound(String),
    #[error("Bad home dir")]
    BadHomeDir,
    #[error("Bad config file: {0}")]
    BadConfigFile(String),
    #[error("Config field not found: {0}")]
    ConfigFieldNotFound(String),

    // HTTP/Network errors
    #[error("HTTP request error: {0}")]
    Request(#[from] reqwest::Error),

    // Header formatting errors
    #[error("Invalid header value format: {0}")]
    InvalidHeaderValueFormat(String),
}

pub type Result<T> = std::result::Result<T, Error>;

// Re-export the unified error and result types for easy access
pub use Error as OciError;
pub use Result as OciResult;
