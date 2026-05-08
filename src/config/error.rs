//! Typed configuration errors ([`ConfigError`]).

use std::path::PathBuf;

/// Structured error type for configuration operations.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ConfigError {
    #[error("Cannot read config file {path}: {source}")]
    FileRead {
        path: PathBuf,
        source: std::io::Error,
    },

    #[error("cannot read {path}: {source}")]
    Read {
        path: PathBuf,
        source: std::io::Error,
    },

    #[error("cannot write {path}: {source}")]
    Write {
        path: PathBuf,
        source: std::io::Error,
    },

    #[error("Invalid TOML in {path}: {source}")]
    TomlParse {
        path: String,
        source: toml::de::Error,
    },

    #[error("Invalid TOML: {0}")]
    Toml(toml::de::Error),

    #[error("invalid TOML in {path}: {source}")]
    TomlEditParse {
        path: String,
        source: toml_edit::TomlError,
    },

    #[error("cannot determine config path ($HOME not set)")]
    NoHome,

    #[error("cannot create config directory: {0}")]
    CreateDir(std::io::Error),

    #[error("modification produced invalid TOML (this is a bug)")]
    InvalidOutput,

    #[error("{0}")]
    Validation(String),
}

impl From<String> for ConfigError {
    fn from(s: String) -> Self {
        ConfigError::Validation(s)
    }
}
