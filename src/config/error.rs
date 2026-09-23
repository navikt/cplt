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

/// Whether a failed config read means "there is no file" (#385).
///
/// `NotFound`, and `NotADirectory` — a path through a regular file, such as
/// `CPLT_CONFIG=/dev/null/nonexistent`, cannot name a file either. Every other
/// error (EACCES, EIO, a symlink loop, ...) means a file may be there with
/// restrictions in it, so callers must fail rather than fall back to defaults.
#[must_use]
pub fn is_absent(e: &std::io::Error) -> bool {
    matches!(
        e.kind(),
        std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory
    )
}
