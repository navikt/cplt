//! Typed configuration errors ([`ConfigError`]).

use std::path::PathBuf;

/// Structured error type for configuration operations.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ConfigError {
    #[error("Cannot read config file {path}: {source}{}", sandbox_hint(.source))]
    FileRead {
        path: PathBuf,
        source: std::io::Error,
    },

    #[error("cannot read {path}: {source}{}", sandbox_hint(.source))]
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

/// Why a config read fails inside a cplt session. The sandbox denies the
/// config on purpose (Seatbelt EPERM, Landlock EACCES), so `--print-profile`,
/// `doctor` and `config show/get/validate` stop there. Say so, rather than
/// leave the user suspecting the file.
pub const IN_SANDBOX_HINT: &str = "you are inside a cplt sandbox; the config is deliberately \
     unreadable here — run this outside the sandbox";

/// `IN_SANDBOX_HINT` as a suffix, when it applies to `e`.
fn sandbox_hint(e: &std::io::Error) -> String {
    if e.kind() == std::io::ErrorKind::PermissionDenied
        && std::env::var_os("__CPLT_WRAPPED").is_some()
    {
        format!(" ({IN_SANDBOX_HINT})")
    } else {
        String::new()
    }
}

/// Whether a failed read of `path` means "there is no file" (#385).
///
/// `NotFound`, and `NotADirectory` only when one of `path`'s ancestors exists
/// and is not a directory (`CPLT_CONFIG=/dev/null/nonexistent`, whose local
/// layer is `/dev/null/local/<hash>.toml`): nothing can live under it. A
/// trailing slash on a real file (`config.toml/`) is ENOTDIR too, but every
/// ancestor is a directory and the file is right there, so that is an error.
/// Every other error (EACCES, EIO, a symlink loop, ...) means a file may be
/// there with restrictions in it, so callers must fail rather than fall back
/// to defaults.
#[must_use]
pub fn is_absent(e: &std::io::Error, path: &std::path::Path) -> bool {
    match e.kind() {
        std::io::ErrorKind::NotFound => true,
        // `ancestors()` drops a trailing slash, so `skip(1)` skips the file.
        std::io::ErrorKind::NotADirectory => path
            .ancestors()
            .skip(1)
            .any(|a| std::fs::metadata(a).is_ok_and(|m| !m.is_dir())),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::is_absent;
    use std::path::{Path, PathBuf};

    fn classify(path: &Path) -> bool {
        let e = std::fs::read_to_string(path).expect_err("must not be readable");
        is_absent(&e, path)
    }

    #[test]
    fn only_paths_that_cannot_name_a_file_are_absent() {
        let dir = tempfile::tempdir().expect("tempdir");
        let file = dir.path().join("config.toml");
        std::fs::write(&file, "").expect("write");

        assert!(classify(&dir.path().join("missing.toml")));
        assert!(classify(Path::new("/dev/null/nonexistent")));
        assert!(classify(Path::new("/dev/null/local/abc.toml")));
        assert!(
            classify(&file.join("x")),
            "a path through a file names nothing"
        );
        // `config.toml/` is ENOTDIR as well, but it names the real file.
        let slashed = PathBuf::from(format!("{}/", file.display()));
        assert!(
            !classify(&slashed),
            "a trailing slash must not hide the file"
        );
    }
}
