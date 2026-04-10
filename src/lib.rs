pub mod config;
pub mod discover;
pub mod proxy;
pub mod sandbox;
pub mod scratch;

/// Safety check: reject overly broad project roots.
pub fn is_unsafe_root(path: &std::path::Path, home: &std::path::Path) -> bool {
    let p = path.to_string_lossy();
    p == "/"
        || p == "/Users"
        || p == "/tmp"
        || p == "/private/tmp"
        || p == "/var"
        || p == "/private/var"
        || p == "/Applications"
        || p == "/System"
        || path == home
}
