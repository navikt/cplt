//! cplt — sandbox wrapper for AI coding agents.
//!
//! Runs AI agents (GitHub Copilot, OpenCode, Gemini CLI) inside a
//! deny-by-default OS sandbox (macOS Seatbelt, Linux Landlock+seccomp),
//! with a filtering CONNECT proxy for network control.

pub mod agent;
pub mod audit;
pub mod check;
pub mod config;
pub mod detect;
pub mod discover;
pub mod gh_proxy;
pub mod git;
pub mod gradle_init;
pub mod init;
pub mod proxy;
pub mod repo_config;
pub mod sandbox;
pub mod scratch;
pub mod settings;
pub mod subscriptions;
pub mod trust;
pub mod ui;
pub mod update;

/// Safety check: reject overly broad project roots.
///
/// Prevents accidental sandbox misconfiguration by blocking roots that
/// would grant access to the entire system, user home, or sensitive
/// system directories. Platform-specific entries are gated with `cfg`.
pub fn is_unsafe_root(path: &std::path::Path, home: &std::path::Path) -> bool {
    let p = path.to_string_lossy();

    // Common: filesystem root, home dir, and platform-shared temp/var roots
    if p == "/" || p == "/tmp" || p == "/var" || path == home {
        return true;
    }

    // macOS-specific unsafe roots
    #[cfg(target_os = "macos")]
    {
        if p == "/Users"
            || p == "/private/tmp"
            || p == "/private/var"
            || p == "/Applications"
            || p == "/System"
        {
            return true;
        }
    }

    // Linux-specific unsafe roots
    #[cfg(target_os = "linux")]
    {
        if p == "/home"
            || p == "/var/tmp"
            || p == "/proc"
            || p == "/sys"
            || p == "/boot"
            || p == "/usr"
            || p == "/etc"
        {
            return true;
        }
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn rejects_common_unsafe_roots() {
        let home = Path::new("/Users/test");
        assert!(is_unsafe_root(Path::new("/"), home));
        assert!(is_unsafe_root(Path::new("/tmp"), home));
        assert!(is_unsafe_root(Path::new("/var"), home));
        assert!(is_unsafe_root(home, home));
    }

    #[test]
    fn accepts_normal_project_dirs() {
        let home = Path::new("/Users/test");
        assert!(!is_unsafe_root(
            Path::new("/Users/test/projects/myapp"),
            home
        ));
        assert!(!is_unsafe_root(Path::new("/opt/work"), home));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn rejects_macos_unsafe_roots() {
        let home = Path::new("/Users/test");
        assert!(is_unsafe_root(Path::new("/Users"), home));
        assert!(is_unsafe_root(Path::new("/private/tmp"), home));
        assert!(is_unsafe_root(Path::new("/Applications"), home));
        assert!(is_unsafe_root(Path::new("/System"), home));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn rejects_linux_unsafe_roots() {
        let home = Path::new("/home/test");
        assert!(is_unsafe_root(Path::new("/home"), home));
        assert!(is_unsafe_root(Path::new("/proc"), home));
        assert!(is_unsafe_root(Path::new("/sys"), home));
        assert!(is_unsafe_root(Path::new("/boot"), home));
        assert!(is_unsafe_root(Path::new("/usr"), home));
        assert!(is_unsafe_root(Path::new("/etc"), home));
    }
}
