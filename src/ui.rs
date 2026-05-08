//! Centralized color and output helpers.
//!
//! All terminal styling goes through this module. Respects the `NO_COLOR`
//! environment variable (<https://no-color.org>) and per-stream TTY detection
//! so piped output is never polluted with escape sequences.
//!
//! - Use [`color()`] for stderr output (the default for `[cplt]` messages).
//! - Use [`stdout_color()`] for stdout output (`config show`, `doctor`, etc.).

use std::io::IsTerminal;
use std::sync::OnceLock;

// ── ANSI escape codes ──────────────────────────────────────────

pub const GREEN: &str = "\x1b[0;32m";
pub const RED: &str = "\x1b[0;31m";
pub const YELLOW: &str = "\x1b[0;33m";
pub const BLUE: &str = "\x1b[0;34m";
pub const BOLD: &str = "\x1b[1m";
pub const DIM: &str = "\x1b[2m";
pub const RESET: &str = "\x1b[0m";

/// Whether `NO_COLOR` is absent. Cached on first call.
fn no_color_absent() -> bool {
    static ABSENT: OnceLock<bool> = OnceLock::new();
    *ABSENT.get_or_init(|| std::env::var_os("NO_COLOR").is_none())
}

/// Whether color is enabled for **stderr**. Cached on first call.
///
/// Returns `false` when `NO_COLOR` is set (any value) or stderr is not a TTY.
pub fn use_color() -> bool {
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(|| no_color_absent() && std::io::stderr().is_terminal())
}

/// Whether color is enabled for **stdout**. Cached on first call.
///
/// Returns `false` when `NO_COLOR` is set (any value) or stdout is not a TTY.
pub fn use_stdout_color() -> bool {
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(|| no_color_absent() && std::io::stdout().is_terminal())
}

/// Return the escape code for **stderr** if color is enabled, empty string otherwise.
#[inline]
pub fn color(code: &str) -> &str {
    if use_color() { code } else { "" }
}

/// Return the escape code for **stdout** if color is enabled, empty string otherwise.
#[inline]
pub fn stdout_color(code: &str) -> &str {
    if use_stdout_color() { code } else { "" }
}

// ── Prefixed output helpers (always stderr) ────────────────────

pub fn info(msg: &str) {
    eprintln!("{}[cplt]{} {msg}", color(BLUE), color(RESET));
}

pub fn ok(msg: &str) {
    eprintln!("{}[cplt]{} {msg}", color(GREEN), color(RESET));
}

pub fn warn(msg: &str) {
    eprintln!("{}[cplt]{} {msg}", color(YELLOW), color(RESET));
}

pub fn error(msg: &str) {
    eprintln!("{}[cplt]{} {msg}", color(RED), color(RESET));
}
