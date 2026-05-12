//! Centralized color and output helpers.
//!
//! All terminal styling goes through this module. Color decision respects
//! (in priority order):
//! 1. `FORCE_COLOR` env var — forces color even when piped (CI systems)
//! 2. `NO_COLOR` env var — disables color (<https://no-color.org>)
//! 3. `TERM=dumb` — disables color (legacy terminals)
//! 4. TTY detection — color only when writing to an interactive terminal
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

/// Whether `FORCE_COLOR` is set (any value). Overrides all other checks.
/// Presence-only, matching the `NO_COLOR` convention.
fn force_color_set() -> bool {
    static FORCED: OnceLock<bool> = OnceLock::new();
    *FORCED.get_or_init(|| std::env::var_os("FORCE_COLOR").is_some())
}

/// Whether color should be suppressed by environment variables.
/// True when NO_COLOR is set (any value) or TERM=dumb.
fn env_suppresses_color() -> bool {
    static SUPPRESSED: OnceLock<bool> = OnceLock::new();
    *SUPPRESSED.get_or_init(|| {
        if std::env::var_os("NO_COLOR").is_some() {
            return true;
        }
        std::env::var("TERM").is_ok_and(|t| t == "dumb")
    })
}

/// Whether color is enabled for **stderr**. Cached on first call.
///
/// Priority: FORCE_COLOR > NO_COLOR/TERM=dumb > TTY detection.
pub fn use_color() -> bool {
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(|| {
        if force_color_set() {
            return true;
        }
        if env_suppresses_color() {
            return false;
        }
        std::io::stderr().is_terminal()
    })
}

/// Whether color is enabled for **stdout**. Cached on first call.
///
/// Priority: FORCE_COLOR > NO_COLOR/TERM=dumb > TTY detection.
pub fn use_stdout_color() -> bool {
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(|| {
        if force_color_set() {
            return true;
        }
        if env_suppresses_color() {
            return false;
        }
        std::io::stdout().is_terminal()
    })
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
