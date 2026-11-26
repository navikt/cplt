//! Host-side MCP broker for local stdio servers (phase 1 of
//! `docs/design/mcp-host-broker.md`, #824). On Linux (#834) only under
//! Bubblewrap with the bus sockets masked; see `sandbox::mcp_broker_refusal`.
//!
//! nav-pilot writes one broker spec per server into
//! `$XDG_CONFIG_HOME/cplt/mcp/`: a standard MCP `server.json` plus the
//! `_meta["io.github.navikt/broker"]` extension. cplt validates each spec
//! against the design's invariants, and for each one it accepts it points the
//! client's entry at `cplt mcp-stdio <id>`. That shim runs in the sandbox and
//! pipes stdio over a per-session Unix socket to this broker, which spawns the
//! server on the host (env cleared, egress through its own proxy) and applies
//! the spec's tool policy to every JSON-RPC message.
//!
//! Authority: as for the worktree broker, the socket lives outside every
//! granted root and the sandbox may connect to that one path. There is no
//! secret: the client is the sandboxed agent, and it can only name a server
//! the user's spec already declares.

use std::time::Duration;

/// The `_meta` key of the broker extension.
pub const META_KEY: &str = "io.github.navikt/broker";
/// Extension versions this cplt reads, reported by `cplt mcp status --json`.
pub const SCHEMA_VERSIONS: &[u64] = &[1];
/// Version of the `cplt mcp status --json` document itself.
pub const STATUS_VERSION: u64 = 1;
/// The variable naming the socket to `cplt mcp-stdio`. Set in the client's
/// server entry, not the agent's environment.
pub const SOCKET_ENV: &str = "CPLT_MCP_SOCKET";
/// Default-off gate for remote MCP specs (`remotes[]`: gh-token and oauth);
/// active only when `"1"`. One gate for every remote mechanism (#909).
pub const REMOTE_GATE_ENV: &str = "CPLT_MCP_REMOTE";
/// The gate's old name, honoured for one release with a deprecation notice.
pub const REMOTE_GATE_ENV_OLD: &str = "CPLT_MCP_OAUTH_REMOTE";
/// MCP versions that carry one JSON-RPC message per line on stdio.
const PROTOCOL_VERSIONS: &[&str] = &["2025-06-18", "2025-11-25"];
const SPEC_LIMIT: u64 = 256 * 1024;
const CONFIG_LIMIT: u64 = 1024 * 1024;
/// Message cap, each way.
const MAX_MESSAGE: u64 = 4 * 1024 * 1024;
const MAX_IN_FLIGHT: usize = 8;
const SPAWNS_PER_MINUTE: usize = 3;
const KILL_GRACE: Duration = Duration::from_secs(2);
/// Per-call deadline (design 5.6): past it the client gets a timeout error
/// and the slot is freed.
const CALL_TIMEOUT: Duration = Duration::from_secs(if cfg!(test) { 2 } else { 120 });
const PROBE_TIMEOUT: Duration = Duration::from_secs(10);
/// JSON-RPC error code for a request the broker refuses.
const DENIED: i64 = -32001;
/// Notifications a client may send through.
const CLIENT_NOTIFICATIONS: &[&str] = &[
    "notifications/initialized",
    "notifications/cancelled",
    "notifications/roots/list_changed",
];

mod client;
mod credential;
mod egress;
mod graphql;
mod open_url;
mod policy;
pub(crate) mod remote;
mod retry;
mod runtime;
mod shim;
mod spec;
mod status;

pub use crate::sandbox::OAUTH_CALLBACK_PORT;
pub use client::{apply_opencode_overlay, copilot_launch_args};
pub use open_url::{
    HOST_OPENER as OPEN_URL_HOST_OPENER, SHIM_NAMES as OPEN_URL_SHIMS, opener_config_writable,
    run as run_open_url, shim_script as open_url_shim,
    shim_script_unrunnable as open_url_shim_unrunnable,
};
pub use runtime::{Broker, Log, bwrap_disables_userns};
pub use shim::run_stdio;
pub use spec::{
    Detected, Spec, detect, drop_writable, github_spec, launch_github, load, remote_gate_enabled,
    spec_dir, unusable_line,
};
pub use status::{GithubMcp, run_status, status_json};

/// The XDG base dir `var` for `home`. The host's `$var` describes the host's
/// HOME, so it applies only when `home` is that HOME (or HOME is unset); a
/// broker handed another HOME derives every XDG dir from it instead (#1273).
pub(crate) fn xdg_dir(var: &str, home: &std::path::Path, default: &str) -> std::path::PathBuf {
    match std::env::var_os("HOME") {
        Some(h) if std::path::Path::new(&h) != home => home.join(default),
        _ => crate::opencode_v2::xdg_base(var, home, default),
    }
}

#[cfg(test)]
mod xdg_tests {
    use std::path::Path;

    #[test]
    fn xdg_dir_follows_an_explicit_home() {
        let got = temp_env::with_vars(
            [
                ("HOME", Some("/host")),
                ("XDG_CONFIG_HOME", Some("/host/xdg")),
            ],
            || {
                (
                    super::xdg_dir("XDG_CONFIG_HOME", Path::new("/other"), ".config"),
                    super::xdg_dir("XDG_CONFIG_HOME", Path::new("/host"), ".config"),
                )
            },
        );
        assert_eq!(got.0, Path::new("/other/.config"));
        assert_eq!(got.1, Path::new("/host/xdg"));
    }
}

#[cfg(test)]
pub(crate) mod test_util {
    use super::META_KEY;
    use super::spec::{Spec, validate};

    use std::path::PathBuf;

    use serde_json::{Value, json};

    pub(crate) fn spec_json(ext: Value) -> String {
        json!({"name": "io.github.nais/nais-mcp", "version": "7.0.1", "_meta": {META_KEY: ext}})
            .to_string()
    }

    pub(crate) fn base() -> Value {
        json!({
            "v": 1,
            "credential": "nais-keychain",
            "command": ["nais", "alpha", "mcp", "serve"],
            "egressHosts": ["console.nav.cloud.nais.io"],
            "tools": {"allow": ["get_nais_context", "execute_graphql"], "classes": {}},
            "argChecks": {"execute_graphql": "graphql-read-only"},
            "login": {"run": "nais login -n", "status": "nais auth print-access-token"}
        })
    }

    pub(crate) const FILE: &str = "io.github.nais__nais-mcp.json";

    pub(crate) fn check(ext: Value) -> Result<Spec, String> {
        validate(&spec_json(ext), FILE, |n| {
            Some(PathBuf::from("/opt/homebrew/bin").join(n))
        })
    }

    pub(crate) fn with(mut v: Value, ptr: &str, x: Value) -> Value {
        *v.pointer_mut(ptr).unwrap() = x;
        v
    }
}
