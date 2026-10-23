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
/// MCP versions that carry one JSON-RPC message per line on stdio.
const PROTOCOL_VERSIONS: &[&str] = &["2025-06-18", "2025-11-25"];
const SPEC_LIMIT: u64 = 256 * 1024;
const CONFIG_LIMIT: u64 = 1024 * 1024;
/// Message cap, each way.
const MAX_MESSAGE: u64 = 4 * 1024 * 1024;
const MAX_IN_FLIGHT: usize = 8;
const SPAWNS_PER_MINUTE: usize = 3;
const KILL_GRACE: Duration = Duration::from_secs(2);
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
mod policy;
mod runtime;
mod shim;
mod spec;
mod status;

pub use client::{apply_opencode_overlay, copilot_launch_args};
pub use runtime::{Broker, Log};
pub use shim::run_stdio;
pub use spec::{Detected, Spec, detect, drop_writable, load, spec_dir};
pub use status::{run_status, status_json};

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
