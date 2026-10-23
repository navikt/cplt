//! `cplt mcp status [--json]`.

use std::path::Path;
use std::process::ExitCode;

use serde_json::{Value, json};

use super::credential::credential_ok;
use super::spec::{Detected, spec_dir};
use super::{SCHEMA_VERSIONS, STATUS_VERSION};

/// `cplt mcp status --json`. `supported`: this host can run the broker
/// (on Linux, only under Bubblewrap with the bus masked, #834).
pub fn status_json(found: &Detected, enabled: bool, probe: bool, supported: bool) -> Value {
    let mut servers: Vec<Value> = found
        .specs
        .iter()
        .map(|s| {
            json!({
                "id": s.id,
                "state": if enabled { "brokered" } else { "off" },
                "transport": "unix",
                "credential": s.credential,
                "credential_ok": if probe { credential_ok(s) } else { None },
                "tools_allowed": s.allow.len(),
                "clients": super::client::WIRED_CLIENTS,
            })
        })
        .collect();
    servers.extend(
        found
            .disabled
            .iter()
            .map(|id| json!({"id": id, "state": "off"})),
    );
    json!({
        "version": STATUS_VERSION,
        "schema": SCHEMA_VERSIONS,
        "platform_supported": supported,
        "servers": servers,
        "rejected": found.rejected,
    })
}

/// `cplt mcp status [--json]`. Reads the specs as a launch from the current
/// directory would, without starting anything.
pub fn run_status(
    as_json: bool,
    home: &Path,
    found: &Detected,
    enabled: bool,
    supported: bool,
) -> ExitCode {
    let status = status_json(found, enabled && supported, true, supported);
    if as_json {
        println!("{status}");
        return ExitCode::SUCCESS;
    }
    println!("MCP broker specs in {}", spec_dir(home).display());
    for s in status["servers"].as_array().into_iter().flatten() {
        println!(
            "  {}  {}  credential_ok: {}",
            s["id"].as_str().unwrap_or("").escape_debug(),
            s["state"].as_str().unwrap_or(""),
            s["credential_ok"]
        );
    }
    for r in &found.rejected {
        println!("  {}", r.line());
    }
    ExitCode::SUCCESS
}
