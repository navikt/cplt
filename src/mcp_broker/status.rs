//! `cplt mcp status [--json]`.

use std::path::Path;
use std::process::ExitCode;

use serde_json::{Value, json};

use super::credential::credential_ok;
use super::spec::{Detected, spec_dir};
use super::{SCHEMA_VERSIONS, STATUS_VERSION};

/// `cplt mcp status --json`. `supported`: this host can run the broker
/// (on Linux, only under Bubblewrap with the bus masked, #834).
/// `off_reason`: why the broker would be off for this launch (#838).
pub fn status_json(
    found: &Detected,
    enabled: bool,
    probe: bool,
    supported: bool,
    off_reason: Option<&str>,
) -> Value {
    let mut servers: Vec<Value> = found
        .specs
        .iter()
        .map(|s| {
            let (ok, note) = if probe {
                credential_ok(s)
            } else {
                (None, None)
            };
            json!({
                "id": s.id,
                "state": if enabled { "brokered" } else { "off" },
                "transport": "unix",
                "credential": s.credential,
                "credential_ok": ok,
                "credential_note": note,
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
        "off_reason": off_reason,
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
    refusal: Option<&str>,
) -> ExitCode {
    let supported = refusal.is_none();
    let status = status_json(found, enabled && supported, true, supported, refusal);
    if as_json {
        println!("{status}");
        return ExitCode::SUCCESS;
    }
    println!("MCP broker specs in {}", spec_dir(home).display());
    if let Some(why) = refusal {
        println!("  broker off for this launch: {why}");
    }
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
