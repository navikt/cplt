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
/// `project`: the project the writable-tree checks ran against, `None`
/// outside one (they then ran against an empty project).
/// `clients`: the clients this launch would point at the broker.
/// `remote_off`: why a gh-token remote would not serve OpenCode (#909).
#[allow(clippy::too_many_arguments)] // one per status input
pub fn status_json(
    found: &Detected,
    project: Option<&Path>,
    enabled: bool,
    probe: bool,
    supported: bool,
    off_reason: Option<&str>,
    clients: &[&str],
    remote_off: Option<&str>,
) -> Value {
    // Remote specs are served on the proxy port, so the stdio broker's
    // platform refusal does not reach them.
    let remote_on = enabled;
    let fallback = remote_off.is_some_and(|r| r.starts_with(super::spec::FALLBACK_PREFIX));
    let enabled = enabled && supported;
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
                "clients": if enabled { clients } else { &[] },
            })
        })
        .collect();
    // A gh-token remote (#909) reaches OpenCode v2 only, for now.
    let remote_clients: Vec<&str> = clients
        .iter()
        .copied()
        .filter(|c| remote_on && *c == "opencode")
        .collect();
    servers.extend(found.remotes.iter().map(|s| {
        let (ok, note) = if probe {
            credential_ok(s)
        } else {
            (None, None)
        };
        json!({
            "id": s.id,
            "state": match (remote_clients.is_empty(), remote_off) {
                _ if fallback => "inactive",
                (true, _) => "off",
                (false, Some(_)) => "inactive",
                (false, None) => "brokered",
            },
            "reason": remote_off,
            "transport": "http",
            "mechanism": s.credential.name,
            "credential": s.credential,
            "credential_ok": ok,
            "credential_note": note,
            "egress_hosts": s.egress_hosts,
            "tools_allowed": s.allow.len(),
            "clients": remote_clients,
        })
    }));
    // A gh-token spec that cannot serve: the built-in endpoint does (#1115).
    servers.extend(found.remote_refused.iter().map(|r| {
        json!({
            "id": r.file,
            "state": "inactive",
            "reason": remote_off.unwrap_or(&r.reason),
            "transport": "http",
            "credential": null,
            "credential_ok": null,
            "credential_note": null,
            "tools_allowed": null,
            "clients": [],
        })
    }));
    if fallback {
        let gh: Vec<&str> = clients
            .iter()
            .copied()
            .filter(|c| *c == "opencode")
            .collect();
        servers.push(json!({
            "id": "github-mcp",
            "state": "built-in",
            "reason": "served by the built-in endpoint without the spec's restrictions \
                       (tools.allow is NOT applied); read-only and lockdown are still forced",
            "transport": "http",
            "credential": null,
            "credential_ok": null,
            "credential_note": null,
            "tools_allowed": null,
            "clients": gh,
        }));
    }
    servers.extend(found.disabled.iter().map(|id| {
        // Skipped before loading: nothing else is known about it. A disabled
        // gh-token spec is inactive, not off: the built-in endpoint serves.
        let gh_off = found.remote_disabled.as_ref().filter(|(g, _, _)| g == id);
        json!({
            "id": id,
            "state": if gh_off.is_some() { "inactive" } else { "off" },
            "reason": gh_off.map(|(_, why, _)| {
                format!("disabled by {why}; tools.allow not applied, built-in endpoint serves GitHub MCP")
            }),
            "transport": null,
            "credential": null,
            "credential_ok": null,
            "credential_note": null,
            "tools_allowed": null,
            "clients": [],
        })
    }));
    json!({
        "version": STATUS_VERSION,
        "schema": SCHEMA_VERSIONS,
        "platform_supported": supported,
        "off_reason": off_reason,
        "project": project.map(|p| p.display().to_string()),
        "servers": servers,
        "rejected": found.rejected,
    })
}

/// `cplt mcp status [--json]`. Reads the specs as a launch from the current
/// directory would, without starting anything; outside a project, as a
/// launch from an empty one would.
#[allow(clippy::too_many_arguments)] // one per status input
pub fn run_status(
    as_json: bool,
    home: &Path,
    project: Option<&Path>,
    found: &Detected,
    enabled: bool,
    refusal: Option<&str>,
    clients: &[&str],
    remote_off: Option<&str>,
) -> ExitCode {
    let supported = refusal.is_none();
    let status = status_json(
        found, project, enabled, true, supported, refusal, clients, remote_off,
    );
    if as_json {
        println!("{status}");
        return ExitCode::SUCCESS;
    }
    println!("MCP broker specs in {}", spec_dir(home).display());
    if let Some(why) = refusal {
        println!("  broker off for this launch: {why}");
    }
    for s in status["servers"].as_array().into_iter().flatten() {
        let state = s["state"].as_str().unwrap_or("");
        // Only gh-token rows (#909, gated) carry a reason.
        let state = match s["reason"].as_str() {
            Some(why) => format!("{state}: {}", why.escape_debug()),
            None => state.to_string(),
        };
        println!(
            "  {}  {state}  credential_ok: {}",
            s["id"].as_str().unwrap_or("").escape_debug(),
            s["credential_ok"]
        );
    }
    for r in &found.rejected {
        println!("  {}", r.line());
    }
    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refused_gh_spec_row_is_inactive_with_reason() {
        let r = crate::mcp_broker::spec::Rejected {
            file: "/x/gh.json".into(),
            reason: "/x is writable in the sandbox".into(),
            fix: "f".into(),
        };
        let found = Detected {
            remote_refused: Some(r.clone()),
            rejected: vec![r],
            ..Default::default()
        };
        let v = status_json(
            &found,
            None,
            true,
            false,
            true,
            None,
            &["opencode"],
            Some("off: why"),
        );
        let row = &v["servers"][0];
        assert_eq!(row["id"], "/x/gh.json");
        assert_eq!(row["state"], "inactive");
        assert_eq!(row["reason"], "off: why");
    }

    /// #1115: a fallback shows the spec inactive and a GitHub MCP row
    /// served by the built-in endpoint without the spec's restrictions.
    #[test]
    fn fallback_shows_builtin_github_row() {
        let dir = tempfile::tempdir().unwrap();
        let root = crate::mcp_broker::spec::tests::gh_root();
        std::fs::write(
            dir.path().join(crate::mcp_broker::test_util::FILE),
            root.to_string(),
        )
        .unwrap();
        let mut found =
            crate::mcp_broker::spec::load_with_gate(dir.path(), &[], &[], |_| None, true);
        found.broker_off();
        let why = crate::mcp_broker::github_spec(&found, dir.path(), |_| None).unwrap_err();
        let v = status_json(
            &found,
            None,
            false,
            false,
            true,
            None,
            &["opencode"],
            Some(&why),
        );
        let rows = v["servers"].as_array().unwrap();
        let gh = rows.iter().find(|r| r["id"] == "github-mcp").unwrap();
        assert_eq!(gh["state"], "built-in");
        assert!(gh["reason"].as_str().unwrap().contains("NOT applied"));
        assert_eq!(gh["clients"], json!(["opencode"]));
        let spec = rows.iter().find(|r| r["id"] != "github-mcp").unwrap();
        assert_eq!(spec["state"], "inactive");
        assert!(
            spec["reason"]
                .as_str()
                .unwrap()
                .contains("sandbox.mcp_broker = false")
        );
        // --no-github-mcp-proxy path: same row, other reason.
        let mut found2 =
            crate::mcp_broker::spec::load_with_gate(dir.path(), &[], &[], |_| None, true);
        found2.disable_remotes();
        let why2 = crate::mcp_broker::github_spec(&found2, dir.path(), |_| None).unwrap_err();
        let v2 = status_json(
            &found2,
            None,
            false,
            false,
            true,
            None,
            &["opencode"],
            Some(&why2),
        );
        let spec2 = v2["servers"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["id"] != "github-mcp")
            .unwrap();
        assert_eq!(spec2["state"], "inactive");
        assert!(
            spec2["reason"]
                .as_str()
                .unwrap()
                .contains("GitHub MCP proxy is off")
        );
        // No fallback, no row.
        let v = status_json(
            &found,
            None,
            false,
            false,
            true,
            None,
            &["opencode"],
            Some("x"),
        );
        assert!(
            v["servers"]
                .as_array()
                .unwrap()
                .iter()
                .all(|r| r["id"] != "github-mcp")
        );
        // A spec still loaded but unusable (ambiguous) is inactive.
        let mut two = crate::mcp_broker::spec::load_with_gate(dir.path(), &[], &[], |_| None, true);
        two.remotes.push(two.remotes[0].clone());
        let why = crate::mcp_broker::github_spec(&two, dir.path(), |_| None).unwrap_err();
        let v = status_json(
            &two,
            None,
            true,
            false,
            true,
            None,
            &["opencode"],
            Some(&why),
        );
        assert_eq!(v["servers"][0]["state"], "inactive");
    }

    #[test]
    fn disabled_rows_carry_every_field() {
        let found = Detected {
            disabled: vec!["io.example/x".into()],
            ..Default::default()
        };
        let v = status_json(&found, None, true, false, true, None, &["copilot"], None);
        let row = &v["servers"][0];
        for k in [
            "id",
            "state",
            "transport",
            "credential",
            "credential_ok",
            "credential_note",
            "tools_allowed",
            "clients",
        ] {
            assert!(row.get(k).is_some(), "{k} missing: {row}");
        }
        assert_eq!(row["state"], "off");
        assert_eq!(row["clients"], json!([]));
    }

    /// #909: a gh-token remote is listed with its mechanism and egress
    /// host, served to OpenCode only, and the stdio refusal does not hide it.
    #[test]
    fn gh_token_remote_row() {
        let dir = tempfile::tempdir().unwrap();
        let root = crate::mcp_broker::spec::tests::gh_root();
        std::fs::write(
            dir.path().join(crate::mcp_broker::test_util::FILE),
            root.to_string(),
        )
        .unwrap();
        let found = crate::mcp_broker::spec::load_with_gate(dir.path(), &[], &[], |_| None, true);
        let v = status_json(
            &found,
            None,
            true,
            false,
            false,
            Some("no"),
            &["copilot", "opencode"],
            None,
        );
        let row = &v["servers"][0];
        assert_eq!(row["mechanism"], "gh-token");
        assert_eq!(row["state"], "brokered");
        assert_eq!(row["transport"], "http");
        assert_eq!(row["egress_hosts"], json!(["api.githubcopilot.com"]));
        assert_eq!(row["clients"], json!(["opencode"]));
        let v = status_json(
            &found,
            None,
            true,
            false,
            true,
            None,
            &["opencode"],
            Some("deny.env names GH_TOKEN"),
        );
        assert_eq!(v["servers"][0]["state"], "inactive");
        assert_eq!(v["servers"][0]["reason"], "deny.env names GH_TOKEN");
        let v = status_json(&found, None, true, false, true, None, &["copilot"], None);
        assert_eq!(v["servers"][0]["state"], "off");
    }
}
