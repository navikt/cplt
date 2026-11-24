//! `cplt mcp status [--json]`.

use std::path::Path;
use std::process::ExitCode;

use serde_json::{Value, json};

use super::credential::credential_ok;
use super::spec::{Detected, spec_dir};
use super::{SCHEMA_VERSIONS, STATUS_VERSION};

/// How a launch would serve GitHub MCP (#909, #1115).
#[derive(Default)]
pub struct GithubMcp<'a> {
    /// `"built-in"`, `"broker"` (a gh-token spec), or `None`: not served.
    pub served_by: Option<&'static str>,
    /// Why a gh-token spec exists but cannot serve.
    pub spec_unusable: Option<&'a str>,
    /// Why GitHub MCP would not be served at all.
    pub inactive: Option<&'a str>,
}

/// `cplt mcp status --json`. `supported`: this host can run the broker
/// (on Linux, only under Bubblewrap with the bus masked, #834).
/// `off_reason`: why the broker would be off for this launch (#838).
/// `project`: the project the writable-tree checks ran against, `None`
/// outside one (they then ran against an empty project).
/// `clients`: the clients this launch would point at the broker.
/// `github`: how a launch would serve GitHub MCP (#909, #1115).
#[allow(clippy::too_many_arguments)] // one per status input
pub fn status_json(
    found: &Detected,
    project: Option<&Path>,
    enabled: bool,
    probe: bool,
    supported: bool,
    off_reason: Option<&str>,
    clients: &[&str],
    github: &GithubMcp,
) -> Value {
    // Why a gh-token remote would not serve OpenCode (#909).
    let remote_off = github.spec_unusable.or(github.inactive);
    // GitHub MCP reaches OpenCode v2 only.
    let served_by = github.served_by.filter(|_| clients.contains(&"opencode"));
    // Remote specs are served on the proxy port, so the stdio broker's
    // platform refusal does not reach them.
    let remote_on = enabled;
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
    // A refused gh-token spec cannot serve (#909): show why.
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
    servers.extend(found.disabled.iter().map(|id| {
        // Skipped before loading: nothing else is known about it. A disabled
        // gh-token spec is inactive, with its reason (#1115).
        let gh_off = found.remote_disabled.as_ref().filter(|(g, _, _)| g == id);
        json!({
            "id": id,
            "state": if gh_off.is_some() { "inactive" } else { "off" },
            "reason": gh_off.map(|(_, why, _)| why),
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
        // Additive (#1115): who serves GitHub MCP, and whether a gh-token
        // spec's restrictions apply. `reason`: why it is not served, or why
        // the spec is not applied.
        "github_mcp": {
            "served_by": served_by,
            "spec_restrictions_applied": served_by == Some("broker"),
            "reason": if served_by.is_some() { github.spec_unusable } else { github.inactive.or(github.spec_unusable) },
        },
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
    github: &GithubMcp,
) -> ExitCode {
    let supported = refusal.is_none();
    let status = status_json(
        found, project, enabled, true, supported, refusal, clients, github,
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
        println!(
            "  {}  {}  credential_ok: {}",
            s["id"].as_str().unwrap_or("").escape_debug(),
            s["state"].as_str().unwrap_or(""),
            s["credential_ok"]
        );
        if let Some(why) = s["reason"].as_str() {
            println!("    {}", why.escape_debug());
        }
    }
    if status["github_mcp"]["served_by"] == "built-in" && github.spec_unusable.is_some() {
        println!(
            "  GitHub MCP: built-in endpoint, without the gh-token spec's restrictions \
             (tools.allow is NOT applied; read-only and lockdown are still forced)"
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

    fn off(why: &str) -> GithubMcp<'_> {
        GithubMcp {
            inactive: Some(why),
            ..Default::default()
        }
    }

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
            &off("off: why"),
        );
        let row = &v["servers"][0];
        assert_eq!(row["id"], "/x/gh.json");
        assert_eq!(row["state"], "inactive");
        assert_eq!(row["reason"], "off: why");
    }

    /// #1115: an unusable gh-token spec. The fallback is claimed only when
    /// the built-in endpoint serves; otherwise the spec row says why it is
    /// unused and `github_mcp.reason` why GitHub MCP is not served. No
    /// synthetic `servers[]` row either way.
    #[test]
    fn unusable_spec_claims_fallback_only_when_served() {
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
        assert!(!why.contains("built-in") && why.contains("sandbox.mcp_broker = false"));
        let status = |served_by, inactive, clients: &[&str]| {
            let g = GithubMcp {
                served_by,
                spec_unusable: Some(&why),
                inactive,
            };
            status_json(&found, None, false, false, true, None, clients, &g)
        };
        // Served by the built-in endpoint: the fallback.
        let v = status(Some("built-in"), None, &["opencode"]);
        assert_eq!(v["version"], 1);
        assert_eq!(v["servers"].as_array().unwrap().len(), 1);
        let row = &v["servers"][0];
        assert_eq!(row["state"], "inactive");
        assert_eq!(row["reason"], "sandbox.mcp_broker = false");
        let g = &v["github_mcp"];
        assert_eq!(g["served_by"], "built-in");
        assert_eq!(g["spec_restrictions_applied"], false);
        assert_eq!(g["reason"], why.as_str());
        // Not served: no entry, deny.env GH_TOKEN, proxy off, no gh login.
        for reason in [
            "no GitHub MCP entry in the OpenCode config",
            "deny.env names GH_TOKEN",
            "cplt's proxy is off",
        ] {
            let v = status(None, Some(reason), &["opencode"]);
            assert_eq!(v["servers"].as_array().unwrap().len(), 1);
            assert_eq!(v["servers"][0]["state"], "inactive");
            assert_eq!(v["servers"][0]["reason"], "sandbox.mcp_broker = false");
            assert_eq!(v["github_mcp"]["served_by"], Value::Null);
            assert_eq!(v["github_mcp"]["reason"], reason);
        }
        // --agent copilot: no OpenCode client, so nothing serves GitHub MCP.
        let v = status(Some("built-in"), None, &["copilot"]);
        assert_eq!(v["github_mcp"]["served_by"], Value::Null);
        // A usable spec: brokered, restrictions applied.
        let ok = crate::mcp_broker::spec::load_with_gate(dir.path(), &[], &[], |_| None, true);
        let g = GithubMcp {
            served_by: Some("broker"),
            ..Default::default()
        };
        let v = status_json(&ok, None, true, false, true, None, &["opencode"], &g);
        assert_eq!(v["github_mcp"]["spec_restrictions_applied"], true);
        assert_eq!(v["github_mcp"]["reason"], Value::Null);
    }

    #[test]
    fn disabled_rows_carry_every_field() {
        let found = Detected {
            disabled: vec!["io.example/x".into()],
            ..Default::default()
        };
        let v = status_json(
            &found,
            None,
            true,
            false,
            true,
            None,
            &["copilot"],
            &GithubMcp::default(),
        );
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
            &GithubMcp::default(),
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
            &off("deny.env names GH_TOKEN"),
        );
        assert_eq!(v["servers"][0]["state"], "inactive");
        assert_eq!(v["servers"][0]["reason"], "deny.env names GH_TOKEN");
        let v = status_json(
            &found,
            None,
            true,
            false,
            true,
            None,
            &["copilot"],
            &GithubMcp::default(),
        );
        assert_eq!(v["servers"][0]["state"], "off");
    }
}
