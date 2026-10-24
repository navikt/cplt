//! Client wiring: OpenCode and Copilot CLI overlays.

use std::collections::BTreeSet;
use std::path::Path;

use serde_json::{Map, Value, json};

use super::runtime::Broker;
use super::spec::Spec;
use super::{CONFIG_LIMIT, SOCKET_ENV};

/// Does a client entry's command run `spec`'s command?
pub(crate) fn matches_command(spec: &Spec, argv: &[&str]) -> bool {
    let Some((first, rest)) = argv.split_first() else {
        return false;
    };
    Path::new(first).file_name().and_then(|f| f.to_str()) == Some(spec.command[0].as_str())
        && rest.starts_with(
            &spec.command[1..]
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>(),
        )
}

pub(crate) fn str_array(v: Option<&Value>) -> Vec<&str> {
    v.and_then(Value::as_array)
        .map(|a| a.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default()
}

/// The user's OpenCode config files (the same set as
/// [`crate::github_mcp::configured_servers`]), parsed.
pub fn opencode_configs(home: &Path, content: Option<&str>) -> Vec<Value> {
    let dirs = crate::opencode_v2::user_config_dirs(home);
    crate::github_mcp::user_configs(&dirs, None, content)
}

/// `OPENCODE_CONFIG_CONTENT` with each brokered server's entry pointed at
/// `cplt mcp-stdio <id>`. The user's entries that run the spec's command are
/// overlaid in place (v2 `mcp.servers.<n>` or legacy `mcp.<n>`); with none, an
/// entry named after the id is added. `None` when `existing` is not a JSON
/// object.
pub fn opencode_overlay(
    existing: Option<&str>,
    configs: &[Value],
    specs: &[&Spec],
    socket: &Path,
) -> Option<String> {
    let mut root = match existing.map(str::trim).filter(|s| !s.is_empty()) {
        None => Map::new(),
        Some(s) => match serde_json::from_str(s).ok()? {
            Value::Object(m) => m,
            _ => return None,
        },
    };
    // Every name the user's files or this overlay already use: a fallback
    // must never land on one.
    let mut used: BTreeSet<String> = configs
        .iter()
        .flat_map(|c| [c.pointer("/mcp/servers"), c.get("mcp")])
        .chain([
            root.get("mcp").and_then(|m| m.get("servers")),
            root.get("mcp"),
        ])
        .filter_map(|m| m.and_then(Value::as_object))
        .flat_map(|m| m.keys().cloned())
        .collect();
    for spec in specs {
        let mut names: Vec<(bool, String)> = Vec::new();
        for c in configs {
            for (v2, map) in [(true, c.pointer("/mcp/servers")), (false, c.get("mcp"))] {
                for (name, s) in map.and_then(Value::as_object).into_iter().flatten() {
                    if matches_command(spec, &str_array(s.get("command"))) {
                        names.push((v2, name.clone()));
                    }
                }
            }
        }
        names.sort();
        names.dedup();
        if names.is_empty() {
            names.push((true, free_name(spec, &mut used, true)));
        }
        for (v2, name) in names {
            let mut parent = object_at(&mut root, "mcp")?;
            if v2 {
                parent = object_at(parent, "servers")?;
            }
            // Wholesale, so nothing of a same-named entry in this value
            // survives. OpenCode still deep-merges keys from the files.
            parent.insert(
                name,
                json!({
                    "type": "local",
                    "command": ["cplt", "mcp-stdio", spec.id],
                    "environment": {SOCKET_ENV: socket.display().to_string()},
                }),
            );
        }
    }
    Some(Value::Object(root).to_string())
}

/// A name no user entry or earlier spec has: the short name (when
/// `short_first`), then the full id, then the full id with a counter.
pub(crate) fn free_name(spec: &Spec, used: &mut BTreeSet<String>, short_first: bool) -> String {
    let full = spec.full_name();
    let mut name = if short_first {
        spec.short_name().to_string()
    } else {
        full.clone()
    };
    let mut n = 1;
    while used.contains(&name) {
        name = if n == 1 {
            full.clone()
        } else {
            format!("{full}-{n}")
        };
        n += 1;
    }
    used.insert(name.clone());
    name
}

pub(crate) fn object_at<'a>(
    map: &'a mut Map<String, Value>,
    key: &str,
) -> Option<&'a mut Map<String, Value>> {
    map.entry(key)
        .or_insert_with(|| Value::Object(Map::new()))
        .as_object_mut()
}

/// Copilot CLI args: `--disable-mcp-server` for each user entry that runs a
/// spec's command under another name, and one `--additional-mcp-config` with
/// the brokered entries. The first matching user entry keeps its name, so its
/// tool names and approvals stay the same.
pub fn copilot_args(mcp_config: Option<&str>, specs: &[&Spec], socket: &Path) -> Vec<String> {
    let user: Value = mcp_config
        .and_then(|t| serde_json::from_str(&crate::agent::strip_jsonc(t)).ok())
        .unwrap_or(Value::Null);
    let mut args = Vec::new();
    let mut servers = Map::new();
    for spec in specs {
        let mut matching: Vec<&String> = user
            .get("mcpServers")
            .and_then(Value::as_object)
            .into_iter()
            .flatten()
            .filter(|(_, s)| {
                let mut argv = vec![s.get("command").and_then(Value::as_str).unwrap_or("")];
                argv.extend(str_array(s.get("args")));
                matches_command(spec, &argv)
            })
            .map(|(n, _)| n)
            .collect();
        matching.sort();
        // Exactly the spec id: under a "Registry only" policy Copilot allows a
        // server only when its config key is a registry server name. A user
        // entry with the same name is overridden by --additional-mcp-config;
        // every other entry running the command is turned off.
        let name = spec.id.clone();
        // Never one of the injected names: the flag would switch ours off.
        for other in matching
            .iter()
            .filter(|n| !specs.iter().any(|s| &s.id == **n))
        {
            args.push("--disable-mcp-server".into());
            args.push((*other).clone());
        }
        servers.insert(
            name,
            json!({
                "type": "local",
                "command": "cplt",
                "args": ["mcp-stdio", spec.id],
                "env": {SOCKET_ENV: socket.display().to_string()},
                "tools": ["*"],
            }),
        );
    }
    if !servers.is_empty() {
        args.push("--additional-mcp-config".into());
        args.push(json!({"mcpServers": servers}).to_string());
    }
    args
}

/// Point OpenCode v2 at the broker: merge the overlay into the session's
/// `OPENCODE_CONFIG_CONTENT` (which the GitHub MCP proxy may already have
/// set), else the host's when it reaches the session.
pub fn apply_opencode_overlay(
    env: &mut Vec<(String, String)>,
    home: &Path,
    broker: &Broker,
    deny_env: &[String],
    host_reaches: bool,
) {
    const VAR: &str = "OPENCODE_CONFIG_CONTENT";
    if deny_env.iter().any(|d| d == VAR) {
        crate::ui::warn(
            "deny.env names OPENCODE_CONFIG_CONTENT: brokered MCP servers left as configured in OpenCode.",
        );
        return;
    }
    let pos = env.iter().position(|(k, _)| k == VAR);
    let existing = match pos {
        Some(i) => Some(env[i].1.clone()),
        None => host_reaches.then(|| std::env::var(VAR).ok()).flatten(),
    };
    let specs: Vec<&Spec> = broker.specs().collect();
    let configs = opencode_configs(home, existing.as_deref());
    match opencode_overlay(existing.as_deref(), &configs, &specs, broker.socket()) {
        Some(value) => match pos {
            Some(i) => env[i].1 = value,
            None => env.push((VAR.into(), value)),
        },
        None => crate::ui::warn(
            "OPENCODE_CONFIG_CONTENT is not a JSON object: brokered MCP servers left as configured.",
        ),
    }
}

/// The Copilot CLI args for the broker, from the user's
/// `~/.copilot/mcp-config.json`.
pub fn copilot_launch_args(home: &Path, broker: &Broker) -> Vec<String> {
    let text =
        crate::untrusted::read_untrusted(&home.join(".copilot/mcp-config.json"), CONFIG_LIMIT)
            .ok()
            .flatten();
    let specs: Vec<&Spec> = broker.specs().collect();
    copilot_args(text.as_deref(), &specs, broker.socket())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mcp_broker::test_util::*;

    use std::path::Path;

    use serde_json::{Value, json};

    #[test]
    fn client_overlays() {
        let s = check(base()).unwrap();
        let sock = Path::new("/private/tmp/x/m");
        let user = json!({"mcp": {"servers": {"nais": {"type": "local", "command": ["/opt/homebrew/bin/nais", "alpha", "mcp", "serve"]}}}});
        let out: Value =
            serde_json::from_str(&opencode_overlay(None, &[user], &[&s], sock).unwrap()).unwrap();
        assert_eq!(
            out["mcp"]["servers"]["nais"]["command"],
            json!(["cplt", "mcp-stdio", "io.github.nais/nais-mcp"])
        );
        let out: Value =
            serde_json::from_str(&opencode_overlay(Some(r#"{"a":1}"#), &[], &[&s], sock).unwrap())
                .unwrap();
        assert_eq!(out["a"], 1);
        assert_eq!(out["mcp"]["servers"]["nais-mcp"]["type"], "local");
        assert!(opencode_overlay(Some("[]"), &[], &[&s], sock).is_none());

        let cfg = r#"{"mcpServers":{"b":{"command":"nais","args":["alpha","mcp","serve"]},"a":{"command":"nais","args":["alpha","mcp","serve"]},"c":{"command":"x"}}}"#;
        let args = copilot_args(Some(cfg), &[&s], sock);
        assert_eq!(
            args[..5],
            [
                "--disable-mcp-server",
                "a",
                "--disable-mcp-server",
                "b",
                "--additional-mcp-config"
            ]
        );
        let v: Value = serde_json::from_str(&args[5]).unwrap();
        assert_eq!(
            v["mcpServers"]["io.github.nais/nais-mcp"]["args"],
            json!(["mcp-stdio", "io.github.nais/nais-mcp"])
        );
        assert!(copilot_args(None, &[], sock).is_empty());
    }

    #[test]
    fn overlay_names_never_collide() {
        let s = check(base()).unwrap();
        let sock = Path::new("/private/tmp/x/m");
        let other = json!({"mcp": {"servers": {"nais-mcp": {"type": "remote", "url": "https://x.example"}}}});
        let out: Value =
            serde_json::from_str(&opencode_overlay(None, &[other], &[&s], sock).unwrap()).unwrap();
        assert!(out["mcp"]["servers"].get("nais-mcp").is_none(), "{out}");
        assert_eq!(
            out["mcp"]["servers"]["io.github.nais__nais-mcp"]["type"],
            "local"
        );
        let existing = r#"{"mcp":{"servers":{"nais":{"command":["nais","alpha","mcp","serve"],"oauth":true}}}}"#;
        let user: Value = serde_json::from_str(existing).unwrap();
        let out: Value =
            serde_json::from_str(&opencode_overlay(Some(existing), &[user], &[&s], sock).unwrap())
                .unwrap();
        assert!(
            out["mcp"]["servers"]["nais"].get("oauth").is_none(),
            "wholesale: {out}"
        );
    }

    #[test]
    fn fallback_names_never_collide() {
        let one = Spec {
            id: "io.example.one/server".into(),
            ..check(with(base(), "/credential", json!("none"))).unwrap()
        };
        let two = Spec {
            id: "io.example.two/server".into(),
            ..one.clone()
        };
        let sock = Path::new("/s");
        let user = json!({"mcp": {"servers": {"io.example.one__server": {"type": "remote"}}}});
        let out: Value =
            serde_json::from_str(&opencode_overlay(None, &[user], &[&one, &two], sock).unwrap())
                .unwrap();
        let names: Vec<&String> = out["mcp"]["servers"].as_object().unwrap().keys().collect();
        assert_eq!(names, ["io.example.two__server", "server"], "{out}");
        // Copilot: the key is exactly the id (registry policy), never
        // renamed; a same-named user entry is overridden, not disabled.
        let cfg = r#"{"mcpServers":{"io.example.two/server":{"command":"nais","args":["alpha","mcp","serve"]}}}"#;
        let args = copilot_args(Some(cfg), &[&one, &two], sock);
        assert!(
            !args.iter().any(|a| a == "--disable-mcp-server"),
            "{args:?}"
        );
        let v: Value = serde_json::from_str(args.last().unwrap()).unwrap();
        let names: Vec<&String> = v["mcpServers"].as_object().unwrap().keys().collect();
        assert_eq!(names, ["io.example.one/server", "io.example.two/server"]);
    }

    /// nav-pilot's own OPENCODE_CONFIG_CONTENT (policy, plugins, providers,
    /// agent model, its other servers) survives; only the broker's entry is
    /// added, and an entry under the short name that does not run the spec's
    /// command (here disabled) is left alone, so the broker takes another name.
    #[test]
    fn opencode_overlay_keeps_existing_content() {
        let s = check(base()).unwrap();
        let existing = json!({
            "permission": {"bash": "ask"},
            "plugin": ["nav-pilot-hooks"],
            "enabled_providers": ["github-copilot"],
            "agent": {"build": {"model": "github-copilot/x"}},
            "mcp": {"servers": {
                "aksel": {"type": "remote", "url": "https://aksel.example"},
                "nais-mcp": {"type": "local", "command": ["other"], "enabled": false}
            }}
        });
        let out = opencode_overlay(
            Some(&existing.to_string()),
            std::slice::from_ref(&existing),
            &[&s],
            Path::new("/s"),
        )
        .unwrap();
        let mut out: Value = serde_json::from_str(&out).unwrap();
        let added = out["mcp"]["servers"]
            .as_object_mut()
            .unwrap()
            .remove("io.github.nais__nais-mcp")
            .unwrap();
        assert_eq!(
            added["command"],
            json!(["cplt", "mcp-stdio", "io.github.nais/nais-mcp"])
        );
        assert_eq!(out, existing, "everything else unchanged");
    }
}
