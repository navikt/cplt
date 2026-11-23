//! GitHub's remote MCP server for OpenCode v2, through a host-side proxy (#797).
//!
//! GitHub's OAuth has no dynamic client registration, so OpenCode cannot log
//! in to `api.githubcopilot.com/mcp` itself, and cplt strips `GH_TOKEN` for
//! it. When the user's own OpenCode config names that server, cplt serves an
//! endpoint at a random secret path on its existing CONNECT proxy port and
//! points the entry at it with `"oauth": false`. No new port is opened: on
//! Linux, Landlock port rules cannot be pinned to loopback, so a new port
//! would be open to every host.
//!
//! The endpoint adds the host's gh token and forwards every request to one
//! fixed upstream, the read-only endpoint, with `X-MCP-Readonly` and
//! `X-MCP-Lockdown` forced on. The token never enters the sandbox through
//! this path; the agent gets a read-only, lockdown view of GitHub.
//!
//! cplt has no TLS stack, so the upstream leg runs through the system `curl`
//! (trusted dirs only), one process per request. The token and the request
//! reach curl on stdin as a config file, never in argv, and `-q` keeps the
//! user's `~/.curlrc` out.

use std::path::{Path, PathBuf};

use crate::agent::SecretToken;

use serde_json::{Map, Value};

use crate::mcp_broker::remote::{Endpoint, install_endpoint};

/// The only place requests go, whatever URL the user's entry names.
pub const UPSTREAM: &str = "https://api.githubcopilot.com/mcp/readonly";
/// Forced on every request: a read-only, lockdown view of GitHub.
pub const FORCED_HEADERS: &[&str] = &["X-MCP-Readonly: true", "X-MCP-Lockdown: true"];
const CONFIG_LIMIT: u64 = 1024 * 1024;

/// Does `url` name GitHub's remote MCP server (full or read-only endpoint)?
pub fn is_github_mcp_url(url: &str) -> bool {
    let url = url.trim().to_ascii_lowercase();
    let Some(rest) = url.strip_prefix("https://") else {
        return false;
    };
    let rest = rest.split(['?', '#']).next().unwrap_or_default();
    let rest = rest.trim_end_matches('/');
    let rest = rest.replacen("api.githubcopilot.com:443/", "api.githubcopilot.com/", 1);
    rest == "api.githubcopilot.com/mcp" || rest == "api.githubcopilot.com/mcp/readonly"
}

/// An entry to route: (`true` for v2's `mcp.servers.<name>`, `false` for the
/// legacy `mcp.<name>` that v2 still reads; the name).
pub type Entry = (bool, String);

/// The entries in `config` that point at GitHub's MCP.
pub fn github_servers(config: &Value) -> Vec<Entry> {
    let is_github = |s: &Value| {
        s.get("url")
            .and_then(Value::as_str)
            .is_some_and(is_github_mcp_url)
    };
    let mut out = Vec::new();
    for (v2, map) in [
        (true, config.pointer("/mcp/servers")),
        (false, config.get("mcp")),
    ] {
        for (name, s) in map.and_then(Value::as_object).into_iter().flatten() {
            if is_github(s) {
                out.push((v2, name.clone()));
            }
        }
    }
    out
}

/// The `OPENCODE_CONFIG_CONTENT` value: `existing` with each entry pointed at
/// `proxy_url` and its OAuth off, in the shape it was found in. OpenCode
/// deep-merges this over the files, so the rest of each entry (`enabled`,
/// `timeout`) stays the user's. `None` when `existing` is not a JSON object:
/// cplt will not replace a value it cannot read.
pub fn overlay(existing: Option<&str>, entries: &[Entry], proxy_url: &str) -> Option<String> {
    let mut root = match existing.map(str::trim).filter(|s| !s.is_empty()) {
        None => Map::new(),
        Some(s) => match serde_json::from_str(s).ok()? {
            Value::Object(m) => m,
            _ => return None,
        },
    };
    for (v2, name) in entries {
        let mut parent = object_at(&mut root, "mcp")?;
        if *v2 {
            parent = object_at(parent, "servers")?;
        }
        let entry = object_at(parent, name)?;
        entry.insert("type".into(), "remote".into());
        entry.insert("url".into(), proxy_url.into());
        entry.insert("oauth".into(), false.into());
    }
    Some(Value::Object(root).to_string())
}

fn object_at<'a>(map: &'a mut Map<String, Value>, key: &str) -> Option<&'a mut Map<String, Value>> {
    map.entry(key)
        .or_insert_with(|| Value::Object(Map::new()))
        .as_object_mut()
}

/// The GitHub MCP entries in the config files the user controls: the config
/// dirs (`$XDG_CONFIG_HOME/opencode`, `OPENCODE_CONFIG_DIR`), `OPENCODE_CONFIG`
/// and `OPENCODE_CONFIG_CONTENT`. Project files are agent-writable and never
/// count: an agent must not be able to switch on spending the user's token.
/// `nav-pilot mcp enable --client opencode` writes the user config dir.
pub fn configured_servers(
    dirs: &[PathBuf],
    config_file: Option<&Path>,
    content: Option<&str>,
) -> Vec<Entry> {
    let mut names: Vec<Entry> = user_configs(dirs, config_file, content)
        .iter()
        .flat_map(github_servers)
        .collect();
    names.sort();
    names.dedup();
    names
}

/// The user's OpenCode configs, parsed: `config.json`, `opencode.json` and
/// `opencode.jsonc` in each of `dirs`, then `config_file`, then `content`.
/// Read as untrusted (no symlinks, size cap); unreadable or invalid ones are
/// skipped. Project config is never among them.
pub fn user_configs(
    dirs: &[PathBuf],
    config_file: Option<&Path>,
    content: Option<&str>,
) -> Vec<Value> {
    let mut files: Vec<PathBuf> = dirs
        .iter()
        .flat_map(|d| ["config.json", "opencode.json", "opencode.jsonc"].map(|f| d.join(f)))
        .collect();
    files.extend(config_file.map(Path::to_path_buf));
    let mut texts: Vec<String> = files
        .iter()
        .filter_map(|f| {
            crate::untrusted::read_untrusted(f, CONFIG_LIMIT)
                .ok()
                .flatten()
        })
        .collect();
    texts.extend(content.map(str::to_string));
    texts
        .iter()
        .filter_map(|t| serde_json::from_str(&crate::agent::strip_jsonc(t)).ok())
        .collect()
}

/// A fresh secret for the endpoint path.
pub fn new_secret() -> Result<String, String> {
    crate::scratch::generate_session_id()
}

/// Serve the endpoint at `/<secret>` on the running proxy.
pub fn install(token: SecretToken, secret: &str) -> Result<(), String> {
    let curl = crate::git::trusted_binary("curl").ok_or("no curl in the trusted dirs")?;
    install_endpoint(endpoint(token, secret, curl, UPSTREAM))
}

fn endpoint(token: SecretToken, secret: &str, curl: PathBuf, upstream: &str) -> Endpoint {
    Endpoint {
        token,
        path: format!("/{secret}"),
        curl,
        upstream: upstream.into(),
        forced: FORCED_HEADERS.iter().map(ToString::to_string).collect(),
        tag: "github-mcp".into(),
        timeout_secs: crate::mcp_broker::remote::MAX_TIME_SECS,
        policy: None,
    }
}

/// Install a test endpoint with `upstream` (the real one is pinned).
#[cfg(test)]
pub(crate) fn install_for_test(upstream: &str, token: &str, secret: &str) -> Option<()> {
    let curl = crate::git::trusted_binary("curl")?;
    install_endpoint(endpoint(
        SecretToken::new(token.into()),
        secret,
        curl,
        upstream,
    ))
    .ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_detection() {
        for u in [
            "https://api.githubcopilot.com/mcp",
            "https://api.githubcopilot.com/mcp/",
            "https://API.githubcopilot.com/mcp/readonly",
            "https://api.githubcopilot.com:443/mcp/readonly?x=1",
        ] {
            assert!(is_github_mcp_url(u), "{u}");
        }
        for u in [
            "http://api.githubcopilot.com/mcp",
            "https://api.githubcopilot.com/mcp/x",
            "https://evil.example/api.githubcopilot.com/mcp",
            "https://api.githubcopilot.com.evil/mcp",
        ] {
            assert!(!is_github_mcp_url(u), "{u}");
        }
    }

    #[test]
    fn finds_entries_in_user_config_only() {
        let dir = tempfile::tempdir().unwrap();
        let oc = dir.path().join("oc");
        std::fs::create_dir(&oc).unwrap();
        std::fs::write(
            oc.join("opencode.jsonc"),
            r#"{ // c
              "mcp": {"servers": {"gh": {"type": "remote", "url": "https://api.githubcopilot.com/mcp/readonly"},
                                   "other": {"type": "remote", "url": "https://example.com/mcp"},}}}"#,
        )
        .unwrap();
        let file = dir.path().join("custom.json");
        std::fs::write(
            &file,
            r#"{"mcp":{"old":{"type":"remote","url":"https://api.githubcopilot.com/mcp/"}}}"#,
        )
        .unwrap();
        let content = r#"{"mcp":{"servers":{"gh2":{"url":"https://api.githubcopilot.com/mcp"}}}}"#;
        assert_eq!(
            configured_servers(&[oc], Some(&file), Some(content)),
            [
                (false, "old".to_string()),
                (true, "gh".to_string()),
                (true, "gh2".to_string())
            ]
        );
        // Nothing else is read: a project dir is not one of the inputs.
        assert_eq!(configured_servers(&[], None, None), []);
    }

    #[test]
    fn overlay_keeps_the_users_keys() {
        let existing = r#"{"model":"x","mcp":{"servers":{"gh":{"enabled":true,"headers":{"a":"b"}},"o":{"url":"u"}}}}"#;
        let gh = [(true, "gh".to_string())];
        let v: Value =
            serde_json::from_str(&overlay(Some(existing), &gh, "http://p").unwrap()).unwrap();
        assert_eq!(v["model"], "x");
        assert_eq!(v["mcp"]["servers"]["o"]["url"], "u");
        let e = &v["mcp"]["servers"]["gh"];
        assert_eq!(
            (
                e["url"].as_str(),
                e["oauth"].as_bool(),
                e["enabled"].as_bool()
            ),
            (Some("http://p"), Some(false), Some(true))
        );
        let fresh: Value = serde_json::from_str(&overlay(None, &gh, "http://p").unwrap()).unwrap();
        assert_eq!(fresh["mcp"]["servers"]["gh"]["type"], "remote");
        let old: Value =
            serde_json::from_str(&overlay(None, &[(false, "gh".into())], "http://p").unwrap())
                .unwrap();
        assert_eq!(
            (
                old["mcp"]["gh"]["oauth"].as_bool(),
                old["mcp"].get("servers")
            ),
            (Some(false), None)
        );
        assert_eq!(overlay(Some("[1]"), &gh, "http://p"), None);
        assert_eq!(overlay(Some("{\"mcp\":1}"), &gh, "http://p"), None);
    }

    /// Byte snapshot of the `OPENCODE_CONFIG_CONTENT` overlay (#909 PR1 moved
    /// the remote leg; the overlay must not change).
    #[test]
    fn overlay_snapshot() {
        let existing = r#"{"model":"x","mcp":{"servers":{"gh":{"enabled":true,"headers":{"a":"b"}},"o":{"url":"u"}},"old":{"url":"https://api.githubcopilot.com/mcp"}}}"#;
        let entries = [(true, "gh".to_string()), (false, "old".to_string())];
        const SNAPSHOT: &str = r#"{"mcp":{"old":{"oauth":false,"type":"remote","url":"http://127.0.0.1:9/s3cr3t"},"servers":{"gh":{"enabled":true,"headers":{"a":"b"},"oauth":false,"type":"remote","url":"http://127.0.0.1:9/s3cr3t"},"o":{"url":"u"}}},"model":"x"}"#;
        let got = overlay(Some(existing), &entries, "http://127.0.0.1:9/s3cr3t").unwrap();
        assert_eq!(got, SNAPSHOT, "{got}");
    }
}
