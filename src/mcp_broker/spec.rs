//! Broker specs: reading, validating (invariants 1-6) and rejecting.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::credential::Credential;
use super::{META_KEY, REMOTE_GATE_ENV, REMOTE_GATE_ENV_OLD, SCHEMA_VERSIONS, SPEC_LIMIT};

pub const OAUTH_CLIENT_ID: &str = "https://ki-utvikling.nav.no/cplt/oauth-client.json";
pub const OAUTH_REDIRECT_URI: &str = "http://127.0.0.1:62471/callback";

/// A spec that passed every check.
#[derive(Clone, Debug)]
pub struct Spec {
    pub id: String,
    /// The spec file it was read from (set by [`load`]).
    pub file: PathBuf,
    pub credential: &'static Credential,
    /// `command` as written, for finding the user's own client entry.
    pub command: Vec<String>,
    /// `command[0]` resolved in the trusted dirs.
    pub program: PathBuf,
    pub remote: Option<String>,
    /// Header lines the remote leg forces on every request (`Name: value`),
    /// from the remote's `headers`; the client's copies are dropped.
    pub remote_headers: Vec<String>,
    /// The remote leg's per-request limit (curl `--max-time`), seconds.
    pub timeout_secs: u64,
    pub egress_hosts: Vec<String>,
    pub allow: BTreeSet<String>,
    /// Tools whose `query` argument must pass [`graphql_read_only`].
    pub graphql: BTreeSet<String>,
    pub login: Option<String>,
}

impl Spec {
    /// The client entry name when the user has none: the id's last segment.
    pub(crate) fn short_name(&self) -> &str {
        self.id.rsplit('/').next().unwrap_or(&self.id)
    }

    /// The whole id as an entry name (`/` as `__`, as in the file name).
    pub(crate) fn full_name(&self) -> String {
        self.id.replace('/', "__")
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct Rejected {
    pub file: String,
    pub reason: String,
    pub fix: String,
}

impl Rejected {
    /// For a terminal: every field escaped, since a file name in a spec dir
    /// the agent could reach may carry control sequences.
    pub fn line(&self) -> String {
        let e = |s: &str| s.escape_debug().to_string();
        format!(
            "{}: broker spec rejected: {}. Fix: {}",
            e(&self.file),
            e(&self.reason),
            e(&self.fix)
        )
    }
}

/// Drop every spec whose file, or any entry on the way to it, the final
/// sandbox policy makes writable (`writable` asks the policy about one
/// path). The same for the credential mechanism's own dirs: the host-side
/// server and probe read its login and config there, so a session grant
/// over them (#1061) would let the agent read the login and rewrite the
/// config. The grant wins and the server is dropped, with a line naming it.
/// Returns the newly rejected, already printed.
pub fn drop_writable(
    found: &mut Detected,
    home: &Path,
    writable: impl Fn(&Path) -> Option<PathBuf>,
) {
    let mut kept = Vec::new();
    for spec in std::mem::take(&mut found.specs) {
        if let Some(tree) = writable(&spec.file) {
            found.rejected.push(Rejected {
                file: spec.file.display().to_string(),
                reason: format!("{} is writable in the sandbox", tree.display()),
                fix: format!(
                    "move XDG_CONFIG_HOME (or the spec) out of {}, or drop that write grant",
                    tree.display()
                ),
            });
            continue;
        }
        let hit = spec
            .credential
            .host_write_dirs(home)
            .into_iter()
            .find_map(|d| writable(&d).map(|tree| (d, tree)));
        match hit {
            None => kept.push(spec),
            Some((dir, tree)) => found.rejected.push(Rejected {
                file: spec.file.display().to_string(),
                reason: format!(
                    "the {} login dir {} is writable in the sandbox (grant: {})",
                    spec.credential.name,
                    dir.display(),
                    tree.display()
                ),
                fix: format!(
                    "drop the write grant on {} to use this server; the grant wins and the server is off",
                    tree.display()
                ),
            }),
        }
    }
    found.specs = kept;
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct Ext {
    #[serde(rename = "v")]
    _v: u64,
    credential: String,
    #[serde(default)]
    command: Vec<String>,
    #[serde(default)]
    egress_hosts: Vec<String>,
    tools: Tools,
    #[serde(default)]
    write_consent: bool,
    #[serde(default)]
    arg_checks: BTreeMap<String, String>,
    #[serde(default)]
    login: Option<Login>,
    #[serde(default)]
    oauth: Option<OAuth>,
    #[serde(default)]
    timeout_secs: Option<u64>,
}

/// Bounds on a remote spec's `timeoutSecs`: long enough for a slow tool
/// call, short enough that a stalled upstream frees its proxy slot (#1059).
pub const REMOTE_TIMEOUT_SECS: std::ops::RangeInclusive<u64> = 30..=3600;
pub const REMOTE_TIMEOUT_DEFAULT: u64 = 600;
/// The only upstream a gh-token spec may name: the host's gh token is sent
/// there, so the spec cannot point it anywhere else.
pub const GH_TOKEN_UPSTREAM: &str = "https://api.githubcopilot.com/mcp/readonly";
/// The only header a gh-token spec may set. Read-only and lockdown are forced
/// by cplt on every gh-token endpoint, and `Authorization` comes from cplt alone.
const GH_TOKEN_HEADERS: &[&str] = &["X-MCP-Toolsets"];

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct OAuth {
    resource: String,
    client_id: String,
    redirect_uri: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Tools {
    allow: Vec<String>,
    #[serde(default)]
    classes: BTreeMap<String, String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Login {
    #[serde(default)]
    run: Option<String>,
    /// Accepted so a spec carrying it still loads (nav-pilot writes it), but
    /// never used: cplt's probe comes from its mechanism table.
    #[serde(default, rename = "status")]
    _status: Option<String>,
}

/// `$XDG_CONFIG_HOME/cplt/mcp`, the directory nav-pilot writes specs to.
pub fn spec_dir(home: &Path) -> PathBuf {
    crate::opencode_v2::xdg_base("XDG_CONFIG_HOME", home, ".config")
        .join("cplt")
        .join("mcp")
}

/// The spec file name for `id`.
pub fn file_name(id: &str) -> String {
    format!("{}.json", id.replace('/', "__"))
}

fn remote_gate_enabled() -> bool {
    if std::env::var(REMOTE_GATE_ENV).as_deref() == Ok("1") {
        return true;
    }
    // shortcut: drop the old name one release after the rename.
    let old = std::env::var(REMOTE_GATE_ENV_OLD).as_deref() == Ok("1");
    if old {
        static NOTICE: std::sync::Once = std::sync::Once::new();
        NOTICE.call_once(|| {
            eprintln!("cplt: {REMOTE_GATE_ENV_OLD} is deprecated; set {REMOTE_GATE_ENV}=1 instead");
        });
    }
    old
}

/// Validate one spec (invariants 1-6 of design section 5.3). `resolve` finds a
/// bare command name in the trusted dirs.
#[cfg_attr(not(test), allow(dead_code))]
pub fn validate(
    text: &str,
    file: &str,
    resolve: impl Fn(&str) -> Option<PathBuf>,
) -> Result<Spec, String> {
    validate_gated(text, file, resolve, remote_gate_enabled())
}

pub(crate) fn validate_gated(
    text: &str,
    file: &str,
    resolve: impl Fn(&str) -> Option<PathBuf>,
    oauth_gate: bool,
) -> Result<Spec, String> {
    let root: Value = serde_json::from_str(text).map_err(|e| format!("not valid JSON ({e})"))?;
    let id = root
        .get("name")
        .and_then(Value::as_str)
        .ok_or("server.json has no name")?
        .to_string();
    if id.is_empty()
        || !id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "._-/".contains(c))
    {
        return Err("name must be a reverse-DNS server name".into());
    }
    if file != file_name(&id) {
        return Err(format!("file name must be {}", file_name(&id)));
    }
    let ext = root
        .pointer(&format!("/_meta/{}", META_KEY.replace('/', "~1")))
        .ok_or_else(|| format!("no _meta[\"{META_KEY}\"] extension"))?;
    let v = ext
        .get("v")
        .and_then(Value::as_u64)
        .ok_or("extension has no v")?;
    if !SCHEMA_VERSIONS.contains(&v) {
        return Err(format!(
            "extension v{v} is not supported by this cplt (reads {SCHEMA_VERSIONS:?})"
        ));
    }
    let ext: Ext = serde_json::from_value(ext.clone()).map_err(|e| format!("extension: {e}"))?;
    let remotes = match root.get("remotes") {
        None | Some(Value::Null) => &[][..],
        Some(Value::Array(a)) => a.as_slice(),
        Some(_) => return Err("remotes must be an array".into()),
    };
    let has_remotes = !remotes.is_empty();
    // 4: remote upstreams require the feature gate and a remote mechanism.
    if has_remotes && !(oauth_gate && matches!(ext.credential.as_str(), "oauth" | "gh-token")) {
        return Err(format!(
            "remote upstreams are not brokered yet; only a host command (remotes[] needs {REMOTE_GATE_ENV}=1 and credential gh-token or oauth)"
        ));
    }
    if !has_remotes && ext.oauth.is_some() {
        return Err("oauth block without an oauth remote".into());
    }
    if !has_remotes && ext.timeout_secs.is_some() {
        return Err("timeoutSecs applies only to a remote upstream".into());
    }
    // `packages[]` is never run (`command` is), but it is part of the spec
    // nav-pilot hands over, so invariants 2 and 6 still hold for it.
    let packages = root.get("packages").cloned().unwrap_or(Value::Null);

    // 2 and 6: no secret values and no credential placeholders. Credentials
    // come from cplt's mechanism table only, never from the spec.
    let mut strings = Vec::new();
    collect_strings(&packages, &mut strings);
    strings.extend(ext.command.iter().map(String::as_str));
    strings.extend(ext.egress_hosts.iter().map(String::as_str));
    if let Some(o) = &ext.oauth {
        strings.push(o.resource.as_str());
        strings.push(o.client_id.as_str());
        strings.push(o.redirect_uri.as_str());
    }
    if has_remotes {
        for r in remotes {
            if let Some(u) = r.get("url").and_then(Value::as_str) {
                strings.push(u);
            }
            if let Some(h) = r.get("headers") {
                collect_strings(h, &mut strings);
            }
        }
    }
    for s in &strings {
        // Per `/` segment: a token in a URL path (`/mcp/ghp_…`) is not a prefix.
        if s.split('/').any(looks_like_secret) {
            return Err("the spec holds what looks like a secret value".into());
        }
        if s.contains('{') || s.contains("$(") || s.contains("${") {
            return Err(format!(
                "credential placeholder in {:?}: the credential comes from cplt, not the spec",
                s.escape_debug().to_string()
            ));
        }
    }
    let secret_env = packages
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|p| p.get("environmentVariables")?.as_array())
        .flatten()
        .any(|e| e.get("isSecret") == Some(&Value::Bool(true)));
    if secret_env {
        return Err("environmentVariables with isSecret: no cplt mechanism supplies them".into());
    }

    // 1: the mechanism exists and fixes what may run or connect.
    let mut remote_headers = Vec::new();
    let (credential, command, program, remote) = if has_remotes {
        let (credential, url, headers) = validate_remote(remotes, &ext)?;
        remote_headers = headers;
        (credential, Vec::new(), PathBuf::new(), Some(url))
    } else {
        let credential = Credential::parse(&ext.credential)?;
        if ext.command.is_empty() {
            return Err("no command".into());
        }
        if let Some(fixed) = credential.command
            && ext.command != fixed
        {
            return Err(format!(
                "credential {} runs only `{}`",
                credential.name,
                fixed.join(" ")
            ));
        }
        if ext.command.iter().any(|a| a.chars().any(char::is_control)) {
            return Err("control characters in command".into());
        }
        let name = &ext.command[0];
        if name.contains('/') {
            return Err("command[0] must be a bare name, resolved in the trusted dirs".into());
        }
        let program = resolve(name).ok_or_else(|| format!("{name} is not in the trusted dirs"))?;
        (credential, ext.command, program, None)
    };

    for host in &ext.egress_hosts {
        check_host(host)?;
    }

    // 3: write and external tools need consent; host-exec never.
    for (tool, class) in &ext.tools.classes {
        match class.as_str() {
            "read" => {}
            "host-exec" => {
                return Err(format!("tool {tool} is host-exec, which is never brokered"));
            }
            "write" | "external" if ext.tools.allow.contains(tool) && !ext.write_consent => {
                return Err(format!(
                    "tool {tool} is {class} and allowed without writeConsent"
                ));
            }
            "write" | "external" => {}
            other => return Err(format!("tool {tool} has unknown class {other}")),
        }
    }
    // 5: tool policy comes only from the spec.
    if let Some(t) = ext
        .tools
        .allow
        .iter()
        .find(|t| t.is_empty() || t.chars().any(char::is_control))
    {
        return Err(format!("bad tool name {:?}", t.escape_debug().to_string()));
    }
    let mut graphql = BTreeSet::new();
    for (tool, check) in &ext.arg_checks {
        if check != "graphql-read-only" {
            return Err(format!("unknown argCheck {check}"));
        }
        graphql.insert(tool.clone());
    }
    let login = ext.login.and_then(|l| l.run);
    if login
        .as_deref()
        .is_some_and(|l| l.chars().any(char::is_control))
    {
        return Err("control characters in login.run".into());
    }
    Ok(Spec {
        id,
        file: PathBuf::new(),
        credential,
        command,
        program,
        remote,
        remote_headers,
        timeout_secs: ext.timeout_secs.unwrap_or(REMOTE_TIMEOUT_DEFAULT),
        egress_hosts: ext.egress_hosts,
        allow: ext.tools.allow.into_iter().collect(),
        graphql,
        login,
    })
}

/// Printable ASCII, no query, fragment or dot segments: a prefix compare on
/// such a URL is then a path compare. A token can still sit in a path
/// segment; the per-segment `looks_like_secret` check in `validate` covers that.
fn plain_https_url(url: &str, what: &str) -> Result<(), String> {
    let ok = url.bytes().all(|b| b.is_ascii_graphic())
        && !url.contains(['?', '#', '%', '\\'])
        && !url.split('/').any(|seg| seg == "." || seg == "..");
    if ok {
        Ok(())
    } else {
        Err(format!(
            "{what} must be a plain https URL (printable ASCII, no query, fragment, escapes or dot segments)"
        ))
    }
}

/// A remote spec's one upstream, by mechanism: (mechanism, url, forced
/// header lines). Shared rules first, then the mechanism's own.
fn validate_remote(
    remotes: &[Value],
    ext: &Ext,
) -> Result<(&'static Credential, String, Vec<String>), String> {
    let mech = ext.credential.as_str();
    if remotes.len() != 1 {
        return Err(format!("{mech} spec must have exactly one remote"));
    }
    let remote = remotes[0]
        .as_object()
        .ok_or("remote entry must be an object")?;
    let gh = mech == "gh-token";
    if remote.contains_key("headers") && !gh {
        return Err(format!("remote headers are not allowed on an {mech} spec"));
    }
    // Only these keys: any other would escape the secret checks.
    if let Some(k) = remote
        .keys()
        .find(|k| !(*k == "type" || *k == "url" || (gh && *k == "headers")))
    {
        return Err(format!(
            "unknown key {:?} on the {mech} remote",
            k.escape_debug().to_string()
        ));
    }
    if remote.get("type").and_then(Value::as_str) != Some("streamable-http") {
        return Err(format!("{mech} remote type must be streamable-http"));
    }
    let url = remote
        .get("url")
        .and_then(Value::as_str)
        .ok_or_else(|| format!("{mech} remote must have a url string"))?;
    plain_https_url(url, "remote url")?;
    let rest = url
        .strip_prefix("https://")
        .ok_or_else(|| format!("{mech} remote url must start with https://"))?;
    let host = rest.split('/').next().unwrap_or("");
    // No port at all, so always 443.
    if host.contains('@') || host.contains(':') {
        return Err(format!(
            "{mech} remote url must not contain userinfo or port"
        ));
    }
    check_host(host)?;
    if !ext.egress_hosts.iter().any(|h| h == host) {
        return Err(format!("{mech} remote host {host} must be in egressHosts"));
    }
    if !ext.command.is_empty() {
        return Err(format!("{mech} spec must not specify command"));
    }
    if let Some(t) = ext.timeout_secs
        && !REMOTE_TIMEOUT_SECS.contains(&t)
    {
        return Err(format!(
            "timeoutSecs {t} is outside {}..={}",
            REMOTE_TIMEOUT_SECS.start(),
            REMOTE_TIMEOUT_SECS.end()
        ));
    }
    if gh {
        if ext.oauth.is_some() {
            return Err("oauth block on a gh-token spec".into());
        }
        // The host's gh token goes to this one URL, nowhere else.
        if url != GH_TOKEN_UPSTREAM {
            return Err(format!("gh-token remote url must be {GH_TOKEN_UPSTREAM}"));
        }
        let headers = gh_token_headers(remote.get("headers"))?;
        return Ok((&super::credential::GH_TOKEN, url.to_string(), headers));
    }
    validate_oauth(url, host, ext)?;
    Ok((&super::credential::OAUTH, url.to_string(), Vec::new()))
}

/// A gh-token remote's forced headers: `X-MCP-Readonly: true` and
/// `X-MCP-Lockdown: true` always, plus the spec's `X-MCP-Toolsets` (the only
/// header it may set, non-empty, `[a-z0-9_,-]` only). The host's token goes
/// to this endpoint, so the spec can narrow it but never widen it.
fn gh_token_headers(v: Option<&Value>) -> Result<Vec<String>, String> {
    let mut out: Vec<String> = crate::github_mcp::FORCED_HEADERS
        .iter()
        .map(|h| (*h).to_string())
        .collect();
    let Some(v) = v else {
        return Ok(out);
    };
    let list = v.as_array().ok_or("remote headers must be an array")?;
    let mut seen = false;
    for h in list {
        let o = h
            .as_object()
            .filter(|o| o.keys().all(|k| k == "name" || k == "value"))
            .ok_or("each remote header must be {\"name\", \"value\"} only")?;
        let (Some(name), Some(value)) = (
            o.get("name").and_then(Value::as_str),
            o.get("value").and_then(Value::as_str),
        ) else {
            return Err("each remote header needs a name and a value string".into());
        };
        let Some(&canon) = GH_TOKEN_HEADERS
            .iter()
            .find(|n| n.eq_ignore_ascii_case(name))
        else {
            return Err(format!(
                "remote header {:?} is not allowed on a gh-token spec (only {}); cplt sets the credential and forces X-MCP-Readonly and X-MCP-Lockdown itself",
                name.escape_debug().to_string(),
                GH_TOKEN_HEADERS.join(", ")
            ));
        };
        if value.is_empty()
            || !value
                .bytes()
                .all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'_' | b',' | b'-'))
        {
            return Err(format!(
                "remote header {canon} must be a non-empty list of toolset names (a-z, 0-9, _, -, comma)"
            ));
        }
        if std::mem::replace(&mut seen, true) {
            return Err(format!("remote header {canon} is set twice"));
        }
        out.push(format!("{canon}: {value}"));
    }
    Ok(out)
}

fn validate_oauth(url: &str, host: &str, ext: &Ext) -> Result<(), String> {
    let oauth = ext
        .oauth
        .as_ref()
        .ok_or("oauth spec requires an oauth block")?;
    plain_https_url(&oauth.resource, "oauth.resource")?;
    let res_rest = oauth
        .resource
        .strip_prefix("https://")
        .ok_or("oauth.resource must start with https://")?;
    let res_host = res_rest.split('/').next().unwrap_or("");
    // Compare parsed origin host as well as path boundary so `https://` or
    // `https://host.evil` cannot pass as a prefix of `https://host/...`.
    let same_origin_prefix = res_host == host
        && (url == oauth.resource
            || (url.starts_with(&oauth.resource)
                && (oauth.resource.ends_with('/')
                    || url.as_bytes().get(oauth.resource.len()) == Some(&b'/'))));
    if !same_origin_prefix {
        return Err(
            "oauth.resource must equal the remote url or be a same-origin prefix of it".into(),
        );
    }
    if oauth.client_id != OAUTH_CLIENT_ID {
        return Err(format!("oauth.clientId must be {OAUTH_CLIENT_ID}"));
    }
    if oauth.redirect_uri != OAUTH_REDIRECT_URI {
        return Err(format!("oauth.redirectUri must be {OAUTH_REDIRECT_URI}"));
    }
    Ok(())
}

pub(crate) fn collect_strings<'a>(v: &'a Value, out: &mut Vec<&'a str>) {
    match v {
        Value::String(s) => out.push(s),
        Value::Array(a) => a.iter().for_each(|v| collect_strings(v, out)),
        Value::Object(m) => m.values().for_each(|v| collect_strings(v, out)),
        _ => {}
    }
}

/// A conservative token sniff: common vendor prefixes, bearer values, JWTs.
pub(crate) fn looks_like_secret(s: &str) -> bool {
    const PREFIXES: &[&str] = &[
        "ghp_",
        "gho_",
        "ghu_",
        "ghs_",
        "ghr_",
        "github_pat_",
        "glpat-",
        "xoxb-",
        "xoxp-",
        "AKIA",
        "sk-",
        "eyJ",
    ];
    let s = s.trim();
    let lower = s.to_ascii_lowercase();
    PREFIXES
        .iter()
        .any(|p| s.starts_with(p) && s.len() >= p.len() + 8)
        || ["bearer ", "token ", "basic "]
            .iter()
            .any(|p| lower.starts_with(p) && s.len() > p.len())
}

/// A bare public hostname not on the built-in blocklist (only that list:
/// a user blocklist is not consulted): no scheme, port, IP literal, wildcard or
/// localhost.
pub(crate) fn check_host(host: &str) -> Result<(), String> {
    let bad = || {
        Err(format!(
            "egressHosts entry {:?} is not a bare public hostname",
            host.escape_debug().to_string()
        ))
    };
    let labels: Vec<&str> = host.split('.').collect();
    if host.len() > 253
        || labels.len() < 2
        || host != crate::proxy::normalize_hostname(host)
        || host.ends_with(".localhost")
        || host.ends_with(".local")
        || labels.iter().all(|l| l.chars().all(|c| c.is_ascii_digit()))
        || labels.iter().any(|l| {
            l.is_empty()
                || l.len() > 63
                || l.starts_with('-')
                || l.ends_with('-')
                || !l.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
        })
    {
        return bad();
    }
    // The proxy refuses these for the agent; a spec does not get them back.
    if crate::proxy::is_blocked_in_list(host, &crate::proxy::builtin_blocklist()) {
        return Err(format!(
            "egressHosts entry {host} is on cplt's blocked-domains list"
        ));
    }
    Ok(())
}

/// What launch detection found.
#[derive(Default)]
pub struct Detected {
    pub specs: Vec<Spec>,
    pub rejected: Vec<Rejected>,
    /// Skipped by `--no-mcp-broker`.
    pub disabled: Vec<String>,
}

/// Load every spec in `dir`. A file in `writable` (a tree the sandbox can
/// write), a symlink, or a spec that fails validation is rejected, never
/// loaded. No directory means no specs.
pub fn load(dir: &Path, writable: &[PathBuf], disabled: &[String]) -> Detected {
    load_with(dir, writable, disabled, crate::git::trusted_binary)
}

/// [`load`] with the trusted-dir lookup injected, so tests need no real
/// binaries.
pub(crate) fn load_with(
    dir: &Path,
    writable: &[PathBuf],
    disabled: &[String],
    resolve: impl Fn(&str) -> Option<PathBuf>,
) -> Detected {
    load_with_gate(dir, writable, disabled, resolve, remote_gate_enabled())
}

pub(crate) fn load_with_gate(
    dir: &Path,
    writable: &[PathBuf],
    disabled: &[String],
    resolve: impl Fn(&str) -> Option<PathBuf>,
    oauth_gate: bool,
) -> Detected {
    let mut out = Detected::default();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return out;
    };
    let canon = |p: &Path| std::fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf());
    let real_dir = canon(dir);
    let dir_link = dir
        .symlink_metadata()
        .is_ok_and(|m| m.file_type().is_symlink());
    let mut files: Vec<PathBuf> = entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|e| e == "json"))
        .collect();
    files.sort();
    let mut seen = BTreeSet::new();
    for path in files {
        let file = path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .into_owned();
        let tree = writable
            .iter()
            .find(|w| real_dir.starts_with(canon(w)) || canon(&path).starts_with(canon(w)));
        let file_link = path
            .symlink_metadata()
            .is_ok_and(|m| m.file_type().is_symlink());
        // (reason, fix): the fix matches the cause; only a bad spec is
        // nav-pilot's to rewrite.
        let result = if dir_link {
            Err((
                format!("{} is a symlink", dir.display()),
                format!(
                    "replace the symlink {} with a real directory",
                    dir.display()
                ),
            ))
        } else if let Some(tree) = tree {
            Err((
                format!("{} is writable in the sandbox", tree.display()),
                format!(
                    "move XDG_CONFIG_HOME (or the spec) out of {}, or drop that write grant",
                    tree.display()
                ),
            ))
        } else if file_link {
            Err((
                "the spec is a symlink".into(),
                format!(
                    "replace the symlink {} with the file itself",
                    path.display()
                ),
            ))
        } else {
            let enable = || {
                let id = file.trim_end_matches(".json").replace("__", "/");
                format!("nav-pilot mcp enable {id}")
            };
            match crate::untrusted::read_untrusted(&path, SPEC_LIMIT) {
                Ok(Some(text)) => match validate_gated(&text, &file, &resolve, oauth_gate) {
                    Ok(spec) if spec.remote.is_some() && spec.credential.name == "oauth" => Err((
                        "oauth remotes are validated but not served yet (no login in this cplt)"
                            .into(),
                        "remove the spec until cplt supports oauth login".into(),
                    )),
                    // ponytail: the gh-token remote leg exists (#909 PR2); no
                    // client is pointed at it until PR3/PR4.
                    Ok(spec) if spec.remote.is_some() => Err((
                        "gh-token remotes are validated but not served to a client yet".into(),
                        "remove the spec until cplt wires the GitHub MCP broker".into(),
                    )),
                    Ok(spec) => Ok(spec),
                    Err(r) => Err((r, enable())),
                },
                Ok(None) => Err(("not a regular file, or too large".into(), enable())),
                Err(e) => Err((format!("cannot read ({e})"), enable())),
            }
        };
        match result {
            Ok(spec) if disabled.contains(&spec.id) => out.disabled.push(spec.id),
            Ok(spec) if !seen.insert(spec.id.clone()) => {}
            Ok(mut spec) => {
                spec.file.clone_from(&path);
                out.specs.push(spec);
            }
            Err((reason, fix)) => {
                out.rejected.push(Rejected {
                    file: path.display().to_string(),
                    reason,
                    fix,
                });
            }
        }
    }
    out
}

/// Launch detection: load, print one line per rejected spec. The launch
/// always continues.
pub fn detect(home: &Path, writable: &[PathBuf], disabled: &[String]) -> Detected {
    let found = load(&spec_dir(home), writable, disabled);
    for r in &found.rejected {
        crate::ui::warn(&r.line());
    }
    found
}

#[cfg(test)]
pub(crate) mod tests {
    /// `load` with a fake trusted-dir lookup: every name resolves.
    fn load_test(dir: &Path, writable: &[PathBuf], disabled: &[String]) -> Detected {
        load_with(dir, writable, disabled, |n| {
            Some(PathBuf::from("/opt/homebrew/bin").join(n))
        })
    }

    use super::*;
    use crate::mcp_broker::test_util::*;

    use std::path::PathBuf;

    use serde_json::{Value, json};

    #[test]
    fn accepts_the_nais_spec() {
        let s = check(base()).unwrap();
        assert_eq!(s.id, "io.github.nais/nais-mcp");
        assert_eq!(s.program, PathBuf::from("/opt/homebrew/bin/nais"));
        assert!(s.graphql.contains("execute_graphql"));
        assert_eq!(s.login.as_deref(), Some("nais login -n"));
    }

    #[test]
    fn rejects_unknown_version_unknown_fields_and_wrong_file() {
        assert!(
            check(with(base(), "/v", json!(2)))
                .unwrap_err()
                .contains("v2")
        );
        let mut v = base();
        v["extra"] = json!(1);
        assert!(check(v).is_err());
        assert!(
            validate(&spec_json(base()), "x.json", |_| None)
                .unwrap_err()
                .contains("file name")
        );
    }

    #[test]
    fn invariant_1_mechanism_and_command() {
        assert!(check(with(base(), "/credential", json!("aws"))).is_err());
        assert!(
            check(with(base(), "/credential", json!("gh-token")))
                .unwrap_err()
                .contains("cannot serve a command")
        );
        assert!(
            check(with(
                base(),
                "/command",
                json!(["nais", "alpha", "mcp", "serve", "--x"])
            ))
            .is_err()
        );
        assert!(check(with(base(), "/command", json!(["bash", "-c", "x"]))).is_err());
        let none = with(base(), "/credential", json!("none"));
        assert!(check(with(none, "/command", json!(["uvx", "srv"]))).is_ok());
    }

    #[test]
    fn invariant_2_no_secrets() {
        let mut root: Value = serde_json::from_str(&spec_json(base())).unwrap();
        root["packages"] = json!([{"environmentVariables": [{"name": "K", "isSecret": true}]}]);
        assert!(validate(&root.to_string(), FILE, |_| Some("/bin/x".into())).is_err());
        let none = with(base(), "/credential", json!("none"));
        let cmd = with(none, "/command", json!(["srv", "ghp_abcdefghijklmnop"]));
        assert!(check(cmd).unwrap_err().contains("secret"));
    }

    #[test]
    fn invariant_3_classes() {
        let hx = with(base(), "/tools/classes", json!({"run": "host-exec"}));
        assert!(check(hx).unwrap_err().contains("host-exec"));
        let w = with(
            base(),
            "/tools/classes",
            json!({"execute_graphql": "write"}),
        );
        assert!(check(w.clone()).unwrap_err().contains("writeConsent"));
        let mut ok = w;
        ok["writeConsent"] = json!(true);
        assert!(check(ok).is_ok());
        // A write tool that is not allowed needs no consent.
        assert!(check(with(base(), "/tools/classes", json!({"other": "write"}))).is_ok());
    }

    #[test]
    fn invariant_4_no_remotes_and_trusted_dirs() {
        let mut root: Value = serde_json::from_str(&spec_json(base())).unwrap();
        root["remotes"] = json!([{"type": "streamable-http", "url": "http://x.example"}]);
        assert!(
            validate(&root.to_string(), FILE, |_| Some("/bin/x".into()))
                .unwrap_err()
                .contains("remote upstreams are not brokered")
        );
        assert!(
            validate(&spec_json(base()), FILE, |_| None)
                .unwrap_err()
                .contains("trusted")
        );
        let none = with(base(), "/credential", json!("none"));
        assert!(
            check(with(none, "/command", json!(["/tmp/x"])))
                .unwrap_err()
                .contains("bare")
        );
        for h in [
            "localhost",
            "1.2.3.4",
            "x.example:443",
            "https://x.example",
            "*.example.com",
            "X.example",
        ] {
            assert!(
                check(with(base(), "/egressHosts", json!([h]))).is_err(),
                "{h}"
            );
        }
    }

    #[test]
    fn invariant_6_no_placeholders() {
        let none = with(base(), "/credential", json!("none"));
        assert!(
            check(with(
                none.clone(),
                "/command",
                json!(["srv", "--token", "${TOKEN}"])
            ))
            .is_err()
        );
        assert!(check(with(none, "/command", json!(["srv", "{api_key}"]))).is_err());
        let mut root: Value = serde_json::from_str(&spec_json(base())).unwrap();
        root["remotes"] = json!([{"url": "https://x.example", "headers": [{"name": "Authorization", "value": "Bearer {token}"}]}]);
        assert!(validate(&root.to_string(), FILE, |_| Some("/bin/x".into())).is_err());
    }

    #[test]
    fn load_refuses_symlinks_and_writable_trees() {
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("real.json");
        std::fs::write(&real, spec_json(base())).unwrap();
        std::os::unix::fs::symlink(&real, dir.path().join(FILE)).unwrap();
        let found = load_test(dir.path(), &[], &[]);
        assert!(found.specs.is_empty());
        let r = found
            .rejected
            .iter()
            .find(|r| r.reason.contains("symlink"))
            .unwrap();
        assert!(r.fix.starts_with("replace the symlink"), "{r:?}");
        std::fs::remove_file(dir.path().join(FILE)).unwrap();
        std::fs::rename(&real, dir.path().join(FILE)).unwrap();
        let found = load_test(dir.path(), &[dir.path().to_path_buf()], &[]);
        assert!(
            found.specs.is_empty() && found.rejected[0].reason.contains("writable in the sandbox")
        );
        assert!(
            load_test(&dir.path().join("missing"), &[], &[])
                .rejected
                .is_empty()
        );
    }

    #[test]
    fn file_level_write_grants_and_policy_rejections() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join(FILE);
        std::fs::write(&f, spec_json(base())).unwrap();
        let found = load_test(dir.path(), std::slice::from_ref(&f), &[]);
        assert!(
            found.specs.is_empty() && found.rejected[0].reason.contains("writable in the sandbox")
        );
        let mut found = load_test(dir.path(), &[], &[]);
        assert_eq!(found.specs.len(), 1);
        assert_eq!(found.specs[0].file, f);
        drop_writable(&mut found, Path::new("/nohome"), |p| {
            (p == f).then(|| PathBuf::from("/grant"))
        });
        assert!(found.specs.is_empty());
        assert!(found.rejected[0].reason.contains("/grant"));
    }

    #[test]
    fn a_write_grant_over_the_login_dir_drops_the_server() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(FILE), spec_json(base())).unwrap();
        let home = Path::new("/home/u");
        let login = super::super::credential::MECHANISMS[0].host_write_dirs(home);
        // The path the child runtime grants, per platform (#1061).
        let want = if cfg!(target_os = "macos") {
            home.join("Library/Application Support/nais")
        } else {
            std::env::var_os("XDG_CONFIG_HOME")
                .map(PathBuf::from)
                .filter(|p| p.is_absolute())
                .unwrap_or_else(|| home.join(".config"))
                .join("nais")
        };
        assert_eq!(login, std::slice::from_ref(&want));

        // An unrelated grant leaves the server alone.
        let mut found = load_test(dir.path(), &[], &[]);
        drop_writable(&mut found, home, |p| {
            (p == Path::new("/elsewhere")).then(|| p.to_path_buf())
        });
        assert_eq!(found.specs.len(), 1);
        assert!(found.rejected.is_empty());

        // A grant over the login dir: the server is off, the line names the grant.
        let mut found = load_test(dir.path(), &[], &[]);
        drop_writable(&mut found, home, |p| {
            p.starts_with(&want).then(|| PathBuf::from("/home/u/grant"))
        });
        assert!(found.specs.is_empty());
        let line = found.rejected[0].line();
        assert!(
            line.contains("login dir") && line.contains("/home/u/grant"),
            "{line}"
        );
    }

    #[test]
    fn a_blocked_egress_host_is_refused() {
        assert!(check_host("console.nav.cloud.nais.io").is_ok());
        for h in ["webhook.site", "x.webhook.site"] {
            assert!(check_host(h).unwrap_err().contains("blocked"), "{h}");
        }
    }

    #[test]
    fn rejected_lines_are_escaped() {
        let r = Rejected {
            file: "a\u{1b}[2Jb.json".into(),
            reason: "x\ny".into(),
            fix: "f".into(),
        };
        let l = r.line();
        assert!(!l.contains('\u{1b}') && !l.contains('\n'), "{l}");
    }

    #[test]
    fn the_fix_matches_the_cause() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(FILE), spec_json(base())).unwrap();
        let r = &load_test(dir.path(), &[dir.path().to_path_buf()], &[]).rejected[0];
        assert!(r.fix.starts_with("move XDG_CONFIG_HOME"), "{r:?}");
        assert!(
            r.fix
                .contains(&*std::fs::canonicalize(dir.path()).unwrap().to_string_lossy())
                || r.fix.contains(&*dir.path().to_string_lossy()),
            "names the tree: {r:?}"
        );
        let link = tempfile::tempdir().unwrap();
        let ln = link.path().join("mcp");
        std::os::unix::fs::symlink(dir.path(), &ln).unwrap();
        let r = &load_test(&ln, &[], &[]).rejected[0];
        assert!(
            r.fix.starts_with("replace the symlink") && r.fix.contains("real directory"),
            "{r:?}"
        );
        // A bad spec is still nav-pilot's to rewrite.
        std::fs::write(dir.path().join(FILE), "{").unwrap();
        let r = &load_test(dir.path(), &[], &[]).rejected[0];
        assert_eq!(r.fix, "nav-pilot mcp enable io.github.nais/nais-mcp");
    }

    fn oauth_root() -> Value {
        let mut ext = base();
        ext["credential"] = json!("oauth");
        ext.as_object_mut().unwrap().remove("command");
        ext["egressHosts"] = json!(["fgw.example"]);
        ext["oauth"] = json!({
            "resource": "https://fgw.example/mcp/nais",
            "clientId": OAUTH_CLIENT_ID,
            "redirectUri": OAUTH_REDIRECT_URI,
        });
        let mut root: Value = serde_json::from_str(&spec_json(ext)).unwrap();
        root["remotes"] = json!([{
            "type": "streamable-http",
            "url": "https://fgw.example/mcp/nais",
        }]);
        root
    }

    fn check_oauth(root: &Value, gate: bool) -> Result<Spec, String> {
        validate_gated(
            &root.to_string(),
            FILE,
            |n| Some(PathBuf::from("/opt/homebrew/bin").join(n)),
            gate,
        )
    }

    #[test]
    fn oauth_remote_accepted_when_gated_and_refused_when_off() {
        let root = oauth_root();
        let spec = check_oauth(&root, true).unwrap();
        assert_eq!(spec.remote.as_deref(), Some("https://fgw.example/mcp/nais"));
        assert_eq!(spec.credential.name, "oauth");
        assert!(spec.command.is_empty());
        assert!(spec.program.as_os_str().is_empty());
        assert!(spec.graphql.contains("execute_graphql"));

        // Same-origin prefixes are accepted.
        for res in [
            "https://fgw.example",
            "https://fgw.example/",
            "https://fgw.example/mcp",
            "https://fgw.example/mcp/",
        ] {
            let mut r = oauth_root();
            r["_meta"][META_KEY]["oauth"]["resource"] = json!(res);
            assert!(check_oauth(&r, true).is_ok(), "{res}");
        }

        // Default-off gate refuses remotes.
        assert!(
            check_oauth(&root, false)
                .unwrap_err()
                .contains("not brokered")
        );
    }

    #[test]
    fn oauth_remote_rejects_invalid_fields() {
        let mut r = oauth_root();
        r["remotes"][0]["url"] = json!("http://fgw.example/mcp/nais");
        assert!(check_oauth(&r, true).is_err());

        let mut r = oauth_root();
        r["_meta"][META_KEY]["oauth"]["clientId"] = json!("https://other.example/client.json");
        assert!(check_oauth(&r, true).is_err());

        let mut r = oauth_root();
        r["_meta"][META_KEY]["oauth"]["redirectUri"] = json!("http://127.0.0.1:9999/callback");
        assert!(check_oauth(&r, true).is_err());

        for bad_res in [
            "https://other.example/mcp/nais",
            "https://fgw.example.evil/mcp/nais",
            "https://fgw.example/m",
            "https://",
        ] {
            let mut r = oauth_root();
            r["_meta"][META_KEY]["oauth"]["resource"] = json!(bad_res);
            assert!(check_oauth(&r, true).is_err(), "{bad_res}");
        }

        let mut r = oauth_root();
        r["_meta"][META_KEY]["egressHosts"] = json!(["other.example"]);
        assert!(check_oauth(&r, true).is_err());

        let mut r = oauth_root();
        r["remotes"] = json!([
            {"type": "streamable-http", "url": "https://fgw.example/mcp/nais"},
            {"type": "streamable-http", "url": "https://fgw.example/mcp/other"}
        ]);
        assert!(check_oauth(&r, true).is_err());

        let mut r = oauth_root();
        r["_meta"][META_KEY]["command"] = json!(["nais"]);
        assert!(check_oauth(&r, true).is_err());

        let mut r = oauth_root();
        r["_meta"][META_KEY]
            .as_object_mut()
            .unwrap()
            .remove("oauth");
        assert!(check_oauth(&r, true).is_err());

        let mut r = oauth_root();
        r["remotes"][0]["headers"] = json!([]);
        assert!(check_oauth(&r, true).is_err());

        let mut r = oauth_root();
        r["remotes"][0]["token"] = json!("x");
        assert!(check_oauth(&r, true).unwrap_err().contains("unknown key"));

        for bad_url in [
            "https://fgw.example/mcp/nais?token=abc",
            "https://fgw.example/mcp/nais#x",
            "https://fgw.example/mcp/nais/../other",
            "https://fgw.example/mcp/%2e%2e/other",
            "https://fgw.example/mcp/n\u{e6}is",
            "https://u@fgw.example/mcp/nais",
            "https://fgw.example:8443/mcp/nais",
        ] {
            let mut r = oauth_root();
            r["remotes"][0]["url"] = json!(bad_url);
            assert!(check_oauth(&r, true).is_err(), "{bad_url}");
        }

        let mut r = oauth_root();
        r["remotes"] = json!({});
        assert!(check_oauth(&r, true).unwrap_err().contains("array"));

        // Shared policy checks still apply.
        let mut r = oauth_root();
        r["_meta"][META_KEY]["tools"]["classes"] = json!({"run": "host-exec"});
        assert!(check_oauth(&r, true).unwrap_err().contains("host-exec"));

        // Secrets/placeholders in remote url or oauth fields are refused.
        let mut r = oauth_root();
        r["remotes"][0]["url"] = json!("https://fgw.example/${TOKEN}");
        assert!(check_oauth(&r, true).is_err());

        // A token in a path segment is refused, in url and in resource.
        for tok in ["ghp_abcdefghijklmnop", "eyJhbGciOiJIUzI1NiJ9"] {
            let u = format!("https://fgw.example/mcp/{tok}");
            let mut r = oauth_root();
            r["remotes"][0]["url"] = json!(u);
            r["_meta"][META_KEY]["oauth"]["resource"] = json!(u);
            assert!(check_oauth(&r, true).unwrap_err().contains("secret"), "{u}");
            let mut r = oauth_root();
            r["_meta"][META_KEY]["oauth"]["resource"] = json!(format!("https://fgw.example/{tok}"));
            assert!(
                check_oauth(&r, true).unwrap_err().contains("secret"),
                "{tok}"
            );
        }
    }

    #[test]
    fn oauth_block_on_command_spec_is_refused() {
        let mut ext = base();
        ext["oauth"] = json!({
            "resource": "https://fgw.example/mcp/nais",
            "clientId": OAUTH_CLIENT_ID,
            "redirectUri": OAUTH_REDIRECT_URI,
        });
        assert!(
            validate_gated(
                &spec_json(ext),
                FILE,
                |n| Some(PathBuf::from("/opt/homebrew/bin").join(n)),
                true,
            )
            .unwrap_err()
            .contains("oauth block without an oauth remote")
        );
    }

    #[test]
    fn load_rejects_validated_oauth_remote() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(FILE), oauth_root().to_string()).unwrap();
        let found = load_with_gate(
            dir.path(),
            &[],
            &[],
            |n| Some(PathBuf::from("/opt/homebrew/bin").join(n)),
            true,
        );
        assert!(found.specs.is_empty());
        assert_eq!(found.rejected.len(), 1);
        assert_eq!(
            found.rejected[0].reason,
            "oauth remotes are validated but not served yet (no login in this cplt)"
        );
        assert_eq!(
            found.rejected[0].fix,
            "remove the spec until cplt supports oauth login"
        );
    }

    pub(crate) fn gh_root() -> Value {
        let ext = json!({
            "v": 1,
            "credential": "gh-token",
            "egressHosts": ["api.githubcopilot.com"],
            "tools": {"allow": ["get_me"], "classes": {}},
        });
        let mut root: Value = serde_json::from_str(&spec_json(ext)).unwrap();
        root["remotes"] = json!([{
            "type": "streamable-http",
            "url": GH_TOKEN_UPSTREAM,
            "headers": [{"name": "x-mcp-toolsets", "value": "repos,issues"}],
        }]);
        root
    }

    #[test]
    fn gh_token_remote_accepted_only_when_gated() {
        let spec = check_oauth(&gh_root(), true).unwrap();
        assert_eq!(spec.credential.name, "gh-token");
        assert_eq!(spec.remote.as_deref(), Some(GH_TOKEN_UPSTREAM));
        assert_eq!(
            spec.remote_headers,
            [
                "X-MCP-Readonly: true",
                "X-MCP-Lockdown: true",
                "X-MCP-Toolsets: repos,issues"
            ]
        );
        assert_eq!(spec.timeout_secs, REMOTE_TIMEOUT_DEFAULT);
        assert!(spec.command.is_empty());
        // A command mechanism cannot take a remote.
        let mut r = gh_root();
        r["_meta"][META_KEY]["credential"] = json!("none");
        assert!(check_oauth(&r, true).unwrap_err().contains("not brokered"));
        // Gate off: refused exactly as before this mechanism existed.
        let e = check_oauth(&gh_root(), false).unwrap_err();
        assert!(
            e.starts_with("remote upstreams are not brokered yet"),
            "{e}"
        );
        assert!(e.contains("CPLT_MCP_REMOTE=1"), "{e}");
    }

    #[test]
    fn gh_token_remote_rejects() {
        let refused = |edit: &dyn Fn(&mut Value), want: &str| {
            let mut r = gh_root();
            edit(&mut r);
            let e = check_oauth(&r, true).unwrap_err();
            assert!(e.contains(want), "{want}: {e}");
        };
        let url = |u: &'static str| move |r: &mut Value| r["remotes"][0]["url"] = json!(u);
        refused(&url("https://api.github.com/mcp/readonly"), "egressHosts");
        refused(
            &|r| {
                r["_meta"][META_KEY]["egressHosts"] = json!(["api.github.com"]);
                r["remotes"][0]["url"] = json!("https://api.github.com/mcp/readonly");
            },
            "gh-token remote url must be",
        );
        refused(
            &url("https://api.githubcopilot.com/mcp"),
            "must be https://api",
        );
        refused(
            &url("https://api.githubcopilot.com/mcp/readonly/x"),
            "must be https://api",
        );
        refused(
            &url("https://api.githubcopilot.com:443/mcp/readonly"),
            "port",
        );
        refused(
            &url("https://api.githubcopilot.com:8443/mcp/readonly"),
            "port",
        );
        refused(&url("http://api.githubcopilot.com/mcp/readonly"), "https");
        let hdr = |n: &'static str, v: &'static str| {
            move |r: &mut Value| r["remotes"][0]["headers"] = json!([{"name": n, "value": v}])
        };
        refused(&hdr("Authorization", "x"), "not allowed on a gh-token spec");
        refused(&hdr("authorization", "x"), "not allowed on a gh-token spec");
        refused(&hdr("X-MCP-Other", "x"), "not allowed");
        refused(&hdr("Cookie", "x"), "not allowed");
        refused(
            &hdr("X-MCP-Toolsets", "a\r\nAuthorization: y"),
            "toolset names",
        );
        refused(&hdr("X-MCP-Toolsets", "a\nb"), "toolset names");
        refused(&hdr("X-MCP-Toolsets", "a\u{7f}"), "toolset names");
        refused(&hdr("X-MCP-Toolsets", ""), "toolset names");
        refused(&hdr("X-MCP-Toolsets", " "), "toolset names");
        refused(&hdr("X-MCP-Toolsets", "Repos"), "toolset names");
        refused(&hdr("X-MCP-Readonly", "false"), "forces X-MCP-Readonly");
        refused(&hdr("X-MCP-Readonly", "true"), "not allowed");
        refused(&hdr("x-mcp-lockdown", "false"), "not allowed");
        refused(&hdr("X-MCP-Lockdown", " "), "not allowed");
        refused(
            &|r| {
                r["remotes"][0]["headers"] = json!([
                    {"name": "X-MCP-Toolsets", "value": "a"},
                    {"name": "x-mcp-toolsets", "value": "b"}
                ]);
            },
            "twice",
        );
        refused(
            &|r| {
                r["remotes"][0]["headers"] =
                    json!([{"name": "X-MCP-Toolsets", "value": "repos", "isSecret": false}]);
            },
            "only",
        );
        refused(&|r| r["remotes"][0]["headers"] = json!({}), "array");
        refused(&|r| r["remotes"][0]["token"] = json!("x"), "unknown key");
        refused(
            &|r| r["_meta"][META_KEY]["command"] = json!(["gh", "mcp"]),
            "must not specify command",
        );
        refused(
            &|r| r["_meta"][META_KEY]["oauth"] = json!({"resource": GH_TOKEN_UPSTREAM, "clientId": OAUTH_CLIENT_ID, "redirectUri": OAUTH_REDIRECT_URI}),
            "oauth block",
        );
        refused(
            &|r| r["remotes"][0]["type"] = json!("sse"),
            "streamable-http",
        );
        refused(
            &|r| {
                let one = r["remotes"][0].clone();
                r["remotes"] = json!([one.clone(), one]);
            },
            "exactly one remote",
        );
        for t in [0, 29, 3601, u64::MAX] {
            refused(
                &|r| r["_meta"][META_KEY]["timeoutSecs"] = json!(t),
                "timeoutSecs",
            );
        }
        for t in [30, 900, 3600] {
            let mut r = gh_root();
            r["_meta"][META_KEY]["timeoutSecs"] = json!(t);
            assert_eq!(check_oauth(&r, true).unwrap().timeout_secs, t);
        }
    }

    #[test]
    fn timeout_secs_on_a_command_spec_is_refused() {
        let ext = with(base(), "/v", json!(1));
        let mut ext = ext;
        ext["timeoutSecs"] = json!(600);
        assert!(check(ext).unwrap_err().contains("only to a remote"));
    }

    #[test]
    fn load_does_not_serve_a_gh_token_remote_yet() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(FILE), gh_root().to_string()).unwrap();
        let found = load_with_gate(dir.path(), &[], &[], |_| None, true);
        assert!(found.specs.is_empty());
        assert!(
            found.rejected[0].reason.contains("gh-token remotes"),
            "{}",
            found.rejected[0].reason
        );
        let found = load_with_gate(dir.path(), &[], &[], |_| None, false);
        assert!(found.rejected[0].reason.contains("not brokered yet"));
    }
}
