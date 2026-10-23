//! Broker specs: reading, validating (invariants 1-6) and rejecting.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::credential::Credential;
use super::{META_KEY, SCHEMA_VERSIONS, SPEC_LIMIT};

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
/// path). Returns the newly rejected, already printed.
pub fn drop_writable(found: &mut Detected, writable: impl Fn(&Path) -> Option<PathBuf>) {
    let mut kept = Vec::new();
    for spec in std::mem::take(&mut found.specs) {
        match writable(&spec.file) {
            None => kept.push(spec),
            Some(tree) => {
                let r = Rejected {
                    file: spec.file.display().to_string(),
                    reason: format!("{} is writable in the sandbox", tree.display()),
                    fix: format!(
                        "move XDG_CONFIG_HOME (or the spec) out of {}, or drop that write grant",
                        tree.display()
                    ),
                };
                found.rejected.push(r);
            }
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

/// Validate one spec (invariants 1-6 of design section 5.3). `resolve` finds a
/// bare command name in the trusted dirs.
pub fn validate(
    text: &str,
    file: &str,
    resolve: impl Fn(&str) -> Option<PathBuf>,
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
    // 4: only a host command is brokered; any remote upstream is refused, so
    // nothing in `remotes[]` is read further.
    if root
        .get("remotes")
        .and_then(Value::as_array)
        .is_some_and(|a| !a.is_empty())
    {
        return Err("remote upstreams are not brokered yet; only a host command".into());
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
    for s in &strings {
        if looks_like_secret(s) {
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

    // 1: the mechanism exists and fixes what may run.
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
        command: ext.command,
        program,
        egress_hosts: ext.egress_hosts,
        allow: ext.tools.allow.into_iter().collect(),
        graphql,
        login,
    })
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

/// A bare public hostname: no scheme, port, IP literal, wildcard or
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
                Ok(Some(text)) => validate(&text, &file, &resolve).map_err(|r| (r, enable())),
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
mod tests {
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
                .contains("built-in")
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
        drop_writable(&mut found, |p| (p == f).then(|| PathBuf::from("/grant")));
        assert!(found.specs.is_empty());
        assert!(found.rejected[0].reason.contains("/grant"));
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
}
