//! Per-repo user config (#340): the *local* layer.
//!
//! One file per checkout, stored OUTSIDE the repository at
//! `~/.config/cplt/local/<sha256 hex of the canonical project dir>.toml`, so it
//! inherits the protection the trust store already depends on: write access to
//! `~/.config/cplt/` is denied inside the sandbox, therefore the agent cannot
//! author its own grants here. A file inside the repository could not make that
//! claim (see #340 §2), which is why this layer lives here and may widen.
//!
//! The file is the ordinary `config.toml` schema with one extra `[local]`
//! header table (`path`, `remote`, `written_at`) that the loader strips before
//! deserializing. Stripping is how the header stays out of the global schema:
//! adding a `local` field to [`Config`] would make `[local]` a legal table in
//! `~/.config/cplt/config.toml` too, and leaving it in place would make
//! `deserialize_collecting_unknowns` warn "unknown key" on every launch.
//!
//! This module owns both ends of the file: the loader, and the `[local]`
//! header `cplt config set --local` stamps on it. Keeping them together is
//! deliberate — the recorded `remote` is compared after normalization at load
//! (see [`remote_mismatch`]), so the writer must record the same normalized
//! value or the tripwire fires on every subsequent launch.

use std::path::{Path, PathBuf};

use serde::Deserialize;

use super::error::ConfigError;
use super::path::config_dir;
use super::types::{Config, LoadedConfig};
use crate::ui;

/// Subdirectory within the cplt config dir for local (per-repo user) configs.
const LOCAL_DIR: &str = "local";

/// The `[local]` header, stripped before the rest is parsed as a [`Config`].
#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct LocalHeader {
    /// The canonical project dir, in the clear, for listing and diagnostics.
    /// The filename is its hash; this is what makes an orphan file readable.
    /// Declared (rather than ignored) so `deny_unknown_fields` can catch a
    /// misspelled `remote` instead of silently disarming the tripwire, and
    /// checked against the directory the file is keyed under in [`parse_local`]
    /// so it is documentation rather than decoration.
    path: String,
    /// The `origin` remote as it was when the file was written. A staleness
    /// tripwire, NOT an identity — see [`remote_mismatch`].
    remote: String,
    /// ISO 8601 timestamp of the last write. Informational.
    #[allow(dead_code)]
    written_at: String,
}

/// The path-valued config keys, as `[section].key` — the only keys a relative
/// entry is refused for.
///
/// Deliberately not "every string in the file": `sandbox.allow_cache_exec`
/// entries are directory *names* under `~/Library/Caches` and `proxy.upstream`
/// is a URL, so a blanket "must start with `/` or `~`" rule would reject both.
fn path_valued(config: &Config) -> [(&'static str, &[String]); 6] {
    [
        ("allow.read", &config.allow.read),
        ("allow.write", &config.allow.write),
        ("allow.exec", &config.allow.exec),
        ("allow.socket", &config.allow.socket),
        ("deny.paths", &config.deny.paths),
        ("sandbox.repo_dirs", &config.sandbox.repo_dirs),
    ]
}

/// Canonical identity of a checkout: the same value the trust store binds an
/// approval to (`src/trust.rs`), with the same fail-soft fallback when
/// canonicalization is not possible.
fn canonical_key(project_dir: &Path) -> String {
    std::fs::canonicalize(project_dir).map_or_else(
        |_| project_dir.to_string_lossy().into_owned(),
        |p| p.to_string_lossy().into_owned(),
    )
}

/// `~/.config/cplt/local/`, or `<parent of $CPLT_CONFIG>/local/`.
///
/// Derived from [`config_dir`], so a `CPLT_CONFIG` relocation moves `local/`
/// exactly as it moves `trust/` — one resolution rule, not two.
pub fn local_dir() -> Option<PathBuf> {
    Some(config_dir()?.join(LOCAL_DIR))
}

/// The local config file for `project_dir`, whether or not it exists.
pub fn local_path(project_dir: &Path) -> Option<PathBuf> {
    use sha2::{Digest, Sha256};
    let hash = Sha256::digest(canonical_key(project_dir).as_bytes());
    let name: String = hash.iter().map(|b| format!("{b:02x}")).collect();
    Some(local_dir()?.join(format!("{name}.toml")))
}

/// Load the local config for `project_dir`.
///
/// - Missing file: `Ok(None)`, silently. That is the normal case.
/// - Recorded remote no longer matches `origin`: a loud warning and `Ok(None)`.
/// - Malformed TOML, an unreadable file, or a relative path: `Err` — the launch
///   fails. Skipping a bad file would silently revert a local `deny.paths` to
///   whatever global says, which is a silent grant.
pub fn load_local(project_dir: &Path) -> Result<Option<LoadedConfig>, ConfigError> {
    let Some(path) = local_path(project_dir) else {
        return Ok(None);
    };
    if !path.exists() {
        return Ok(None);
    }
    let raw = std::fs::read_to_string(&path).map_err(|e| ConfigError::FileRead {
        path: path.clone(),
        source: e,
    })?;
    let config = parse_local_doc(&raw, &path, project_dir)?;
    Ok(config.map(|config| LoadedConfig { config, path, raw }))
}

/// Parse local config text the way [`load_local`] parses the file on disk:
/// `[local]` header stripped, staleness tripwire applied, relative paths
/// refused.
///
/// Exists so a caller holding the text rather than the path — `cplt settings`,
/// which must show what the launch would apply, including its staged edits —
/// cannot accidentally use a plain `Config::parse` and disagree with the
/// launch about what is in force.
pub fn parse_local_doc(
    raw: &str,
    path: &Path,
    project_dir: &Path,
) -> Result<Option<Config>, ConfigError> {
    parse_local(
        raw,
        path,
        crate::trust::canonical_remote(project_dir),
        Some(&canonical_key(project_dir)),
    )
}

/// Parse a local config file. Split out from [`load_local`] so the remote and
/// the canonical project dir are injected rather than shelled out for: no git,
/// no filesystem, testable.
pub(super) fn parse_local(
    raw: &str,
    path: &Path,
    current_remote: Option<String>,
    project_key: Option<&str>,
) -> Result<Option<Config>, ConfigError> {
    let display = path.display().to_string();
    let mut root = raw
        .parse::<toml::Table>()
        .map_err(|source| ConfigError::TomlParse {
            path: display.clone(),
            source,
        })?;

    // Strip the header before the body is deserialized (see module docs).
    let header: LocalHeader = match root.remove("local") {
        Some(value) => value.try_into().map_err(|source| ConfigError::TomlParse {
            path: display.clone(),
            source,
        })?,
        None => LocalHeader::default(),
    };
    // The filename is a hash of the canonical project dir, so a `[local] path`
    // that names a different directory means the header was hand-edited or the
    // file was copied. It is not authority — the hash already decided which
    // checkout this file belongs to — but leaving it unchecked is what makes
    // the field decorative. Warn and carry on.
    if let (Some(expected), false) = (project_key, header.path.is_empty())
        && header.path != expected
    {
        ui::warn(&format!(
            "{display} is keyed to {expected}, but its [local] path says {}. \
             The filename decides; fix the header or re-write the file.",
            header.path
        ));
    }
    if let Some(recorded) = remote_mismatch(&header.remote, current_remote.as_deref()) {
        // Not `ui::info`: this warning is deliberately NOT suppressible by
        // --quiet, following #284. A grant the user cannot see is the thing the
        // whole layer is trying not to be.
        ui::warn(&format!(
            "local config not applied: {display} was written for remote {recorded}, \
             but origin is now {}. Re-adopt it if this is intentional.",
            current_remote.as_deref().unwrap_or("(none)")
        ));
        return Ok(None);
    }

    let (config, unknown_keys) = super::validation::deserialize_collecting_unknowns(
        &toml::to_string(&root).map_err(|_| {
            ConfigError::Validation(format!(
                "{display}: local config is not representable as TOML"
            ))
        })?,
    )
    .map_err(|source| ConfigError::TomlParse {
        path: display.clone(),
        source,
    })?;

    for key_path in &unknown_keys {
        ui::warn(&format!(
            "{}, ignored ({display})",
            super::validation::describe_unknown_key(key_path)
        ));
    }

    reject_relative_paths(&config, &display)?;

    Ok(Some(config))
}

/// Refuse relative path entries, at `config set --local` and again at load.
///
/// In `config.toml` a relative path anchors to `~/.config/cplt/`, which is
/// meaningless here; anchoring to the repo instead would reintroduce the
/// symlink-repointing hazard `resolve_repo_allow_path` exists to close, this
/// time repointable by the agent between sessions rather than only by a commit.
fn reject_relative_paths(config: &Config, display: &str) -> Result<(), ConfigError> {
    for (key, values) in path_valued(config) {
        for value in values {
            if !(value.starts_with('/') || value.starts_with('~')) {
                return Err(ConfigError::Validation(format!(
                    "{display}: {key} entry {value:?} is relative — \
                     local config accepts absolute and ~/ paths only"
                )));
            }
        }
    }
    Ok(())
}

/// Validate a local config document: everything `config.toml` must satisfy,
/// plus the absolute-paths-only rule. The `[local]` header needs no stripping —
/// [`Config`] ignores unknown tables, and the loader strips it for real.
pub fn validate_local_document(doc: &toml_edit::DocumentMut) -> Result<(), ConfigError> {
    super::editing::validate_global_document(doc)?;
    reject_relative_paths(&Config::parse(&doc.to_string())?, "local config")
}

/// Stamp the `[local]` header onto a document about to be written.
///
/// `remote` is written through [`crate::trust::canonical_remote`], the exact
/// function the loader compares against, so a freshly written file never trips
/// its own staleness wire. `written_at` and `path` are refreshed on every
/// write; a `config set --local` in a checkout whose origin has changed is
/// therefore also how the user re-adopts a file the tripwire stopped.
pub fn stamp_local_header(doc: &mut toml_edit::DocumentMut, project_dir: &Path) {
    let table = doc
        .entry("local")
        .or_insert(toml_edit::Item::Table(toml_edit::Table::new()));
    let Some(table) = table.as_table_mut() else {
        return;
    };
    table.insert("path", toml_edit::value(canonical_key(project_dir)));
    table.insert(
        "remote",
        toml_edit::value(crate::trust::canonical_remote(project_dir).unwrap_or_default()),
    );
    table.insert("written_at", toml_edit::value(crate::trust::now_iso8601()));
}

/// Every file under `local/`, as `(file, recorded [local] path)`.
///
/// The recorded path is empty when the file has no header or cannot be read —
/// `config local list` still shows the file, since an unreadable orphan is
/// exactly what a user needs to be told about.
pub fn list_local() -> Vec<(PathBuf, String)> {
    let Some(dir) = local_dir() else {
        return Vec::new();
    };
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return Vec::new();
    };
    let mut out: Vec<(PathBuf, String)> = entries
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "toml"))
        .map(|path| {
            let recorded = std::fs::read_to_string(&path)
                .ok()
                .and_then(|raw| raw.parse::<toml::Table>().ok())
                .and_then(|root| Some(root.get("local")?.get("path")?.as_str()?.to_string()))
                .unwrap_or_default();
            (path, recorded)
        })
        .collect();
    out.sort();
    out
}

/// Whether the recorded remote disagrees with the current `origin`; returns the
/// recorded value when it does.
///
/// This is a tripwire, not authentication. An attacker who controls the path
/// can set `origin` to match too — but an attacker who controls the path
/// already controls the user's checkout. What it catches is the honest case: a
/// different repository now lives where the grants were made, so the grants are
/// stale and must not apply.
///
/// An empty recorded remote means the file never claimed one (a repo with no
/// origin), so there is nothing to trip.
///
/// Both sides are normalized before comparing. `current` already is (it comes
/// from [`crate::trust::canonical_remote`]), but the recorded side is whatever
/// is in the file: a hand-written `https://github.com/x/y.git` is the same
/// remote and must not trip the wire. Normalizing at READ also means a future
/// change to `normalize_remote_url` cannot silently disarm every file already
/// on disk — which it would if the writer were the only normalizer.
fn remote_mismatch<'a>(recorded: &'a str, current: Option<&str>) -> Option<&'a str> {
    if recorded.is_empty() {
        return None;
    }
    let normalized = crate::trust::normalize_remote_url(recorded);
    if current.map(crate::trust::normalize_remote_url) == Some(normalized) {
        None
    } else {
        Some(recorded)
    }
}

impl Config {
    /// Take every value the local config sets, over `self`.
    ///
    /// `Option` fields: local when `Some`, so an unset local key falls through to
    /// global. List fields: union, as config and CLI already are.
    ///
    /// Two list-shaped keys are the stated exception to the union rule:
    /// `proxy.allow_private_domains` and `proxy.upstream_no_proxy` are
    /// `Option<Vec<String>>`, and they REPLACE. `None` (key absent) and
    /// `Some(vec![])` (key present and empty) are distinguishable there and
    /// mean different things, and replacing is the only semantics that lets a
    /// local file *narrow* either list. Both narrow in the tightening
    /// direction — fewer domains reachable without the proxy, more traffic
    /// forced through the corporate proxy — so a union would remove the one
    /// safe edit a per-repo file can make to them. #340's "lists union" holds
    /// for every `Vec<T>` key; these two are `Option<Vec<T>>` and do not.
    ///
    /// Booleans do NOT get their answer from here — they run the registry ladder in
    /// `registry.rs`, which sees local and global as separate layers so it can name
    /// the one a value came from. Overlaying them anyway is harmless (the ladder
    /// consults local first, so the overlaid value only shows through where local
    /// is silent) and keeps this one function the whole story for scalars.
    #[must_use]
    pub(super) fn overlay(&self, local: &Config) -> Config {
        macro_rules! take_set {
            ($out:expr, $loc:expr, $($f:ident),+ $(,)?) => {
                $( if $loc.$f.is_some() { $out.$f = $loc.$f.clone(); } )+
            };
        }
        macro_rules! union_lists {
            ($out:expr, $loc:expr, $($f:ident),+ $(,)?) => {
                $( for v in &$loc.$f {
                    if !$out.$f.contains(v) { $out.$f.push(v.clone()); }
                } )+
            };
        }

        // Anti-drift guard. Every struct `overlay` merges is destructured here
        // without `..`, so adding a field to any of them fails to COMPILE until
        // this function says what to do with it. A field silently dropped from
        // the overlay would fall back to global — for a tightening key, a
        // silent grant. The bindings are all `_`: this exists for the compiler.
        let Config {
            config_version: _,
            proxy:
                super::types::ProxyConfig {
                    enabled: _,
                    forced: _,
                    port: _,
                    blocked_domains: _,
                    allowed_domains: _,
                    default_allowlist: _,
                    log_file: _,
                    log_level: _,
                    allow_private_domains: _,
                    timeout: _,
                    upstream: _,
                    upstream_no_proxy: _,
                    subscriptions:
                        super::types::SubscriptionsConfig {
                            refresh: _,
                            blocklists: _,
                        },
                },
            allow:
                super::types::AllowConfig {
                    read: _,
                    write: _,
                    exec: _,
                    socket: _,
                    ports: _,
                    localhost: _,
                },
            deny: super::types::DenyConfig { paths: _ },
            sandbox:
                super::types::SandboxConfig {
                    agent: _,
                    preset: _,
                    validate: _,
                    brief: _,
                    agents_md: _,
                    allow_env_files: _,
                    allow_localhost_any: _,
                    pass_env: _,
                    repo_dirs: _,
                    inherit_env: _,
                    allow_lifecycle_scripts: _,
                    allow_gpg_signing: _,
                    deny_clipboard: _,
                    allow_jvm_attach: _,
                    allow_msbuild: _,
                    gradle_init: _,
                    allow_docker: _,
                    allow_tmp_exec: _,
                    allow_cache_exec: _,
                    allow_cache_exec_any: _,
                    allow_browser: _,
                    keychain_substitute: _,
                    scratch_dir: _,
                    audit: _,
                    use_bubblewrap: _,
                    quiet: _,
                    yes: _,
                    gh_proxy: _,
                    git_push_prevention: _,
                },
            gh_guard:
                super::types::GhGuardConfig {
                    enabled: _,
                    mode: _,
                    scope_check: _,
                    block_auth_token: _,
                    inject_token: _,
                    unknown_command: _,
                    allow_api_write: _,
                },
            git_guard:
                super::types::GitGuardConfig {
                    enabled: _,
                    mode: _,
                    prevent_push: _,
                    prevent_force_push: _,
                    protect_default_branch_only: _,
                    allow_push: _,
                },
        } = local;

        let mut out = self.clone();
        take_set!(out, local, config_version);
        take_set!(
            out.proxy,
            local.proxy,
            enabled,
            forced,
            port,
            blocked_domains,
            allowed_domains,
            default_allowlist,
            log_file,
            log_level,
            allow_private_domains,
            timeout,
            upstream,
            upstream_no_proxy,
        );
        take_set!(out.proxy.subscriptions, local.proxy.subscriptions, refresh);
        union_lists!(
            out.proxy.subscriptions,
            local.proxy.subscriptions,
            blocklists
        );
        union_lists!(
            out.allow,
            local.allow,
            read,
            write,
            exec,
            socket,
            ports,
            localhost
        );
        union_lists!(out.deny, local.deny, paths);
        take_set!(
            out.sandbox,
            local.sandbox,
            agent,
            preset,
            validate,
            brief,
            agents_md,
            allow_env_files,
            allow_localhost_any,
            inherit_env,
            allow_lifecycle_scripts,
            allow_gpg_signing,
            deny_clipboard,
            allow_jvm_attach,
            allow_msbuild,
            gradle_init,
            allow_docker,
            allow_tmp_exec,
            allow_cache_exec_any,
            allow_browser,
            keychain_substitute,
            scratch_dir,
            audit,
            use_bubblewrap,
            quiet,
            yes,
            gh_proxy,
            git_push_prevention,
        );
        // `repo_dirs` unions like every other list, but only local ever holds
        // one: `Config::load_file` clears a global list with a warning, so the
        // union is always `[] ∪ local`. It is spelled as a union anyway so a
        // future layer does not silently drop entries.
        union_lists!(
            out.sandbox,
            local.sandbox,
            pass_env,
            allow_cache_exec,
            repo_dirs
        );
        take_set!(
            out.gh_guard,
            local.gh_guard,
            enabled,
            mode,
            scope_check,
            block_auth_token,
            inject_token,
            unknown_command,
            allow_api_write,
        );
        take_set!(
            out.git_guard,
            local.git_guard,
            enabled,
            mode,
            prevent_push,
            prevent_force_push,
            protect_default_branch_only,
        );
        union_lists!(out.git_guard, local.git_guard, allow_push);
        out
    }
}

#[cfg(test)]
#[allow(clippy::disallowed_methods)] // test code: no unsandboxed parent to protect (#239)
mod tests {
    use super::*;

    fn parse(raw: &str) -> Result<Option<Config>, ConfigError> {
        parse_local(raw, Path::new("/tmp/local.toml"), None, None)
    }

    #[test]
    fn header_is_stripped_and_body_parses() {
        let cfg = parse(
            "[local]\npath = \"/repo\"\nremote = \"\"\nwritten_at = \"now\"\n\
             [sandbox]\nallow_docker = true\n",
        )
        .unwrap()
        .unwrap();
        assert_eq!(cfg.sandbox.allow_docker, Some(true));
    }

    #[test]
    fn missing_header_is_fine() {
        let cfg = parse("[sandbox]\nquiet = true\n").unwrap().unwrap();
        assert_eq!(cfg.sandbox.quiet, Some(true));
    }

    #[test]
    fn malformed_toml_is_an_error() {
        assert!(parse("[sandbox\nquiet = true\n").is_err());
    }

    #[test]
    fn relative_path_is_refused() {
        let err = parse("[allow]\nread = [\"scratch\"]\n").unwrap_err();
        assert!(err.to_string().contains("relative"), "{err}");

        let err = parse("[deny]\npaths = [\"../secrets\"]\n").unwrap_err();
        assert!(err.to_string().contains("relative"), "{err}");
    }

    #[test]
    fn absolute_and_tilde_paths_are_accepted() {
        let cfg = parse("[allow]\nread = [\"/srv/scratch\", \"~/scratch\"]\n")
            .unwrap()
            .unwrap();
        assert_eq!(cfg.allow.read.len(), 2);
    }

    /// `allow_cache_exec` holds directory NAMES and `proxy.upstream` a URL —
    /// neither is a path, so the relative-path rule must not reach them.
    #[test]
    fn non_path_string_keys_are_not_path_checked() {
        let cfg = parse(
            "[sandbox]\nallow_cache_exec = [\"ms-playwright\"]\n\
             [proxy]\nupstream = \"http://proxy.example:8080\"\n",
        )
        .unwrap()
        .unwrap();
        assert_eq!(cfg.sandbox.allow_cache_exec, ["ms-playwright"]);
        assert_eq!(
            cfg.proxy.upstream.as_deref(),
            Some("http://proxy.example:8080")
        );
    }

    #[test]
    fn mismatched_remote_applies_nothing() {
        let applied = parse_local(
            "[local]\nremote = \"github.com/navikt/a\"\n[sandbox]\nallow_docker = true\n",
            Path::new("/tmp/local.toml"),
            Some("github.com/navikt/b".to_string()),
            None,
        )
        .unwrap();
        assert!(applied.is_none(), "a stale remote must apply nothing");
    }

    /// The recorded remote is normalized at READ, not trusted to have been
    /// normalized at write: a hand-written `.git`-suffixed HTTPS URL is the
    /// same remote and must not trip the wire.
    #[test]
    fn a_denormalized_recorded_remote_still_matches() {
        let cfg = parse_local(
            "[local]\nremote = \"https://GitHub.com/navikt/a.git\"\n\
             [sandbox]\nallow_docker = true\n",
            Path::new("/tmp/local.toml"),
            Some("github.com/navikt/a".to_string()),
            None,
        )
        .unwrap()
        .unwrap();
        assert_eq!(cfg.sandbox.allow_docker, Some(true));
    }

    #[test]
    fn matching_remote_applies() {
        let cfg = parse_local(
            "[local]\nremote = \"github.com/navikt/a\"\n[sandbox]\nallow_docker = true\n",
            Path::new("/tmp/local.toml"),
            Some("github.com/navikt/a".to_string()),
            None,
        )
        .unwrap()
        .unwrap();
        assert_eq!(cfg.sandbox.allow_docker, Some(true));
    }

    #[test]
    fn overlay_takes_local_scalars_and_unions_lists() {
        let global: Config = toml::from_str(
            "[proxy]\nport = 8080\n[allow]\nread = [\"/a\"]\n[sandbox]\nagent = \"claude\"\n",
        )
        .unwrap();
        let local: Config =
            toml::from_str("[proxy]\nport = 9090\n[allow]\nread = [\"/b\"]\n").unwrap();
        let merged = global.overlay(&local);
        assert_eq!(merged.proxy.port, Some(9090));
        assert_eq!(merged.allow.read, ["/a", "/b"]);
        assert_eq!(merged.sandbox.agent.as_deref(), Some("claude"));
    }

    /// The sharpest coupling in the layer: the writer records the remote, the
    /// loader compares it after normalization. A file cplt just wrote must
    /// apply on the next launch, and a denormalized `origin` must survive the
    /// trip — otherwise the tripwire fires on every launch of a repo whose
    /// remote is spelled `https://GitHub.com/x/y.git`.
    #[test]
    fn a_written_file_loads_back_with_its_remote_intact() {
        let dir = tempfile::tempdir().unwrap();
        let repo = dir.path();
        let git = |args: &[&str]| {
            std::process::Command::new("git")
                .current_dir(repo)
                .env("GIT_CONFIG_GLOBAL", "/dev/null")
                .env("GIT_CONFIG_NOSYSTEM", "1")
                .args(args)
                .output()
                .expect("git should run")
                .status
                .success()
        };
        assert!(git(&["init", "--quiet"]));
        assert!(git(&[
            "remote",
            "add",
            "origin",
            "https://GitHub.com/navikt/spleis.git",
        ]));

        let mut doc = toml_edit::DocumentMut::new();
        stamp_local_header(&mut doc, repo);
        let key = crate::config::lookup_key("sandbox.allow_docker").unwrap();
        super::super::editing::set_value_in_doc(&mut doc, key, "true").unwrap();
        validate_local_document(&doc).unwrap();

        let raw = doc.to_string();
        assert!(
            raw.contains("remote = \"github.com/navikt/spleis\""),
            "the header must record the NORMALIZED remote: {raw}"
        );

        let loaded = parse_local(
            &raw,
            Path::new("/tmp/local.toml"),
            crate::trust::canonical_remote(repo),
            Some(&canonical_key(repo)),
        )
        .unwrap()
        .expect("a file cplt just wrote must apply on the next launch");
        assert_eq!(loaded.sandbox.allow_docker, Some(true));
    }

    /// Relative paths are refused at write time, not only at load: a file that
    /// would fail the next launch must not be written in the first place.
    #[test]
    fn a_relative_path_is_refused_before_it_is_written() {
        let doc = "[allow]\nread = [\"scratch\"]\n"
            .parse::<toml_edit::DocumentMut>()
            .unwrap();
        let err = validate_local_document(&doc).unwrap_err();
        assert!(err.to_string().contains("relative"), "{err}");
    }

    /// `sandbox.repo_dirs` is a path list, so the local layer's absolute-or-`~`
    /// rule must reach it: a relative entry has no anchor a repository root
    /// could live at (`~/.config/cplt/../inner` is not a checkout).
    #[test]
    fn repo_dirs_entries_are_path_checked() {
        let err = parse("[sandbox]\nrepo_dirs = [\"../sibling\"]\n").unwrap_err();
        assert!(err.to_string().contains("relative"), "{err}");

        let cfg = parse("[sandbox]\nrepo_dirs = [\"/repo/inner\", \"~/code/other\"]\n")
            .unwrap()
            .unwrap();
        assert_eq!(cfg.sandbox.repo_dirs.len(), 2);
    }

    /// The overlay must carry the list, or the launch would validate an empty
    /// set and the persisted repositories would silently drop out of scope.
    #[test]
    fn overlay_carries_repo_dirs() {
        let global = Config::default();
        let local: Config = toml::from_str("[sandbox]\nrepo_dirs = [\"/repo/inner\"]\n").unwrap();
        assert_eq!(global.overlay(&local).sandbox.repo_dirs, ["/repo/inner"]);
    }

    #[test]
    fn local_path_follows_the_config_dir() {
        // Same input, same name: the filename is a pure function of the
        // canonical path, like the trust store's fingerprint.
        let a = local_path(Path::new("/definitely/not/here"));
        let b = local_path(Path::new("/definitely/not/here"));
        assert_eq!(a, b);
    }
}
