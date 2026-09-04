//! Per-repository config overrides (`.cplt.toml`).

use super::error::ConfigError;
use super::path::collapse_tilde;
use super::registry::{ConfigKeyInfo, ConfigValueType};

// ── Repo config set support ──────────────────────────────────────────

/// Mapping from global config key to repo config location.
#[derive(Debug, Clone, Copy, PartialEq)]
#[non_exhaustive]
pub enum RepoKeyTarget {
    /// Goes under [propose] as a top-level boolean.
    ProposeBool,
    /// Goes under [propose.allow] as an array.
    ProposeAllow(&'static str),
    /// Goes under [propose.proxy] as an array.
    ProposeProxy(&'static str),
    /// Goes under [deny] directly.
    Deny(&'static str),
}

/// A boolean a repo may propose in `.cplt.toml`, described once.
///
/// One row per `[propose]` boolean, holding everything the four places that
/// used to keep their own copy of this list need: the trust-store key, the
/// global config key it corresponds to, how to read the proposal, and how to
/// apply it. `propose` and `apply` are the only per-key code; the rest of the
/// pipeline iterates.
///
/// Proposals are strictly additive — `apply` only ever sets a flag to `true`,
/// and only for a `Some(true)` proposal whose key the user has approved. A
/// repo can never turn a permission back off.
pub struct ProposeBoolRow {
    /// Name used in `[propose]` and in the trust store.
    pub key: &'static str,
    /// The global config key this proposal corresponds to.
    pub config_key: (&'static str, &'static str),
    pub propose: fn(&crate::repo_config::ProposeSection) -> Option<bool>,
    pub apply: fn(&mut super::types::Resolved),
}

/// Every boolean a `.cplt.toml` may propose.
pub static PROPOSE_BOOLS: &[ProposeBoolRow] = &[
    ProposeBoolRow {
        key: "allow_localhost_any",
        config_key: ("sandbox", "allow_localhost_any"),
        propose: |p| p.allow_localhost_any,
        apply: |r| r.allow_localhost_any = true,
    },
    ProposeBoolRow {
        key: "allow_jvm_attach",
        config_key: ("sandbox", "allow_jvm_attach"),
        propose: |p| p.allow_jvm_attach,
        apply: |r| r.allow_jvm_attach = true,
    },
    ProposeBoolRow {
        key: "allow_msbuild",
        config_key: ("sandbox", "allow_msbuild"),
        propose: |p| p.allow_msbuild,
        apply: |r| r.allow_msbuild = true,
    },
    ProposeBoolRow {
        key: "gradle_init",
        config_key: ("sandbox", "gradle_init"),
        propose: |p| p.gradle_init,
        apply: |r| r.gradle_init = true,
    },
    ProposeBoolRow {
        key: "allow_docker",
        config_key: ("sandbox", "allow_docker"),
        propose: |p| p.allow_docker,
        apply: |r| r.allow_docker = true,
    },
    ProposeBoolRow {
        key: "allow_tmp_exec",
        config_key: ("sandbox", "allow_tmp_exec"),
        propose: |p| p.allow_tmp_exec,
        apply: |r| r.allow_tmp_exec = true,
    },
    ProposeBoolRow {
        key: "allow_gpg_signing",
        config_key: ("sandbox", "allow_gpg_signing"),
        propose: |p| p.allow_gpg_signing,
        apply: |r| r.allow_gpg_signing = true,
    },
    ProposeBoolRow {
        key: "allow_lifecycle_scripts",
        config_key: ("sandbox", "allow_lifecycle_scripts"),
        propose: |p| p.allow_lifecycle_scripts,
        apply: |r| r.allow_lifecycle_scripts = true,
    },
    ProposeBoolRow {
        key: "allow_browser",
        config_key: ("sandbox", "allow_browser"),
        propose: |p| p.allow_browser,
        apply: |r| r.allow_browser = true,
    },
    ProposeBoolRow {
        key: "allow_env_files",
        config_key: ("sandbox", "allow_env_files"),
        propose: |p| p.allow_env_files,
        apply: |r| r.allow_env_files = true,
    },
    // `.cplt.toml` spells these two with the legacy `sandbox.*` config keys, so
    // `config set --repo sandbox.gh_proxy` keeps writing the name a repo file
    // already uses.
    ProposeBoolRow {
        key: "gh_guard",
        config_key: ("sandbox", "gh_proxy"),
        propose: |p| p.gh_guard,
        apply: |r| r.gh_guard.enabled = true,
    },
    ProposeBoolRow {
        key: "git_push_prevention",
        config_key: ("sandbox", "git_push_prevention"),
        propose: |p| p.git_push_prevention,
        apply: |r| r.git_guard.enabled = true,
    },
];

/// Map a global config key to its repo config location.
/// Returns None if the key is not valid in repo config.
pub fn repo_key_target(key_info: &ConfigKeyInfo) -> Option<RepoKeyTarget> {
    if PROPOSE_BOOLS
        .iter()
        .any(|row| row.config_key == (key_info.section, key_info.key))
    {
        return Some(RepoKeyTarget::ProposeBool);
    }
    match (key_info.section, key_info.key) {
        // Propose arrays
        ("allow", "read") => Some(RepoKeyTarget::ProposeAllow("read")),
        ("allow", "write") => Some(RepoKeyTarget::ProposeAllow("write")),
        ("allow", "ports") => Some(RepoKeyTarget::ProposeAllow("ports")),
        ("allow", "localhost") => Some(RepoKeyTarget::ProposeAllow("localhost")),
        // Propose proxy
        ("proxy", "allow_private_domains") => {
            Some(RepoKeyTarget::ProposeProxy("allow_private_domains"))
        }
        // Deny section
        ("deny", "paths") => Some(RepoKeyTarget::Deny("paths")),
        ("deny", "env") => Some(RepoKeyTarget::Deny("env")),
        // Everything else is not valid in repo config
        _ => None,
    }
}

/// Keys that are valid in repo config but rejected — provides clear error messages.
pub fn repo_key_rejection_reason(key_info: &ConfigKeyInfo) -> &'static str {
    match (key_info.section, key_info.key) {
        ("sandbox", "preset") => {
            "composes multiple dangerous permissions (docker, tmp exec, ...). \
             A repo must request individual keys so each can be reviewed and trusted"
        }
        ("sandbox", "quiet") => "controls local CLI output, not project sandbox policy",
        ("sandbox", "validate") => "controls local validation behavior, not project policy",
        ("sandbox", "scratch_dir") => "controls local temp handling, not project policy",
        ("sandbox", "brief") => "controls local agent-context output, not project policy",
        ("sandbox", "agents_md") => {
            "a repo must not be able to make cplt write into its own AGENTS.md"
        }
        ("sandbox", "audit") => "controls local CLI output, not project sandbox policy",
        ("sandbox", "use_bubblewrap") => {
            "depends on bwrap being installed locally, not project policy"
        }
        ("sandbox", "inherit_env") => {
            "too dangerous for repo config, it would affect all team members"
        }
        ("sandbox", "pass_env") => "environment variables are machine-specific, not project policy",
        ("allow", "exec") => {
            "exec grants are machine-specific paths, and a repo must not be able to make \
             one of its own trees executable"
        }
        ("sandbox", "allow_cache_exec") => "cache paths are machine-specific, not project policy",
        ("sandbox", "allow_cache_exec_any") => {
            "too dangerous for repo config, it would affect all team members"
        }
        ("proxy", "enabled") => "proxy settings are machine-specific, not project policy",
        ("proxy", "forced") => "proxy settings are machine-specific, not project policy",
        ("proxy", "port") => "proxy port is machine-specific, not project policy",
        ("proxy", "log_file") => "log paths are machine-specific, not project policy",
        ("proxy", "log_level") => "log level is a personal preference, not project policy",
        ("proxy", "blocked_domains") => {
            "domain lists are machine-specific paths, not project policy"
        }
        ("proxy", "allowed_domains") => {
            "domain lists are machine-specific paths, not project policy"
        }
        ("proxy", "default_allowlist") => "proxy settings are machine-specific, not project policy",
        // Blocklist subscriptions (issue #144) are GLOBAL-only: a malicious repo
        // must not be able to point cplt at an attacker-controlled list. The
        // repo config schema has no [proxy] table, so a `.cplt.toml` cannot even
        // express these — this mirrors proxy.forced's rejection for the
        // `config set --repo` path.
        ("proxy", "subscriptions")
        | ("proxy", "subscriptions.blocklists")
        | ("proxy", "subscriptions.refresh") => {
            "subscription sources are machine/network-specific and security-sensitive, \
             not project policy. A repo must not be able to add a subscription"
        }
        ("proxy", "upstream") => {
            "the corporate proxy is machine/network-specific, not project policy"
        }
        ("proxy", "upstream_no_proxy") => {
            "the corporate proxy is machine/network-specific, not project policy"
        }
        _ => "not supported in repo config",
    }
}

/// Set a value in a repo config (.cplt.toml) document.
pub fn set_repo_value_in_doc(
    doc: &mut toml_edit::DocumentMut,
    key_info: &ConfigKeyInfo,
    target: RepoKeyTarget,
    value: &str,
    unset: bool,
) -> Result<(), ConfigError> {
    use toml_edit::{Array, Item, Table, Value};

    match target {
        RepoKeyTarget::ProposeBool => {
            let section = doc
                .entry("propose")
                .or_insert(Item::Table(Table::new()))
                .as_table_mut()
                .ok_or_else(|| ConfigError::Validation("invalid [propose] section".to_string()))?;

            if unset {
                section.remove(key_info.key);
            } else {
                let b: bool = value.parse().map_err(|_| {
                    ConfigError::Validation(format!("expected 'true' or 'false', got '{value}'"))
                })?;
                if !b {
                    return Err(ConfigError::Validation(format!(
                        "{}.{} = false has no effect in repo config.\n  \
                         Repo config can only request enabling permissions.\n  \
                         Use --unset to remove it.",
                        key_info.section, key_info.key
                    )));
                }
                section[key_info.key] = toml_edit::value(b);
            }
        }
        RepoKeyTarget::ProposeAllow(array_key) => {
            let propose = doc
                .entry("propose")
                .or_insert(Item::Table(Table::new()))
                .as_table_mut()
                .ok_or_else(|| ConfigError::Validation("invalid [propose] section".to_string()))?;
            let allow = propose
                .entry("allow")
                .or_insert(Item::Table(Table::new()))
                .as_table_mut()
                .ok_or_else(|| {
                    ConfigError::Validation("invalid [propose.allow] section".to_string())
                })?;

            if unset {
                if value.is_empty() {
                    // --unset without value: remove the entire array
                    allow.remove(array_key);
                } else if let Some(arr) = allow.get_mut(array_key).and_then(|v| v.as_array_mut()) {
                    // Match both raw value and collapsed form for removal
                    let collapsed = collapse_tilde(value);
                    arr.retain(|v| {
                        let s = v.as_str().unwrap_or_default();
                        s != value
                            && s != collapsed
                            && v.as_integer().map(|i| i.to_string()).as_deref() != Some(value)
                    });
                    if arr.is_empty() {
                        allow.remove(array_key);
                    }
                } else {
                    allow.remove(array_key);
                }
            } else {
                let arr = allow
                    .entry(array_key)
                    .or_insert(Item::Value(Value::Array(Array::new())))
                    .as_array_mut()
                    .ok_or_else(|| ConfigError::Validation("expected array".to_string()))?;

                // Parse as u16 for port arrays, string otherwise
                if key_info.value_type == ConfigValueType::U16Array {
                    let port: u16 = value.parse().map_err(|_| {
                        ConfigError::Validation(format!(
                            "expected port number (1-65535), got '{value}'"
                        ))
                    })?;
                    if !arr.iter().any(|v| v.as_integer() == Some(i64::from(port))) {
                        arr.push(i64::from(port));
                    }
                } else {
                    // For path-type arrays (read, write), store with ~ for portability
                    let stored = if array_key == "read" || array_key == "write" {
                        collapse_tilde(value)
                    } else {
                        value.to_string()
                    };
                    // Check both forms to avoid duplicates from pre-collapse entries
                    let already_present = arr
                        .iter()
                        .any(|v| v.as_str().is_some_and(|s| s == stored || s == value));
                    if !already_present {
                        arr.push(stored.as_str());
                    }
                }
            }
        }
        RepoKeyTarget::ProposeProxy(array_key) => {
            let propose = doc
                .entry("propose")
                .or_insert(Item::Table(Table::new()))
                .as_table_mut()
                .ok_or_else(|| ConfigError::Validation("invalid [propose] section".to_string()))?;
            let proxy = propose
                .entry("proxy")
                .or_insert(Item::Table(Table::new()))
                .as_table_mut()
                .ok_or_else(|| {
                    ConfigError::Validation("invalid [propose.proxy] section".to_string())
                })?;

            if unset {
                if value.is_empty() {
                    // --unset without value: remove the entire array
                    proxy.remove(array_key);
                } else if let Some(arr) = proxy.get_mut(array_key).and_then(|v| v.as_array_mut()) {
                    arr.retain(|v| v.as_str() != Some(value));
                    if arr.is_empty() {
                        proxy.remove(array_key);
                    }
                } else {
                    proxy.remove(array_key);
                }
            } else {
                let arr = proxy
                    .entry(array_key)
                    .or_insert(Item::Value(Value::Array(Array::new())))
                    .as_array_mut()
                    .ok_or_else(|| ConfigError::Validation("expected array".to_string()))?;
                if !arr.iter().any(|v| v.as_str() == Some(value)) {
                    arr.push(value);
                }
            }
        }
        RepoKeyTarget::Deny(array_key) => {
            let section = doc
                .entry("deny")
                .or_insert(Item::Table(Table::new()))
                .as_table_mut()
                .ok_or_else(|| ConfigError::Validation("invalid [deny] section".to_string()))?;

            if unset {
                if value.is_empty() {
                    // --unset without value: remove the entire array
                    section.remove(array_key);
                } else if let Some(arr) = section.get_mut(array_key).and_then(|v| v.as_array_mut())
                {
                    // Match both raw value and collapsed form for removal
                    let collapsed = collapse_tilde(value);
                    arr.retain(|v| {
                        let s = v.as_str().unwrap_or_default();
                        s != value && s != collapsed
                    });
                    if arr.is_empty() {
                        section.remove(array_key);
                    }
                } else {
                    section.remove(array_key);
                }
            } else {
                let arr = section
                    .entry(array_key)
                    .or_insert(Item::Value(Value::Array(Array::new())))
                    .as_array_mut()
                    .ok_or_else(|| ConfigError::Validation("expected array".to_string()))?;
                // For path arrays, store with ~ for portability
                let stored = if array_key == "paths" {
                    collapse_tilde(value)
                } else {
                    value.to_string()
                };
                // Check both forms to avoid duplicates from pre-collapse entries
                let already_present = arr
                    .iter()
                    .any(|v| v.as_str().is_some_and(|s| s == stored || s == value));
                if !already_present {
                    arr.push(stored.as_str());
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::lookup_key;

    #[test]
    fn repo_key_target_propose_booleans() {
        let info = lookup_key("sandbox.allow_jvm_attach").unwrap();
        assert_eq!(repo_key_target(info), Some(RepoKeyTarget::ProposeBool));
    }

    #[test]
    fn repo_key_target_propose_allow_arrays() {
        let info = lookup_key("allow.read").unwrap();
        assert_eq!(
            repo_key_target(info),
            Some(RepoKeyTarget::ProposeAllow("read"))
        );
    }

    #[test]
    fn repo_key_target_deny() {
        let info = lookup_key("deny.paths").unwrap();
        assert_eq!(repo_key_target(info), Some(RepoKeyTarget::Deny("paths")));
    }

    #[test]
    fn repo_key_target_rejected_keys() {
        let info = lookup_key("sandbox.quiet").unwrap();
        assert_eq!(repo_key_target(info), None);
    }

    #[test]
    fn set_repo_value_propose_bool() {
        let mut doc = "".parse::<toml_edit::DocumentMut>().unwrap();
        let info = lookup_key("sandbox.allow_jvm_attach").unwrap();
        let target = repo_key_target(info).unwrap();
        set_repo_value_in_doc(&mut doc, info, target, "true", false).unwrap();
        let result = doc.to_string();
        assert!(result.contains("[propose]"));
        assert!(result.contains("allow_jvm_attach = true"));
    }

    #[test]
    fn set_repo_value_propose_allow() {
        let mut doc = "".parse::<toml_edit::DocumentMut>().unwrap();
        let info = lookup_key("allow.read").unwrap();
        let target = repo_key_target(info).unwrap();
        set_repo_value_in_doc(&mut doc, info, target, "/tmp/test", false).unwrap();
        let result = doc.to_string();
        assert!(result.contains("[propose.allow]"));
        assert!(result.contains("/tmp/test"));
    }

    #[test]
    fn set_repo_value_deny() {
        let mut doc = "".parse::<toml_edit::DocumentMut>().unwrap();
        let info = lookup_key("deny.paths").unwrap();
        let target = repo_key_target(info).unwrap();
        set_repo_value_in_doc(&mut doc, info, target, "/tmp/secret", false).unwrap();
        let result = doc.to_string();
        assert!(result.contains("[deny]"));
        assert!(result.contains("/tmp/secret"));
    }

    #[test]
    fn set_repo_value_unset() {
        let mut doc = "[propose]\nallow_jvm_attach = true\n"
            .parse::<toml_edit::DocumentMut>()
            .unwrap();
        let info = lookup_key("sandbox.allow_jvm_attach").unwrap();
        let target = repo_key_target(info).unwrap();
        set_repo_value_in_doc(&mut doc, info, target, "", true).unwrap();
        let result = doc.to_string();
        assert!(!result.contains("allow_jvm_attach"));
    }

    #[test]
    fn set_repo_value_rejects_false_bool() {
        let mut doc = "".parse::<toml_edit::DocumentMut>().unwrap();
        let info = lookup_key("sandbox.allow_jvm_attach").unwrap();
        let target = repo_key_target(info).unwrap();
        let result = set_repo_value_in_doc(&mut doc, info, target, "false", false);
        assert!(result.is_err());
    }

    #[test]
    fn set_repo_value_propose_proxy() {
        let mut doc = "".parse::<toml_edit::DocumentMut>().unwrap();
        let info = lookup_key("proxy.allow_private_domains").unwrap();
        let target = repo_key_target(info).unwrap();
        set_repo_value_in_doc(&mut doc, info, target, "intern.nav.no", false).unwrap();
        let result = doc.to_string();
        assert!(result.contains("[propose.proxy]"));
        assert!(result.contains("intern.nav.no"));
    }

    #[test]
    fn set_repo_value_propose_port() {
        let mut doc = "".parse::<toml_edit::DocumentMut>().unwrap();
        let info = lookup_key("allow.ports").unwrap();
        let target = repo_key_target(info).unwrap();
        set_repo_value_in_doc(&mut doc, info, target, "8080", false).unwrap();
        let result = doc.to_string();
        assert!(result.contains("8080"));
    }

    #[test]
    fn set_repo_value_collapses_home_paths_for_read() {
        let home = std::env::var("HOME").unwrap();
        let abs_path = format!("{home}/.config/gcloud/application_default_credentials.json");
        let mut doc = "".parse::<toml_edit::DocumentMut>().unwrap();
        let info = lookup_key("allow.read").unwrap();
        let target = repo_key_target(info).unwrap();
        set_repo_value_in_doc(&mut doc, info, target, &abs_path, false).unwrap();
        let result = doc.to_string();
        assert!(
            result.contains("~/.config/gcloud/application_default_credentials.json"),
            "absolute home path should be collapsed to ~/ form, got: {result}"
        );
        assert!(
            !result.contains(&home),
            "absolute home prefix should not remain in output"
        );
    }

    #[test]
    fn set_repo_value_collapses_home_paths_for_write() {
        let home = std::env::var("HOME").unwrap();
        let abs_path = format!("{home}/some/dir");
        let mut doc = "".parse::<toml_edit::DocumentMut>().unwrap();
        let info = lookup_key("allow.write").unwrap();
        let target = repo_key_target(info).unwrap();
        set_repo_value_in_doc(&mut doc, info, target, &abs_path, false).unwrap();
        let result = doc.to_string();
        assert!(
            result.contains("~/some/dir"),
            "should collapse to ~/some/dir, got: {result}"
        );
    }

    #[test]
    fn set_repo_value_does_not_collapse_non_home_paths() {
        let mut doc = "".parse::<toml_edit::DocumentMut>().unwrap();
        let info = lookup_key("allow.read").unwrap();
        let target = repo_key_target(info).unwrap();
        set_repo_value_in_doc(&mut doc, info, target, "/tmp/something", false).unwrap();
        let result = doc.to_string();
        assert!(
            result.contains("/tmp/something"),
            "non-home path should be stored as-is"
        );
    }

    #[test]
    fn set_repo_value_unset_matches_collapsed_form() {
        let home = std::env::var("HOME").unwrap();
        let abs_path = format!("{home}/.config/gcloud/creds.json");
        // First set a collapsed value
        let mut doc = "".parse::<toml_edit::DocumentMut>().unwrap();
        let info = lookup_key("allow.read").unwrap();
        let target = repo_key_target(info).unwrap();
        set_repo_value_in_doc(&mut doc, info, target, &abs_path, false).unwrap();
        assert!(doc.to_string().contains("~/.config/gcloud/creds.json"));

        // Now unset using the absolute path (as shell would expand it)
        set_repo_value_in_doc(&mut doc, info, target, &abs_path, true).unwrap();
        let result = doc.to_string();
        assert!(
            !result.contains("creds.json"),
            "unset with absolute path should remove collapsed entry, got: {result}"
        );
    }

    #[test]
    fn set_repo_value_deny_collapses_home_paths() {
        let home = std::env::var("HOME").unwrap();
        let abs_path = format!("{home}/.ssh");
        let mut doc = "".parse::<toml_edit::DocumentMut>().unwrap();
        let info = lookup_key("deny.paths").unwrap();
        let target = repo_key_target(info).unwrap();
        set_repo_value_in_doc(&mut doc, info, target, &abs_path, false).unwrap();
        let result = doc.to_string();
        assert!(
            result.contains("~/.ssh"),
            "deny paths should collapse home prefix, got: {result}"
        );
    }

    #[test]
    fn set_repo_value_no_duplicate_when_legacy_absolute_exists() {
        let home = std::env::var("HOME").unwrap();
        let abs_path = format!("{home}/.config/gcloud/creds.json");
        // Simulate a legacy entry with absolute path already in the doc
        let initial = format!("[propose.allow]\nread = [\"{abs_path}\"]\n");
        let mut doc = initial.parse::<toml_edit::DocumentMut>().unwrap();
        let info = lookup_key("allow.read").unwrap();
        let target = repo_key_target(info).unwrap();
        // Adding the same path again should NOT create a duplicate
        set_repo_value_in_doc(&mut doc, info, target, &abs_path, false).unwrap();
        let result = doc.to_string();
        let count = result.matches("creds.json").count();
        assert_eq!(
            count, 1,
            "should not duplicate when legacy absolute entry exists, got: {result}"
        );
    }
}
