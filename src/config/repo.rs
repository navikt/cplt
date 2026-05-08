//! Per-repository config overrides (`.cplt.toml`).

use super::error::ConfigError;
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

/// Map a global config key to its repo config location.
/// Returns None if the key is not valid in repo config.
pub fn repo_key_target(key_info: &ConfigKeyInfo) -> Option<RepoKeyTarget> {
    match (key_info.section, key_info.key) {
        // Propose booleans
        ("sandbox", "allow_localhost_any") => Some(RepoKeyTarget::ProposeBool),
        ("sandbox", "allow_jvm_attach") => Some(RepoKeyTarget::ProposeBool),
        ("sandbox", "allow_docker") => Some(RepoKeyTarget::ProposeBool),
        ("sandbox", "allow_tmp_exec") => Some(RepoKeyTarget::ProposeBool),
        ("sandbox", "allow_gpg_signing") => Some(RepoKeyTarget::ProposeBool),
        ("sandbox", "allow_lifecycle_scripts") => Some(RepoKeyTarget::ProposeBool),
        ("sandbox", "allow_browser") => Some(RepoKeyTarget::ProposeBool),
        ("sandbox", "allow_env_files") => Some(RepoKeyTarget::ProposeBool),
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
        ("sandbox", "quiet") => "controls local CLI output, not project sandbox policy",
        ("sandbox", "validate") => "controls local validation behavior, not project policy",
        ("sandbox", "scratch_dir") => "controls local temp handling, not project policy",
        ("sandbox", "inherit_env") => {
            "too dangerous for repo config — would affect all team members"
        }
        ("sandbox", "pass_env") => "environment variables are machine-specific, not project policy",
        ("sandbox", "allow_cache_exec") => "cache paths are machine-specific, not project policy",
        ("sandbox", "allow_cache_exec_any") => {
            "too dangerous for repo config — would affect all team members"
        }
        ("proxy", "enabled") => "proxy settings are machine-specific, not project policy",
        ("proxy", "port") => "proxy port is machine-specific, not project policy",
        ("proxy", "log_file") => "log paths are machine-specific, not project policy",
        ("proxy", "log_level") => "log level is a personal preference, not project policy",
        ("proxy", "blocked_domains") => {
            "domain lists are machine-specific paths, not project policy"
        }
        ("proxy", "allowed_domains") => {
            "domain lists are machine-specific paths, not project policy"
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
                    arr.retain(|v| {
                        v.as_str() != Some(value)
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
                } else if !arr.iter().any(|v| v.as_str() == Some(value)) {
                    arr.push(value);
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
                    arr.retain(|v| v.as_str() != Some(value));
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
                if !arr.iter().any(|v| v.as_str() == Some(value)) {
                    arr.push(value);
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
}
