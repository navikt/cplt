//! Unknown-key detection and typo suggestions.

use super::types::Config;

// ── Config validation (unknown key detection) ────────────────────────

/// Valid keys for each TOML section. Used by `validate_config` to detect typos.
const VALID_PROXY_KEYS: &[&str] = &[
    "enabled",
    "port",
    "blocked_domains",
    "allowed_domains",
    "log_file",
    "log_level",
    "allow_private_domains",
];
const VALID_ALLOW_KEYS: &[&str] = &["read", "write", "socket", "ports", "localhost"];
const VALID_DENY_KEYS: &[&str] = &["paths"];
const VALID_SANDBOX_KEYS: &[&str] = &[
    "agent",
    "validate",
    "allow_env_files",
    "allow_localhost_any",
    "pass_env",
    "inherit_env",
    "allow_lifecycle_scripts",
    "allow_gpg_signing",
    "allow_jvm_attach",
    "allow_docker",
    "allow_tmp_exec",
    "scratch_dir",
    "quiet",
    "allow_cache_exec",
    "allow_cache_exec_any",
    "allow_browser",
    // Deprecated — use [gh_guard] and [git_guard] sections instead.
    "gh_proxy",
    "git_push_prevention",
];
const VALID_GH_GUARD_KEYS: &[&str] = &[
    "enabled",
    "mode",
    "scope_check",
    "block_auth_token",
    "inject_token",
    "unknown_command",
    "allow_api_write",
];
const VALID_GIT_GUARD_KEYS: &[&str] = &[
    "enabled",
    "mode",
    "prevent_push",
    "prevent_force_push",
    "protect_default_branch_only",
    "allow_push",
];
const VALID_AUDIT_KEYS: &[&str] = &["enabled", "destination", "level", "format"];
const VALID_SECTIONS: &[&str] = &[
    "proxy",
    "allow",
    "deny",
    "sandbox",
    "gh_guard",
    "git_guard",
    "audit",
    "config_version",
];

/// A single validation diagnostic.
#[derive(Debug)]
pub struct ConfigDiagnostic {
    pub level: DiagnosticLevel,
    pub message: String,
}

#[derive(Debug, PartialEq)]
#[non_exhaustive]
pub enum DiagnosticLevel {
    Error,
    Warning,
}

impl std::fmt::Display for ConfigDiagnostic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let prefix = match self.level {
            DiagnosticLevel::Error => "error",
            DiagnosticLevel::Warning => "warning",
        };
        write!(f, "{prefix}: {}", self.message)
    }
}

/// Validate a TOML config string for unknown keys and dangerous settings.
///
/// This is stricter than runtime loading — runtime silently ignores unknown keys
/// for forward compatibility, but `config validate` reports them so typos like
/// `inherit_evn = true` don't silently fail.
pub fn validate_config(toml_text: &str) -> Vec<ConfigDiagnostic> {
    let mut diagnostics = Vec::new();

    // First check: is it valid TOML at all?
    let table: toml::Table = match toml_text.parse() {
        Ok(t) => t,
        Err(e) => {
            diagnostics.push(ConfigDiagnostic {
                level: DiagnosticLevel::Error,
                message: format!("invalid TOML syntax: {e}"),
            });
            return diagnostics;
        }
    };

    // Check top-level keys (should all be known sections or scalar keys)
    for key in table.keys() {
        if !VALID_SECTIONS.contains(&key.as_str()) {
            let suggestion = suggest_key(key, VALID_SECTIONS);
            let hint = suggestion
                .map(|s| format!(" (did you mean '{s}'?)"))
                .unwrap_or_default();
            diagnostics.push(ConfigDiagnostic {
                level: DiagnosticLevel::Error,
                message: format!("unknown top-level key '{key}'{hint}"),
            });
        }
    }

    // Check keys within each known section
    check_section_keys(&table, "proxy", VALID_PROXY_KEYS, &mut diagnostics);
    check_section_keys(&table, "allow", VALID_ALLOW_KEYS, &mut diagnostics);
    check_section_keys(&table, "deny", VALID_DENY_KEYS, &mut diagnostics);
    check_section_keys(&table, "sandbox", VALID_SANDBOX_KEYS, &mut diagnostics);
    check_section_keys(&table, "gh_guard", VALID_GH_GUARD_KEYS, &mut diagnostics);
    check_section_keys(&table, "git_guard", VALID_GIT_GUARD_KEYS, &mut diagnostics);
    check_section_keys(&table, "audit", VALID_AUDIT_KEYS, &mut diagnostics);

    // Also verify it deserializes correctly (catches type errors)
    if diagnostics
        .iter()
        .all(|d| d.level != DiagnosticLevel::Error)
        && let Err(e) = toml::from_str::<Config>(toml_text)
    {
        diagnostics.push(ConfigDiagnostic {
            level: DiagnosticLevel::Error,
            message: format!("type error: {e}"),
        });
    }

    // Warn about dangerous settings
    if let Some(sandbox) = table.get("sandbox").and_then(|v| v.as_table()) {
        if sandbox.get("inherit_env").and_then(toml::Value::as_bool) == Some(true) {
            diagnostics.push(ConfigDiagnostic {
                level: DiagnosticLevel::Warning,
                message: "sandbox.inherit_env = true: all env vars will be exposed (DANGEROUS)"
                    .to_string(),
            });
        }
        if sandbox.get("allow_tmp_exec").and_then(toml::Value::as_bool) == Some(true) {
            diagnostics.push(ConfigDiagnostic {
                level: DiagnosticLevel::Warning,
                message: "sandbox.allow_tmp_exec = true: exec from temp dirs enabled (DANGEROUS)"
                    .to_string(),
            });
        }
        if sandbox
            .get("allow_cache_exec_any")
            .and_then(toml::Value::as_bool)
            == Some(true)
        {
            diagnostics.push(ConfigDiagnostic {
                level: DiagnosticLevel::Warning,
                message: "sandbox.allow_cache_exec_any = true: exec from all ~/Library/Caches enabled (DANGEROUS)"
                    .to_string(),
            });
        }
        if sandbox
            .get("allow_gpg_signing")
            .and_then(toml::Value::as_bool)
            == Some(true)
        {
            diagnostics.push(ConfigDiagnostic {
                level: DiagnosticLevel::Warning,
                message: "sandbox.allow_gpg_signing = true: GPG agent socket exposed — signing requests possible (DANGEROUS)"
                    .to_string(),
            });
        }
        if sandbox.get("allow_docker").and_then(toml::Value::as_bool) == Some(true) {
            diagnostics.push(ConfigDiagnostic {
                level: DiagnosticLevel::Warning,
                message: "sandbox.allow_docker = true: Docker socket exposed — container mounts bypass sandbox (DANGEROUS)"
                    .to_string(),
            });
        }
    }

    diagnostics
}

fn check_section_keys(
    table: &toml::Table,
    section: &str,
    valid_keys: &[&str],
    diagnostics: &mut Vec<ConfigDiagnostic>,
) {
    let Some(section_value) = table.get(section) else {
        return;
    };
    let Some(section_table) = section_value.as_table() else {
        diagnostics.push(ConfigDiagnostic {
            level: DiagnosticLevel::Error,
            message: format!(
                "[{section}] must be a table, not a {}",
                value_type_name(section_value)
            ),
        });
        return;
    };

    for key in section_table.keys() {
        if !valid_keys.contains(&key.as_str()) {
            let suggestion = suggest_key(key, valid_keys);
            let hint = suggestion
                .map(|s| format!(" (did you mean '{s}'?)"))
                .unwrap_or_default();
            diagnostics.push(ConfigDiagnostic {
                level: DiagnosticLevel::Error,
                message: format!("unknown key '{key}' in [{section}]{hint}"),
            });
        }
    }
}

/// Suggest the closest valid key using simple edit distance.
pub(super) fn suggest_key<'a>(input: &str, valid: &[&'a str]) -> Option<&'a str> {
    let input_lower = input.to_lowercase();
    valid
        .iter()
        .filter_map(|&candidate| {
            let dist = edit_distance(&input_lower, candidate);
            // Only suggest if reasonably close (at most 3 edits and less than half the key length)
            if dist <= 3 && dist < candidate.len() / 2 + 1 {
                Some((candidate, dist))
            } else {
                None
            }
        })
        .min_by_key(|(_, d)| *d)
        .map(|(s, _)| s)
}

/// Simple Levenshtein edit distance.
fn edit_distance(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let mut matrix = vec![vec![0usize; b.len() + 1]; a.len() + 1];

    for (i, row) in matrix.iter_mut().enumerate() {
        row[0] = i;
    }
    for (j, val) in matrix[0].iter_mut().enumerate() {
        *val = j;
    }
    for (i, a_char) in a.iter().enumerate() {
        for (j, b_char) in b.iter().enumerate() {
            let cost = usize::from(a_char != b_char);
            matrix[i + 1][j + 1] = (matrix[i][j + 1] + 1)
                .min(matrix[i + 1][j] + 1)
                .min(matrix[i][j] + cost);
        }
    }
    matrix[a.len()][b.len()]
}

fn value_type_name(v: &toml::Value) -> &'static str {
    match v {
        toml::Value::String(_) => "string",
        toml::Value::Integer(_) => "integer",
        toml::Value::Float(_) => "float",
        toml::Value::Boolean(_) => "boolean",
        toml::Value::Datetime(_) => "datetime",
        toml::Value::Array(_) => "array",
        toml::Value::Table(_) => "table",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::path::default_config_contents;
    use crate::config::registry::CONFIG_KEYS;

    #[test]
    fn validate_valid_config_no_diagnostics() {
        let toml = r#"
[proxy]
enabled = true
port = 9090

[allow]
read = ["/opt/homebrew"]
ports = [8080]

[deny]
paths = ["~/.config/gcloud"]

[sandbox]
validate = true
quiet = false
"#;
        let diagnostics = validate_config(toml);
        assert!(
            diagnostics.is_empty(),
            "valid config should have no diagnostics: {diagnostics:?}"
        );
    }

    #[test]
    fn validate_empty_config_no_diagnostics() {
        let diagnostics = validate_config("");
        assert!(diagnostics.is_empty());
    }

    #[test]
    fn validate_detects_unknown_top_level_section() {
        let toml = "[proxxy]\nenabled = true\n";
        let diagnostics = validate_config(toml);
        assert!(
            diagnostics.iter().any(|d| {
                d.level == DiagnosticLevel::Error
                    && d.message.contains("unknown top-level key 'proxxy'")
            }),
            "should detect unknown top-level key: {diagnostics:?}"
        );
    }

    #[test]
    fn validate_suggests_similar_section() {
        let toml = "[sandox]\nquiet = true\n";
        let diagnostics = validate_config(toml);
        let msg = diagnostics
            .iter()
            .find(|d| d.message.contains("sandox"))
            .unwrap();
        assert!(
            msg.message.contains("did you mean 'sandbox'?"),
            "should suggest: {}",
            msg.message
        );
    }

    #[test]
    fn validate_detects_unknown_key_in_section() {
        let toml = "[sandbox]\ninherit_evn = true\n";
        let diagnostics = validate_config(toml);
        assert!(
            diagnostics.iter().any(|d| {
                d.level == DiagnosticLevel::Error && d.message.contains("unknown key 'inherit_evn'")
            }),
            "should detect typo: {diagnostics:?}"
        );
    }

    #[test]
    fn validate_suggests_similar_key() {
        let toml = "[sandbox]\ninherit_evn = true\n";
        let diagnostics = validate_config(toml);
        let msg = diagnostics
            .iter()
            .find(|d| d.message.contains("inherit_evn"))
            .unwrap();
        assert!(
            msg.message.contains("did you mean 'inherit_env'?"),
            "should suggest: {}",
            msg.message
        );
    }

    #[test]
    fn validate_detects_invalid_toml_syntax() {
        let toml = "[sandbox\nquiet = true\n";
        let diagnostics = validate_config(toml);
        assert!(diagnostics.iter().any(|d| {
            d.level == DiagnosticLevel::Error && d.message.contains("invalid TOML syntax")
        }));
    }

    #[test]
    fn validate_warns_about_dangerous_inherit_env() {
        let toml = "[sandbox]\ninherit_env = true\n";
        let diagnostics = validate_config(toml);
        assert!(
            diagnostics.iter().any(|d| {
                d.level == DiagnosticLevel::Warning && d.message.contains("DANGEROUS")
            }),
            "should warn about dangerous: {diagnostics:?}"
        );
    }

    #[test]
    fn validate_warns_about_dangerous_tmp_exec() {
        let toml = "[sandbox]\nallow_tmp_exec = true\n";
        let diagnostics = validate_config(toml);
        assert!(
            diagnostics.iter().any(|d| {
                d.level == DiagnosticLevel::Warning && d.message.contains("DANGEROUS")
            })
        );
    }

    #[test]
    fn validate_no_warning_for_safe_settings() {
        let toml = "[sandbox]\nquiet = true\nscratch_dir = true\n";
        let diagnostics = validate_config(toml);
        assert!(
            diagnostics.is_empty(),
            "safe settings should have no diagnostics: {diagnostics:?}"
        );
    }

    #[test]
    fn validate_detects_type_error() {
        let toml = "[proxy]\nport = \"not a number\"\n";
        let diagnostics = validate_config(toml);
        assert!(
            diagnostics
                .iter()
                .any(|d| { d.level == DiagnosticLevel::Error && d.message.contains("type error") }),
            "should catch type errors: {diagnostics:?}"
        );
    }

    #[test]
    fn validate_detects_section_used_as_scalar() {
        let toml = "proxy = true\n";
        let diagnostics = validate_config(toml);
        assert!(
            diagnostics.iter().any(|d| {
                d.level == DiagnosticLevel::Error && d.message.contains("must be a table")
            }),
            "should detect section as scalar: {diagnostics:?}"
        );
    }

    #[test]
    fn validate_default_config_template() {
        let contents = default_config_contents();
        let diagnostics = validate_config(&contents);
        assert!(
            diagnostics.is_empty(),
            "default template should validate clean: {diagnostics:?}"
        );
    }

    /// Ensures every valid sandbox/allow key has a CONFIG_KEYS entry and is
    /// mentioned in the default config template. Catches forgotten docs when
    /// adding new config options.
    #[test]
    fn config_keys_cover_all_valid_keys() {
        let template = default_config_contents();

        // Every sandbox key must have a CONFIG_KEYS entry
        for &key in VALID_SANDBOX_KEYS {
            let has_entry = CONFIG_KEYS
                .iter()
                .any(|k| k.section == "sandbox" && k.key == key);
            assert!(
                has_entry,
                "VALID_SANDBOX_KEYS contains '{key}' but CONFIG_KEYS has no sandbox.{key} entry"
            );
        }

        // Every sandbox key must appear in the default config template
        // (except deprecated keys that are documented in their own sections)
        const DEPRECATED_SANDBOX_KEYS: &[&str] = &["gh_proxy", "git_push_prevention"];
        for &key in VALID_SANDBOX_KEYS {
            if DEPRECATED_SANDBOX_KEYS.contains(&key) {
                continue;
            }
            assert!(
                template.contains(key),
                "VALID_SANDBOX_KEYS contains '{key}' but default_config_contents() does not mention it"
            );
        }

        // Every allow key must have a CONFIG_KEYS entry
        for &key in VALID_ALLOW_KEYS {
            let has_entry = CONFIG_KEYS
                .iter()
                .any(|k| k.section == "allow" && k.key == key);
            assert!(
                has_entry,
                "VALID_ALLOW_KEYS contains '{key}' but CONFIG_KEYS has no allow.{key} entry"
            );
        }
    }

    #[test]
    fn validate_multiple_unknown_keys_reported() {
        let toml = "[sandbox]\nquiet_mode = true\nfast = true\n";
        let diagnostics = validate_config(toml);
        let errors: Vec<_> = diagnostics
            .iter()
            .filter(|d| d.level == DiagnosticLevel::Error)
            .collect();
        assert_eq!(
            errors.len(),
            2,
            "should report both unknown keys: {diagnostics:?}"
        );
    }

    #[test]
    fn edit_distance_identical() {
        assert_eq!(edit_distance("hello", "hello"), 0);
    }

    #[test]
    fn edit_distance_one_char_diff() {
        assert_eq!(edit_distance("inherit_env", "inherit_evn"), 2);
    }

    #[test]
    fn edit_distance_empty_strings() {
        assert_eq!(edit_distance("", "abc"), 3);
        assert_eq!(edit_distance("abc", ""), 3);
    }
}
