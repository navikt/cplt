//! Unknown-key detection and typo suggestions.
//!
//! Valid key names are **derived from the serde structs** (via [`serde_ignored`])
//! rather than hand-maintained string arrays: any key that does not map to a
//! `Config` struct field is reported as unknown. Adding a new config option
//! therefore only requires touching the struct definition — typos of it are
//! flagged automatically, with no parallel list to keep in sync.
//!
//! Runtime loading stays forward-compatible: unknown keys are ignored (not a
//! hard error) so configs can be shared across cplt versions, but they are
//! surfaced as a warning at load time and as diagnostics in `cplt config validate`.

use super::registry::CONFIG_KEYS;
use super::types::{Config, Preset};

// ── Config validation (unknown key detection) ────────────────────────

/// Top-level scalar keys that are valid but not TOML sections.
const TOP_LEVEL_SCALARS: &[&str] = &["config_version"];

/// Deserialize a user `Config` from TOML while collecting the dotted paths of
/// any keys that do not correspond to a struct field (unknown/misspelled keys).
///
/// This is the single source of truth for "is this key known?": validity is
/// derived from the `#[derive(Deserialize)]` structs, so there is no key list
/// to keep in sync. Unknown keys are collected, **not** rejected — callers
/// decide whether to warn (forward-compatible load) or error (`config validate`).
pub(super) fn deserialize_collecting_unknowns(
    toml_text: &str,
) -> Result<(Config, Vec<String>), toml::de::Error> {
    let de = toml::Deserializer::parse(toml_text)?;
    let mut ignored = Vec::new();
    let config = serde_ignored::deserialize(de, |path| {
        ignored.push(path.to_string());
    })?;
    Ok((config, ignored))
}

/// The distinct `[section]` names known to the config, derived from the registry.
fn known_sections() -> Vec<&'static str> {
    let mut sections = Vec::new();
    for info in CONFIG_KEYS {
        if !sections.contains(&info.section) {
            sections.push(info.section);
        }
    }
    sections
}

/// Valid keys within a given section, derived from the registry.
fn section_keys(section: &str) -> Vec<&'static str> {
    CONFIG_KEYS
        .iter()
        .filter(|info| info.section == section)
        .map(|info| info.key)
        .collect()
}

/// Valid top-level keys (section names plus top-level scalars like `config_version`).
fn top_level_keys() -> Vec<&'static str> {
    let mut keys = known_sections();
    keys.extend_from_slice(TOP_LEVEL_SCALARS);
    keys
}

/// Build a human-readable message for an unknown key path (e.g. `sandbox.inherit_evn`),
/// including a "did you mean 'x'?" suggestion derived from the registry.
///
/// Candidate keys for the suggestion come from `CONFIG_KEYS`, so suggestions
/// automatically cover any option present in the registry.
pub(super) fn describe_unknown_key(path: &str) -> String {
    if let Some((section, key)) = path.split_once('.') {
        // Exclude the reported key itself from the suggestion candidates. The
        // candidates come from CONFIG_KEYS (a superset that includes repo-only
        // keys like `deny.env`), so a key that is valid in the registry but not
        // on the user-config struct would otherwise suggest itself
        // ("did you mean 'env'?"), which is nonsense.
        let candidates: Vec<&str> = section_keys(section)
            .into_iter()
            .filter(|c| *c != key)
            .collect();
        let hint = suggest_key(key, &candidates)
            .map(|s| format!(" (did you mean '{s}'?)"))
            .unwrap_or_default();
        format!("unknown key '{key}' in [{section}]{hint}")
    } else {
        let candidates: Vec<&str> = top_level_keys()
            .into_iter()
            .filter(|c| *c != path)
            .collect();
        let hint = suggest_key(path, &candidates)
            .map(|s| format!(" (did you mean '{s}'?)"))
            .unwrap_or_default();
        format!("unknown top-level key '{path}'{hint}")
    }
}

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

    // Structural check: a known section must be a table, not a scalar.
    // This gives a clearer message than the raw serde type error below.
    for section in known_sections() {
        if let Some(value) = table.get(section)
            && !value.is_table()
        {
            diagnostics.push(ConfigDiagnostic {
                level: DiagnosticLevel::Error,
                message: format!(
                    "[{section}] must be a table, not a {}",
                    value_type_name(value)
                ),
            });
        }
    }

    // Unknown/misspelled keys and type errors: derive validity from the structs
    // via serde_ignored. Unknown keys are collected (not fatal); a type error
    // aborts deserialization and is reported as such.
    match deserialize_collecting_unknowns(toml_text) {
        Ok((_config, unknown_keys)) => {
            for path in unknown_keys {
                diagnostics.push(ConfigDiagnostic {
                    level: DiagnosticLevel::Error,
                    message: describe_unknown_key(&path),
                });
            }
        }
        Err(e) => {
            // A section-as-scalar error is already reported above with a nicer
            // message — don't double-report it as a generic type error.
            if diagnostics
                .iter()
                .all(|d| d.level != DiagnosticLevel::Error)
            {
                diagnostics.push(ConfigDiagnostic {
                    level: DiagnosticLevel::Error,
                    message: format!("type error: {e}"),
                });
            }
        }
    }

    // Warn about dangerous settings
    if let Some(sandbox) = table.get("sandbox").and_then(|v| v.as_table()) {
        // A preset is dangerous when its baseline enables any of the guarded
        // toggles — `permissive` and `full-trust` do, `strict`/`standard` do
        // not. Derive the enabled toggles from `Preset::baseline()` (via
        // `enabled_dangerous_names`) so this warning names exactly what the
        // preset turns on and cannot drift from the preset definitions.
        if let Some(preset_str) = sandbox.get("preset").and_then(toml::Value::as_str)
            && let Some(preset) = Preset::from_name(preset_str)
        {
            let enabled = preset.enabled_dangerous_names();
            if !enabled.is_empty() {
                diagnostics.push(ConfigDiagnostic {
                    level: DiagnosticLevel::Warning,
                    message: format!(
                        "sandbox.preset = \"{preset}\": enables {} (DANGEROUS)",
                        enabled.join(", ")
                    ),
                });
            }
        }
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
    fn validate_warns_about_dangerous_preset_permissive() {
        let toml = "[sandbox]\npreset = \"permissive\"\n";
        let diagnostics = validate_config(toml);
        let warning = diagnostics
            .iter()
            .find(|d| d.level == DiagnosticLevel::Warning && d.message.contains("preset"))
            .unwrap_or_else(|| panic!("should warn about permissive preset: {diagnostics:?}"));
        assert!(warning.message.contains("DANGEROUS"), "{}", warning.message);
        // Names exactly the toggles permissive enables (and none it doesn't).
        assert!(warning.message.contains("tmp-exec"), "{}", warning.message);
        assert!(
            warning.message.contains("localhost-any"),
            "{}",
            warning.message
        );
        assert!(
            warning.message.contains("lifecycle-scripts"),
            "{}",
            warning.message
        );
        assert!(!warning.message.contains("docker"), "{}", warning.message);
        assert!(
            !warning.message.contains("env-files"),
            "{}",
            warning.message
        );
    }

    #[test]
    fn validate_warns_about_dangerous_preset_full_trust() {
        let toml = "[sandbox]\npreset = \"full-trust\"\n";
        let diagnostics = validate_config(toml);
        let warning = diagnostics
            .iter()
            .find(|d| d.level == DiagnosticLevel::Warning && d.message.contains("preset"))
            .unwrap_or_else(|| panic!("should warn about full-trust preset: {diagnostics:?}"));
        assert!(warning.message.contains("DANGEROUS"), "{}", warning.message);
        // full-trust enables all five toggles, including docker + env-files.
        for name in [
            "tmp-exec",
            "localhost-any",
            "lifecycle-scripts",
            "docker",
            "env-files",
        ] {
            assert!(warning.message.contains(name), "{}", warning.message);
        }
    }

    #[test]
    fn validate_no_warning_for_safe_presets() {
        for preset in ["strict", "standard"] {
            let toml = format!("[sandbox]\npreset = \"{preset}\"\n");
            let diagnostics = validate_config(&toml);
            assert!(
                !diagnostics
                    .iter()
                    .any(|d| d.level == DiagnosticLevel::Warning),
                "preset={preset} should not warn: {diagnostics:?}"
            );
        }
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

    /// Forward compatibility: a config using a section/key that this cplt
    /// version does not know about must still LOAD successfully (unknown keys
    /// are ignored, not fatal) — users share configs across cplt versions.
    #[test]
    fn future_unknown_section_still_loads() {
        let toml = "
[sandbox]
quiet = true

[future_feature]
some_new_option = true
";
        // Deserialization must succeed and yield the known values...
        let (config, unknown) = deserialize_collecting_unknowns(toml).unwrap();
        assert_eq!(config.sandbox.quiet, Some(true));
        // ...while still surfacing the unknown top-level section.
        assert!(
            unknown.iter().any(|p| p == "future_feature"),
            "unknown section should be collected: {unknown:?}"
        );
    }

    /// A brand-new struct field is auto-covered: because validity is derived
    /// from the structs, a real field (`sandbox.yes`) is never flagged even
    /// though no hand-maintained key list mentions it. This is the regression
    /// the old VALID_*_KEYS arrays were prone to (they omitted `yes`).
    #[test]
    fn valid_struct_field_not_flagged_as_unknown() {
        let toml = "[sandbox]\nyes = true\n";
        let diagnostics = validate_config(toml);
        assert!(
            diagnostics.is_empty(),
            "a real struct field must not be flagged: {diagnostics:?}"
        );
    }

    /// Unknown nested key is reported with its `section.key` context.
    #[test]
    fn validate_detects_unknown_nested_key() {
        let toml = "[gh_guard]\nenabled = true\nbogus_option = true\n";
        let diagnostics = validate_config(toml);
        assert!(
            diagnostics.iter().any(|d| {
                d.level == DiagnosticLevel::Error
                    && d.message.contains("unknown key 'bogus_option'")
                    && d.message.contains("[gh_guard]")
            }),
            "should detect unknown nested key with section context: {diagnostics:?}"
        );
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

    #[test]
    fn unknown_key_valid_in_registry_but_not_struct_does_not_self_suggest() {
        // `deny.env` is a repo-only registry key with no field on the user
        // DenyConfig struct, so serde_ignored flags it as unknown. The
        // suggestion must NOT be the same key ("did you mean 'env'?").
        let msg = describe_unknown_key("deny.env");
        assert!(msg.contains("unknown key 'env' in [deny]"), "got: {msg}");
        assert!(
            !msg.contains("did you mean 'env'"),
            "self-suggestion leaked: {msg}"
        );
    }

    #[test]
    fn unknown_key_still_suggests_a_genuine_typo() {
        // A real typo of a user-struct key still gets a suggestion.
        let msg = describe_unknown_key("sandbox.inherit_evn");
        assert!(msg.contains("did you mean 'inherit_env'"), "got: {msg}");
    }
}
