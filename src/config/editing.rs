//! TOML document manipulation for `cplt config set/unset/add`.

use std::path::PathBuf;

use super::error::ConfigError;
use super::path::{config_path, expand_tilde};
use super::registry::{ConfigKeyInfo, ConfigValueType, lookup_key};

/// Parse a CLI value string into the correct TOML type for the given key.
fn parse_value_for_key(
    key_info: &ConfigKeyInfo,
    value: &str,
) -> Result<toml_edit::Value, ConfigError> {
    match key_info.value_type {
        ConfigValueType::Bool => match value {
            "true" => Ok(toml_edit::value(true).into_value().unwrap()),
            "false" => Ok(toml_edit::value(false).into_value().unwrap()),
            _ => Err(ConfigError::Validation(format!(
                "invalid boolean value '{value}' for {}.{}: expected 'true' or 'false'",
                key_info.section, key_info.key
            ))),
        },
        ConfigValueType::U16 => {
            let n: u16 = value.parse().map_err(|_| {
                ConfigError::Validation(format!(
                    "invalid port value '{value}' for {}.{}: expected 1-65535",
                    key_info.section, key_info.key
                ))
            })?;
            if n == 0 {
                return Err(ConfigError::Validation(format!(
                    "port 0 is not valid for {}.{}",
                    key_info.section, key_info.key
                )));
            }
            Ok(toml_edit::value(i64::from(n)).into_value().unwrap())
        }
        ConfigValueType::Str => Ok(toml_edit::value(value).into_value().unwrap()),
        ConfigValueType::U16Array => {
            // Comma-separated: "8080,9090" or single "8080"
            let mut arr = toml_edit::Array::new();
            for item in value.split(',') {
                let item = item.trim();
                let n: u16 = item.parse().map_err(|_| {
                    ConfigError::Validation(format!(
                        "invalid port value '{item}': expected 1-65535"
                    ))
                })?;
                if n == 0 {
                    return Err(ConfigError::Validation("port 0 is not valid".to_string()));
                }
                arr.push(i64::from(n));
            }
            Ok(toml_edit::Value::Array(arr))
        }
        ConfigValueType::StrArray => {
            // Comma-separated: "path1,path2" or single "path1"
            let mut arr = toml_edit::Array::new();
            for item in value.split(',') {
                arr.push(item.trim());
            }
            Ok(toml_edit::Value::Array(arr))
        }
    }
}

/// Parse a single element value for appending to an array.
fn parse_element_for_key(
    key_info: &ConfigKeyInfo,
    value: &str,
) -> Result<toml_edit::Value, ConfigError> {
    match key_info.value_type {
        ConfigValueType::U16Array => {
            let n: u16 = value.parse().map_err(|_| {
                ConfigError::Validation(format!("invalid port value '{value}': expected 1-65535"))
            })?;
            if n == 0 {
                return Err(ConfigError::Validation("port 0 is not valid".to_string()));
            }
            Ok(toml_edit::value(i64::from(n)).into_value().unwrap())
        }
        ConfigValueType::StrArray => {
            if value.contains(',') {
                return Err(ConfigError::Validation(format!(
                    "value contains a comma — add one value at a time:\n  \
                     cplt config set {}.{} <VALUE>",
                    key_info.section, key_info.key
                )));
            }
            // Expand ~ so stored values are always absolute paths.
            // For non-path keys (e.g. pass_env), expand_tilde is a no-op.
            let expanded = expand_tilde(value);
            Ok(toml_edit::value(expanded.to_string_lossy().as_ref())
                .into_value()
                .unwrap())
        }
        _ => Err(ConfigError::Validation(format!(
            "{}.{} is not an array key — use 'set' without --append",
            key_info.section, key_info.key
        ))),
    }
}

/// Set a value in a TOML document, creating the section if needed.
pub fn set_value_in_doc(
    doc: &mut toml_edit::DocumentMut,
    key_info: &ConfigKeyInfo,
    value: &str,
) -> Result<(), ConfigError> {
    let typed_value = parse_value_for_key(key_info, value)?;

    // Ensure section exists
    if !doc.contains_table(key_info.section) {
        doc[key_info.section] = toml_edit::Item::Table(toml_edit::Table::new());
    }

    doc[key_info.section][key_info.key] = toml_edit::Item::Value(typed_value);
    Ok(())
}

/// Append a value to an array in a TOML document.
/// Idempotent — skips if the value is already present.
pub fn append_value_in_doc(
    doc: &mut toml_edit::DocumentMut,
    key_info: &ConfigKeyInfo,
    value: &str,
) -> Result<(), ConfigError> {
    let element = parse_element_for_key(key_info, value)?;

    // Ensure section exists
    if !doc.contains_table(key_info.section) {
        doc[key_info.section] = toml_edit::Item::Table(toml_edit::Table::new());
    }

    let section = doc[key_info.section].as_table_mut().ok_or_else(|| {
        ConfigError::Validation(format!(
            "[{}] is not a table in the config file",
            key_info.section
        ))
    })?;
    if let Some(item) = section.get_mut(key_info.key) {
        if let Some(arr) = item.as_array_mut() {
            // Skip if already present (idempotent)
            if !array_contains(arr, &element) {
                arr.push_formatted(element);
            }
            Ok(())
        } else {
            Err(ConfigError::Validation(format!(
                "{}.{} exists but is not an array",
                key_info.section, key_info.key
            )))
        }
    } else {
        let mut arr = toml_edit::Array::new();
        arr.push_formatted(element);
        section.insert(
            key_info.key,
            toml_edit::Item::Value(toml_edit::Value::Array(arr)),
        );
        Ok(())
    }
}

/// Remove a single element from an array in a TOML document.
/// If the array becomes empty, removes the key entirely.
/// Returns `true` if any elements were actually removed.
pub fn remove_array_element_in_doc(
    doc: &mut toml_edit::DocumentMut,
    key_info: &ConfigKeyInfo,
    value: &str,
) -> Result<bool, ConfigError> {
    let element = parse_element_for_key(key_info, value)?;

    let Some(section) = doc.get_mut(key_info.section).and_then(|s| s.as_table_mut()) else {
        return Ok(false); // Section doesn't exist — nothing to remove
    };

    let Some(item) = section.get_mut(key_info.key) else {
        return Ok(false); // Key doesn't exist — nothing to remove
    };

    let Some(arr) = item.as_array_mut() else {
        return Err(ConfigError::Validation(format!(
            "{}.{} exists but is not an array",
            key_info.section, key_info.key
        )));
    };

    // Find and remove all matching elements (handles manual duplicates)
    let mut removed = false;
    while let Some(idx) = array_index_of(arr, &element) {
        arr.remove(idx);
        removed = true;
    }

    // Clean up empty arrays
    if arr.is_empty() {
        section.remove(key_info.key);
    }

    Ok(removed)
}

/// Check if a TOML array contains a value (by semantic equality).
fn array_contains(arr: &toml_edit::Array, value: &toml_edit::Value) -> bool {
    array_index_of(arr, value).is_some()
}

/// Find the index of a value in a TOML array (by semantic equality).
fn array_index_of(arr: &toml_edit::Array, value: &toml_edit::Value) -> Option<usize> {
    arr.iter().position(|v| values_equal(v, value))
}

/// Compare two TOML values semantically (ignoring formatting).
fn values_equal(a: &toml_edit::Value, b: &toml_edit::Value) -> bool {
    match (a, b) {
        (toml_edit::Value::String(a), toml_edit::Value::String(b)) => a.value() == b.value(),
        (toml_edit::Value::Integer(a), toml_edit::Value::Integer(b)) => a.value() == b.value(),
        _ => false,
    }
}

/// Remove a key from a TOML document (--unset).
pub fn unset_value_in_doc(doc: &mut toml_edit::DocumentMut, key_info: &ConfigKeyInfo) {
    if let Some(section) = doc.get_mut(key_info.section).and_then(|s| s.as_table_mut()) {
        section.remove(key_info.key);
    }
}

/// Read the current display value for a key from a toml_edit document.
/// Returns `None` if the key is not set.
pub fn get_value_from_doc(
    doc: &toml_edit::DocumentMut,
    key_info: &ConfigKeyInfo,
) -> Option<String> {
    let section = doc.get(key_info.section)?.as_table()?;
    let item = section.get(key_info.key)?;
    Some(format_edit_value(item))
}

fn format_edit_value(item: &toml_edit::Item) -> String {
    match item {
        toml_edit::Item::Value(toml_edit::Value::Array(arr)) => {
            let items: Vec<String> = arr
                .iter()
                .map(|v| match v {
                    toml_edit::Value::String(s) => s.value().clone(),
                    toml_edit::Value::Integer(i) => i.value().to_string(),
                    other => other.to_string(),
                })
                .collect();
            format!("[{}]", items.join(", "))
        }
        toml_edit::Item::Value(toml_edit::Value::String(s)) => s.value().clone(),
        toml_edit::Item::Value(toml_edit::Value::Integer(i)) => i.value().to_string(),
        toml_edit::Item::Value(toml_edit::Value::Boolean(b)) => b.value().to_string(),
        other => other.to_string(),
    }
}

/// The full set/get/unset operation on a config file.
/// Handles file creation, validation, and write-back.
pub struct ConfigSetOp {
    pub key_info: &'static ConfigKeyInfo,
    pub path: PathBuf,
}

impl ConfigSetOp {
    pub fn new(dotted_key: &str) -> Result<Self, ConfigError> {
        let key_info = lookup_key(dotted_key)?;
        let path = config_path().ok_or(ConfigError::NoHome)?;
        Ok(Self { key_info, path })
    }

    /// Load the existing TOML document, or create an empty one.
    pub fn load_document(&self) -> Result<toml_edit::DocumentMut, ConfigError> {
        if self.path.exists() {
            let raw = std::fs::read_to_string(&self.path).map_err(|e| ConfigError::Read {
                path: self.path.clone(),
                source: e,
            })?;
            raw.parse::<toml_edit::DocumentMut>()
                .map_err(|e| ConfigError::TomlEditParse {
                    path: self.path.display().to_string(),
                    source: e,
                })
        } else {
            Ok(toml_edit::DocumentMut::new())
        }
    }

    /// Write the document back, creating parent dirs if needed.
    /// Only verifies the result is valid TOML (not full key validation —
    /// an existing typo elsewhere shouldn't block a valid set operation).
    pub fn write_document(&self, doc: &toml_edit::DocumentMut) -> Result<(), ConfigError> {
        let output = doc.to_string();

        // Sanity check: the result must still be valid TOML
        if output.parse::<toml::Table>().is_err() {
            return Err(ConfigError::InvalidOutput);
        }

        // Create parent dirs
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent).map_err(ConfigError::CreateDir)?;
        }

        std::fs::write(&self.path, output).map_err(|e| ConfigError::Write {
            path: self.path.clone(),
            source: e,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::lookup_key;

    #[test]
    fn set_value_in_doc_creates_section_and_key() {
        let mut doc = "".parse::<toml_edit::DocumentMut>().unwrap();
        let info = lookup_key("sandbox.quiet").unwrap();
        set_value_in_doc(&mut doc, info, "true").unwrap();
        let result = doc.to_string();
        assert!(result.contains("[sandbox]"));
        assert!(result.contains("quiet = true"));
    }

    #[test]
    fn set_value_in_doc_overwrites_existing() {
        let mut doc = "[sandbox]\nquiet = false\n"
            .parse::<toml_edit::DocumentMut>()
            .unwrap();
        let info = lookup_key("sandbox.quiet").unwrap();
        set_value_in_doc(&mut doc, info, "true").unwrap();
        let result = doc.to_string();
        assert!(result.contains("quiet = true"));
        assert!(!result.contains("quiet = false"));
    }

    #[test]
    fn set_value_in_doc_preserves_comments() {
        let input = "# Important security comment\n[sandbox]\n# This is quiet\nquiet = false\n";
        let mut doc = input.parse::<toml_edit::DocumentMut>().unwrap();
        let info = lookup_key("sandbox.quiet").unwrap();
        set_value_in_doc(&mut doc, info, "true").unwrap();
        let result = doc.to_string();
        assert!(result.contains("Important security comment"));
        assert!(result.contains("quiet = true"));
    }

    #[test]
    fn set_value_in_doc_port_number() {
        let mut doc = "".parse::<toml_edit::DocumentMut>().unwrap();
        let info = lookup_key("proxy.port").unwrap();
        set_value_in_doc(&mut doc, info, "9090").unwrap();
        let result = doc.to_string();
        assert!(result.contains("port = 9090"));
    }

    #[test]
    fn set_value_in_doc_string_value() {
        let mut doc = "".parse::<toml_edit::DocumentMut>().unwrap();
        let info = lookup_key("proxy.log_file").unwrap();
        set_value_in_doc(&mut doc, info, "/tmp/proxy.log").unwrap();
        let result = doc.to_string();
        assert!(result.contains("log_file = \"/tmp/proxy.log\""));
    }

    #[test]
    fn set_value_in_doc_array_replacement() {
        let mut doc = "".parse::<toml_edit::DocumentMut>().unwrap();
        let info = lookup_key("allow.ports").unwrap();
        set_value_in_doc(&mut doc, info, "8080,9090").unwrap();
        let result = doc.to_string();
        assert!(result.contains("8080"));
        assert!(result.contains("9090"));
    }

    #[test]
    fn set_value_rejects_invalid_bool() {
        let mut doc = "".parse::<toml_edit::DocumentMut>().unwrap();
        let info = lookup_key("sandbox.quiet").unwrap();
        assert!(set_value_in_doc(&mut doc, info, "yes").is_err());
    }

    #[test]
    fn set_value_rejects_invalid_port() {
        let mut doc = "".parse::<toml_edit::DocumentMut>().unwrap();
        let info = lookup_key("proxy.port").unwrap();
        assert!(set_value_in_doc(&mut doc, info, "99999").is_err());
        assert!(set_value_in_doc(&mut doc, info, "abc").is_err());
    }

    #[test]
    fn append_value_in_doc_new_array() {
        let mut doc = "".parse::<toml_edit::DocumentMut>().unwrap();
        let info = lookup_key("allow.ports").unwrap();
        append_value_in_doc(&mut doc, info, "3000").unwrap();
        let result = doc.to_string();
        assert!(result.contains("3000"));
    }

    #[test]
    fn append_value_in_doc_existing_array() {
        let mut doc = "[allow]\nports = [8080]\n"
            .parse::<toml_edit::DocumentMut>()
            .unwrap();
        let info = lookup_key("allow.ports").unwrap();
        append_value_in_doc(&mut doc, info, "9090").unwrap();
        let result = doc.to_string();
        assert!(result.contains("8080"));
        assert!(result.contains("9090"));
    }

    #[test]
    fn append_value_is_idempotent() {
        let mut doc = "[allow]\nread = [\"/tmp/a\"]\n"
            .parse::<toml_edit::DocumentMut>()
            .unwrap();
        let info = lookup_key("allow.read").unwrap();
        append_value_in_doc(&mut doc, info, "/tmp/a").unwrap();
        let arr = doc["allow"]["read"].as_array().unwrap();
        assert_eq!(arr.len(), 1, "duplicate should not be added");
    }

    #[test]
    fn append_value_idempotent_ports() {
        let mut doc = "[allow]\nports = [8080]\n"
            .parse::<toml_edit::DocumentMut>()
            .unwrap();
        let info = lookup_key("allow.ports").unwrap();
        append_value_in_doc(&mut doc, info, "8080").unwrap();
        let arr = doc["allow"]["ports"].as_array().unwrap();
        assert_eq!(arr.len(), 1, "duplicate port should not be added");
    }

    #[test]
    fn append_rejects_non_array_key() {
        let info = lookup_key("sandbox.quiet").unwrap();
        let mut doc = "".parse::<toml_edit::DocumentMut>().unwrap();
        assert!(append_value_in_doc(&mut doc, info, "true").is_err());
    }

    #[test]
    fn unset_value_removes_key() {
        let mut doc = "[sandbox]\nquiet = true\nvalidate = true\n"
            .parse::<toml_edit::DocumentMut>()
            .unwrap();
        let info = lookup_key("sandbox.quiet").unwrap();
        unset_value_in_doc(&mut doc, info);
        let result = doc.to_string();
        assert!(!result.contains("quiet"));
        assert!(result.contains("validate = true"));
    }

    #[test]
    fn unset_value_noop_if_missing() {
        let mut doc = "[sandbox]\nvalidate = true\n"
            .parse::<toml_edit::DocumentMut>()
            .unwrap();
        let info = lookup_key("sandbox.quiet").unwrap();
        unset_value_in_doc(&mut doc, info);
        let result = doc.to_string();
        assert!(result.contains("validate = true"));
    }

    #[test]
    fn remove_array_element_removes_single_value() {
        let mut doc = "[allow]\nread = [\"/tmp/a\", \"/tmp/b\", \"/tmp/c\"]\n"
            .parse::<toml_edit::DocumentMut>()
            .unwrap();
        let info = lookup_key("allow.read").unwrap();
        let removed = remove_array_element_in_doc(&mut doc, info, "/tmp/b").unwrap();
        assert!(removed, "should report element was removed");
        let result = doc.to_string();
        assert!(result.contains("/tmp/a"));
        assert!(!result.contains("/tmp/b"));
        assert!(result.contains("/tmp/c"));
    }

    #[test]
    fn remove_array_element_cleans_up_empty_array() {
        let mut doc = "[allow]\nread = [\"/tmp/a\"]\n"
            .parse::<toml_edit::DocumentMut>()
            .unwrap();
        let info = lookup_key("allow.read").unwrap();
        remove_array_element_in_doc(&mut doc, info, "/tmp/a").unwrap();
        let result = doc.to_string();
        assert!(
            !result.contains("read"),
            "empty array key should be removed"
        );
    }

    #[test]
    fn remove_array_element_noop_if_not_present() {
        let mut doc = "[allow]\nread = [\"/tmp/a\"]\n"
            .parse::<toml_edit::DocumentMut>()
            .unwrap();
        let info = lookup_key("allow.read").unwrap();
        let removed = remove_array_element_in_doc(&mut doc, info, "/tmp/missing").unwrap();
        assert!(!removed, "should report nothing was removed");
        let arr = doc["allow"]["read"].as_array().unwrap();
        assert_eq!(arr.len(), 1, "array should be unchanged");
    }

    #[test]
    fn remove_array_element_noop_if_key_missing() {
        let mut doc = "".parse::<toml_edit::DocumentMut>().unwrap();
        let info = lookup_key("allow.read").unwrap();
        let removed = remove_array_element_in_doc(&mut doc, info, "/tmp/a").unwrap();
        assert!(!removed, "should report nothing was removed");
    }

    #[test]
    fn remove_array_element_port() {
        let mut doc = "[allow]\nports = [8080, 9090, 3000]\n"
            .parse::<toml_edit::DocumentMut>()
            .unwrap();
        let info = lookup_key("allow.ports").unwrap();
        remove_array_element_in_doc(&mut doc, info, "9090").unwrap();
        let arr = doc["allow"]["ports"].as_array().unwrap();
        assert_eq!(arr.len(), 2);
        assert_eq!(arr.get(0).unwrap().as_integer(), Some(8080));
        assert_eq!(arr.get(1).unwrap().as_integer(), Some(3000));
    }

    #[test]
    fn remove_array_element_errors_on_non_array() {
        let mut doc = "[sandbox]\nquiet = true\n"
            .parse::<toml_edit::DocumentMut>()
            .unwrap();
        let info = lookup_key("sandbox.quiet").unwrap();
        let result = remove_array_element_in_doc(&mut doc, info, "true");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not an array"));
    }

    #[test]
    fn remove_array_element_removes_all_duplicates() {
        let mut doc = "[allow]\nread = [\"/tmp/a\", \"/tmp/a\", \"/tmp/b\"]\n"
            .parse::<toml_edit::DocumentMut>()
            .unwrap();
        let info = lookup_key("allow.read").unwrap();
        remove_array_element_in_doc(&mut doc, info, "/tmp/a").unwrap();
        let arr = doc["allow"]["read"].as_array().unwrap();
        assert_eq!(arr.len(), 1, "both duplicates should be removed");
        assert_eq!(arr.get(0).unwrap().as_str(), Some("/tmp/b"));
    }

    #[test]
    fn append_rejects_comma_separated_values() {
        let mut doc = "[allow]\nread = []\n"
            .parse::<toml_edit::DocumentMut>()
            .unwrap();
        let info = lookup_key("allow.read").unwrap();
        let result = append_value_in_doc(&mut doc, info, "/tmp/a,/tmp/b");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("comma"));
    }
}
