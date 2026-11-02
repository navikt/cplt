//! Verifies that every `cplt <subcommand> ...` command named in user-facing strings
//! under `src/` exists in the build and that referenced flags are valid.
//!
//! See GitHub issue navikt/cplt#942.

#![allow(clippy::disallowed_methods)]

mod common;

use common::cplt_cmd;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// False positives in user-facing string literals that start with `cplt` but are
/// not executable commands.
const ALLOWLIST: &[(&str, &str)] = &[("cplt", "bare binary name without subcommand or flags")];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtractedCommand {
    pub file: String,
    pub line: usize,
    pub raw: String,
    pub subwords: Vec<String>,
    pub flags: Vec<String>,
}

fn is_allowlisted(cmd: &str) -> bool {
    let normalized: String = cmd.split_whitespace().collect::<Vec<_>>().join(" ");
    for (entry, _reason) in ALLOWLIST {
        if normalized == *entry
            || (*entry != "cplt" && normalized.starts_with(&format!("{entry} ")))
        {
            return true;
        }
    }
    false
}

fn is_placeholder_or_arg(token: &str) -> bool {
    if token.starts_with('-') {
        return true;
    }
    if token.contains('<') || token.contains('>') {
        return true;
    }
    if token.contains('{') || token.contains('}') {
        return true;
    }
    if token.contains('[') || token.contains(']') {
        return true;
    }
    if token.contains('|') || token.contains('/') || token.contains('\\') {
        return true;
    }
    if token.contains('.') || token.contains('_') {
        return true;
    }
    if token.contains("...") {
        return true;
    }
    if token == "true" || token == "false" {
        return true;
    }
    if token.len() > 1 && token.chars().all(|c| c.is_ascii_uppercase()) {
        return true;
    }
    if token == "repos" || token == "git" {
        return true;
    }
    if token.ends_with(':') {
        return true;
    }
    false
}

pub fn parse_command(file: &str, line: usize, raw: &str) -> Option<ExtractedCommand> {
    if is_allowlisted(raw) {
        return None;
    }
    let tokens: Vec<&str> = raw.split_whitespace().collect();
    if tokens.is_empty() || tokens[0] != "cplt" {
        return None;
    }
    let mut subwords = Vec::new();
    for &t in &tokens[1..] {
        let t_clean = t.trim_matches(|c| c == '"' || c == '\'');
        if is_placeholder_or_arg(t_clean) {
            break;
        }
        subwords.push(t_clean.to_string());
    }

    let mut flags = Vec::new();
    for &t in &tokens[1..] {
        let t_clean = t.trim_matches(|c| {
            c == '['
                || c == ']'
                || c == '('
                || c == ')'
                || c == '{'
                || c == '}'
                || c == '`'
                || c == '\''
                || c == '"'
        });
        let t_clean = t_clean.split('{').next().unwrap_or(t_clean);
        if t_clean.starts_with("--") && t_clean.len() > 2 && t_clean != "--" {
            let flag_name = t_clean.split('=').next().unwrap_or(t_clean);
            flags.push(flag_name.to_string());
        }
    }

    Some(ExtractedCommand {
        file: file.to_string(),
        line,
        raw: raw.to_string(),
        subwords,
        flags,
    })
}

fn extract_strings_from_source(src: &str) -> Vec<(String, usize)> {
    let mut strings = Vec::new();
    let bytes = src.as_bytes();
    let n = bytes.len();
    let mut i = 0;
    while i < n {
        // Line comments: skip
        if i + 1 < n && bytes[i] == b'/' && bytes[i + 1] == b'/' {
            i += 2;
            while i < n && bytes[i] != b'\n' {
                i += 1;
            }
            continue;
        }
        // Block comments: skip with depth tracking
        if i + 1 < n && bytes[i] == b'/' && bytes[i + 1] == b'*' {
            i += 2;
            let mut depth = 1;
            while i < n && depth > 0 {
                if i + 1 < n && bytes[i] == b'/' && bytes[i + 1] == b'*' {
                    depth += 1;
                    i += 2;
                } else if i + 1 < n && bytes[i] == b'*' && bytes[i + 1] == b'/' {
                    depth -= 1;
                    i += 2;
                } else {
                    i += 1;
                }
            }
            continue;
        }
        // Raw strings: r"..." or r#"..."# or r##"..."##
        if bytes[i] == b'r' && i + 1 < n && (bytes[i + 1] == b'"' || bytes[i + 1] == b'#') {
            let mut j = i + 1;
            let mut hashes = 0;
            while j < n && bytes[j] == b'#' {
                hashes += 1;
                j += 1;
            }
            if j < n && bytes[j] == b'"' {
                j += 1;
                let start = j;
                let mut found = None;
                while j < n {
                    if bytes[j] == b'"' {
                        let mut h = 0;
                        while j + 1 + h < n && h < hashes && bytes[j + 1 + h] == b'#' {
                            h += 1;
                        }
                        if h == hashes {
                            found = Some(j);
                            break;
                        }
                    }
                    j += 1;
                }
                if let Some(end) = found {
                    let line = src[..start].lines().count();
                    strings.push((src[start..end].to_string(), line.max(1)));
                    i = end + 1 + hashes;
                    continue;
                }
            }
        }
        // Char literals: skip (e.g. '\'', 'a', '\n')
        if bytes[i] == b'\'' {
            i += 1;
            if i < n && bytes[i] == b'\\' {
                i += 2;
                if i < n && bytes[i] == b'\'' {
                    i += 1;
                }
            } else if i < n && bytes[i] != b'\'' {
                i += 1;
                if i < n && bytes[i] == b'\'' {
                    i += 1;
                }
            }
            continue;
        }
        // Normal string literal
        if bytes[i] == b'"' {
            let start = i + 1;
            let line = src[..start].lines().count();
            i += 1;
            while i < n {
                if bytes[i] == b'\\' {
                    i += 2;
                } else if bytes[i] == b'"' {
                    break;
                } else {
                    i += 1;
                }
            }
            if i < n {
                strings.push((src[start..i].to_string(), line.max(1)));
                i += 1;
            }
            continue;
        }
        i += 1;
    }
    strings
}

fn find_commands_in_string(s: &str) -> Vec<String> {
    let mut cmds = Vec::new();
    let clean = s.replace("\\\n", " ");

    let bytes = clean.as_bytes();
    let n = bytes.len();
    let mut i = 0;
    while i < n {
        if bytes[i] == b'`'
            && let Some(end) = bytes[i + 1..].iter().position(|&b| b == b'`')
        {
            let end_idx = i + 1 + end;
            let content = clean[i + 1..end_idx].trim();
            let first = content.split_whitespace().next();
            if first == Some("cplt") {
                cmds.push(content.to_string());
            }
            i = end_idx + 1;
            continue;
        }
        i += 1;
    }

    cmds
}

fn collect_rs_files(dir: &Path, files: &mut Vec<PathBuf>) {
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                collect_rs_files(&path, files);
            } else if path.extension().is_some_and(|ext| ext == "rs") {
                files.push(path);
            }
        }
    }
}

pub fn extract_all_commands(src_dir: &Path) -> Vec<ExtractedCommand> {
    let mut files = Vec::new();
    collect_rs_files(src_dir, &mut files);
    files.sort();

    let mut commands = Vec::new();
    for file in files {
        let content = std::fs::read_to_string(&file).unwrap_or_default();
        let rel_path = file.to_string_lossy().to_string();
        for (str_lit, line) in extract_strings_from_source(&content) {
            for raw_cmd in find_commands_in_string(&str_lit) {
                if let Some(cmd) = parse_command(&rel_path, line, &raw_cmd) {
                    commands.push(cmd);
                }
            }
        }
    }
    commands
}

fn get_help_output(
    subwords: &[String],
    cache: &mut HashMap<Vec<String>, Result<String, String>>,
) -> Result<String, String> {
    if let Some(res) = cache.get(subwords) {
        return res.clone();
    }
    let mut cmd = cplt_cmd();
    for word in subwords {
        cmd.arg(word);
    }
    cmd.arg("--help");
    let output = match cmd.output() {
        Ok(out) => out,
        Err(e) => {
            let err = format!("Failed to execute cplt: {e}");
            cache.insert(subwords.to_vec(), Err(err.clone()));
            return Err(err);
        }
    };
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
        let err = format!(
            "cplt {} --help failed with exit code {:?}: {}",
            subwords.join(" "),
            output.status.code(),
            stderr.trim()
        );
        cache.insert(subwords.to_vec(), Err(err.clone()));
        return Err(err);
    }
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    cache.insert(subwords.to_vec(), Ok(stdout.clone()));
    Ok(stdout)
}

#[allow(clippy::implicit_hasher)]
pub fn check_command(
    cmd: &ExtractedCommand,
    cache: &mut HashMap<Vec<String>, Result<String, String>>,
) -> Result<(), String> {
    let help_text = get_help_output(&cmd.subwords, cache)?;
    for flag in &cmd.flags {
        if !help_text.contains(flag) {
            return Err(format!(
                "Command `{}` in {}:{} specifies flag `{}` which was not found in `cplt {} --help`",
                cmd.raw,
                cmd.file,
                cmd.line,
                flag,
                cmd.subwords.join(" ")
            ));
        }
    }
    Ok(())
}

#[test]
fn control_synthetic_command_reported() {
    let mut cache = HashMap::new();
    let synthetic = ExtractedCommand {
        file: "synthetic.rs".to_string(),
        line: 1,
        raw: "cplt frobnicate".to_string(),
        subwords: vec!["frobnicate".to_string()],
        flags: vec![],
    };
    let res = check_command(&synthetic, &mut cache);
    assert!(res.is_err(), "cplt frobnicate must fail validation");
    let err = res.unwrap_err();
    assert!(
        err.contains("frobnicate"),
        "error message should name frobnicate: {err}"
    );
}

#[test]
fn control_synthetic_flag_reported() {
    let mut cache = HashMap::new();
    let synthetic = ExtractedCommand {
        file: "synthetic.rs".to_string(),
        line: 1,
        raw: "cplt doctor --nonexistent-flag".to_string(),
        subwords: vec!["doctor".to_string()],
        flags: vec!["--nonexistent-flag".to_string()],
    };
    let res = check_command(&synthetic, &mut cache);
    assert!(res.is_err(), "nonexistent flag must fail validation");
    let err = res.unwrap_err();
    assert!(
        err.contains("--nonexistent-flag"),
        "error message should name flag: {err}"
    );
}

#[test]
fn test_message_commands_exist_in_binary() {
    let src_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let commands = extract_all_commands(&src_dir);
    println!(
        "Extracted and validated {} cplt commands across src/",
        commands.len()
    );
    assert!(
        !commands.is_empty(),
        "Scanner should have found cplt commands in src/"
    );

    let mut cache = HashMap::new();
    let mut errors = Vec::new();

    for cmd in &commands {
        if let Err(e) = check_command(cmd, &mut cache) {
            errors.push(e);
        }
    }

    assert!(
        errors.is_empty(),
        "Found {} broken command(s) in src/:\n{}",
        errors.len(),
        errors.join("\n")
    );
}
