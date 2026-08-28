//! `cplt init` subcommand — auto-generate .cplt.toml from project detection.
//!
//! Scans the current project for build files, frameworks, and patterns,
//! then generates a .cplt.toml file with appropriate sandbox permissions.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write;
use std::path::Path;

use crate::detect::{Detection, DetectionReport, SandboxFlag, Suggestion};

/// Options for the init command (mapped from CLI args).
pub struct InitOptions {
    /// Write the generated config to disk.
    pub write: bool,
    /// Overwrite existing .cplt.toml (requires write).
    pub force: bool,
    /// Merge new detections into existing .cplt.toml without removing entries.
    pub merge: bool,
    /// Output only the TOML (no decoration/ecosystem info).
    pub quiet: bool,
}

/// Result of running the init command.
pub enum InitResult {
    /// Generated config (preview or written).
    Generated {
        toml: String,
        path: std::path::PathBuf,
        written: bool,
    },
    /// File already exists and --force not given.
    AlreadyExists(std::path::PathBuf),
    /// Nothing detected — empty project.
    NothingDetected,
    /// Write failed.
    WriteFailed(std::path::PathBuf, std::io::Error),
}

/// Run the init command from a pre-computed detection report.
/// Avoids redundant filesystem scans when the caller already has the report.
pub fn run_init(project_dir: &Path, report: &DetectionReport, opts: &InitOptions) -> InitResult {
    if report.detections.is_empty() && report.workspace_members.is_empty() {
        return InitResult::NothingDetected;
    }

    let config_path = project_dir.join(".cplt.toml");

    // Note: init reads the working-tree file (not git HEAD) intentionally.
    // This is a local dev tool for authoring configs — the runtime config loader
    // in repo_config.rs reads from git HEAD for tamper-resistance.
    let toml = if opts.merge && config_path.exists() {
        let existing = match std::fs::read_to_string(&config_path) {
            Ok(c) => c,
            Err(e) => return InitResult::WriteFailed(config_path, e),
        };
        merge_toml(&existing, report)
    } else {
        generate_toml(report)
    };

    if opts.write {
        if config_path.exists() && !opts.force && !opts.merge {
            return InitResult::AlreadyExists(config_path);
        }
        if let Err(e) = std::fs::write(&config_path, &toml) {
            return InitResult::WriteFailed(config_path, e);
        }
        return InitResult::Generated {
            toml,
            path: config_path,
            written: true,
        };
    }

    InitResult::Generated {
        toml,
        path: config_path,
        written: false,
    }
}

/// Format the detection report for human-readable stdout display.
pub fn format_report(report: &DetectionReport) -> String {
    let mut out = String::new();

    writeln!(out, "Detected ecosystems:").unwrap();
    writeln!(out).unwrap();

    for detection in &report.detections {
        write_detection(&mut out, detection);
    }

    // Show workspace member detections
    if !report.workspace_members.is_empty() {
        writeln!(out, "Workspace members:").unwrap();
        writeln!(out).unwrap();
        for member in &report.workspace_members {
            writeln!(out, "  📁 {} ({})", member.relative_path, member.source).unwrap();
            for detection in &member.detections {
                writeln!(out, "    • {}", detection.name).unwrap();
                for signal in &detection.signals {
                    writeln!(out, "      ↳ {signal}").unwrap();
                }
            }
        }
        writeln!(out).unwrap();
    }

    if !report.diagnostics.is_empty() {
        writeln!(out, "Diagnostics:").unwrap();
        for diag in &report.diagnostics {
            writeln!(out, "  [{}/warning] {}", diag.detector, diag.message).unwrap();
        }
        writeln!(out).unwrap();
    }

    out
}

fn write_detection(out: &mut String, d: &Detection) {
    writeln!(out, "  • {}", d.name).unwrap();
    for signal in &d.signals {
        writeln!(out, "    ↳ {signal}").unwrap();
    }
    if !d.suggestions.is_empty() {
        writeln!(out, "    Suggests:").unwrap();
        for suggestion in &d.suggestions {
            writeln!(out, "      {}", format_suggestion(suggestion)).unwrap();
        }
    }
    writeln!(out).unwrap();
}

fn format_suggestion(s: &Suggestion) -> String {
    match s {
        Suggestion::Propose(flag) => format!("{} = true", flag.key_name()),
        Suggestion::AllowRead(p) => format!("allow.read = [\"{p}\"]"),
        Suggestion::AllowWrite(p) => format!("allow.write = [\"{p}\"]"),
        Suggestion::AllowPort(p) => format!("allow.ports = [{p}]"),
        Suggestion::AllowLocalhost(p) => format!("allow.localhost = [{p}]"),
        Suggestion::AllowCacheExec(p) => {
            format!("sandbox.allow_cache_exec = [\"{p}\"]  (personal config)")
        }
        Suggestion::DenyEnv(v) => format!("deny.env = [\"{v}\"]"),
        Suggestion::DenyPath(p) => format!("deny.paths = [\"{p}\"]"),
        Suggestion::AllowPrivateDomain(d) => {
            format!("proxy.allow_private_domains = [\"{d}\"]")
        }
    }
}

/// Generate a valid .cplt.toml from a detection report.
///
/// Only includes suggestions appropriate for repo-level config.
/// Machine-specific suggestions (cache_exec, home-relative paths) are emitted
/// as comments with guidance to add them to personal config.
///
/// When provenance is available (from monorepo detection), adds comments
/// showing which subdirectory triggered each suggestion. Dangerous permissions
/// from heuristic fallback scans are commented out for manual review.
pub fn generate_toml(report: &DetectionReport) -> String {
    let mut out = String::new();

    writeln!(out, "# Generated by `cplt init`. Review before trusting.").unwrap();

    // List all detected ecosystems (root + workspace members)
    let mut all_ecosystems: Vec<&str> = report.detections.iter().map(|d| d.name).collect();
    for member in &report.workspace_members {
        for d in &member.detections {
            if !all_ecosystems.contains(&d.name) {
                all_ecosystems.push(d.name);
            }
        }
    }
    writeln!(out, "# Detected: {}", all_ecosystems.join(", ")).unwrap();

    // Show workspace members in header
    if !report.workspace_members.is_empty() {
        writeln!(out, "# Workspace members:").unwrap();
        for member in &report.workspace_members {
            let ecosystems: Vec<&str> = member.detections.iter().map(|d| d.name).collect();
            if ecosystems.is_empty() {
                writeln!(out, "#   {} ({})", member.relative_path, member.source).unwrap();
            } else {
                writeln!(
                    out,
                    "#   {} ({}): {}",
                    member.relative_path,
                    member.source,
                    ecosystems.join(", ")
                )
                .unwrap();
            }
        }
    }
    writeln!(out).unwrap();

    // Partition suggestions into repo-appropriate vs personal-config
    let mut deny_env: BTreeSet<&str> = BTreeSet::new();
    let mut deny_paths: BTreeSet<&str> = BTreeSet::new();
    let mut propose_flags: BTreeSet<&str> = BTreeSet::new();
    let mut allow_read: BTreeSet<&str> = BTreeSet::new();
    let mut allow_write: BTreeSet<&str> = BTreeSet::new();
    let mut allow_ports: BTreeSet<u16> = BTreeSet::new();
    let mut allow_localhost: BTreeSet<u16> = BTreeSet::new();
    let mut proxy_private: BTreeSet<&str> = BTreeSet::new();

    // Machine-specific suggestions → emitted as comments
    let mut personal_hints: Vec<String> = Vec::new();

    for s in &report.suggestions {
        match s {
            Suggestion::Propose(flag) => {
                propose_flags.insert(flag.key_name());
            }
            Suggestion::AllowRead(p) => {
                if is_home_relative(p) {
                    personal_hints.push(format!("allow.read = [\"{p}\"]  # in personal config"));
                } else {
                    allow_read.insert(p.as_str());
                }
            }
            Suggestion::AllowWrite(p) => {
                if is_home_relative(p) {
                    personal_hints.push(format!("allow.write = [\"{p}\"]  # in personal config"));
                } else {
                    allow_write.insert(p.as_str());
                }
            }
            Suggestion::AllowPort(p) => {
                allow_ports.insert(*p);
            }
            Suggestion::AllowLocalhost(p) => {
                allow_localhost.insert(*p);
            }
            Suggestion::AllowCacheExec(p) => {
                personal_hints.push(format!(
                    "sandbox.allow_cache_exec = [\"{p}\"]  # in personal config"
                ));
            }
            Suggestion::DenyEnv(v) => {
                deny_env.insert(v.as_str());
            }
            Suggestion::DenyPath(p) => {
                deny_paths.insert(p.as_str());
            }
            Suggestion::AllowPrivateDomain(d) => {
                proxy_private.insert(d.as_str());
            }
        }
    }

    // [deny] section — unconditionally applied (tightening)
    let has_deny = !deny_env.is_empty() || !deny_paths.is_empty();
    if has_deny {
        writeln!(out, "[deny]").unwrap();
        if !deny_env.is_empty() {
            write_string_array(&mut out, "env", &deny_env);
        }
        if !deny_paths.is_empty() {
            write_string_array(&mut out, "paths", &deny_paths);
        }
        writeln!(out).unwrap();
    }

    // [propose] section — requires trust acceptance (relaxing)
    let has_propose = !propose_flags.is_empty()
        || !allow_read.is_empty()
        || !allow_write.is_empty()
        || !allow_ports.is_empty()
        || !allow_localhost.is_empty()
        || !proxy_private.is_empty();

    if has_propose {
        writeln!(out, "[propose]").unwrap();
        for flag in &propose_flags {
            // Check if this is a dangerous flag from fallback-only sources
            let should_comment =
                should_comment_out_flag(flag, &report.provenance, &report.workspace_members);
            let provenance_comment = format_provenance(flag, &report.provenance);

            // Look up the SandboxFlag to check for risk warnings
            let warning = SandboxFlag::iter_all()
                .find(|f| f.key_name() == *flag)
                .and_then(SandboxFlag::risk_warning);

            if let Some(warning) = warning {
                writeln!(out, "# ⚠️  {warning}").unwrap();
            }
            if !provenance_comment.is_empty() {
                writeln!(out, "# Suggested by: {provenance_comment}").unwrap();
            }
            if should_comment {
                writeln!(
                    out,
                    "# {flag} = true  # uncomment after reviewing (from heuristic scan)"
                )
                .unwrap();
            } else {
                writeln!(out, "{flag} = true").unwrap();
            }
        }
        if !propose_flags.is_empty() {
            writeln!(out).unwrap();
        }

        // [propose.allow] sub-section for arrays
        let has_allow = !allow_read.is_empty()
            || !allow_write.is_empty()
            || !allow_ports.is_empty()
            || !allow_localhost.is_empty();

        if has_allow {
            writeln!(out, "[propose.allow]").unwrap();
            if !allow_read.is_empty() {
                write_string_array(&mut out, "read", &allow_read);
            }
            if !allow_write.is_empty() {
                write_string_array(&mut out, "write", &allow_write);
            }
            if !allow_ports.is_empty() {
                write_port_array(&mut out, "ports", &allow_ports);
            }
            if !allow_localhost.is_empty() {
                write_port_array(&mut out, "localhost", &allow_localhost);
            }
            writeln!(out).unwrap();
        }

        // [propose.proxy] sub-section
        if !proxy_private.is_empty() {
            writeln!(out, "[propose.proxy]").unwrap();
            write_string_array(&mut out, "allow_private_domains", &proxy_private);
            writeln!(out).unwrap();
        }
    }

    // Personal config hints (machine-specific settings)
    if !personal_hints.is_empty() {
        writeln!(
            out,
            "# The following are machine-specific. Add them to ~/.config/cplt/config.toml:"
        )
        .unwrap();
        for hint in &personal_hints {
            writeln!(out, "# {hint}").unwrap();
        }
        writeln!(out).unwrap();
    }

    out
}

/// Merge newly detected suggestions into an existing .cplt.toml.
///
/// Parses the existing config, adds new entries (ports, paths, flags) that
/// aren't already present, and regenerates the TOML. Preserves existing entries.
fn merge_toml(existing_content: &str, report: &DetectionReport) -> String {
    use crate::repo_config;

    let Ok(existing) = repo_config::parse_and_validate(existing_content) else {
        return generate_toml(report);
    };

    // Collect new suggestions
    let mut propose_flags: BTreeSet<&str> = BTreeSet::new();
    let mut allow_read: BTreeSet<&str> = BTreeSet::new();
    let mut allow_write: BTreeSet<&str> = BTreeSet::new();
    let mut allow_ports: BTreeSet<u16> = BTreeSet::new();
    let mut allow_localhost: BTreeSet<u16> = BTreeSet::new();
    let mut deny_env: BTreeSet<&str> = BTreeSet::new();
    let mut deny_paths: BTreeSet<&str> = BTreeSet::new();
    let mut proxy_private: BTreeSet<&str> = BTreeSet::new();

    for s in &report.suggestions {
        match s {
            Suggestion::Propose(flag) => {
                propose_flags.insert(flag.key_name());
            }
            Suggestion::AllowRead(p) if !is_home_relative(p) => {
                allow_read.insert(p.as_str());
            }
            Suggestion::AllowWrite(p) if !is_home_relative(p) => {
                allow_write.insert(p.as_str());
            }
            Suggestion::AllowPort(p) => {
                allow_ports.insert(*p);
            }
            Suggestion::AllowLocalhost(p) => {
                allow_localhost.insert(*p);
            }
            Suggestion::DenyEnv(v) => {
                deny_env.insert(v.as_str());
            }
            Suggestion::DenyPath(p) => {
                deny_paths.insert(p.as_str());
            }
            Suggestion::AllowPrivateDomain(d) => {
                proxy_private.insert(d.as_str());
            }
            _ => {}
        }
    }

    // Merge with existing: add items not already present
    for v in &existing.deny.env {
        deny_env.insert(v.as_str());
    }
    for p in &existing.deny.paths {
        deny_paths.insert(p.as_str());
    }
    let existing_flags = repo_config::proposed_keys(&existing.propose);
    for key in &existing_flags {
        // Only include boolean flags, not compound keys (allow.ports, etc.)
        if !key.contains('.') {
            propose_flags.insert(key);
        }
    }
    for p in &existing.propose.allow.read {
        allow_read.insert(p.as_str());
    }
    for p in &existing.propose.allow.write {
        allow_write.insert(p.as_str());
    }
    for p in &existing.propose.allow.ports {
        allow_ports.insert(*p);
    }
    for p in &existing.propose.allow.localhost {
        allow_localhost.insert(*p);
    }
    for d in &existing.propose.proxy.allow_private_domains {
        proxy_private.insert(d.as_str());
    }

    // Regenerate TOML with merged data
    let mut out = String::new();

    writeln!(
        out,
        "# Generated by `cplt init --merge`. Review before trusting."
    )
    .unwrap();

    let mut all_ecosystems: Vec<&str> = report.detections.iter().map(|d| d.name).collect();
    for member in &report.workspace_members {
        for d in &member.detections {
            if !all_ecosystems.contains(&d.name) {
                all_ecosystems.push(d.name);
            }
        }
    }
    writeln!(out, "# Detected: {}", all_ecosystems.join(", ")).unwrap();
    writeln!(out).unwrap();

    // [deny]
    let has_deny = !deny_env.is_empty() || !deny_paths.is_empty();
    if has_deny {
        writeln!(out, "[deny]").unwrap();
        if !deny_env.is_empty() {
            write_string_array(&mut out, "env", &deny_env);
        }
        if !deny_paths.is_empty() {
            write_string_array(&mut out, "paths", &deny_paths);
        }
        writeln!(out).unwrap();
    }

    // [propose]
    let has_propose = !propose_flags.is_empty()
        || !allow_read.is_empty()
        || !allow_write.is_empty()
        || !allow_ports.is_empty()
        || !allow_localhost.is_empty()
        || !proxy_private.is_empty();

    if has_propose {
        writeln!(out, "[propose]").unwrap();
        for flag in &propose_flags {
            writeln!(out, "{flag} = true").unwrap();
        }
        if !propose_flags.is_empty() {
            writeln!(out).unwrap();
        }

        let has_allow = !allow_read.is_empty()
            || !allow_write.is_empty()
            || !allow_ports.is_empty()
            || !allow_localhost.is_empty();

        if has_allow {
            writeln!(out, "[propose.allow]").unwrap();
            if !allow_read.is_empty() {
                write_string_array(&mut out, "read", &allow_read);
            }
            if !allow_write.is_empty() {
                write_string_array(&mut out, "write", &allow_write);
            }
            if !allow_ports.is_empty() {
                write_port_array(&mut out, "ports", &allow_ports);
            }
            if !allow_localhost.is_empty() {
                write_port_array(&mut out, "localhost", &allow_localhost);
            }
            writeln!(out).unwrap();
        }

        if !proxy_private.is_empty() {
            writeln!(out, "[propose.proxy]").unwrap();
            write_string_array(&mut out, "allow_private_domains", &proxy_private);
            writeln!(out).unwrap();
        }
    }

    out
}

/// Check if a dangerous flag should be commented out because it was only
/// suggested by heuristic fallback scans (not by explicit workspace configs or root).
fn should_comment_out_flag(
    flag_key: &str,
    provenance: &BTreeMap<Suggestion, BTreeSet<String>>,
    workspace_members: &[crate::detect::WorkspaceMember],
) -> bool {
    // Only comment out dangerous flags
    let is_dangerous = SandboxFlag::iter_all()
        .find(|f| f.key_name() == flag_key)
        .is_some_and(|f| f.risk_warning().is_some());

    if !is_dangerous || provenance.is_empty() {
        return false;
    }

    // Find the provenance for this flag
    let flag_suggestion = SandboxFlag::iter_all()
        .find(|f| f.key_name() == flag_key)
        .map(Suggestion::Propose);

    let Some(sources) = flag_suggestion.and_then(|s| provenance.get(&s)) else {
        return false;
    };

    // If any source is root ("."), it's explicitly detected — don't comment out
    if sources.contains(".") {
        return false;
    }

    // Check if all contributing paths come from fallback-discovered members
    sources.iter().all(|path| {
        workspace_members.iter().any(|m| {
            m.relative_path == *path && m.source == crate::detect::WorkspaceSource::Fallback
        })
    })
}

/// Format provenance for a flag as a human-readable string.
fn format_provenance(
    flag_key: &str,
    provenance: &BTreeMap<Suggestion, BTreeSet<String>>,
) -> String {
    if provenance.is_empty() {
        return String::new();
    }

    let flag_suggestion = SandboxFlag::iter_all()
        .find(|f| f.key_name() == flag_key)
        .map(Suggestion::Propose);

    let Some(sources) = flag_suggestion.and_then(|s| provenance.get(&s)) else {
        return String::new();
    };

    sources
        .iter()
        .map(|s| if s == "." { "(root)" } else { s.as_str() })
        .collect::<Vec<_>>()
        .join(", ")
}

/// Check if a path starts with ~ (home-relative, not appropriate for repo config).
fn is_home_relative(path: &str) -> bool {
    path.starts_with('~')
}

/// Escape a string for use in TOML basic strings (double-quoted).
/// Prevents injection of arbitrary TOML via crafted file content.
fn toml_escape(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
        .replace('\t', "\\t")
}

fn write_string_array(out: &mut String, key: &str, values: &BTreeSet<&str>) {
    if values.len() == 1 {
        writeln!(
            out,
            "{key} = [\"{}\"]",
            toml_escape(values.iter().next().unwrap())
        )
        .unwrap();
    } else {
        writeln!(out, "{key} = [").unwrap();
        for val in values {
            writeln!(out, "  \"{}\",", toml_escape(val)).unwrap();
        }
        writeln!(out, "]").unwrap();
    }
}

fn write_port_array(out: &mut String, key: &str, values: &BTreeSet<u16>) {
    let ports: Vec<String> = values.iter().map(ToString::to_string).collect();
    writeln!(out, "{key} = [{}]", ports.join(", ")).unwrap();
}

// ══════════════════════════════════════════════════════════════════════
// Global config generation — for `cplt init --global`
// ══════════════════════════════════════════════════════════════════════

use crate::detect::{GlobalDetectionReport, GlobalSuggestion};

/// Format a human-readable report of global detections.
pub fn format_global_report(report: &GlobalDetectionReport) -> String {
    let mut out = String::new();
    if report.detections.is_empty() {
        return out;
    }
    writeln!(out, "Detected machine-level configuration:").unwrap();
    writeln!(out).unwrap();
    for det in &report.detections {
        writeln!(out, "  • {}", det.name).unwrap();
        writeln!(out, "    ↳ {}", det.reason).unwrap();
        if !det.suggestions.is_empty() {
            writeln!(out, "    Suggests:").unwrap();
            for s in &det.suggestions {
                writeln!(out, "      {}", format_global_suggestion(s)).unwrap();
            }
        }
        writeln!(out).unwrap();
    }
    out
}

fn format_global_suggestion(s: &GlobalSuggestion) -> String {
    match s {
        GlobalSuggestion::CacheExec(name) => {
            format!("sandbox.allow_cache_exec = [\"{name}\"]")
        }
        GlobalSuggestion::GpgSigning => "sandbox.allow_gpg_signing = true".to_string(),
        GlobalSuggestion::AllowRead(path) => format!("allow.read = [\"{path}\"]"),
        GlobalSuggestion::SetAgent(name) => format!("sandbox.agent = \"{name}\""),
    }
}

/// Generate a valid personal config TOML from global detection.
pub fn generate_global_toml(report: &GlobalDetectionReport) -> String {
    let mut out = String::new();

    writeln!(
        out,
        "# Generated by `cplt init --global`. Review before use."
    )
    .unwrap();
    writeln!(
        out,
        "# Detected: {}",
        report
            .detections
            .iter()
            .map(|d| d.name)
            .collect::<Vec<_>>()
            .join(", ")
    )
    .unwrap();
    writeln!(out).unwrap();

    // Collect suggestions by section
    let mut cache_exec: BTreeSet<&str> = BTreeSet::new();
    let mut allow_read: BTreeSet<&str> = BTreeSet::new();
    let mut gpg_signing = false;
    let mut agent: Option<&str> = None;

    for det in &report.detections {
        for s in &det.suggestions {
            match s {
                GlobalSuggestion::CacheExec(name) => {
                    cache_exec.insert(name.as_str());
                }
                GlobalSuggestion::GpgSigning => gpg_signing = true,
                GlobalSuggestion::AllowRead(path) => {
                    allow_read.insert(path.as_str());
                }
                GlobalSuggestion::SetAgent(name) => agent = Some(name.as_str()),
            }
        }
    }

    // [sandbox] section
    let has_sandbox = !cache_exec.is_empty() || gpg_signing || agent.is_some();
    if has_sandbox {
        writeln!(out, "[sandbox]").unwrap();
        if let Some(a) = agent {
            writeln!(out, "agent = \"{}\"", toml_escape(a)).unwrap();
        }
        if gpg_signing {
            writeln!(out, "allow_gpg_signing = true").unwrap();
        }
        if !cache_exec.is_empty() {
            write_string_array(&mut out, "allow_cache_exec", &cache_exec);
        }
        writeln!(out).unwrap();
    }

    // [allow] section
    if !allow_read.is_empty() {
        writeln!(out, "[allow]").unwrap();
        write_string_array(&mut out, "read", &allow_read);
        writeln!(out).unwrap();
    }

    out
}

/// Result of running init --global.
pub enum GlobalInitResult {
    /// Config was generated (and possibly written).
    Generated {
        toml: String,
        written: bool,
        path: std::path::PathBuf,
    },
    /// File already exists and --force not given.
    AlreadyExists(std::path::PathBuf),
    /// Write failed.
    WriteFailed(std::path::PathBuf, std::io::Error),
}

/// Run the global init workflow.
pub fn run_init_global(
    config_path: &Path,
    report: &GlobalDetectionReport,
    opts: &InitOptions,
) -> GlobalInitResult {
    let toml = generate_global_toml(report);

    if !opts.write {
        return GlobalInitResult::Generated {
            toml,
            written: false,
            path: config_path.to_path_buf(),
        };
    }

    if config_path.exists() && !opts.force {
        return GlobalInitResult::AlreadyExists(config_path.to_path_buf());
    }

    // Ensure parent directory exists
    if let Some(parent) = config_path.parent()
        && let Err(e) = std::fs::create_dir_all(parent)
    {
        return GlobalInitResult::WriteFailed(config_path.to_path_buf(), e);
    }

    match std::fs::write(config_path, &toml) {
        Ok(()) => GlobalInitResult::Generated {
            toml,
            written: true,
            path: config_path.to_path_buf(),
        },
        Err(e) => GlobalInitResult::WriteFailed(config_path.to_path_buf(), e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detect::{SandboxFlag, Signal, Suggestion};

    #[test]
    fn generates_propose_flags() {
        let report = DetectionReport {
            detections: vec![Detection {
                name: "Docker",
                signals: vec![Signal::FileExists {
                    path: "Dockerfile".to_string(),
                }],
                suggestions: vec![Suggestion::Propose(SandboxFlag::AllowDocker)],
            }],
            suggestions: [Suggestion::Propose(SandboxFlag::AllowDocker)]
                .into_iter()
                .collect(),
            diagnostics: vec![],
            workspace_members: vec![],
            provenance: std::collections::BTreeMap::new(),
        };

        let toml = generate_toml(&report);
        assert!(toml.contains("[propose]"));
        assert!(toml.contains("allow_docker = true"));
    }

    #[test]
    fn generates_deny_env() {
        let report = DetectionReport {
            detections: vec![Detection {
                name: "Environment secrets",
                signals: vec![],
                suggestions: vec![Suggestion::DenyEnv("API_SECRET_KEY".to_string())],
            }],
            suggestions: [Suggestion::DenyEnv("API_SECRET_KEY".to_string())]
                .into_iter()
                .collect(),
            diagnostics: vec![],
            workspace_members: vec![],
            provenance: std::collections::BTreeMap::new(),
        };

        let toml = generate_toml(&report);
        assert!(toml.contains("[deny]"));
        assert!(toml.contains("API_SECRET_KEY"));
    }

    #[test]
    fn generates_allow_arrays() {
        let report = DetectionReport {
            detections: vec![Detection {
                name: "JVM (Gradle)",
                signals: vec![],
                suggestions: vec![
                    Suggestion::Propose(SandboxFlag::AllowJvmAttach),
                    Suggestion::AllowRead("~/.gradle/gradle.properties".to_string()),
                ],
            }],
            suggestions: [
                Suggestion::Propose(SandboxFlag::AllowJvmAttach),
                Suggestion::AllowRead("~/.gradle/gradle.properties".to_string()),
            ]
            .into_iter()
            .collect(),
            diagnostics: vec![],
            workspace_members: vec![],
            provenance: std::collections::BTreeMap::new(),
        };

        let toml = generate_toml(&report);
        // Home-relative paths go to personal config hints (comments)
        assert!(!toml.contains("[propose.allow]"));
        assert!(toml.contains("~/.gradle/gradle.properties"));
        assert!(toml.contains("# in personal config"));
        assert!(toml.contains("allow_jvm_attach = true"));
    }

    #[test]
    fn generates_port_arrays() {
        let report = DetectionReport {
            detections: vec![Detection {
                name: "Docker",
                signals: vec![],
                suggestions: vec![
                    Suggestion::AllowPort(5432),
                    Suggestion::AllowPort(8080),
                    Suggestion::AllowLocalhost(3000),
                ],
            }],
            suggestions: [
                Suggestion::AllowPort(5432),
                Suggestion::AllowPort(8080),
                Suggestion::AllowLocalhost(3000),
            ]
            .into_iter()
            .collect(),
            diagnostics: vec![],
            workspace_members: vec![],
            provenance: std::collections::BTreeMap::new(),
        };

        let toml = generate_toml(&report);
        assert!(toml.contains("ports = [5432, 8080]"));
        assert!(toml.contains("localhost = [3000]"));
    }

    #[test]
    fn multi_ecosystem_generates_merged_toml() {
        let report = DetectionReport {
            detections: vec![
                Detection {
                    name: "JVM (Gradle)",
                    signals: vec![],
                    suggestions: vec![Suggestion::Propose(SandboxFlag::AllowJvmAttach)],
                },
                Detection {
                    name: "Docker",
                    signals: vec![],
                    suggestions: vec![
                        Suggestion::Propose(SandboxFlag::AllowDocker),
                        Suggestion::AllowPort(5432),
                    ],
                },
            ],
            suggestions: [
                Suggestion::Propose(SandboxFlag::AllowJvmAttach),
                Suggestion::Propose(SandboxFlag::AllowDocker),
                Suggestion::AllowPort(5432),
            ]
            .into_iter()
            .collect(),
            diagnostics: vec![],
            workspace_members: vec![],
            provenance: std::collections::BTreeMap::new(),
        };

        let toml = generate_toml(&report);
        assert!(toml.contains("allow_docker = true"));
        assert!(toml.contains("allow_jvm_attach = true"));
        assert!(toml.contains("ports = [5432]"));
        // Header should mention both
        assert!(toml.contains("JVM (Gradle)"));
        assert!(toml.contains("Docker"));
    }

    #[test]
    fn empty_report_minimal_output() {
        let report = DetectionReport {
            detections: vec![Detection {
                name: "Rust",
                signals: vec![],
                suggestions: vec![],
            }],
            suggestions: BTreeSet::new(),
            diagnostics: vec![],
            workspace_members: vec![],
            provenance: std::collections::BTreeMap::new(),
        };

        let toml = generate_toml(&report);
        // Should just have the header comment and nothing else
        assert!(toml.contains("# Generated by"));
        assert!(!toml.contains("[deny]"));
        assert!(!toml.contains("[propose]"));
    }

    #[test]
    fn init_nothing_detected_on_empty_dir() {
        let dir = tempfile::tempdir().unwrap();
        let report = crate::detect::detect_project(dir.path());
        let result = run_init(
            dir.path(),
            &report,
            &InitOptions {
                write: false,
                force: false,
                merge: false,
                quiet: false,
            },
        );
        assert!(matches!(result, InitResult::NothingDetected));
    }

    #[test]
    fn init_generates_preview() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("Cargo.toml"), "[package]\nname=\"x\"").unwrap();
        let report = crate::detect::detect_project(dir.path());
        let result = run_init(
            dir.path(),
            &report,
            &InitOptions {
                write: false,
                force: false,
                merge: false,
                quiet: false,
            },
        );
        match result {
            InitResult::Generated { written, .. } => assert!(!written),
            _ => panic!("expected Generated"),
        }
    }

    #[test]
    fn init_writes_file() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("Dockerfile"), "FROM node:20").unwrap();
        let report = crate::detect::detect_project(dir.path());
        let result = run_init(
            dir.path(),
            &report,
            &InitOptions {
                write: true,
                force: false,
                merge: false,
                quiet: false,
            },
        );
        match result {
            InitResult::Generated { written, path, .. } => {
                assert!(written);
                assert!(path.exists());
                let content = std::fs::read_to_string(&path).unwrap();
                assert!(content.contains("allow_docker"));
            }
            _ => panic!("expected Generated"),
        }
    }

    #[test]
    fn init_refuses_overwrite_without_force() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("Dockerfile"), "FROM node:20").unwrap();
        std::fs::write(dir.path().join(".cplt.toml"), "# existing").unwrap();
        let report = crate::detect::detect_project(dir.path());
        let result = run_init(
            dir.path(),
            &report,
            &InitOptions {
                write: true,
                force: false,
                merge: false,
                quiet: false,
            },
        );
        assert!(matches!(result, InitResult::AlreadyExists(_)));
    }

    #[test]
    fn init_overwrites_with_force() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("Dockerfile"), "FROM node:20").unwrap();
        std::fs::write(dir.path().join(".cplt.toml"), "# existing").unwrap();
        let report = crate::detect::detect_project(dir.path());
        let result = run_init(
            dir.path(),
            &report,
            &InitOptions {
                write: true,
                force: true,
                merge: false,
                quiet: false,
            },
        );
        assert!(matches!(
            result,
            InitResult::Generated { written: true, .. }
        ));
    }

    #[test]
    fn format_report_includes_ecosystems() {
        let report = DetectionReport {
            detections: vec![Detection {
                name: "Node.js",
                signals: vec![Signal::FileExists {
                    path: "package.json".to_string(),
                }],
                suggestions: vec![Suggestion::Propose(SandboxFlag::AllowLocalhostAny)],
            }],
            suggestions: [Suggestion::Propose(SandboxFlag::AllowLocalhostAny)]
                .into_iter()
                .collect(),
            diagnostics: vec![],
            workspace_members: vec![],
            provenance: std::collections::BTreeMap::new(),
        };

        let text = format_report(&report);
        assert!(text.contains("Node.js"));
        assert!(text.contains("package.json"));
        assert!(text.contains("allow_localhost_any"));
    }

    #[test]
    fn cache_exec_goes_to_personal_hint() {
        let report = DetectionReport {
            detections: vec![Detection {
                name: "Playwright",
                signals: vec![],
                suggestions: vec![Suggestion::AllowCacheExec("ms-playwright".to_string())],
            }],
            suggestions: [Suggestion::AllowCacheExec("ms-playwright".to_string())]
                .into_iter()
                .collect(),
            diagnostics: vec![],
            workspace_members: vec![],
            provenance: std::collections::BTreeMap::new(),
        };

        let toml = generate_toml(&report);
        // Should NOT be in [propose.allow] as a real key
        assert!(!toml.contains("[propose.allow]"));
        // Should be in personal config hint comment
        assert!(toml.contains("# sandbox.allow_cache_exec"));
        assert!(toml.contains("ms-playwright"));
        assert!(toml.contains("personal config"));
    }

    #[test]
    fn generated_toml_parses_as_valid_repo_config() {
        // Roundtrip: generate TOML → parse with repo_config deserializer
        let report = DetectionReport {
            detections: vec![
                Detection {
                    name: "Docker",
                    signals: vec![],
                    suggestions: vec![
                        Suggestion::Propose(SandboxFlag::AllowDocker),
                        Suggestion::AllowPort(5432),
                        Suggestion::AllowLocalhost(3000),
                    ],
                },
                Detection {
                    name: "Environment secrets",
                    signals: vec![],
                    suggestions: vec![Suggestion::DenyEnv("SECRET_KEY".to_string())],
                },
            ],
            suggestions: [
                Suggestion::Propose(SandboxFlag::AllowDocker),
                Suggestion::AllowPort(5432),
                Suggestion::AllowLocalhost(3000),
                Suggestion::DenyEnv("SECRET_KEY".to_string()),
            ]
            .into_iter()
            .collect(),
            diagnostics: vec![],
            workspace_members: vec![],
            provenance: std::collections::BTreeMap::new(),
        };

        let toml_str = generate_toml(&report);
        // Should parse without error
        let parsed: crate::repo_config::RepoConfig =
            toml::from_str(&toml_str).expect("generated TOML should parse as valid RepoConfig");

        assert_eq!(parsed.propose.allow_docker, Some(true));
        assert_eq!(parsed.propose.allow.ports, vec![5432]);
        assert_eq!(parsed.propose.allow.localhost, vec![3000]);
        assert_eq!(parsed.deny.env, vec!["SECRET_KEY"]);
    }

    // ── Global config generation tests ───────────────────────────────

    use crate::detect::{GlobalDetection, GlobalDetectionReport, GlobalSuggestion};

    #[test]
    fn global_empty_report_generates_minimal_toml() {
        let report = GlobalDetectionReport { detections: vec![] };
        let toml = generate_global_toml(&report);
        assert!(toml.contains("# Generated by"));
        assert!(!toml.contains("[sandbox]"));
        assert!(!toml.contains("[allow]"));
    }

    #[test]
    fn global_cache_exec_generates_sandbox_section() {
        let report = GlobalDetectionReport {
            detections: vec![GlobalDetection {
                name: "Playwright browsers",
                reason: "ms-playwright cache directory exists".to_string(),
                suggestions: vec![GlobalSuggestion::CacheExec("ms-playwright".to_string())],
            }],
        };
        let toml = generate_global_toml(&report);
        assert!(toml.contains("[sandbox]"));
        assert!(toml.contains("allow_cache_exec = [\"ms-playwright\"]"));
    }

    #[test]
    fn global_gpg_generates_flag() {
        let report = GlobalDetectionReport {
            detections: vec![GlobalDetection {
                name: "GPG signing",
                reason: "git commit.gpgsign=true".to_string(),
                suggestions: vec![GlobalSuggestion::GpgSigning],
            }],
        };
        let toml = generate_global_toml(&report);
        assert!(toml.contains("allow_gpg_signing = true"));
    }

    #[test]
    fn global_allow_read_generates_allow_section() {
        let report = GlobalDetectionReport {
            detections: vec![GlobalDetection {
                name: "Gradle registry",
                reason: "contains repo config".to_string(),
                suggestions: vec![GlobalSuggestion::AllowRead(
                    "~/.gradle/gradle.properties".to_string(),
                )],
            }],
        };
        let toml = generate_global_toml(&report);
        assert!(toml.contains("[allow]"));
        assert!(toml.contains("read = [\"~/.gradle/gradle.properties\"]"));
    }

    #[test]
    fn global_agent_generates_sandbox_agent() {
        let report = GlobalDetectionReport {
            detections: vec![GlobalDetection {
                name: "Default agent",
                reason: "opencode found in PATH".to_string(),
                suggestions: vec![GlobalSuggestion::SetAgent("opencode".to_string())],
            }],
        };
        let toml = generate_global_toml(&report);
        assert!(toml.contains("agent = \"opencode\""));
    }

    #[test]
    fn global_multi_detection_merges() {
        let report = GlobalDetectionReport {
            detections: vec![
                GlobalDetection {
                    name: "pnpm dlx",
                    reason: "exists".to_string(),
                    suggestions: vec![GlobalSuggestion::CacheExec("pnpm/dlx".to_string())],
                },
                GlobalDetection {
                    name: "Playwright browsers",
                    reason: "exists".to_string(),
                    suggestions: vec![GlobalSuggestion::CacheExec("ms-playwright".to_string())],
                },
                GlobalDetection {
                    name: "GPG signing",
                    reason: "configured".to_string(),
                    suggestions: vec![GlobalSuggestion::GpgSigning],
                },
            ],
        };
        let toml = generate_global_toml(&report);
        assert!(toml.contains("[sandbox]"));
        assert!(toml.contains("allow_gpg_signing = true"));
        // Both cache_exec entries merged into one array
        assert!(toml.contains("\"pnpm/dlx\""));
        assert!(toml.contains("\"ms-playwright\""));
    }

    #[test]
    fn global_generated_toml_is_valid() {
        let report = GlobalDetectionReport {
            detections: vec![
                GlobalDetection {
                    name: "Playwright",
                    reason: "test".to_string(),
                    suggestions: vec![
                        GlobalSuggestion::CacheExec("ms-playwright".to_string()),
                        GlobalSuggestion::AllowRead("~/.gradle/gradle.properties".to_string()),
                    ],
                },
                GlobalDetection {
                    name: "GPG",
                    reason: "test".to_string(),
                    suggestions: vec![GlobalSuggestion::GpgSigning],
                },
            ],
        };
        let toml = generate_global_toml(&report);
        // Must parse as valid TOML (uses Config struct from config module)
        let parsed: toml::Value = toml::from_str(&toml)
            .unwrap_or_else(|e| panic!("Generated TOML should be valid: {e}\n\n{toml}"));
        // Verify structure
        let sandbox = parsed.get("sandbox").unwrap().as_table().unwrap();
        assert_eq!(
            sandbox.get("allow_gpg_signing").unwrap().as_bool(),
            Some(true)
        );
        let cache_exec = sandbox.get("allow_cache_exec").unwrap().as_array().unwrap();
        assert_eq!(cache_exec.len(), 1);
        let allow = parsed.get("allow").unwrap().as_table().unwrap();
        let read = allow.get("read").unwrap().as_array().unwrap();
        assert_eq!(read.len(), 1);
    }

    // ── Merge tests ──────────────────────────────────────────────────

    #[test]
    fn merge_preserves_existing_ports_and_adds_new() {
        let existing = "\
[propose]
allow_docker = true

[propose.allow]
ports = [5432, 3000]
";

        let report = DetectionReport {
            detections: vec![Detection {
                name: "Docker",
                signals: vec![Signal::FileExists {
                    path: "docker-compose.yml".to_string(),
                }],
                suggestions: vec![
                    Suggestion::Propose(SandboxFlag::AllowDocker),
                    Suggestion::AllowPort(8080),
                    Suggestion::AllowPort(3000), // duplicate — should not double
                ],
            }],
            suggestions: [
                Suggestion::Propose(SandboxFlag::AllowDocker),
                Suggestion::AllowPort(8080),
                Suggestion::AllowPort(3000),
            ]
            .into_iter()
            .collect(),
            diagnostics: vec![],
            workspace_members: vec![],
            provenance: std::collections::BTreeMap::new(),
        };

        let merged = merge_toml(existing, &report);
        let parsed: crate::repo_config::RepoConfig =
            toml::from_str(&merged).expect("merged TOML should be valid");

        assert_eq!(parsed.propose.allow_docker, Some(true));
        // All three ports present, no duplicates
        let mut ports = parsed.propose.allow.ports.clone();
        ports.sort_unstable();
        assert_eq!(ports, vec![3000, 5432, 8080]);
    }

    #[test]
    fn merge_preserves_existing_flags_and_deny() {
        let existing = r#"
[deny]
env = ["SECRET_KEY"]

[propose]
allow_jvm_attach = true
"#;

        let report = DetectionReport {
            detections: vec![Detection {
                name: "Docker",
                signals: vec![Signal::FileExists {
                    path: "Dockerfile".to_string(),
                }],
                suggestions: vec![
                    Suggestion::Propose(SandboxFlag::AllowDocker),
                    Suggestion::DenyEnv("DB_PASSWORD".to_string()),
                ],
            }],
            suggestions: [
                Suggestion::Propose(SandboxFlag::AllowDocker),
                Suggestion::DenyEnv("DB_PASSWORD".to_string()),
            ]
            .into_iter()
            .collect(),
            diagnostics: vec![],
            workspace_members: vec![],
            provenance: std::collections::BTreeMap::new(),
        };

        let merged = merge_toml(existing, &report);
        let parsed: crate::repo_config::RepoConfig =
            toml::from_str(&merged).expect("merged TOML should be valid");

        // Existing deny preserved + new one added
        assert!(parsed.deny.env.contains(&"SECRET_KEY".to_string()));
        assert!(parsed.deny.env.contains(&"DB_PASSWORD".to_string()));
        // Existing flag preserved
        assert_eq!(parsed.propose.allow_jvm_attach, Some(true));
        // New flag added
        assert_eq!(parsed.propose.allow_docker, Some(true));
    }

    #[test]
    fn merge_with_write_updates_file() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("Dockerfile"), "FROM node:20").unwrap();
        std::fs::write(
            dir.path().join(".cplt.toml"),
            "[propose]\nallow_jvm_attach = true\n\n[propose.allow]\nports = [9999]\n",
        )
        .unwrap();

        let report = DetectionReport {
            detections: vec![Detection {
                name: "Docker",
                signals: vec![Signal::FileExists {
                    path: "Dockerfile".to_string(),
                }],
                suggestions: vec![
                    Suggestion::Propose(SandboxFlag::AllowDocker),
                    Suggestion::AllowPort(8080),
                ],
            }],
            suggestions: [
                Suggestion::Propose(SandboxFlag::AllowDocker),
                Suggestion::AllowPort(8080),
            ]
            .into_iter()
            .collect(),
            diagnostics: vec![],
            workspace_members: vec![],
            provenance: std::collections::BTreeMap::new(),
        };

        let result = run_init(
            dir.path(),
            &report,
            &InitOptions {
                write: true,
                force: false,
                merge: true,
                quiet: false,
            },
        );
        match result {
            InitResult::Generated { written, path, .. } => {
                assert!(written);
                let content = std::fs::read_to_string(&path).unwrap();
                let parsed: crate::repo_config::RepoConfig =
                    toml::from_str(&content).expect("should parse");
                // Existing port preserved
                assert!(parsed.propose.allow.ports.contains(&9999));
                // New port added
                assert!(parsed.propose.allow.ports.contains(&8080));
                // Existing flag preserved
                assert_eq!(parsed.propose.allow_jvm_attach, Some(true));
                // New flag added
                assert_eq!(parsed.propose.allow_docker, Some(true));
            }
            _ => panic!("expected Generated with written=true"),
        }
    }

    #[test]
    fn init_without_merge_refuses_existing() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("Dockerfile"), "FROM node:20").unwrap();
        std::fs::write(dir.path().join(".cplt.toml"), "# existing\n").unwrap();

        let report = DetectionReport {
            detections: vec![Detection {
                name: "Docker",
                signals: vec![Signal::FileExists {
                    path: "Dockerfile".to_string(),
                }],
                suggestions: vec![Suggestion::Propose(SandboxFlag::AllowDocker)],
            }],
            suggestions: [Suggestion::Propose(SandboxFlag::AllowDocker)]
                .into_iter()
                .collect(),
            diagnostics: vec![],
            workspace_members: vec![],
            provenance: std::collections::BTreeMap::new(),
        };

        // Without merge or force → AlreadyExists
        let result = run_init(
            dir.path(),
            &report,
            &InitOptions {
                write: true,
                force: false,
                merge: false,
                quiet: false,
            },
        );
        assert!(matches!(result, InitResult::AlreadyExists(_)));
    }
}
