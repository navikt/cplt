//! Interactive settings editor backed by the same config documents as `cplt config`.
//!
//! The TUI stages changes and writes them atomically only after validation. It
//! deliberately does not run inside a sandbox: a sandboxed agent must never be
//! able to alter the user's policy or repository trust decisions.

use std::collections::HashMap;
use std::io::{self, IsTerminal};
use std::path::{Path, PathBuf};

use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind, KeyModifiers},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::{
    Terminal,
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::Line,
    widgets::{Block, Borders, Cell, Clear, Paragraph, Row, Table, TableState, Tabs, Wrap},
};

use crate::config::{
    self, ConfigKeyInfo, ConfigValueType, RepoKeyTarget, Resolved, all_config_keys,
    append_value_in_doc, get_value_from_doc, repo_key_target, security_confirmation,
    set_repo_value_in_doc, set_value_in_doc, unset_value_in_doc, validate_global_document,
    write_document_atomically, write_repo_document_atomically,
};
use crate::{repo_config, trust};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Scope {
    Effective,
    Global,
    Repository,
}

impl Scope {
    const ALL: [Self; 3] = [Self::Effective, Self::Global, Self::Repository];

    fn label(self) -> &'static str {
        match self {
            Self::Effective => "Effective",
            Self::Global => "Global",
            Self::Repository => "Repository",
        }
    }
}

#[derive(Clone)]
struct PendingChange {
    key: &'static ConfigKeyInfo,
    scope: Scope,
    value: Option<String>,
}

#[derive(Clone, Debug)]
struct EffectiveSetting {
    value: String,
    source: &'static str,
}

struct SettingsApp {
    scope: Scope,
    selected: usize,
    filter: String,
    editing_filter: bool,
    editing_value: bool,
    value_input: String,
    status: String,
    pending: Vec<PendingChange>,
    global_doc: toml_edit::DocumentMut,
    global_path: PathBuf,
    repo_doc: toml_edit::DocumentMut,
    repo_path: PathBuf,
    project_dir: PathBuf,
    effective: HashMap<(&'static str, &'static str), EffectiveSetting>,
    dangerous_confirmation: Option<String>,
}

impl SettingsApp {
    fn load() -> Result<Self, String> {
        let global_path = config::config_path().ok_or("$HOME is not set")?;
        let global_doc = load_doc(&global_path)?;
        let project_dir = detect_project_root()
            .or_else(|| std::env::current_dir().ok())
            .ok_or("cannot determine project directory")?;
        let repo_path = project_dir.join(repo_config::REPO_CONFIG_FILE);
        let repo_doc = load_doc(&repo_path)?;
        let effective = effective_snapshot(&global_doc, &project_dir)?;
        Ok(Self {
            scope: Scope::Effective,
            selected: 0,
            filter: String::new(),
            editing_filter: false,
            editing_value: false,
            value_input: String::new(),
            status: "Use / to search, Tab to change scope, Enter to edit, Ctrl+S to save."
                .to_string(),
            pending: Vec::new(),
            global_doc,
            global_path,
            repo_doc,
            repo_path,
            project_dir,
            effective,
            dangerous_confirmation: None,
        })
    }

    fn visible_keys(&self) -> Vec<&'static ConfigKeyInfo> {
        all_config_keys()
            .iter()
            .filter(|key| {
                if self.scope == Scope::Repository && repo_key_target(key).is_none() {
                    return false;
                }
                let needle = self.filter.to_ascii_lowercase();
                needle.is_empty()
                    || format!("{}.{} {}", key.section, key.key, key.description)
                        .to_ascii_lowercase()
                        .contains(&needle)
            })
            .collect()
    }

    fn selected_key(&self) -> Option<&'static ConfigKeyInfo> {
        self.visible_keys().get(self.selected).copied()
    }

    fn set_scope(&mut self, scope: Scope) {
        self.scope = scope;
        self.selected = 0;
        self.status = match scope {
            Scope::Repository => {
                "Repository edits update the working tree. Commit .cplt.toml, then review with `cplt trust`."
                    .to_string()
            }
            _ => format!("{} settings", scope.label()),
        };
    }

    fn stage(&mut self, key: &'static ConfigKeyInfo, value: Option<String>) {
        self.pending.retain(|change| {
            !(change.key.section == key.section
                && change.key.key == key.key
                && change.scope == self.scope)
        });
        let is_original = match self.scope {
            Scope::Global => match value.as_deref() {
                Some(value) if !key.value_type.is_array() => {
                    get_value_from_doc(&self.global_doc, key)
                        .unwrap_or_else(|| key.default_display.to_string())
                        == value
                }
                None => get_value_from_doc(&self.global_doc, key).is_none(),
                _ => false,
            },
            Scope::Repository => match value.as_deref() {
                Some("true")
                    if matches!(repo_key_target(key), Some(RepoKeyTarget::ProposeBool)) =>
                {
                    repo_proposal_enabled(&self.repo_doc, key)
                }
                None => repo_value_is_unset(&self.repo_doc, key),
                _ => false,
            },
            Scope::Effective => true,
        };
        if !is_original {
            self.pending.push(PendingChange {
                key,
                scope: self.scope,
                value,
            });
        }
        self.status = format!(
            "{} {}.{} for {}. Ctrl+S saves {} change(s).",
            if is_original { "Reverted" } else { "Staged" },
            key.section,
            key.key,
            self.scope.label().to_ascii_lowercase(),
            self.pending.len()
        );
    }

    fn toggle_selected(&mut self) {
        let Some(key) = self.selected_key() else {
            return;
        };
        if key.value_type != ConfigValueType::Bool {
            self.status =
                "Only boolean settings can be toggled. Press Enter to edit this value.".to_string();
            return;
        }
        if self.scope == Scope::Effective {
            self.status =
                "Effective values are read-only. Switch to Global or Repository.".to_string();
            return;
        }
        if self.scope == Scope::Repository {
            let Some(RepoKeyTarget::ProposeBool) = repo_key_target(key) else {
                self.status = "Repository deny and list values are edited with Enter.".to_string();
                return;
            };
            let preview = self.preview_repo_doc();
            if repo_proposal_enabled(&preview, key) {
                self.stage(key, None);
            } else {
                self.stage(key, Some("true".to_string()));
            }
        } else {
            let preview = self.preview_global_doc();
            let value = get_value_from_doc(&preview, key)
                .unwrap_or_else(|| key.default_display.to_string());
            self.stage(
                key,
                Some(if value == "true" { "false" } else { "true" }.to_string()),
            );
        }
    }

    fn begin_value_edit(&mut self) {
        let Some(key) = self.selected_key() else {
            return;
        };
        if self.scope == Scope::Effective {
            self.status =
                "Effective values are read-only. Switch to Global or Repository.".to_string();
            return;
        }
        if key.value_type == ConfigValueType::ArrayOfTables {
            self.status = format!(
                "{}.{}, an array of tables, is read-only here. Edit TOML directly.",
                key.section, key.key
            );
            return;
        }
        self.value_input = if is_sensitive(key) {
            self.status = format!(
                "Current {}.{} credentials are hidden. Enter a replacement; Esc cancels.",
                key.section, key.key
            );
            String::new()
        } else if self.scope == Scope::Global && !key.value_type.is_array() {
            get_value_from_doc(&self.preview_global_doc(), key).unwrap_or_default()
        } else {
            String::new()
        };
        self.editing_value = true;
        if !is_sensitive(key) {
            self.status = format!(
                "Enter a value for {}.{}; Enter stages it, Esc cancels.",
                key.section, key.key
            );
        }
    }

    fn submit_value(&mut self) {
        let Some(key) = self.selected_key() else {
            return;
        };
        let value = self.value_input.trim().to_string();
        self.editing_value = false;
        if value.is_empty() {
            self.stage(key, None);
        } else {
            self.stage(key, Some(value));
        }
    }

    fn dangerous_changes(&self) -> Vec<String> {
        self.pending
            .iter()
            .filter_map(|change| {
                if change.scope == Scope::Repository
                    && change.value.is_some()
                    && matches!(
                        repo_key_target(change.key),
                        Some(
                            RepoKeyTarget::ProposeBool
                                | RepoKeyTarget::ProposeAllow(_)
                                | RepoKeyTarget::ProposeProxy(_)
                        )
                    )
                {
                    return Some(format!(
                        "{}.{} requests a repository sandbox permission",
                        change.key.section, change.key.key
                    ));
                }
                change.value.as_deref().and_then(|value| {
                    security_confirmation(change.key, value, false)
                        .map(|reason| format!("{}.{} {reason}", change.key.section, change.key.key))
                })
            })
            .collect()
    }

    fn save(&mut self, confirmed_dangerous: bool) -> Result<(), String> {
        if self.pending.is_empty() {
            self.status = "No staged changes.".to_string();
            return Ok(());
        }
        let mut global = self.global_doc.clone();
        let mut repo = self.repo_doc.clone();
        let mut write_global = false;
        let mut write_repo = false;
        for change in &self.pending {
            match change.scope {
                Scope::Global => {
                    apply_global_change(&mut global, change)?;
                    write_global = true;
                }
                Scope::Repository => {
                    apply_repo_change(&mut repo, change)?;
                    write_repo = true;
                }
                Scope::Effective => {}
            }
        }
        if !confirmed_dangerous && !self.dangerous_changes().is_empty() {
            return Err("dangerous settings require confirmation".to_string());
        }
        if write_repo {
            let text = repo.to_string();
            repo_config::parse_and_validate(&text)
                .map_err(|error| format!("refusing to write invalid .cplt.toml: {error}"))?;
        }
        if write_global {
            validate_global_document(&global)
                .map_err(|error| format!("refusing to write invalid global config: {error}"))?;
        }
        if write_global {
            write_document_atomically(&self.global_path, &global)
                .map_err(|error| error.to_string())?;
            self.global_doc = global;
        }
        if write_repo {
            write_repo_document_atomically(&self.repo_path, &repo)
                .map_err(|error| error.to_string())?;
            self.repo_doc = repo;
        }
        self.effective = effective_snapshot(&self.global_doc, &self.project_dir)?;
        let count = self.pending.len();
        self.pending.clear();
        self.status = format!("Saved {count} change(s) atomically.");
        Ok(())
    }

    fn preview_global_doc(&self) -> toml_edit::DocumentMut {
        let mut doc = self.global_doc.clone();
        for change in self
            .pending
            .iter()
            .filter(|change| change.scope == Scope::Global)
        {
            let _ = apply_global_change(&mut doc, change);
        }
        doc
    }

    fn preview_repo_doc(&self) -> toml_edit::DocumentMut {
        let mut doc = self.repo_doc.clone();
        for change in self
            .pending
            .iter()
            .filter(|change| change.scope == Scope::Repository)
        {
            let _ = apply_repo_change(&mut doc, change);
        }
        doc
    }
}

fn apply_global_change(
    doc: &mut toml_edit::DocumentMut,
    change: &PendingChange,
) -> Result<(), String> {
    match &change.value {
        None => {
            unset_value_in_doc(doc, change.key);
            Ok(())
        }
        Some(value) if change.key.value_type.is_array() => {
            append_value_in_doc(doc, change.key, value).map_err(|error| error.to_string())
        }
        Some(value) => set_value_in_doc(doc, change.key, value).map_err(|error| error.to_string()),
    }
}

fn apply_repo_change(
    doc: &mut toml_edit::DocumentMut,
    change: &PendingChange,
) -> Result<(), String> {
    let target = repo_key_target(change.key).ok_or_else(|| {
        format!(
            "{}.{} is not valid in repository config",
            change.key.section, change.key.key
        )
    })?;
    set_repo_value_in_doc(
        doc,
        change.key,
        target,
        change.value.as_deref().unwrap_or(""),
        change.value.is_none(),
    )
    .map_err(|error| error.to_string())
}

fn load_doc(path: &std::path::Path) -> Result<toml_edit::DocumentMut, String> {
    if !path.exists() {
        return Ok(toml_edit::DocumentMut::new());
    }
    let raw = std::fs::read_to_string(path)
        .map_err(|error| format!("cannot read {}: {error}", path.display()))?;
    raw.parse()
        .map_err(|error| format!("invalid TOML in {}: {error}", path.display()))
}

fn effective_snapshot(
    global_doc: &toml_edit::DocumentMut,
    project_dir: &Path,
) -> Result<HashMap<(&'static str, &'static str), EffectiveSetting>, String> {
    let config =
        config::Config::parse(&global_doc.to_string()).map_err(|error| error.to_string())?;
    let mut base = config
        .merge_with_no_proxy_env(config::CliFlags::default(), None)
        .map_err(|error| error.to_string())?;
    let _ = base.reconcile_proxy_forced();
    let base_values = resolved_values(&base, global_doc);

    let mut effective = config
        .merge_with_no_proxy_env(config::CliFlags::default(), None)
        .map_err(|error| error.to_string())?;
    if let Ok(Some(loaded)) = repo_config::load_repo_config(project_dir) {
        let approved = approved_repo_keys(project_dir, &loaded.config);
        let approved_refs: Vec<&str> = approved.iter().map(String::as_str).collect();
        effective.apply_repo_config(&loaded.config, &loaded.dir, &approved_refs);
    }
    let _ = effective.reconcile_proxy_forced();
    let effective_values = resolved_values(&effective, global_doc);

    Ok(all_config_keys()
        .iter()
        .map(|key| {
            let id = (key.section, key.key);
            let value = effective_values
                .get(&id)
                .cloned()
                .unwrap_or_else(|| key.default_display.to_string());
            let source = if base_values.get(&id) != Some(&value) {
                "repository"
            } else if get_value_from_doc(global_doc, key).is_some() {
                "global"
            } else if value != key.default_display {
                "preset"
            } else {
                "default"
            };
            (id, EffectiveSetting { value, source })
        })
        .collect())
}

fn approved_repo_keys(project_dir: &Path, repo: &repo_config::RepoConfig) -> Vec<String> {
    let Some(entry) = trust::load_trust(project_dir) else {
        return Vec::new();
    };
    let current_hash = trust::proposal_content_hash(&repo.propose);
    if !trust::approved_path_matches(&entry, project_dir)
        || trust::approval_is_stale(&entry.accepted.content_hash, &current_hash)
    {
        return Vec::new();
    }
    entry.accepted.keys
}

fn resolved_values(
    resolved: &Resolved,
    global_doc: &toml_edit::DocumentMut,
) -> HashMap<(&'static str, &'static str), String> {
    all_config_keys()
        .iter()
        .map(|key| {
            let fallback = || {
                get_value_from_doc(global_doc, key)
                    .unwrap_or_else(|| key.default_display.to_string())
            };
            let value = match (key.section, key.key) {
                ("proxy", "enabled") => resolved.with_proxy.to_string(),
                ("proxy", "forced") => resolved.proxy_forced.to_string(),
                ("proxy", "port") => resolved.proxy_port.to_string(),
                ("proxy", "blocked_domains") => {
                    format_optional_path(resolved.blocked_domains.as_ref())
                }
                ("proxy", "allowed_domains") => {
                    format_optional_path(resolved.allowed_domains.as_ref())
                }
                ("proxy", "default_allowlist") => resolved.default_allowlist.to_string(),
                ("proxy", "log_file") => format_optional_path(resolved.proxy_log_file.as_ref()),
                ("proxy", "log_level") => resolved.proxy_log_level.as_str().to_string(),
                ("proxy", "timeout") => resolved.proxy_timeout.as_secs().to_string(),
                ("proxy", "upstream_no_proxy") => format_strings(&resolved.proxy_upstream_no_proxy),
                ("proxy", "allow_private_domains") => {
                    format_strings(&resolved.allow_private_domains)
                }
                ("allow", "read") => format_paths(&resolved.allow_read),
                ("allow", "write") => format_paths(&resolved.allow_write),
                ("allow", "socket") => format_paths(&resolved.allow_socket),
                ("allow", "ports") => format_values(&resolved.allow_ports),
                ("allow", "localhost") => format_values(&resolved.allow_localhost),
                ("deny", "paths") => format_paths(&resolved.deny_paths),
                ("deny", "env") => format_strings(&resolved.deny_env),
                ("sandbox", "agent") => resolved.agent.clone().unwrap_or_default(),
                ("sandbox", "preset") => resolved
                    .preset
                    .map_or_else(|| "standard".to_string(), |preset| preset.to_string()),
                ("sandbox", "validate") => (!resolved.no_validate).to_string(),
                ("sandbox", "allow_env_files") => resolved.allow_env_files.to_string(),
                ("sandbox", "allow_localhost_any") => resolved.allow_localhost_any.to_string(),
                ("sandbox", "pass_env") => format_strings(&resolved.pass_env),
                ("sandbox", "inherit_env") => resolved.inherit_env.to_string(),
                ("sandbox", "allow_lifecycle_scripts") => {
                    resolved.allow_lifecycle_scripts.to_string()
                }
                ("sandbox", "allow_gpg_signing") => resolved.allow_gpg_signing.to_string(),
                ("sandbox", "allow_tmp_exec") => resolved.allow_tmp_exec.to_string(),
                ("sandbox", "scratch_dir") => resolved.scratch_dir.to_string(),
                ("sandbox", "audit") => resolved.audit.to_string(),
                ("sandbox", "use_bubblewrap") => resolved
                    .use_bubblewrap
                    .map_or_else(|| "auto-detect".to_string(), |value| value.to_string()),
                ("sandbox", "quiet") => resolved.quiet.to_string(),
                ("sandbox", "yes") => resolved.yes.to_string(),
                ("sandbox", "allow_jvm_attach") => resolved.allow_jvm_attach.to_string(),
                ("sandbox", "allow_docker") => resolved.allow_docker.to_string(),
                ("sandbox", "allow_cache_exec") => format_strings(&resolved.allow_cache_exec),
                ("sandbox", "allow_cache_exec_any") => resolved.allow_cache_exec_any.to_string(),
                ("sandbox", "allow_browser") => resolved.allow_browser.to_string(),
                ("sandbox", "gh_proxy") => resolved.gh_guard.enabled.to_string(),
                ("sandbox", "git_push_prevention") => resolved.git_guard.enabled.to_string(),
                ("gh_guard", "enabled") => resolved.gh_guard.enabled.to_string(),
                ("gh_guard", "mode") => resolved.gh_guard.mode.to_string(),
                ("gh_guard", "scope_check") => resolved.gh_guard.scope_check.to_string(),
                ("gh_guard", "block_auth_token") => resolved.gh_guard.block_auth_token.to_string(),
                ("gh_guard", "inject_token") => resolved.gh_guard.inject_token.to_string(),
                ("gh_guard", "unknown_command") => resolved.gh_guard.unknown_command.to_string(),
                ("gh_guard", "allow_api_write") => resolved.gh_guard.allow_api_write.to_string(),
                ("git_guard", "enabled") => resolved.git_guard.enabled.to_string(),
                ("git_guard", "mode") => resolved.git_guard.mode.to_string(),
                ("git_guard", "prevent_push") => resolved.git_guard.prevent_push.to_string(),
                ("git_guard", "prevent_force_push") => {
                    resolved.git_guard.prevent_force_push.to_string()
                }
                ("git_guard", "protect_default_branch_only") => {
                    resolved.git_guard.protect_default_branch_only.to_string()
                }
                _ => fallback(),
            };
            ((key.section, key.key), value)
        })
        .collect()
}

fn format_optional_path(path: Option<&PathBuf>) -> String {
    path.map_or_else(String::new, |path| path.display().to_string())
}

fn format_paths(paths: &[PathBuf]) -> String {
    format!(
        "[{}]",
        paths
            .iter()
            .map(|path| path.display().to_string())
            .collect::<Vec<_>>()
            .join(", ")
    )
}

fn format_strings(values: &[String]) -> String {
    format!("[{}]", values.join(", "))
}

fn format_values<T: ToString>(values: &[T]) -> String {
    format!(
        "[{}]",
        values
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(", ")
    )
}

fn repo_proposal_enabled(doc: &toml_edit::DocumentMut, key: &ConfigKeyInfo) -> bool {
    doc.get("propose")
        .and_then(toml_edit::Item::as_table)
        .and_then(|table| table.get(key.key))
        .and_then(toml_edit::Item::as_bool)
        == Some(true)
}

fn repo_value_is_unset(doc: &toml_edit::DocumentMut, key: &ConfigKeyInfo) -> bool {
    match repo_key_target(key) {
        Some(RepoKeyTarget::ProposeBool) => !repo_proposal_enabled(doc, key),
        Some(RepoKeyTarget::ProposeAllow(name)) => nested_repo_value(doc, "propose", "allow", name),
        Some(RepoKeyTarget::ProposeProxy(name)) => nested_repo_value(doc, "propose", "proxy", name),
        Some(RepoKeyTarget::Deny(name)) => direct_repo_value(doc, "deny", name),
        None => true,
    }
}

fn nested_repo_value(
    doc: &toml_edit::DocumentMut,
    section: &str,
    subsection: &str,
    key: &str,
) -> bool {
    doc.get(section)
        .and_then(toml_edit::Item::as_table)
        .and_then(|table| table.get(subsection))
        .and_then(toml_edit::Item::as_table)
        .and_then(|table| table.get(key))
        .is_none()
}

fn direct_repo_value(doc: &toml_edit::DocumentMut, section: &str, key: &str) -> bool {
    doc.get(section)
        .and_then(toml_edit::Item::as_table)
        .and_then(|table| table.get(key))
        .is_none()
}

fn is_sensitive(key: &ConfigKeyInfo) -> bool {
    key.section == "proxy" && key.key == "upstream"
}

fn redact_value(key: &ConfigKeyInfo, value: String) -> String {
    if is_sensitive(key) {
        crate::proxy::redact_upstream_url(&value)
    } else {
        value
    }
}

fn detect_project_root() -> Option<PathBuf> {
    // Resolves the repo containing the process cwd — no project dir is known
    // at this point. Hardened all the same: cwd may be inside a hostile repo.
    let output = crate::git::command(std::path::Path::new("."), &["rev-parse", "--show-toplevel"])?
        .output()
        .ok()?;
    output.status.success().then(|| {
        String::from_utf8(output.stdout)
            .ok()
            .map(|value| PathBuf::from(value.trim()))
    })?
}

struct TerminalGuard;

impl TerminalGuard {
    fn enter() -> io::Result<Self> {
        Self::enter_with(
            enable_raw_mode,
            || execute!(io::stdout(), EnterAlternateScreen),
            disable_raw_mode,
        )
    }

    fn enter_with(
        enable: impl FnOnce() -> io::Result<()>,
        enter_alternate_screen: impl FnOnce() -> io::Result<()>,
        rollback_raw_mode: impl FnOnce() -> io::Result<()>,
    ) -> io::Result<Self> {
        enable()?;
        if let Err(error) = enter_alternate_screen() {
            let _ = rollback_raw_mode();
            return Err(error);
        }
        Ok(Self)
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
        let _ = execute!(io::stdout(), LeaveAlternateScreen);
    }
}

/// Run the interactive settings editor.
pub fn run() -> Result<(), String> {
    if std::env::var_os("__CPLT_TRUST_LOCKED").is_some() {
        return Err("Cannot edit settings from inside the sandbox.".to_string());
    }
    if !io::stdin().is_terminal() || !io::stdout().is_terminal() {
        return Err(
            "cplt settings requires an interactive terminal. Use `cplt config set` in scripts or CI."
                .to_string(),
        );
    }
    let mut app = SettingsApp::load()?;
    let _guard =
        TerminalGuard::enter().map_err(|error| format!("cannot initialize terminal: {error}"))?;
    let backend = CrosstermBackend::new(io::stdout());
    let mut terminal = Terminal::new(backend).map_err(|error| error.to_string())?;
    let result = run_loop(&mut terminal, &mut app);
    let _ = terminal.show_cursor();
    result
}

fn run_loop(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    app: &mut SettingsApp,
) -> Result<(), String> {
    loop {
        terminal
            .draw(|frame| render(frame, app))
            .map_err(|error| error.to_string())?;
        let Event::Key(key) = event::read().map_err(|error| error.to_string())? else {
            continue;
        };
        if key.kind != KeyEventKind::Press {
            continue;
        }
        if app.editing_filter {
            match key.code {
                KeyCode::Esc | KeyCode::Enter => app.editing_filter = false,
                KeyCode::Backspace => {
                    app.filter.pop();
                    app.selected = 0;
                }
                KeyCode::Char(value) => {
                    app.filter.push(value);
                    app.selected = 0;
                }
                _ => {}
            }
            continue;
        }
        if app.dangerous_confirmation.is_some() {
            match key.code {
                KeyCode::Char('y') | KeyCode::Char('Y') => {
                    app.dangerous_confirmation = None;
                    if let Err(error) = app.save(true) {
                        app.status = error;
                    }
                }
                KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc => {
                    app.dangerous_confirmation = None;
                    app.status = "Dangerous changes were not saved.".to_string();
                }
                _ => {}
            }
            continue;
        }
        if app.editing_value {
            match key.code {
                KeyCode::Esc => app.editing_value = false,
                KeyCode::Enter => app.submit_value(),
                KeyCode::Backspace => {
                    app.value_input.pop();
                }
                KeyCode::Char(value) => app.value_input.push(value),
                _ => {}
            }
            continue;
        }
        match key.code {
            KeyCode::Char('q') | KeyCode::Esc => return Ok(()),
            KeyCode::Char('/') => app.editing_filter = true,
            KeyCode::Tab => {
                let index = Scope::ALL
                    .iter()
                    .position(|scope| *scope == app.scope)
                    .unwrap_or(0);
                app.set_scope(Scope::ALL[(index + 1) % Scope::ALL.len()]);
            }
            KeyCode::Up | KeyCode::Char('k') => app.selected = app.selected.saturating_sub(1),
            KeyCode::Down | KeyCode::Char('j') => {
                app.selected = (app.selected + 1).min(app.visible_keys().len().saturating_sub(1));
            }
            KeyCode::Char(' ') => app.toggle_selected(),
            KeyCode::Enter => app.begin_value_edit(),
            KeyCode::Char('r') => {
                if let Some(key) = app.selected_key() {
                    if app.scope == Scope::Effective {
                        app.status = "Effective values are read-only.".to_string();
                    } else {
                        app.stage(key, None);
                    }
                }
            }
            KeyCode::Char('s') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                let dangerous = app.dangerous_changes();
                if !dangerous.is_empty() {
                    app.dangerous_confirmation = Some(dangerous.join("\n"));
                } else if let Err(error) = app.save(false) {
                    app.status = error;
                }
            }
            _ => {}
        }
    }
}

fn render(frame: &mut ratatui::Frame, app: &mut SettingsApp) {
    let layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(5),
            Constraint::Length(5),
        ])
        .split(frame.area());
    let tab_index = Scope::ALL
        .iter()
        .position(|scope| *scope == app.scope)
        .unwrap_or(0);
    frame.render_widget(
        Tabs::new(
            Scope::ALL
                .iter()
                .map(|scope| Line::from(scope.label()))
                .collect::<Vec<_>>(),
        )
        .select(tab_index)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" cplt settings "),
        )
        .highlight_style(
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        layout[0],
    );
    let keys = app.visible_keys();
    let global_preview = app.preview_global_doc();
    let repo_preview = app.preview_repo_doc();
    let rows = keys.iter().map(|key| {
        let setting = app.effective.get(&(key.section, key.key));
        let value = match app.scope {
            Scope::Effective => setting.map_or_else(
                || key.default_display.to_string(),
                |setting| setting.value.clone(),
            ),
            Scope::Global => get_value_from_doc(&global_preview, key)
                .unwrap_or_else(|| key.default_display.to_string()),
            Scope::Repository => repo_value_label(&repo_preview, key),
        };
        let value = redact_value(key, value);
        let staged = app.pending.iter().any(|change| {
            change.scope == app.scope
                && change.key.section == key.section
                && change.key.key == key.key
        });
        let source = match app.scope {
            Scope::Effective => setting.map_or("default", |setting| setting.source),
            Scope::Global if staged => "staged",
            Scope::Global => {
                if get_value_from_doc(&app.global_doc, key).is_some() {
                    "set"
                } else {
                    "inherited"
                }
            }
            Scope::Repository if staged => "staged",
            Scope::Repository => repo_key_target(key).map_or("not supported", |_| "proposal/deny"),
        };
        Row::new(vec![
            Cell::from(format!("{}.{}", key.section, key.key)),
            Cell::from(value),
            Cell::from(source),
        ])
    });
    let table = Table::new(
        rows,
        [
            Constraint::Percentage(39),
            Constraint::Percentage(33),
            Constraint::Percentage(28),
        ],
    )
    .header(Row::new(["Setting", "Value", "Source"]).style(Style::default().fg(Color::Cyan)))
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title(if app.filter.is_empty() {
                " Settings "
            } else {
                " Settings (filtered) "
            }),
    )
    .row_highlight_style(Style::default().bg(Color::DarkGray))
    .highlight_symbol("› ");
    let mut state = TableState::default();
    state.select(Some(app.selected.min(keys.len().saturating_sub(1))));
    frame.render_stateful_widget(table, layout[1], &mut state);

    let detail = app.selected_key().map_or_else(
        || "No matching settings.".to_string(),
        |key| {
            let danger = if key.dangerous {
                " WARNING: security-sensitive."
            } else {
                ""
            };
            format!("{}.{}: {}{}", key.section, key.key, key.description, danger)
        },
    );
    let footer = format!(
        "{}\nFilter: {}{}  Pending: {}  [/] search [Tab] scope [Space] toggle [Enter] edit [R] reset [Ctrl+S] save [Q] quit",
        app.status,
        app.filter,
        if app.editing_filter { "▌" } else { "" },
        app.pending.len()
    );
    frame.render_widget(
        Paragraph::new(vec![Line::from(detail), Line::from(footer)])
            .block(Block::default().borders(Borders::ALL).title(" Details "))
            .wrap(Wrap { trim: true }),
        layout[2],
    );
    if app.editing_value {
        let area = centered_rect(70, 20, frame.area());
        frame.render_widget(Clear, area);
        frame.render_widget(
            Paragraph::new(format!(
                "Value: {}\n\nEnter stages the change. Esc cancels.",
                app.value_input
            ))
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(" Edit setting "),
            ),
            area,
        );
    }
    if let Some(dangerous) = &app.dangerous_confirmation {
        let area = centered_rect(75, 30, frame.area());
        frame.render_widget(Clear, area);
        frame.render_widget(
            Paragraph::new(format!(
                "The following changes weaken sandbox security:\n\n{dangerous}\n\nSave anyway? [y/N]"
            ))
            .block(Block::default().borders(Borders::ALL).title(" Confirm security-sensitive changes "))
            .wrap(Wrap { trim: true }),
            area,
        );
    }
}

fn repo_value_label(doc: &toml_edit::DocumentMut, key: &ConfigKeyInfo) -> String {
    match repo_key_target(key) {
        Some(RepoKeyTarget::ProposeBool) => {
            if repo_proposal_enabled(doc, key) {
                "true".to_string()
            } else {
                "(unset)".to_string()
            }
        }
        Some(_) => "(configured in .cplt.toml)".to_string(),
        None => "(not supported)".to_string(),
    }
}

fn centered_rect(
    percent_x: u16,
    percent_y: u16,
    area: ratatui::layout::Rect,
) -> ratatui::layout::Rect {
    let vertical = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(area);
    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(vertical[1])[1]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::lookup_key;
    use ratatui::backend::TestBackend;
    use std::cell::Cell;

    fn test_app(global: &str) -> SettingsApp {
        let global_doc = global.parse::<toml_edit::DocumentMut>().unwrap();
        SettingsApp {
            scope: Scope::Global,
            selected: 0,
            filter: String::new(),
            editing_filter: false,
            editing_value: false,
            value_input: String::new(),
            status: String::new(),
            pending: Vec::new(),
            global_doc,
            global_path: PathBuf::from("config.toml"),
            repo_doc: toml_edit::DocumentMut::new(),
            repo_path: PathBuf::from(".cplt.toml"),
            project_dir: PathBuf::from("."),
            effective: HashMap::new(),
            dangerous_confirmation: None,
        }
    }

    #[test]
    fn global_change_uses_config_editor_semantics() {
        let key = lookup_key("sandbox.quiet").unwrap();
        let change = PendingChange {
            key,
            scope: Scope::Global,
            value: Some("true".to_string()),
        };
        let mut doc = toml_edit::DocumentMut::new();
        apply_global_change(&mut doc, &change).unwrap();
        assert_eq!(get_value_from_doc(&doc, key).as_deref(), Some("true"));
    }

    #[test]
    fn repository_bool_is_written_as_a_proposal() {
        let key = lookup_key("sandbox.allow_jvm_attach").unwrap();
        let change = PendingChange {
            key,
            scope: Scope::Repository,
            value: Some("true".to_string()),
        };
        let mut doc = toml_edit::DocumentMut::new();
        apply_repo_change(&mut doc, &change).unwrap();
        assert!(repo_proposal_enabled(&doc, key));
        assert!(repo_config::parse_and_validate(&doc.to_string()).is_ok());
    }

    #[test]
    fn dangerous_change_requires_explicit_confirmation() {
        let key = lookup_key("sandbox.allow_docker").unwrap();
        let change = PendingChange {
            key,
            scope: Scope::Global,
            value: Some("true".to_string()),
        };
        assert!(security_confirmation(key, "true", false).is_some());
        assert_eq!(change.scope, Scope::Global);
    }

    #[test]
    fn repository_proposals_always_require_confirmation() {
        let key = lookup_key("sandbox.allow_jvm_attach").unwrap();
        let change = PendingChange {
            key,
            scope: Scope::Repository,
            value: Some("true".to_string()),
        };
        let app = SettingsApp {
            scope: Scope::Repository,
            selected: 0,
            filter: String::new(),
            editing_filter: false,
            editing_value: false,
            value_input: String::new(),
            status: String::new(),
            pending: vec![change],
            global_doc: toml_edit::DocumentMut::new(),
            global_path: PathBuf::from("config.toml"),
            repo_doc: toml_edit::DocumentMut::new(),
            repo_path: PathBuf::from(".cplt.toml"),
            project_dir: PathBuf::from("."),
            effective: HashMap::new(),
            dangerous_confirmation: None,
        };
        assert_eq!(app.dangerous_changes().len(), 1);
    }

    #[test]
    fn toggling_twice_reverts_the_staged_change() {
        let mut app = test_app("");
        app.selected = app
            .visible_keys()
            .iter()
            .position(|key| key.section == "sandbox" && key.key == "quiet")
            .unwrap();

        app.toggle_selected();
        assert_eq!(app.pending.len(), 1);
        app.toggle_selected();

        assert!(app.pending.is_empty());
    }

    #[test]
    fn effective_snapshot_applies_strict_preset_baseline() {
        let project = tempfile::tempdir().unwrap();
        let doc = "[sandbox]\npreset = \"strict\"\n"
            .parse::<toml_edit::DocumentMut>()
            .unwrap();

        let snapshot = effective_snapshot(&doc, project.path()).unwrap();

        assert_eq!(snapshot.get(&("proxy", "forced")).unwrap().value, "true");
        assert_eq!(
            snapshot.get(&("gh_guard", "enabled")).unwrap().value,
            "true"
        );
        assert_eq!(
            snapshot.get(&("git_guard", "enabled")).unwrap().value,
            "true"
        );
        assert_eq!(
            snapshot.get(&("gh_guard", "enabled")).unwrap().source,
            "preset"
        );
    }

    #[test]
    fn invalid_global_change_is_rejected_before_write() {
        let dir = tempfile::tempdir().unwrap();
        let mut app = test_app("");
        app.global_path = dir.path().join("config.toml");
        app.project_dir = dir.path().to_path_buf();
        app.pending.push(PendingChange {
            key: lookup_key("sandbox.preset").unwrap(),
            scope: Scope::Global,
            value: Some("not-a-preset".to_string()),
        });

        let error = app.save(true).unwrap_err();

        assert!(error.contains("invalid global config"));
        assert!(!app.global_path.exists());
    }

    #[test]
    fn rendered_settings_redact_upstream_credentials() {
        let mut app =
            test_app("[proxy]\nupstream = \"http://username:super-secret@proxy.example:8080\"\n");
        let backend = TestBackend::new(120, 30);
        let mut terminal = Terminal::new(backend).unwrap();

        terminal.draw(|frame| render(frame, &mut app)).unwrap();

        let rendered: String = terminal
            .backend()
            .buffer()
            .content()
            .iter()
            .map(ratatui::buffer::Cell::symbol)
            .collect();
        assert!(!rendered.contains("super-secret"));
        assert!(rendered.contains("username:***"));
    }

    #[test]
    fn alternate_screen_failure_rolls_back_raw_mode() {
        let raw_enabled = Cell::new(false);
        let raw_disabled = Cell::new(false);

        let result = TerminalGuard::enter_with(
            || {
                raw_enabled.set(true);
                Ok(())
            },
            || Err(io::Error::other("alternate screen failed")),
            || {
                raw_disabled.set(true);
                Ok(())
            },
        );

        assert!(result.is_err());
        assert!(raw_enabled.get());
        assert!(raw_disabled.get());
    }
}
