//! `gh` CLI proxy — command-level filtering for sandboxed agents.
//!
//! Prevents destructive GitHub operations by intercepting `gh` commands
//! before they reach the real binary. Uses a default-deny policy for
//! unknown commands and a three-tier classification:
//!
//! - **Allow**: always permitted (read operations)
//! - **ScopeCheck**: permitted only for the current repository
//! - **Block**: never permitted (destructive/out-of-scope)
//!
//! The proxy is implemented as a shell wrapper placed ahead of the real
//! `gh` in `$PATH`. The wrapper calls back to cplt for policy decisions.

use std::path::Path;

/// Policy decision for a `gh` command.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// Always allowed — read-only or harmless operations.
    Allow,
    /// Allowed only if targeting the current repository.
    ScopeCheck,
    /// Always blocked — destructive or out-of-scope.
    Block,
}

/// Result of evaluating a gh command against the policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyResult {
    pub decision: Decision,
    pub reason: &'static str,
}

/// A parsed gh command extracted from argv.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedCommand {
    /// Top-level command group (e.g., "pr", "repo", "api").
    pub command: String,
    /// Subcommand within the group (e.g., "create", "delete").
    /// None for commands that don't have subcommands (e.g., "gh api ...").
    pub subcommand: Option<String>,
    /// The `-R`/`--repo` flag value, if present.
    pub repo_flag: Option<String>,
    /// For `gh api`: the HTTP method (from `-X`/`--method`).
    pub method: Option<String>,
    /// For `gh api`: whether input flags are present (`-f`, `-F`, `--input`).
    pub has_input_flags: bool,
}

/// Static policy entry mapping (command, subcommand) to a decision.
struct PolicyEntry {
    command: &'static str,
    subcommand: &'static str,
    decision: Decision,
    reason: &'static str,
}

/// Wildcard marker — matches any subcommand for a command group.
const ANY: &str = "*";

/// The compiled policy table. Order does not matter — lookup is by exact match
/// with wildcard fallback.
static POLICY: &[PolicyEntry] = &[
    // ── gh repo ──
    PolicyEntry {
        command: "repo",
        subcommand: "view",
        decision: Decision::Allow,
        reason: "read-only",
    },
    PolicyEntry {
        command: "repo",
        subcommand: "list",
        decision: Decision::Allow,
        reason: "read-only",
    },
    PolicyEntry {
        command: "repo",
        subcommand: "set-default",
        decision: Decision::Allow,
        reason: "local git config only",
    },
    PolicyEntry {
        command: "repo",
        subcommand: "gitignore",
        decision: Decision::Allow,
        reason: "read-only templates",
    },
    PolicyEntry {
        command: "repo",
        subcommand: "license",
        decision: Decision::Allow,
        reason: "read-only templates",
    },
    PolicyEntry {
        command: "repo",
        subcommand: "clone",
        decision: Decision::Block,
        reason: "cloning other repos is out of scope",
    },
    PolicyEntry {
        command: "repo",
        subcommand: "create",
        decision: Decision::Block,
        reason: "creating repos is destructive",
    },
    PolicyEntry {
        command: "repo",
        subcommand: "delete",
        decision: Decision::Block,
        reason: "deletes entire repository",
    },
    PolicyEntry {
        command: "repo",
        subcommand: "archive",
        decision: Decision::Block,
        reason: "irreversible state change",
    },
    PolicyEntry {
        command: "repo",
        subcommand: "unarchive",
        decision: Decision::Block,
        reason: "state change on other repos",
    },
    PolicyEntry {
        command: "repo",
        subcommand: "edit",
        decision: Decision::Block,
        reason: "modifies repo settings",
    },
    PolicyEntry {
        command: "repo",
        subcommand: "fork",
        decision: Decision::Block,
        reason: "creates new repo",
    },
    PolicyEntry {
        command: "repo",
        subcommand: "rename",
        decision: Decision::Block,
        reason: "renames repository",
    },
    PolicyEntry {
        command: "repo",
        subcommand: "sync",
        decision: Decision::Block,
        reason: "could overwrite branches",
    },
    PolicyEntry {
        command: "repo",
        subcommand: "deploy-key",
        decision: Decision::Block,
        reason: "credential management",
    },
    PolicyEntry {
        command: "repo",
        subcommand: "autolink",
        decision: Decision::Block,
        reason: "repo settings modification",
    },
    // ── gh pr ──
    PolicyEntry {
        command: "pr",
        subcommand: "list",
        decision: Decision::Allow,
        reason: "read-only",
    },
    PolicyEntry {
        command: "pr",
        subcommand: "view",
        decision: Decision::Allow,
        reason: "read-only",
    },
    PolicyEntry {
        command: "pr",
        subcommand: "status",
        decision: Decision::Allow,
        reason: "read-only",
    },
    PolicyEntry {
        command: "pr",
        subcommand: "diff",
        decision: Decision::Allow,
        reason: "read-only",
    },
    PolicyEntry {
        command: "pr",
        subcommand: "checks",
        decision: Decision::Allow,
        reason: "read-only",
    },
    PolicyEntry {
        command: "pr",
        subcommand: "checkout",
        decision: Decision::ScopeCheck,
        reason: "modifies local git state",
    },
    PolicyEntry {
        command: "pr",
        subcommand: "create",
        decision: Decision::ScopeCheck,
        reason: "normal agent workflow",
    },
    PolicyEntry {
        command: "pr",
        subcommand: "comment",
        decision: Decision::ScopeCheck,
        reason: "normal agent workflow",
    },
    PolicyEntry {
        command: "pr",
        subcommand: "edit",
        decision: Decision::ScopeCheck,
        reason: "editing PR metadata",
    },
    PolicyEntry {
        command: "pr",
        subcommand: "review",
        decision: Decision::ScopeCheck,
        reason: "adding reviews",
    },
    PolicyEntry {
        command: "pr",
        subcommand: "ready",
        decision: Decision::ScopeCheck,
        reason: "marking draft as ready",
    },
    PolicyEntry {
        command: "pr",
        subcommand: "update-branch",
        decision: Decision::ScopeCheck,
        reason: "updating PR branch",
    },
    PolicyEntry {
        command: "pr",
        subcommand: "close",
        decision: Decision::ScopeCheck,
        reason: "closing PRs",
    },
    PolicyEntry {
        command: "pr",
        subcommand: "reopen",
        decision: Decision::ScopeCheck,
        reason: "reopening PRs",
    },
    PolicyEntry {
        command: "pr",
        subcommand: "merge",
        decision: Decision::Block,
        reason: "merging is a human decision",
    },
    PolicyEntry {
        command: "pr",
        subcommand: "revert",
        decision: Decision::Block,
        reason: "high-impact operation",
    },
    PolicyEntry {
        command: "pr",
        subcommand: "lock",
        decision: Decision::Block,
        reason: "moderation action",
    },
    PolicyEntry {
        command: "pr",
        subcommand: "unlock",
        decision: Decision::Block,
        reason: "moderation action",
    },
    // ── gh issue ──
    PolicyEntry {
        command: "issue",
        subcommand: "list",
        decision: Decision::Allow,
        reason: "read-only",
    },
    PolicyEntry {
        command: "issue",
        subcommand: "view",
        decision: Decision::Allow,
        reason: "read-only",
    },
    PolicyEntry {
        command: "issue",
        subcommand: "status",
        decision: Decision::Allow,
        reason: "read-only",
    },
    PolicyEntry {
        command: "issue",
        subcommand: "create",
        decision: Decision::ScopeCheck,
        reason: "agents may create issues",
    },
    PolicyEntry {
        command: "issue",
        subcommand: "comment",
        decision: Decision::ScopeCheck,
        reason: "agents comment on issues",
    },
    PolicyEntry {
        command: "issue",
        subcommand: "edit",
        decision: Decision::ScopeCheck,
        reason: "editing issue metadata",
    },
    PolicyEntry {
        command: "issue",
        subcommand: "close",
        decision: Decision::ScopeCheck,
        reason: "closing issues",
    },
    PolicyEntry {
        command: "issue",
        subcommand: "reopen",
        decision: Decision::ScopeCheck,
        reason: "reopening issues",
    },
    PolicyEntry {
        command: "issue",
        subcommand: "develop",
        decision: Decision::ScopeCheck,
        reason: "creating linked branches",
    },
    PolicyEntry {
        command: "issue",
        subcommand: "delete",
        decision: Decision::Block,
        reason: "destructive — cannot be undone",
    },
    PolicyEntry {
        command: "issue",
        subcommand: "transfer",
        decision: Decision::Block,
        reason: "moves issue to another repo",
    },
    PolicyEntry {
        command: "issue",
        subcommand: "lock",
        decision: Decision::Block,
        reason: "moderation action",
    },
    PolicyEntry {
        command: "issue",
        subcommand: "unlock",
        decision: Decision::Block,
        reason: "moderation action",
    },
    PolicyEntry {
        command: "issue",
        subcommand: "pin",
        decision: Decision::Block,
        reason: "repo-level moderation",
    },
    PolicyEntry {
        command: "issue",
        subcommand: "unpin",
        decision: Decision::Block,
        reason: "repo-level moderation",
    },
    // ── gh release ──
    PolicyEntry {
        command: "release",
        subcommand: "list",
        decision: Decision::Allow,
        reason: "read-only",
    },
    PolicyEntry {
        command: "release",
        subcommand: "view",
        decision: Decision::Allow,
        reason: "read-only",
    },
    PolicyEntry {
        command: "release",
        subcommand: "download",
        decision: Decision::Allow,
        reason: "read-only",
    },
    PolicyEntry {
        command: "release",
        subcommand: "verify",
        decision: Decision::Allow,
        reason: "read-only verification",
    },
    PolicyEntry {
        command: "release",
        subcommand: "verify-asset",
        decision: Decision::Allow,
        reason: "read-only verification",
    },
    PolicyEntry {
        command: "release",
        subcommand: "create",
        decision: Decision::Block,
        reason: "publishing releases — human decision",
    },
    PolicyEntry {
        command: "release",
        subcommand: "edit",
        decision: Decision::Block,
        reason: "modifying published releases",
    },
    PolicyEntry {
        command: "release",
        subcommand: "delete",
        decision: Decision::Block,
        reason: "destructive",
    },
    PolicyEntry {
        command: "release",
        subcommand: "delete-asset",
        decision: Decision::Block,
        reason: "destructive",
    },
    PolicyEntry {
        command: "release",
        subcommand: "upload",
        decision: Decision::Block,
        reason: "modifying published releases",
    },
    // ── gh gist ──
    PolicyEntry {
        command: "gist",
        subcommand: "view",
        decision: Decision::Allow,
        reason: "read-only",
    },
    PolicyEntry {
        command: "gist",
        subcommand: "list",
        decision: Decision::Allow,
        reason: "read-only",
    },
    PolicyEntry {
        command: "gist",
        subcommand: "clone",
        decision: Decision::Block,
        reason: "out of scope",
    },
    PolicyEntry {
        command: "gist",
        subcommand: "create",
        decision: Decision::Block,
        reason: "out of scope",
    },
    PolicyEntry {
        command: "gist",
        subcommand: "edit",
        decision: Decision::Block,
        reason: "out of scope",
    },
    PolicyEntry {
        command: "gist",
        subcommand: "delete",
        decision: Decision::Block,
        reason: "destructive",
    },
    PolicyEntry {
        command: "gist",
        subcommand: "rename",
        decision: Decision::Block,
        reason: "out of scope",
    },
    // ── gh secret ──
    PolicyEntry {
        command: "secret",
        subcommand: "list",
        decision: Decision::Allow,
        reason: "read-only (names only)",
    },
    PolicyEntry {
        command: "secret",
        subcommand: "set",
        decision: Decision::Block,
        reason: "modifying secrets",
    },
    PolicyEntry {
        command: "secret",
        subcommand: "delete",
        decision: Decision::Block,
        reason: "destructive",
    },
    // ── gh variable ──
    PolicyEntry {
        command: "variable",
        subcommand: "list",
        decision: Decision::Allow,
        reason: "read-only",
    },
    PolicyEntry {
        command: "variable",
        subcommand: "get",
        decision: Decision::Allow,
        reason: "read-only",
    },
    PolicyEntry {
        command: "variable",
        subcommand: "set",
        decision: Decision::Block,
        reason: "modifying CI variables",
    },
    PolicyEntry {
        command: "variable",
        subcommand: "delete",
        decision: Decision::Block,
        reason: "destructive",
    },
    // ── gh run ──
    PolicyEntry {
        command: "run",
        subcommand: "list",
        decision: Decision::Allow,
        reason: "read-only",
    },
    PolicyEntry {
        command: "run",
        subcommand: "view",
        decision: Decision::Allow,
        reason: "read-only",
    },
    PolicyEntry {
        command: "run",
        subcommand: "download",
        decision: Decision::Allow,
        reason: "read-only (artifacts)",
    },
    PolicyEntry {
        command: "run",
        subcommand: "watch",
        decision: Decision::Allow,
        reason: "read-only (progress)",
    },
    PolicyEntry {
        command: "run",
        subcommand: "rerun",
        decision: Decision::Block,
        reason: "triggers CI",
    },
    PolicyEntry {
        command: "run",
        subcommand: "cancel",
        decision: Decision::Block,
        reason: "cancels other runs",
    },
    PolicyEntry {
        command: "run",
        subcommand: "delete",
        decision: Decision::Block,
        reason: "destructive",
    },
    // ── gh workflow ──
    PolicyEntry {
        command: "workflow",
        subcommand: "list",
        decision: Decision::Allow,
        reason: "read-only",
    },
    PolicyEntry {
        command: "workflow",
        subcommand: "view",
        decision: Decision::Allow,
        reason: "read-only",
    },
    PolicyEntry {
        command: "workflow",
        subcommand: "run",
        decision: Decision::Block,
        reason: "triggers arbitrary code",
    },
    PolicyEntry {
        command: "workflow",
        subcommand: "enable",
        decision: Decision::Block,
        reason: "state change",
    },
    PolicyEntry {
        command: "workflow",
        subcommand: "disable",
        decision: Decision::Block,
        reason: "state change",
    },
    // ── gh label ──
    PolicyEntry {
        command: "label",
        subcommand: "list",
        decision: Decision::Allow,
        reason: "read-only",
    },
    PolicyEntry {
        command: "label",
        subcommand: "create",
        decision: Decision::ScopeCheck,
        reason: "agent might create labels",
    },
    PolicyEntry {
        command: "label",
        subcommand: "edit",
        decision: Decision::ScopeCheck,
        reason: "low-risk",
    },
    PolicyEntry {
        command: "label",
        subcommand: "delete",
        decision: Decision::Block,
        reason: "destructive",
    },
    PolicyEntry {
        command: "label",
        subcommand: "clone",
        decision: Decision::Block,
        reason: "cross-repo operation",
    },
    // ── gh cache ──
    PolicyEntry {
        command: "cache",
        subcommand: "list",
        decision: Decision::Allow,
        reason: "read-only",
    },
    PolicyEntry {
        command: "cache",
        subcommand: "delete",
        decision: Decision::Block,
        reason: "evicts CI caches",
    },
    // ── gh auth ──
    PolicyEntry {
        command: "auth",
        subcommand: "status",
        decision: Decision::Allow,
        reason: "read-only",
    },
    PolicyEntry {
        command: "auth",
        subcommand: "token",
        decision: Decision::Allow,
        reason: "agent needs for auth flows",
    },
    PolicyEntry {
        command: "auth",
        subcommand: "login",
        decision: Decision::Block,
        reason: "credential modification",
    },
    PolicyEntry {
        command: "auth",
        subcommand: "logout",
        decision: Decision::Block,
        reason: "credential modification",
    },
    PolicyEntry {
        command: "auth",
        subcommand: "refresh",
        decision: Decision::Block,
        reason: "credential modification",
    },
    PolicyEntry {
        command: "auth",
        subcommand: "setup-git",
        decision: Decision::Block,
        reason: "modifies global git config",
    },
    PolicyEntry {
        command: "auth",
        subcommand: "switch",
        decision: Decision::Block,
        reason: "credential modification",
    },
    // ── gh config ──
    PolicyEntry {
        command: "config",
        subcommand: "list",
        decision: Decision::Allow,
        reason: "read-only",
    },
    PolicyEntry {
        command: "config",
        subcommand: "get",
        decision: Decision::Allow,
        reason: "read-only",
    },
    PolicyEntry {
        command: "config",
        subcommand: "set",
        decision: Decision::Block,
        reason: "could change auth behavior",
    },
    PolicyEntry {
        command: "config",
        subcommand: "clear-cache",
        decision: Decision::Allow,
        reason: "harmless",
    },
    // ── gh extension ──
    PolicyEntry {
        command: "extension",
        subcommand: "list",
        decision: Decision::Allow,
        reason: "read-only",
    },
    PolicyEntry {
        command: "extension",
        subcommand: "search",
        decision: Decision::Allow,
        reason: "read-only",
    },
    PolicyEntry {
        command: "extension",
        subcommand: "install",
        decision: Decision::Block,
        reason: "downloads and installs code",
    },
    PolicyEntry {
        command: "extension",
        subcommand: "remove",
        decision: Decision::Block,
        reason: "removes extensions",
    },
    PolicyEntry {
        command: "extension",
        subcommand: "upgrade",
        decision: Decision::Block,
        reason: "downloads new code",
    },
    PolicyEntry {
        command: "extension",
        subcommand: "create",
        decision: Decision::Block,
        reason: "out of scope",
    },
    PolicyEntry {
        command: "extension",
        subcommand: "exec",
        decision: Decision::Block,
        reason: "executes arbitrary extension code",
    },
    PolicyEntry {
        command: "extension",
        subcommand: "browse",
        decision: Decision::Block,
        reason: "interactive — not useful for agents",
    },
    // ── gh ssh-key / gh gpg-key ──
    PolicyEntry {
        command: "ssh-key",
        subcommand: "list",
        decision: Decision::Allow,
        reason: "read-only",
    },
    PolicyEntry {
        command: "ssh-key",
        subcommand: "add",
        decision: Decision::Block,
        reason: "adds credentials to account",
    },
    PolicyEntry {
        command: "ssh-key",
        subcommand: "delete",
        decision: Decision::Block,
        reason: "removes credentials",
    },
    PolicyEntry {
        command: "gpg-key",
        subcommand: "list",
        decision: Decision::Allow,
        reason: "read-only",
    },
    PolicyEntry {
        command: "gpg-key",
        subcommand: "add",
        decision: Decision::Block,
        reason: "adds credentials to account",
    },
    PolicyEntry {
        command: "gpg-key",
        subcommand: "delete",
        decision: Decision::Block,
        reason: "removes credentials",
    },
    // ── gh org ──
    PolicyEntry {
        command: "org",
        subcommand: "list",
        decision: Decision::Allow,
        reason: "read-only",
    },
    // ── Entire-group wildcards ──
    PolicyEntry {
        command: "search",
        subcommand: ANY,
        decision: Decision::Allow,
        reason: "read-only search",
    },
    PolicyEntry {
        command: "ruleset",
        subcommand: ANY,
        decision: Decision::Allow,
        reason: "read-only",
    },
    PolicyEntry {
        command: "attestation",
        subcommand: ANY,
        decision: Decision::Allow,
        reason: "read-only verification",
    },
    PolicyEntry {
        command: "copilot",
        subcommand: ANY,
        decision: Decision::Allow,
        reason: "Copilot calling itself",
    },
    PolicyEntry {
        command: "project",
        subcommand: "list",
        decision: Decision::Allow,
        reason: "read-only",
    },
    PolicyEntry {
        command: "project",
        subcommand: "view",
        decision: Decision::Allow,
        reason: "read-only",
    },
    PolicyEntry {
        command: "project",
        subcommand: "field-list",
        decision: Decision::Allow,
        reason: "read-only",
    },
    PolicyEntry {
        command: "project",
        subcommand: "item-list",
        decision: Decision::Allow,
        reason: "read-only",
    },
    PolicyEntry {
        command: "project",
        subcommand: ANY,
        decision: Decision::Block,
        reason: "modifies project boards",
    },
    PolicyEntry {
        command: "codespace",
        subcommand: ANY,
        decision: Decision::Block,
        reason: "out of scope",
    },
    PolicyEntry {
        command: "agent-task",
        subcommand: ANY,
        decision: Decision::Block,
        reason: "out of scope — spawning agent tasks",
    },
    PolicyEntry {
        command: "skill",
        subcommand: ANY,
        decision: Decision::Block,
        reason: "extension management",
    },
];

/// Parse a `gh` command line into its structured components.
///
/// Expects `args` to be the arguments *after* the `gh` binary name,
/// i.e. `["pr", "create", "--title", "fix: bug"]`.
pub fn parse_command(args: &[&str]) -> Option<ParsedCommand> {
    if args.is_empty() {
        return None;
    }

    // Skip global flags that appear before the command
    let mut idx = 0;
    while idx < args.len() && args[idx].starts_with('-') {
        // Skip flag and its value if it takes one
        if matches!(args[idx], "--repo" | "-R") {
            idx += 1; // skip value
        }
        idx += 1;
    }

    if idx >= args.len() {
        return None;
    }

    let command = args[idx].to_string();
    idx += 1;

    // Special case: `gh api` has no subcommand — the next positional is the endpoint
    if command == "api" {
        let mut method = None;
        let mut has_input_flags = false;
        let mut repo_flag = None;

        for i in idx..args.len() {
            match args[i] {
                "-X" | "--method" => {
                    if i + 1 < args.len() {
                        method = Some(args[i + 1].to_uppercase());
                    }
                }
                "-f" | "-F" | "--input" => {
                    has_input_flags = true;
                }
                "-R" | "--repo" => {
                    if i + 1 < args.len() {
                        repo_flag = Some(args[i + 1].to_string());
                    }
                }
                _ => {}
            }
        }

        return Some(ParsedCommand {
            command,
            subcommand: None,
            repo_flag,
            method,
            has_input_flags,
        });
    }

    // Find subcommand (first non-flag argument after command)
    let mut subcommand = None;
    let mut repo_flag = None;
    let mut i = idx;
    while i < args.len() {
        match args[i] {
            "-R" | "--repo" => {
                if i + 1 < args.len() {
                    repo_flag = Some(args[i + 1].to_string());
                    i += 2;
                    continue;
                }
            }
            arg if arg.starts_with('-') => {
                // Skip flags; if it looks like it takes a value, skip next too
                // We can't know for sure, but single-letter flags with a following
                // non-flag arg are likely flag+value pairs. We're conservative here.
                i += 1;
                continue;
            }
            arg => {
                if subcommand.is_none() {
                    subcommand = Some(arg.to_string());
                }
            }
        }
        i += 1;
    }

    Some(ParsedCommand {
        command,
        subcommand,
        repo_flag,
        method: None,
        has_input_flags: false,
    })
}

/// Look up the policy decision for a parsed command.
pub fn evaluate(cmd: &ParsedCommand) -> PolicyResult {
    // Special handling for `gh api`
    if cmd.command == "api" {
        return evaluate_api(cmd);
    }

    let sub = cmd.subcommand.as_deref().unwrap_or("");

    // First try exact match
    for entry in POLICY {
        if entry.command == cmd.command && entry.subcommand == sub {
            return PolicyResult {
                decision: entry.decision,
                reason: entry.reason,
            };
        }
    }

    // Then try wildcard match for the command group
    for entry in POLICY {
        if entry.command == cmd.command && entry.subcommand == ANY {
            return PolicyResult {
                decision: entry.decision,
                reason: entry.reason,
            };
        }
    }

    // Default-deny: unknown commands are blocked
    PolicyResult {
        decision: Decision::Block,
        reason: "unknown command — blocked by default",
    }
}

/// Special policy evaluation for `gh api`.
///
/// GET requests are scope-checked. Any other method (or presence of input
/// flags that imply a write) is blocked.
fn evaluate_api(cmd: &ParsedCommand) -> PolicyResult {
    // If input flags are present, it's implicitly a write
    if cmd.has_input_flags {
        return PolicyResult {
            decision: Decision::Block,
            reason: "gh api with input flags implies write operation",
        };
    }

    match cmd.method.as_deref() {
        None | Some("GET") => PolicyResult {
            decision: Decision::ScopeCheck,
            reason: "gh api GET — scope-checked",
        },
        Some(_) => PolicyResult {
            decision: Decision::Block,
            reason: "gh api with non-GET method",
        },
    }
}

/// Check if a repo flag targets the expected repository.
///
/// `current_repo` should be in "owner/name" format.
/// Returns true if the command targets the current repo (or has no -R flag).
pub fn is_repo_in_scope(cmd: &ParsedCommand, current_repo: &str) -> bool {
    match &cmd.repo_flag {
        None => true, // No -R flag — implicitly targets current repo
        Some(target) => {
            // Normalize comparison: case-insensitive, strip trailing .git
            let target_clean = target.trim_end_matches(".git").to_lowercase();
            let current_clean = current_repo.to_lowercase();
            target_clean == current_clean
        }
    }
}

/// Detect the current repository from the working directory.
///
/// Tries `git remote get-url origin` and parses the owner/repo from it.
/// Returns None if not in a git repo or remote URL can't be parsed.
pub fn detect_current_repo(project_dir: &Path) -> Option<String> {
    let output = std::process::Command::new("git")
        .args(["remote", "get-url", "origin"])
        .current_dir(project_dir)
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let url = String::from_utf8_lossy(&output.stdout).trim().to_string();
    parse_repo_from_url(&url)
}

/// Parse owner/repo from a git remote URL.
///
/// Handles:
/// - `https://github.com/owner/repo.git`
/// - `https://github.com/owner/repo`
/// - `git@github.com:owner/repo.git`
/// - `ssh://git@github.com/owner/repo.git`
fn parse_repo_from_url(url: &str) -> Option<String> {
    // SSH shorthand: git@github.com:owner/repo.git
    if let Some(rest) = url.strip_prefix("git@github.com:") {
        let repo = rest.trim_end_matches(".git");
        if repo.contains('/') {
            return Some(repo.to_string());
        }
    }

    // HTTPS or SSH URL
    // Look for github.com in the path
    let path = if let Some(rest) = url.strip_prefix("https://github.com/") {
        rest
    } else if let Some(rest) = url.strip_prefix("ssh://git@github.com/") {
        rest
    } else if let Some(rest) = url.strip_prefix("http://github.com/") {
        rest
    } else {
        return None;
    };

    let repo = path.trim_end_matches(".git");
    // Should have exactly one slash: owner/repo
    if repo.matches('/').count() == 1 && !repo.starts_with('/') && !repo.ends_with('/') {
        Some(repo.to_string())
    } else {
        None
    }
}

/// Generate the shell wrapper script content.
///
/// The wrapper intercepts `gh` invocations, calls `cplt gh-gate` for
/// policy decisions, and either passes through to the real `gh` or exits
/// with an error message.
///
/// `real_gh` is the path to the real `gh` binary.
/// `cplt_bin` is the path to the cplt binary (for calling `gh-gate`).
pub fn generate_wrapper_script(real_gh: &str, cplt_bin: &str) -> String {
    format!(
        r#"#!/bin/sh
# cplt gh proxy — blocks destructive gh operations in sandboxed agents.
# This wrapper is auto-generated. Do not edit.

exec "{cplt_bin}" gh-gate --real-gh "{real_gh}" -- "$@"
"#
    )
}

/// Evaluate a full command and return a human-friendly verdict.
///
/// This is the entry point used by the `gh-gate` subcommand.
/// Returns `Ok(())` if the command should be allowed, or `Err(message)` if blocked.
pub fn gate(args: &[&str], project_dir: &Path) -> Result<(), String> {
    let cmd = parse_command(args)
        .ok_or_else(|| "gh-proxy: could not parse command (no arguments provided)".to_string())?;

    let result = evaluate(&cmd);

    match result.decision {
        Decision::Allow => Ok(()),
        Decision::ScopeCheck => {
            let current_repo = detect_current_repo(project_dir).unwrap_or_default();

            if current_repo.is_empty() {
                // Can't determine repo — allow but warn
                Ok(())
            } else if is_repo_in_scope(&cmd, &current_repo) {
                Ok(())
            } else {
                Err(format!(
                    "blocked by cplt: 'gh {}{}' targets '{}' but current repo is '{}' ({})",
                    cmd.command,
                    cmd.subcommand
                        .as_deref()
                        .map(|s| format!(" {s}"))
                        .unwrap_or_default(),
                    cmd.repo_flag.as_deref().unwrap_or("unknown"),
                    current_repo,
                    result.reason,
                ))
            }
        }
        Decision::Block => Err(format!(
            "blocked by cplt: 'gh {}{}' is not allowed in sandbox ({})",
            cmd.command,
            cmd.subcommand
                .as_deref()
                .map(|s| format!(" {s}"))
                .unwrap_or_default(),
            result.reason,
        )),
    }
}

// ── Git push prevention ───────────────────────────────────────────────

/// Git subcommands that perform remote writes.
/// Blocked by the git wrapper to prevent agents from pushing code.
const GIT_BLOCKED_SUBCOMMANDS: &[&str] = &["push", "request-pull"];

/// Git subcommands that are always allowed (read-only or local-only).
const GIT_ALLOWED_SUBCOMMANDS: &[&str] = &[
    // Porcelain: reading
    "status",
    "log",
    "show",
    "diff",
    "shortlog",
    "describe",
    "blame",
    "grep",
    "bisect",
    "range-diff",
    "notes",
    // Porcelain: branching/local writes
    "branch",
    "checkout",
    "switch",
    "merge",
    "rebase",
    "cherry-pick",
    "revert",
    "reset",
    "restore",
    "stash",
    "tag",
    "worktree",
    // Porcelain: working tree
    "add",
    "rm",
    "mv",
    "clean",
    "sparse-checkout",
    // Porcelain: commits
    "commit",
    "am",
    "apply",
    // Porcelain: remote reads
    "fetch",
    "pull",
    "clone",
    "ls-remote",
    "remote",
    // Porcelain: inspection
    "reflog",
    "fsck",
    "count-objects",
    "verify-commit",
    "verify-tag",
    // Porcelain: config and misc
    "config",
    "help",
    "version",
    "init",
    "archive",
    "rev-parse",
    "rev-list",
    "for-each-ref",
    // Plumbing: reads
    "cat-file",
    "hash-object",
    "ls-tree",
    "ls-files",
    "diff-tree",
    "diff-files",
    "diff-index",
    "merge-base",
    "name-rev",
    "symbolic-ref",
    "show-ref",
    "var",
    "check-ref-format",
    "fmt-merge-msg",
    "mailinfo",
    "mailsplit",
    "stripspace",
    // Plumbing: packing (local)
    "pack-objects",
    "unpack-objects",
    "index-pack",
    "pack-refs",
    "prune",
    "gc",
    "maintenance",
    "rerere",
    // Misc
    "submodule",
    "lfs",
];

/// Evaluate a git command. Returns Ok(()) if allowed, Err with message if blocked.
///
/// Used by the `cplt git-gate` subcommand.
pub fn gate_git(args: &[&str]) -> Result<(), String> {
    // Find the subcommand by skipping global flags.
    // Git global flags that take a value (must skip the next arg too).
    const FLAGS_WITH_VALUE: &[&str] = &[
        "-c",
        "-C",
        "--git-dir",
        "--work-tree",
        "--namespace",
        "--super-prefix",
        "--config-env",
    ];

    let mut i = 0;
    let mut subcommand = None;
    while i < args.len() {
        let arg = args[i];
        if FLAGS_WITH_VALUE.contains(&arg) {
            i += 2; // skip flag and its value
            continue;
        }
        if arg.starts_with('-') {
            i += 1;
            continue;
        }
        subcommand = Some(arg);
        break;
    }

    let Some(sub) = subcommand else {
        // No subcommand (e.g., `git --version`) — allow
        return Ok(());
    };

    if GIT_BLOCKED_SUBCOMMANDS.contains(&sub) {
        return Err(format!(
            "blocked by cplt: 'git {sub}' is not allowed in sandbox \
             (push prevention is enabled — commit locally and let the human push)"
        ));
    }

    // If it's in the allow list, pass through
    if GIT_ALLOWED_SUBCOMMANDS.contains(&sub) {
        return Ok(());
    }

    // Unknown git subcommand — allow by default.
    // Git's subcommand space is enormous (plumbing, aliases, extensions).
    // Unlike gh where unknown = likely new destructive feature,
    // unknown git commands are usually safe plumbing or aliases.
    // The explicit block list is sufficient for push prevention.
    Ok(())
}

/// Generate the git wrapper script content.
///
/// Like the gh wrapper, this intercepts git invocations and blocks push operations.
pub fn generate_git_wrapper_script(real_git: &str, cplt_bin: &str) -> String {
    format!(
        r#"#!/bin/sh
# cplt git proxy — blocks git push in sandboxed agents.
# This wrapper is auto-generated. Do not edit.

exec "{cplt_bin}" git-gate --real-git "{real_git}" -- "$@"
"#
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── parse_command tests ──

    #[test]
    fn parse_simple_command() {
        let cmd = parse_command(&["pr", "list"]).unwrap();
        assert_eq!(cmd.command, "pr");
        assert_eq!(cmd.subcommand.as_deref(), Some("list"));
        assert_eq!(cmd.repo_flag, None);
    }

    #[test]
    fn parse_command_with_repo_flag() {
        let cmd = parse_command(&["pr", "view", "-R", "navikt/cplt", "123"]).unwrap();
        assert_eq!(cmd.command, "pr");
        assert_eq!(cmd.subcommand.as_deref(), Some("view"));
        assert_eq!(cmd.repo_flag.as_deref(), Some("navikt/cplt"));
    }

    #[test]
    fn parse_command_with_long_repo_flag() {
        let cmd = parse_command(&["issue", "list", "--repo", "owner/repo"]).unwrap();
        assert_eq!(cmd.command, "issue");
        assert_eq!(cmd.subcommand.as_deref(), Some("list"));
        assert_eq!(cmd.repo_flag.as_deref(), Some("owner/repo"));
    }

    #[test]
    fn parse_api_get() {
        let cmd = parse_command(&["api", "/repos/owner/repo/pulls"]).unwrap();
        assert_eq!(cmd.command, "api");
        assert_eq!(cmd.subcommand, None);
        assert_eq!(cmd.method, None);
        assert!(!cmd.has_input_flags);
    }

    #[test]
    fn parse_api_post() {
        let cmd = parse_command(&["api", "-X", "POST", "/repos/owner/repo/issues"]).unwrap();
        assert_eq!(cmd.command, "api");
        assert_eq!(cmd.method.as_deref(), Some("POST"));
    }

    #[test]
    fn parse_api_with_input_flags() {
        let cmd = parse_command(&["api", "/repos/o/r/issues", "-f", "title=bug"]).unwrap();
        assert_eq!(cmd.command, "api");
        assert!(cmd.has_input_flags);
    }

    #[test]
    fn parse_empty_args() {
        assert!(parse_command(&[]).is_none());
    }

    #[test]
    fn parse_only_flags() {
        // e.g. `gh --version`
        assert!(parse_command(&["--version"]).is_none());
    }

    // ── evaluate tests ──

    #[test]
    fn allow_read_operations() {
        let cases = [
            ("pr", "list"),
            ("pr", "view"),
            ("issue", "list"),
            ("repo", "view"),
            ("run", "list"),
            ("search", "repos"),
            ("search", "issues"),
        ];
        for (cmd, sub) in cases {
            let parsed = ParsedCommand {
                command: cmd.to_string(),
                subcommand: Some(sub.to_string()),
                repo_flag: None,
                method: None,
                has_input_flags: false,
            };
            let result = evaluate(&parsed);
            assert_eq!(
                result.decision,
                Decision::Allow,
                "expected Allow for {cmd} {sub}"
            );
        }
    }

    #[test]
    fn block_destructive_operations() {
        let cases = [
            ("repo", "delete"),
            ("repo", "create"),
            ("pr", "merge"),
            ("issue", "delete"),
            ("release", "create"),
            ("secret", "set"),
            ("workflow", "run"),
        ];
        for (cmd, sub) in cases {
            let parsed = ParsedCommand {
                command: cmd.to_string(),
                subcommand: Some(sub.to_string()),
                repo_flag: None,
                method: None,
                has_input_flags: false,
            };
            let result = evaluate(&parsed);
            assert_eq!(
                result.decision,
                Decision::Block,
                "expected Block for {cmd} {sub}"
            );
        }
    }

    #[test]
    fn scope_check_write_operations() {
        let cases = [
            ("pr", "create"),
            ("pr", "comment"),
            ("issue", "create"),
            ("issue", "close"),
            ("label", "create"),
        ];
        for (cmd, sub) in cases {
            let parsed = ParsedCommand {
                command: cmd.to_string(),
                subcommand: Some(sub.to_string()),
                repo_flag: None,
                method: None,
                has_input_flags: false,
            };
            let result = evaluate(&parsed);
            assert_eq!(
                result.decision,
                Decision::ScopeCheck,
                "expected ScopeCheck for {cmd} {sub}"
            );
        }
    }

    #[test]
    fn default_deny_unknown_commands() {
        let parsed = ParsedCommand {
            command: "invented-future-cmd".to_string(),
            subcommand: Some("destroy".to_string()),
            repo_flag: None,
            method: None,
            has_input_flags: false,
        };
        let result = evaluate(&parsed);
        assert_eq!(result.decision, Decision::Block);
    }

    #[test]
    fn wildcard_groups() {
        // search group allows everything
        let parsed = ParsedCommand {
            command: "search".to_string(),
            subcommand: Some("repos".to_string()),
            repo_flag: None,
            method: None,
            has_input_flags: false,
        };
        assert_eq!(evaluate(&parsed).decision, Decision::Allow);

        // codespace group blocks everything
        let parsed = ParsedCommand {
            command: "codespace".to_string(),
            subcommand: Some("create".to_string()),
            repo_flag: None,
            method: None,
            has_input_flags: false,
        };
        assert_eq!(evaluate(&parsed).decision, Decision::Block);
    }

    #[test]
    fn api_get_is_scope_check() {
        let parsed = ParsedCommand {
            command: "api".to_string(),
            subcommand: None,
            repo_flag: None,
            method: None,
            has_input_flags: false,
        };
        assert_eq!(evaluate(&parsed).decision, Decision::ScopeCheck);

        let parsed = ParsedCommand {
            command: "api".to_string(),
            subcommand: None,
            repo_flag: None,
            method: Some("GET".to_string()),
            has_input_flags: false,
        };
        assert_eq!(evaluate(&parsed).decision, Decision::ScopeCheck);
    }

    #[test]
    fn api_post_is_blocked() {
        let parsed = ParsedCommand {
            command: "api".to_string(),
            subcommand: None,
            repo_flag: None,
            method: Some("POST".to_string()),
            has_input_flags: false,
        };
        assert_eq!(evaluate(&parsed).decision, Decision::Block);
    }

    #[test]
    fn api_with_input_flags_is_blocked() {
        let parsed = ParsedCommand {
            command: "api".to_string(),
            subcommand: None,
            repo_flag: None,
            method: None,
            has_input_flags: true,
        };
        assert_eq!(evaluate(&parsed).decision, Decision::Block);
    }

    // ── repo scope tests ──

    #[test]
    fn scope_check_no_repo_flag_is_in_scope() {
        let cmd = ParsedCommand {
            command: "pr".to_string(),
            subcommand: Some("create".to_string()),
            repo_flag: None,
            method: None,
            has_input_flags: false,
        };
        assert!(is_repo_in_scope(&cmd, "navikt/cplt"));
    }

    #[test]
    fn scope_check_matching_repo() {
        let cmd = ParsedCommand {
            command: "pr".to_string(),
            subcommand: Some("create".to_string()),
            repo_flag: Some("navikt/cplt".to_string()),
            method: None,
            has_input_flags: false,
        };
        assert!(is_repo_in_scope(&cmd, "navikt/cplt"));
    }

    #[test]
    fn scope_check_different_repo() {
        let cmd = ParsedCommand {
            command: "pr".to_string(),
            subcommand: Some("create".to_string()),
            repo_flag: Some("other/repo".to_string()),
            method: None,
            has_input_flags: false,
        };
        assert!(!is_repo_in_scope(&cmd, "navikt/cplt"));
    }

    #[test]
    fn scope_check_case_insensitive() {
        let cmd = ParsedCommand {
            command: "pr".to_string(),
            subcommand: Some("create".to_string()),
            repo_flag: Some("Navikt/CPLT".to_string()),
            method: None,
            has_input_flags: false,
        };
        assert!(is_repo_in_scope(&cmd, "navikt/cplt"));
    }

    #[test]
    fn scope_check_strips_git_suffix() {
        let cmd = ParsedCommand {
            command: "pr".to_string(),
            subcommand: Some("create".to_string()),
            repo_flag: Some("navikt/cplt.git".to_string()),
            method: None,
            has_input_flags: false,
        };
        assert!(is_repo_in_scope(&cmd, "navikt/cplt"));
    }

    // ── URL parsing tests ──

    #[test]
    fn parse_https_url() {
        assert_eq!(
            parse_repo_from_url("https://github.com/navikt/cplt.git"),
            Some("navikt/cplt".to_string())
        );
    }

    #[test]
    fn parse_https_url_no_git() {
        assert_eq!(
            parse_repo_from_url("https://github.com/navikt/cplt"),
            Some("navikt/cplt".to_string())
        );
    }

    #[test]
    fn parse_ssh_shorthand() {
        assert_eq!(
            parse_repo_from_url("git@github.com:navikt/cplt.git"),
            Some("navikt/cplt".to_string())
        );
    }

    #[test]
    fn parse_ssh_url() {
        assert_eq!(
            parse_repo_from_url("ssh://git@github.com/navikt/cplt.git"),
            Some("navikt/cplt".to_string())
        );
    }

    #[test]
    fn parse_non_github_url() {
        assert_eq!(
            parse_repo_from_url("https://gitlab.com/owner/repo.git"),
            None
        );
    }

    // ── wrapper script test ──

    #[test]
    fn wrapper_script_contains_paths() {
        let script = generate_wrapper_script("/usr/bin/gh", "/usr/local/bin/cplt");
        assert!(script.contains("/usr/bin/gh"));
        assert!(script.contains("/usr/local/bin/cplt"));
        assert!(script.starts_with("#!/bin/sh"));
    }

    // ── project group specific ordering ──

    #[test]
    fn project_list_allowed_but_edit_blocked() {
        let list = ParsedCommand {
            command: "project".to_string(),
            subcommand: Some("list".to_string()),
            repo_flag: None,
            method: None,
            has_input_flags: false,
        };
        assert_eq!(evaluate(&list).decision, Decision::Allow);

        let edit = ParsedCommand {
            command: "project".to_string(),
            subcommand: Some("edit".to_string()),
            repo_flag: None,
            method: None,
            has_input_flags: false,
        };
        assert_eq!(evaluate(&edit).decision, Decision::Block);
    }

    // ── git gate tests ──

    #[test]
    fn git_push_is_blocked() {
        assert!(gate_git(&["push"]).is_err());
        assert!(gate_git(&["push", "origin", "main"]).is_err());
        assert!(gate_git(&["push", "--force"]).is_err());
        assert!(gate_git(&["-c", "user.name=x", "push"]).is_err());
    }

    #[test]
    fn git_request_pull_is_blocked() {
        assert!(gate_git(&["request-pull", "v1.0", "origin"]).is_err());
    }

    #[test]
    fn git_read_operations_allowed() {
        assert!(gate_git(&["status"]).is_ok());
        assert!(gate_git(&["log", "--oneline"]).is_ok());
        assert!(gate_git(&["diff", "HEAD~1"]).is_ok());
        assert!(gate_git(&["fetch", "origin"]).is_ok());
        assert!(gate_git(&["pull"]).is_ok());
        assert!(gate_git(&["branch", "-a"]).is_ok());
    }

    #[test]
    fn git_local_writes_allowed() {
        assert!(gate_git(&["commit", "-m", "fix"]).is_ok());
        assert!(gate_git(&["add", "."]).is_ok());
        assert!(gate_git(&["checkout", "-b", "feature"]).is_ok());
        assert!(gate_git(&["merge", "main"]).is_ok());
        assert!(gate_git(&["rebase", "main"]).is_ok());
        assert!(gate_git(&["stash"]).is_ok());
        assert!(gate_git(&["tag", "v1.0"]).is_ok());
    }

    #[test]
    fn git_no_subcommand_allowed() {
        assert!(gate_git(&["--version"]).is_ok());
        assert!(gate_git(&[]).is_ok());
    }

    #[test]
    fn git_unknown_subcommand_allowed() {
        // Unknown git commands default to allow (unlike gh which defaults to block)
        assert!(gate_git(&["some-custom-alias"]).is_ok());
    }

    #[test]
    fn git_wrapper_script_contains_paths() {
        let script = generate_git_wrapper_script("/usr/bin/git", "/usr/local/bin/cplt");
        assert!(script.contains("/usr/bin/git"));
        assert!(script.contains("/usr/local/bin/cplt"));
        assert!(script.contains("git-gate"));
    }
}
