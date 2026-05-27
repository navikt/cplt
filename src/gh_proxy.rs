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
    /// Command not in policy table — decision deferred to GatePolicy.unknown_command.
    Unknown,
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
    /// For `gh api`: the endpoint path (e.g., "/repos/owner/repo/pulls").
    pub api_endpoint: Option<String>,
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
    // ── gh help / version (always allowed) ──
    PolicyEntry {
        command: "help",
        subcommand: ANY,
        decision: Decision::Allow,
        reason: "read-only informational",
    },
    PolicyEntry {
        command: "version",
        subcommand: ANY,
        decision: Decision::Allow,
        reason: "read-only informational",
    },
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
        reason: "read-only (may be blocked by block_auth_token policy)",
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

    // Skip global flags that appear before the command.
    // gh global flags that take a value argument:
    const GLOBAL_FLAGS_WITH_VALUE: &[&str] = &["--repo", "-R", "--hostname"];
    let mut idx = 0;
    let mut global_repo_flag: Option<String> = None;
    while idx < args.len() && args[idx].starts_with('-') {
        let arg = args[idx];
        // Handle --flag=value forms (skip as single arg)
        if let Some(val) = arg.strip_prefix("--repo=") {
            global_repo_flag = Some(val.to_string());
            idx += 1;
            continue;
        }
        if arg.starts_with("-R") && arg.len() > 2 && !arg.starts_with("-R=") {
            global_repo_flag = Some(arg[2..].to_string());
            idx += 1;
            continue;
        }
        if arg.contains('=') {
            idx += 1;
            continue;
        }
        // Skip flag and its value if it takes one
        if GLOBAL_FLAGS_WITH_VALUE.contains(&arg) {
            if (arg == "--repo" || arg == "-R") && idx + 1 < args.len() {
                global_repo_flag = Some(args[idx + 1].to_string());
            }
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
        let mut api_endpoint = None;

        // Flags that consume the next argument as a value
        const API_FLAGS_WITH_VALUE: &[&str] = &[
            "-X",
            "--method",
            "-R",
            "--repo",
            "-f",
            "-F",
            "--field",
            "--raw-field",
            "--input",
            "-H",
            "--header",
            "--hostname",
            "-t",
            "--template",
            "-q",
            "--jq",
            "--cache",
            "-p",
            "--preview",
        ];

        let mut i = idx;
        while i < args.len() {
            let arg = args[i];
            // Handle --flag=value forms
            if let Some(val) = arg.strip_prefix("--method=") {
                method = Some(val.to_uppercase());
            } else if arg.starts_with("-X") && arg.len() > 2 {
                // -XPOST form (short flag with attached value)
                method = Some(arg[2..].to_uppercase());
            } else if let Some(val) = arg.strip_prefix("--repo=") {
                repo_flag = Some(val.to_string());
            } else if arg.starts_with("-R") && arg.len() > 2 {
                repo_flag = Some(arg[2..].to_string());
            } else if arg.starts_with("--field=")
                || arg.starts_with("--raw-field=")
                || arg.starts_with("--input=")
            {
                // --field=key=value, --raw-field=key=value, --input=-
                // These imply a mutating request (POST)
                has_input_flags = true;
            } else if (arg.starts_with("-f") && arg.len() > 2 && arg.as_bytes()[2] != b'-')
                || (arg.starts_with("-F") && arg.len() > 2 && arg.as_bytes()[2] != b'-')
            {
                // -ftitle=bug, -Ftitle=bug — combined short flag with attached value
                has_input_flags = true;
            } else if arg.starts_with('-') {
                match arg {
                    "-X" | "--method" => {
                        if i + 1 < args.len() {
                            method = Some(args[i + 1].to_uppercase());
                            i += 1;
                        }
                    }
                    "-f" | "-F" | "--input" | "--field" | "--raw-field" => {
                        has_input_flags = true;
                        // These take a value argument
                        i += 1;
                    }
                    "-R" | "--repo" => {
                        if i + 1 < args.len() {
                            repo_flag = Some(args[i + 1].to_string());
                            i += 1;
                        }
                    }
                    f if API_FLAGS_WITH_VALUE.contains(&f) => {
                        i += 1; // skip value
                    }
                    _ => {} // boolean flag, skip
                }
            } else {
                // Positional argument — this is the API endpoint
                if api_endpoint.is_none() {
                    api_endpoint = Some(arg.to_string());
                }
            }
            i += 1;
        }

        return Some(ParsedCommand {
            command,
            subcommand: None,
            repo_flag: repo_flag.or(global_repo_flag),
            method,
            has_input_flags,
            api_endpoint,
        });
    }

    // Find subcommand (first non-flag argument after command)
    let mut subcommand = None;
    let mut repo_flag = None;
    let mut i = idx;
    while i < args.len() {
        let arg = args[i];
        // Handle --repo=value and -Rvalue forms
        if let Some(val) = arg.strip_prefix("--repo=") {
            repo_flag = Some(val.to_string());
            i += 1;
            continue;
        }
        if arg.starts_with("-R") && arg.len() > 2 {
            // Handle both `-Rowner/repo` and `-R=owner/repo`
            let val = arg[2..].strip_prefix('=').unwrap_or(&arg[2..]);
            repo_flag = Some(val.to_string());
            i += 1;
            continue;
        }
        match arg {
            "-R" | "--repo" => {
                if i + 1 < args.len() {
                    repo_flag = Some(args[i + 1].to_string());
                    i += 2;
                    continue;
                }
            }
            a if a.starts_with('-') => {
                // Skip flags
                i += 1;
                continue;
            }
            a => {
                if subcommand.is_none() {
                    subcommand = Some(a.to_string());
                }
            }
        }
        i += 1;
    }

    Some(ParsedCommand {
        command,
        subcommand,
        repo_flag: repo_flag.or(global_repo_flag),
        method: None,
        has_input_flags: false,
        api_endpoint: None,
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

    // Default: unknown commands — decision deferred to GatePolicy
    PolicyResult {
        decision: Decision::Unknown,
        reason: "unknown command — not in policy table",
    }
}

/// Special policy evaluation for `gh api`.
///
/// GET requests are scope-checked. Any other method (or presence of input
/// flags that imply a write) is blocked.
fn evaluate_api(cmd: &ParsedCommand) -> PolicyResult {
    // Block GraphQL endpoint — it allows arbitrary mutations via stdin/body
    // that cannot be statically analyzed for scope or intent.
    if let Some(ref endpoint) = cmd.api_endpoint
        && (endpoint == "graphql" || endpoint == "/graphql")
    {
        return PolicyResult {
            decision: Decision::Block,
            reason: "gh api graphql allows arbitrary mutations — use specific REST endpoints instead",
        };
    }

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
/// For `gh api` commands, also checks the endpoint URL path for /repos/{owner}/{repo}/.
/// Non-repo API endpoints (orgs, users) are NOT implicitly allowed — they require
/// explicit -R or a matching /repos/ path.
pub fn is_repo_in_scope(cmd: &ParsedCommand, current_repo: &str) -> bool {
    // Check -R/--repo flag first
    if let Some(target) = &cmd.repo_flag {
        let target_clean = target.trim_end_matches(".git").to_lowercase();
        let current_clean = current_repo.to_lowercase();
        return target_clean == current_clean;
    }

    // For gh api: extract repo from endpoint path like /repos/{owner}/{repo}/...
    if cmd.command == "api" {
        if let Some(ref endpoint) = cmd.api_endpoint {
            if let Some(endpoint_repo) = extract_repo_from_api_path(endpoint) {
                let current_clean = current_repo.to_lowercase();
                return endpoint_repo.to_lowercase() == current_clean;
            }
            // Check if this is a relative path (no leading /) — gh resolves these
            // to the current repo automatically (e.g., `gh api pulls/67/comments`).
            let path = endpoint.strip_prefix('/').unwrap_or(endpoint);
            let path = path.split('?').next().unwrap_or(path);
            if !path.starts_with("repos/")
                && !path.starts_with("orgs/")
                && !path.starts_with("users/")
                && !path.starts_with("user")
                && !path.starts_with("notifications")
                && !path.starts_with("graphql")
            {
                // Relative endpoint — gh CLI resolves to current repo. Allow.
                return true;
            }
            // Absolute non-repo endpoint (e.g., /orgs/..., /user/...) — not in scope.
            return false;
        }
        // No endpoint at all for gh api — shouldn't happen, but deny
        return false;
    }

    // Non-api commands: no -R flag → implicitly targets current repo
    true
}

/// Extract "owner/repo" from a GitHub API endpoint path.
///
/// Matches patterns like:
/// - `/repos/owner/repo/pulls`
/// - `repos/owner/repo/issues/1`
/// - `/repos/owner/repo` (exact)
///
/// Returns None if the path doesn't match the /repos/{owner}/{repo} pattern.
fn extract_repo_from_api_path(endpoint: &str) -> Option<String> {
    // Strip query string/fragment before parsing path segments
    let endpoint = endpoint.split('?').next().unwrap_or(endpoint);
    let endpoint = endpoint.split('#').next().unwrap_or(endpoint);
    let path = endpoint.strip_prefix('/').unwrap_or(endpoint);
    let parts: Vec<&str> = path.split('/').collect();

    // Must start with "repos" and have at least owner + repo
    if parts.len() >= 3 && parts[0] == "repos" && !parts[1].is_empty() && !parts[2].is_empty() {
        Some(format!("{}/{}", parts[1], parts[2]))
    } else {
        None
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

/// Escape a string for safe inclusion in a POSIX shell script.
///
/// Wraps the value in single quotes and escapes any embedded single quotes
/// using the `'\''` idiom (end quote, literal quote, resume quote).
fn shell_escape(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// Generate the shell wrapper script content.
///
/// The wrapper intercepts `gh` invocations, calls `cplt gh-gate` for
/// policy decisions, and either passes through to the real `gh` or exits
/// with an error message.
///
/// `real_gh` is the path to the real `gh` binary.
/// `cplt_bin` is the path to the cplt binary (for calling `gh-gate`).
/// Policy flags are baked into the wrapper invocation so the gate doesn't
/// re-read config at runtime (security: agent could edit config files).
pub fn generate_wrapper_script(
    real_gh: &str,
    cplt_bin: &str,
    policy: &crate::config::GhGuardPolicy,
) -> String {
    let cplt_escaped = shell_escape(cplt_bin);
    let gh_escaped = shell_escape(real_gh);
    let mode_flag = match policy.mode {
        crate::config::EnforcementMode::Block => "--mode=block",
        crate::config::EnforcementMode::Warn => "--mode=warn",
        crate::config::EnforcementMode::Audit => "--mode=audit",
    };
    let scope_flag = if policy.scope_check {
        "--scope-check"
    } else {
        "--no-scope-check"
    };
    let auth_flag = if policy.block_auth_token {
        "--block-auth-token"
    } else {
        "--no-block-auth-token"
    };
    let unknown_flag = match policy.unknown_command {
        crate::config::UnknownCommandPolicy::Block => "--unknown-command=block",
        crate::config::UnknownCommandPolicy::Allow => "--unknown-command=allow",
    };
    format!(
        r#"#!/bin/sh
# cplt gh proxy — blocks destructive gh operations in sandboxed agents.
# This wrapper is auto-generated. Do not edit.

exec {cplt_escaped} gh-gate --real-gh {gh_escaped} {mode_flag} {scope_flag} {auth_flag} {unknown_flag} -- "$@"
"#
    )
}

/// Immutable policy passed to the gate function at invocation time.
/// Baked into the wrapper script as CLI flags — never re-read from config.
#[derive(Debug, Clone, Copy)]
pub struct GatePolicy {
    /// Enforcement mode for violations.
    pub mode: crate::config::EnforcementMode,
    /// Enforce same-repo check for ScopeCheck commands.
    pub scope_check: bool,
    /// Block `gh auth token` (token exfiltration prevention).
    pub block_auth_token: bool,
    /// Policy for commands not in the classification table.
    pub unknown_command: UnknownCommandDecision,
}

/// What to do with commands not in the policy table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnknownCommandDecision {
    Block,
    Allow,
}

impl Default for GatePolicy {
    fn default() -> Self {
        Self {
            mode: crate::config::EnforcementMode::Block,
            scope_check: true,
            block_auth_token: true,
            unknown_command: UnknownCommandDecision::Block,
        }
    }
}

/// Evaluate a full command and return a human-friendly verdict.
///
/// This is the entry point used by the `gh-gate` subcommand.
/// Returns `Ok(())` if the command should be allowed, or `Err(message)` if blocked.
pub fn gate(args: &[&str], project_dir: &Path, policy: &GatePolicy) -> Result<(), String> {
    let Some(cmd) = parse_command(args) else {
        // No command parsed — this happens for `gh --help`, `gh --version`, `gh help`, etc.
        // These are read-only informational invocations — always allow.
        return Ok(());
    };

    // Handle `gh auth token` block (credential exfiltration prevention)
    if policy.block_auth_token
        && cmd.command == "auth"
        && cmd.subcommand.as_deref() == Some("token")
    {
        return Err(
            "⚠️ BLOCKED by sandbox: 'gh auth token' is not allowed in this environment.\n\
             Reason: token exfiltration prevention — use GH_TOKEN env var instead.\n\
             This operation is restricted by the cplt sandbox to prevent credential leaks.\n\
             Stop and report this to the human operator — they can run this command outside the sandbox."
                .to_string(),
        );
    }

    let result = evaluate(&cmd);

    match result.decision {
        Decision::Allow => Ok(()),
        Decision::ScopeCheck => {
            if !policy.scope_check {
                return Ok(());
            }
            let current_repo = detect_current_repo(project_dir).unwrap_or_default();

            if current_repo.is_empty() {
                if cmd.repo_flag.is_some() {
                    Err(format!(
                        "⚠️ BLOCKED by sandbox: 'gh {} {}' cannot verify target repository scope.\n\
                         The -R flag targets {:?} but the current repo could not be detected.\n\
                         This operation is restricted by the cplt sandbox environment.\n\
                         Stop and report this to the human operator — they can run this command outside the sandbox.",
                        cmd.command,
                        cmd.subcommand.as_deref().unwrap_or(""),
                        cmd.repo_flag.as_deref().unwrap_or("unknown")
                    ))
                } else {
                    Ok(())
                }
            } else if is_repo_in_scope(&cmd, &current_repo) {
                Ok(())
            } else {
                Err(format!(
                    "⚠️ BLOCKED by sandbox: 'gh {}{}' targets '{}' which is outside the current repo '{}'.\n\
                     Reason: {}\n\
                     This operation is restricted by the cplt sandbox environment.\n\
                     Stop and report this to the human operator — they can run this command outside the sandbox.",
                    cmd.command,
                    cmd.subcommand
                        .as_deref()
                        .map(|s| format!(" {s}"))
                        .unwrap_or_default(),
                    cmd.repo_flag
                        .as_deref()
                        .or(cmd.api_endpoint.as_deref())
                        .unwrap_or("unknown"),
                    current_repo,
                    result.reason,
                ))
            }
        }
        Decision::Block => Err(format!(
            "⚠️ BLOCKED by sandbox: 'gh {}{}' is not allowed in this environment.\n\
             Reason: {}\n\
             This operation is restricted by the cplt sandbox to prevent unintended changes.\n\
             Stop and report this to the human operator — they can run this command outside the sandbox.",
            cmd.command,
            cmd.subcommand
                .as_deref()
                .map(|s| format!(" {s}"))
                .unwrap_or_default(),
            result.reason,
        )),
        Decision::Unknown => match policy.unknown_command {
            UnknownCommandDecision::Allow => Ok(()),
            UnknownCommandDecision::Block => Err(format!(
                "⚠️ BLOCKED by sandbox: 'gh {}{}' is not recognized by the policy table.\n\
                     This command may have been added in a newer gh CLI version.\n\
                     This operation is restricted by the cplt sandbox (default-deny for unknown commands).\n\
                     Stop and report this to the human operator — they can run this command outside the sandbox.",
                cmd.command,
                cmd.subcommand
                    .as_deref()
                    .map(|s| format!(" {s}"))
                    .unwrap_or_default(),
            )),
        },
    }
}

// ── Git push prevention ───────────────────────────────────────────────

/// Git subcommands that perform remote writes.
/// Blocked by the git wrapper to prevent agents from pushing code.
const GIT_BLOCKED_SUBCOMMANDS: &[&str] = &["push", "request-pull", "send-pack"];

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
/// `prevent_push` controls whether push/request-pull/send-pack are blocked.
/// `prevent_force_push` blocks force push even when regular push is allowed.
/// `protect_default_branch_only` allows pushes to non-default branches (not main/master).
pub fn gate_git(
    args: &[&str],
    prevent_push: bool,
    prevent_force_push: bool,
    protect_default_branch_only: bool,
    allow_push_rules: &[crate::config::ResolvedPushRule],
    real_git: Option<&Path>,
) -> Result<(), String> {
    // If push prevention is entirely disabled, allow everything
    if !prevent_push && !prevent_force_push {
        return Ok(());
    }

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

    if prevent_push && GIT_BLOCKED_SUBCOMMANDS.contains(&sub) {
        // When protect_default_branch_only is set, only block pushes targeting
        // the default branch (main/master). Feature branch pushes are allowed.
        if protect_default_branch_only && sub == "push" {
            let push_args = &args[i + 1..];
            let target_branch = extract_push_target_branch(push_args);
            if let Some(branch) = target_branch {
                if !is_default_branch(branch) {
                    return Ok(());
                }
            } else {
                // No explicit branch: `git push` pushes current branch.
                // Resolve via real git to determine if we're on a protected branch.
                let current_branch = real_git.and_then(resolve_current_branch);
                match current_branch {
                    Some(ref b) if !is_default_branch(b) => return Ok(()),
                    Some(_) => {
                        // On default branch — fall through to block
                    }
                    None => {
                        // Can't determine branch — fail closed for safety
                    }
                }
            }
        }

        // Check allow_push exception rules before blocking
        if sub == "push" && !allow_push_rules.is_empty() {
            let push_args = &args[i + 1..];
            let has_force = push_args.iter().any(|a| {
                *a == "--force"
                    || *a == "-f"
                    || a.starts_with("--force-with-lease")
                    || a.starts_with("--force-if-includes")
            });
            let (remote, branch) = extract_push_remote_and_branch(push_args, real_git);
            if matches_allow_push_rule(
                allow_push_rules,
                remote.as_deref(),
                branch.as_deref(),
                has_force,
            ) {
                return Ok(());
            }
        }

        return Err(format!(
            "⚠️ BLOCKED by sandbox: 'git {sub}' is not allowed in this environment.\n\
             Push prevention is enabled — commit your changes locally.\n\
             This operation is restricted by the cplt sandbox to prevent unintended pushes.\n\
             Stop and report this to the human operator — they will review and push when ready."
        ));
    }

    // If only force push prevention is active (prevent_push=false, prevent_force_push=true),
    // check for force push flags on push commands
    if !prevent_push && prevent_force_push && sub == "push" {
        let push_args = &args[i + 1..];
        let has_force = push_args.iter().any(|a| {
            *a == "--force"
                || *a == "-f"
                || a.starts_with("--force-with-lease")
                || a.starts_with("--force-if-includes")
        });
        if has_force {
            return Err(
                "⚠️ BLOCKED by sandbox: 'git push --force' is not allowed in this environment.\n\
                 Force push prevention is enabled — regular push is allowed but force push is blocked.\n\
                 Stop and report this to the human operator."
                    .to_string(),
            );
        }
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

/// Default branch names that are protected when `protect_default_branch_only` is active.
const DEFAULT_BRANCH_NAMES: &[&str] = &["main", "master"];

/// Check if a branch name is a default branch (main/master).
fn is_default_branch(branch: &str) -> bool {
    // Strip remote prefix if present (e.g., "origin/main" → "main")
    let short = branch.rsplit('/').next().unwrap_or(branch);
    DEFAULT_BRANCH_NAMES.contains(&short)
}

/// Extract the target branch from `git push` arguments.
///
/// Parses refspecs like `origin feature-branch`, `origin HEAD:refs/heads/feature`,
/// or just `feature-branch`. Returns None if no explicit branch target found.
fn extract_push_target_branch<'a>(push_args: &[&'a str]) -> Option<&'a str> {
    // Push flags that consume a value
    const PUSH_FLAGS_WITH_VALUE: &[&str] = &[
        "--repo",
        "--receive-pack",
        "--exec",
        "-o",
        "--push-option",
        "--signed",
        "--force-with-lease",
    ];

    let mut positionals: Vec<&str> = Vec::new();
    let mut i = 0;
    while i < push_args.len() {
        let arg = push_args[i];
        if arg == "--" {
            // Everything after -- is positional
            positionals.extend_from_slice(&push_args[i + 1..]);
            break;
        }
        if arg.contains('=') && arg.starts_with('-') {
            // --flag=value, skip
            i += 1;
            continue;
        }
        if PUSH_FLAGS_WITH_VALUE.contains(&arg) {
            i += 2;
            continue;
        }
        if arg.starts_with('-') {
            i += 1;
            continue;
        }
        positionals.push(arg);
        i += 1;
    }

    // `git push [remote] [refspec...]`
    // positionals[0] is usually the remote, positionals[1+] are refspecs
    match positionals.len() {
        0 => None, // `git push` — pushes current branch
        1 => {
            // Could be remote OR refspec. If it looks like a remote name, no branch specified.
            // Common remotes: origin, upstream, fork, etc.
            // If it contains a colon, it's a refspec like "HEAD:refs/heads/branch"
            let arg = positionals[0];
            if let Some(dst) = extract_branch_from_refspec(arg) {
                Some(dst)
            } else {
                None // Just a remote name, no explicit branch
            }
        }
        _ => {
            // positionals[0] = remote, positionals[1] = first refspec
            let refspec = positionals[1];
            if let Some(dst) = extract_branch_from_refspec(refspec) {
                Some(dst)
            } else {
                // Plain branch name like "feature-branch"
                Some(refspec)
            }
        }
    }
}

/// Parse a git refspec and extract the destination branch.
///
/// Refspecs: `src:dst`, `HEAD:refs/heads/branch`, or just a branch name.
/// Returns the destination part (after `:`) or None if no colon.
fn extract_branch_from_refspec(refspec: &str) -> Option<&str> {
    if let Some((_src, dst)) = refspec.split_once(':') {
        // Strip refs/heads/ prefix if present
        let branch = dst
            .strip_prefix("refs/heads/")
            .or_else(|| dst.strip_prefix("refs/for/"))
            .unwrap_or(dst);
        Some(branch)
    } else {
        None
    }
}

/// Resolve the current git branch by calling the real git binary.
fn resolve_current_branch(real_git: &Path) -> Option<String> {
    let output = std::process::Command::new(real_git)
        .args(["symbolic-ref", "--short", "HEAD"])
        .output()
        .ok()?;
    if output.status.success() {
        let branch = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if branch.is_empty() {
            None
        } else {
            Some(branch)
        }
    } else {
        None
    }
}

/// Extract the remote and branch from `git push` arguments.
/// Returns (remote, branch) — either may be None.
fn extract_push_remote_and_branch(
    push_args: &[&str],
    real_git: Option<&Path>,
) -> (Option<String>, Option<String>) {
    let target = extract_push_target_branch(push_args);
    let branch = match target {
        Some(b) => Some(b.to_string()),
        None => real_git.and_then(resolve_current_branch),
    };

    // Extract remote (first positional that's not a refspec)
    let mut positionals: Vec<&str> = Vec::new();
    let mut i = 0;
    while i < push_args.len() {
        let arg = push_args[i];
        if arg == "--" {
            break;
        }
        if arg.starts_with('-') {
            // Skip flags with values
            if arg.contains('=')
                || ![
                    "--repo",
                    "--receive-pack",
                    "--exec",
                    "-o",
                    "--push-option",
                    "--signed",
                    "--force-with-lease",
                ]
                .contains(&arg)
            {
                i += 1;
            } else {
                i += 2;
            }
            continue;
        }
        positionals.push(arg);
        i += 1;
    }
    let remote = positionals.first().map(ToString::to_string);

    (remote, branch)
}

/// Check if a push matches any allow_push exception rule.
/// All specified fields in a rule must match (AND logic).
fn matches_allow_push_rule(
    rules: &[crate::config::ResolvedPushRule],
    remote: Option<&str>,
    branch: Option<&str>,
    is_force: bool,
) -> bool {
    for rule in rules {
        // If force push and rule doesn't allow force, skip
        if is_force && !rule.force {
            continue;
        }
        // Check remote constraint
        if let Some(ref rule_remote) = rule.remote {
            match remote {
                Some(r) if r == rule_remote => {}
                _ => continue,
            }
        }
        // Check branch constraints (glob patterns)
        if !rule.branches.is_empty() {
            match branch {
                Some(b) => {
                    let matches = rule.branches.iter().any(|pattern| glob_match(pattern, b));
                    if !matches {
                        continue;
                    }
                }
                None => continue, // Can't verify branch — don't match
            }
        }
        // All constraints matched
        return true;
    }
    false
}

/// Simple glob matching for branch patterns.
/// Supports `*` (any chars within segment) and `**` or trailing `*` for multi-segment.
fn glob_match(pattern: &str, value: &str) -> bool {
    if pattern == "*" || pattern == "**" {
        return true;
    }
    if let Some(prefix) = pattern.strip_suffix("/*") {
        // e.g. "agent/*" matches "agent/fix-123"
        value.starts_with(prefix) && value.len() > prefix.len() + 1
    } else if let Some(prefix) = pattern.strip_suffix('*') {
        // e.g. "copilot-*" matches "copilot-fix-123"
        value.starts_with(prefix)
    } else {
        // Exact match
        pattern == value
    }
}

/// Generate the git wrapper script content.
///
/// Like the gh wrapper, this intercepts git invocations and blocks push operations.
pub fn generate_git_wrapper_script(
    real_git: &str,
    cplt_bin: &str,
    policy: &crate::config::GitGuardPolicy,
) -> String {
    let cplt_escaped = shell_escape(cplt_bin);
    let git_escaped = shell_escape(real_git);
    let mode_flag = match policy.mode {
        crate::config::EnforcementMode::Block => "--mode=block",
        crate::config::EnforcementMode::Warn => "--mode=warn",
        crate::config::EnforcementMode::Audit => "--mode=audit",
    };
    let prevent_push_flag = if policy.prevent_push {
        "--prevent-push=true"
    } else {
        "--prevent-push=false"
    };
    let prevent_force_push_flag = if policy.prevent_force_push {
        "--prevent-force-push=true"
    } else {
        "--prevent-force-push=false"
    };
    let protect_default_flag = if policy.protect_default_branch_only {
        "--protect-default-branch-only=true"
    } else {
        "--protect-default-branch-only=false"
    };
    let allow_push_flag = if policy.allow_push.is_empty() {
        String::new()
    } else {
        let json = serde_json::to_string(&policy.allow_push).unwrap_or_default();
        format!(" --allow-push-rules='{}'", json.replace('\'', "'\\''"))
    };
    format!(
        r#"#!/bin/sh
# cplt git proxy — blocks git push in sandboxed agents.
# This wrapper is auto-generated. Do not edit.

exec {cplt_escaped} git-gate --real-git {git_escaped} {mode_flag} {prevent_push_flag} {prevent_force_push_flag} {protect_default_flag}{allow_push_flag} -- "$@"
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
        assert_eq!(cmd.api_endpoint.as_deref(), Some("/repos/owner/repo/pulls"));
    }

    #[test]
    fn parse_api_post() {
        let cmd = parse_command(&["api", "-X", "POST", "/repos/owner/repo/issues"]).unwrap();
        assert_eq!(cmd.command, "api");
        assert_eq!(cmd.method.as_deref(), Some("POST"));
        assert_eq!(
            cmd.api_endpoint.as_deref(),
            Some("/repos/owner/repo/issues")
        );
    }

    #[test]
    fn parse_api_with_input_flags() {
        let cmd = parse_command(&["api", "/repos/o/r/issues", "-f", "title=bug"]).unwrap();
        assert_eq!(cmd.command, "api");
        assert!(cmd.has_input_flags);
        assert_eq!(cmd.api_endpoint.as_deref(), Some("/repos/o/r/issues"));
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
                api_endpoint: None,
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
                api_endpoint: None,
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
                api_endpoint: None,
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
            api_endpoint: None,
        };
        let result = evaluate(&parsed);
        assert_eq!(result.decision, Decision::Unknown);
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
            api_endpoint: None,
        };
        assert_eq!(evaluate(&parsed).decision, Decision::Allow);

        // codespace group blocks everything
        let parsed = ParsedCommand {
            command: "codespace".to_string(),
            subcommand: Some("create".to_string()),
            repo_flag: None,
            method: None,
            has_input_flags: false,
            api_endpoint: None,
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
            api_endpoint: None,
        };
        assert_eq!(evaluate(&parsed).decision, Decision::ScopeCheck);

        let parsed = ParsedCommand {
            command: "api".to_string(),
            subcommand: None,
            repo_flag: None,
            method: Some("GET".to_string()),
            has_input_flags: false,
            api_endpoint: None,
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
            api_endpoint: None,
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
            api_endpoint: None,
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
            api_endpoint: None,
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
            api_endpoint: None,
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
            api_endpoint: None,
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
            api_endpoint: None,
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
            api_endpoint: None,
        };
        assert!(is_repo_in_scope(&cmd, "navikt/cplt"));
    }

    // ── API endpoint scope tests ──

    #[test]
    fn api_endpoint_out_of_scope() {
        let cmd = ParsedCommand {
            command: "api".to_string(),
            subcommand: None,
            repo_flag: None,
            method: None,
            has_input_flags: false,
            api_endpoint: Some("/repos/other/repo/pulls".to_string()),
        };
        assert!(!is_repo_in_scope(&cmd, "navikt/cplt"));
    }

    #[test]
    fn api_endpoint_in_scope() {
        let cmd = ParsedCommand {
            command: "api".to_string(),
            subcommand: None,
            repo_flag: None,
            method: None,
            has_input_flags: false,
            api_endpoint: Some("/repos/navikt/cplt/pulls".to_string()),
        };
        assert!(is_repo_in_scope(&cmd, "navikt/cplt"));
    }

    #[test]
    fn api_endpoint_no_repos_prefix_out_of_scope() {
        // Endpoints like /user or /orgs/foo don't have repo context — blocked
        let cmd = ParsedCommand {
            command: "api".to_string(),
            subcommand: None,
            repo_flag: None,
            method: None,
            has_input_flags: false,
            api_endpoint: Some("/user".to_string()),
        };
        assert!(!is_repo_in_scope(&cmd, "navikt/cplt"));
    }

    #[test]
    fn api_endpoint_orgs_out_of_scope() {
        let cmd = ParsedCommand {
            command: "api".to_string(),
            subcommand: None,
            repo_flag: None,
            method: None,
            has_input_flags: false,
            api_endpoint: Some("/orgs/navikt/members".to_string()),
        };
        assert!(!is_repo_in_scope(&cmd, "navikt/cplt"));
    }

    #[test]
    fn api_relative_path_in_scope() {
        // Relative paths like `pulls/67/comments` are resolved by gh to current repo
        let cmd = ParsedCommand {
            command: "api".to_string(),
            subcommand: None,
            repo_flag: None,
            method: None,
            has_input_flags: false,
            api_endpoint: Some("pulls/67/comments".to_string()),
        };
        assert!(is_repo_in_scope(&cmd, "navikt/cplt"));
    }

    #[test]
    fn api_relative_path_with_query_string_in_scope() {
        let cmd = ParsedCommand {
            command: "api".to_string(),
            subcommand: None,
            repo_flag: None,
            method: None,
            has_input_flags: false,
            api_endpoint: Some("pulls?state=open".to_string()),
        };
        assert!(is_repo_in_scope(&cmd, "navikt/cplt"));
    }

    #[test]
    fn api_endpoint_repo_flag_takes_precedence() {
        // -R flag overrides endpoint path
        let cmd = ParsedCommand {
            command: "api".to_string(),
            subcommand: None,
            repo_flag: Some("other/repo".to_string()),
            method: None,
            has_input_flags: false,
            api_endpoint: Some("/repos/navikt/cplt/pulls".to_string()),
        };
        assert!(!is_repo_in_scope(&cmd, "navikt/cplt"));
    }

    #[test]
    fn extract_repo_from_api_path_basic() {
        assert_eq!(
            extract_repo_from_api_path("/repos/navikt/cplt/pulls"),
            Some("navikt/cplt".to_string())
        );
        assert_eq!(
            extract_repo_from_api_path("repos/navikt/cplt"),
            Some("navikt/cplt".to_string())
        );
        assert_eq!(extract_repo_from_api_path("/user"), None);
        assert_eq!(extract_repo_from_api_path("/repos"), None);
        assert_eq!(extract_repo_from_api_path("/repos/owner"), None);
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
        let policy = crate::config::GhGuardPolicy::default();
        let script = generate_wrapper_script("/usr/bin/gh", "/usr/local/bin/cplt", &policy);
        assert!(script.contains("/usr/bin/gh"));
        assert!(script.contains("/usr/local/bin/cplt"));
        assert!(script.starts_with("#!/bin/sh"));
        assert!(script.contains("--mode=block"));
        assert!(script.contains("--scope-check"));
        assert!(script.contains("--block-auth-token"));
        assert!(script.contains("--unknown-command=block"));
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
            api_endpoint: None,
        };
        assert_eq!(evaluate(&list).decision, Decision::Allow);

        let edit = ParsedCommand {
            command: "project".to_string(),
            subcommand: Some("edit".to_string()),
            repo_flag: None,
            method: None,
            has_input_flags: false,
            api_endpoint: None,
        };
        assert_eq!(evaluate(&edit).decision, Decision::Block);
    }

    // ── git gate tests ──

    #[test]
    fn git_push_is_blocked() {
        assert!(gate_git(&["push"], true, true, false, &[], None).is_err());
        assert!(gate_git(&["push", "origin", "main"], true, true, false, &[], None).is_err());
        assert!(gate_git(&["push", "--force"], true, true, false, &[], None).is_err());
        assert!(gate_git(&["-c", "user.name=x", "push"], true, true, false, &[], None).is_err());
    }

    #[test]
    fn git_request_pull_is_blocked() {
        assert!(
            gate_git(
                &["request-pull", "v1.0", "origin"],
                true,
                true,
                false,
                &[],
                None
            )
            .is_err()
        );
    }

    #[test]
    fn git_read_operations_allowed() {
        assert!(gate_git(&["status"], true, true, false, &[], None).is_ok());
        assert!(gate_git(&["log", "--oneline"], true, true, false, &[], None).is_ok());
        assert!(gate_git(&["diff", "HEAD~1"], true, true, false, &[], None).is_ok());
        assert!(gate_git(&["fetch", "origin"], true, true, false, &[], None).is_ok());
        assert!(gate_git(&["pull"], true, true, false, &[], None).is_ok());
        assert!(gate_git(&["branch", "-a"], true, true, false, &[], None).is_ok());
    }

    #[test]
    fn git_local_writes_allowed() {
        assert!(gate_git(&["commit", "-m", "fix"], true, true, false, &[], None).is_ok());
        assert!(gate_git(&["add", "."], true, true, false, &[], None).is_ok());
        assert!(gate_git(&["checkout", "-b", "feature"], true, true, false, &[], None).is_ok());
        assert!(gate_git(&["merge", "main"], true, true, false, &[], None).is_ok());
        assert!(gate_git(&["rebase", "main"], true, true, false, &[], None).is_ok());
        assert!(gate_git(&["stash"], true, true, false, &[], None).is_ok());
        assert!(gate_git(&["tag", "v1.0"], true, true, false, &[], None).is_ok());
    }

    #[test]
    fn git_no_subcommand_allowed() {
        assert!(gate_git(&["--version"], true, true, false, &[], None).is_ok());
        assert!(gate_git(&[], true, true, false, &[], None).is_ok());
    }

    #[test]
    fn git_unknown_subcommand_allowed() {
        // Unknown git commands default to allow (unlike gh which defaults to block)
        assert!(gate_git(&["some-custom-alias"], true, true, false, &[], None).is_ok());
    }

    #[test]
    fn git_push_allowed_when_prevention_disabled() {
        assert!(gate_git(&["push"], false, false, false, &[], None).is_ok());
        assert!(gate_git(&["push", "--force"], false, false, false, &[], None).is_ok());
        assert!(gate_git(&["send-pack", "origin"], false, false, false, &[], None).is_ok());
    }

    #[test]
    fn git_force_push_blocked_when_only_force_prevention() {
        // Regular push allowed, force push blocked
        assert!(gate_git(&["push", "origin", "main"], false, true, false, &[], None).is_ok());
        assert!(gate_git(&["push", "--force"], false, true, false, &[], None).is_err());
        assert!(
            gate_git(
                &["push", "--force-with-lease"],
                false,
                true,
                false,
                &[],
                None
            )
            .is_err()
        );
    }

    #[test]
    fn git_wrapper_script_contains_paths() {
        let policy = crate::config::GitGuardPolicy::default();
        let script = generate_git_wrapper_script("/usr/bin/git", "/usr/local/bin/cplt", &policy);
        assert!(script.contains("/usr/bin/git"));
        assert!(script.contains("/usr/local/bin/cplt"));
        assert!(script.contains("git-gate"));
        assert!(script.contains("--mode=block"));
    }

    #[test]
    fn shell_escape_handles_quotes() {
        let policy = crate::config::GhGuardPolicy::default();
        let script = generate_wrapper_script("/path/with'quote/gh", "/path/with\"dq/cplt", &policy);
        assert!(script.contains("gh-gate"));
        // Should use single-quote escaping, no unescaped double quotes in paths
        assert!(!script.contains(r#""/path/with'quote/gh""#));
    }

    #[test]
    fn parse_api_method_equals_form() {
        let cmd = parse_command(&["api", "--method=POST", "/repos/x/y/issues"]).unwrap();
        assert_eq!(cmd.method.as_deref(), Some("POST"));
    }

    #[test]
    fn parse_api_short_method_attached() {
        let cmd = parse_command(&["api", "-XDELETE", "/repos/x/y/issues/1"]).unwrap();
        assert_eq!(cmd.method.as_deref(), Some("DELETE"));
    }

    #[test]
    fn parse_api_field_long_form() {
        let cmd = parse_command(&["api", "/repos/x/y/issues", "--field", "title=t"]).unwrap();
        assert!(cmd.has_input_flags);
    }

    #[test]
    fn parse_api_raw_field_long_form() {
        let cmd = parse_command(&["api", "/repos/x/y/issues", "--raw-field", "body=b"]).unwrap();
        assert!(cmd.has_input_flags);
    }

    #[test]
    fn parse_repo_equals_form() {
        let cmd = parse_command(&["pr", "list", "--repo=navikt/cplt"]).unwrap();
        assert_eq!(cmd.repo_flag.as_deref(), Some("navikt/cplt"));
    }

    #[test]
    fn parse_global_repo_before_command() {
        let cmd = parse_command(&["--repo", "navikt/cplt", "pr", "list"]).unwrap();
        assert_eq!(cmd.repo_flag.as_deref(), Some("navikt/cplt"));
        assert_eq!(cmd.command, "pr");
    }

    #[test]
    fn parse_hostname_flag_skipped() {
        // --hostname takes a value, shouldn't confuse the parser
        let cmd = parse_command(&["--hostname", "github.example.com", "pr", "list"]).unwrap();
        assert_eq!(cmd.command, "pr");
        assert_eq!(cmd.subcommand.as_deref(), Some("list"));
    }

    #[test]
    fn git_gate_blocks_send_pack() {
        let result = gate_git(
            &["send-pack", "origin", "main"],
            true,
            true,
            false,
            &[],
            None,
        );
        assert!(result.is_err());
    }

    // ── protect_default_branch_only tests ──

    #[test]
    fn protect_default_allows_feature_branch() {
        assert!(
            gate_git(
                &["push", "origin", "feature/x"],
                true,
                true,
                true,
                &[],
                None
            )
            .is_ok()
        );
        assert!(
            gate_git(
                &["push", "origin", "copilot/fix"],
                true,
                true,
                true,
                &[],
                None
            )
            .is_ok()
        );
        assert!(gate_git(&["push", "origin", "dev"], true, true, true, &[], None).is_ok());
    }

    #[test]
    fn protect_default_blocks_main() {
        assert!(gate_git(&["push", "origin", "main"], true, true, true, &[], None).is_err());
        assert!(gate_git(&["push", "origin", "master"], true, true, true, &[], None).is_err());
    }

    #[test]
    fn protect_default_blocks_refspec_to_main() {
        assert!(
            gate_git(
                &["push", "origin", "HEAD:refs/heads/main"],
                true,
                true,
                true,
                &[],
                None
            )
            .is_err()
        );
        assert!(
            gate_git(
                &["push", "origin", "abc123:refs/heads/master"],
                true,
                true,
                true,
                &[],
                None
            )
            .is_err()
        );
    }

    #[test]
    fn protect_default_allows_refspec_to_feature() {
        assert!(
            gate_git(
                &["push", "origin", "HEAD:refs/heads/feature/x"],
                true,
                true,
                true,
                &[],
                None
            )
            .is_ok()
        );
    }

    #[test]
    fn protect_default_blocks_bare_push_without_git() {
        // When real_git is None (can't resolve branch), fail closed for safety
        assert!(gate_git(&["push"], true, true, true, &[], None).is_err());
        assert!(gate_git(&["push", "origin"], true, true, true, &[], None).is_err());
    }

    #[test]
    fn is_default_branch_recognizes_main_master() {
        assert!(is_default_branch("main"));
        assert!(is_default_branch("master"));
        assert!(is_default_branch("origin/main"));
        assert!(is_default_branch("origin/master"));
        assert!(!is_default_branch("feature/main-fix"));
        assert!(!is_default_branch("develop"));
        assert!(!is_default_branch("copilot/fix"));
    }

    #[test]
    fn extract_push_target_handles_refspecs() {
        assert_eq!(
            extract_push_target_branch(&["origin", "feature"]),
            Some("feature")
        );
        assert_eq!(
            extract_push_target_branch(&["origin", "HEAD:refs/heads/main"]),
            Some("main")
        );
        assert_eq!(extract_push_target_branch(&["origin"]), None);
        assert_eq!(extract_push_target_branch(&[]), None);
    }

    #[test]
    fn glob_match_patterns() {
        assert!(glob_match("agent/*", "agent/fix-123"));
        assert!(glob_match("copilot-*", "copilot-fix-123"));
        assert!(glob_match("*", "anything"));
        assert!(glob_match("**", "any/nested/path"));
        assert!(glob_match("feature", "feature"));
        assert!(!glob_match("agent/*", "other/fix"));
        assert!(!glob_match("feature", "feature2"));
    }

    #[test]
    fn allow_push_rule_matches() {
        use crate::config::ResolvedPushRule;

        let rules = vec![ResolvedPushRule {
            remote: Some("fork".to_string()),
            branches: vec!["agent/*".to_string()],
            force: false,
        }];

        // Matches: correct remote + matching branch
        assert!(matches_allow_push_rule(
            &rules,
            Some("fork"),
            Some("agent/fix-123"),
            false
        ));
        // Doesn't match: wrong remote
        assert!(!matches_allow_push_rule(
            &rules,
            Some("origin"),
            Some("agent/fix-123"),
            false
        ));
        // Doesn't match: wrong branch
        assert!(!matches_allow_push_rule(
            &rules,
            Some("fork"),
            Some("main"),
            false
        ));
        // Doesn't match: force push not allowed
        assert!(!matches_allow_push_rule(
            &rules,
            Some("fork"),
            Some("agent/fix"),
            true
        ));

        // Rule with force=true
        let rules_force = vec![ResolvedPushRule {
            remote: None,
            branches: vec!["agent/*".to_string()],
            force: true,
        }];
        assert!(matches_allow_push_rule(
            &rules_force,
            Some("origin"),
            Some("agent/x"),
            true
        ));
        assert!(matches_allow_push_rule(
            &rules_force,
            Some("origin"),
            Some("agent/x"),
            false
        ));
    }

    #[test]
    fn allow_push_rule_in_gate_git() {
        use crate::config::ResolvedPushRule;

        let rules = vec![ResolvedPushRule {
            remote: Some("fork".to_string()),
            branches: vec!["agent/*".to_string()],
            force: false,
        }];

        // Push to fork agent/fix should be allowed despite prevent_push=true
        assert!(
            gate_git(
                &["push", "fork", "agent/fix-123"],
                true,
                true,
                false,
                &rules,
                None
            )
            .is_ok()
        );

        // Push to origin agent/fix should still be blocked (wrong remote)
        assert!(
            gate_git(
                &["push", "origin", "agent/fix-123"],
                true,
                true,
                false,
                &rules,
                None
            )
            .is_err()
        );
    }
}
