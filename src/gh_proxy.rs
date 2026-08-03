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
        // `-R=owner/repo` (attached-equals form) — strip the leading '=' so the
        // value is captured. Without this the flag is silently dropped by the
        // generic `arg.contains('=')` skip below and treated as current-repo.
        if let Some(val) = arg.strip_prefix("-R=") {
            global_repo_flag = Some(val.to_string());
            idx += 1;
            continue;
        }
        if arg.starts_with("-R") && arg.len() > 2 {
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
                // -XPOST or -X=POST form (short flag with attached value).
                // Strip an optional leading '=' so `-X=DELETE` is not read as the
                // bogus method "=DELETE" (which would bypass the DELETE block).
                let val = arg[2..].strip_prefix('=').unwrap_or(&arg[2..]);
                method = Some(val.to_uppercase());
            } else if let Some(val) = arg.strip_prefix("--repo=") {
                repo_flag = Some(val.to_string());
            } else if arg.starts_with("-R") && arg.len() > 2 {
                // Handle both `-Rowner/repo` and `-R=owner/repo`.
                let val = arg[2..].strip_prefix('=').unwrap_or(&arg[2..]);
                repo_flag = Some(val.to_string());
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
    evaluate_with_policy(cmd, false)
}

/// Look up the policy decision for a parsed command, respecting policy flags.
pub fn evaluate_with_policy(cmd: &ParsedCommand, allow_api_write: bool) -> PolicyResult {
    // Special handling for `gh api`
    if cmd.command == "api" {
        return evaluate_api(cmd, allow_api_write);
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
/// flags that imply a write) is blocked by default. When `allow_api_write`
/// is true, writes are scope-checked instead of blocked. GraphQL is always
/// blocked regardless (arbitrary mutations can't be statically scope-checked).
fn evaluate_api(cmd: &ParsedCommand, allow_api_write: bool) -> PolicyResult {
    // Block GraphQL endpoint — it allows arbitrary mutations via stdin/body
    // that cannot be statically analyzed for scope or intent.
    // Normalize: strip trailing slashes and query params before matching.
    if let Some(ref endpoint) = cmd.api_endpoint {
        let normalized = endpoint
            .trim_end_matches('/')
            .split('?')
            .next()
            .unwrap_or(endpoint);
        // Extract the path component so a fully-qualified URL
        // (`https://api.github.com/graphql`) is caught too, not just the
        // relative `graphql` / `/graphql` forms.
        let path = normalized
            .split_once("://")
            .and_then(|(_, rest)| rest.split_once('/'))
            .map_or(normalized, |(_, p)| p);
        if path.trim_start_matches('/') == "graphql" {
            return PolicyResult {
                decision: Decision::Block,
                reason: "gh api graphql allows arbitrary mutations — use specific REST endpoints instead",
            };
        }
    }

    // Evaluate the HTTP method BEFORE the input-flags shortcut. DELETE is always
    // destructive, so `gh api -X DELETE /repos/o/r/x -f k=v` must hit this block
    // rather than being reclassified as a scope-checkable write just because it
    // also carries input fields.
    if matches!(cmd.method.as_deref(), Some("DELETE")) {
        return PolicyResult {
            decision: Decision::Block,
            reason: "gh api DELETE is destructive — not permitted even with allow_api_write",
        };
    }

    // If input flags are present, it's implicitly a write
    if cmd.has_input_flags {
        return if allow_api_write {
            PolicyResult {
                decision: Decision::ScopeCheck,
                reason: "gh api write (input flags) — scope-checked (allow_api_write=true)",
            }
        } else {
            PolicyResult {
                decision: Decision::Block,
                reason: "gh api with input flags implies write operation",
            }
        };
    }

    match cmd.method.as_deref() {
        None | Some("GET") => PolicyResult {
            decision: Decision::ScopeCheck,
            reason: "gh api GET — scope-checked",
        },
        // DELETE handled above (before the input-flags shortcut).
        Some(_) => {
            if allow_api_write {
                PolicyResult {
                    decision: Decision::ScopeCheck,
                    reason: "gh api write method — scope-checked (allow_api_write=true)",
                }
            } else {
                PolicyResult {
                    decision: Decision::Block,
                    reason: "gh api with non-GET method",
                }
            }
        }
    }
}

/// Check if a repo flag targets the expected repository.
///
/// `current_repo` should be in "owner/name" format.
/// Returns true if the command targets the current repo (or has no -R flag).
/// For `gh api` commands, also checks the endpoint URL path for /repos/{owner}/{repo}/.
/// Non-repo API endpoints (orgs, users) are NOT implicitly allowed — they require
/// explicit -R or a matching /repos/ path.
///
/// Security: write operations (`has_input_flags` or non-GET method) never use the
/// relative-path fallback — they require an explicit /repos/{owner}/{repo}/... match.
/// This prevents scope-check bypass via top-level endpoints (e.g. `gists`, `app/...`)
/// that don't start with a deny-listed prefix.
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
            let Ok(endpoint) = github_api_endpoint_path(endpoint) else {
                return false;
            };
            if let Some(endpoint_repo) = extract_repo_from_api_path(endpoint) {
                let current_clean = current_repo.to_lowercase();
                return endpoint_repo.to_lowercase() == current_clean;
            }
            // Write operations (input flags or non-GET method) require an explicit
            // /repos/{owner}/{repo}/... path — no relative-path fallback.
            // This prevents top-level API endpoints (gists, app/installations, teams, etc.)
            // from being treated as in-scope just because they don't match a deny-list.
            let is_write =
                cmd.has_input_flags || matches!(cmd.method.as_deref(), Some(m) if m != "GET");
            if is_write {
                return false;
            }
            // For reads: check if this looks like a relative path (no leading absolute prefix)
            // that gh CLI resolves to the current repo (e.g., `gh api pulls/67/comments`).
            let path = endpoint.strip_prefix('/').unwrap_or(endpoint);
            let path = path.split('?').next().unwrap_or(path);
            if !path.starts_with("repos/")
                && !path.starts_with("orgs/")
                && !path.starts_with("users/")
                && !path.starts_with("user")
                && !path.starts_with("notifications")
                && !path.starts_with("graphql")
            {
                // Relative read endpoint — gh CLI resolves to current repo. Allow.
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

    // Must start with "repos" and have at least owner + repo.
    // Reject "." / ".." segments — they are not valid owner/repo names and could
    // otherwise be used to craft a path that string-matches the current repo
    // while resolving elsewhere.
    let is_dot = |s: &str| s == "." || s == "..";
    if parts.len() >= 3
        && parts[0] == "repos"
        && !parts[1].is_empty()
        && !parts[2].is_empty()
        && !is_dot(parts[1])
        && !is_dot(parts[2])
    {
        Some(format!("{}/{}", parts[1], parts[2]))
    } else {
        None
    }
}

/// Detect the repository rooted at the supplied project directory.
///
/// Reads `remote.origin.url` from local repository config only and parses the
/// owner/repo from it. Global/system config, includes, and inherited `GIT_*`
/// variables are ignored because they could retarget the guard's scope.
pub fn detect_current_repo(real_git: &Path, project_dir: &Path) -> Result<String, String> {
    let mut command = std::process::Command::new(real_git);
    for (key, _) in std::env::vars_os() {
        if key.to_string_lossy().starts_with("GIT_") {
            command.env_remove(key);
        }
    }

    let output = command
        .args([
            "config",
            "--local",
            "--no-includes",
            "--get",
            "remote.origin.url",
        ])
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .current_dir(project_dir)
        .output()
        .map_err(|e| format!("failed to run trusted git binary: {e}"))?;

    if !output.status.success() {
        return Err(format!(
            "trusted git could not read the local origin ({})",
            output.status
        ));
    }

    let url = String::from_utf8_lossy(&output.stdout);
    parse_repo_from_url(url.trim())
        .ok_or_else(|| "local origin is not a supported GitHub repository URL".to_string())
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
    let path = url
        .strip_prefix("https://github.com/")
        .or_else(|| {
            // HTTPS with embedded credentials:
            //   https://x-access-token:TOKEN@github.com/owner/repo.git
            // Anchor the host check to the URL *authority* (the segment before the
            // first '/'), so a crafted path such as
            //   https://evil.example/@github.com/owner/repo.git
            // is NOT mis-parsed as a GitHub URL.
            let after_scheme = url.strip_prefix("https://")?;
            let (authority, rest) = match after_scheme.split_once('/') {
                Some((a, r)) => (a, r),
                None => (after_scheme, ""),
            };
            // Strip any userinfo (user:token@) and an optional :port.
            let host = authority
                .rsplit('@')
                .next()
                .unwrap_or(authority)
                .split(':')
                .next()
                .unwrap_or(authority);
            (host == "github.com").then_some(rest)
        })
        .or_else(|| url.strip_prefix("ssh://git@github.com/"))
        .or_else(|| url.strip_prefix("http://github.com/"))?;

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
/// `repo_scope` is the repository verified before the sandboxed agent starts.
/// `cplt_bin` is the path to the cplt binary (for calling `gh-gate`).
/// Policy flags are baked into the wrapper invocation so the gate doesn't
/// re-read config at runtime (security: agent could edit config files).
pub fn generate_wrapper_script(
    real_gh: &str,
    repo_scope: Option<&str>,
    cplt_bin: &str,
    policy: &crate::config::GhGuardPolicy,
) -> String {
    let cplt_escaped = shell_escape(cplt_bin);
    let gh_escaped = shell_escape(real_gh);
    let repo_scope_flag = repo_scope
        .map(|repo| format!("--repo-scope {}", shell_escape(repo)))
        .unwrap_or_default();
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
    let api_write_flag = if policy.allow_api_write {
        "--allow-api-write"
    } else {
        "--no-allow-api-write"
    };
    format!(
        r#"#!/bin/sh
# cplt gh proxy — blocks destructive gh operations in sandboxed agents.
# This wrapper is auto-generated. Do not edit.

exec {cplt_escaped} gh-gate --real-gh {gh_escaped} {repo_scope_flag} {mode_flag} {scope_flag} {auth_flag} {unknown_flag} {api_write_flag} -- "$@"
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
    /// Block `gh auth token` from printing the raw token to any caller, serving
    /// it once from a 0600 scratch file that is deleted after the first read.
    ///
    /// Best-effort, not a same-UID boundary (Finding 3): it keeps the token out
    /// of the process environment and off `gh auth token`'s stdout for later
    /// callers, but the cache file lives in the agent's own `TMPDIR`, so a
    /// determined same-UID agent can still read it before the legitimate
    /// consumer. See `cache_gh_token_to_file`.
    pub block_auth_token: bool,
    /// Policy for commands not in the classification table.
    pub unknown_command: UnknownCommandDecision,
    /// Allow `gh api` write operations (POST/PATCH/PUT and input flags),
    /// scope-checked to the current repo. GraphQL remains blocked.
    pub allow_api_write: bool,
}

/// What to do with commands not in the policy table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnknownCommandDecision {
    Block,
    Allow,
}

/// Information established by the guard and required when invoking `gh`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct GateApproval {
    /// Host-qualified repository verified for a scope-checked command.
    ///
    /// The caller must set `GH_REPO` to this value before executing `gh`, pinning
    /// the operation to the same repository the guard approved.
    pub repo_scope: Option<String>,
}

impl Default for GatePolicy {
    fn default() -> Self {
        Self {
            mode: crate::config::EnforcementMode::Block,
            scope_check: true,
            block_auth_token: true,
            unknown_command: UnknownCommandDecision::Block,
            allow_api_write: false,
        }
    }
}

/// True if a `gh auth status` argument requests that the token be printed.
///
/// A naive exact match on `--show-token`/`-t` misses the equivalent spellings
/// that gh (cobra/pflag) accepts, every one of which leaks the OAuth token:
///   • `--show-token`       — canonical long form
///   • `--show-token=true`  — long form with an attached boolean value
///   • `-t`                 — short form
///   • `-at` / `-ta`        — bundled single-dash boolean cluster (auth status
///                            also accepts `-a`/`--active`, so shorthands combine)
///
/// A single-dash cluster containing `t` reveals the token; a `--`-prefixed long
/// flag (e.g. `--tags`) is NOT a cluster and must never be treated as one, or the
/// guard would misfire on unrelated flags. This check must stay conservative
/// (fail closed): any credible spelling of the token flag has to be caught here
/// because the POLICY table classifies `auth status` as a read-only Allow.
fn arg_reveals_token(arg: &str) -> bool {
    if arg == "--show-token" || arg.starts_with("--show-token=") {
        return true;
    }
    // Single-dash short cluster (`-t`, `-at`, `-ta`, …) — explicitly NOT a
    // `--long` flag, so `--tags` and friends are excluded.
    if arg.starts_with('-') && !arg.starts_with("--") && arg.len() > 1 {
        return arg[1..].contains('t');
    }
    false
}

/// Evaluate a full command and return a human-friendly verdict.
///
/// This is the entry point used by the `gh-gate` subcommand.
/// Returns the verified repository scope when allowed, or an error when blocked.
pub fn gate(
    args: &[&str],
    project_dir: &Path,
    policy: &GatePolicy,
) -> Result<GateApproval, String> {
    gate_with_git(args, project_dir, policy, Path::new("git"))
}

/// Evaluate a `gh` command using a pre-resolved Git binary for repository scope.
///
/// The Git subprocess ignores global/system configuration, local includes, and
/// inherited `GIT_*` variables so agent-controlled process state cannot retarget
/// the repository used by the scope decision.
pub fn gate_with_git(
    args: &[&str],
    project_dir: &Path,
    policy: &GatePolicy,
    real_git: &Path,
) -> Result<GateApproval, String> {
    gate_with_scope_resolver(args, policy, || detect_current_repo(real_git, project_dir))
}

/// Evaluate a `gh` command using repository scope captured before agent startup.
pub fn gate_with_repo_scope(
    args: &[&str],
    policy: &GatePolicy,
    repo_scope: Option<&str>,
) -> Result<GateApproval, String> {
    gate_with_scope_resolver(args, policy, || {
        repo_scope
            .map(str::to_owned)
            .ok_or_else(|| "repository scope was unavailable at sandbox startup".to_string())
    })
}

fn gate_with_scope_resolver(
    args: &[&str],
    policy: &GatePolicy,
    resolve_scope: impl FnOnce() -> Result<String, String>,
) -> Result<GateApproval, String> {
    let Some(cmd) = parse_command(args) else {
        // No command parsed — this happens for `gh --help`, `gh --version`, `gh help`, etc.
        // These are read-only informational invocations — always allow.
        return Ok(GateApproval::default());
    };

    // Handle token-revealing `gh auth` commands (credential exfiltration prevention).
    //
    // Two paths print the raw OAuth token:
    //   • `gh auth token`             — dedicated token printer
    //   • `gh auth status --show-token` / `-t` — prints the token alongside status
    // The POLICY table classifies `auth status` as a read-only Allow, so every
    // spelling of the token flag (`--show-token`, `--show-token=true`, `-t`, and
    // bundled `-at`/`-ta` clusters — see `arg_reveals_token`) must be caught here
    // or it leaks the token with the default config. Plain `gh auth status` (no
    // token flag) stays allowed.
    let reveals_token_via_status = cmd.command == "auth"
        && cmd.subcommand.as_deref() == Some("status")
        && args.iter().any(|a| arg_reveals_token(a));
    if policy.block_auth_token
        && cmd.command == "auth"
        && (cmd.subcommand.as_deref() == Some("token") || reveals_token_via_status)
    {
        return Err(
            "⚠️ BLOCKED by sandbox: revealing the GitHub token is not allowed in this environment.\n\
             Reason: token exfiltration prevention — use GH_TOKEN env var instead.\n\
             This operation is restricted by the cplt sandbox to prevent credential leaks.\n\
             Please make a note of this for the human operator and continue with your remaining work."
                .to_string(),
        );
    }

    let result = evaluate_with_policy(&cmd, policy.allow_api_write);

    if policy.scope_check {
        if cmd.command == "api"
            && let Some(endpoint) = cmd.api_endpoint.as_deref()
            && github_api_endpoint_path(endpoint).is_err()
        {
            return Err(
                "⚠️ BLOCKED by sandbox: 'gh api' targets an endpoint outside \
                 'https://api.github.com'.\n\
                 This operation is restricted by the cplt sandbox environment.\n\
                 Please make a note of this for the human operator and continue with your remaining work."
                    .to_string(),
            );
        }

        if let Some(hostname) = requested_hostname(args)
            && hostname != "github.com"
        {
            return Err(format!(
                "⚠️ BLOCKED by sandbox: 'gh {} {}' targets GitHub host '{hostname}', \
                 outside the approved host 'github.com'.\n\
                 This operation is restricted by the cplt sandbox environment.\n\
                 Please make a note of this for the human operator and continue with your remaining work.",
                cmd.command,
                cmd.subcommand.as_deref().unwrap_or("")
            ));
        }
    }

    match result.decision {
        Decision::Allow => Ok(if policy.scope_check {
            approval_from_scope(resolve_scope().ok())
        } else {
            GateApproval::default()
        }),
        Decision::ScopeCheck => {
            if !policy.scope_check {
                return Ok(GateApproval::default());
            }

            let current_repo = resolve_scope().map_err(|reason| {
                format!(
                    "⚠️ BLOCKED by sandbox: 'gh {} {}' cannot verify target repository scope.\n\
                     Reason: {reason}.\n\
                     This operation is restricted by the cplt sandbox environment.\n\
                     Please make a note of this for the human operator and continue with your remaining work.",
                    cmd.command,
                    cmd.subcommand.as_deref().unwrap_or("")
                )
            })?;

            if is_repo_in_scope(&cmd, &current_repo) {
                Ok(GateApproval {
                    repo_scope: Some(format!("github.com/{current_repo}")),
                })
            } else {
                Err(format!(
                    "⚠️ BLOCKED by sandbox: 'gh {}{}' targets '{}' which is outside the current repo '{}'.\n\
                     Reason: {}\n\
                     This operation is restricted by the cplt sandbox environment.\n\
                    Please make a note of this for the human operator and continue with your remaining work.",
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
             Please make a note of this for the human operator and continue with your remaining work.",
            cmd.command,
            cmd.subcommand
                .as_deref()
                .map(|s| format!(" {s}"))
                .unwrap_or_default(),
            result.reason,
        )),
        Decision::Unknown => match policy.unknown_command {
            UnknownCommandDecision::Allow => Ok(if policy.scope_check {
                approval_from_scope(resolve_scope().ok())
            } else {
                GateApproval::default()
            }),
            UnknownCommandDecision::Block => Err(format!(
                "⚠️ BLOCKED by sandbox: 'gh {}{}' is not recognized by the policy table.\n\
                     This command may have been added in a newer gh CLI version.\n\
                     This operation is restricted by the cplt sandbox (default-deny for unknown commands).\n\
                     Please make a note of this for the human operator and continue with your remaining work.",
                cmd.command,
                cmd.subcommand
                    .as_deref()
                    .map(|s| format!(" {s}"))
                    .unwrap_or_default(),
            )),
        },
    }
}

fn approval_from_scope(repo_scope: Option<String>) -> GateApproval {
    GateApproval {
        repo_scope: repo_scope.map(|repo| format!("github.com/{repo}")),
    }
}

fn requested_hostname<'a>(args: &'a [&str]) -> Option<&'a str> {
    for (index, arg) in args.iter().enumerate() {
        if let Some(hostname) = arg.strip_prefix("--hostname=") {
            return Some(hostname);
        }
        if *arg == "--hostname" {
            return args.get(index + 1).copied().or(Some(""));
        }
    }
    None
}

fn github_api_endpoint_path(endpoint: &str) -> Result<&str, ()> {
    if endpoint.contains("://") {
        endpoint.strip_prefix("https://api.github.com/").ok_or(())
    } else {
        Ok(endpoint)
    }
}

// ── Git push prevention ───────────────────────────────────────────────

/// Git subcommands that perform remote writes.
/// Blocked by the git wrapper to prevent agents from pushing code.
///
/// `subtree` is NOT here: only `git subtree push` is a remote write — the
/// `add`/`pull`/`split`/`merge` subcommands are local operations. It is handled
/// as a special case in `gate_git` so the local forms stay allowed.
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
    // subtree: local forms (add/pull/split/merge) allowed; `subtree push` is
    // blocked as a special case in gate_git.
    "subtree",
];

/// `git push` flags that consume a following space-separated value.
///
/// NOTE: `--force-with-lease` and `--signed` are intentionally absent. They only
/// accept an `=`-attached value (`--force-with-lease=ref`, `--signed=true`) — never
/// a space-separated argument. Listing them here would wrongly swallow the next
/// positional (the remote/refspec), both false-blocking legitimate pushes and
/// corrupting branch detection. This single list is shared by all push parsers so
/// the rule can't drift between copies.
const PUSH_FLAGS_WITH_VALUE: &[&str] =
    &["--repo", "--receive-pack", "--exec", "-o", "--push-option"];

/// True if `arg` is a force-push *flag* (`--force`, `-f`, or a `--force-with-lease`/
/// `--force-if-includes` variant, which may carry an `=`-attached value).
fn is_force_push_flag(arg: &str) -> bool {
    arg == "--force"
        || arg == "-f"
        || arg.starts_with("--force-with-lease")
        || arg.starts_with("--force-if-includes")
}

/// Collect the positional arguments (remote, refspecs) from `git push` args,
/// skipping flags and any values they consume. Shared so remote/branch/force
/// parsing all see the same positional set.
fn push_positionals<'a>(push_args: &[&'a str]) -> Vec<&'a str> {
    let mut positionals: Vec<&str> = Vec::new();
    let mut i = 0;
    while i < push_args.len() {
        let arg = push_args[i];
        if arg == "--" {
            // Everything after `--` is positional.
            positionals.extend_from_slice(&push_args[i + 1..]);
            break;
        }
        if arg.starts_with('-') {
            if !arg.contains('=') && PUSH_FLAGS_WITH_VALUE.contains(&arg) {
                i += 2; // skip flag and its value
            } else {
                i += 1; // boolean flag or `--flag=value`
            }
            continue;
        }
        positionals.push(arg);
        i += 1;
    }
    positionals
}

/// Whether a `git push` invocation performs a force update.
///
/// Recognizes both explicit force flags AND the `+`-prefixed refspec shorthand
/// (`git push origin +main`, `+feature:feature`), which forces the update with no
/// flag at all. The refspec form is checked only against positionals so a `+` in a
/// flag value can't produce a false positive.
fn push_is_force(push_args: &[&str]) -> bool {
    if push_args.iter().any(|a| is_force_push_flag(a)) {
        return true;
    }
    push_positionals(push_args)
        .iter()
        .any(|a| a.starts_with('+'))
}

/// Resolve the destination branch a refspec targets.
///
/// Strips a leading `+` (force marker) and, for `src:dst` refspecs, returns the
/// `dst` half with any `refs/heads/` or `refs/for/` prefix removed. For a plain
/// branch token, returns it unchanged (minus the `+`). This ensures a `+`-forced
/// refspec such as `+main` or `+HEAD:refs/heads/main` is still recognized as
/// targeting the default branch.
fn refspec_target_branch(refspec: &str) -> &str {
    let refspec = refspec.strip_prefix('+').unwrap_or(refspec);
    if let Some((_src, dst)) = refspec.split_once(':') {
        dst.strip_prefix("refs/heads/")
            .or_else(|| dst.strip_prefix("refs/for/"))
            .unwrap_or(dst)
    } else {
        refspec
    }
}

/// The remote whose URL defines the enforced repository scope.
///
/// The gh-guard reads `git remote get-url origin` at gate time, so only mutations
/// that create or retarget `origin` can bypass scope — management of other remotes
/// (upstream, fork, …) is harmless and must stay allowed.
const SCOPE_REMOTE: &str = "origin";

/// `git remote add` flags that consume a following value (so the value is not
/// mistaken for the remote name when locating the positional arguments).
const REMOTE_ADD_VALUE_FLAGS: &[&str] = &["-t", "-m"];

/// True if a `git remote <verb> …` invocation creates or retargets `origin`'s URL.
///
/// Only the verbs that can point `origin` at a new URL threaten scope integrity:
///   • `set-url origin …` — rewrites origin's URL in place.
///   • `add origin …`     — (re)creates origin pointing at the given URL.
///   • `rename <x> origin` — promotes another remote to become `origin`.
/// Non-origin forms (`add upstream`, `rename a b`, `set-url upstream`), plus
/// `remove`/`rm` and read-only verbs, are left alone.
fn remote_verb_retargets_origin(verb: &str, verb_args: &[&str]) -> bool {
    let value_flags: &[&str] = if verb == "add" {
        REMOTE_ADD_VALUE_FLAGS
    } else {
        &[]
    };
    // Positional (non-flag) tokens, skipping flags and any values they consume.
    let mut positionals: Vec<&str> = Vec::new();
    let mut i = 0;
    while i < verb_args.len() {
        let a = verb_args[i];
        if a.starts_with('-') {
            if value_flags.contains(&a) {
                i += 2;
            } else {
                i += 1;
            }
            continue;
        }
        positionals.push(a);
        i += 1;
    }
    match verb {
        // `add`/`set-url`: the first positional is the remote name.
        "add" | "set-url" => positionals.first().copied() == Some(SCOPE_REMOTE),
        // `rename <old> <new>`: only promoting a remote *to* `origin` retargets scope.
        "rename" => positionals.get(1).copied() == Some(SCOPE_REMOTE),
        _ => false,
    }
}

/// Detect `git` invocations that would change which repository the `origin` remote
/// points at.
///
/// The gh-guard derives the enforced repository scope by reading
/// `git remote get-url origin` at gate time. If an agent can create or rewrite
/// `origin`'s URL (directly, or via git's URL-rewrite config), it can retarget
/// every "in-scope" operation to an arbitrary repository. So while the git guard
/// is active, mutating `origin`'s URL is blocked. Managing other remotes
/// (`git remote add upstream …`, `rename`, `remove`) and read-only inspection
/// (`git remote -v`, `git remote get-url origin`, `git config --get …`) are
/// unaffected — those cannot redirect the scope source.
fn is_remote_scope_mutation(sub: &str, sub_args: &[&str]) -> bool {
    match sub {
        "remote" => {
            // First non-flag token is the verb. No verb → list (read-only).
            let Some(verb_idx) = sub_args.iter().position(|a| !a.starts_with('-')) else {
                return false;
            };
            let verb = sub_args[verb_idx];
            if matches!(verb, "add" | "set-url" | "rename") {
                remote_verb_retargets_origin(verb, &sub_args[verb_idx + 1..])
            } else {
                false
            }
        }
        "config" => config_sets_remote_url(sub_args),
        _ => false,
    }
}

/// True if `git config` args write to a key that can redirect the enforced scope.
///
/// Two key families qualify, both of which persistently change where a github.com
/// URL resolves:
///   • `remote.origin.url` / `remote.origin.pushurl` — the scope is read from
///     `origin`, so retargeting its URL is a direct bypass. Non-origin remote
///     URLs (`remote.upstream.url`) are harmless and stay allowed.
///   • `url.<base>.insteadOf` / `url.<base>.pushInsteadOf` — git's URL-rewrite
///     rules silently redirect `fetch`/`pull`/`clone`/`push` transport for any
///     matching URL, an equivalent transport-remap (code-injection) vector.
///
/// Reads (`--get`, `--get-all`, `--get-regexp`, `--list`, and the bare
/// `git config <key>` form that just prints the value) are allowed; only a key
/// with a following value (a set) is treated as a scope mutation. Keys are matched
/// case-insensitively, as git config key names are case-insensitive.
fn config_sets_remote_url(sub_args: &[&str]) -> bool {
    const READ_FLAGS: &[&str] = &[
        "--get",
        "--get-all",
        "--get-regexp",
        "--get-urlmatch",
        "--list",
        "-l",
    ];
    if sub_args
        .iter()
        .any(|a| READ_FLAGS.contains(&a.to_lowercase().as_str()))
    {
        return false;
    }
    for (idx, arg) in sub_args.iter().enumerate() {
        let key = arg.to_lowercase();
        let redirects_scope = key == "remote.origin.url"
            || key == "remote.origin.pushurl"
            || (key.starts_with("url.")
                && (key.ends_with(".insteadof") || key.ends_with(".pushinsteadof")));
        if redirects_scope {
            // A non-flag token after the key is the value → this is a write.
            return sub_args.get(idx + 1).is_some_and(|v| !v.starts_with('-'));
        }
    }
    false
}

/// True if the invocation is `git subtree push` (the only remote-write subtree form).
fn is_subtree_push(sub_args: &[&str]) -> bool {
    sub_args.iter().find(|a| !a.starts_with('-')).copied() == Some("push")
}

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

    // Defense in depth: block `-c alias.*` arguments that could redefine subcommands.
    // Even though unknown subcommands are now denied, this prevents confusion if an
    // alias maps to an allowed subcommand name but actually runs something else.
    if prevent_push {
        let mut j = 0;
        while j < args.len() {
            if args[j] == "-c" {
                if let Some(val) = args.get(j + 1) {
                    let lower = val.to_lowercase();
                    if lower.starts_with("alias.") {
                        return Err("⚠️ BLOCKED by sandbox: 'git -c alias.*' is not allowed.\n\
                             Push prevention is active — git alias definitions via -c are blocked \
                             to prevent guard bypass."
                            .to_string());
                    }
                }
                j += 2;
            } else {
                j += 1;
            }
        }
    }

    let Some(sub) = subcommand else {
        // No subcommand (e.g., `git --version`) — allow
        return Ok(());
    };

    // Arguments belonging to the subcommand (everything after it).
    let sub_args = &args[i + 1..];

    // Scope integrity: block mutation of remote URLs while the guard is active.
    // The gh-guard reads `origin` to determine the enforced repo scope, so
    // rewriting a remote's URL would let an agent redirect in-scope operations
    // to another repository. `git remote`/`git config` are otherwise allowed
    // (read-only inspection), so this must be intercepted explicitly.
    if is_remote_scope_mutation(sub, sub_args) {
        return Err(format!(
            "⚠️ BLOCKED by sandbox: 'git {sub}' would change a remote's URL.\n\
             The gh-guard derives the enforced repository scope from the 'origin' remote;\n\
             rewriting it could redirect in-scope operations to another repository.\n\
             Read-only inspection (git remote -v, git config --get remote.origin.url) is still allowed.\n\
             Please make a note of this for the human operator and continue with your remaining work."
        ));
    }

    // `git subtree push` is a remote write — block it like a bare push while
    // leaving the local subtree forms (add/pull/split/merge) allowed.
    if prevent_push && sub == "subtree" && is_subtree_push(sub_args) {
        return Err(
            "⚠️ BLOCKED by sandbox: 'git subtree push' is not allowed in this environment.\n\
             Push prevention is enabled — 'subtree push' performs a remote write.\n\
             Local subtree operations (add/pull/split/merge) are still allowed.\n\
             Please make a note of this for the human operator and continue with your remaining work."
                .to_string(),
        );
    }

    if prevent_push && GIT_BLOCKED_SUBCOMMANDS.contains(&sub) {
        // When protect_default_branch_only is set, only block pushes targeting
        // the default branch (main/master). Feature branch pushes are allowed,
        // but force push is still checked independently.
        if protect_default_branch_only && sub == "push" {
            let push_args = &args[i + 1..];
            let target_branch = extract_push_target_branch(push_args);
            let is_feature_branch = if let Some(branch) = target_branch {
                !is_default_branch(branch)
            } else {
                // No explicit branch: `git push` pushes current branch.
                // Resolve via real git to determine if we're on a protected branch.
                let current_branch = real_git.and_then(resolve_current_branch);
                match current_branch {
                    Some(ref b) if !is_default_branch(b) => true,
                    Some(_) => false, // On default branch — fall through to block
                    None => false,    // Can't determine branch — fail closed for safety
                }
            };

            if is_feature_branch {
                // Feature branch push allowed, but still enforce force-push prevention
                if prevent_force_push {
                    let has_force = push_is_force(push_args);
                    if has_force {
                        return Err(
                            "⚠️ BLOCKED by sandbox: 'git push --force' is not allowed in this environment.\n\
                             Force push prevention is enabled — regular push to feature branches is allowed but force push is blocked.\n\
                             Please make a note of this for the human operator and continue with your remaining work."
                                .to_string(),
                        );
                    }
                }
                return Ok(());
            }
        }

        // Check allow_push exception rules before blocking
        if sub == "push" && !allow_push_rules.is_empty() {
            let push_args = &args[i + 1..];
            let has_force = push_is_force(push_args);
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
             Please make a note of this for the human operator and continue with your remaining work."
        ));
    }

    // If only force push prevention is active (prevent_push=false, prevent_force_push=true),
    // check for force push flags on push commands
    if !prevent_push && prevent_force_push && sub == "push" {
        let push_args = &args[i + 1..];
        let has_force = push_is_force(push_args);
        if has_force {
            return Err(
                "⚠️ BLOCKED by sandbox: 'git push --force' is not allowed in this environment.\n\
                 Force push prevention is enabled — regular push is allowed but force push is blocked.\n\
                 Please make a note of this for the human operator and continue with your remaining work."
                    .to_string(),
            );
        }
    }

    // If it's in the allow list, pass through
    if GIT_ALLOWED_SUBCOMMANDS.contains(&sub) {
        return Ok(());
    }

    // Unknown git subcommand — block when push prevention is active.
    // An agent can define aliases (via `git config` or `-c alias.x=push`) that resolve
    // to blocked subcommands. Since alias expansion happens inside the real git binary
    // (after the guard has already approved), unknown subcommands must be blocked
    // to prevent bypass via `git -c alias.p=push p origin main` or similar.
    if prevent_push {
        return Err(format!(
            "⚠️ BLOCKED by sandbox: 'git {sub}' is not a recognized subcommand.\n\
             Push prevention is active — only known git subcommands are allowed.\n\
             If this is a legitimate command, please ask the human operator to allow it."
        ));
    }

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
/// `origin +main` (force), or just `feature-branch`. Returns None if no explicit
/// branch target found (e.g. `git push origin`, where the current branch is pushed).
fn extract_push_target_branch<'a>(push_args: &[&'a str]) -> Option<&'a str> {
    let positionals = push_positionals(push_args);

    // `git push [remote] [refspec...]`
    // positionals[0] is usually the remote, positionals[1+] are refspecs
    match positionals.len() {
        0 => None, // `git push` — pushes current branch
        1 => {
            // Could be remote OR refspec. A colon (`HEAD:refs/heads/branch`) or a
            // leading `+` (forced refspec) means an explicit target; a bare word
            // is just a remote name with no branch specified.
            let arg = positionals[0];
            if arg.contains(':') || arg.starts_with('+') {
                Some(refspec_target_branch(arg))
            } else {
                None
            }
        }
        _ => {
            // positionals[0] = remote, positionals[1+] = refspecs
            // Check ALL refspecs — return first that is a default branch (most restrictive).
            // This prevents bypass via `git push origin feature main` where "main" is the
            // second refspec and would be missed if we only check the first.
            for refspec in &positionals[1..] {
                let branch = refspec_target_branch(refspec);
                if is_default_branch(branch) {
                    return Some(branch);
                }
            }
            // No default branch found — return first refspec for caller context.
            Some(refspec_target_branch(positionals[1]))
        }
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

    // Extract remote (first positional — the remote name).
    let remote = push_positionals(push_args).first().map(ToString::to_string);

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
    fn parse_https_url_with_embedded_token() {
        // GitHub Actions clones with https://x-access-token:TOKEN@github.com/owner/repo.git
        assert_eq!(
            parse_repo_from_url("https://x-access-token:ghs_abc123@github.com/navikt/cplt.git"),
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

    #[test]
    fn parse_https_url_spoofed_github_in_path_rejected() {
        // The host is evil.example, not github.com — the `@github.com/` substring
        // sits in the path and must NOT be treated as a GitHub URL.
        assert_eq!(
            parse_repo_from_url("https://evil.example/@github.com/navikt/cplt.git"),
            None
        );
        assert_eq!(
            parse_repo_from_url(
                "https://x-access-token:TOKEN@evil.example/@github.com/navikt/cplt.git"
            ),
            None
        );
    }

    // ── wrapper script test ──

    #[test]
    fn wrapper_script_contains_paths() {
        let policy = crate::config::GhGuardPolicy::default();
        let script = generate_wrapper_script(
            "/usr/bin/gh",
            Some("navikt/cplt"),
            "/usr/local/bin/cplt",
            &policy,
        );
        assert!(script.contains("/usr/bin/gh"));
        assert!(script.contains("--repo-scope 'navikt/cplt'"));
        assert!(script.contains("/usr/local/bin/cplt"));
        assert!(script.starts_with("#!/bin/sh"));
        assert!(script.contains("--mode=block"));
        assert!(script.contains("--scope-check"));
        assert!(script.contains("--block-auth-token"));
        assert!(script.contains("--unknown-command=block"));
        assert!(script.contains("--no-allow-api-write"));
    }

    #[test]
    fn wrapper_script_includes_allow_api_write_flag() {
        let policy = crate::config::GhGuardPolicy {
            allow_api_write: true,
            ..Default::default()
        };
        let script = generate_wrapper_script(
            "/usr/bin/gh",
            Some("navikt/cplt"),
            "/usr/local/bin/cplt",
            &policy,
        );
        assert!(
            script.contains("--allow-api-write"),
            "wrapper must bake in --allow-api-write when policy has allow_api_write=true"
        );
    }

    #[test]
    fn api_write_allowed_when_policy_set() {
        let cmd = ParsedCommand {
            command: "api".to_string(),
            subcommand: None,
            repo_flag: None,
            method: Some("POST".to_string()),
            has_input_flags: false,
            api_endpoint: Some("repos/navikt/cplt/pulls/comments/123/replies".to_string()),
        };
        // Default policy: write should be blocked
        assert_eq!(
            evaluate_with_policy(&cmd, false).decision,
            Decision::Block,
            "gh api POST must be blocked by default"
        );
        // With allow_api_write: write should be scope-checked
        assert_eq!(
            evaluate_with_policy(&cmd, true).decision,
            Decision::ScopeCheck,
            "gh api POST must be ScopeCheck when allow_api_write=true"
        );
    }

    #[test]
    fn api_write_with_input_flags_allowed_when_policy_set() {
        let cmd = ParsedCommand {
            command: "api".to_string(),
            subcommand: None,
            repo_flag: None,
            method: None,
            has_input_flags: true,
            api_endpoint: Some("repos/navikt/cplt/pulls/comments/123/replies".to_string()),
        };
        assert_eq!(
            evaluate_with_policy(&cmd, false).decision,
            Decision::Block,
            "gh api with input flags must be blocked by default"
        );
        assert_eq!(
            evaluate_with_policy(&cmd, true).decision,
            Decision::ScopeCheck,
            "gh api with input flags must be ScopeCheck when allow_api_write=true"
        );
    }

    #[test]
    fn graphql_blocked_even_with_allow_api_write() {
        let cmd = ParsedCommand {
            command: "api".to_string(),
            subcommand: None,
            repo_flag: None,
            method: Some("POST".to_string()),
            has_input_flags: false,
            api_endpoint: Some("graphql".to_string()),
        };
        assert_eq!(
            evaluate_with_policy(&cmd, true).decision,
            Decision::Block,
            "GraphQL must be blocked even when allow_api_write=true"
        );
    }

    #[test]
    fn api_delete_blocked_even_with_allow_api_write() {
        let cmd = ParsedCommand {
            command: "api".to_string(),
            subcommand: None,
            repo_flag: None,
            method: Some("DELETE".to_string()),
            has_input_flags: false,
            api_endpoint: Some("repos/navikt/cplt/issues/1/labels/bug".to_string()),
        };
        assert_eq!(
            evaluate_with_policy(&cmd, true).decision,
            Decision::Block,
            "DELETE must be blocked even when allow_api_write=true"
        );
    }

    #[test]
    fn api_write_to_top_level_endpoint_not_in_scope() {
        // gists, app/installations, projects, notifications — top-level endpoints that are
        // NOT repo-relative. is_repo_in_scope must reject them for write operations,
        // preventing the relative-path fallback from granting access to the full GitHub API.
        for endpoint in &[
            "gists",
            "app/installations/123/access_tokens",
            "projects/456",
            "notifications/threads/789/subscription",
        ] {
            let cmd = ParsedCommand {
                command: "api".to_string(),
                subcommand: None,
                repo_flag: None,
                method: Some("POST".to_string()),
                has_input_flags: true,
                api_endpoint: Some(endpoint.to_string()),
            };
            assert!(
                !is_repo_in_scope(&cmd, "navikt/cplt"),
                "write to top-level endpoint '{endpoint}' must not be in scope",
            );
        }
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
    fn git_unknown_subcommand_blocked_when_push_prevention_active() {
        // Unknown git commands are blocked when push prevention is active
        // to prevent alias-based bypass (e.g., `git -c alias.p=push p`)
        assert!(gate_git(&["some-custom-alias"], true, true, false, &[], None).is_err());
        // But allowed when push prevention is disabled
        assert!(gate_git(&["some-custom-alias"], false, false, false, &[], None).is_ok());
        // Also allowed when only force push prevention (no regular push block)
        assert!(gate_git(&["some-custom-alias"], false, true, false, &[], None).is_ok());
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
        let script = generate_wrapper_script(
            "/path/with'quote/gh",
            Some("navikt/repo'with-quote"),
            "/path/with\"dq/cplt",
            &policy,
        );
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

    // ── Security fix tests ──────────────────────────────────────────

    #[test]
    fn git_alias_bypass_blocked() {
        // `-c alias.p=push` should be blocked when push prevention is active
        assert!(
            gate_git(
                &["-c", "alias.p=push", "p", "origin", "main"],
                true,
                true,
                false,
                &[],
                None
            )
            .is_err()
        );
        assert!(
            gate_git(
                &["-c", "alias.x=send-pack", "x"],
                true,
                true,
                false,
                &[],
                None
            )
            .is_err()
        );
        // Case insensitive check
        assert!(gate_git(&["-c", "ALIAS.p=push", "p"], true, true, false, &[], None).is_err());
        // Not blocked when push prevention is disabled
        assert!(gate_git(&["-c", "alias.p=push", "p"], false, false, false, &[], None).is_ok());
    }

    #[test]
    fn git_subtree_push_blocked() {
        // `git subtree push` is now explicitly blocked
        assert!(
            gate_git(
                &["subtree", "push", "--prefix=lib", "origin", "main"],
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
    fn git_force_push_to_feature_branch_blocked() {
        // Even with protect_default_branch_only=true, force push to feature branch
        // should be blocked when prevent_force_push=true
        assert!(
            gate_git(
                &["push", "--force", "origin", "feature-branch"],
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
                &["push", "-f", "origin", "my-feature"],
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
                &["push", "--force-with-lease", "origin", "feature"],
                true,
                true,
                true,
                &[],
                None
            )
            .is_err()
        );
        // But regular push to feature branch is still allowed
        assert!(
            gate_git(
                &["push", "origin", "feature-branch"],
                true,
                true,
                true,
                &[],
                None
            )
            .is_ok()
        );
        // Force push to feature branch allowed when prevent_force_push=false
        assert!(
            gate_git(
                &["push", "--force", "origin", "feature-branch"],
                true,
                false,
                true,
                &[],
                None
            )
            .is_ok()
        );
    }

    #[test]
    fn git_multiple_refspecs_checked() {
        // `git push origin feature main` should be blocked because "main" is a default branch
        assert!(
            gate_git(
                &["push", "origin", "feature", "main"],
                true,
                true,
                true,
                &[],
                None
            )
            .is_err()
        );
        // `git push origin feature develop` — neither is default, should be allowed
        assert!(
            gate_git(
                &["push", "origin", "feature", "develop"],
                true,
                true,
                true,
                &[],
                None
            )
            .is_ok()
        );
        // `git push origin HEAD:refs/heads/feature HEAD:refs/heads/master` — master is default
        assert!(
            gate_git(
                &[
                    "push",
                    "origin",
                    "HEAD:refs/heads/feature",
                    "HEAD:refs/heads/master"
                ],
                true,
                true,
                true,
                &[],
                None
            )
            .is_err()
        );
    }

    // ── Guard hardening regression tests (issue #116) ───────────────

    // Bug 1: `gh auth status --show-token`/`-t` leaks the token even though the
    // POLICY table marks `auth status` as a read-only Allow.
    #[test]
    fn gh_auth_status_show_token_blocked() {
        let dir = std::path::Path::new(".");
        let policy = GatePolicy::default(); // block_auth_token = true
        assert!(gate(&["auth", "status", "--show-token"], dir, &policy).is_err());
        assert!(gate(&["auth", "status", "-t"], dir, &policy).is_err());
        // pflag flag variants that bypass an exact-string match must be caught too.
        assert!(gate(&["auth", "status", "--show-token=true"], dir, &policy).is_err());
        assert!(gate(&["auth", "status", "-at"], dir, &policy).is_err()); // bundled -a -t
        assert!(gate(&["auth", "status", "-ta"], dir, &policy).is_err()); // bundle, other order
        // `gh auth token` remains blocked.
        assert!(gate(&["auth", "token"], dir, &policy).is_err());
        // Plain `gh auth status` (no token flag) is still allowed.
        assert!(gate(&["auth", "status"], dir, &policy).is_ok());
        // `-a`/`--active` alone (no token) and unrelated `--`-long flags must not misfire.
        assert!(gate(&["auth", "status", "-a"], dir, &policy).is_ok());
        assert!(gate(&["auth", "status", "--tags"], dir, &policy).is_ok());

        // When block_auth_token is disabled, --show-token is allowed.
        let unlocked = GatePolicy {
            block_auth_token: false,
            ..Default::default()
        };
        assert!(gate(&["auth", "status", "--show-token"], dir, &unlocked).is_ok());
    }

    // Bug 2: scope is derived from `origin`'s URL, so rewriting a remote URL
    // must be blocked while read-only inspection stays allowed.
    #[test]
    fn git_remote_url_mutation_blocked_scope_integrity() {
        // Mutating remote URLs / identity is blocked.
        assert!(
            gate_git(
                &[
                    "remote",
                    "set-url",
                    "origin",
                    "https://github.com/evil/repo"
                ],
                true,
                true,
                false,
                &[],
                None
            )
            .is_err()
        );
        assert!(
            gate_git(
                &[
                    "remote",
                    "set-url",
                    "--push",
                    "origin",
                    "https://github.com/evil/repo"
                ],
                true,
                true,
                false,
                &[],
                None
            )
            .is_err()
        );
        // Re-creating `origin` pointing elsewhere is the same bypass.
        assert!(
            gate_git(
                &["remote", "add", "origin", "https://github.com/evil/repo"],
                true,
                true,
                false,
                &[],
                None
            )
            .is_err()
        );
        // Promoting another remote *to* `origin` retargets the scope source.
        assert!(
            gate_git(
                &["remote", "rename", "upstream", "origin"],
                true,
                true,
                false,
                &[],
                None
            )
            .is_err()
        );
        // `git config remote.origin.url <value>` is a write → blocked.
        assert!(
            gate_git(
                &[
                    "config",
                    "remote.origin.url",
                    "https://github.com/evil/repo"
                ],
                true,
                true,
                false,
                &[],
                None
            )
            .is_err()
        );

        // Read-only inspection stays allowed.
        assert!(gate_git(&["remote", "-v"], true, true, false, &[], None).is_ok());
        assert!(gate_git(&["remote"], true, true, false, &[], None).is_ok());
        assert!(
            gate_git(
                &["remote", "get-url", "origin"],
                true,
                true,
                false,
                &[],
                None
            )
            .is_ok()
        );
        assert!(gate_git(&["remote", "show", "origin"], true, true, false, &[], None).is_ok());
        assert!(
            gate_git(
                &["config", "--get", "remote.origin.url"],
                true,
                true,
                false,
                &[],
                None
            )
            .is_ok()
        );
        // Bare read form `git config remote.origin.url` (prints the value).
        assert!(
            gate_git(
                &["config", "remote.origin.url"],
                true,
                true,
                false,
                &[],
                None
            )
            .is_ok()
        );
        // Unrelated config writes are unaffected.
        assert!(gate_git(&["config", "user.name", "x"], true, true, false, &[], None).is_ok());
    }

    // Finding 2: git's URL-rewrite keys (`url.<base>.insteadOf` /
    // `pushInsteadOf`) persistently redirect where github.com URLs resolve, an
    // equivalent transport-remap vector — they must be blocked like remote URL sets.
    #[test]
    fn git_config_insteadof_rewrite_blocked() {
        // Setting an insteadOf / pushInsteadOf rewrite is blocked.
        assert!(
            gate_git(
                &[
                    "config",
                    "url.https://evil/.insteadOf",
                    "https://github.com/"
                ],
                true,
                true,
                false,
                &[],
                None
            )
            .is_err()
        );
        assert!(
            gate_git(
                &[
                    "config",
                    "url.https://evil/.pushInsteadOf",
                    "https://github.com/"
                ],
                true,
                true,
                false,
                &[],
                None
            )
            .is_err()
        );
        // Reads of the same key stay allowed.
        assert!(
            gate_git(
                &["config", "--get", "url.https://evil/.insteadOf"],
                true,
                true,
                false,
                &[],
                None
            )
            .is_ok()
        );
        // Bare read form (prints the value) stays allowed.
        assert!(
            gate_git(
                &["config", "url.https://evil/.insteadOf"],
                true,
                true,
                false,
                &[],
                None
            )
            .is_ok()
        );
    }

    // Finding 3: managing NON-origin remotes doesn't touch the scope source and
    // must stay allowed; only mutations that create/retarget `origin` are blocked.
    #[test]
    fn git_nonorigin_remote_management_allowed() {
        // Non-origin management: allowed (was previously over-blocked).
        for args in [
            &["remote", "add", "upstream", "https://github.com/other/repo"][..],
            &["remote", "rename", "oldfork", "newfork"][..],
            &["remote", "remove", "upstream"][..],
            &["remote", "rm", "upstream"][..],
            &[
                "remote",
                "set-url",
                "upstream",
                "https://github.com/other/repo",
            ][..],
            // Renaming origin away / removing origin can't redirect (re-adding
            // origin is itself blocked), so it is allowed.
            &["remote", "rename", "origin", "backup"][..],
            &["remote", "remove", "origin"][..],
            // Non-origin config URL sets are unrelated to scope.
            &[
                "config",
                "remote.upstream.url",
                "https://github.com/other/repo",
            ][..],
        ] {
            assert!(
                gate_git(args, true, true, false, &[], None).is_ok(),
                "expected allowed: git {}",
                args.join(" ")
            );
        }

        // Origin-retargeting mutations: still blocked (scope-bypass prevention).
        for args in [
            &[
                "remote",
                "set-url",
                "origin",
                "https://github.com/evil/repo",
            ][..],
            &["remote", "add", "origin", "https://github.com/evil/repo"][..],
            &["remote", "rename", "upstream", "origin"][..],
        ] {
            assert!(
                gate_git(args, true, true, false, &[], None).is_err(),
                "expected blocked: git {}",
                args.join(" ")
            );
        }

        // The origin-retarget block also holds under force-push-only policy,
        // and still does not over-block non-origin management there.
        assert!(
            gate_git(
                &[
                    "remote",
                    "set-url",
                    "origin",
                    "https://github.com/evil/repo"
                ],
                false,
                true,
                false,
                &[],
                None
            )
            .is_err()
        );
        assert!(
            gate_git(
                &["remote", "add", "upstream", "https://github.com/other/repo"],
                false,
                true,
                false,
                &[],
                None
            )
            .is_ok()
        );
    }

    // Bug 3: a leading `+` on a refspec forces the update and must be recognized
    // both for default-branch protection and force-push prevention.
    #[test]
    fn git_plus_refspec_force_detected() {
        // `+main` targets the default branch under protect_default_branch_only.
        assert!(gate_git(&["push", "origin", "+main"], true, true, true, &[], None).is_err());
        assert!(gate_git(&["push", "origin", "+master"], true, true, true, &[], None).is_err());
        assert!(
            gate_git(
                &["push", "origin", "+HEAD:refs/heads/main"],
                true,
                true,
                true,
                &[],
                None
            )
            .is_err()
        );
        // `+feature:feature` is a force update under prevent_force_push (push allowed).
        assert!(
            gate_git(
                &["push", "origin", "+feature:feature"],
                false,
                true,
                false,
                &[],
                None
            )
            .is_err()
        );
        // Sanity: the non-force forms remain allowed.
        assert!(
            gate_git(
                &["push", "origin", "feature:feature"],
                false,
                true,
                false,
                &[],
                None
            )
            .is_ok()
        );
        // `+feature` is a force to a feature branch: blocked when force-push is
        // prevented, but allowed when it is not (prevent_force_push=false).
        assert!(gate_git(&["push", "origin", "+feature"], true, true, true, &[], None).is_err());
        assert!(
            gate_git(
                &["push", "origin", "+feature"],
                true,
                false,
                true,
                &[],
                None
            )
            .is_ok()
        );
    }

    // Bug 4: `--force-with-lease`/`--signed` take only `=`-attached values, so
    // they must NOT swallow the following remote/refspec.
    #[test]
    fn git_force_with_lease_space_form_not_value_consuming() {
        use crate::config::ResolvedPushRule;
        let rules = vec![ResolvedPushRule {
            remote: Some("origin".to_string()),
            branches: vec!["agent/*".to_string()],
            force: true,
        }];
        // The remote/branch must parse correctly (not be eaten by --force-with-lease).
        assert!(
            gate_git(
                &["push", "--force-with-lease", "origin", "agent/x"],
                true,
                true,
                false,
                &rules,
                None
            )
            .is_ok()
        );
        // Branch parsing is correct with the flag present.
        let (remote, branch) =
            extract_push_remote_and_branch(&["--force-with-lease", "origin", "agent/x"], None);
        assert_eq!(remote.as_deref(), Some("origin"));
        assert_eq!(branch.as_deref(), Some("agent/x"));
        let (remote, branch) =
            extract_push_remote_and_branch(&["--signed", "origin", "agent/y"], None);
        assert_eq!(remote.as_deref(), Some("origin"));
        assert_eq!(branch.as_deref(), Some("agent/y"));
    }

    // Bug 5: DELETE must be blocked even when input flags are also present.
    #[test]
    fn api_delete_with_input_flags_blocked() {
        let parsed = parse_command(&["api", "-X", "DELETE", "/repos/o/r/x", "-f", "k=v"]).unwrap();
        assert!(parsed.has_input_flags);
        assert_eq!(parsed.method.as_deref(), Some("DELETE"));
        assert_eq!(
            evaluate_with_policy(&parsed, true).decision,
            Decision::Block,
            "DELETE with input flags must be blocked even with allow_api_write"
        );
        assert_eq!(
            evaluate_with_policy(&parsed, false).decision,
            Decision::Block
        );
    }

    // Bug 6: only `git subtree push` is a remote write; local forms are allowed.
    #[test]
    fn git_subtree_local_allowed_push_blocked() {
        assert!(
            gate_git(
                &[
                    "subtree",
                    "add",
                    "--prefix=lib",
                    "https://example/x",
                    "main"
                ],
                true,
                true,
                false,
                &[],
                None
            )
            .is_ok()
        );
        assert!(
            gate_git(
                &["subtree", "pull", "--prefix=lib", "origin", "main"],
                true,
                true,
                false,
                &[],
                None
            )
            .is_ok()
        );
        assert!(
            gate_git(
                &["subtree", "split", "--prefix=lib"],
                true,
                true,
                false,
                &[],
                None
            )
            .is_ok()
        );
        assert!(
            gate_git(
                &["subtree", "push", "--prefix=lib", "origin", "main"],
                true,
                true,
                false,
                &[],
                None
            )
            .is_err()
        );
    }

    // Lower-severity: full-URL graphql evades the relative-form block.
    #[test]
    fn api_graphql_full_url_blocked() {
        for ep in ["graphql", "/graphql", "https://api.github.com/graphql"] {
            let cmd = ParsedCommand {
                command: "api".to_string(),
                subcommand: None,
                repo_flag: None,
                method: Some("POST".to_string()),
                has_input_flags: false,
                api_endpoint: Some(ep.to_string()),
            };
            assert_eq!(
                evaluate_with_policy(&cmd, true).decision,
                Decision::Block,
                "graphql endpoint '{ep}' must be blocked"
            );
        }
    }

    // Lower-severity: `.`/`..` path segments must not resolve to a repo.
    #[test]
    fn extract_repo_rejects_dot_segments() {
        assert_eq!(extract_repo_from_api_path("/repos/./cplt/pulls"), None);
        assert_eq!(extract_repo_from_api_path("/repos/navikt/../pulls"), None);
        assert_eq!(extract_repo_from_api_path("repos/../../etc/passwd"), None);
    }

    // Lower-severity: `-R=`/`-X=` attached-equals in the api parser.
    #[test]
    fn parse_api_attached_equals_flags() {
        let cmd = parse_command(&["api", "/repos/owner/repo/pulls", "-R=owner/repo"]).unwrap();
        assert_eq!(cmd.repo_flag.as_deref(), Some("owner/repo"));
        let cmd = parse_command(&["api", "-X=DELETE", "/repos/o/r/x/1"]).unwrap();
        assert_eq!(cmd.method.as_deref(), Some("DELETE"));
    }

    // Lower-severity: global `-R=other/repo` before the subcommand must not be dropped.
    #[test]
    fn parse_global_repo_attached_equals_before_command() {
        let cmd = parse_command(&["-R=navikt/cplt", "pr", "list"]).unwrap();
        assert_eq!(cmd.repo_flag.as_deref(), Some("navikt/cplt"));
        assert_eq!(cmd.command, "pr");
        assert_eq!(cmd.subcommand.as_deref(), Some("list"));
    }
}
