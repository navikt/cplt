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

use std::path::{Path, PathBuf};

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
    // `gh auth setup-git` points `credential.helper` at this verb, so every HTTPS
    // push runs it; without an entry it hit default-deny and push died with
    // "could not read Username" (#396). Ungated by `block_auth_token`: gating it
    // would break push in the default config and would withhold nothing —
    // claude/antigravity/goose can read the token out of the Keychain grant
    // themselves, Copilot's cache sits in its own TMPDIR, and opencode/pi/exec
    // reach whatever `hosts.yml` or `--pass-env` already handed them — in every
    // case the helper reveals nothing the agent could not read directly.
    // `block_auth_token` does not block `auth token` from the shim either:
    // `decide_gh_gate` intercepts it first, so it means "serve the cache once,
    // else report no cached token".
    PolicyEntry {
        command: "auth",
        subcommand: "git-credential",
        decision: Decision::Allow,
        reason: "git credential helper required for HTTPS push",
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

/// Check if a command targets the expected repository.
///
/// `startup_repo` should be in "owner/name" format. Explicit repository targets
/// are compared with it directly. Implicit repository targets require
/// `invocation_repo`, which is resolved from the command's cwd by the caller.
/// For `gh api` commands, also checks the endpoint URL path for /repos/{owner}/{repo}/.
/// Non-repo API endpoints (orgs, users) are NOT implicitly allowed — they require
/// explicit -R or a matching /repos/ path.
///
/// Security: write operations (`has_input_flags` or non-GET method) never use the
/// relative-path fallback — they require an explicit /repos/{owner}/{repo}/... match.
/// This prevents scope-check bypass via top-level endpoints (e.g. `gists`, `app/...`)
/// that don't start with a deny-listed prefix.
pub fn is_repo_in_scope(
    cmd: &ParsedCommand,
    scope: &[String],
    invocation_repo: Option<&str>,
) -> Option<String> {
    // Check -R/--repo flag first
    if let Some(target) = &cmd.repo_flag {
        return scope_member(scope, target);
    }

    // For gh api: extract repo from endpoint path like /repos/{owner}/{repo}/...
    if cmd.command == "api" {
        if let Some(ref endpoint) = cmd.api_endpoint {
            let Ok(endpoint) = github_api_endpoint_path(endpoint) else {
                return None;
            };
            if let Some(endpoint_repo) = extract_repo_from_api_path(endpoint) {
                return scope_member(scope, &endpoint_repo);
            }
            // Write operations (input flags or non-GET method) require an explicit
            // /repos/{owner}/{repo}/... path — no relative-path fallback.
            // This prevents top-level API endpoints (gists, app/installations, teams, etc.)
            // from being treated as in-scope just because they don't match a deny-list.
            let is_write =
                cmd.has_input_flags || matches!(cmd.method.as_deref(), Some(m) if m != "GET");
            if is_write {
                return None;
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
                // Relative read endpoint — gh CLI resolves to the invocation cwd's
                // repo, which must still be a member of the immutable startup scope.
                return invocation_repo.and_then(|repo| scope_member(scope, repo));
            }
            // Absolute non-repo endpoint (e.g., /orgs/..., /user/...) — not in scope.
            return None;
        }
        // No endpoint at all for gh api — shouldn't happen, but deny
        return None;
    }

    // Non-api commands: no -R flag → implicitly targets the invocation cwd's repo.
    invocation_repo.and_then(|repo| scope_member(scope, repo))
}

/// The scope member `target` names, in the spelling captured at launch.
///
/// The launch-time spelling is what gets pinned into `GH_REPO`, so a `-R` that
/// differs only in case or a `.git` suffix still pins the canonical member.
fn scope_member(scope: &[String], target: &str) -> Option<String> {
    scope
        .iter()
        .find(|member| repos_match(target, member))
        .cloned()
}

/// How the scope set is named in a refusal. Identical to the old single-value
/// wording when the set has one member.
fn scope_label(scope: &[String]) -> String {
    scope.join(", ")
}

/// Two `owner/name` spellings naming the same repository: GitHub is
/// case-insensitive and an origin URL may carry a `.git` suffix.
pub(crate) fn repos_match(left: &str, right: &str) -> bool {
    left.trim_end_matches(".git")
        .eq_ignore_ascii_case(right.trim_end_matches(".git"))
}

fn requires_invocation_repo_check(cmd: &ParsedCommand) -> bool {
    if cmd.repo_flag.is_some() {
        return false;
    }

    if cmd.command != "api" {
        return true;
    }

    // An explicit /repos/{owner}/{repo}/ API path already carries its target;
    // preserve the existing endpoint-vs-startup-scope check for that form.
    match cmd.api_endpoint.as_deref() {
        Some(endpoint) => github_api_endpoint_path(endpoint)
            .ok()
            .and_then(extract_repo_from_api_path)
            .is_none(),
        None => true,
    }
}

/// Read-only command groups whose implicit target is the repository of the cwd.
///
/// Global commands (`auth`, `search`, `gist`, `org`, `project`, `config`,
/// `extension`, `attestation`, `copilot`, ssh/gpg keys) do not resolve a
/// repository from the cwd, so they stay usable from any directory.
const CWD_SCOPED_COMMANDS: &[&str] = &[
    "pr", "issue", "run", "workflow", "release", "label", "cache", "secret", "variable", "repo",
    "ruleset",
];

/// Subcommands of a [`CWD_SCOPED_COMMANDS`] group that do not target the cwd
/// repository: they take an owner (or nothing) instead.
const CWD_SCOPED_EXCEPTIONS: &[(&str, &str)] =
    &[("repo", "list"), ("repo", "gitignore"), ("repo", "license")];

/// Allow-tier commands are read-only, but an implicit target still silently
/// retargets the startup repo when the agent is working in a sibling repo (#213).
/// Check the cwd for the repo-scoped ones only.
fn allow_tier_requires_invocation_repo_check(cmd: &ParsedCommand) -> bool {
    let sub = cmd.subcommand.as_deref().unwrap_or("");
    requires_invocation_repo_check(cmd)
        && CWD_SCOPED_COMMANDS.contains(&cmd.command.as_str())
        && !CWD_SCOPED_EXCEPTIONS.contains(&(cmd.command.as_str(), sub))
}

/// Resolve the repository of the invocation cwd with the trusted Git binary.
fn resolve_invocation_repo(real_git: Option<&Path>) -> Result<String, String> {
    let real_git = real_git.ok_or_else(|| {
        "trusted Git binary was unavailable for invocation cwd verification".to_string()
    })?;
    let cwd =
        std::env::current_dir().map_err(|e| format!("failed to determine invocation cwd: {e}"))?;
    detect_current_repo(real_git, &cwd)
}

/// `hint` names the way out of the block, which differs by tier: an Allow-tier
/// read accepts an explicit `-R owner/repo` for any repository, a ScopeCheck
/// write does not.
fn out_of_scope_cwd_error(
    cmd: &ParsedCommand,
    invocation_repo: &str,
    scope: &[String],
    hint: &str,
) -> String {
    let startup_repo = scope_label(scope);
    format!(
        "⚠️ BLOCKED by sandbox: 'gh {}{}' was invoked from repository '{invocation_repo}' outside the startup repo '{startup_repo}'.\n\
         Reason: implicit repository targets must resolve to the repository captured at sandbox startup.\n\
         {hint}\n\
         This operation is restricted by the cplt sandbox environment.\n\
         Please make a note of this for the human operator and continue with your remaining work.",
        cmd.command,
        cmd.subcommand
            .as_deref()
            .map(|s| format!(" {s}"))
            .unwrap_or_default(),
    )
}

/// Approval for an Allow-tier (read-only) command.
///
/// The startup scope stays authoritative and the *matched member* is pinned into
/// `GH_REPO`. An implicit repo-scoped read from a repository outside the set is
/// blocked instead of being silently answered from a member of it.
///
/// With several members the pin is only ever the member the command itself
/// names, or the one its cwd resolves to. When neither is known, a one-member
/// scope still pins (nothing else can be meant), a larger one pins nothing:
/// picking a member on the command's behalf is #213 with N repositories to
/// guess wrong about.
fn allow_tier_approval(
    cmd: &ParsedCommand,
    policy: &GatePolicy,
    resolve_scope: impl FnOnce() -> Result<Vec<String>, String>,
    real_git: Option<&Path>,
) -> Result<GateApproval, String> {
    if !policy.scope_check {
        return Ok(GateApproval::default());
    }
    let Ok(scope) = resolve_scope() else {
        return Ok(GateApproval::default());
    };
    // An explicit target (-R, or a /repos/{owner}/{repo} path) that names a
    // member pins to that member, never to the launch repository.
    if let Some(member) = is_repo_in_scope(cmd, &scope, None) {
        return Ok(approval_from_scope(Some(member)));
    }
    if allow_tier_requires_invocation_repo_check(cmd)
        && let Ok(invocation_repo) = resolve_invocation_repo(real_git)
    {
        let Some(member) = scope_member(&scope, &invocation_repo) else {
            return Err(out_of_scope_cwd_error(
                cmd,
                &invocation_repo,
                &scope,
                "Run it from the startup repository's checkout, or name the target \
                 explicitly with -R owner/repo where the command accepts it.",
            ));
        };
        return Ok(approval_from_scope(Some(member)));
    }
    Ok(approval_from_scope(single_member(&scope)))
}

/// The only member of a one-repository scope, or `None` when there is a choice
/// to be made — which the guard never makes on the command's behalf.
fn single_member(scope: &[String]) -> Option<String> {
    match scope {
        [only] => Some(only.clone()),
        _ => None,
    }
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
///
/// Deliberately does **not** route through [`crate::git::command`] (#210).
/// It needs `--local --no-includes`, which is stricter than the shared path.
/// `real_git` must be a [`crate::git::trusted_git`] path — this runs in the
/// unsandboxed parent at launch, so a `PATH`-resolved binary here is a previous
/// session's planted `git` executing as the user. `git config` executes nothing, so
/// the shared `-c` overrides would add no security here. If this ever grows a
/// subcommand that reads working-tree content, move it onto the shared path.
#[allow(clippy::disallowed_methods)] // `real_git` is a git::trusted_git() path supplied by the caller
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
/// `repo_scope` is the set of repositories verified before the sandboxed agent
/// starts — the launch repository plus every `--repo-dir` root on GitHub.
/// `real_git` is the trusted Git binary used to verify an implicit target's cwd.
/// `cplt_bin` is the path to the cplt binary (for calling `gh-gate`).
/// Policy flags are baked into the wrapper invocation so the gate doesn't
/// re-read config at runtime (security: agent could edit config files).
pub fn generate_wrapper_script(
    real_gh: &str,
    repo_scope: &[String],
    real_git: Option<&str>,
    cplt_bin: &str,
    policy: &crate::config::GhGuardPolicy,
) -> String {
    let cplt_escaped = shell_escape(cplt_bin);
    let gh_escaped = shell_escape(real_gh);
    let repo_scope_flag = repo_scope
        .iter()
        .map(|repo| format!("--repo-scope {}", shell_escape(repo)))
        .collect::<Vec<_>>()
        .join(" ");
    let real_git_flag = real_git
        .map(|git| format!("--real-git {}", shell_escape(git)))
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

exec {cplt_escaped} gh-gate --real-gh {gh_escaped} {repo_scope_flag} {real_git_flag} {mode_flag} {scope_flag} {auth_flag} {unknown_flag} {api_write_flag} -- "$@"
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
/// Used by `cplt check` (`check.rs`), which explains what the guard would do.
/// The `gh-gate` subcommand does not come through here: it has the startup
/// scope captured before launch and calls `gate_with_repo_scope` instead.
///
/// Returns the repository scope when one could be resolved, or an error when
/// the command is blocked. An allowed decision does not imply a scope — a
/// command that needs none is allowed without resolving one.
pub fn gate(
    args: &[&str],
    project_dir: &Path,
    policy: &GatePolicy,
) -> Result<GateApproval, String> {
    // Trusted, not PATH (#250). The only caller is `cplt check`, which runs in
    // the UNSANDBOXED parent, so a `git` planted in a write+exec directory on
    // PATH would execute as the user. `gate_with_git` documents its parameter
    // as a trusted binary; passing `Path::new("git")` kept that promise by
    // convention rather than by the code.
    //
    // No trusted git means the scope cannot be verified, so the resolver errors
    // and scope-checked commands are refused. That matches what the gh wrapper
    // already tells the user in the same situation, and it fails closed: the
    // alternative is answering a scope question with an unverified answer.
    // Resolved once, and passed to BOTH consumers: the scope resolver below and
    // `gate_with_scope_resolver`'s own `real_git`, which #230 uses to verify the
    // invocation repo of an implicit target. Passing `None` there would silently
    // skip that check.
    let trusted = crate::git::trusted_git();
    gate_with_scope_resolver(
        args,
        policy,
        || {
            let git = trusted.ok_or_else(|| {
                "no git in a trusted directory, so the repository scope cannot be verified"
                    .to_string()
            })?;
            detect_current_repo(git, project_dir).map(|repo| vec![repo])
        },
        trusted,
    )
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
    gate_with_scope_resolver(
        args,
        policy,
        || detect_current_repo(real_git, project_dir).map(|repo| vec![repo]),
        Some(real_git),
    )
}

/// Evaluate a `gh` command using startup scope and a trusted Git binary for cwd checks.
///
/// The startup scope remains authoritative. It is a *set*: the launch repository
/// plus every `--repo-dir` root whose origin is on GitHub. The invocation cwd is
/// consulted only for implicit repository targets, and only as evidence that the
/// command still refers to a member of that immutable set.
pub fn gate_with_repo_scope(
    args: &[&str],
    policy: &GatePolicy,
    repo_scope: &[String],
    real_git: Option<&Path>,
) -> Result<GateApproval, String> {
    gate_with_scope_resolver(
        args,
        policy,
        || {
            if repo_scope.is_empty() {
                Err("repository scope was unavailable at sandbox startup".to_string())
            } else {
                Ok(repo_scope.to_vec())
            }
        },
        real_git,
    )
}

fn gate_with_scope_resolver(
    args: &[&str],
    policy: &GatePolicy,
    resolve_scope: impl FnOnce() -> Result<Vec<String>, String>,
    real_git: Option<&Path>,
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
             Reason: token exfiltration prevention. Use the GH_TOKEN env var instead.\n\
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
        Decision::Allow => allow_tier_approval(&cmd, policy, resolve_scope, real_git),
        Decision::ScopeCheck => {
            if !policy.scope_check {
                return Ok(GateApproval::default());
            }

            let scope = resolve_scope().map_err(|reason| {
                format!(
                    "⚠️ BLOCKED by sandbox: 'gh {} {}' cannot verify target repository scope.\n\
                     Reason: {reason}.\n\
                     This operation is restricted by the cplt sandbox environment.\n\
                     Please make a note of this for the human operator and continue with your remaining work.",
                    cmd.command,
                    cmd.subcommand.as_deref().unwrap_or("")
                )
            })?;

            let invocation_repo = if requires_invocation_repo_check(&cmd) {
                Some(resolve_invocation_repo(real_git).map_err(|reason| {
                    format!(
                        "⚠️ BLOCKED by sandbox: 'gh {}{}' cannot verify the repository for its implicit target.\n\
                         Reason: {reason}.\n\
                         The invocation cwd must resolve to the repository captured at sandbox startup.\n\
                         This operation is restricted by the cplt sandbox environment.\n\
                         Please make a note of this for the human operator and continue with your remaining work.",
                        cmd.command,
                        cmd.subcommand
                            .as_deref()
                            .map(|s| format!(" {s}"))
                            .unwrap_or_default(),
                    )
                })?)
            } else {
                None
            };

            if let Some(member) = is_repo_in_scope(&cmd, &scope, invocation_repo.as_deref()) {
                // The matched member, never the launch repository: pinning the
                // launch repo with a set in play is #213, N repositories wide.
                Ok(GateApproval {
                    repo_scope: Some(format!("github.com/{member}")),
                })
            } else if let Some(invocation_repo) = invocation_repo.as_deref()
                && scope_member(&scope, invocation_repo).is_none()
            {
                Err(out_of_scope_cwd_error(
                    &cmd,
                    invocation_repo,
                    &scope,
                    "Run it from the startup repository's checkout.",
                ))
            } else {
                Err(format!(
                    "⚠️ BLOCKED by sandbox: 'gh {}{}' targets '{}' which is outside the startup repo '{}'.\n\
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
                    scope_label(&scope),
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
            UnknownCommandDecision::Allow => {
                allow_tier_approval(&cmd, policy, resolve_scope, real_git)
            }
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

/// Every long option real `git push` accepts, transcribed from `git push -h`
/// (git 2.50.1, Apple Git-155) — plus `--help`, which parse-options adds to
/// every builtin. The usage's `--[no-]x` spelling means `--no-x` is accepted
/// too, so the check strips a leading `no-` before looking a name up here.
///
/// Fail-closed by design. Git's parse-options also resolves *unique
/// abbreviations* (`--rep` → `--repo`, `--forc` → `--force`, `--al` →
/// `--all`), which every parser in this file — all of them exact-match — reads
/// as something else entirely: an abbreviated `--repo` leaves the destination
/// URL sitting in refspec position, where it is taken for a branch name that
/// is not the protected one, and an abbreviated `--force`/`--mirror`/`--tags`
/// is invisible to force and unconstrainable-mode detection. Rather than
/// reimplement git's prefix matching (and inherit its ambiguity rules), any
/// option not spelled out exactly is refused while a push guard is active.
/// A future git option therefore gets refused rather than silently misparsed;
/// when one appears, add it here.
const PUSH_LONG_OPTIONS: &[&str] = &[
    "all",
    "atomic",
    "branches",
    "delete",
    "dry-run",
    "exec",
    "follow-tags",
    "force",
    "force-if-includes",
    "force-with-lease",
    "help",
    "ipv4",
    "ipv6",
    "mirror",
    "porcelain",
    "progress",
    "prune",
    "push-option",
    "quiet",
    "receive-pack",
    "recurse-submodules",
    "repo",
    "set-upstream",
    "signed",
    "tags",
    "thin",
    "verbose",
    "verify",
];

/// The first `git push` option token that cannot be bound to an exact option,
/// if any: an unknown/abbreviated long option, or a bundled short cluster.
///
/// Bundling is refused rather than expanded for the same reason abbreviation
/// is: `-vo`, `-qo`, `-fu` and friends all parse in git and in none of this
/// file's parsers. The one single-dash token longer than two characters that
/// is unambiguous is `-o<value>` (`git push -oci.skip`), so it stays allowed.
///
/// Walks arguments the same way [`push_positionals`] does, so a flag's *value*
/// (`-o --whatever`) is never mistaken for an option, and everything after
/// `--` is positional.
fn unbindable_push_option<'a>(push_args: &[&'a str]) -> Option<&'a str> {
    let mut i = 0;
    while i < push_args.len() {
        let arg = push_args[i];
        if arg == "--" {
            break;
        }
        if let Some(long) = arg.strip_prefix("--") {
            let name = long.split('=').next().unwrap_or(long);
            if !PUSH_LONG_OPTIONS.contains(&name.strip_prefix("no-").unwrap_or(name)) {
                return Some(arg);
            }
        } else if arg.starts_with('-') && arg.len() > 2 && !arg.starts_with("-o") {
            return Some(arg);
        }
        if arg.starts_with('-') {
            if !arg.contains('=') && PUSH_FLAGS_WITH_VALUE.contains(&arg) {
                i += 2; // skip flag and its value
            } else {
                i += 1;
            }
            continue;
        }
        i += 1;
    }
    None
}

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

/// Config key prefixes that can redirect where a push lands (`remote.*`, `url.*`,
/// `push.*`, `branch.*`) or redefine what a subcommand runs (`alias.*`). Supplied
/// via `-c`/`--config-env` they diverge the exec'd push from the config the guard
/// authorized against, so they are refused at the gate.
///
/// `include.*`/`includeif.*` are here too: `-c include.path=<file>` pulls in an
/// arbitrary config file that can itself set `remote.origin.pushurl` (verified —
/// `get-url --push` then reports the diverted URL while the guard's probe, run
/// without the `-c`, still sees the real one). Blocking the include key closes
/// the indirection without having to chase what the included file might set.
const SENSITIVE_CONFIG_PREFIXES: &[&str] = &[
    "alias.",
    "remote.",
    "url.",
    "push.",
    "branch.",
    "include.",
    "includeif.",
];

/// The first `-c` / `--config-env` key an agent supplied that matches a
/// [`SENSITIVE_CONFIG_PREFIXES`] entry, if any.
///
/// Scans both the space-separated form (`-c k=v`, `--config-env k=ENV`) and the
/// `=`-attached long form (`--config-env=k=ENV`). `-c` has no `=`-attached form:
/// git always takes its `name=value` as the following token.
fn injected_sensitive_config_key(args: &[&str]) -> Option<(&'static str, String)> {
    let sensitive = |kv: &str| -> Option<String> {
        let key = kv.split('=').next().unwrap_or(kv);
        let lower = key.to_ascii_lowercase();
        SENSITIVE_CONFIG_PREFIXES
            .iter()
            .any(|p| lower.starts_with(p))
            .then(|| key.to_string())
    };
    let mut i = 0;
    while i < args.len() {
        let arg = args[i];
        if arg == "-c" || arg == "--config-env" {
            if let Some(kv) = args.get(i + 1) {
                if let Some(key) = sensitive(kv) {
                    // Name the flag the user actually typed; the refusal
                    // message quotes it back and the two are not
                    // interchangeable to someone acting on it.
                    let flag = if arg == "-c" { "-c" } else { "--config-env" };
                    return Some((flag, key));
                }
                i += 2;
                continue;
            }
        } else if let Some(kv) = arg.strip_prefix("--config-env=")
            && let Some(key) = sensitive(kv)
        {
            return Some(("--config-env", key));
        }
        i += 1;
    }
    None
}

/// The push destination that escapes remote-based authorization, if any.
///
/// Two forms redirect a push away from the remote the guard authorizes against:
/// `--repo`/`--repo=<url>`, and a first positional that is not a configured
/// remote of this repository.
///
/// On the positional: git parses `git push [<repository> [<refspec>…]]`, and the
/// FIRST positional is ALWAYS the repository — never a refspec. Verified against
/// git 2.50: `git push main:main` tries to ssh to host `main`, `git push
/// HEAD:refs/heads/x` to host `HEAD`, and `git push +main` fails with "'+main'
/// does not appear to be a git repository". So the `main:main` (refspec) vs
/// `host:path` (URL) ambiguity needs no syntactic tie-breaker: *position*
/// decides, exactly as git decides it, and a refspec only ever appears from the
/// second positional on.
///
/// What is left to establish is whether that repository argument is a name the
/// guard's remote-based authorization can actually bind to, and git's own remote
/// list is the only authority on that — no syntactic rule can do it, because a
/// slash-less, colon-less relative path (`git push b2.git main`) is a valid
/// destination too (GHSA-3m7m-m3rq-5cw8). With no git to ask, nothing can be
/// proven a configured remote, so any positional is treated as an override
/// (fail closed).
fn push_destination_override<'a>(
    sub_args: &[&'a str],
    real_git: Option<&Path>,
    repo_args: &[&str],
) -> Option<&'a str> {
    for (idx, arg) in sub_args.iter().enumerate() {
        // Report the destination itself, not the flag token — the refusal says
        // "'X' is not a configured remote", which is only true of the value.
        if let Some(url) = arg.strip_prefix("--repo=") {
            return Some(url);
        }
        if *arg == "--repo" {
            // A trailing `--repo` with no value is git's error to give; still
            // refuse, naming the only token there is.
            return Some(sub_args.get(idx + 1).copied().unwrap_or(arg));
        }
    }
    let dest = *push_positionals(sub_args).first()?;
    match real_git {
        Some(git) if resolve_remote_url(git, repo_args, dest).is_some() => None,
        _ => Some(dest),
    }
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
/// The verb of a `git remote <verb> …` invocation, and where it sits.
///
/// The first non-flag token. `None` is the bare listing form, which is
/// read-only.
fn remote_verb<'a>(sub_args: &[&'a str]) -> Option<(usize, &'a str)> {
    let idx = sub_args.iter().position(|a| !a.starts_with('-'))?;
    Some((idx, sub_args[idx]))
}

fn is_remote_scope_mutation(sub: &str, sub_args: &[&str]) -> bool {
    match sub {
        "remote" => {
            let Some((verb_idx, verb)) = remote_verb(sub_args) else {
                return false;
            };
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

/// True if these `git symbolic-ref` arguments *write* `refs/remotes/<remote>/HEAD`.
///
/// Fails closed on shape rather than enumerating the write forms. The only
/// invocation provably a read is one whose every `-`-prefixed token is exactly
/// `-q`, `--quiet` or `--short` and which has exactly one positional; that form
/// stays allowed because git internals and the guard's own launch-time
/// resolution use it. Anything else — a bundled short cluster (`-qm`, `-qd`),
/// an abbreviated long (`--del`, `--d`), an unknown flag, or a second
/// positional — is a write as far as this gate is concerned, and is blocked
/// when any positional names a `refs/remotes/<remote>/HEAD` ref.
///
/// Enumerating instead is what let `-qm r <ref> <target>` through: `-qm` is not
/// `-m`, so a skip-the-unknown parser dropped it, took its reason argument as
/// the first positional and looked for the ref in the wrong slot. Git resolves
/// abbreviations and bundles; this gate refuses to guess which token is which.
///
/// Names git itself rejects (`…/HEAD/`, `…//HEAD`, `./refs/…`, absolute paths —
/// "refusing to update ref with bad name") need no handling here.
fn symbolic_ref_writes_remote_head(sub_args: &[&str]) -> bool {
    const READ_FLAGS: &[&str] = &["-q", "--quiet", "--short"];
    let dashdash = sub_args.iter().position(|a| *a == "--");
    let head = &sub_args[..dashdash.unwrap_or(sub_args.len())];
    let tail = dashdash.map_or(&[][..], |i| &sub_args[i + 1..]);

    let read_shape = head
        .iter()
        .all(|a| !a.starts_with('-') || READ_FLAGS.contains(a));
    let positionals = || head.iter().filter(|a| !a.starts_with('-')).chain(tail);
    if read_shape && positionals().count() == 1 {
        return false; // read form
    }
    positionals().any(|name| {
        name.strip_prefix("refs/remotes/")
            .and_then(|r| r.strip_suffix("/HEAD"))
            .is_some_and(|remote| !remote.is_empty())
    })
}

/// Evaluate a git command. Returns Ok(()) if allowed, Err with message if blocked.
///
/// Used by the `cplt git-gate` subcommand.
/// `prevent_push` controls whether push/request-pull/send-pack are blocked.
/// `prevent_force_push` blocks force push even when regular push is allowed.
/// `protect_default_branch_only` allows pushes to non-default branches (not main/master).
/// `repo_facts` carries the launch-time answers the guard must not re-derive from
/// inside the sandbox — see [`RepoFacts`].
pub fn gate_git(
    args: &[&str],
    prevent_push: bool,
    prevent_force_push: bool,
    protect_default_branch_only: bool,
    allow_push_rules: &[crate::config::ResolvedPushRule],
    real_git: Option<&Path>,
    repo_facts: &RepoFacts,
) -> Result<(), String> {
    // If push prevention is entirely disabled, allow everything
    if !prevent_push && !prevent_force_push {
        return Ok(());
    }

    // Find the subcommand by skipping global flags.
    let mut i = 0;
    let mut subcommand = None;
    while i < args.len() {
        let arg = args[i];
        if GIT_GLOBAL_FLAGS_WITH_VALUE.contains(&arg) {
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

    // Defense in depth: block command-line config (`-c` / `--config-env`) that
    // could redirect where a push lands or redefine what a subcommand does.
    //
    // The guard resolves the push destination with its OWN git calls, which
    // forward only `-C`/`--git-dir`/`--work-tree` (never the agent's `-c`), but
    // `perform_gate_effect` execs the ORIGINAL argv. So `-c
    // remote.origin.pushurl=<evil>`, `-c remote.pushDefault=…`, `-c push.default=…`,
    // `-c url.<b>.pushInsteadOf=…`, or an `alias.*` redefinition would be
    // authorized against one config and then run under another (H-10). Rather
    // than mirror every such key into the probe, reject the whole class at the
    // gate — it is never needed for a legitimate push and always precedes one.
    //
    // Gated on EITHER setting, not on `prevent_push` alone: with
    // `prevent_push = false, prevent_force_push = true` — a supported
    // combination — `git -c 'alias.p=push --force' p origin feature` expanded
    // inside the real git binary after the guard had approved a subcommand it
    // did not recognize as a push, and the force push landed (#408). Every
    // reason this check exists applies whenever the guard has any push verdict
    // to protect.
    if (prevent_push || prevent_force_push)
        && let Some((flag, key)) = injected_sensitive_config_key(args)
    {
        return Err(format!(
            "⚠️ BLOCKED by sandbox: 'git {flag} {key}=…' is not allowed while push prevention is active.\n\
             Command-line config that can redirect a push (remote.*, url.*, push.*, branch.*) or\n\
             redefine a subcommand (alias.*) is refused, because the guard would authorize against\n\
             different configuration than the push actually runs under.\n\
             Configure the remote in the repository instead, and push to it by name.\n\
             Please make a note of this for the human operator and continue with your remaining work."
        ));
    }

    let Some(sub) = subcommand else {
        // No subcommand (e.g., `git --version`) — allow
        return Ok(());
    };

    // Arguments belonging to the subcommand (everything after it).
    let sub_args = &args[i + 1..];

    // The repository this invocation targets. Every git call the guard makes to
    // refine its verdict must go through these, or it decides from the launch
    // repository's branch and remotes instead (#215).
    let repo_args = repo_target_args(&args[..i]);

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

    // `git remote set-head` writes `refs/remotes/<remote>/HEAD` — the very ref
    // the push guard's default-branch yardstick used to be read from
    // (GHSA-cm6f-3wjh-x9qx). The facts are baked at launch now, so this cannot
    // move the yardstick within a session; refusing it stops the persisted
    // rewrite that would retarget the NEXT launch. It is one of three controls
    // on that ref: the profile's path deny (files backend only), this block,
    // and the `symbolic-ref` write block below (backend-independent).
    if prevent_push && sub == "remote" && remote_verb(sub_args).map(|(_, v)| v) == Some("set-head")
    {
        return Err(
            "⚠️ BLOCKED by sandbox: 'git remote set-head' is not allowed in this environment.\n\
             It rewrites refs/remotes/<remote>/HEAD, the record of which branch is the protected\n\
             default one. The push guard reads that fact from before this session started, so\n\
             rewriting it changes nothing it decides — but nothing legitimate needs it here either.\n\
             Run it OUTSIDE the sandbox if the recorded default branch is wrong.\n\
             Please make a note of this for the human operator and continue with your remaining work."
                .to_string(),
        );
    }

    // `git symbolic-ref refs/remotes/<remote>/HEAD <target>` writes the same ref
    // `git remote set-head` does, and it is the one write the filesystem cannot
    // stop: on a repository with the `reftable` ref backend (git 2.45+) that ref
    // is not a file at all — it lives in the binary tables under `.git/reftable/`,
    // which has to stay writable — so the profile's deny on
    // `.git/refs/remotes/*/HEAD` matches nothing and the rewrite succeeds. The
    // baked facts hold for the current session, but `cplt exec` re-bakes at every
    // launch, so a persisted rewrite hands the next launch a forged default
    // branch (GHSA-cm6f-3wjh-x9qx). A path deny cannot see a ref that is not a
    // path, so this control has to live in the gate, where it is
    // backend-independent. The read form stays allowed — git internals and the
    // launch-time fact capture both use it.
    if prevent_push && sub == "symbolic-ref" && symbolic_ref_writes_remote_head(sub_args) {
        return Err(
            "⚠️ BLOCKED by sandbox: writing refs/remotes/<remote>/HEAD is not allowed in this environment.\n\
             That symref records which branch is the protected default one, and the push guard reads it\n\
             when a session starts — so rewriting it here would retarget the guard at the next launch.\n\
             Reading it (git symbolic-ref [--short] <ref>) is still allowed.\n\
             Run the write OUTSIDE the sandbox if the recorded default branch is wrong.\n\
             Please make a note of this for the human operator and continue with your remaining work."
                .to_string(),
        );
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

    // Fail closed on any push option the guard cannot bind exactly. Git's
    // parse-options accepts unique abbreviations and bundled short flags; the
    // guard's parsers accept neither, and every disagreement between the two is
    // a bypass — `--rep origin <url> feature` puts the destination in refspec
    // position, `--forc`/`--al`/`--mir`/`--ta`/`-fu` hide a force or whole-repo
    // push from detection. Refusing the unbindable spelling is the one check
    // that closes both, and it sits ahead of every other push parser here so
    // none of them ever sees a token it would misread.
    if sub == "push"
        && let Some(opt) = unbindable_push_option(sub_args)
    {
        return Err(format!(
            "⚠️ BLOCKED by sandbox: 'git push {opt}' is not allowed in this environment.\n\
             '{opt}' is not an exact 'git push' option. Git resolves abbreviations ('--rep' for '--repo')\n\
             and bundled short flags ('-vo'), but the guard binds options by exact spelling, so an option\n\
             it cannot bind is refused instead of misparsed — a misparse moves the push destination or\n\
             hides '--force'.\n\
             Spell the option out in full, one flag per token: `git push --repo=<url>`, `-o <option>`, `-v -o <option>`.\n\
             Please make a note of this for the human operator and continue with your remaining work."
        ));
    }

    // A destination that is not a configured remote — `--repo=<url>`, or the
    // positional repository argument `git push <url|path> [refspec…]` — overrides
    // where the push lands, so any remote/URL authorization the guard performs
    // would be about a different target than the push writes to (H-10,
    // GHSA-3m7m-m3rq-5cw8). Reject it while push prevention is active; a
    // legitimate push names a configured remote instead.
    if prevent_push
        && sub == "push"
        && let Some(dest) = push_destination_override(sub_args, real_git, &repo_args)
    {
        return Err(format!(
            "⚠️ BLOCKED by sandbox: 'git push {dest}' is not allowed while push prevention is active.\n\
             '{dest}' is not a configured remote of this repository, so it redirects the push past remote-based\n\
             authorization — branch protection and allow_push rules bind to the remote, not to this argument.\n\
             Push to a configured remote by name instead: `git push <remote> <branch>`.\n\
             Please make a note of this for the human operator and continue with your remaining work."
        ));
    }

    if prevent_push && GIT_BLOCKED_SUBCOMMANDS.contains(&sub) {
        // When protect_default_branch_only is set, only block pushes targeting
        // the default branch (main/master). Feature branch pushes are allowed,
        // but force push is still checked independently.
        // Hints appended to the block message when a setting could not be
        // honoured as written. A guard that fails closed silently is only half
        // the fix: the operator has to learn why, and what to do about it.
        let mut block_hints: Vec<String> = Vec::new();

        // The repository's real default branch, resolved in the repo this
        // command targets. `None` means it could not be determined.
        let default_branch =
            if sub == "push" && (protect_default_branch_only || !allow_push_rules.is_empty()) {
                // The remote the push truly lands on, not an assumed `origin`:
                // the *branch* yardstick has to come from the same remote the
                // push writes to, or `remote.pushDefault` picks which remote's
                // default branch the guard compares against.
                let remote = push_dest_remote(&args[i + 1..], real_git, &repo_args);
                // Baked at launch, never re-read here: `refs/remotes/<remote>/HEAD`
                // is agent-writable, so asking the sandboxed repository at gate time
                // let the agent choose the guard's yardstick (GHSA-cm6f-3wjh-x9qx).
                let resolved = repo_facts
                    .default_branch(&remote, &repo_args, real_git)
                    .map(ToString::to_string);
                if resolved.is_none() && protect_default_branch_only {
                    block_hints.push(if repo_facts.describes(&repo_args, real_git) {
                        format!(
                            "protect_default_branch_only is set, but the default branch of remote \
                         '{remote}' could not be determined when this session started, so the \
                         guard cannot tell a feature branch from the protected one. Run \
                         `git remote set-head {remote} -a` (it records refs/remotes/{remote}/HEAD \
                         locally, no push) OUTSIDE the sandbox and start a new session."
                        )
                    } else if repo_args.is_empty() {
                        // No redirect flag, and still not the launch repository:
                        // the working directory is somewhere else — a nested
                        // clone, or GIT_DIR/GIT_WORK_TREE in the environment.
                        // Naming the repository we actually landed in is the
                        // only way the operator can tell those apart (#416).
                        let here = real_git
                            .and_then(|git| git_common_dir(git, &[]))
                            .map_or_else(
                                || {
                                    " (this directory is not a git repository the guard can read)"
                                        .to_string()
                                },
                                |dir| format!(" (its shared git directory is {dir})"),
                            );
                        format!(
                            "protect_default_branch_only is set, but this push does not run in the \
                         repository this session was launched in{here}. The protected branch is \
                         captured once at launch, for the launch repository, and it is not \
                         re-derived inside the sandbox — a nested clone, or GIT_DIR / \
                         GIT_WORK_TREE pointing elsewhere, has its own default branch that these \
                         facts say nothing about. Push from the launch repository, or start a \
                         session in this one."
                        )
                    } else {
                        "protect_default_branch_only is set, but this push redirects git \
                     elsewhere (-C / --git-dir / --work-tree). The protected branch is \
                     captured once at launch, for the project directory exactly as it was \
                     named, and it is not re-derived inside the sandbox — so any redirect, \
                     including one into a subdirectory of this same repository, leaves the \
                     guard without a default branch to judge against. Run the push without \
                     the redirect, or from a session launched in that repository."
                            .to_string()
                    });
                }
                resolved
            } else {
                None
            };

        if protect_default_branch_only && sub == "push" {
            let push_args = &args[i + 1..];
            // Without a resolved default branch nothing is a proven feature
            // branch, and a push whose destination refs cannot be enumerated
            // (whole-repo modes, config-driven destinations) is never provably
            // feature-only — both fall through to the normal block (fail closed).
            let targets = push_target_branches(push_args, real_git, &repo_args);
            let is_feature_branch = default_branch.is_some()
                && match &targets {
                    PushTargets::Branches(branches) if !branches.is_empty() => branches
                        .iter()
                        .all(|b| !is_protected_branch(b, default_branch.as_deref())),
                    _ => false,
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

            // The refusal that follows is about *one branch*, not about pushing.
            // Without saying so the only route the message names is the escape
            // hatch, which tells the reader to turn the guard off — the one
            // answer a security control must not lead with. Naming the branch
            // and the form that works keeps the actionable route in the message.
            let remote = push_dest_remote(push_args, real_git, &repo_args);
            // Name the branch only when the push resolves to exactly one. With
            // several destinations, or none we could enumerate, there is no
            // single branch to point at and the generic wording is the honest
            // one.
            let target_branch = match &targets {
                PushTargets::Branches(branches) if branches.len() == 1 => branches.first(),
                _ => None,
            };
            if default_branch.is_some() {
                match target_branch {
                    Some(branch) => block_hints.push(format!(
                        "'{branch}' is the protected branch here. Only the default \
                         branch is protected (protect_default_branch_only), so \
                         pushing a feature branch works as it is: \
                         `git push {remote} <branch>` with any other name."
                    )),
                    None => block_hints.push(format!(
                        "This push targets the checked-out branch, which is either \
                         the protected default branch or could not be resolved. \
                         Naming a feature branch explicitly works: \
                         `git push {remote} <branch>`."
                    )),
                }
            }
        }

        // Check allow_push exception rules before blocking
        if sub == "push" && !allow_push_rules.is_empty() {
            let push_args = &args[i + 1..];
            let has_force = push_is_force(push_args);
            // Resolve where the push actually lands, then authorize against
            // EVERY push URL of that destination. A bare `git push` follows
            // git's own remote resolution (`branch.<b>.pushRemote` →
            // `remote.pushDefault` → `branch.<b>.remote` → `origin`) rather than
            // assuming `origin`, and a remote-named rule must match every
            // configured `pushurl` — `git push` writes to all of them, so
            // checking only the first fails open (H-10). `matches_allow_push_rule`
            // treats an empty URL set as authorizing nothing for a remote-named
            // rule (fail closed).
            let dest_remote = push_dest_remote(push_args, real_git, &repo_args);
            let dest_url_strings = real_git
                .map(|git| resolve_push_urls(git, &repo_args, &dest_remote))
                .unwrap_or_default();
            let dest_urls: Vec<&str> = dest_url_strings.iter().map(String::as_str).collect();
            // The rule's branch glob must bind against EVERY destination branch
            // the push updates. An unconstrainable form (whole-repo modes,
            // multi-refspec beyond the glob, config-driven destinations) is
            // never authorized — the operator's `branches` filter cannot bound
            // it, so it fails closed (H-10).
            let authorized = match push_target_branches(push_args, real_git, &repo_args) {
                PushTargets::Branches(branches) if !branches.is_empty() => {
                    branches.iter().all(|b| {
                        matches_allow_push_rule(allow_push_rules, &dest_urls, Some(b), has_force)
                    })
                }
                _ => false,
            };
            if authorized {
                return Ok(());
            }
            // A rule naming a remote that could not be pinned to a URL at
            // launch matches nothing (see `matches_allow_push_rule`). Say so,
            // or the operator sees a rule that looks like it should apply.
            if let Some(name) = allow_push_rules
                .iter()
                .find(|r| r.remote.is_some() && r.url.is_none())
                .and_then(|r| r.remote.clone())
            {
                block_hints.push(format!(
                    "An allow_push rule names remote '{name}', but that name could not be \
                     pinned to a repository URL at launch, so the rule authorizes nothing. \
                     A bare remote name is not a repository identity — every repository has \
                     an 'origin' — so matching it by name would let the rule authorize \
                     pushes to other repositories (#215). Add the remote to the project \
                     repository before launch (`git remote add {name} <url>`) so the rule \
                     pins to it."
                ));
            }
        }

        let hints = if block_hints.is_empty() {
            String::new()
        } else {
            format!("\n{}", block_hints.join("\n"))
        };
        return Err(format!(
            "⚠️ BLOCKED by sandbox: 'git {sub}' is not allowed in this environment.\n\
             Push prevention is enabled — commit your changes locally.\n\
             This operation is restricted by the cplt sandbox to prevent unintended pushes.{hints}\n\
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

    // Unknown git subcommand — block when any push verdict is being enforced.
    // An agent can define aliases (via `git config` or `-c alias.x=push`) that resolve
    // to blocked subcommands. Since alias expansion happens inside the real git binary
    // (after the guard has already approved), unknown subcommands must be blocked
    // to prevent bypass via `git -c alias.p=push p origin main` or similar.
    //
    // `prevent_force_push` counts here too. Gating on `prevent_push` alone left
    // the force-push-only configuration approving `p` as an unrecognized
    // subcommand, after which git expanded the alias into the very `push
    // --force` the guard refuses when spelled out (#408).
    // `GIT_BLOCKED_SUBCOMMANDS` are recognized, not unknown. Under
    // `prevent_push` they returned above; under force-push-only they are
    // allowed to reach git (a plain `git push` is legal there), so they must not
    // be swept up here as unrecognized.
    if (prevent_push || prevent_force_push) && !GIT_BLOCKED_SUBCOMMANDS.contains(&sub) {
        return Err(format!(
            "⚠️ BLOCKED by sandbox: 'git {sub}' is not a recognized subcommand.\n\
             Push prevention is active — only known git subcommands are allowed.\n\
             An unrecognized subcommand may be an alias that expands to a push inside git,\n\
             after this guard has already decided, so it is refused rather than guessed at.\n\
             If this is a legitimate command, please ask the human operator to allow it."
        ));
    }

    Ok(())
}

/// Branch names protected under `protect_default_branch_only` regardless of what
/// the repository's real default branch turns out to be.
///
/// A floor, not the answer: the repository's own default branch is resolved by
/// [`resolve_default_branch`] and protected in addition to these. Keeping
/// `main`/`master` protected as well costs nothing (a repo whose default is
/// `develop` has no business pushing to a stale `main` either) and means the
/// resolved answer can only ever add protection.
const DEFAULT_BRANCH_NAMES: &[&str] = &["main", "master"];

/// Check whether a branch is protected under `protect_default_branch_only`.
///
/// `default_branch` is the repository's actual default as resolved by
/// [`resolve_default_branch`]; `main`/`master` are protected on top of it. The
/// setting promises to protect *the default branch*, so a repo whose default is
/// `develop`, `trunk` or `production` must be covered — a hardcoded name list
/// alone silently protects nothing there.
fn is_protected_branch(branch: &str, default_branch: Option<&str>) -> bool {
    // A `refs/heads/`-qualified refspec target reaches here unstripped when the
    // refspec has no colon (`git push origin refs/heads/release/2026`);
    // `refspec_target_branch` only strips the prefix off the `src:dst` form.
    let branch = branch.strip_prefix("refs/heads/").unwrap_or(branch);
    // Last path segment, so a remote-qualified `origin/main` still matches the
    // unslashed floor names below.
    let short = branch.rsplit('/').next().unwrap_or(branch);
    DEFAULT_BRANCH_NAMES.contains(&short)
        // The whole name, because the two sides arrive differently: `branch`
        // comes from push argv or `symbolic-ref --short HEAD`, so it is the
        // branch name entire — `release/2026`, slashes and all — while
        // `default_branch` comes from the `refs/remotes/<remote>/HEAD` symref
        // with only the `<remote>/` prefix taken off, so it is `release/2026`
        // too. Comparing last segments alone asked `"release/2026" == "2026"`
        // and a repository whose default branch has a slash in it was silently
        // unprotected — the exact under-protection #346 was written to remove,
        // surviving in the comparison.
        || default_branch == Some(branch)
        // Kept for the remote-qualified spelling of an unslashed default
        // (`origin/develop` against a default of `develop`). It can only add
        // protection: a false match here blocks a push, never allows one.
        || default_branch == Some(short)
}

/// `git push` flags that update refs a branch glob cannot bound: whole-repo and
/// all-refs push modes. Verified against git 2.50 — `--all`/`--branches` push
/// every branch (incl. the default), `--mirror` every ref, `--tags` all tags,
/// `--follow-tags` pushes annotated tags reachable from the branch *in addition*
/// to it (verified: `push origin agent/x --follow-tags` pushes agent/x AND the
/// tag), `--prune` deletes remote refs. A branch-constrained rule must fail
/// closed on any of them (H-10).
fn is_unconstrainable_push_flag(arg: &str) -> bool {
    matches!(
        arg,
        "--all" | "--mirror" | "--branches" | "--tags" | "--follow-tags" | "--prune"
    )
}

/// What a `git push` writes to, as far as a branch filter can be enforced.
enum PushTargets {
    /// The push updates refs that cannot be enumerated against a branch glob
    /// (whole-repo push modes, `matching`/`upstream` push.default, a configured
    /// `remote.<dest>.push` refspec, or an undeterminable current branch). Any
    /// branch-constrained decision must fail closed.
    Unconstrainable,
    /// The exact set of destination branch names the push updates. Every one
    /// must satisfy the branch constraint for the push to be authorized.
    Branches(Vec<String>),
}

/// Enumerate the destination branches a `git push` updates, or declare it
/// unconstrainable against a branch filter (fail closed).
///
/// This is the single choke point both the `protect_default_branch_only` and
/// `allow_push` branch checks route through, so every push *form* — modes,
/// multi-refspec, and the config-driven no-refspec destinations — is judged the
/// same way. Checking only `positionals[1]` (the old behaviour) let
/// `git push origin agent/x main`, `--all`, `push.default=matching`, and a
/// `remote.push` refspec write outside the glob (H-10, all verified by dry-run).
fn push_target_branches(
    push_args: &[&str],
    real_git: Option<&Path>,
    repo_args: &[&str],
) -> PushTargets {
    if push_args.iter().any(|a| is_unconstrainable_push_flag(a)) {
        return PushTargets::Unconstrainable;
    }

    let positionals = push_positionals(push_args);
    // Mirror extract_push_target_branch's positional interpretation, but keep
    // the explicit remote (if any) and ALL refspecs.
    let (remote_positional, refspecs): (Option<&str>, &[&str]) = match positionals.len() {
        0 => (None, &[]),
        1 => {
            let arg = positionals[0];
            if arg.contains(':') || arg.starts_with('+') {
                (None, &positionals[0..1]) // a lone refspec; remote defaulted
            } else {
                (Some(arg), &[]) // a bare remote; no refspec
            }
        }
        _ => (Some(positionals[0]), &positionals[1..]),
    };

    if !refspecs.is_empty() {
        // Explicit refspecs override push.default and any configured push
        // refspec, so the destinations are exactly their target refs — but only
        // once the *shape* of each refspec is accounted for. Comparing a token
        // literally is what let `HEAD`, `@`, `:` and glob refspecs past: the
        // guard matched the token text against the glob while git resolved it
        // to a real branch (H-10).
        let mut branches = Vec::new();
        for spec in refspecs {
            let bare = spec.strip_prefix('+').unwrap_or(spec);
            if bare.contains(':') {
                // Explicit destination: a remote-side ref NAME, taken literally.
                let dst = refspec_target_branch(bare);
                // `:` and `src:` push the matching set; a `*` destination is a
                // multi-ref pattern. Neither can be enumerated against a glob.
                if dst.is_empty() || dst.contains('*') {
                    return PushTargets::Unconstrainable;
                }
                branches.push(dst.to_string());
            } else {
                if bare.is_empty() || bare.contains('*') {
                    return PushTargets::Unconstrainable;
                }
                // A colon-less token is a LOCAL rev whose resolved branch is the
                // destination: `HEAD` and `@` mean the current branch, not a
                // branch literally named "HEAD". Resolve it; anything that is
                // not a `refs/heads/` ref (tag, detached HEAD, unknown token)
                // is not a branch this glob can authorize, so fail closed.
                let Some(git) = real_git else {
                    return PushTargets::Unconstrainable;
                };
                match resolve_token_branch(git, repo_args, bare) {
                    Some(b) => branches.push(b),
                    None => return PushTargets::Unconstrainable,
                }
            }
        }
        return PushTargets::Branches(branches);
    }

    // No explicit refspec: the destination is normally the current branch, but
    // `push.default` in {matching,upstream,tracking} or a configured
    // `remote.<dest>.push` refspec sends it to refs we cannot enumerate here.
    let Some(git) = real_git else {
        return PushTargets::Unconstrainable; // cannot probe config → fail closed
    };
    if let Some(mode) = git_config_value(git, repo_args, "push.default")
        && matches!(mode.as_str(), "matching" | "upstream" | "tracking")
    {
        return PushTargets::Unconstrainable;
    }
    let dest_remote = match remote_positional {
        Some(r) => r.to_string(),
        None => resolve_push_dest_remote(git, repo_args),
    };
    if git_config_value(git, repo_args, &format!("remote.{dest_remote}.push")).is_some() {
        return PushTargets::Unconstrainable;
    }
    match resolve_current_branch(git, repo_args) {
        Some(b) => PushTargets::Branches(vec![b]),
        None => PushTargets::Unconstrainable, // undeterminable branch → fail closed
    }
}

/// Git global flags that redirect which repository a command operates on.
///
/// `-c`, `--namespace` and friends are deliberately absent: they change
/// configuration, not the target repository, and forwarding attacker-chosen
/// `-c` values into the guard's own git calls would hand the agent a way to
/// influence the verdict.
const REPO_TARGET_FLAGS: &[&str] = &["-C", "--git-dir", "--work-tree"];

/// Git global flags that consume a following space-separated value, so a scan of
/// the global-flag prefix never mistakes such a value for a flag of its own.
const GIT_GLOBAL_FLAGS_WITH_VALUE: &[&str] = &[
    "-c",
    "-C",
    "--git-dir",
    "--work-tree",
    "--namespace",
    "--super-prefix",
    "--config-env",
];

/// The `-C` / `--git-dir` / `--work-tree` arguments of a git invocation, in
/// order, so the guard's own git calls resolve against the repository the
/// command actually targets rather than the launch repository (#215).
///
/// Both spellings are collected: the space-separated form (`-C dir`) and the
/// `=`-attached long form (`--git-dir=dir`). Multiple `-C` are kept in order
/// because git applies them cumulatively.
fn repo_target_args<'a>(args: &[&'a str]) -> Vec<&'a str> {
    let mut out: Vec<&str> = Vec::new();
    let mut i = 0;
    while i < args.len() {
        let arg = args[i];
        if REPO_TARGET_FLAGS.contains(&arg) {
            if let Some(value) = args.get(i + 1) {
                out.push(arg);
                out.push(value);
            }
            i += 2;
            continue;
        }
        if GIT_GLOBAL_FLAGS_WITH_VALUE.contains(&arg) {
            i += 2; // a value that must not be scanned as a flag
            continue;
        }
        if arg.starts_with("--")
            && let Some((flag, _)) = arg.split_once('=')
            && REPO_TARGET_FLAGS.contains(&flag)
        {
            out.push(arg);
        }
        i += 1;
    }
    out
}

/// The branch a colon-less push token designates, in the repo `repo_args` targets.
///
/// `git push origin HEAD` does not push to a branch named "HEAD" — it pushes to
/// whatever branch HEAD resolves to. Comparing the token text against a branch
/// glob is what let `HEAD` and `@` past the guard while the real push advanced
/// the protected branch (H-10). `rev-parse --symbolic-full-name` gives the ref
/// the token names, verified against git 2.50:
///
/// - `HEAD` / `@` on a branch → `refs/heads/<branch>`
/// - a branch name → its own `refs/heads/` ref
/// - a tag → `refs/tags/<name>` (not a branch)
/// - detached HEAD → the literal `HEAD` (exit 0, no ref)
/// - an unknown token → exit 128
///
/// Only a `refs/heads/` answer is a branch, so everything else yields `None`
/// and the caller fails closed. The token is always a push positional, which
/// `push_positionals` never lets start with `-`, so it cannot be read as a flag.
#[allow(clippy::disallowed_methods)] // `real_git` is a git::trusted_git() path supplied by the caller
fn resolve_token_branch(real_git: &Path, repo_args: &[&str], token: &str) -> Option<String> {
    let output = std::process::Command::new(real_git)
        .args(repo_args)
        .args(["rev-parse", "--symbolic-full-name", token])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let full = String::from_utf8_lossy(&output.stdout).trim().to_string();
    full.strip_prefix("refs/heads/")
        .filter(|b| !b.is_empty())
        .map(ToString::to_string)
}

/// Resolve the current git branch of the repository `repo_args` targets.
#[allow(clippy::disallowed_methods)] // `real_git` is a git::trusted_git() path supplied by the caller
fn resolve_current_branch(real_git: &Path, repo_args: &[&str]) -> Option<String> {
    let output = std::process::Command::new(real_git)
        .args(repo_args)
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

/// Normalized *push* URL of `remote` in the repository `repo_args` targets.
///
/// `--push` reports the URL a `git push` to this remote actually writes to: the
/// remote's `pushurl` when one is configured, otherwise its fetch URL. Both
/// callers are push-authorization decisions, so the URL the push goes to — not
/// the fetch URL it may diverge from — is the one identity must be proven
/// against (H-10). A remote with a divergent `pushurl` was previously authorized
/// against its fetch URL while pushing somewhere else entirely.
///
/// `None` when the remote does not exist, git fails, or no git binary is
/// available — every caller treats that as "cannot prove identity" and fails
/// closed.
#[allow(clippy::disallowed_methods)] // `real_git` is a git::trusted_git() path supplied by the caller
fn resolve_remote_url(real_git: &Path, repo_args: &[&str], remote: &str) -> Option<String> {
    // `--` guards against a remote name that looks like a flag.
    let output = std::process::Command::new(real_git)
        .args(repo_args)
        .args(["remote", "get-url", "--push", "--", remote])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let url = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if url.is_empty() {
        None
    } else {
        Some(crate::trust::normalize_remote_url(&url))
    }
}

/// Every normalized push URL of `remote` in the repository `repo_args` targets.
///
/// `git push` writes to ALL of a remote's configured `pushurl`s, but `get-url
/// --push` without `--all` returns only the first — a divergent second URL would
/// otherwise go unauthorized. The gate-time check requires *every* returned URL
/// to match a rule, so this returns them all.
///
/// Empty when the remote does not exist, git fails, or no git binary is
/// available — the caller treats an empty set as "cannot prove identity" and
/// fails closed.
#[allow(clippy::disallowed_methods)] // `real_git` is a git::trusted_git() path supplied by the caller
fn resolve_push_urls(real_git: &Path, repo_args: &[&str], remote: &str) -> Vec<String> {
    // `--` guards against a remote name that looks like a flag.
    let Ok(output) = std::process::Command::new(real_git)
        .args(repo_args)
        .args(["remote", "get-url", "--push", "--all", "--", remote])
        .output()
    else {
        return Vec::new();
    };
    if !output.status.success() {
        return Vec::new();
    }
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(crate::trust::normalize_remote_url)
        .collect()
}

/// A single git config value in the repository `repo_args` targets, or `None`.
///
/// `key` is a fixed, guard-constructed key (never agent-supplied), so no `--`
/// guard is needed; `--get` takes exactly one name.
#[allow(clippy::disallowed_methods)] // `real_git` is a git::trusted_git() path supplied by the caller
fn git_config_value(real_git: &Path, repo_args: &[&str], key: &str) -> Option<String> {
    let output = std::process::Command::new(real_git)
        .args(repo_args)
        .args(["config", "--get", key])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let value = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if value.is_empty() { None } else { Some(value) }
}

/// The remote a bare `git push` (no explicit remote argument) writes to,
/// following git's own resolution order (verified against git 2.50):
/// `branch.<current>.pushRemote`, then `remote.pushDefault`, then
/// `branch.<current>.remote`, then `origin`.
///
/// Resolved in the repository `repo_args` targets so the authorization decision
/// is made about the URL the push truly lands at, rather than an assumed
/// `origin` — assuming `origin` fails *open* whenever a diverted `pushRemote`,
/// `pushDefault` or upstream `remote` is configured but `origin` happens to
/// match the rule (H-10).
fn resolve_push_dest_remote(real_git: &Path, repo_args: &[&str]) -> String {
    let branch = resolve_current_branch(real_git, repo_args);
    if let Some(b) = &branch
        && let Some(remote) =
            git_config_value(real_git, repo_args, &format!("branch.{b}.pushRemote"))
    {
        return remote;
    }
    if let Some(remote) = git_config_value(real_git, repo_args, "remote.pushDefault") {
        return remote;
    }
    // git falls back to the branch's fetch remote before `origin`: a planted
    // `branch.<b>.remote` diverts a bare push, so it must be resolved too.
    if let Some(b) = &branch
        && let Some(remote) = git_config_value(real_git, repo_args, &format!("branch.{b}.remote"))
    {
        return remote;
    }
    SCOPE_REMOTE.to_string()
}

/// The default branch of `remote` in the repository `repo_args` targets.
///
/// Read from the local `refs/remotes/<remote>/HEAD` symref that `git clone` and
/// `git remote set-head` write, so no network call is made and the answer is the
/// one this repository holds.
///
/// Called ONLY from [`capture_repo_facts`], in the unsandboxed parent at launch.
/// `refs/remotes/<remote>/HEAD` is an ordinary, agent-writable ref file, so
/// asking this question at gate time inside the sandbox let the agent pick the
/// guard's yardstick (GHSA-cm6f-3wjh-x9qx). Do not call it from `gate_git`.
///
/// `None` when the symref is missing, the remote does not exist, or git fails.
#[allow(clippy::disallowed_methods)] // `real_git` is a git::trusted_git() path supplied by the caller
fn resolve_default_branch(real_git: &Path, repo_args: &[&str], remote: &str) -> Option<String> {
    // The ref name is always `refs/…`-prefixed, so a remote called `-x` cannot
    // turn into a flag here.
    let refname = format!("refs/remotes/{remote}/HEAD");
    let output = std::process::Command::new(real_git)
        .args(repo_args)
        .args(["symbolic-ref", "--short", &refname])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let value = String::from_utf8_lossy(&output.stdout).trim().to_string();
    // `--short` yields `origin/main`; the branch name is what callers compare.
    let branch = value
        .strip_prefix(&format!("{remote}/"))
        .unwrap_or(&value)
        .to_string();
    if branch.is_empty() {
        None
    } else {
        Some(branch)
    }
}

/// Facts about the launch repository, captured in the unsandboxed parent with
/// the trusted git binary and baked into the generated `git` wrapper.
///
/// The guard used to answer "what is this remote's default branch?" by running
/// `git symbolic-ref refs/remotes/<remote>/HEAD` at gate time, inside the
/// sandbox, against the repository the agent works in. `refs/remotes/*/HEAD` is
/// an ordinary ref file under `.git/refs/` — not covered by
/// `PROTECTED_IN_GITDIR` — and `symbolic-ref` is an allowed subcommand, so the
/// agent could rewrite the guard's own yardstick and then push to the real
/// default branch (GHSA-cm6f-3wjh-x9qx). Capturing the answer before the
/// sandbox starts removes the dependency on agent-writable state entirely,
/// exactly as the gh guard's `--repo-scope` pin already does.
///
/// Only facts that are *stable for the session* belong here. Anything that
/// legitimately changes while the agent works — which branch HEAD points at,
/// which URL a remote currently pushes to — must stay dynamic, or the guard
/// would authorize against a snapshot while git acts on the present.
#[derive(Debug, Default, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RepoFacts {
    /// Canonical path of the repository these facts describe, so a `-C` that
    /// redirects the command elsewhere is not judged by them (#215).
    #[serde(default)]
    pub project_dir: String,
    /// Canonical `git rev-parse --git-common-dir` of the launch repository.
    ///
    /// `project_dir` alone cannot answer "is this the launch repository?" for a
    /// command that carries no redirect: the gate inherits the agent's working
    /// directory, so `cd nested && git push` — a clone of a *different* repo
    /// under the project tree — reached the baked facts and was judged against
    /// the launch repo's protected branch (#416). The *common* dir, not the git
    /// dir, so a linked `git worktree` of the launch repository (whose git dir
    /// is `.git/worktrees/<name>` but whose common dir is the launch repo's)
    /// still resolves to the same repository.
    #[serde(default)]
    pub git_common_dir: String,
    /// Remote name → its default branch, from `refs/remotes/<remote>/HEAD`.
    #[serde(default)]
    pub default_branches: std::collections::BTreeMap<String, String>,
}

impl RepoFacts {
    /// Whether these facts describe the repository `repo_args` targets.
    ///
    /// A `-C <dir>` naming the very repository the facts were captured for is
    /// described by them. Anything else — a `-C` elsewhere, several `-C`,
    /// `--git-dir`, `--work-tree` — targets a repository these facts say
    /// nothing about, and re-deriving the answer from *that* repository is the
    /// hole this type exists to close, so it yields no facts and the caller
    /// fails closed.
    ///
    /// No redirect at all used to be assumed to mean the launch repository. It
    /// does not: the gate runs with the agent's working directory, so `cd
    /// nested && git push origin <its default branch>` — and `GIT_DIR` /
    /// `GIT_WORK_TREE` in the environment, which carry no flag to notice — were
    /// judged against the launch repository's baked facts (#416). Which
    /// repository you are standing in is a different question from what its
    /// default branch is: the second must come from launch (it is
    /// agent-writable, GHSA-cm6f-3wjh-x9qx), the first can only be asked now.
    /// So ask it, and compare against the launch repo's common dir baked at the
    /// same time. An unknown common dir on either side means "cannot tell", and
    /// that fails closed rather than treating every repository as the launch
    /// one.
    fn describes(&self, repo_args: &[&str], real_git: Option<&Path>) -> bool {
        if repo_args.is_empty() {
            let (Some(git), false) = (real_git, self.git_common_dir.is_empty()) else {
                return false;
            };
            return git_common_dir(git, &[]).is_some_and(|d| d == self.git_common_dir);
        }
        let mut dir: Option<&str> = None;
        let mut it = repo_args.iter();
        while let Some(arg) = it.next() {
            if *arg != "-C" {
                return false; // --git-dir / --work-tree: not a plain work-tree redirect
            }
            let Some(value) = it.next() else {
                return false;
            };
            if dir.is_some() {
                return false; // cumulative `-C`: not worth resolving, fail closed
            }
            dir = Some(value);
        }
        let (Some(dir), false) = (dir, self.project_dir.is_empty()) else {
            return false;
        };
        match (
            std::fs::canonicalize(dir),
            std::fs::canonicalize(&self.project_dir),
        ) {
            (Ok(a), Ok(b)) => a == b,
            _ => false,
        }
    }

    /// The baked default branch of `remote`, or `None` when there is no baked
    /// answer — which every caller treats as "cannot tell a feature branch from
    /// the protected one" and fails closed.
    #[must_use]
    pub fn default_branch(
        &self,
        remote: &str,
        repo_args: &[&str],
        real_git: Option<&Path>,
    ) -> Option<&str> {
        if !self.describes(repo_args, real_git) {
            return None;
        }
        self.default_branches.get(remote).map(String::as_str)
    }
}

/// Canonical `git rev-parse --git-common-dir` of the repository `repo_args`
/// targets, or `None` when git cannot say (not a repository, git absent, a path
/// that does not resolve). Every caller treats `None` as "cannot tell" and fails
/// closed.
///
/// `--path-format=absolute` because the bare form is relative to the working
/// directory git resolved it in, which is not the one this process is comparing
/// against; canonicalized on top so a symlinked path (`/tmp` → `/private/tmp`)
/// compares equal to the baked one.
#[allow(clippy::disallowed_methods)] // `real_git` is a git::trusted_git() path supplied by the caller
fn git_common_dir(real_git: &Path, repo_args: &[&str]) -> Option<String> {
    let output = std::process::Command::new(real_git)
        .args(repo_args)
        .args(["rev-parse", "--path-format=absolute", "--git-common-dir"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if path.is_empty() {
        return None;
    }
    Some(
        std::fs::canonicalize(path)
            .ok()?
            .to_string_lossy()
            .into_owned(),
    )
}

/// Every configured remote of the repository `repo_args` targets.
#[allow(clippy::disallowed_methods)] // `real_git` is a git::trusted_git() path supplied by the caller
fn list_remotes(real_git: &Path, repo_args: &[&str]) -> Vec<String> {
    let Ok(output) = std::process::Command::new(real_git)
        .args(repo_args)
        .args(["remote"])
        .output()
    else {
        return Vec::new();
    };
    if !output.status.success() {
        return Vec::new();
    }
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(ToString::to_string)
        .collect()
}

/// Capture [`RepoFacts`] for `project_dir` at launch.
///
/// Runs once in the unsandboxed parent, so `real_git` must be a
/// [`crate::git::trusted_git`] path — the same rule as
/// [`resolve_push_rule_urls`]. A remote with no recorded
/// `refs/remotes/<remote>/HEAD` is simply absent from the map, and the guard
/// fails closed for it.
#[must_use]
pub fn capture_repo_facts(real_git: &Path, project_dir: &Path) -> RepoFacts {
    let dir = project_dir.to_string_lossy().into_owned();
    let repo_args = ["-C", dir.as_str()];
    let mut facts = RepoFacts {
        project_dir: std::fs::canonicalize(project_dir)
            .unwrap_or_else(|_| project_dir.to_path_buf())
            .to_string_lossy()
            .into_owned(),
        git_common_dir: git_common_dir(real_git, &repo_args).unwrap_or_default(),
        ..RepoFacts::default()
    };
    for remote in list_remotes(real_git, &repo_args) {
        if let Some(branch) = resolve_default_branch(real_git, &repo_args, &remote) {
            facts.default_branches.insert(remote, branch);
        }
    }
    facts
}

/// What a `--repo-dir` root is, captured in the unsandboxed parent at launch.
///
/// Same rule as [`capture_repo_facts`]: `real_git` must be a
/// [`crate::git::trusted_git`] path, and the answers are taken once, before the
/// agent can touch the repository they describe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NamedRoot {
    /// Canonical path of the root.
    pub path: PathBuf,
    /// `owner/name` from `origin`. `None` when the origin is not a GitHub URL,
    /// which is not an error — the root simply stays out of the gh scope set.
    pub repo: Option<String>,
    /// `git rev-parse --git-common-dir`, canonicalized. Identifies the
    /// repository regardless of which linked worktree of it is being used.
    pub git_common_dir: String,
}

/// Capture [`NamedRoot`] facts for one `--repo-dir` root.
#[must_use]
pub fn capture_named_root(real_git: &Path, dir: &Path) -> NamedRoot {
    let d = dir.to_string_lossy().into_owned();
    NamedRoot {
        path: std::fs::canonicalize(dir).unwrap_or_else(|_| dir.to_path_buf()),
        repo: detect_current_repo(real_git, dir).ok(),
        git_common_dir: git_common_dir(real_git, &["-C", d.as_str()]).unwrap_or_default(),
    }
}

/// Whether `project_dir` has any remote configured at all.
///
/// Separates "no default branch could be captured" into its two cases: a repo
/// with remotes whose `refs/remotes/*/HEAD` was never recorded (pushes really
/// will be refused, and `git remote set-head` really is the fix), and a repo
/// with nowhere to push, where neither is true.
#[must_use]
pub fn has_remotes(real_git: &Path, project_dir: &Path) -> bool {
    let dir = project_dir.to_string_lossy().into_owned();
    !list_remotes(real_git, &["-C", dir.as_str()]).is_empty()
}

/// The remote a `git push` writes to.
///
/// An explicit positional remote wins. A single positional that is a refspec
/// (`HEAD:main`, `+main`) is not a remote name, and neither is no positional at
/// all: both follow git's own resolution via [`resolve_push_dest_remote`].
/// Assuming `origin` there fails *open* — with `remote.pushDefault upstream`
/// the push lands on `upstream` while the guard consults `origin`'s baked
/// default branch, so a bare `git push` on `develop` slipped past
/// `protect_default_branch_only` when `develop` was upstream's default. The
/// agent cannot pick the guard's yardstick, but it could pick which remote's
/// yardstick was read.
fn push_dest_remote(push_args: &[&str], real_git: Option<&Path>, repo_args: &[&str]) -> String {
    if let Some(remote) = push_positionals(push_args)
        .first()
        .copied()
        .filter(|r| !r.contains(':') && !r.starts_with('+'))
    {
        return remote.to_string();
    }
    real_git.map_or_else(
        || SCOPE_REMOTE.to_string(),
        |git| resolve_push_dest_remote(git, repo_args),
    )
}

/// Pin each rule's remote *name* to the URL that name has in the launch
/// repository, so the rule identifies a repository and not just a name (#215).
///
/// Runs once at wrapper-install time, in the unsandboxed parent, so `real_git`
/// must be a [`crate::git::trusted_git`] path. A name that does not resolve
/// (no such remote) is left with `url: None`, which authorizes nothing — see
/// [`matches_allow_push_rule`].
#[must_use]
pub fn resolve_push_rule_urls(
    real_git: &Path,
    project_dir: &Path,
    rules: &[crate::config::ResolvedPushRule],
) -> Vec<crate::config::ResolvedPushRule> {
    let dir = project_dir.to_string_lossy().into_owned();
    let repo_args = ["-C", dir.as_str()];
    rules
        .iter()
        .map(|rule| {
            let mut rule = rule.clone();
            if rule.url.is_none()
                && let Some(name) = rule.remote.as_deref()
            {
                rule.url = resolve_remote_url(real_git, &repo_args, name);
            }
            rule
        })
        .collect()
}

/// Check if a push matches any allow_push exception rule.
/// All specified fields in a rule must match (AND logic).
fn matches_allow_push_rule(
    rules: &[crate::config::ResolvedPushRule],
    dest_urls: &[&str],
    branch: Option<&str>,
    is_force: bool,
) -> bool {
    for rule in rules {
        // If force push and rule doesn't allow force, skip
        if is_force && !rule.force {
            continue;
        }
        // Check remote constraint.
        //
        // A rule that names a remote identifies a *repository*, never a name:
        // the push's remote must resolve to the same URL the rule was pinned to
        // at launch, so a rule for this repo's `origin` does not authorize a
        // push to another repo's `origin` (#215).
        //
        // An unresolvable URL on either side matches nothing. A rule that could
        // not be pinned at launch (`url: None`) therefore authorizes nothing at
        // all: falling back to the bare name would grant exactly the cross-repo
        // authorization #215 exists to prevent, since every repository has a
        // remote called `origin`. The operator is warned at launch and told why
        // the push was blocked.
        //
        // A push writes to *every* configured `pushurl`, so a remote-named rule
        // authorizes the push only if EVERY destination URL is the pinned one;
        // an empty set (URL unresolvable) authorizes nothing. Checking only the
        // first URL would let a divergent second `pushurl` through (H-10). A
        // rule with no remote (`remote: None`) is branches-only by the
        // operator's choice and skips the URL check entirely.
        if rule.remote.is_some() {
            let Some(rule_url) = rule.url.as_deref() else {
                continue;
            };
            if dest_urls.is_empty() || dest_urls.iter().any(|u| *u != rule_url) {
                continue;
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
    repo_facts: &RepoFacts,
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
    // The launch-time repository facts, baked in exactly like the gh guard's
    // `--repo-scope`. Absent when nothing could be captured, which fails closed.
    let repo_facts_flag = if repo_facts.default_branches.is_empty() {
        String::new()
    } else {
        let json = serde_json::to_string(repo_facts).unwrap_or_default();
        format!(" --repo-facts='{}'", json.replace('\'', "'\\''"))
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

exec {cplt_escaped} git-gate --real-git {git_escaped} {mode_flag} {prevent_push_flag} {prevent_force_push_flag} {protect_default_flag}{allow_push_flag}{repo_facts_flag} -- "$@"
"#
    )
}

#[cfg(test)]
#[allow(clippy::disallowed_methods)] // test code: no unsandboxed parent to protect (#239)
mod tests {
    use super::*;

    /// Test shim: the single-repository scope these cases were written for.
    fn in_scope(cmd: &ParsedCommand, repo: &str, invocation_repo: Option<&str>) -> bool {
        is_repo_in_scope(cmd, &[repo.to_string()], invocation_repo).is_some()
    }

    /// Test shim for [`gate_git`] that supplies the launch-time [`RepoFacts`]
    /// for the repository the invocation targets, the way `sandbox_exec`
    /// captures them before the sandbox starts. Tests drive the guard through
    /// `-C <scratch repo>`; in production the agent's own `git push` carries no
    /// redirect and the facts are those of the launch repository.
    fn gate_git_t(
        args: &[&str],
        prevent_push: bool,
        prevent_force_push: bool,
        protect_default_branch_only: bool,
        allow_push_rules: &[crate::config::ResolvedPushRule],
        real_git: Option<&Path>,
    ) -> Result<(), String> {
        let dir = args
            .iter()
            .position(|a| *a == "-C")
            .and_then(|i| args.get(i + 1))
            .copied()
            .unwrap_or(".");
        let facts = real_git.map_or_else(RepoFacts::default, |git| {
            capture_repo_facts(git, Path::new(dir))
        });
        gate_git(
            args,
            prevent_push,
            prevent_force_push,
            protect_default_branch_only,
            allow_push_rules,
            real_git,
            &facts,
        )
    }

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

    // Issue #396: the credential helper installed by `gh auth setup-git` must be
    // allowed, or HTTPS `git push` fails with "could not read Username".
    #[test]
    fn auth_git_credential_allowed() {
        let parsed = ParsedCommand {
            command: "auth".to_string(),
            subcommand: Some("git-credential".to_string()),
            repo_flag: None,
            method: None,
            has_input_flags: false,
            api_endpoint: None,
        };
        assert_eq!(evaluate(&parsed).decision, Decision::Allow);

        // And through the full gate, including with block_auth_token on (the
        // default): the helper stays allowed while `gh auth token` stays gated.
        let dir = std::path::Path::new(".");
        let policy = GatePolicy::default(); // block_auth_token = true
        assert!(gate(&["auth", "git-credential", "get"], dir, &policy).is_ok());
        assert!(gate(&["auth", "token"], dir, &policy).is_err());
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
    fn scope_check_no_repo_flag_requires_matching_invocation_repo() {
        let cmd = ParsedCommand {
            command: "pr".to_string(),
            subcommand: Some("create".to_string()),
            repo_flag: None,
            method: None,
            has_input_flags: false,
            api_endpoint: None,
        };
        assert!(in_scope(&cmd, "navikt/cplt", Some("navikt/cplt")));
        assert!(!in_scope(&cmd, "navikt/cplt", Some("evil-org/other-repo")));
        assert!(!in_scope(&cmd, "navikt/cplt", None));
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
        assert!(in_scope(&cmd, "navikt/cplt", None));
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
        assert!(!in_scope(&cmd, "navikt/cplt", None));
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
        assert!(in_scope(&cmd, "navikt/cplt", None));
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
        assert!(in_scope(&cmd, "navikt/cplt", None));
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
        assert!(!in_scope(&cmd, "navikt/cplt", None));
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
        assert!(in_scope(&cmd, "navikt/cplt", None));
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
        assert!(!in_scope(&cmd, "navikt/cplt", None));
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
        assert!(!in_scope(&cmd, "navikt/cplt", None));
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
        assert!(in_scope(&cmd, "navikt/cplt", Some("navikt/cplt")));
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
        assert!(in_scope(&cmd, "navikt/cplt", Some("navikt/cplt")));
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
        assert!(!in_scope(&cmd, "navikt/cplt", None));
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
        // The `@` need not start the path segment; the authority still ends at
        // the first `/` (GHSA-xcvh-hxfg-f4cg, same class as `normalize_remote_url`).
        assert_eq!(
            parse_repo_from_url("https://evil.example/x@github.com/navikt/cplt.git"),
            None
        );
        // …and a real `github.com` authority with an `@` later in the path is
        // not GitHub's `owner/repo` either — three segments, so it fails closed.
        assert_eq!(
            parse_repo_from_url("https://github.com/navikt/x@evil.example/cplt.git"),
            None
        );
    }

    // ── wrapper script test ──

    #[test]
    fn wrapper_script_contains_paths() {
        let policy = crate::config::GhGuardPolicy::default();
        let script = generate_wrapper_script(
            "/usr/bin/gh",
            &["navikt/cplt".to_string()],
            Some("/usr/bin/git"),
            "/usr/local/bin/cplt",
            &policy,
        );
        assert!(script.contains("/usr/bin/gh"));
        assert!(script.contains("--repo-scope 'navikt/cplt'"));
        assert!(script.contains("/usr/local/bin/cplt"));
        assert!(script.contains("--real-git '/usr/bin/git'"));
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
            &["navikt/cplt".to_string()],
            Some("/usr/bin/git"),
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
                !in_scope(&cmd, "navikt/cplt", None),
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
        assert!(
            gate_git(
                &["push"],
                true,
                true,
                false,
                &[],
                None,
                &RepoFacts::default()
            )
            .is_err()
        );
        assert!(
            gate_git(
                &["push", "origin", "main"],
                true,
                true,
                false,
                &[],
                None,
                &RepoFacts::default()
            )
            .is_err()
        );
        assert!(
            gate_git(
                &["push", "--force"],
                true,
                true,
                false,
                &[],
                None,
                &RepoFacts::default()
            )
            .is_err()
        );
        assert!(
            gate_git(
                &["-c", "user.name=x", "push"],
                true,
                true,
                false,
                &[],
                None,
                &RepoFacts::default()
            )
            .is_err()
        );
    }

    #[test]
    fn git_request_pull_is_blocked() {
        assert!(
            gate_git_t(
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
        assert!(
            gate_git(
                &["status"],
                true,
                true,
                false,
                &[],
                None,
                &RepoFacts::default()
            )
            .is_ok()
        );
        assert!(
            gate_git(
                &["log", "--oneline"],
                true,
                true,
                false,
                &[],
                None,
                &RepoFacts::default()
            )
            .is_ok()
        );
        assert!(
            gate_git(
                &["diff", "HEAD~1"],
                true,
                true,
                false,
                &[],
                None,
                &RepoFacts::default()
            )
            .is_ok()
        );
        assert!(
            gate_git(
                &["fetch", "origin"],
                true,
                true,
                false,
                &[],
                None,
                &RepoFacts::default()
            )
            .is_ok()
        );
        assert!(
            gate_git(
                &["pull"],
                true,
                true,
                false,
                &[],
                None,
                &RepoFacts::default()
            )
            .is_ok()
        );
        assert!(
            gate_git(
                &["branch", "-a"],
                true,
                true,
                false,
                &[],
                None,
                &RepoFacts::default()
            )
            .is_ok()
        );
    }

    #[test]
    fn git_local_writes_allowed() {
        assert!(
            gate_git(
                &["commit", "-m", "fix"],
                true,
                true,
                false,
                &[],
                None,
                &RepoFacts::default()
            )
            .is_ok()
        );
        assert!(
            gate_git(
                &["add", "."],
                true,
                true,
                false,
                &[],
                None,
                &RepoFacts::default()
            )
            .is_ok()
        );
        assert!(
            gate_git(
                &["checkout", "-b", "feature"],
                true,
                true,
                false,
                &[],
                None,
                &RepoFacts::default()
            )
            .is_ok()
        );
        assert!(
            gate_git(
                &["merge", "main"],
                true,
                true,
                false,
                &[],
                None,
                &RepoFacts::default()
            )
            .is_ok()
        );
        assert!(
            gate_git(
                &["rebase", "main"],
                true,
                true,
                false,
                &[],
                None,
                &RepoFacts::default()
            )
            .is_ok()
        );
        assert!(
            gate_git(
                &["stash"],
                true,
                true,
                false,
                &[],
                None,
                &RepoFacts::default()
            )
            .is_ok()
        );
        assert!(
            gate_git(
                &["tag", "v1.0"],
                true,
                true,
                false,
                &[],
                None,
                &RepoFacts::default()
            )
            .is_ok()
        );
    }

    #[test]
    fn git_no_subcommand_allowed() {
        assert!(
            gate_git(
                &["--version"],
                true,
                true,
                false,
                &[],
                None,
                &RepoFacts::default()
            )
            .is_ok()
        );
        assert!(gate_git(&[], true, true, false, &[], None, &RepoFacts::default()).is_ok());
    }

    /// The force-push-only configuration (`prevent_push = false`,
    /// `prevent_force_push = true`) is supported, and every gate that exists to
    /// keep an alias from expanding into a push inside the real git binary has
    /// to run under it too. Gating them on `prevent_push` alone let
    /// `git -c 'alias.p=push --force' p origin feature` through while
    /// `git push --force origin feature` was refused (#408).
    #[test]
    fn force_push_only_refuses_alias_and_injected_config() {
        let force_only =
            |args: &[&str]| gate_git(args, false, true, false, &[], None, &RepoFacts::default());

        // The reported bypass, both spellings of the injection.
        let err = force_only(&["-c", "alias.p=push --force", "p", "origin", "feature"])
            .expect_err("-c alias.* must be refused under force-push-only");
        assert!(
            err.contains("is not allowed while push prevention is active"),
            "{err}"
        );
        assert!(
            force_only(&["--config-env", "alias.p=EVIL", "p", "origin", "feature"]).is_err(),
            "--config-env alias.* must be refused under force-push-only"
        );
        assert!(
            force_only(&["--config-env=alias.p=EVIL", "p", "origin", "feature"]).is_err(),
            "--config-env=alias.* must be refused under force-push-only"
        );
        // A destination-redirecting key, not only `alias.*`.
        assert!(
            force_only(&[
                "-c",
                "remote.origin.pushurl=https://evil/x.git",
                "push",
                "origin",
                "x"
            ])
            .is_err(),
            "-c remote.*.pushurl must be refused under force-push-only"
        );

        // The alias's landing pad: an unrecognized subcommand is what git would
        // expand, so it is refused rather than approved on the way past.
        let err = force_only(&["p", "origin", "feature"])
            .expect_err("an unknown subcommand must be refused under force-push-only");
        assert!(err.contains("is not a recognized subcommand"), "{err}");

        // Abbreviated and bundled force spellings. `unbindable_push_option` is
        // gated on `sub == "push"` rather than on `prevent_push`, so these were
        // already correct — pinned here so the gating stays that way.
        for args in [
            ["push", "--forc", "origin", "feature"],
            ["push", "-fu", "origin", "feature"],
            ["push", "--force", "origin", "feature"],
        ] {
            assert!(
                force_only(&args).is_err(),
                "force-push-only must refuse {args:?}"
            );
        }

        // …without turning the force-push-only configuration into a push block:
        // a plain push is exactly what it is supposed to allow. `push` is a
        // recognized subcommand, so the unknown-subcommand refusal must not
        // sweep it up now that it runs under this configuration.
        assert!(
            force_only(&["push", "origin", "feature"]).is_ok(),
            "force-push-only must still allow a plain push"
        );
        assert!(
            force_only(&["status"]).is_ok(),
            "force-push-only must still allow ordinary read commands"
        );
    }

    #[test]
    fn git_unknown_subcommand_blocked_when_push_prevention_active() {
        // Unknown git commands are blocked when push prevention is active
        // to prevent alias-based bypass (e.g., `git -c alias.p=push p`)
        assert!(
            gate_git(
                &["some-custom-alias"],
                true,
                true,
                false,
                &[],
                None,
                &RepoFacts::default()
            )
            .is_err()
        );
        // But allowed when push prevention is disabled
        assert!(
            gate_git(
                &["some-custom-alias"],
                false,
                false,
                false,
                &[],
                None,
                &RepoFacts::default()
            )
            .is_ok()
        );
        // Refused under force-push-only too (#408). Allowing it here was the
        // bypass: `git -c 'alias.p=push --force' p origin feature` reached git,
        // which expanded the alias into the force push the guard refuses when
        // it is spelled out.
        assert!(
            gate_git(
                &["some-custom-alias"],
                false,
                true,
                false,
                &[],
                None,
                &RepoFacts::default()
            )
            .is_err()
        );
    }

    #[test]
    fn git_push_allowed_when_prevention_disabled() {
        assert!(
            gate_git(
                &["push"],
                false,
                false,
                false,
                &[],
                None,
                &RepoFacts::default()
            )
            .is_ok()
        );
        assert!(
            gate_git(
                &["push", "--force"],
                false,
                false,
                false,
                &[],
                None,
                &RepoFacts::default()
            )
            .is_ok()
        );
        assert!(
            gate_git(
                &["send-pack", "origin"],
                false,
                false,
                false,
                &[],
                None,
                &RepoFacts::default()
            )
            .is_ok()
        );
    }

    #[test]
    fn git_force_push_blocked_when_only_force_prevention() {
        // Regular push allowed, force push blocked
        assert!(
            gate_git(
                &["push", "origin", "main"],
                false,
                true,
                false,
                &[],
                None,
                &RepoFacts::default()
            )
            .is_ok()
        );
        assert!(
            gate_git(
                &["push", "--force"],
                false,
                true,
                false,
                &[],
                None,
                &RepoFacts::default()
            )
            .is_err()
        );
        assert!(
            gate_git_t(
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
        let script = generate_git_wrapper_script(
            "/usr/bin/git",
            "/usr/local/bin/cplt",
            &policy,
            &RepoFacts::default(),
        );
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
            &["navikt/repo'with-quote".to_string()],
            Some("/path/with'quote/git"),
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
            &RepoFacts::default(),
        );
        assert!(result.is_err());
    }

    /// Create local branches in a scratch repo so a test can push to them.
    ///
    /// The guard resolves a colon-less push token with `rev-parse`, so a branch
    /// that does not exist locally cannot be pushed — git refuses such a push
    /// too ("src refspec does not match any"), so a fixture that skips this is
    /// testing a push that could never happen.
    fn make_branches(git: &Path, repo: &Path, names: &[&str]) {
        for name in names {
            let ok = std::process::Command::new(git)
                .args(["-C", repo.to_str().unwrap(), "branch", name])
                .env("GIT_CONFIG_GLOBAL", "/dev/null")
                .env("GIT_CONFIG_NOSYSTEM", "1")
                .output()
                .expect("git must run")
                .status
                .success();
            assert!(ok, "creating branch {name} must succeed");
        }
    }

    // ── protect_default_branch_only tests ──

    /// `gate_git` for a push inside `repo`, under `protect_default_branch_only`.
    fn gate_push_in(git: &Path, repo: &str, push_args: &[&str]) -> Result<(), String> {
        let mut args = vec!["-C", repo];
        args.extend_from_slice(push_args);
        gate_git_t(&args, true, true, true, &[], Some(git))
    }

    /// #386: the shipped defaults — no config, no flags, no `allow_push` rule —
    /// refuse a push to the default branch and allow one to a feature branch.
    /// Driven from the resolved config rather than from literals, so a default
    /// that flips back fails here rather than only in the config tests.
    #[test]
    fn standard_defaults_block_the_default_branch_and_allow_feature_branches() {
        use crate::config::{CliFlags, Config, EnforcementMode};

        let r = Config::default().merge(CliFlags::default()).unwrap();
        assert_eq!(r.git_guard.mode, EnforcementMode::Block);
        assert!(r.git_guard.enabled);
        assert!(
            r.git_guard.allow_push.is_empty(),
            "the default posture must need no push exception to stay usable"
        );

        let Some((_tmp, repo)) = scratch_repo("main", "https://github.com/o/o.git") else {
            return; // no git available
        };
        let git = which_git().unwrap();
        // The branch has to exist: the guard resolves a colon-less push token
        // with `rev-parse`, and an absent branch fails closed for a reason that
        // has nothing to do with the default under test.
        make_branches(&git, &repo, &["feature/x"]);
        let dir = repo.to_string_lossy().into_owned();
        let gate = |push_args: &[&str]| {
            let mut args = vec!["-C", dir.as_str()];
            args.extend_from_slice(push_args);
            gate_git_t(
                &args,
                r.git_guard.prevent_push,
                r.git_guard.prevent_force_push,
                r.git_guard.protect_default_branch_only,
                &r.git_guard.allow_push,
                Some(&git),
            )
        };
        assert!(
            gate(&["push", "origin", "main"]).is_err(),
            "a push to the default branch must be refused by default"
        );
        assert!(
            gate(&["push", "origin", "feature/x"]).is_ok(),
            "a feature-branch push must still work by default"
        );
    }

    #[test]
    fn protect_default_allows_feature_branch() {
        let Some((_tmp, repo)) = scratch_repo("main", "https://github.com/o/o.git") else {
            return; // no git available
        };
        let git = which_git().unwrap();
        make_branches(&git, &repo, &["feature/x", "copilot/fix", "dev"]);
        let dir = repo.to_string_lossy().into_owned();
        for branch in ["feature/x", "copilot/fix", "dev"] {
            assert!(
                gate_push_in(&git, &dir, &["push", "origin", branch]).is_ok(),
                "push to {branch} should be allowed"
            );
        }
    }

    #[test]
    fn protect_default_blocks_main() {
        let Some((_tmp, repo)) = scratch_repo("main", "https://github.com/o/o.git") else {
            return;
        };
        let git = which_git().unwrap();
        let dir = repo.to_string_lossy().into_owned();
        assert!(gate_push_in(&git, &dir, &["push", "origin", "main"]).is_err());
        assert!(gate_push_in(&git, &dir, &["push", "origin", "master"]).is_err());
    }

    /// A refusal must name the route that still works. Before this the message
    /// said only that push prevention was enabled, and the one way forward it
    /// named was the escape hatch — turning the guard off.
    #[test]
    fn a_default_branch_refusal_names_the_feature_branch_route() {
        let Some((_tmp, repo)) = scratch_repo("main", "https://github.com/o/o.git") else {
            return;
        };
        let git = which_git().unwrap();
        let dir = repo.to_string_lossy().into_owned();
        let msg = gate_push_in(&git, &dir, &["push", "origin", "main"])
            .expect_err("a push to the default branch must be refused");
        assert!(msg.contains("'main' is the protected branch"), "{msg}");
        assert!(msg.contains("git push origin <branch>"), "{msg}");
        // The hint is wrapped in source with `\` continuations. Without them the
        // literal carries the indentation, and the user reads a message with
        // runs of spaces through the middle of it.
        assert!(
            !msg.contains("  "),
            "the refusal must not carry source indentation as literal spaces: {msg}"
        );
    }

    #[test]
    fn protect_default_blocks_refspec_to_main() {
        let Some((_tmp, repo)) = scratch_repo("main", "https://github.com/o/o.git") else {
            return;
        };
        let git = which_git().unwrap();
        let dir = repo.to_string_lossy().into_owned();
        assert!(gate_push_in(&git, &dir, &["push", "origin", "HEAD:refs/heads/main"]).is_err());
        assert!(gate_push_in(&git, &dir, &["push", "origin", "abc123:refs/heads/master"]).is_err());
    }

    #[test]
    fn protect_default_allows_refspec_to_feature() {
        let Some((_tmp, repo)) = scratch_repo("main", "https://github.com/o/o.git") else {
            return;
        };
        let git = which_git().unwrap();
        let dir = repo.to_string_lossy().into_owned();
        assert!(gate_push_in(&git, &dir, &["push", "origin", "HEAD:refs/heads/feature/x"]).is_ok());
    }

    #[test]
    fn protect_default_blocks_bare_push_without_git() {
        // When real_git is None nothing can be resolved — neither the current
        // branch nor the repository's default branch — so every push is blocked.
        assert!(
            gate_git(
                &["push"],
                true,
                true,
                true,
                &[],
                None,
                &RepoFacts::default()
            )
            .is_err()
        );
        assert!(
            gate_git(
                &["push", "origin"],
                true,
                true,
                true,
                &[],
                None,
                &RepoFacts::default()
            )
            .is_err()
        );
        assert!(
            gate_git_t(
                &["push", "origin", "feature/x"],
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
    fn is_protected_branch_covers_the_floor_and_the_resolved_default() {
        assert!(is_protected_branch("main", None));
        assert!(is_protected_branch("master", None));
        assert!(is_protected_branch("origin/main", None));
        assert!(!is_protected_branch("develop", None));
        assert!(!is_protected_branch("feature/main-fix", None));
        assert!(!is_protected_branch("copilot/fix", None));
        // The repository's own default branch is protected as well, and the
        // floor still holds alongside it.
        assert!(is_protected_branch("develop", Some("develop")));
        assert!(is_protected_branch("origin/develop", Some("develop")));
        assert!(is_protected_branch("main", Some("develop")));
        assert!(!is_protected_branch("feature/x", Some("develop")));
    }

    #[test]
    fn is_protected_branch_covers_a_slashed_default_branch() {
        // A default branch is free to have a slash in it. Comparing only the
        // last path segment asked `"release/2026" == "2026"` and left such a
        // repository's default branch pushable.
        assert!(is_protected_branch("release/2026", Some("release/2026")));
        assert!(is_protected_branch(
            "refs/heads/release/2026",
            Some("release/2026")
        ));
        assert!(is_protected_branch("main", Some("release/2026")));
        // Neighbours of a slashed default are still feature branches.
        assert!(!is_protected_branch("release/2025", Some("release/2026")));
        assert!(!is_protected_branch("2026", Some("release/2026")));
        assert!(!is_protected_branch("feature/x", Some("release/2026")));
    }

    #[test]
    fn protect_default_blocks_slashed_default_branch() {
        let Some((_tmp, repo)) =
            scratch_repo_with_default("release/2026", "https://github.com/o/o.git", "release/2026")
        else {
            return;
        };
        let git = which_git().unwrap();
        make_branches(&git, &repo, &["release/2025", "feature/x"]);
        let dir = repo.to_string_lossy().into_owned();
        assert!(gate_push_in(&git, &dir, &["push", "origin", "release/2026"]).is_err());
        assert!(
            gate_push_in(
                &git,
                &dir,
                &["push", "origin", "HEAD:refs/heads/release/2026"]
            )
            .is_err()
        );
        assert!(gate_push_in(&git, &dir, &["push", "origin", "refs/heads/release/2026"]).is_err());
        // Bare `git push` on the checked-out default branch, too.
        assert!(gate_push_in(&git, &dir, &["push"]).is_err());
        // A second refspec must not smuggle it past the first.
        assert!(
            gate_push_in(&git, &dir, &["push", "origin", "feature/x", "release/2026"]).is_err()
        );
        // Feature branches in the same repository stay pushable.
        assert!(gate_push_in(&git, &dir, &["push", "origin", "release/2025"]).is_ok());
        assert!(gate_push_in(&git, &dir, &["push", "origin", "feature/x"]).is_ok());
    }

    #[test]
    fn push_target_branches_enumerates_and_fails_closed() {
        // Pure-arg cases (no git): only forms that need no resolution enumerate.
        let branches = |args: &[&str]| match push_target_branches(args, None, &[]) {
            PushTargets::Branches(b) => Some(b),
            PushTargets::Unconstrainable => None,
        };
        // An explicit destination is a literal remote-side ref name.
        assert_eq!(
            branches(&["origin", "HEAD:refs/heads/main"]),
            Some(vec!["main".to_string()])
        );
        assert_eq!(
            branches(&["origin", "agent/x:main", "b:release"]),
            Some(vec!["main".to_string(), "release".to_string()])
        );
        // Glob and empty destinations are multi-ref/matching forms (H-10).
        assert!(branches(&["origin", "refs/heads/*:refs/heads/*"]).is_none());
        assert!(branches(&["origin", "refs/heads/ma*:refs/heads/ma*"]).is_none());
        assert!(branches(&["origin", ":"]).is_none());
        assert!(branches(&["origin", "main:"]).is_none());
        assert!(branches(&["origin", "*"]).is_none());
        // Whole-repo modes.
        assert!(branches(&["--all", "origin"]).is_none());
        assert!(branches(&["--mirror", "origin"]).is_none());
        assert!(branches(&["--tags", "origin"]).is_none());
        assert!(branches(&["--follow-tags", "origin"]).is_none());
        // A colon-less token needs resolution; without git that fails closed.
        assert!(branches(&["origin", "feature"]).is_none());
        assert!(branches(&["origin", "HEAD"]).is_none());
        assert!(branches(&["origin"]).is_none()); // bare remote, no git to probe
        assert!(branches(&[]).is_none());
    }

    #[test]
    fn push_target_branches_resolves_colonless_tokens() {
        // `HEAD` and `@` are not branch names — they resolve to the current
        // branch, which is what the push actually writes (H-10).
        let Some(git) = git_or_skip() else { return };
        let (_tmp, repo) = scratch_repo("agent/x", "https://github.com/o/o.git")
            .expect("git present: scratch repo must build");
        make_branches(&git, &repo, &["v-branch"]);
        let dir = repo.to_string_lossy().into_owned();
        let repo_args = ["-C", dir.as_str()];
        let branches = |args: &[&str]| match push_target_branches(args, Some(&git), &repo_args) {
            PushTargets::Branches(b) => Some(b),
            PushTargets::Unconstrainable => None,
        };
        // On agent/x, HEAD and @ both mean agent/x.
        assert_eq!(
            branches(&["origin", "HEAD"]),
            Some(vec!["agent/x".to_string()])
        );
        assert_eq!(
            branches(&["origin", "@"]),
            Some(vec!["agent/x".to_string()])
        );
        // A plain branch name still resolves to itself.
        assert_eq!(
            branches(&["origin", "main"]),
            Some(vec!["main".to_string()])
        );
        assert_eq!(
            branches(&["origin", "+main"]),
            Some(vec!["main".to_string()])
        );
        // Every refspec is enumerated, not just the first.
        assert_eq!(
            branches(&["origin", "agent/x", "main"]),
            Some(vec!["agent/x".to_string(), "main".to_string()])
        );
        // A token that is not a branch fails closed.
        assert!(branches(&["origin", "no-such-branch"]).is_none());
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

        // A rule naming a remote carries the URL that name resolved to at
        // launch — the rule identifies a repository, not a name.
        let rules = vec![ResolvedPushRule {
            remote: Some("fork".to_string()),
            branches: vec!["agent/*".to_string()],
            force: false,
            url: Some("github.com/me/fork".to_string()),
        }];

        // Matches: the push's remote resolves to the pinned URL + matching branch
        assert!(matches_allow_push_rule(
            &rules,
            &["github.com/me/fork"],
            Some("agent/fix-123"),
            false
        ));
        // Doesn't match: same remote *name*, different repository
        assert!(!matches_allow_push_rule(
            &rules,
            &["github.com/someone/else"],
            Some("agent/fix-123"),
            false
        ));
        // Doesn't match: the push's remote could not be resolved at all
        assert!(!matches_allow_push_rule(
            &rules,
            &[],
            Some("agent/fix-123"),
            false
        ));
        // Doesn't match: one of several push URLs diverges — a push writes to
        // all of them, so every URL must be the pinned one (H-10).
        assert!(!matches_allow_push_rule(
            &rules,
            &["github.com/me/fork", "github.com/evil/elsewhere"],
            Some("agent/fix-123"),
            false
        ));
        // Doesn't match: wrong branch
        assert!(!matches_allow_push_rule(
            &rules,
            &["github.com/me/fork"],
            Some("main"),
            false
        ));
        // Doesn't match: force push not allowed
        assert!(!matches_allow_push_rule(
            &rules,
            &["github.com/me/fork"],
            Some("agent/fix"),
            true
        ));

        // A rule whose remote name could not be pinned at launch authorizes
        // nothing: a bare name matches every repository's remote of that name.
        let unpinned = vec![ResolvedPushRule {
            remote: Some("fork".to_string()),
            branches: vec!["agent/*".to_string()],
            force: false,
            url: None,
        }];
        assert!(!matches_allow_push_rule(
            &unpinned,
            &["github.com/me/fork"],
            Some("agent/fix-123"),
            false
        ));
        assert!(!matches_allow_push_rule(
            &unpinned,
            &[],
            Some("agent/fix-123"),
            false
        ));

        // Rule with no remote constraint: branches only, force allowed. The URL
        // set is irrelevant — the operator chose not to pin a remote.
        let rules_force = vec![ResolvedPushRule {
            remote: None,
            branches: vec!["agent/*".to_string()],
            force: true,
            url: None,
        }];
        assert!(matches_allow_push_rule(
            &rules_force,
            &["github.com/any/repo"],
            Some("agent/x"),
            true
        ));
        assert!(matches_allow_push_rule(
            &rules_force,
            &[],
            Some("agent/x"),
            false
        ));
    }

    use std::path::PathBuf;

    // ── multi-repo targeting (#215) ──
    //
    // The guard's conditional refinements must read the branch and the remotes
    // of the repository the command targets, not of whatever repository the
    // agent happens to have been launched in.

    /// A scratch git repo on `branch`, with `origin` pointing at `origin_url`.
    /// `None` when git is unavailable.
    fn scratch_repo(branch: &str, origin_url: &str) -> Option<(tempfile::TempDir, PathBuf)> {
        scratch_repo_with_default(branch, origin_url, "main")
    }

    /// Same, with the remote's default branch spelled out — including the
    /// slashed forms (`release/2026`) a repository is free to use.
    fn scratch_repo_with_default(
        branch: &str,
        origin_url: &str,
        default_branch: &str,
    ) -> Option<(tempfile::TempDir, PathBuf)> {
        let git = which_git()?;
        let tmp = tempfile::tempdir().ok()?;
        let repo = tmp.path().join("repo");
        std::fs::create_dir_all(&repo).ok()?;
        let run = |args: &[&str]| {
            std::process::Command::new(&git)
                .args(args)
                .current_dir(&repo)
                .env("GIT_CONFIG_GLOBAL", "/dev/null")
                .env("GIT_CONFIG_NOSYSTEM", "1")
                .output()
                .ok()
                .filter(|o| o.status.success())
        };
        run(&["init"])?;
        // `git init -b` is not available on every git these tests may meet.
        run(&["symbolic-ref", "HEAD", &format!("refs/heads/{branch}")])?;
        // A real commit, so `branch` actually exists. The guard resolves a
        // colon-less push token (`HEAD`, `@`, a branch name) with `rev-parse`,
        // which answers nothing in an unborn repository — an unborn fixture
        // would make every push fail closed for the wrong reason and hide
        // whatever the test meant to prove.
        run(&[
            "-c",
            "user.email=t@example.com",
            "-c",
            "user.name=t",
            "commit",
            "--allow-empty",
            "-q",
            "-m",
            "init",
        ])?;
        // The remote's default branch exists locally too, so a push naming it
        // resolves the way it would in a real clone.
        if default_branch != branch {
            run(&["branch", default_branch])?;
        }
        run(&["remote", "add", "origin", origin_url])?;
        // `git clone` records the remote's default branch here; these fixtures
        // stand in for cloned repos, so they record one too.
        run(&[
            "symbolic-ref",
            "refs/remotes/origin/HEAD",
            &format!("refs/remotes/origin/{default_branch}"),
        ])?;
        Some((tmp, repo))
    }

    /// `git` if it runs, probed directly rather than through `which` so the
    /// tests do not silently skip on a machine that has git but no `which`.
    /// `Command` resolves the bare name through PATH.
    fn which_git() -> Option<PathBuf> {
        std::process::Command::new("git")
            .arg("--version")
            .output()
            .ok()
            .filter(|o| o.status.success())
            .map(|_| PathBuf::from("git"))
    }

    /// `which_git()` or a LOUD skip. A silent `return` on a git-less host would
    /// let CI hide a regression behind a green test, so the skip prints to
    /// stderr and names the test. (CI has git; the e2e twins hard-panic.)
    #[track_caller]
    fn git_or_skip() -> Option<PathBuf> {
        let git = which_git();
        if git.is_none() {
            eprintln!(
                "SKIP {}: git not found in PATH — guard resolution not exercised",
                std::panic::Location::caller()
            );
        }
        git
    }

    #[test]
    fn repo_target_args_forwards_only_repo_flags() {
        assert_eq!(repo_target_args(&["-C", "/b"]), vec!["-C", "/b"]);
        assert_eq!(
            repo_target_args(&["--git-dir=/b/.git", "--work-tree", "/b"]),
            vec!["--git-dir=/b/.git", "--work-tree", "/b"]
        );
        // `-c` and its value are configuration, not a repo target, and the
        // value must not be scanned as a flag of its own.
        assert!(repo_target_args(&["-c", "-C", "-c", "user.name=x"]).is_empty());
    }

    #[test]
    fn branch_is_resolved_in_the_repo_dash_c_targets() {
        let Some((_tmp, repo)) = scratch_repo("main", "https://github.com/other/other.git") else {
            return; // no git available
        };
        let git = which_git().unwrap();
        let dir = repo.to_string_lossy().into_owned();

        // `git -C <repo-on-main> push` must be blocked even though the repo the
        // test process runs in may sit on a feature branch.
        let blocked = gate_git_t(&["-C", &dir, "push"], true, true, true, &[], Some(&git));
        assert!(
            blocked.is_err(),
            "push to main of the -C target must be blocked, got {blocked:?}"
        );

        // And the mirror image: a -C target on a feature branch is allowed even
        // when the process's own repo cannot be resolved (detached CI checkout).
        let Some((_tmp2, feature)) =
            scratch_repo("feature/x", "https://github.com/other/other.git")
        else {
            return;
        };
        let feature_dir = feature.to_string_lossy().into_owned();
        assert!(
            gate_git_t(
                &["-C", &feature_dir, "push"],
                true,
                false,
                true,
                &[],
                Some(&git)
            )
            .is_ok(),
            "push to a feature branch of the -C target must be allowed"
        );
    }

    #[test]
    fn allow_push_rule_does_not_match_a_same_named_remote_elsewhere() {
        use crate::config::ResolvedPushRule;

        let Some((_tmp, repo)) = scratch_repo("main", "https://github.com/other/other.git") else {
            return; // no git available
        };
        let git = which_git().unwrap();
        let dir = repo.to_string_lossy().into_owned();

        // A rule written for the launch repo's `origin`, pinned at launch to
        // that repo's URL.
        let rule = ResolvedPushRule {
            remote: Some("origin".to_string()),
            branches: vec!["main".to_string()],
            force: false,
            url: Some(crate::trust::normalize_remote_url(
                "git@github.com:navikt/cplt.git",
            )),
        };
        let args = ["-C", dir.as_str(), "push", "origin", "main"];
        assert!(
            gate_git_t(&args, true, true, false, &[rule], Some(&git)).is_err(),
            "a rule for another repository's origin must not authorize this push"
        );

        // Same rule, and now the target repo really is that repository — spelled
        // in a different but equivalent URL form.
        let Some((_tmp2, same)) = scratch_repo("main", "https://github.com/navikt/cplt") else {
            return;
        };
        let same_dir = same.to_string_lossy().into_owned();
        let rule = ResolvedPushRule {
            remote: Some("origin".to_string()),
            branches: vec!["main".to_string()],
            force: false,
            url: Some(crate::trust::normalize_remote_url(
                "git@github.com:navikt/cplt.git",
            )),
        };
        let args = ["-C", same_dir.as_str(), "push", "origin", "main"];
        assert!(
            gate_git_t(&args, true, true, false, &[rule], Some(&git)).is_ok(),
            "the same repository under an equivalent URL form must still match"
        );
    }

    #[test]
    fn push_rule_urls_are_pinned_from_the_launch_repo() {
        use crate::config::ResolvedPushRule;

        let Some((_tmp, repo)) = scratch_repo("main", "git@github.com:navikt/cplt.git") else {
            return; // no git available
        };
        let git = which_git().unwrap();
        let rules = vec![
            ResolvedPushRule {
                remote: Some("origin".to_string()),
                branches: vec![],
                force: false,
                url: None,
            },
            // A name with no such remote stays unresolved, and an unresolved
            // rule authorizes nothing.
            ResolvedPushRule {
                remote: Some("fork".to_string()),
                branches: vec![],
                force: false,
                url: None,
            },
        ];
        let resolved = resolve_push_rule_urls(&git, &repo, &rules);
        assert_eq!(resolved[0].url.as_deref(), Some("github.com/navikt/cplt"));
        assert_eq!(resolved[1].url, None);
    }

    #[test]
    fn push_rule_url_is_pinned_to_the_push_url_not_the_fetch_url() {
        use crate::config::ResolvedPushRule;

        // origin fetches from one repo but has a divergent `pushurl` pointing
        // elsewhere. Authorization must be judged against where the push
        // actually lands (H-10), not the fetch URL the push never touches.
        let Some((_tmp, repo)) = scratch_repo("main", "git@github.com:navikt/cplt.git") else {
            return; // no git available
        };
        let git = which_git().unwrap();
        let set_pushurl = std::process::Command::new(&git)
            .args([
                "-C",
                repo.to_str().unwrap(),
                "remote",
                "set-url",
                "--push",
                "origin",
                "git@github.com:evil/elsewhere.git",
            ])
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .output()
            .unwrap();
        assert!(set_pushurl.status.success());

        let rules = vec![ResolvedPushRule {
            remote: Some("origin".to_string()),
            branches: vec![],
            force: false,
            url: None,
        }];
        let resolved = resolve_push_rule_urls(&git, &repo, &rules);
        assert_eq!(
            resolved[0].url.as_deref(),
            Some("github.com/evil/elsewhere"),
            "the rule must pin the push URL, not the fetch URL"
        );
        assert_ne!(resolved[0].url.as_deref(), Some("github.com/navikt/cplt"));
    }

    // ── H-10: the guard must authorize against the URL the push runs under ──
    //
    // The guard probes with its own git (dropping the agent's `-c`) but
    // `perform_gate_effect` execs the original argv, so any config or flag that
    // diverts the destination must be caught at the gate. Each test drives
    // `gate_git` with a rule pinned to the scratch repo's `origin` and asserts
    // the diverted push is BLOCKED. Setup uses real git; on a git-less host the
    // test skips explicitly (`which_git` None) rather than passing vacuously —
    // when git IS present the fixture MUST build (`expect`).

    /// Run a git config/setup command against `repo`, panicking on failure so a
    /// broken fixture is loud instead of silently skipping the real assertion.
    fn git_setup(git: &Path, repo: &Path, args: &[&str]) {
        let ok = std::process::Command::new(git)
            .args(["-C", repo.to_str().unwrap()])
            .args(args)
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .output()
            .expect("git must run")
            .status
            .success();
        assert!(ok, "git setup {args:?} must succeed");
    }

    /// An allow_push rule pinned to the scratch repo's `origin`, allowing agent/*.
    fn origin_agent_rule() -> crate::config::ResolvedPushRule {
        crate::config::ResolvedPushRule {
            remote: Some("origin".to_string()),
            branches: vec!["agent/*".to_string()],
            force: false,
            url: Some(crate::trust::normalize_remote_url(
                "git@github.com:navikt/cplt.git",
            )),
        }
    }

    #[test]
    fn allow_push_blocks_pushurl_injected_via_dash_c() {
        let Some(git) = git_or_skip() else { return };
        let (_tmp, repo) = scratch_repo("agent/x", "git@github.com:navikt/cplt.git")
            .expect("git present: scratch repo must build");
        let dir = repo.to_string_lossy().into_owned();
        let rules = vec![origin_agent_rule()];
        // Baseline: a legitimate push to origin agent/x IS allowed.
        assert!(
            gate_git_t(
                &["-C", &dir, "push", "origin", "agent/x"],
                true,
                true,
                false,
                &rules,
                Some(&git)
            )
            .is_ok(),
            "the fixture must allow a legitimate push"
        );
        // Attack: `-c remote.origin.pushurl=<evil>` is refused at the gate.
        assert!(
            gate_git_t(
                &[
                    "-C",
                    &dir,
                    "-c",
                    "remote.origin.pushurl=https://github.com/evil/x.git",
                    "push",
                    "origin",
                    "agent/x",
                ],
                true,
                true,
                false,
                &rules,
                Some(&git)
            )
            .is_err(),
            "a -c pushurl injection must be blocked"
        );
    }

    #[test]
    fn allow_push_blocks_pushdefault_injected_via_dash_c() {
        let Some(git) = git_or_skip() else { return };
        let (_tmp, repo) = scratch_repo("agent/x", "git@github.com:navikt/cplt.git")
            .expect("git present: scratch repo must build");
        let dir = repo.to_string_lossy().into_owned();
        let rules = vec![origin_agent_rule()];
        assert!(
            gate_git_t(
                &[
                    "-C",
                    &dir,
                    "-c",
                    "remote.pushDefault=evil2",
                    "-c",
                    "push.default=current",
                    "push",
                ],
                true,
                true,
                false,
                &rules,
                Some(&git)
            )
            .is_err(),
            "-c remote.pushDefault / push.default injection must be blocked"
        );
    }

    #[test]
    fn allow_push_blocks_repo_url_override() {
        let Some(git) = git_or_skip() else { return };
        let (_tmp, repo) = scratch_repo("agent/x", "git@github.com:navikt/cplt.git")
            .expect("git present: scratch repo must build");
        let dir = repo.to_string_lossy().into_owned();
        let rules = vec![origin_agent_rule()];
        // No refspec: without the --repo block, remote resolves to origin (which
        // the rule allows for the current agent/x branch) and the push would be
        // authorized while `--repo` redirects it to <evil>. The block catches it.
        assert!(
            gate_git_t(
                &["-C", &dir, "push", "--repo=https://github.com/evil/x.git",],
                true,
                true,
                false,
                &rules,
                Some(&git)
            )
            .is_err(),
            "git push --repo=<url> must be blocked"
        );
    }

    #[test]
    fn allow_push_blocks_when_a_second_pushurl_diverges() {
        let Some(git) = git_or_skip() else { return };
        let (_tmp, repo) = scratch_repo("agent/x", "git@github.com:navikt/cplt.git")
            .expect("git present: scratch repo must build");
        // origin gains two push URLs: the pinned one plus a divergent one.
        // `git push` writes to both; `get-url --push` alone would see only the
        // first. Requiring every URL to match blocks it.
        git_setup(
            &git,
            &repo,
            &[
                "remote",
                "set-url",
                "--push",
                "origin",
                "git@github.com:navikt/cplt.git",
            ],
        );
        git_setup(
            &git,
            &repo,
            &[
                "remote",
                "set-url",
                "--add",
                "--push",
                "origin",
                "https://github.com/evil/x.git",
            ],
        );
        let dir = repo.to_string_lossy().into_owned();
        let rules = vec![origin_agent_rule()];
        assert!(
            gate_git_t(
                &["-C", &dir, "push", "origin", "agent/x"],
                true,
                true,
                false,
                &rules,
                Some(&git)
            )
            .is_err(),
            "a divergent second pushurl must block the push"
        );
    }

    #[test]
    fn allow_push_bare_push_resolves_real_destination_not_origin() {
        let Some(git) = git_or_skip() else { return };
        let rules = vec![origin_agent_rule()];

        // Control: with no diversion, bare `git push` resolves to origin and is
        // allowed — proving the destination resolver returns origin normally.
        let (_c, control) = scratch_repo("agent/x", "git@github.com:navikt/cplt.git")
            .expect("git present: scratch repo must build");
        let control_dir = control.to_string_lossy().into_owned();
        assert!(
            gate_git_t(
                &["-C", &control_dir, "push"],
                true,
                true,
                false,
                &rules,
                Some(&git)
            )
            .is_ok(),
            "a bare push with no diversion must resolve to origin and be allowed"
        );

        // Attack: a planted `remote.pushDefault` (writable .git/config on
        // Linux/bwrap) diverts a bare push to another remote. Assuming origin
        // would authorize it; resolving the real destination blocks it.
        let (_a, repo) = scratch_repo("agent/x", "git@github.com:navikt/cplt.git")
            .expect("git present: scratch repo must build");
        git_setup(
            &git,
            &repo,
            &["remote", "add", "evil", "https://github.com/evil/x.git"],
        );
        git_setup(&git, &repo, &["config", "remote.pushDefault", "evil"]);
        let dir = repo.to_string_lossy().into_owned();
        assert!(
            gate_git_t(&["-C", &dir, "push"], true, true, false, &rules, Some(&git)).is_err(),
            "a bare push diverted by remote.pushDefault must be blocked"
        );
    }

    #[test]
    fn allow_push_blocks_include_path_pushurl_injection() {
        // B1: `-c include.path=<file>` pulls in config that can set
        // remote.origin.pushurl; the guard's probe (no -c) never sees it.
        let Some(git) = git_or_skip() else { return };
        let (_t, repo) = scratch_repo("agent/x", "git@github.com:navikt/cplt.git")
            .expect("git present: scratch repo must build");
        let dir = repo.to_string_lossy().into_owned();
        let rules = vec![origin_agent_rule()];
        assert!(
            gate_git_t(
                &[
                    "-C",
                    &dir,
                    "-c",
                    "include.path=/tmp/evil.inc",
                    "push",
                    "origin",
                    "agent/x",
                ],
                true,
                true,
                false,
                &rules,
                Some(&git)
            )
            .is_err(),
            "-c include.path must be blocked"
        );
        assert!(
            gate_git_t(
                &[
                    "-C",
                    &dir,
                    "-c",
                    "includeIf.onbranch:agent/**.path=/tmp/evil.inc",
                    "push",
                    "origin",
                    "agent/x",
                ],
                true,
                true,
                false,
                &rules,
                Some(&git)
            )
            .is_err(),
            "-c includeIf.*.path must be blocked"
        );
    }

    #[test]
    fn allow_push_blocks_bare_push_diverted_by_branch_remote() {
        // B2: `branch.<b>.remote` diverts a bare push when pushRemote/pushDefault
        // are unset — git's resolution order includes it before origin.
        let Some(git) = git_or_skip() else { return };
        let (_t, repo) = scratch_repo("agent/x", "git@github.com:navikt/cplt.git")
            .expect("git present: scratch repo must build");
        git_setup(
            &git,
            &repo,
            &["remote", "add", "evil", "https://github.com/evil/x.git"],
        );
        git_setup(&git, &repo, &["config", "branch.agent/x.remote", "evil"]);
        git_setup(
            &git,
            &repo,
            &["config", "branch.agent/x.merge", "refs/heads/agent/x"],
        );
        let dir = repo.to_string_lossy().into_owned();
        let rules = vec![origin_agent_rule()];
        assert!(
            gate_git_t(&["-C", &dir, "push"], true, true, false, &rules, Some(&git)).is_err(),
            "a bare push diverted by branch.<b>.remote must be blocked"
        );
    }

    #[test]
    fn allow_push_blocks_whole_repo_push_modes() {
        // B3: --all/--mirror/--tags push refs a branch glob cannot bound. These
        // need no config and work on any platform.
        let Some(git) = git_or_skip() else { return };
        let (_t, repo) = scratch_repo("agent/x", "git@github.com:navikt/cplt.git")
            .expect("git present: scratch repo must build");
        let dir = repo.to_string_lossy().into_owned();
        let rules = vec![origin_agent_rule()];
        for mode in [
            "--all",
            "--mirror",
            "--tags",
            "--follow-tags",
            "--branches",
            "--prune",
        ] {
            assert!(
                gate_git_t(
                    &["-C", &dir, "push", mode, "origin"],
                    true,
                    true,
                    false,
                    &rules,
                    Some(&git)
                )
                .is_err(),
                "whole-repo push mode {mode} must be blocked"
            );
        }
    }

    #[test]
    fn allow_push_blocks_second_refspec_outside_glob() {
        // B3: `git push origin agent/x main` — every refspec must bind, not just
        // the first. No config needed.
        let Some(git) = git_or_skip() else { return };
        let (_t, repo) = scratch_repo("agent/x", "git@github.com:navikt/cplt.git")
            .expect("git present: scratch repo must build");
        let dir = repo.to_string_lossy().into_owned();
        let rules = vec![origin_agent_rule()];
        assert!(
            gate_git_t(
                &["-C", &dir, "push", "origin", "agent/x", "main"],
                true,
                true,
                false,
                &rules,
                Some(&git)
            )
            .is_err(),
            "a second refspec outside the glob must block the push"
        );
    }

    #[test]
    fn allow_push_blocks_config_driven_norefspec_destinations() {
        // B3: no-refspec forms whose real destination is set by config.
        let Some(git) = git_or_skip() else { return };
        let rules = vec![origin_agent_rule()];

        // push.default=matching pushes every same-named branch, incl. main.
        let (_a, r1) = scratch_repo("agent/x", "git@github.com:navikt/cplt.git")
            .expect("git present: scratch repo must build");
        git_setup(&git, &r1, &["config", "push.default", "matching"]);
        let d1 = r1.to_string_lossy().into_owned();
        assert!(
            gate_git_t(
                &["-C", &d1, "push", "origin"],
                true,
                true,
                false,
                &rules,
                Some(&git)
            )
            .is_err(),
            "push.default=matching must block a no-refspec push"
        );

        // A configured push refspec sends `git push origin` outside the glob.
        let (_b, r2) = scratch_repo("agent/x", "git@github.com:navikt/cplt.git")
            .expect("git present: scratch repo must build");
        git_setup(
            &git,
            &r2,
            &["config", "remote.origin.push", "refs/heads/*:refs/heads/*"],
        );
        let d2 = r2.to_string_lossy().into_owned();
        assert!(
            gate_git_t(
                &["-C", &d2, "push", "origin"],
                true,
                true,
                false,
                &rules,
                Some(&git)
            )
            .is_err(),
            "a configured remote.push refspec must block a no-refspec push"
        );

        // push.default=upstream sends the current branch to its merge ref (main).
        let (_c, r3) = scratch_repo("agent/x", "git@github.com:navikt/cplt.git")
            .expect("git present: scratch repo must build");
        git_setup(&git, &r3, &["config", "push.default", "upstream"]);
        git_setup(
            &git,
            &r3,
            &["config", "branch.agent/x.merge", "refs/heads/main"],
        );
        let d3 = r3.to_string_lossy().into_owned();
        assert!(
            gate_git_t(&["-C", &d3, "push"], true, true, false, &rules, Some(&git)).is_err(),
            "push.default=upstream must block a bare push"
        );
    }

    #[test]
    fn sensitive_config_and_repo_override_detection() {
        // Pure parsing: no git needed.
        assert!(
            injected_sensitive_config_key(&["-c", "remote.origin.pushurl=x", "push"]).is_some()
        );
        assert!(injected_sensitive_config_key(&["-c", "push.default=current", "push"]).is_some());
        assert!(injected_sensitive_config_key(&["-c", "url.x.pushInsteadOf=y", "push"]).is_some());
        assert!(
            injected_sensitive_config_key(&["-c", "branch.main.pushRemote=evil", "push"]).is_some()
        );
        assert!(
            injected_sensitive_config_key(&["--config-env", "remote.origin.url=EVIL", "push"])
                .is_some()
        );
        assert!(injected_sensitive_config_key(&["--config-env=push.default=X", "push"]).is_some());
        // Innocuous config and normal pushes are not caught.
        // The refusal quotes the flag back, so detection must report which one
        // was used rather than assuming `-c` (H-10 review).
        assert_eq!(
            injected_sensitive_config_key(&["-c", "push.default=current", "push"])
                .map(|(flag, _)| flag),
            Some("-c")
        );
        assert_eq!(
            injected_sensitive_config_key(&["--config-env", "remote.origin.url=EVIL", "push"])
                .map(|(flag, _)| flag),
            Some("--config-env")
        );
        assert_eq!(
            injected_sensitive_config_key(&["--config-env=push.default=X", "push"])
                .map(|(flag, _)| flag),
            Some("--config-env")
        );

        assert!(injected_sensitive_config_key(&["-c", "core.pager=cat", "push"]).is_none());
        assert!(injected_sensitive_config_key(&["push", "origin", "main"]).is_none());
        assert!(injected_sensitive_config_key(&["-C", "/some/dir", "push"]).is_none());

        // `--repo` is caught without consulting git at all, and reports the
        // destination it names rather than the flag token.
        assert_eq!(
            push_destination_override(&["--repo=https://x", "main"], None, &[]),
            Some("https://x")
        );
        assert_eq!(
            push_destination_override(&["--repo", "https://x"], None, &[]),
            Some("https://x")
        );
        // A positional destination cannot be proven a configured remote without
        // git, so it fails closed.
        assert_eq!(
            push_destination_override(&["origin", "main"], None, &[]),
            Some("origin")
        );
        // No positional at all is a bare `git push` — no destination override.
        assert_eq!(push_destination_override(&["--force"], None, &[]), None);
    }

    #[test]
    fn allow_push_rule_in_gate_git() {
        use crate::config::ResolvedPushRule;

        let Some((_tmp, repo)) = scratch_repo("main", "https://github.com/me/fork.git") else {
            return; // no git available
        };
        let git = which_git().unwrap();
        make_branches(&git, &repo, &["agent/fix-123"]);
        let dir = repo.to_string_lossy().into_owned();
        let rules = vec![ResolvedPushRule {
            remote: Some("origin".to_string()),
            branches: vec!["agent/*".to_string()],
            force: false,
            url: Some(crate::trust::normalize_remote_url(
                "https://github.com/me/fork.git",
            )),
        }];

        // Push to the pinned repository's agent/* is allowed despite prevent_push
        assert!(
            gate_git_t(
                &["-C", &dir, "push", "origin", "agent/fix-123"],
                true,
                true,
                false,
                &rules,
                Some(&git)
            )
            .is_ok()
        );

        // A branch outside the rule is still blocked
        assert!(
            gate_git_t(
                &["-C", &dir, "push", "origin", "main"],
                true,
                true,
                false,
                &rules,
                Some(&git)
            )
            .is_err()
        );
    }

    // GHSA-3m7m-m3rq-5cw8: the first positional of `git push` is git's
    // *repository* argument, never a refspec. Parsing `git@host:path` as a
    // refspec made the destination branch `attacker/x.git`, which matched no
    // protection rule, so the push escaped to another repository entirely —
    // while the default-branch yardstick was still read from `origin`.
    #[test]
    fn push_to_an_explicit_destination_is_blocked() {
        use crate::config::ResolvedPushRule;

        let Some((_tmp, repo)) = scratch_repo("main", "https://github.com/me/fork.git") else {
            return; // no git available
        };
        let git = which_git().unwrap();
        make_branches(&git, &repo, &["agent/fix-123"]);
        let dir = repo.to_string_lossy().into_owned();
        let rules = vec![ResolvedPushRule {
            remote: Some("origin".to_string()),
            branches: vec!["agent/*".to_string()],
            force: false,
            url: Some(crate::trust::normalize_remote_url(
                "https://github.com/me/fork.git",
            )),
        }];
        // The advisory's own configuration: block mode, push and force-push
        // prevented, only the default branch protected.
        let gate = |args: &[&str], rules: &[ResolvedPushRule]| {
            let mut full = vec!["-C", dir.as_str()];
            full.extend_from_slice(args);
            gate_git_t(&full, true, true, true, rules, Some(&git))
        };

        for dest in [
            "git@github.com:attacker/x.git", // scp-style
            "ssh://git@github.com/attacker/x.git",
            "https://github.com/attacker/x.git",
            "file:///tmp/attacker-x.git",
            "../attacker-x.git", // bare filesystem path
            "attacker-x.git",    // …and its slash-less, colon-less form
        ] {
            // Alone, git pushes the current branch to that destination.
            assert!(gate(&["push", dest], &[]).is_err(), "{dest} alone");
            // Followed by a refspec it used to read as an ordinary
            // remote-plus-feature-branch push.
            assert!(
                gate(&["push", dest, "agent/fix-123"], &[]).is_err(),
                "{dest} with refspec"
            );
            // An allow_push rule pinned to origin authorizes origin, not this.
            assert!(
                gate(&["push", dest, "agent/fix-123"], &rules).is_err(),
                "{dest} with an origin-pinned allow_push rule"
            );
        }

        // Git resolves unique abbreviations and bundled short flags; the
        // guard's exact-match parsers do not, and each disagreement moved the
        // destination out of repository position into refspec position, where
        // it read as an ordinary feature branch. Reproduced end to end against
        // real git: `push --rep origin <url> feature` pushed to <url>.
        for opt in ["--rep", "--push-opt", "-vo", "-qo", "-no"] {
            assert!(
                gate(
                    &[
                        "push",
                        opt,
                        "origin",
                        "file:///tmp/attacker-x.git",
                        "agent/fix-123"
                    ],
                    &[]
                )
                .is_err(),
                "{opt} destination override"
            );
        }
        // Same class on the force/whole-repo flags: these defeat
        // `is_force_push_flag` / `is_unconstrainable_push_flag`.
        for opt in ["--forc", "-fu", "--al", "--mir", "--ta"] {
            assert!(
                gate(&["push", opt, "origin", "agent/fix-123"], &[]).is_err(),
                "{opt} force/mode flag"
            );
        }
        // Exact spellings keep working.
        for args in [
            &["push", "-u", "origin", "agent/fix-123"][..],
            &["push", "-q", "-v", "origin", "agent/fix-123"][..],
            &["push", "-n", "origin", "agent/fix-123"][..],
            &["push", "-o", "ci.skip", "origin", "agent/fix-123"][..],
            &["push", "-oci.skip", "origin", "agent/fix-123"][..],
            &["push", "--push-option=ci.skip", "origin", "agent/fix-123"][..],
            &["push", "--set-upstream", "origin", "agent/fix-123"][..],
            &["push", "--no-verify", "origin", "agent/fix-123"][..],
            &["push", "--atomic", "--signed", "origin", "agent/fix-123"][..],
            &[
                "push",
                "--receive-pack=/usr/bin/git-receive-pack",
                "origin",
                "agent/fix-123",
            ][..],
            &[
                "push",
                "--exec=/usr/bin/git-receive-pack",
                "origin",
                "agent/fix-123",
            ][..],
            &["push", "origin", "--", "agent/fix-123"][..],
        ] {
            assert!(gate(args, &[]).is_ok(), "{args:?} must stay allowed");
        }

        // Refspecs stay refspecs from the second positional on.
        assert!(gate(&["push", "origin", "agent/fix-123"], &[]).is_ok());
        assert!(gate(&["push", "origin", "HEAD:refs/heads/agent/fix-123"], &[]).is_ok());
        assert!(gate(&["push", "origin", "agent/fix-123:agent/fix-123"], &[]).is_ok());
        // The pinned allow_push rule still authorizes its own remote.
        assert!(gate(&["push", "origin", "agent/fix-123"], &rules).is_ok());
        // And the protected branch is still refused through that remote.
        assert!(gate(&["push", "origin", "main"], &[]).is_err());
        assert!(gate(&["push", "origin", "main"], &rules).is_err());
    }

    // ── Security fix tests ──────────────────────────────────────────

    #[test]
    fn git_alias_bypass_blocked() {
        // `-c alias.p=push` should be blocked when push prevention is active
        assert!(
            gate_git_t(
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
            gate_git_t(
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
        assert!(
            gate_git(
                &["-c", "ALIAS.p=push", "p"],
                true,
                true,
                false,
                &[],
                None,
                &RepoFacts::default()
            )
            .is_err()
        );
        // Not blocked when push prevention is disabled
        assert!(
            gate_git(
                &["-c", "alias.p=push", "p"],
                false,
                false,
                false,
                &[],
                None,
                &RepoFacts::default()
            )
            .is_ok()
        );
    }

    #[test]
    fn git_subtree_push_blocked() {
        // `git subtree push` is now explicitly blocked
        assert!(
            gate_git_t(
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
            gate_git_t(
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
            gate_git_t(
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
            gate_git_t(
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
        let Some((_tmp, repo)) = scratch_repo("main", "https://github.com/o/o.git") else {
            return; // no git available
        };
        let git = which_git().unwrap();
        make_branches(&git, &repo, &["feature-branch", "my-feature", "feature"]);
        let dir = repo.to_string_lossy().into_owned();
        assert!(
            gate_git_t(
                &["-C", &dir, "push", "origin", "feature-branch"],
                true,
                true,
                true,
                &[],
                Some(&git)
            )
            .is_ok()
        );
        // Force push to feature branch allowed when prevent_force_push=false
        assert!(
            gate_git_t(
                &["-C", &dir, "push", "--force", "origin", "feature-branch"],
                true,
                false,
                true,
                &[],
                Some(&git)
            )
            .is_ok()
        );
    }

    #[test]
    fn git_multiple_refspecs_checked() {
        // `git push origin feature main` should be blocked because "main" is a default branch
        assert!(
            gate_git_t(
                &["push", "origin", "feature", "main"],
                true,
                true,
                true,
                &[],
                None
            )
            .is_err()
        );
        // `git push origin feature develop` — neither is protected here, allowed
        let Some((_tmp, repo)) = scratch_repo("main", "https://github.com/o/o.git") else {
            return; // no git available
        };
        let git = which_git().unwrap();
        make_branches(&git, &repo, &["feature", "develop"]);
        let dir = repo.to_string_lossy().into_owned();
        assert!(
            gate_git_t(
                &["-C", &dir, "push", "origin", "feature", "develop"],
                true,
                true,
                true,
                &[],
                Some(&git)
            )
            .is_ok()
        );
        // `git push origin HEAD:refs/heads/feature HEAD:refs/heads/master` — master is default
        assert!(
            gate_git_t(
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
            gate_git_t(
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
            gate_git_t(
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
            gate_git_t(
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
            gate_git_t(
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
            gate_git_t(
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
        assert!(
            gate_git(
                &["remote", "-v"],
                true,
                true,
                false,
                &[],
                None,
                &RepoFacts::default()
            )
            .is_ok()
        );
        assert!(
            gate_git(
                &["remote"],
                true,
                true,
                false,
                &[],
                None,
                &RepoFacts::default()
            )
            .is_ok()
        );
        assert!(
            gate_git_t(
                &["remote", "get-url", "origin"],
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
                &["remote", "show", "origin"],
                true,
                true,
                false,
                &[],
                None,
                &RepoFacts::default()
            )
            .is_ok()
        );
        assert!(
            gate_git_t(
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
            gate_git_t(
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
        assert!(
            gate_git(
                &["config", "user.name", "x"],
                true,
                true,
                false,
                &[],
                None,
                &RepoFacts::default()
            )
            .is_ok()
        );
    }

    // Finding 2: git's URL-rewrite keys (`url.<base>.insteadOf` /
    // `pushInsteadOf`) persistently redirect where github.com URLs resolve, an
    // equivalent transport-remap vector — they must be blocked like remote URL sets.
    #[test]
    fn git_config_insteadof_rewrite_blocked() {
        // Setting an insteadOf / pushInsteadOf rewrite is blocked.
        assert!(
            gate_git_t(
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
            gate_git_t(
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
            gate_git_t(
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
            gate_git_t(
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
    /// The write form of `git symbolic-ref` on `refs/remotes/<remote>/HEAD` is
    /// the one route to that symref the filesystem cannot deny: on a `reftable`
    /// repository the ref is not a file, so the path deny matches nothing.
    /// Backend-independent by construction — the gate never looks at the disk.
    #[test]
    fn git_symbolic_ref_write_to_remote_head_is_blocked() {
        for args in [
            &[
                "symbolic-ref",
                "refs/remotes/origin/HEAD",
                "refs/remotes/origin/decoy",
            ][..],
            &[
                "symbolic-ref",
                "-m",
                "why",
                "refs/remotes/upstream/HEAD",
                "refs/heads/x",
            ][..],
            &["symbolic-ref", "-d", "refs/remotes/origin/HEAD"][..],
            &["symbolic-ref", "--delete", "-q", "refs/remotes/origin/HEAD"][..],
            &[
                "symbolic-ref",
                "--",
                "refs/remotes/origin/HEAD",
                "refs/heads/x",
            ][..],
            // Bundled shorts and abbreviated longs: git resolves them, an
            // enumerating parser did not. `-qm` is not `-m`, so its reason
            // argument used to become the first positional and hide the ref.
            &[
                "symbolic-ref",
                "-qm",
                "r",
                "refs/remotes/origin/HEAD",
                "refs/remotes/origin/decoy",
            ][..],
            &["symbolic-ref", "-qd", "refs/remotes/origin/HEAD"][..],
            &["symbolic-ref", "-dm", "x", "refs/remotes/origin/HEAD"][..],
            &["symbolic-ref", "--del", "refs/remotes/origin/HEAD"][..],
            &["symbolic-ref", "--d", "refs/remotes/origin/HEAD"][..],
            // An unrecognised flag is a write shape, wherever the ref sits.
            &["symbolic-ref", "-z", "v", "refs/remotes/origin/HEAD"][..],
        ] {
            let err = gate_git(args, true, true, false, &[], None, &RepoFacts::default())
                .expect_err("writing the remote HEAD symref retargets the guard next launch");
            assert!(err.contains("refs/remotes/<remote>/HEAD"), "got: {err}");
        }
        // The read form must keep working: git internals and the launch-time
        // fact capture both use it.
        for args in [
            &["symbolic-ref", "--short", "refs/remotes/origin/HEAD"][..],
            &["symbolic-ref", "refs/remotes/origin/HEAD"][..],
            &["symbolic-ref", "-q", "HEAD"][..],
        ] {
            assert!(
                gate_git(args, true, true, false, &[], None, &RepoFacts::default()).is_ok(),
                "read form must stay allowed: {args:?}"
            );
        }
        // Writes to other refs are not this control's business.
        assert!(
            gate_git(
                &["symbolic-ref", "HEAD", "refs/heads/trunk"],
                true,
                true,
                false,
                &[],
                None,
                &RepoFacts::default()
            )
            .is_ok()
        );
        // Only while a push guard is active.
        assert!(
            gate_git(
                &["symbolic-ref", "refs/remotes/origin/HEAD", "refs/heads/x"],
                false,
                false,
                false,
                &[],
                None,
                &RepoFacts::default()
            )
            .is_ok(),
            "with no push prevention there is no push verdict to protect"
        );
    }

    /// `git remote set-head` writes `refs/remotes/<remote>/HEAD` — one of the
    /// three controls on that symref, alongside the profile's path deny (files
    /// backend only) and the `symbolic-ref` write block above.
    #[test]
    fn git_remote_set_head_is_blocked_while_push_is_prevented() {
        for args in [
            &["remote", "set-head", "origin", "-a"][..],
            &["remote", "set-head", "upstream", "develop"][..],
            &["remote", "-v", "set-head", "origin", "-d"][..],
        ] {
            let err = gate_git(args, true, true, false, &[], None, &RepoFacts::default())
                .expect_err("set-head rewrites the recorded default branch");
            assert!(err.contains("set-head"), "got: {err}");
        }
        // Only while a push guard is active, and only `set-head`.
        assert!(
            gate_git(
                &["remote", "set-head", "origin", "-a"],
                false,
                false,
                false,
                &[],
                None,
                &RepoFacts::default()
            )
            .is_ok(),
            "with no push prevention there is no push verdict to protect"
        );
        assert!(
            gate_git(
                &["remote", "show", "origin"],
                true,
                true,
                false,
                &[],
                None,
                &RepoFacts::default()
            )
            .is_ok(),
            "read-only remote inspection stays allowed"
        );
    }

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
                gate_git(args, true, true, false, &[], None, &RepoFacts::default()).is_ok(),
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
                gate_git(args, true, true, false, &[], None, &RepoFacts::default()).is_err(),
                "expected blocked: git {}",
                args.join(" ")
            );
        }

        // The origin-retarget block also holds under force-push-only policy,
        // and still does not over-block non-origin management there.
        assert!(
            gate_git_t(
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
            gate_git_t(
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
        assert!(
            gate_git(
                &["push", "origin", "+main"],
                true,
                true,
                true,
                &[],
                None,
                &RepoFacts::default()
            )
            .is_err()
        );
        assert!(
            gate_git(
                &["push", "origin", "+master"],
                true,
                true,
                true,
                &[],
                None,
                &RepoFacts::default()
            )
            .is_err()
        );
        assert!(
            gate_git_t(
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
            gate_git_t(
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
            gate_git_t(
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
        assert!(
            gate_git(
                &["push", "origin", "+feature"],
                true,
                true,
                true,
                &[],
                None,
                &RepoFacts::default()
            )
            .is_err()
        );
        let Some((_tmp, repo)) = scratch_repo("main", "https://github.com/o/o.git") else {
            return; // no git available
        };
        let git = which_git().unwrap();
        make_branches(&git, &repo, &["feature"]);
        let dir = repo.to_string_lossy().into_owned();
        assert!(
            gate_git_t(
                &["-C", &dir, "push", "origin", "+feature"],
                true,
                false,
                true,
                &[],
                Some(&git)
            )
            .is_ok()
        );
    }

    // Bug 4: `--force-with-lease`/`--signed` take only `=`-attached values, so
    // they must NOT swallow the following remote/refspec.
    #[test]
    fn git_force_with_lease_space_form_not_value_consuming() {
        use crate::config::ResolvedPushRule;
        // Branches-only rule: this test is about argument parsing, not about
        // which repository a remote name identifies.
        let rules = vec![ResolvedPushRule {
            remote: None,
            branches: vec!["agent/*".to_string()],
            force: true,
            url: None,
        }];
        // Real repo: a colon-less refspec is resolved with `rev-parse`, so the
        // branch has to exist the way it would in practice.
        let Some((_tmp, repo)) = scratch_repo("main", "https://github.com/o/o.git") else {
            return; // no git available
        };
        let git = which_git().unwrap();
        make_branches(&git, &repo, &["agent/x", "agent/y"]);
        let dir = repo.to_string_lossy().into_owned();
        // The remote/branch must parse correctly (not be eaten by --force-with-lease).
        assert!(
            gate_git_t(
                &[
                    "-C",
                    &dir,
                    "push",
                    "--force-with-lease",
                    "origin",
                    "agent/x"
                ],
                true,
                true,
                false,
                &rules,
                Some(&git)
            )
            .is_ok()
        );
        // The flag must not consume the following remote/refspec: the refspec
        // still resolves to the destination branch.
        let repo_args = ["-C", dir.as_str()];
        let dest = |args: &[&str]| match push_target_branches(args, Some(&git), &repo_args) {
            PushTargets::Branches(b) => b,
            PushTargets::Unconstrainable => vec!["<unconstrainable>".to_string()],
        };
        assert_eq!(
            dest(&["--force-with-lease", "origin", "agent/x"]),
            vec!["agent/x".to_string()]
        );
        assert_eq!(
            dest(&["--signed", "origin", "agent/y"]),
            vec!["agent/y".to_string()]
        );
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
            gate_git_t(
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
            gate_git_t(
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
            gate_git_t(
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
            gate_git_t(
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

    // ── GHSA-cm6f-3wjh-x9qx: the default branch is a launch-time fact ──

    /// Run git in `repo` with the hermetic env the other fixtures use.
    fn run_in(git: &Path, repo: &Path, args: &[&str]) -> bool {
        std::process::Command::new(git)
            .args(["-C", repo.to_str().unwrap()])
            .args(args)
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .output()
            .expect("git must run")
            .status
            .success()
    }

    /// The advisory, verbatim: default branch `trunk`, stock configuration.
    /// `git push origin trunk` is refused; the agent rewrites
    /// `refs/remotes/origin/HEAD` (an ordinary ref file, `symbolic-ref` is an
    /// allowed subcommand) and the push must still be refused, because the
    /// guard reads the branch it was handed at launch and never asks the
    /// repository again.
    #[test]
    fn a_rewritten_remote_head_no_longer_changes_the_verdict() {
        let Some((_tmp, repo)) =
            scratch_repo_with_default("trunk", "https://github.com/o/o.git", "trunk")
        else {
            return; // no git available
        };
        let git = which_git().unwrap();
        make_branches(&git, &repo, &["decoy"]);

        // Captured in the parent, before the sandbox starts.
        let facts = capture_repo_facts(&git, &repo);
        assert_eq!(
            facts.default_branches.get("origin").map(String::as_str),
            Some("trunk"),
            "the fixture must record refs/remotes/origin/HEAD -> origin/trunk"
        );

        let dir = repo.to_string_lossy().into_owned();
        let push_trunk = |facts: &RepoFacts| {
            gate_git(
                &["-C", dir.as_str(), "push", "origin", "trunk"],
                true,
                true,
                true,
                &[],
                Some(&git),
                facts,
            )
        };
        assert!(
            push_trunk(&facts).is_err(),
            "a push to the real default branch must be refused"
        );

        // The exploit step.
        assert!(
            run_in(
                &git,
                &repo,
                &[
                    "symbolic-ref",
                    "refs/remotes/origin/HEAD",
                    "refs/remotes/origin/decoy",
                ],
            ),
            "the fixture must be able to rewrite the symref"
        );
        assert_eq!(
            resolve_default_branch(&git, &["-C", dir.as_str()], "origin").as_deref(),
            Some("decoy"),
            "the rewrite must have taken effect, or this test proves nothing"
        );

        assert!(
            push_trunk(&facts).is_err(),
            "the baked default branch must survive a refs/remotes/origin/HEAD rewrite"
        );
        // …and the decoy the agent planted gains no protection it should not
        // have: a feature branch is still pushable.
        assert!(
            gate_git(
                &["-C", dir.as_str(), "push", "origin", "decoy"],
                true,
                true,
                true,
                &[],
                Some(&git),
                &facts,
            )
            .is_ok(),
            "a feature-branch push must still be allowed after the rewrite"
        );
    }

    /// With no baked answer the guard cannot tell a feature branch from the
    /// protected one, so every push is refused — and says why.
    #[test]
    fn a_default_branch_absent_at_launch_fails_closed() {
        let Some((_tmp, repo)) =
            scratch_repo_with_default("trunk", "https://github.com/o/o.git", "trunk")
        else {
            return; // no git available
        };
        let git = which_git().unwrap();
        make_branches(&git, &repo, &["feature/x"]);
        // A repository with no recorded `refs/remotes/origin/HEAD` — `git init`
        // plus `git remote add`, the shape `git clone` does not produce.
        assert!(run_in(
            &git,
            &repo,
            &["symbolic-ref", "--delete", "refs/remotes/origin/HEAD"],
        ));
        let facts = capture_repo_facts(&git, &repo);
        assert!(facts.default_branches.is_empty(), "nothing to bake");
        let dir = repo.to_string_lossy().into_owned();
        let err = gate_git(
            &["-C", dir.as_str(), "push", "origin", "feature/x"],
            true,
            true,
            true,
            &[],
            Some(&git),
            &facts,
        )
        .expect_err("no baked default branch must refuse, not fall back to allowing");
        assert!(
            err.contains("could not be determined when this session started"),
            "the refusal must name the missing launch-time fact, got: {err}"
        );
    }

    /// `main`/`master` stay protected unconditionally — with baked facts, and
    /// with none at all.
    #[test]
    fn main_and_master_stay_protected_whatever_the_baked_facts_say() {
        let Some((_tmp, repo)) =
            scratch_repo_with_default("trunk", "https://github.com/o/o.git", "trunk")
        else {
            return; // no git available
        };
        let git = which_git().unwrap();
        make_branches(&git, &repo, &["main", "master"]);
        let facts = capture_repo_facts(&git, &repo);
        let dir = repo.to_string_lossy().into_owned();
        for branch in ["main", "master"] {
            let unknown = RepoFacts {
                project_dir: facts.project_dir.clone(),
                ..RepoFacts::default()
            };
            for facts in [&facts, &unknown] {
                assert!(
                    gate_git(
                        &["-C", dir.as_str(), "push", "origin", branch],
                        true,
                        true,
                        true,
                        &[],
                        Some(&git),
                        facts,
                    )
                    .is_err(),
                    "'{branch}' must stay protected even where the default branch is 'trunk'"
                );
            }
        }
    }

    /// The baked facts describe the launch repository. A `-C` pointing
    /// somewhere else is not covered by them, and re-deriving the answer from
    /// that repository is the hole being closed — so it fails closed (#215).
    #[test]
    fn facts_do_not_travel_to_another_repository() {
        let Some((_tmp, repo)) =
            scratch_repo_with_default("trunk", "https://github.com/o/o.git", "trunk")
        else {
            return; // no git available
        };
        let Some((_tmp2, other)) =
            scratch_repo_with_default("trunk", "https://github.com/o/other.git", "trunk")
        else {
            return;
        };
        let git = which_git().unwrap();
        make_branches(&git, &other, &["feature/x"]);
        let facts = capture_repo_facts(&git, &repo);
        let here = repo.to_string_lossy().into_owned();
        let there = other.to_string_lossy().into_owned();

        // `-C <the launch repo>` is still described by the facts.
        make_branches(&git, &repo, &["feature/x"]);
        assert!(
            gate_git(
                &["-C", here.as_str(), "push", "origin", "feature/x"],
                true,
                true,
                true,
                &[],
                Some(&git),
                &facts,
            )
            .is_ok(),
            "a -C naming the launch repository must use its baked facts"
        );

        let err = gate_git(
            &["-C", there.as_str(), "push", "origin", "feature/x"],
            true,
            true,
            true,
            &[],
            Some(&git),
            &facts,
        )
        .expect_err("another repository has no baked default branch");
        assert!(
            err.contains("redirects git elsewhere"),
            "the refusal must say the facts do not cover that repository, got: {err}"
        );
    }

    /// A bare `git push` follows git's own remote resolution, so the branch
    /// yardstick must come from the remote the push actually lands on. Looking
    /// up `origin`'s default branch while `remote.pushDefault` sends the push
    /// to `upstream` let the agent choose *which remote's* yardstick the guard
    /// consulted, and pushed straight to upstream's default branch.
    #[test]
    fn a_bare_push_is_judged_by_the_remote_it_actually_reaches() {
        let Some((_tmp, repo)) =
            scratch_repo_with_default("develop", "https://github.com/o/o.git", "trunk")
        else {
            return; // no git available
        };
        let git = which_git().unwrap();
        let dir = repo.to_string_lossy().into_owned();
        let repo_args = ["-C", dir.as_str()];
        let run = |args: &[&str]| {
            let ok = std::process::Command::new(&git)
                .args(repo_args)
                .args(args)
                .env("GIT_CONFIG_GLOBAL", "/dev/null")
                .env("GIT_CONFIG_NOSYSTEM", "1")
                .output()
                .expect("git must run")
                .status
                .success();
            assert!(ok, "git {args:?} must succeed");
        };
        // Two remotes with different default branches: origin/trunk (already
        // recorded by the fixture) and upstream/develop.
        run(&["remote", "add", "upstream", "https://github.com/o/up.git"]);
        run(&[
            "symbolic-ref",
            "refs/remotes/upstream/HEAD",
            "refs/remotes/upstream/develop",
        ]);
        // Both remotes' facts are baked, so nothing here fails closed merely
        // for want of an answer.
        let facts = capture_repo_facts(&git, &repo);
        assert_eq!(
            facts.default_branch("origin", &repo_args, Some(&git)),
            Some("trunk")
        );
        assert_eq!(
            facts.default_branch("upstream", &repo_args, Some(&git)),
            Some("develop")
        );

        // Both settings are allowed by the gate; together they send a bare push
        // on `develop` to `upstream`, where `develop` IS the default branch.
        run(&["config", "remote.pushDefault", "upstream"]);
        run(&["config", "push.default", "current"]);
        let gate = |args: &[&str]| {
            let mut full = vec!["-C", dir.as_str()];
            full.extend_from_slice(args);
            gate_git(&full, true, true, true, &[], Some(&git), &facts)
        };

        gate(&["push"]).expect_err(
            "a bare push to upstream's default branch must be blocked, not judged by origin",
        );
        // The relaxation still works: a feature branch on the same remote goes
        // through, so this is not a blanket refusal of bare pushes.
        run(&["checkout", "-q", "-b", "feature/x"]);
        gate(&["push"]).expect("a bare push to a feature branch is still allowed");
        // And origin's own yardstick still applies when origin is named.
        gate(&["push", "origin", "trunk"]).expect_err("origin/trunk is protected as before");
        gate(&["push", "origin", "develop"])
            .expect("develop is an ordinary branch on origin, whose default is trunk");
    }

    /// The baked facts reach the guard through the wrapper, spelled like the
    /// flags beside them.
    #[test]
    fn the_wrapper_bakes_the_repository_facts() {
        let policy = crate::config::GitGuardPolicy {
            protect_default_branch_only: true,
            ..Default::default()
        };
        let mut facts = RepoFacts::default();
        facts
            .default_branches
            .insert("origin".to_string(), "trunk".to_string());
        let script =
            generate_git_wrapper_script("/usr/bin/git", "/usr/local/bin/cplt", &policy, &facts);
        assert!(
            script.contains("--repo-facts='"),
            "the wrapper must carry the launch-time facts: {script}"
        );
        assert!(
            script.contains("\"trunk\""),
            "…including the branch: {script}"
        );
        // Nothing to bake → no flag, and the gate fails closed on its absence.
        let empty = generate_git_wrapper_script(
            "/usr/bin/git",
            "/usr/local/bin/cplt",
            &policy,
            &RepoFacts::default(),
        );
        assert!(!empty.contains("--repo-facts"), "got: {empty}");
    }
}
