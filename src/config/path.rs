//! Config file path resolution.

use std::path::{Component, Path, PathBuf};

use super::error::ConfigError;
use super::types::{CONFIG_DIR, CONFIG_FILE};

/// Return the config file path.
/// Checks `CPLT_CONFIG` env var first, then `~/.config/cplt/config.toml`.
pub fn config_path() -> Option<PathBuf> {
    if let Ok(custom) = std::env::var("CPLT_CONFIG") {
        return Some(expand_tilde(&custom));
    }
    std::env::var("HOME")
        .ok()
        .map(|h| PathBuf::from(h).join(CONFIG_DIR).join(CONFIG_FILE))
}

/// Return the cplt config directory path (`~/.config/cplt/`).
pub fn config_dir() -> Option<PathBuf> {
    if let Ok(custom) = std::env::var("CPLT_CONFIG") {
        // If custom config path is set, use its parent directory
        return expand_tilde(&custom)
            .parent()
            .map(std::path::Path::to_path_buf);
    }
    std::env::var("HOME")
        .ok()
        .map(|h| PathBuf::from(h).join(CONFIG_DIR))
}

/// Generate a default config file with comments explaining each option.
pub fn default_config_contents() -> String {
    r#"# cplt configuration
#
# This file configures default behavior for cplt.
# CLI flags always override these settings.
# Location: ~/.config/cplt/config.toml
# Override: CPLT_CONFIG=/path/to/config.toml

# ─── Proxy ───────────────────────────────────────────────────
# CONNECT proxy that logs and filters outbound HTTPS connections.
# Enabled by default. HTTP_PROXY/HTTPS_PROXY and NODE_USE_ENV_PROXY=1 are
# injected so all traffic (Copilot, gh, curl) routes through the proxy.
# The proxy enforces the same port policy as the sandbox (443 + allow-port).
# Disable with --no-proxy or set enabled = false below.
[proxy]
# enabled = true
# Force all egress through the proxy: makes the proxy mandatory and restricts
# kernel-level egress to the proxy port only (no direct *:443). Fails closed.
# If the proxy cannot start, the agent is not launched. (default: false)
# forced = false
# port = 0  # 0 = OS-assigned ephemeral port (avoids conflicts, default)
# blocked_domains = "~/.config/cplt/blocked-domains.txt"
# allowed_domains = "~/.config/cplt/allowed-domains.txt"
# Fail-closed networking (opt-in, default: false). When true, egress is
# restricted to the agent's built-in default allowlist (GitHub Copilot infra +
# package registries for Copilot) merged with allowed_domains above; every other
# domain is blocked. Override for a single run with --allow-all-domains.
# default_allowlist = false
# log_file = "~/.config/cplt/proxy.log"
# Stderr verbosity: "none" (default/silent), "error", "blocked", or "all".
# The log_file always records everything regardless of this setting.
# log_level = "none"
# Domains allowed to resolve to private/internal IPs (bypasses DNS-rebinding block).
# Use for corporate internal services, e.g. MCP servers on your company's intranet.
# Suffix matching: "intern.nav.no" covers all its subdomains.
# allow_private_domains = ["intern.nav.no"]
# Upstream (corporate) proxy to forward CONNECT tunnels through. When set, cplt
# keeps enforcing ALL of its domain filtering, logging, and port checks first,
# then forwards approved tunnels to this proxy instead of connecting directly.
# Optional basic auth: "http://user:pass@host:8080". Only the http scheme is supported.
# upstream = "http://corporate-proxy.example.com:8080"
# Hosts that BYPASS the upstream proxy and are connected to directly (like
# NO_PROXY). Only meaningful together with `upstream`. Suffix matching:
# "example.com" covers all its subdomains. The ambient NO_PROXY/no_proxy env var
# is merged in automatically. All of cplt's domain/port/SSRF filtering still
# applies. A listed host is just connected directly instead of forwarded.
# upstream_no_proxy = ["internal.example.com"]
#
# Subscribable blocklists. GLOBAL-only, tighten-only, opt-in. No
# subscription is enabled by default, so leaving this unset keeps today's
# behavior. Cached lists are UNIONed into the effective blocklist (they can only
# ADD blocks). Fetch with `cplt update-lists`. A fetch/verify failure falls back
# to the last-good cache (fail-open); an entry may pin a sha256 (recommended),
# and a hash mismatch rejects the update with a tamper warning.
# [proxy.subscriptions]
# refresh = "manual"   # "manual" (default), "daily", or "weekly"
# blocklists = [
#     # cplt-maintained default blocklist (opt-in, add it yourself):
#     "https://raw.githubusercontent.com/navikt/cplt/main/blocked-domains.txt",
#     # Pin a sha256 to reject tampered downloads:
#     # { url = "https://example.com/blocklist.txt", sha256 = "<64-hex>" },
# ]

# ─── Allowed paths ──────────────────────────────────────────
# Additional paths the sandboxed process may access.
# These are merged with any --allow-read / --allow-write CLI flags.
# Tilde (~/) is expanded to $HOME.
# Relative paths are resolved from this config file's directory.
[allow]
# read = [
#     "~/some/reference/docs",
# ]
# write = []
#
# Additional outbound TCP ports beyond 443.
# Use for external services.
# ports = [8080]
#
# Localhost ports to allow (localhost is blocked by default).
# Use for MCP servers, dev servers, or local APIs.
# localhost = [3000, 8080]
#
# Unix socket paths to allow access to.
# socket = [
#     "/var/run/docker.sock",
#     "~/.codex/codex-lsp/daemon/daemon.sock",
# ]

# ─── Denied paths ───────────────────────────────────────────
# Additional paths to explicitly block (overrides allows).
# Merged with any --deny-path CLI flags.
# WARNING: paths that cannot be resolved will cause a startup error
# (silently dropping deny rules is a security risk).
[deny]
# paths = [
#     "~/.config/gcloud",
#     "~/.config/op",
# ]

# ─── Sandbox behavior ───────────────────────────────────────
[sandbox]
# Preferred AI coding agent. Auto-detected from PATH if not set.
# Supported: copilot, opencode, gemini, antigravity, pi, claude, goose, shell
# agent = "copilot"
#
# Named policy preset. Sets a baseline for the five sandbox toggles below
# (allow_localhost_any, allow_env_files, allow_tmp_exec, allow_docker,
# allow_lifecycle_scripts). Individual keys still override the preset.
#   strict      = all five off (deny-default)
#   standard    = current defaults (all five off, scratch dir stays on)
#   permissive  = localhost + tmp exec + lifecycle scripts on
#   full-trust  = all five on
# Omit for "standard" (a no-op baseline). E.g. permissive but keep tmp exec off:
#   preset = "permissive"
#   allow_tmp_exec = false
# preset = "standard"
#
# Run sandbox-exec validation test on every launch (default: true).
# Disable to save ~200ms startup if you trust your config.
# validate = true
#
# Allow Copilot to read .env files and private keys (.pem, .key)
# in the project directory. Blocked by default, because these often contain
# secrets that a rogue agent could exfiltrate via HTTPS.
# allow_env_files = false
#
# Allow npm/yarn/pnpm lifecycle scripts (postinstall hooks) to run.
# Blocked by default. Supply chain attacks (e.g. axios March 2026)
# use postinstall hooks to execute malicious payloads.
# allow_lifecycle_scripts = false
#
# DANGEROUS: Allow GPG commit/tag signing inside the sandbox.
# Exposes the GPG agent socket so gpg can request signatures.
# Private keys stay protected. Only the public keyring and agent
# socket are reachable. A compromised process cannot extract the key,
# but it CAN request arbitrary signatures while the session is active.
# allow_gpg_signing = false
#
# Allow JVM Attach API unix sockets in /tmp.
# Needed for JVM testing frameworks that use runtime self-attach:
# MockK inline mocking, Mockito inline agents, ByteBuddy, JMX tools.
# Only allows sockets matching /tmp/.java_pid<PID>. The SSH agent and
# all other unix sockets in /tmp stay blocked.
# Enable this if you work with Kotlin/Java projects that use inline mocking.
# allow_jvm_attach = false
#
# Allow MSBuild worker-node unix sockets in /tmp.
# Needed for `dotnet build`, which forks worker nodes that communicate with
# the client over a Unix domain socket at /tmp/MSBuild<PID>.
# This does NOT allow the persistent MSBuild Server (MSBuildServer-<hash>),
# which stays blocked. cplt also disables reuse of that server via
# DOTNET_CLI_DO_NOT_USE_MSBUILD_SERVER=1. The SSH agent and all other unix
# sockets in /tmp stay blocked.
# Enable this if you work with .NET/MSBuild projects.
# allow_msbuild = false
#
# DANGEROUS: Allow Docker/Colima/OrbStack access inside the sandbox.
# Exposes ~/.docker config (read-only) and Docker daemon unix sockets.
# WARNING: Docker container volumes can mount any host path, completely
# bypassing sandbox filesystem restrictions. Only enable if you trust
# the agent's container usage.
# allow_docker = false
#
# Allow outbound TCP to localhost on ALL ports.
# Needed for build tools like Turbopack (Next.js), Vite, and esbuild
# that spawn workers communicating via TCP on random localhost ports.
# allow_localhost_any = false
#
# Extra environment variables to pass through to the sandbox.
# By default, only a safe allowlist is passed (PATH, HOME, TERM, etc.)
# and cloud credentials are stripped. Use this for tool-specific vars.
# pass_env = ["MY_API_KEY", "CUSTOM_TOOL_CONFIG"]
#
# DANGEROUS: Inherit ALL environment variables (disables sanitization).
# Cloud credentials, npm tokens, database URLs, etc. will be visible.
# inherit_env = false
#
# Enable per-session scratch directory for TMPDIR redirect (default: true).
# Creates ~/.cache/cplt/tmp/{session}/ (Linux) or
# ~/Library/Caches/cplt/tmp/{session}/ (macOS) with write+exec permissions
# so tools like `go test`, `mise` inline tasks, and `node-gyp` can work.
# Cleaned up automatically on exit.
# scratch_dir = true
#
# Print the post-session project-change audit report (default: true). After the
# sandboxed agent exits, cplt diffs the working tree against a pinned baseline
# commit captured before the run and prints the net file changes to stderr,
# flagging sensitive paths (CI/CD, Dockerfiles, lockfiles, scripts, .env, etc.).
# Measured outside the sandbox, so it is not affected by commits/resets inside
# the session. Suppressed by quiet or --no-audit.
# audit = true
#
# Linux only: wrap the sandbox in Bubblewrap namespaces for defense-in-depth
# (PID/IPC/UTS/cgroup/user namespaces plus a private /tmp). The host network
# is shared so the filtering proxy keeps working. Unset = auto-detect: uses
# bwrap when installed, falls back to Landlock + seccomp-BPF otherwise.
# Set false to never use bwrap, true to require it (error if missing).
# use_bubblewrap = true
#
# DANGEROUS: Allow process execution from system temp directories.
# Re-enables exec from /tmp (Linux) or /private/tmp, /private/var/folders (macOS).
# Prefer scratch_dir which creates a controlled executable temp dir.
# allow_tmp_exec = false
#
# Allow process execution from specific ~/Library/Caches subdirectories.
# By default, exec is blocked from ~/Library/Caches to prevent binary-drop
# staging attacks. Use this to unblock specific tools that store and run
# executables there, such as Playwright browsers or pnpm dlx cached packages.
# Example: allow_cache_exec = ["ms-playwright"]
# allow_cache_exec = []
#
# DANGEROUS: Allow process execution from ALL ~/Library/Caches subdirectories.
# Much broader than allow_cache_exec. Prefer specifying exact subdirs.
# allow_cache_exec_any = false
#
# Allow the agent to open URLs in your default browser.
# Needed for OAuth code flows (MCP servers, Antigravity, gh auth login).
# Disabled by default because it lets the agent use your browser session.
# allow_browser = false
#
# EXPERIMENTAL. Drop the macOS Keychain grant for runs where the agent has a
# credential it can reach without it (a token in the environment, or in
# Antigravity's case its own fallback token file). The grant cannot be narrowed
# to one item, so it otherwise reaches every keychain entry the agent can
# unlock. Off by default: if it misjudges an agent you can neither authenticate
# nor re-authenticate from inside the sandbox. Unset it to get the grant back.
# keychain_substitute = false
#
# Suppress the startup configuration summary and non-essential messages.
# Errors and warnings are always shown. Useful once you've reviewed the
# sandbox settings and don't need to see them every time.
# Override with --no-quiet for a single run.
# quiet = false

# ── gh CLI proxy ────────────────────────────────────────────────────────────
# Intercepts `gh` commands and enforces a command-level policy.
# [gh_guard]
# enabled = false             # enable the proxy (blocks destructive GitHub operations)
# mode = "block"              # "block" | "warn" | "audit"
# scope_check = true          # enforce same-repo check on write commands
# block_auth_token = true     # deny 'gh auth token' exfiltration
# inject_token = false        # pre-inject GH_TOKEN into sandbox (opt-in)
# unknown_command = "block"   # policy for commands not in classification table
# allow_api_write = false     # allow gh api POST/PATCH/PUT to current repo (opt-in)

# ── git guard ───────────────────────────────────────────────────────────────
# Intercepts `git` commands to prevent accidental pushes.
# [git_guard]
# enabled = false             # enable git command interception
# mode = "block"              # "block" | "warn" | "audit"
# prevent_push = true         # block push, request-pull, send-pack
# prevent_force_push = true   # block force push (only when prevent_push = false)
# [[git_guard.allow_push]]   # structured push exceptions
# remote = "fork"
# branches = ["agent/*"]
# force = false

# ── audit logging ───────────────────────────────────────────────────────────
# Global audit log for all sandbox gate decisions.
# [audit]
# enabled = false
# destination = "stderr"      # "stderr" or file path
# level = "blocked"           # "blocked" | "decisions" | "all"
# format = "text"             # "text" | "jsonl"
"#
    .to_string()
}

/// Expand leading `~/` to `$HOME/`. Only this form is supported.
pub fn expand_tilde(path: &str) -> PathBuf {
    if let Some(rest) = path.strip_prefix("~/") {
        if let Ok(home) = std::env::var("HOME") {
            return PathBuf::from(home).join(rest);
        }
    } else if path == "~"
        && let Ok(home) = std::env::var("HOME")
    {
        return PathBuf::from(home);
    }
    PathBuf::from(path)
}

/// Replace the user's home directory prefix with `~` for portable storage.
/// Only collapses exact `$HOME` or `$HOME/...` boundaries (component-aware).
/// Returns the original string unchanged if it doesn't start with `$HOME`.
pub fn collapse_tilde(path: &str) -> String {
    let Ok(home) = std::env::var("HOME") else {
        return path.to_string();
    };
    let home_path = std::path::Path::new(&home);
    let input_path = std::path::Path::new(path);
    if let Ok(rest) = input_path.strip_prefix(home_path) {
        if rest.as_os_str().is_empty() {
            "~".to_string()
        } else {
            format!("~/{}", rest.display())
        }
    } else {
        path.to_string()
    }
}

/// Drop `CurDir` components and collapse separators. Purely lexical: it cannot
/// fail and touches nothing on disk.
///
/// `..` never reaches here — `repo_config::reject_path_traversal` rejects it at
/// parse time — so no `ParentDir` handling is needed. `Path::components` already
/// collapses `a//b` and a trailing `/`, and drops interior `.`; a *leading* `./`
/// is the one it deliberately preserves, hence the filter.
pub(crate) fn lexically_normalized(path: &Path) -> PathBuf {
    path.components()
        .filter(|c| !matches!(c, Component::CurDir))
        .collect()
}

/// Canonicalize as much of `path` as exists, then re-append the rest.
///
/// `Path::canonicalize` is all-or-nothing: one absent component and it fails for
/// the whole path. Falling back to the unresolved path is unsound the moment a
/// symlink sits *above* the absent part — `link/secret` with `link -> real` and
/// no `secret` yet emits a rule naming `link/secret`, which Seatbelt matches
/// against nothing (verified: it blocks reads of neither `link/secret` nor
/// `real/secret`, while a rule naming `real/secret` blocks both).
///
/// Walking up to the deepest existing ancestor resolves that symlink while
/// keeping the not-yet-created tail, so the rule names where the file will
/// actually land. This also covers a canonicalize failure that is not ENOENT —
/// a permission-denied ancestor, or ELOOP — where the unresolved fallback would
/// likewise name a path the kernel never matches.
fn canonicalize_deepest(path: &Path) -> PathBuf {
    let mut tail: Vec<&std::ffi::OsStr> = Vec::new();
    let mut cur = path;
    loop {
        if let Ok(base) = cur.canonicalize() {
            return tail.iter().rev().fold(base, |acc, part| acc.join(part));
        }
        // Nothing along the whole path resolved (only reachable if even `/`
        // fails to canonicalize) — keep the lexical form rather than drop it.
        let (Some(parent), Some(name)) = (cur.parent(), cur.file_name()) else {
            return path.to_path_buf();
        };
        tail.push(name);
        cur = parent;
    }
}

/// Resolve a path from a repo `.cplt.toml` into one the sandbox backends can
/// actually enforce: expand a leading `~/`, normalize lexically, anchor a
/// still-relative path to `config_dir` (the directory the `.cplt.toml` came
/// from), then canonicalize as deep as the path exists.
///
/// Every step closes a fail-open. Seatbelt silently accepts a rule it cannot
/// match, so an unenforceable path looks enforced in `--print-profile`:
///
/// | spelling        | emitted verbatim   | enforced by Seatbelt |
/// |-----------------|--------------------|----------------------|
/// | `secrets`       | relative           | no                   |
/// | `./secrets`     | `/repo/./secrets`  | no                   |
/// | `secrets/.`     | `/repo/secrets/.`  | no                   |
/// | `a//b`          | `/repo/a//b`       | no                   |
/// | a symlink       | the link path      | no (SBPL matches the resolved path) |
/// | `link/secret`   | the link path      | no, even though the leaf is absent   |
///
/// Anchoring relative paths is also what the global config already promises for
/// its own entries ("Relative paths are resolved from this config file's
/// directory").
///
/// Repo config is the only source that can deny a path that does not exist yet
/// (macOS starts enforcing once it appears), so neither step may fail the entry:
/// the lexical pass needs nothing on disk, and `canonicalize_deepest` resolves
/// as much as is there. Nothing can be dropped, so nothing can be silently
/// unenforced.
///
/// The lexical pass is belt-and-braces here — `canonicalize_deepest` walks by
/// `parent()`/`file_name()`, which are component-based and would drop `.` and
/// `//` on their own. It is kept so the invariant holds without depending on
/// that, and it is load-bearing in `repo_config::reject_root_path`, which needs
/// to spot a root-equal entry before anything touches the disk.
pub(super) fn resolve_repo_path(path: &str, config_dir: &Path) -> PathBuf {
    let normalized = lexically_normalized(&expand_tilde(path));
    let full = if normalized.is_relative() {
        config_dir.join(normalized)
    } else {
        normalized
    };
    canonicalize_deepest(&full)
}

/// Expand tilde, resolve relative paths against config dir, and canonicalize.
pub(super) fn resolve_config_path(
    path: &str,
    config_dir: Option<&PathBuf>,
) -> Result<PathBuf, ConfigError> {
    let expanded = expand_tilde(path);

    // If relative and we know the config dir, resolve from there
    let full = if expanded.is_relative() {
        if let Some(dir) = config_dir {
            dir.join(&expanded)
        } else {
            expanded
        }
    } else {
        expanded
    };

    std::fs::canonicalize(&full).map_err(|_| {
        ConfigError::Validation(format!(
            "path does not exist or is inaccessible: {}",
            full.display()
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expand_tilde_replaces_home() {
        let expanded = expand_tilde("~/some/path");
        let home = std::env::var("HOME").unwrap();
        assert_eq!(expanded, PathBuf::from(format!("{home}/some/path")));
    }

    #[test]
    fn expand_tilde_bare() {
        let expanded = expand_tilde("~");
        let home = std::env::var("HOME").unwrap();
        assert_eq!(expanded, PathBuf::from(home));
    }

    #[test]
    fn expand_tilde_no_tilde() {
        let expanded = expand_tilde("/absolute/path");
        assert_eq!(expanded, PathBuf::from("/absolute/path"));
    }

    #[test]
    fn expand_tilde_not_at_start() {
        // Only leading ~/ is expanded; mid-path ~ is left alone
        let expanded = expand_tilde("some/~/path");
        assert_eq!(expanded, PathBuf::from("some/~/path"));
    }

    #[test]
    fn default_config_contents_is_valid_toml() {
        use crate::config::Config;
        let contents = default_config_contents();
        let config: Config = toml::from_str(&contents).unwrap();
        assert!(config.proxy.enabled.is_none());
    }

    #[test]
    fn resolve_repo_path_anchors_relative_to_repo_root() {
        // Issue #179: a relative repo-config path used to reach the sandbox
        // verbatim. Seatbelt compiles `(subpath "secrets")` and matches
        // nothing; Landlock/bwrap drop it. Both are silent fail-open.
        assert_eq!(
            resolve_repo_path("secrets", Path::new("/nonexistent-repo")),
            PathBuf::from("/nonexistent-repo/secrets")
        );
        assert_eq!(
            resolve_repo_path("a/b/c.txt", Path::new("/nonexistent-repo")),
            PathBuf::from("/nonexistent-repo/a/b/c.txt")
        );
    }

    #[test]
    fn resolve_repo_path_normalizes_every_inert_spelling() {
        // Verified against the kernel: `(subpath "<d>/./x")`, `"<d>/x/."` and
        // `"<d>//x"` are all accepted by Seatbelt and match nothing, so each
        // must collapse to the one form that is actually enforced. These use a
        // non-existent root deliberately — canonicalize cannot run, so this
        // pins the lexical pass on its own.
        let root = Path::new("/nonexistent-repo");
        let want = PathBuf::from("/nonexistent-repo/secrets");
        for spelling in [
            "secrets",
            "./secrets",
            "secrets/.",
            "secrets/",
            "./secrets/",
        ] {
            assert_eq!(
                resolve_repo_path(spelling, root),
                want,
                "{spelling:?} must normalize to the enforceable form"
            );
        }
        assert_eq!(
            resolve_repo_path("a//b", root),
            PathBuf::from("/nonexistent-repo/a/b")
        );
        // A bare `.` means the repo root itself, not a stray relative fragment.
        assert_eq!(resolve_repo_path("./", root), root);
    }

    #[test]
    fn resolve_repo_path_canonicalizes_when_the_target_exists() {
        // SBPL matches resolved paths, so a deny naming a symlink protects
        // nothing. Canonicalize closes that wherever the target is already on
        // disk — the half of the job the lexical pass cannot do.
        let tmp = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(tmp.path()).unwrap();
        std::fs::create_dir(root.join("real")).unwrap();
        std::os::unix::fs::symlink("real", root.join("link")).unwrap();

        assert_eq!(resolve_repo_path("link", &root), root.join("real"));
        assert_eq!(resolve_repo_path("./link/", &root), root.join("real"));
    }

    #[test]
    fn resolve_repo_path_resolves_a_symlink_above_an_absent_leaf() {
        // The not-yet-created case is only sound when the lexical location
        // equals the future resolved location. A symlink ABOVE the absent leaf
        // breaks that: `canonicalize` fails on the whole path, and naming
        // `link/secret` gives a rule Seatbelt matches against nothing —
        // verified: it blocks reads of neither `link/secret` nor `real/secret`,
        // while naming `real/secret` blocks both. So resolve the deepest
        // existing ancestor and re-append the tail.
        let tmp = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(tmp.path()).unwrap();
        std::fs::create_dir(root.join("real")).unwrap();
        std::os::unix::fs::symlink("real", root.join("link")).unwrap();

        // `secret` does not exist yet — the leaf must survive, the link must not.
        assert_eq!(
            resolve_repo_path("link/secret", &root),
            root.join("real/secret")
        );
        // Several absent levels below the symlink.
        assert_eq!(
            resolve_repo_path("./link/a/b/c", &root),
            root.join("real/a/b/c")
        );
        // And once the leaf exists, the answer does not move.
        std::fs::create_dir(root.join("real/secret")).unwrap();
        assert_eq!(
            resolve_repo_path("link/secret", &root),
            root.join("real/secret")
        );
    }

    #[test]
    fn resolve_repo_path_leaves_absolute_and_tilde_alone() {
        let home = std::env::var("HOME").unwrap();
        assert_eq!(
            resolve_repo_path("/nonexistent-abs/shadow", Path::new("/nonexistent-repo")),
            PathBuf::from("/nonexistent-abs/shadow")
        );
        assert_eq!(
            resolve_repo_path("~/nonexistent-secrets", Path::new("/nonexistent-repo")),
            PathBuf::from(format!("{home}/nonexistent-secrets"))
        );
    }

    #[test]
    fn resolve_repo_path_keeps_paths_that_do_not_exist_yet() {
        // canonicalize FAILS on a path that is not there yet, and repo config is
        // the only source that can deny one (macOS starts enforcing once it
        // appears). So the lexical pass runs first and unconditionally: falling
        // back to the raw join on a canonicalize failure would leave `./x`
        // inert for exactly the not-yet-created case this supports.
        for spelling in ["not/created/yet", "./not/created/yet", "not//created/yet/."] {
            let resolved = resolve_repo_path(spelling, Path::new("/nonexistent-repo"));
            assert_eq!(resolved, PathBuf::from("/nonexistent-repo/not/created/yet"));
            assert!(resolved.is_absolute(), "{spelling:?} must be absolute");
        }
    }

    #[test]
    fn collapse_tilde_home_subpath() {
        let home = std::env::var("HOME").unwrap();
        let input = format!("{home}/.config/gcloud/creds.json");
        assert_eq!(collapse_tilde(&input), "~/.config/gcloud/creds.json");
    }

    #[test]
    fn collapse_tilde_exact_home() {
        let home = std::env::var("HOME").unwrap();
        assert_eq!(collapse_tilde(&home), "~");
    }

    #[test]
    fn collapse_tilde_non_home_path() {
        assert_eq!(collapse_tilde("/tmp/foo"), "/tmp/foo");
    }

    #[test]
    fn collapse_tilde_similar_prefix_not_collapsed() {
        // e.g. HOME=/Users/hans but path is /Users/hans2/foo — must NOT collapse
        let home = std::env::var("HOME").unwrap();
        let similar = format!("{home}2/foo");
        assert_eq!(collapse_tilde(&similar), similar);
    }

    #[test]
    fn collapse_tilde_already_tilde() {
        assert_eq!(collapse_tilde("~/.ssh/config"), "~/.ssh/config");
    }

    #[test]
    fn collapse_tilde_roundtrip_with_expand() {
        let home = std::env::var("HOME").unwrap();
        let original = "~/.config/test";
        let expanded = expand_tilde(original);
        assert_eq!(expanded, PathBuf::from(format!("{home}/.config/test")));
        let collapsed = collapse_tilde(expanded.to_str().unwrap());
        assert_eq!(collapsed, original);
    }
}
