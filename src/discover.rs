//! Runtime environment discovery for cplt.
//!
//! Probes the local environment to determine:
//! - Which auth mechanism Copilot will use
//! - Where Copilot CLI is installed and what native modules it has
//! - Which developer tools are available
//! - Which sandbox-critical paths exist
//!
//! All checks are read-only, local (no network), and fast (<500ms total).

use crate::sandbox::{DENIED_DOTFILES, DENIED_FILES};
use crate::ui;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, Instant};

// ── Result types ────────────────────────────────────────────────

/// Overall discovery result from all probes.
#[derive(Debug)]
pub struct Discovery {
    pub auth: AuthDiscovery,
    pub copilot: CopilotDiscovery,
    pub agents: Vec<AgentInfo>,
    pub tools: ToolDiscovery,
    pub paths: PathDiscovery,
}

/// Discovered agent binary with version info.
#[derive(Debug)]
pub struct AgentInfo {
    pub name: &'static str,
    pub binary_name: &'static str,
    pub path: PathBuf,
    pub version: VersionProbe,
}

/// Outcome of one `<binary> --version` probe.
///
/// `Unknown` and `TimedOut` are deliberately distinct: "the binary answered but
/// said nothing we could parse" and "the binary never answered" are different
/// problems with different fixes, and doctor is the command people run when
/// something is already wrong (#298).
#[derive(Debug, PartialEq, Eq)]
pub enum VersionProbe {
    /// Parsed version string (e.g. `"1.0.21"`).
    Version(String),
    /// Ran to completion without yielding a version: spawn failed, non-zero
    /// exit, or output with no version-looking token.
    Unknown,
    /// Did not exit within [`PROBE_TIMEOUT`]. The child was killed and reaped.
    TimedOut,
}

#[derive(Debug)]
pub struct AuthDiscovery {
    /// Which env var tokens are set (name only, never the value).
    pub env_tokens: Vec<String>,
    /// Whether `gh auth token` succeeds.
    pub gh_cli_auth: bool,
    /// Whether `~/.config/gh/hosts.yml` exists.
    pub gh_config_exists: bool,
    /// Whether `/usr/bin/security` exists and is executable.
    pub security_cli_exists: bool,
    /// Paths to discovered `keytar.node` files.
    pub keytar_nodes: Vec<PathBuf>,
}

#[derive(Debug)]
pub struct CopilotDiscovery {
    /// Resolved path to the `copilot` binary (after symlink resolution).
    pub binary_path: Option<PathBuf>,
    /// All discovered native `.node` modules with their names.
    pub native_modules: Vec<NativeModule>,
}

#[derive(Debug)]
pub struct NativeModule {
    pub name: String,
    pub path: PathBuf,
}

#[derive(Debug)]
pub struct ToolDiscovery {
    /// Discovered tools with their resolved paths.
    pub tools: Vec<ToolInfo>,
    /// Homebrew prefix (e.g. `/opt/homebrew` or `/usr/local`).
    pub homebrew_prefix: Option<PathBuf>,
    /// Which HOME_TOOL_DIRS actually exist on disk, at their effective paths
    /// (relocated tool homes such as `CARGO_HOME` already applied).
    pub existing_home_tool_dirs: Vec<ResolvedToolDir>,
    /// Writable APP_DIRS considered during discovery, including paths that may not yet exist.
    pub existing_app_dirs: Vec<String>,
}

#[derive(Debug)]
pub struct ToolInfo {
    pub name: String,
    pub path: PathBuf,
}

#[derive(Debug)]
pub struct PathDiscovery {
    /// Sensitive dotfile dirs that actually exist (will be denied).
    pub existing_denied_dirs: Vec<String>,
    /// Sensitive files that actually exist (will be denied).
    pub existing_denied_files: Vec<String>,
    /// Whether ~/.copilot exists.
    pub copilot_dir_exists: bool,
    /// Whether ~/Library/Keychains exists.
    pub keychains_dir_exists: bool,
    /// Whether the project dir is inside a git repo.
    pub is_git_repo: bool,
    /// Whether /private/var/db/mds exists (Security framework).
    pub security_db_exists: bool,
}

// ── Auth discovery ──────────────────────────────────────────────

const AUTH_ENV_VARS: &[&str] = &["COPILOT_GITHUB_TOKEN", "GH_TOKEN", "GITHUB_TOKEN"];

pub fn discover_auth(home_dir: &Path) -> AuthDiscovery {
    let env_tokens: Vec<String> = AUTH_ENV_VARS
        .iter()
        .filter(|var| std::env::var(var).is_ok_and(|v| !v.is_empty()))
        .map(std::string::ToString::to_string)
        .collect();

    // Trusted path, not PATH (#239): this runs in the unsandboxed parent, and
    // `gh` is one of the binaries an agent can plant in a write+exec grant. It
    // also answers the question that actually matters — `extract_gh_token`
    // consults a trusted `gh` and nothing else, so a `gh` outside those
    // directories genuinely does not supply the token, whatever it would say
    // here.
    let gh_cli_auth = crate::git::trusted_binary("gh").is_some_and(|gh| {
        #[allow(clippy::disallowed_methods)] // resolved above, not a PATH lookup
        std::process::Command::new(gh)
            .args(["auth", "token"])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .is_ok_and(|s| s.success())
    });

    let gh_config_exists = home_dir.join(".config/gh/hosts.yml").exists();

    // macOS Keychain CLI — not applicable on Linux.
    let security_cli_exists = probe_security_cli();

    let keytar_nodes = find_native_modules(home_dir, "keytar.node");

    AuthDiscovery {
        env_tokens,
        gh_cli_auth,
        gh_config_exists,
        security_cli_exists,
        keytar_nodes,
    }
}

impl AuthDiscovery {
    /// Returns true if at least one auth mechanism is available.
    pub fn any_auth_available(&self) -> bool {
        !self.env_tokens.is_empty()
            || self.gh_cli_auth
            || self.security_cli_exists
            || !self.keytar_nodes.is_empty()
    }
}

// ── Copilot CLI discovery ───────────────────────────────────────

pub fn discover_copilot(home_dir: &Path) -> CopilotDiscovery {
    let binary_path = which_resolved("copilot");

    // Scan for all native modules across all versions
    let mut native_modules = Vec::new();
    for name in &["keytar.node", "pty.node", "computer.node"] {
        for path in find_native_modules(home_dir, name) {
            native_modules.push(NativeModule {
                name: name.to_string(),
                path,
            });
        }
    }
    // Deduplicate by name (keep the latest version path)
    native_modules.sort_by(|a, b| a.path.cmp(&b.path));
    let mut seen_names: std::collections::HashSet<String> = std::collections::HashSet::new();
    native_modules.retain(|m| {
        // Keep the last (highest version) of each name
        seen_names.insert(m.name.clone())
    });
    // We want the latest, so reverse-sort and re-dedup
    native_modules.sort_by(|a, b| b.path.cmp(&a.path));
    seen_names.clear();
    native_modules.retain(|m| seen_names.insert(m.name.clone()));

    CopilotDiscovery {
        binary_path,
        native_modules,
    }
}

// ── Agent discovery ─────────────────────────────────────────────

/// Agents to probe: (display_name, binary_names, version_flag)
const AGENTS_TO_CHECK: &[(&str, &[&str], &[&str])] = &[
    ("Copilot", &["copilot"], &["--version"]),
    ("OpenCode", &["opencode"], &["--version"]),
    ("Antigravity", &["antigravity", "agy"], &["--version"]),
    ("Claude", &["claude"], &["--version"]),
];

/// Per-probe budget for a `--version` call.
///
/// Per probe, not one budget for the whole sweep: a single wedged binary must
/// not hide the state of the others (#298). Five seconds matches
/// `audit::GIT_TIMEOUT` and leaves a Node-based CLI room for a cold start on a
/// loaded machine, while keeping doctor's worst case (every probed agent
/// wedged) in the tens of seconds rather than forever.
const PROBE_TIMEOUT: Duration = Duration::from_secs(5);

/// Run `<path> <args>` and parse a version out of its stdout, giving up after
/// [`PROBE_TIMEOUT`].
///
/// These are the only places discovery *executes* something off the user's
/// `PATH`, and an agent binary that never exits used to hang `cplt doctor`
/// forever with no output — `claude --version` does exactly that when invoked
/// from inside a Claude Code session (#298).
///
/// On timeout the child is killed **and reaped**: dropping a `Child` does not
/// kill it, so returning early without this leaves an orphan that outlives the
/// command. stdout is drained on a helper thread so a chatty binary cannot fill
/// the pipe buffer and deadlock while we poll, and stdin is `/dev/null` so a
/// probe can never sit waiting on the terminal.
///
/// The reader thread is received from with a timeout rather than joined: a
/// probe that forks something inheriting its stdout leaves the pipe open even
/// after the probe itself exits, and an unbounded join there would reintroduce
/// exactly the hang this function exists to remove. A detached reader blocked
/// on a pipe costs one thread in a process that exits moments later.
#[allow(clippy::disallowed_methods)] // runs an already-resolved discovered path; trusting it is #248, not resolution
fn probe_version(path: &Path, args: &[&str]) -> VersionProbe {
    let Ok(mut child) = std::process::Command::new(path)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
    else {
        return VersionProbe::Unknown;
    };
    let Some(mut stdout) = child.stdout.take() else {
        let _ = child.kill();
        let _ = child.wait();
        return VersionProbe::Unknown;
    };
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = stdout.read_to_end(&mut buf);
        let _ = tx.send(buf);
    });

    let deadline = Instant::now() + PROBE_TIMEOUT;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(20));
            }
            outcome => {
                let timed_out = matches!(outcome, Ok(None));
                let _ = child.kill();
                let _ = child.wait();
                return if timed_out {
                    VersionProbe::TimedOut
                } else {
                    VersionProbe::Unknown
                };
            }
        }
    };

    // The child is gone, so unless it left something else holding the write end
    // of the pipe the reader has already seen EOF and sent.
    let Ok(buf) = rx.recv_timeout(Duration::from_millis(500)) else {
        return VersionProbe::Unknown;
    };
    if !status.success() {
        return VersionProbe::Unknown;
    }
    // Parse "GitHub Copilot CLI 1.0.21." → "1.0.21": first token starting with
    // a digit, trailing period trimmed.
    String::from_utf8_lossy(&buf)
        .split_whitespace()
        .find(|w| w.chars().next().is_some_and(|c| c.is_ascii_digit()))
        .map_or(VersionProbe::Unknown, |v| {
            VersionProbe::Version(v.trim_end_matches('.').to_string())
        })
}

/// Discover all available AI coding agents in PATH.
pub fn discover_agents() -> Vec<AgentInfo> {
    AGENTS_TO_CHECK
        .iter()
        .filter_map(|(name, binaries, version_args)| {
            let (binary_name, path) = binaries
                .iter()
                .find_map(|binary| which_resolved(binary).map(|path| (*binary, path)))?;
            let version = probe_version(&path, version_args);
            Some(AgentInfo {
                name,
                binary_name,
                path,
                version,
            })
        })
        .collect()
}

// ── Tool discovery ──────────────────────────────────────────────

const TOOLS_TO_CHECK: &[&str] = &[
    "gh", "git", "node", "npm", "cargo", "python3", "java", "go", "gradle", "yarn",
];

/// Tools whose Windows-side resolution under WSL is a hard failure, not a
/// warning.
///
/// These are the tools cplt itself and the agents depend on: a Windows `npm`
/// installs the win32 platform package into the Windows tree, which is exactly
/// how a user ended up with a Copilot CLI that could not start (#271). The
/// rest — build tools, language runtimes, the `app_dirs()` applications — are
/// only warned about: running one starts a Windows process outside the sandbox,
/// which is worth saying but is not a broken install.
const WSL_CRITICAL_TOOLS: &[&str] = &["gh", "git", "node", "npm"];

use crate::sandbox::app_dirs;
use crate::sandbox::home_tool_dirs;
use crate::sandbox::{ResolvedToolDir, ToolRoot};

/// `tool_roots` relocates HOME_TOOL_DIRS trees named by env vars
/// (`CARGO_HOME`, `GOPATH`, ...); see `ToolRoot`.
pub fn discover_tools(home_dir: &Path, tool_roots: &[ToolRoot]) -> ToolDiscovery {
    let tools: Vec<ToolInfo> = TOOLS_TO_CHECK
        .iter()
        .chain(app_dirs().iter().map(|app_dir| &app_dir.application))
        .filter_map(|name| {
            which_resolved(name).map(|path| ToolInfo {
                name: name.to_string(),
                path,
            })
        })
        .collect();

    let homebrew_prefix = [
        "/opt/homebrew",
        "/usr/local/Homebrew",
        "/home/linuxbrew/.linuxbrew",
    ]
    .iter()
    .map(PathBuf::from)
    .find(|p| p.exists());

    let existing_home_tool_dirs: Vec<ResolvedToolDir> = home_tool_dirs()
        .iter()
        .map(|d| d.resolve(home_dir, tool_roots))
        // Writable cache dirs are always included: tools create them on first use,
        // and the profile must permit the write that creates the directory.
        // Non-writable dirs (tool runtimes) are pruned to existing only.
        .filter(|d| d.dir.write || d.path.exists())
        .collect();

    // Writable app dirs are always included in this list because they potentially could be created on first use.
    // On Linux, Landlock does not support adding access to non-existent paths, so even if included here,
    // a non-existent path would still not be added to the created policy.
    // See the relevant policy implementation for more details.
    // non-writable dirs are pruned to paths that already exist on disk.
    let existing_app_dirs: Vec<String> = app_dirs()
        .iter()
        .flat_map(|app_dir| {
            let write_set: std::collections::HashSet<_> =
                app_dir.write_paths(home_dir).into_iter().collect();
            app_dir
                .all_paths(home_dir)
                .into_iter()
                .filter(move |p| write_set.contains(p) || p.exists())
        })
        .map(|p| p.to_string_lossy().to_string())
        .collect();

    ToolDiscovery {
        tools,
        homebrew_prefix,
        existing_home_tool_dirs,
        existing_app_dirs,
    }
}

// ── Path discovery ──────────────────────────────────────────────

pub fn discover_paths(home_dir: &Path, project_dir: &Path) -> PathDiscovery {
    let existing_denied_dirs: Vec<String> = DENIED_DOTFILES
        .iter()
        .filter(|d| home_dir.join(d).exists())
        .map(std::string::ToString::to_string)
        .collect();

    let existing_denied_files: Vec<String> = DENIED_FILES
        .iter()
        .filter(|f| home_dir.join(f).exists())
        .map(std::string::ToString::to_string)
        .collect();

    let copilot_dir_exists = home_dir.join(".copilot").exists();

    // macOS-only: Keychain and Security framework database.
    let keychains_dir_exists = probe_keychains_dir(home_dir);

    let is_git_repo = crate::git::command(project_dir, &["rev-parse", "--git-dir"])
        .and_then(|mut c| {
            c.stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status()
                .ok()
        })
        .is_some_and(|s| s.success());

    let security_db_exists = probe_security_db();

    PathDiscovery {
        existing_denied_dirs,
        existing_denied_files,
        copilot_dir_exists,
        keychains_dir_exists,
        is_git_repo,
        security_db_exists,
    }
}

// ── Full discovery ──────────────────────────────────────────────

/// Run all discovery probes and return a complete report.
pub fn discover_all(home_dir: &Path, project_dir: &Path) -> Discovery {
    Discovery {
        auth: discover_auth(home_dir),
        copilot: discover_copilot(home_dir),
        agents: discover_agents(),
        tools: discover_tools(home_dir, &[]),
        paths: discover_paths(home_dir, project_dir),
    }
}

// ── Reporting ───────────────────────────────────────────────────

/// The lines doctor prints for the discovered tools, and whether they leave the
/// critical checks passing.
///
/// Split out of `print_report` so a test can assert on what doctor actually
/// emits for a Windows-side tool, not merely on the predicate in isolation.
///
/// Under WSL, interop appends the Windows `PATH` after the distro's, so a tool
/// only resolves to `/mnt/<drive>/…` when no Linux-side install exists. Such a
/// binary cannot run in the Linux namespace and cannot be sandboxed by
/// Landlock, so printing an unconditional green tick for it was how doctor
/// concluded "all critical checks passed" for a setup that could not work
/// (#271). Same predicate, and the same reasoning, as the agents loop above.
fn tool_lines(tools: &[ToolInfo], wsl: bool) -> (Vec<String>, bool) {
    let mut critical_ok = true;
    let lines = tools
        .iter()
        .map(|tool| {
            if !crate::agent::is_wsl_interop_binary(&tool.path, wsl) {
                return format!(
                    "  {}\u{2713}{} {}: {}",
                    ui::stdout_color(ui::GREEN),
                    ui::stdout_color(ui::RESET),
                    tool.name,
                    tool.path.display()
                );
            }
            if WSL_CRITICAL_TOOLS.contains(&tool.name.as_str()) {
                critical_ok = false;
                format!(
                    "  {}\u{2717}{} {}: {} is a Windows install reached through WSL interop \
                     and cannot run in the Linux sandbox. Install {} inside the WSL distro.",
                    ui::stdout_color(ui::RED),
                    ui::stdout_color(ui::RESET),
                    tool.name,
                    tool.path.display(),
                    tool.name
                )
            } else {
                format!(
                    "  {}\u{26a0}{} {}: {} is a Windows install reached through WSL interop; \
                     running it starts a Windows process, outside the sandbox.",
                    ui::stdout_color(ui::YELLOW),
                    ui::stdout_color(ui::RESET),
                    tool.name,
                    tool.path.display()
                )
            }
        })
        .collect();
    (lines, critical_ok)
}

impl Discovery {
    /// Print a human-readable diagnostic report. Returns true if all critical checks pass.
    pub fn print_report(&self) -> bool {
        let mut critical_ok = true;

        // Auth section
        println!(
            "{}{}[doctor]{} {}Auth{}",
            ui::stdout_color(ui::BOLD),
            ui::stdout_color(ui::BLUE),
            ui::stdout_color(ui::RESET),
            ui::stdout_color(ui::BOLD),
            ui::stdout_color(ui::RESET)
        );
        if self.auth.env_tokens.is_empty() {
            println!(
                "  {}⚠{} No env token set (COPILOT_GITHUB_TOKEN, GH_TOKEN, GITHUB_TOKEN)",
                ui::stdout_color(ui::YELLOW),
                ui::stdout_color(ui::RESET)
            );
        } else {
            for var in &self.auth.env_tokens {
                println!(
                    "  {}✓{} Env token: {var} is set",
                    ui::stdout_color(ui::GREEN),
                    ui::stdout_color(ui::RESET)
                );
            }
        }
        if self.auth.gh_cli_auth {
            println!(
                "  {}✓{} gh CLI: authenticated (gh auth token succeeds)",
                ui::stdout_color(ui::GREEN),
                ui::stdout_color(ui::RESET)
            );
        } else if self.auth.gh_config_exists {
            println!(
                "  {}⚠{} gh CLI: config exists (~/.config/gh/hosts.yml) but gh auth token fails",
                ui::stdout_color(ui::YELLOW),
                ui::stdout_color(ui::RESET)
            );
        } else {
            println!(
                "  {}⚠{} gh CLI: no config found (~/.config/gh/hosts.yml)",
                ui::stdout_color(ui::YELLOW),
                ui::stdout_color(ui::RESET)
            );
        }
        print_keychain_status(self.auth.security_cli_exists);
        if self.auth.keytar_nodes.is_empty() {
            println!(
                "  {}⚠{} keytar.node: not found in ~/.copilot/pkg/",
                ui::stdout_color(ui::YELLOW),
                ui::stdout_color(ui::RESET)
            );
        } else {
            println!(
                "  {}✓{} keytar.node: found in ~/.copilot/pkg/",
                ui::stdout_color(ui::GREEN),
                ui::stdout_color(ui::RESET)
            );
        }
        if !self.auth.any_auth_available() {
            println!(
                "  {}✗{} No auth mechanism available, Copilot will fail to authenticate",
                ui::stdout_color(ui::RED),
                ui::stdout_color(ui::RESET)
            );
            critical_ok = false;
        }
        println!();

        // Agents section
        println!(
            "{}{}[doctor]{} {}Agents{}",
            ui::stdout_color(ui::BOLD),
            ui::stdout_color(ui::BLUE),
            ui::stdout_color(ui::RESET),
            ui::stdout_color(ui::BOLD),
            ui::stdout_color(ui::RESET)
        );
        if self.agents.is_empty() {
            println!(
                "  {}✗{} No supported agents found in PATH",
                ui::stdout_color(ui::RED),
                ui::stdout_color(ui::RESET)
            );
            critical_ok = false;
        } else {
            let wsl = cfg!(target_os = "linux") && crate::agent::is_wsl();
            for agent in &self.agents {
                // A Windows-side install reached through WSL interop cannot run
                // in the Linux sandbox, so reporting it as present is what let
                // doctor say "all critical checks passed" for a setup that
                // cannot start (#188). Gated on an actual WSL signal: on a plain
                // Linux box /mnt/c is an ordinary mount and an agent there is
                // fine. WSL appends the Windows PATH after the distro's, so
                // `which` only lands here when no Linux-side install exists.
                if crate::agent::is_wsl_interop_binary(&agent.path, wsl) {
                    println!(
                        "  {}✗{} {} ({}): {} is a Windows install reached through WSL \
                         interop and cannot run in the Linux sandbox. Install Node and {} \
                         inside the WSL distro.",
                        ui::stdout_color(ui::RED),
                        ui::stdout_color(ui::RESET),
                        agent.name,
                        agent.binary_name,
                        agent.path.display(),
                        agent.binary_name
                    );
                    critical_ok = false;
                    continue;
                }
                match agent.version {
                    VersionProbe::Version(ref ver) => println!(
                        "  {}✓{} {} ({}) v{ver}: {}",
                        ui::stdout_color(ui::GREEN),
                        ui::stdout_color(ui::RESET),
                        agent.name,
                        agent.binary_name,
                        agent.path.display()
                    ),
                    VersionProbe::Unknown => println!(
                        "  {}✓{} {} ({}): {}",
                        ui::stdout_color(ui::GREEN),
                        ui::stdout_color(ui::RESET),
                        agent.name,
                        agent.binary_name,
                        agent.path.display()
                    ),
                    // Reported, not omitted: the binary is installed, so
                    // "not detected" would be a lie, and a silently missing
                    // row sends the user looking for an install that is
                    // already there (#298).
                    VersionProbe::TimedOut => println!(
                        "  {}⚠{} {} ({}): {} — version probe did not answer within \
                         {}s and was killed; the binary is installed but may be wedged",
                        ui::stdout_color(ui::YELLOW),
                        ui::stdout_color(ui::RESET),
                        agent.name,
                        agent.binary_name,
                        agent.path.display(),
                        PROBE_TIMEOUT.as_secs()
                    ),
                }
            }
        }
        if !self.copilot.native_modules.is_empty() {
            let names: Vec<&str> = self
                .copilot
                .native_modules
                .iter()
                .map(|m| m.name.as_str())
                .collect();
            println!(
                "  {}✓{} Copilot native modules: {}",
                ui::stdout_color(ui::GREEN),
                ui::stdout_color(ui::RESET),
                names.join(", ")
            );
        }
        println!();

        // Tools section
        println!(
            "{}{}[doctor]{} {}Tools{}",
            ui::stdout_color(ui::BOLD),
            ui::stdout_color(ui::BLUE),
            ui::stdout_color(ui::RESET),
            ui::stdout_color(ui::BOLD),
            ui::stdout_color(ui::RESET)
        );
        let (tool_lines, tools_ok) = tool_lines(
            &self.tools.tools,
            cfg!(target_os = "linux") && crate::agent::is_wsl(),
        );
        for line in &tool_lines {
            println!("{line}");
        }
        critical_ok &= tools_ok;
        let missing: Vec<&&str> = TOOLS_TO_CHECK
            .iter()
            .filter(|name| !self.tools.tools.iter().any(|t| t.name == **name))
            .collect();
        for name in &missing {
            println!(
                "  {}⚠{} {name}: not found",
                ui::stdout_color(ui::YELLOW),
                ui::stdout_color(ui::RESET)
            );
        }
        if let Some(ref prefix) = self.tools.homebrew_prefix {
            println!(
                "  {}✓{} Homebrew: {}",
                ui::stdout_color(ui::GREEN),
                ui::stdout_color(ui::RESET),
                prefix.display()
            );
        }
        if !self.tools.existing_home_tool_dirs.is_empty() {
            let joined: Vec<String> = self
                .tools
                .existing_home_tool_dirs
                .iter()
                .map(|d| d.path.display().to_string())
                .collect();
            println!(
                "  {}✓{} Tool dirs: {}",
                ui::stdout_color(ui::GREEN),
                ui::stdout_color(ui::RESET),
                joined.join(", ")
            );
        }
        let missing_dirs: Vec<&str> = home_tool_dirs()
            .iter()
            .map(|d| d.path)
            .filter(|p| {
                !self
                    .tools
                    .existing_home_tool_dirs
                    .iter()
                    .any(|e| e.dir.path == *p)
            })
            .collect();
        if !missing_dirs.is_empty() {
            let joined: Vec<String> = missing_dirs.iter().map(|d| format!("~/{d}")).collect();
            println!(
                "  {}⚠{} Not found (skippable): {}",
                ui::stdout_color(ui::YELLOW),
                ui::stdout_color(ui::RESET),
                joined.join(", ")
            );
        }
        println!();

        // Paths section
        println!(
            "{}{}[doctor]{} {}Sandbox paths{}",
            ui::stdout_color(ui::BOLD),
            ui::stdout_color(ui::BLUE),
            ui::stdout_color(ui::RESET),
            ui::stdout_color(ui::BOLD),
            ui::stdout_color(ui::RESET)
        );
        if self.paths.is_git_repo {
            println!(
                "  {}✓{} Project: inside a git repository",
                ui::stdout_color(ui::GREEN),
                ui::stdout_color(ui::RESET)
            );
        } else {
            println!(
                "  {}⚠{} Project: not a git repo (using cwd)",
                ui::stdout_color(ui::YELLOW),
                ui::stdout_color(ui::RESET)
            );
        }
        if self.paths.copilot_dir_exists {
            println!(
                "  {}✓{} ~/.copilot exists",
                ui::stdout_color(ui::GREEN),
                ui::stdout_color(ui::RESET)
            );
        } else {
            println!(
                "  {}✗{} ~/.copilot not found, Copilot CLI may not be installed",
                ui::stdout_color(ui::RED),
                ui::stdout_color(ui::RESET)
            );
            critical_ok = false;
        }
        print_macos_path_status(
            self.paths.keychains_dir_exists,
            self.paths.security_db_exists,
        );

        let n_denied =
            self.paths.existing_denied_dirs.len() + self.paths.existing_denied_files.len();
        if n_denied > 0 {
            let dirs: Vec<String> = self
                .paths
                .existing_denied_dirs
                .iter()
                .map(|d| format!("~/{d}"))
                .collect();
            let files: Vec<String> = self
                .paths
                .existing_denied_files
                .iter()
                .map(|f| format!("~/{f}"))
                .collect();
            let all: Vec<&str> = dirs
                .iter()
                .chain(files.iter())
                .map(std::string::String::as_str)
                .collect();
            println!(
                "  {}✓{} Protected ({n_denied} found): {}",
                ui::stdout_color(ui::GREEN),
                ui::stdout_color(ui::RESET),
                all.join(", ")
            );
        }
        println!();

        // Sandbox mechanism section
        println!(
            "{}{}[doctor]{} {}Sandbox mechanism{}",
            ui::stdout_color(ui::BOLD),
            ui::stdout_color(ui::BLUE),
            ui::stdout_color(ui::RESET),
            ui::stdout_color(ui::BOLD),
            ui::stdout_color(ui::RESET)
        );
        if !print_sandbox_mechanism_status() {
            critical_ok = false;
        }
        println!();

        // Summary
        if critical_ok {
            println!(
                "{}[doctor]{} All critical checks passed ✓",
                ui::stdout_color(ui::GREEN),
                ui::stdout_color(ui::RESET)
            );
        } else {
            println!(
                "{}[doctor]{} Critical issues found, the sandbox may not work correctly",
                ui::stdout_color(ui::RED),
                ui::stdout_color(ui::RESET)
            );
        }

        critical_ok
    }
}

// ── Platform-specific probes ────────────────────────────────────
//
// Named functions keep cfg blocks out of the discovery logic above.

/// Check if macOS Keychain CLI exists. Always false on other platforms.
fn probe_security_cli() -> bool {
    #[cfg(target_os = "macos")]
    {
        Path::new("/usr/bin/security").exists()
    }
    #[cfg(not(target_os = "macos"))]
    {
        false
    }
}

/// Check if macOS Keychain directory exists. Always false on other platforms.
fn probe_keychains_dir(home_dir: &Path) -> bool {
    #[cfg(target_os = "macos")]
    {
        home_dir.join("Library/Keychains").exists()
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = home_dir;
        false
    }
}

/// Check if macOS Security framework database exists. Always false on other platforms.
fn probe_security_db() -> bool {
    #[cfg(target_os = "macos")]
    {
        Path::new("/private/var/db/mds").exists()
    }
    #[cfg(not(target_os = "macos"))]
    {
        false
    }
}

/// Print Keychain CLI status in doctor output (macOS only, no-op on Linux).
fn print_keychain_status(security_cli_exists: bool) {
    #[cfg(target_os = "macos")]
    if security_cli_exists {
        println!(
            "  {}✓{} Keychain CLI: /usr/bin/security exists",
            ui::stdout_color(ui::GREEN),
            ui::stdout_color(ui::RESET)
        );
    } else {
        println!(
            "  {}⚠{} Keychain CLI: /usr/bin/security not found",
            ui::stdout_color(ui::YELLOW),
            ui::stdout_color(ui::RESET)
        );
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = security_cli_exists;
    }
}

/// Print macOS-specific path status (keychains, security db). No-op on Linux.
fn print_macos_path_status(keychains_dir_exists: bool, security_db_exists: bool) {
    #[cfg(target_os = "macos")]
    {
        if keychains_dir_exists {
            println!(
                "  {}✓{} ~/Library/Keychains exists",
                ui::stdout_color(ui::GREEN),
                ui::stdout_color(ui::RESET)
            );
        } else {
            println!(
                "  {}⚠{} ~/Library/Keychains not found",
                ui::stdout_color(ui::YELLOW),
                ui::stdout_color(ui::RESET)
            );
        }
        if security_db_exists {
            println!(
                "  {}✓{} /private/var/db/mds exists (Security framework)",
                ui::stdout_color(ui::GREEN),
                ui::stdout_color(ui::RESET)
            );
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = (keychains_dir_exists, security_db_exists);
    }
}

/// Print sandbox mechanism status and return true if mechanism is available.
fn print_sandbox_mechanism_status() -> bool {
    #[cfg(target_os = "macos")]
    {
        let sandbox_exec_exists = Path::new("/usr/bin/sandbox-exec").exists();
        if sandbox_exec_exists {
            println!(
                "  {}✓{} Seatbelt: /usr/bin/sandbox-exec available",
                ui::stdout_color(ui::GREEN),
                ui::stdout_color(ui::RESET)
            );
        } else {
            println!(
                "  {}✗{} Seatbelt: /usr/bin/sandbox-exec not found",
                ui::stdout_color(ui::RED),
                ui::stdout_color(ui::RESET)
            );
        }
        sandbox_exec_exists
    }
    #[cfg(target_os = "linux")]
    {
        use crate::sandbox::landlock_mod::check_availability;
        use landlock::ABI;

        let ok = if let Ok(abi_version) = check_availability() {
            println!(
                "  {}✓{} Landlock: ABI v{abi_version}",
                ui::stdout_color(ui::GREEN),
                ui::stdout_color(ui::RESET)
            );
            if abi_version < ABI::V4 {
                println!(
                    "  {}⚠{} Landlock ABI < v4: TCP port filtering unavailable (kernel < 6.7)",
                    ui::stdout_color(ui::YELLOW),
                    ui::stdout_color(ui::RESET)
                );
                println!("      Network security provided by proxy only.");
            }
            if abi_version < ABI::V9 {
                println!(
                    "  {}⚠{} Landlock ABI < v9: UNIX-socket connect() unavailable (kernel < 7.1)",
                    ui::stdout_color(ui::YELLOW),
                    ui::stdout_color(ui::RESET)
                );
                println!("      Known escape sockets (D-Bus, systemd, container daemons) are only");
                println!("      masked when Bubblewrap is active; otherwise unrestricted.");
            }
            true
        } else {
            println!(
                "  {}✗{} Landlock: not available",
                ui::stdout_color(ui::RED),
                ui::stdout_color(ui::RESET)
            );
            println!("      Requires Linux 5.13+ with Landlock enabled.");
            println!("      Check: cat /sys/kernel/security/lsm (should include 'landlock')");
            false
        };
        // The kernel release, read rather than spawned. This branch is
        // Linux-only, so `/proc/sys/kernel/osrelease` holds exactly what
        // `uname -r` prints — and a spawn here was a bare-name PATH lookup in
        // the unsandboxed parent, which is the class #239 closes. No spawn
        // beats a trusted spawn.
        if let Ok(kernel) = std::fs::read_to_string("/proc/sys/kernel/osrelease") {
            println!(
                "  {}✓{} Kernel: {}",
                ui::stdout_color(ui::GREEN),
                ui::stdout_color(ui::RESET),
                kernel.trim()
            );
        }
        println!(
            "  {}✓{} seccomp: available (built-in on modern kernels)",
            ui::stdout_color(ui::GREEN),
            ui::stdout_color(ui::RESET)
        );
        ok
    }
}

// ── Helpers ─────────────────────────────────────────────────────

/// Find the Copilot CLI package root from the resolved binary path.
///
/// Walks up at most 4 ancestor directories looking for a `package.json`
/// whose `"name"` field is `"@github/copilot"`. This handles any npm-like
/// package manager (npm, pnpm, yarn, bun) and any install prefix (`n`,
/// `nvm`, `volta`, `fnm`, `mise`, custom `--prefix`, etc.).
///
/// Returns `None` when:
/// - the binary is standalone (no `package.json` ancestor) — e.g. Homebrew cask
/// - the nearest `package.json` belongs to a different package
/// - the path would resolve to an unsafe root (`/`, `$HOME`, `/tmp`)
pub fn copilot_pkg_dir(copilot_bin: &Path, home_dir: &Path) -> Option<PathBuf> {
    let mut dir = copilot_bin.parent()?;
    for _ in 0..4 {
        let pkg_json = dir.join("package.json");
        if pkg_json.is_file() && is_copilot_package(&pkg_json) {
            // Reject overly broad directories
            if crate::is_unsafe_root(dir, home_dir) {
                return None;
            }
            return Some(dir.to_path_buf());
        }
        dir = dir.parent()?;
    }
    None
}

/// Find the Copilot CLI SEA extraction cache directory on Linux.
///
/// Copilot CLI ships as a SEA (Single Executable Application) binary that extracts
/// its Node.js runtime to a platform-specific cache directory on first run.
/// On Linux this is `~/.cache/copilot/pkg/linux-{arch}/`.
///
/// Returns `Some(path)` if the directory exists or can reasonably be created
/// (parent exists). The sandbox needs read+exec access to this directory for
/// Copilot's re-exec mechanism to work.
pub fn copilot_sea_cache_dir(home_dir: &Path) -> Option<PathBuf> {
    let pkg_base = home_dir.join(".cache/copilot/pkg");

    // Return the path if it exists OR if the parent (.cache/copilot) exists
    // so that pre-flight extraction can create it.
    if pkg_base.exists() || pkg_base.parent().is_some_and(Path::exists) {
        Some(pkg_base)
    } else {
        None
    }
}

/// Check if a `package.json` file belongs to `@github/copilot`.
fn is_copilot_package(pkg_json: &Path) -> bool {
    let Ok(contents) = std::fs::read_to_string(pkg_json) else {
        return false;
    };
    // Fast-path: skip JSON parsing if the package name isn't mentioned at all
    if !contents.contains("@github/copilot") {
        return false;
    }
    let Ok(v) = serde_json::from_str::<serde_json::Value>(&contents) else {
        return false;
    };
    v.get("name").and_then(|n| n.as_str()) == Some("@github/copilot")
}

/// Discover the global git hooks directory from `core.hooksPath`.
///
/// Runs `git config --global core.hooksPath`, expands `~`, canonicalizes,
/// and validates the result. Returns `None` when:
/// - `core.hooksPath` is not set or the directory doesn't exist
/// - the path resolves to an unsafe root
/// - the path is not under `$HOME` (prevents arbitrary filesystem reads)
/// - the path is too shallow under `$HOME` (must be ≥3 components deep,
///   e.g. `~/.config/git/hooks` OK, `~/hooks` rejected as too broad)
pub fn git_hooks_path(home_dir: &Path) -> Option<PathBuf> {
    // `Path::new(".")` — this query is about the USER's global config, not any
    // particular repository, so it intentionally runs in the process cwd.
    // `crate::git::command` does not blank global config (see its `harden`
    // docs); doing so would break exactly this detection.
    let output = crate::git::command(Path::new("."), &["config", "--global", "core.hooksPath"])?
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let raw = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if raw.is_empty() {
        return None;
    }
    // Expand ~ to home dir
    let expanded = if let Some(rest) = raw.strip_prefix("~/") {
        home_dir.join(rest)
    } else {
        PathBuf::from(&raw)
    };
    // Canonicalize to resolve symlinks
    let resolved = std::fs::canonicalize(&expanded).unwrap_or(expanded);
    // Safety: reject unsafe roots
    if crate::is_unsafe_root(&resolved, home_dir) {
        return None;
    }
    // Must be under $HOME — prevents punching read holes in arbitrary fs paths
    let suffix = resolved.strip_prefix(home_dir).ok()?;
    // Must be ≥3 components deep under $HOME to prevent overly broad reads.
    // e.g. ~/.config/git/hooks (3 components) is OK,
    //      ~/hooks (1 component) is too broad.
    if suffix.components().count() < 3 {
        return None;
    }
    if resolved.is_dir() {
        Some(resolved)
    } else {
        None
    }
}

/// Resolve the shared `.git` directory that governs `dir`, if any.
///
/// This is the directory that actually holds `hooks/` and `config` — the two
/// files that make a repo a persistence vector:
/// - normal repo → `<repo>/.git`
/// - worktree    → the **main** repo's `.git` (the worktree's own `.git` is a file)
/// - bare repo   → the repo directory itself
/// - a path *inside* a repo → that repo's `.git` (git walks up)
///
/// Returns `None` when `dir` is not in a git repository, does not exist, or git
/// is unavailable. Callers must treat that as a no-op, never an error.
///
/// Unlike [`git_common_dir`] this applies **no** unsafe-root/`$HOME` filtering.
/// A path it returns can only ever narrow access, because the caller turns it
/// into write denies, so there is nothing for a filter to protect against.
/// `git_common_dir` needs those filters because it also grants access.
///
/// The asymmetry runs the other way, and it is the part worth guarding: a
/// `None` here means the denies are never emitted, so every new reason to
/// return `None` fails **open**. The three current ones (not a repo, no git,
/// not a directory) leave nothing to protect. Do not add a refusal that a repo
/// can trigger through its own config. `rev-parse` is on
/// `git::CONTENT_FREE_SUBCOMMANDS` for exactly this reason: were it not, a
/// hostile `filter.*.clean` in a granted repo would make the hardened invoker
/// refuse, and that repo's `.git/hooks` would lose its deny.
pub fn git_dir_of(dir: &Path) -> Option<PathBuf> {
    git_dir_of_with(
        crate::git::command(dir, &["rev-parse", "--git-common-dir"]),
        dir,
    )
}

/// [`git_dir_of`] with the hardened invoker's result injected.
///
/// Exists so the no-trusted-git arm is reachable in a test: `trusted_git()`
/// caches in a `OnceLock`, so on a host that has git the fallback branch is
/// otherwise unreachable and a revert of the wiring goes unnoticed.
fn git_dir_of_with(cmd: Option<std::process::Command>, dir: &Path) -> Option<PathBuf> {
    let Some(mut cmd) = cmd else {
        // No trusted git on this machine. Before this fallback existed, that
        // returned `None` and every gitdir-derived deny for a worktree or a
        // separate-gitdir repo silently vanished — the fail-open the doc
        // comment above warns about, now reachable on an ordinary machine
        // whose git simply lives outside the trusted directories.
        //
        // `<dir>/.git` is enough to recover the common cases without running
        // anything: a plain repo has it as a directory, and a worktree or
        // submodule has it as a file holding `gitdir: <path>`. Reading a file
        // is not a PATH-hijack surface, which is the whole reason git is
        // resolved from trusted directories in the first place.
        //
        // Still `None` for a bare repo (no `.git` entry at all); that case has
        // no working tree for an agent to be sandboxed into.
        return gitdir_without_git(dir);
    };
    let output = cmd.output().ok()?;
    if !output.status.success() {
        return None;
    }
    let raw = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if raw.is_empty() {
        return None;
    }
    // git prints the common dir relative to `dir` (`.git`, `../.git`, `.` for a
    // bare repo) unless it is absolute (worktree).
    let path = if Path::new(&raw).is_absolute() {
        PathBuf::from(&raw)
    } else {
        dir.join(&raw)
    };
    let resolved = std::fs::canonicalize(&path).unwrap_or(path);
    if resolved.is_dir() {
        Some(resolved)
    } else {
        None
    }
}

/// Resolve `<dir>`'s git directory by reading `<dir>/.git`, without running git.
///
/// Used only when no trusted git binary exists. Handles the two layouts that
/// matter for the persistence denies:
/// - directory → an ordinary repo, the gitdir is `<dir>/.git`
/// - file      → a worktree or submodule, holding `gitdir: <path>`
///
/// The pointer is resolved relative to `<dir>` when relative, canonicalized,
/// and accepted only if it is a directory — matching what the git-backed path
/// returns. Deliberately no validation beyond that: the result is turned into
/// write denies by the caller, so a wrong answer can only over-deny, never
/// grant. (`git_common_dir` returns before granting whenever there is no
/// trusted git, because its commondir-steering check runs the invoker too.)
///
/// The residual that buys: an agent that can write `<root>/.git` can point this
/// at any existing directory and get that directory's `hooks`/`config`/`modules`
/// write-denied next session. Real git refuses a pointer to a non-gitdir; this
/// does not. It is self-denial-of-service only — it can subtract access, never
/// add it — and the alternative is validating a gitdir's shape without git,
/// which is more code for a worse failure mode.
fn gitdir_without_git(dir: &Path) -> Option<PathBuf> {
    let dot_git = dir.join(".git");
    // `metadata`, not `symlink_metadata`: git follows a `.git` symlink to a
    // directory, and the git-backed path canonicalizes to the target. Not
    // following it here would drop straight to the `read_to_string` branch,
    // fail with EISDIR, and lose the target's denies.
    let meta = std::fs::metadata(&dot_git).ok()?;
    if meta.is_dir() {
        return std::fs::canonicalize(&dot_git).ok().or(Some(dot_git));
    }
    // Regular file only. `read_to_string` opens O_RDONLY, which blocks forever
    // on a FIFO with no writer — an agent that can write `<root>/.git` could
    // otherwise `mkfifo` it and hang the next launch before the sandbox exists.
    // Real git checks the same thing and exits rather than blocking.
    if !meta.is_file() {
        return None;
    }
    let contents = std::fs::read_to_string(&dot_git).ok()?;
    let pointer = contents
        .lines()
        .find_map(|l| l.trim().strip_prefix("gitdir:"))?
        .trim();
    if pointer.is_empty() {
        return None;
    }
    let path = if Path::new(pointer).is_absolute() {
        PathBuf::from(pointer)
    } else {
        dir.join(pointer)
    };
    let resolved = std::fs::canonicalize(&path).unwrap_or(path);
    if !resolved.is_dir() {
        return None;
    }
    // A worktree's pointer names `<main>/.git/worktrees/<name>`, which is NOT
    // the directory that holds `hooks/` and `config` — those live in the shared
    // dir, which `git rev-parse --git-common-dir` returns and which the
    // per-worktree dir names in its own `commondir` file (git writes literally
    // `../..`). Returning the per-worktree dir would satisfy nothing: the denies
    // would land on paths that do not exist while the real hooks stayed open.
    //
    // Submodules and `--separate-git-dir` repos have no `commondir`; their
    // pointer already names the common dir, so they fall through unchanged.
    if let Ok(raw) = std::fs::read_to_string(resolved.join("commondir")) {
        let raw = raw.trim();
        if !raw.is_empty() {
            let common = if Path::new(raw).is_absolute() {
                PathBuf::from(raw)
            } else {
                resolved.join(raw)
            };
            let common = std::fs::canonicalize(&common).unwrap_or(common);
            if common.is_dir() {
                return Some(common);
            }
        }
    }
    Some(resolved)
}

/// Detect if the project is a git worktree and return the shared `.git` directory.
///
/// In a git worktree, the project's `.git` is a file pointing to the main repo's
/// `.git/worktrees/<name>`. Git operations need read+write access to the shared
/// `.git` directory (objects, refs, packed-refs, etc.).
///
/// Returns `None` when:
/// - Not in a git repo
/// - Not a worktree (regular repo with `.git` dir in project root)
/// - The common dir resolves to an unsafe root
/// - The common dir is not under `$HOME`
pub fn git_common_dir(home_dir: &Path, project_dir: &Path) -> Option<PathBuf> {
    // `git_dir_of` runs the hardened invoker and canonicalizes; it also
    // subsumes the old `raw == ".git"` spelling check, because the comparison
    // below is against the *resolved* local `.git` rather than git's output.
    let resolved = git_dir_of(project_dir)?;
    // Not a worktree — the common dir is the project's own `.git` directory,
    // which the project grant already covers.
    let local = project_dir.join(".git");
    if resolved == std::fs::canonicalize(&local).unwrap_or(local) {
        return None;
    }
    // Safety: reject unsafe roots
    if crate::is_unsafe_root(&resolved, home_dir) {
        return None;
    }
    // Must be under $HOME to prevent overly broad filesystem access
    if !resolved.starts_with(home_dir) {
        return None;
    }
    // `--git-common-dir` is not trustworthy on its own: git derives it from a
    // `commondir` file inside the gitdir, which sits in the project tree the
    // agent can write. Planting one makes git name *another repository*, and
    // the checks above wave it through — it is a real git repo under $HOME, so
    // it is neither an unsafe root nor outside home. The grant that follows
    // would hand over that repo's whole object store (every file ever
    // committed, reachable with `git cat-file` regardless of the working-tree
    // deny) plus its refs.
    //
    // Only two layouts are legitimate, and both are relative to the gitdir git
    // actually resolved for this project:
    //   - separate gitdir / plain repo: the common dir *is* the gitdir
    //   - worktree: the common dir is `<gitdir>/../..`, because git writes
    //     literally `../..` into `<main>/.git/worktrees/<name>/commondir`
    // A steered commondir satisfies neither.
    let git_dir = crate::git::command(project_dir, &["rev-parse", "--absolute-git-dir"])?
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| PathBuf::from(String::from_utf8_lossy(&o.stdout).trim()))?;
    let git_dir = std::fs::canonicalize(&git_dir).unwrap_or(git_dir);
    let is_worktree_layout = git_dir.parent().and_then(Path::parent) == Some(resolved.as_path());
    if resolved != git_dir && !is_worktree_layout {
        return None;
    }
    // An unsafe character here must not brick the launch. `prepare()` validates
    // every path it interpolates into the SBPL profile and returns Err on the
    // first bad one, aborting the run — and this path comes off the filesystem,
    // not out of the user's own config, so a directory named with a quote is
    // enough to stop cplt starting at all. The pressure that creates is to
    // rerun the agent unsandboxed, which costs far more than what is dropped
    // here.
    //
    // Skipping is the safe direction because what gets dropped is a *grant*,
    // not a deny: the gitdir denies are keyed on `<project>/.git` and are
    // emitted either way, and without this grant the common dir is not writable
    // at all — it lies outside both the project tree and the granted home
    // directories. The cost is that in-worktree git fails inside the sandbox,
    // loudly, which the warning explains.
    if let Err(e) = crate::sandbox::validate_sbpl_path(&resolved) {
        ui::warn(&format!(
            "Ignoring the shared git directory {}: {e}\n\
             Git operations in this worktree will fail inside the sandbox.",
            resolved.display()
        ));
        return None;
    }
    Some(resolved)
}

///
/// When Copilot is installed via the VS Code extension, the `copilot` binary is a
/// shell script shim that invokes VS Code's Electron runtime:
/// ```text
/// ELECTRON_RUN_AS_NODE=1 "/Applications/Visual Studio Code.app/.../Code Helper (Plugin)" \
///   "/path/to/copilotCLIShim.js" "$@"
/// ```
///
/// The Electron Framework (loaded by `dyld` at startup) lives inside the `.app`
/// bundle. Without read + `file-map-executable` access the sandbox blocks `dyld`
/// from loading it, causing an immediate `SIGABRT`.
///
/// Returns `<bundle>.app/Contents` (not the whole bundle) to limit scope.
/// Also works for VS Code Insiders, Cursor, Windsurf, and other Electron editors.
pub fn discover_electron_app(copilot_bin: &Path) -> Option<PathBuf> {
    // Only process shell scripts (text files), not compiled binaries
    let content = std::fs::read_to_string(copilot_bin).ok()?;
    if !content.starts_with("#!") {
        return None;
    }

    // Must be a Copilot CLI shim — not some unrelated script
    if !content.contains("copilotCLIShim.js") {
        return None;
    }

    // Extract the .app bundle from quoted paths in the shim.
    // The shim uses double-quoted paths: "/.../Something.app/.../Binary"
    for path in extract_quoted_paths(&content) {
        if let Some(app_contents) = find_app_contents(&path) {
            // Verify it's a real macOS app bundle
            if !app_contents.join("Info.plist").is_file() {
                continue;
            }
            // Canonicalize to resolve symlinks, then verify the resolved path
            // still has the .app/Contents structure. Without this check, a
            // symlinked Contents/ could resolve to an arbitrary directory and
            // punch a read+exec hole through the sandbox.
            let canonical = std::fs::canonicalize(&app_contents).unwrap_or(app_contents);
            if canonical.file_name().is_some_and(|n| n == "Contents")
                && canonical
                    .parent()
                    .and_then(|p| p.extension())
                    .is_some_and(|ext| ext.eq_ignore_ascii_case("app"))
            {
                return Some(canonical);
            }
        }
    }
    None
}

/// Extract double-quoted absolute paths from shell script content.
fn extract_quoted_paths(content: &str) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    let bytes = content.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'"' {
            // Find the closing quote
            if let Some(end) = content[i + 1..].find('"') {
                let inner = &content[i + 1..i + 1 + end];
                if inner.starts_with('/') {
                    paths.push(PathBuf::from(inner));
                }
                i += 2 + end;
                continue;
            }
        }
        i += 1;
    }
    paths
}

/// Walk up from a path to find the outermost `<something>.app/Contents`.
/// Returns the `Contents` directory of the top-level `.app` bundle.
///
/// Electron editors nest helper apps inside the main bundle:
/// `Visual Studio Code.app/Contents/Frameworks/Code Helper (Plugin).app/Contents/...`
/// We need the outermost bundle (`Visual Studio Code.app/Contents`) because that's
/// where `Electron Framework.framework` lives.
fn find_app_contents(path: &Path) -> Option<PathBuf> {
    let mut result: Option<PathBuf> = None;
    let mut current = path;
    loop {
        if let Some(name) = current.file_name()
            && name == "Contents"
            && let Some(parent) = current.parent()
            && parent
                .extension()
                .is_some_and(|ext| ext.eq_ignore_ascii_case("app"))
        {
            // Keep going — we want the outermost match
            result = Some(current.to_path_buf());
        }
        match current.parent() {
            Some(p) if p != current => current = p,
            _ => break,
        }
    }
    result
}

/// Resolve a command name to its real path (following symlinks).
///
/// Reads `PATH` in-process rather than spawning `which`. `discover_tools` runs
/// on every launch, in the unsandboxed parent, before the agent starts — and it
/// called this once per tool plus once per app dir. Spawning a bare `which`
/// there means a `which` planted in one of the write+exec grants a previous
/// session had (mise shims, `PNPM_HOME`, `~/.bun/bin`) executes as the user.
/// A pure-Rust lookup has nothing to hijack. Same reasoning as
/// `git::TRUSTED_BIN_DIRS`, one rung better: no spawn beats a trusted spawn.
///
/// Not a trusted-directory lookup, deliberately: the point of discovery is to
/// report what is on the user's `PATH`, wherever it lives. The returned path is
/// only ever *reported* or turned into a sandbox grant, never executed — except
/// by `discover_agents`/`discover_copilot`, which run version probes for
/// `cplt doctor` only.
fn which_resolved(name: &str) -> Option<PathBuf> {
    let path = crate::sandbox::which_binary(name)?;
    Some(std::fs::canonicalize(&path).unwrap_or(path))
}

/// Find native `.node` modules matching a name in `~/.copilot/pkg/`.
fn find_native_modules(home_dir: &Path, module_name: &str) -> Vec<PathBuf> {
    let pkg_dir = home_dir.join(".copilot/pkg/universal");
    let Ok(entries) = std::fs::read_dir(&pkg_dir) else {
        return Vec::new();
    };

    let mut results = Vec::new();
    for entry in entries.flatten() {
        let prebuilds = entry.path().join("prebuilds");
        if !prebuilds.exists() {
            continue;
        }
        // Check all arch directories (darwin-arm64, darwin-x64, etc.)
        if let Ok(arch_entries) = std::fs::read_dir(&prebuilds) {
            for arch_entry in arch_entries.flatten() {
                let module_path = arch_entry.path().join(module_name);
                if module_path.exists() {
                    results.push(module_path);
                }
            }
        }
    }
    results.sort();
    results
}

#[cfg(test)]
#[allow(clippy::disallowed_methods)] // test code: no unsandboxed parent to protect (#239)
mod tests {
    use super::*;

    /// Run git in `dir`, ignoring the developer's own git config.
    fn git_in(dir: &Path, args: &[&str]) -> bool {
        std::process::Command::new("git")
            .args(args)
            .current_dir(dir)
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_AUTHOR_NAME", "t")
            .env("GIT_AUTHOR_EMAIL", "t@example.invalid")
            .env("GIT_COMMITTER_NAME", "t")
            .env("GIT_COMMITTER_EMAIL", "t@example.invalid")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .is_ok_and(|s| s.success())
    }

    /// A `commondir` file planted inside the project's own gitdir must not be
    /// able to steer the sandbox grant at a different repository.
    ///
    /// Git reads `$GIT_DIR/commondir` for any gitdir, not only worktrees, and
    /// its contents come straight back out of `git rev-parse
    /// --git-common-dir`. The under-$HOME and unsafe-root checks do not catch
    /// it: the target is a genuine repo in a perfectly ordinary place. Without
    /// the layout check the victim's whole object store would be granted
    /// read+write.
    #[test]
    fn git_common_dir_rejects_a_planted_commondir() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let home = &std::fs::canonicalize(tmp.path()).expect("canonicalize tmp");
        let home = home.as_path();
        let attacker = home.join("attacker");
        let victim = home.join("victim");
        std::fs::create_dir_all(&attacker).expect("mkdir attacker");
        std::fs::create_dir_all(&victim).expect("mkdir victim");
        if !git_in(&attacker, &["init", "-q", "-b", "main"])
            || !git_in(&victim, &["init", "-q", "-b", "main"])
        {
            eprintln!("SKIPPED: git unavailable");
            return;
        }

        // Sanity: an ordinary repo is not a worktree, so there is no grant.
        assert_eq!(
            git_common_dir(home, &attacker),
            None,
            "a plain repo must not produce a common-dir grant"
        );

        // The agent has write access to its own project tree, so it can write
        // this file. Git now reports the victim's .git as the common dir.
        std::fs::write(
            attacker.join(".git/commondir"),
            victim.join(".git").to_string_lossy().as_bytes(),
        )
        .expect("plant commondir");

        assert_eq!(
            git_common_dir(home, &attacker),
            None,
            "a planted commondir must not grant access to another repository"
        );
    }

    /// The layout check must not break the case it exists to allow: a real
    /// `git worktree add` still resolves to the main repo's `.git`.
    #[test]
    fn git_common_dir_still_resolves_a_real_worktree() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let home = &std::fs::canonicalize(tmp.path()).expect("canonicalize tmp");
        let home = home.as_path();
        let main = home.join("main");
        std::fs::create_dir_all(&main).expect("mkdir main");
        if !git_in(&main, &["init", "-q", "-b", "main"]) {
            eprintln!("SKIPPED: git unavailable");
            return;
        }
        std::fs::write(main.join("f.txt"), "x").expect("write");
        assert!(git_in(&main, &["add", "-A"]), "git add");
        assert!(git_in(&main, &["commit", "-qm", "init"]), "git commit");

        let wt = home.join("wt");
        assert!(
            git_in(
                &main,
                &["worktree", "add", "-q", "-b", "feat", &wt.to_string_lossy()]
            ),
            "git worktree add"
        );

        let expected = std::fs::canonicalize(main.join(".git")).expect("canonicalize .git");
        assert_eq!(
            git_common_dir(home, &wt),
            Some(expected),
            "a real worktree must still resolve to the main repo's .git"
        );
    }

    /// A common dir that cannot be interpolated into the profile must be
    /// skipped, not turned into a launch failure.
    ///
    /// `prepare()` returns Err on the first path containing an SBPL-unsafe
    /// character, and this path is read off the filesystem — so a directory
    /// named with a quote would otherwise stop cplt starting at all, whose only
    /// remedy is to run the agent unsandboxed.
    #[test]
    fn git_common_dir_skips_an_unquotable_path_instead_of_failing() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let home = &std::fs::canonicalize(tmp.path()).expect("canonicalize tmp");
        let home = home.as_path();
        let main = home.join("ma\"in");
        std::fs::create_dir_all(&main).expect("mkdir main");
        if !git_in(&main, &["init", "-q", "-b", "main"]) {
            eprintln!("SKIPPED: git unavailable");
            return;
        }
        std::fs::write(main.join("f.txt"), "x").expect("write");
        assert!(git_in(&main, &["add", "-A"]), "git add");
        assert!(git_in(&main, &["commit", "-qm", "init"]), "git commit");

        let wt = home.join("wt");
        assert!(
            git_in(
                &main,
                &["worktree", "add", "-q", "-b", "feat", &wt.to_string_lossy()],
            ),
            "git worktree add"
        );

        // Precondition: this really is a path prepare() would reject.
        assert!(
            crate::sandbox::validate_sbpl_path(&main.join(".git")).is_err(),
            "fixture must produce an SBPL-unsafe path"
        );
        assert_eq!(
            git_common_dir(home, &wt),
            None,
            "an unquotable common dir must be skipped, not returned for \
             prepare() to hard-error on"
        );
    }

    /// Without a trusted git, a worktree's gitdir must still resolve — it is
    /// where the real hooks live, and losing it means losing their write deny.
    /// The `.git` file is read directly; nothing is spawned.
    #[test]
    fn gitdir_without_git_follows_a_worktree_to_the_shared_dir() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let root = std::fs::canonicalize(tmp.path()).expect("canonicalize");
        let main_git = root.join("main/.git");
        let per_worktree = main_git.join("worktrees/wt");
        std::fs::create_dir_all(&per_worktree).expect("mkdir");
        // What `git worktree add` writes: the pointer names the per-worktree
        // dir, which names the shared dir in its own `commondir`.
        std::fs::write(per_worktree.join("commondir"), "../..\n").expect("write commondir");
        let wt = root.join("wt");
        std::fs::create_dir_all(&wt).expect("mkdir");
        std::fs::write(
            wt.join(".git"),
            format!("gitdir: {}\n", per_worktree.display()),
        )
        .expect("write");

        // The SHARED dir, not the per-worktree one: `hooks/` and `config` live
        // there, and it is what `git rev-parse --git-common-dir` returns.
        assert_eq!(gitdir_without_git(&wt).as_deref(), Some(main_git.as_path()));
    }

    /// The wiring, not just the helper: with no trusted git, `git_dir_of` must
    /// fall back rather than return `None`. Untestable through `git_dir_of`
    /// itself on a host that has git — `trusted_git()` caches — so the invoker
    /// result is injected.
    #[test]
    fn git_dir_of_falls_back_when_there_is_no_trusted_git() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let root = std::fs::canonicalize(tmp.path()).expect("canonicalize");
        let proj = root.join("proj");
        std::fs::create_dir_all(proj.join(".git")).expect("mkdir");

        assert_eq!(
            git_dir_of_with(None, &proj).as_deref(),
            Some(proj.join(".git").as_path()),
            "no trusted git must fall back to reading .git, not fail open"
        );
    }

    /// `read_to_string` on a FIFO blocks forever with no writer. An agent that
    /// can write `<root>/.git` could `mkfifo` it and hang the next launch
    /// before the sandbox exists. Real git exits rather than blocking.
    #[test]
    fn gitdir_without_git_refuses_a_non_regular_dot_git() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let root = std::fs::canonicalize(tmp.path()).expect("canonicalize");
        let proj = root.join("proj");
        std::fs::create_dir_all(&proj).expect("mkdir");
        let fifo = proj.join(".git");

        let made = std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .is_ok_and(|s| s.success());
        if !made {
            return; // no mkfifo on this machine — nothing to assert
        }
        assert_eq!(
            gitdir_without_git(&proj),
            None,
            "a FIFO .git must be refused, not read"
        );
    }

    /// A `.git` symlink to a real gitdir is a supported layout, and git follows
    /// it. Reading link metadata instead would take the pointer-file branch and
    /// fail with EISDIR, losing the target's denies.
    #[test]
    fn gitdir_without_git_follows_a_dot_git_symlink() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let root = std::fs::canonicalize(tmp.path()).expect("canonicalize");
        let real = root.join("elsewhere.git");
        std::fs::create_dir_all(&real).expect("mkdir");
        let proj = root.join("proj");
        std::fs::create_dir_all(&proj).expect("mkdir");
        std::os::unix::fs::symlink(&real, proj.join(".git")).expect("symlink");

        assert_eq!(gitdir_without_git(&proj).as_deref(), Some(real.as_path()));
    }

    /// A relative pointer is the form git actually writes for a submodule.
    #[test]
    fn gitdir_without_git_resolves_a_relative_pointer() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let root = std::fs::canonicalize(tmp.path()).expect("canonicalize");
        let real = root.join(".git/modules/sub");
        std::fs::create_dir_all(&real).expect("mkdir");
        let sub = root.join("sub");
        std::fs::create_dir_all(&sub).expect("mkdir");
        std::fs::write(sub.join(".git"), "gitdir: ../.git/modules/sub\n").expect("write");

        assert_eq!(gitdir_without_git(&sub).as_deref(), Some(real.as_path()));
    }

    #[test]
    fn gitdir_without_git_handles_a_plain_repo_and_a_non_repo() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let root = std::fs::canonicalize(tmp.path()).expect("canonicalize");

        let plain = root.join("plain");
        std::fs::create_dir_all(plain.join(".git")).expect("mkdir");
        assert_eq!(
            gitdir_without_git(&plain).as_deref(),
            Some(plain.join(".git").as_path())
        );

        let bare = root.join("nothing");
        std::fs::create_dir_all(&bare).expect("mkdir");
        assert_eq!(gitdir_without_git(&bare), None, "no .git entry at all");
    }

    /// A pointer that does not resolve to a directory is refused rather than
    /// returned — the git-backed path applies the same `is_dir` check.
    #[test]
    fn gitdir_without_git_refuses_a_dangling_pointer() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let root = std::fs::canonicalize(tmp.path()).expect("canonicalize");
        let dir = root.join("proj");
        std::fs::create_dir_all(&dir).expect("mkdir");
        std::fs::write(dir.join(".git"), "gitdir: /nonexistent/elsewhere\n").expect("write");
        assert_eq!(gitdir_without_git(&dir), None);

        std::fs::write(dir.join(".git"), "not a pointer at all\n").expect("write");
        assert_eq!(gitdir_without_git(&dir), None);
    }

    /// `git_dir_of` is the resolver behind the #212 sibling-repo protections;
    /// each shape below places the hooks somewhere different.
    #[test]
    fn git_dir_of_resolves_every_repo_shape() {
        let base = tempfile::tempdir().expect("tempdir");
        let git = |args: &[&str], cwd: &Path| {
            let ok = std::process::Command::new("git")
                .args(args)
                .current_dir(cwd)
                .env("GIT_AUTHOR_NAME", "t")
                .env("GIT_AUTHOR_EMAIL", "t@e")
                .env("GIT_COMMITTER_NAME", "t")
                .env("GIT_COMMITTER_EMAIL", "t@e")
                .output()
                .expect("run git")
                .status
                .success();
            assert!(ok, "git {args:?} should succeed");
        };

        // Not a repo, and not inside one: a no-op, never an error.
        let plain = base.path().join("plain");
        std::fs::create_dir(&plain).unwrap();
        // A tempdir can itself live inside a repo (TMPDIR under a checkout), and
        // git would then walk up and find that one — assert only when it does not.
        if git_dir_of(base.path()).is_none() {
            assert!(
                git_dir_of(&plain).is_none(),
                "a path outside any repo must resolve to None"
            );
        }
        assert!(
            git_dir_of(&base.path().join("does-not-exist")).is_none(),
            "a path that does not exist must resolve to None"
        );

        // Normal repo, and a subdirectory of it: the repo's own .git.
        let repo = base.path().join("repo");
        std::fs::create_dir(&repo).unwrap();
        git(&["init", "--quiet"], &repo);
        git(&["commit", "--quiet", "--allow-empty", "-m", "x"], &repo);
        let repo_git = std::fs::canonicalize(repo.join(".git")).unwrap();
        assert_eq!(git_dir_of(&repo), Some(repo_git.clone()));
        let sub = repo.join("sub");
        std::fs::create_dir(&sub).unwrap();
        assert_eq!(
            git_dir_of(&sub),
            Some(repo_git.clone()),
            "a grant inside a repo resolves to that repo's .git"
        );

        // Worktree: the shared .git of the MAIN repo, not <worktree>/.git.
        let wt = base.path().join("wt");
        git(
            &[
                "worktree",
                "add",
                "--quiet",
                "-b",
                "b2",
                wt.to_str().unwrap(),
            ],
            &repo,
        );
        assert_eq!(
            git_dir_of(&wt),
            Some(repo_git),
            "a worktree resolves to the main repo's shared .git"
        );

        // Bare repo: the repo directory itself (hooks live at <root>/hooks).
        let bare = base.path().join("bare.git");
        std::fs::create_dir(&bare).unwrap();
        git(&["init", "--bare", "--quiet"], &bare);
        assert_eq!(
            git_dir_of(&bare),
            Some(std::fs::canonicalize(&bare).unwrap()),
            "a bare repo resolves to itself"
        );
    }

    #[test]
    fn which_resolved_finds_common_tools() {
        // /usr/bin/true should always exist on macOS/Linux
        let result = which_resolved("true");
        assert!(result.is_some(), "should find 'true' in PATH");
    }

    #[test]
    fn which_resolved_returns_none_for_missing() {
        let result = which_resolved("nonexistent-tool-xyz-12345");
        assert!(result.is_none());
    }

    #[test]
    fn find_native_modules_handles_missing_dir() {
        let fake_home = PathBuf::from("/nonexistent/home/xyz");
        let result = find_native_modules(&fake_home, "keytar.node");
        assert!(result.is_empty());
    }

    #[test]
    fn auth_discovery_detects_env_vars() {
        let home = PathBuf::from(std::env::var("HOME").unwrap());
        temp_env::with_var("COPILOT_GITHUB_TOKEN", Some("test-token-value"), || {
            let auth = discover_auth(&home);
            assert!(
                auth.env_tokens
                    .contains(&"COPILOT_GITHUB_TOKEN".to_string())
            );
        });
    }

    #[test]
    fn auth_any_available_with_env_token() {
        let auth = AuthDiscovery {
            env_tokens: vec!["GH_TOKEN".to_string()],
            gh_cli_auth: false,
            gh_config_exists: false,
            security_cli_exists: false,
            keytar_nodes: vec![],
        };
        assert!(auth.any_auth_available());
    }

    #[test]
    fn auth_none_available_when_empty() {
        let auth = AuthDiscovery {
            env_tokens: vec![],
            gh_cli_auth: false,
            gh_config_exists: false,
            security_cli_exists: false,
            keytar_nodes: vec![],
        };
        assert!(!auth.any_auth_available());
    }

    #[test]
    fn tool_discovery_finds_git() {
        let home = PathBuf::from(std::env::var("HOME").unwrap());
        let tools = discover_tools(&home, &[]);
        assert!(
            tools.tools.iter().any(|t| t.name == "git"),
            "git should be found on any dev machine"
        );
    }

    #[test]
    fn path_discovery_runs_without_panic() {
        let home = PathBuf::from(std::env::var("HOME").unwrap());
        let project = std::env::current_dir().unwrap();
        let paths = discover_paths(&home, &project);
        // Just verify it doesn't panic and returns plausible results
        let _ = paths.copilot_dir_exists;
    }

    // ── Electron app discovery ──────────────────────────────────

    #[test]
    fn extract_quoted_paths_finds_absolute_paths() {
        let content = r#"#!/bin/sh
ELECTRON_RUN_AS_NODE=1 "/Applications/Visual Studio Code.app/Contents/Frameworks/Code Helper (Plugin).app/Contents/MacOS/Code Helper (Plugin)" "/Users/test/copilotCLIShim.js" "$@"
"#;
        let paths = extract_quoted_paths(content);
        assert_eq!(paths.len(), 2);
        assert_eq!(
            paths[0],
            PathBuf::from(
                "/Applications/Visual Studio Code.app/Contents/Frameworks/Code Helper (Plugin).app/Contents/MacOS/Code Helper (Plugin)"
            )
        );
        assert_eq!(paths[1], PathBuf::from("/Users/test/copilotCLIShim.js"));
    }

    #[test]
    fn extract_quoted_paths_skips_relative_and_variables() {
        let content = r#"#!/bin/sh
"relative/path" "$@" "/absolute/path"
"#;
        let paths = extract_quoted_paths(content);
        assert_eq!(paths.len(), 1);
        assert_eq!(paths[0], PathBuf::from("/absolute/path"));
    }

    #[test]
    fn find_app_contents_outermost_bundle() {
        // Nested .app bundles — should return the outermost .app/Contents
        let path = PathBuf::from(
            "/Applications/Visual Studio Code.app/Contents/Frameworks/Code Helper (Plugin).app/Contents/MacOS/Code Helper (Plugin)",
        );
        let result = find_app_contents(&path);
        assert_eq!(
            result.unwrap(),
            PathBuf::from("/Applications/Visual Studio Code.app/Contents")
        );
    }

    #[test]
    fn find_app_contents_single_bundle() {
        let path = PathBuf::from("/Applications/Cursor.app/Contents/MacOS/Cursor");
        let result = find_app_contents(&path);
        assert_eq!(
            result.unwrap(),
            PathBuf::from("/Applications/Cursor.app/Contents")
        );
    }

    #[test]
    fn find_app_contents_no_bundle() {
        let path = PathBuf::from("/usr/local/bin/node");
        let result = find_app_contents(&path);
        assert!(result.is_none());
    }

    #[test]
    fn find_app_contents_home_applications() {
        let path = PathBuf::from(
            "/Users/test/Applications/Visual Studio Code - Insiders.app/Contents/Frameworks/Code Helper.app/Contents/MacOS/Code Helper",
        );
        let result = find_app_contents(&path);
        assert_eq!(
            result.unwrap(),
            PathBuf::from("/Users/test/Applications/Visual Studio Code - Insiders.app/Contents")
        );
    }

    #[test]
    fn discover_electron_app_non_shim_returns_none() {
        // A compiled binary (non-text) should return None
        let tmp = std::env::temp_dir().join("cplt-test-binary");
        std::fs::write(&tmp, [0x7f, 0x45, 0x4c, 0x46]).unwrap(); // ELF magic
        let result = discover_electron_app(&tmp);
        std::fs::remove_file(&tmp).ok();
        assert!(result.is_none());
    }

    #[test]
    fn discover_electron_app_non_copilot_shim_returns_none() {
        // A shell script without copilotCLIShim.js marker
        let tmp = std::env::temp_dir().join("cplt-test-non-copilot");
        std::fs::write(&tmp, "#!/bin/sh\necho hello\n").unwrap();
        let result = discover_electron_app(&tmp);
        std::fs::remove_file(&tmp).ok();
        assert!(result.is_none());
    }

    #[test]
    fn copilot_sea_cache_dir_returns_none_if_missing() {
        let tmp = std::env::temp_dir().join("cplt-test-no-cache");
        assert!(copilot_sea_cache_dir(&tmp).is_none());
    }

    #[test]
    fn copilot_sea_cache_dir_returns_some_if_parent_exists() {
        let tmp = std::env::temp_dir().join("cplt-test-cache-parent");
        std::fs::create_dir_all(tmp.join(".cache/copilot")).unwrap();
        let expected = tmp.join(".cache/copilot/pkg");
        assert_eq!(copilot_sea_cache_dir(&tmp), Some(expected));
    }

    #[test]
    fn copilot_sea_cache_dir_returns_some_if_exists() {
        let tmp = std::env::temp_dir().join("cplt-test-cache-exists");
        std::fs::create_dir_all(tmp.join(".cache/copilot/pkg")).unwrap();
        let expected = tmp.join(".cache/copilot/pkg");
        assert_eq!(copilot_sea_cache_dir(&tmp), Some(expected));
    }

    // ── #298: version probes must not hang doctor ───────────────

    /// Write an executable shell script with the given body. Callers that care
    /// which process the probe kills use `exec ...`, so the direct child of the
    /// probe *is* that command and no intermediate shell absorbs the signal.
    #[cfg(unix)]
    fn fake_binary(dir: &Path, name: &str, body: &str) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let path = dir.join(name);
        std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        path
    }

    /// A binary that never exits must be given up on, not waited for forever.
    ///
    /// The bound is the point of the test: before #298 this call never
    /// returned, and a regression must fail CI rather than wedge it. The fake
    /// sleeps far longer than [`PROBE_TIMEOUT`], so a broken timeout caps out
    /// at the sleep and then fails the elapsed assertion.
    #[cfg(unix)]
    #[test]
    fn version_probe_gives_up_on_a_binary_that_never_exits() {
        let dir = tempfile::tempdir().unwrap();
        // The fake ticks a file for as long as it lives, so its liveness is
        // observable from the filesystem: no `pgrep`, no `ps`, nothing that can
        // be absent from the machine and turn the orphan check below into a
        // silent pass.
        let heartbeat = dir.path().join("alive");
        let bin = fake_binary(
            dir.path(),
            "wedged",
            &format!(
                "exec sh -c 'while : ; do printf x >> \"{}\" ; sleep 0.2 ; done'",
                heartbeat.display()
            ),
        );

        let start = Instant::now();
        let outcome = probe_version(&bin, &["--version"]);
        let elapsed = start.elapsed();

        assert_eq!(
            outcome,
            VersionProbe::TimedOut,
            "a wedged probe reports TimedOut"
        );
        assert!(
            elapsed < PROBE_TIMEOUT * 3,
            "probe should return near PROBE_TIMEOUT, took {elapsed:?}"
        );

        // Killing without reaping turns one hang into an orphan that outlives
        // the command — the exact state found on the machine in #298. Dropping
        // the Child handle does not do this, so prove the process is gone: a
        // dead ticker stops growing its file.
        let ticks = || std::fs::metadata(&heartbeat).map_or(0, |m| m.len());
        let before = ticks();
        assert!(
            before > 0,
            "the fake never ran, so the check proves nothing"
        );
        std::thread::sleep(Duration::from_millis(800));
        assert_eq!(ticks(), before, "timed-out probe left the child running");
    }

    /// A probe that exits but leaves a child holding its stdout must still
    /// return: waiting for EOF on that pipe is the same hang wearing a
    /// different hat, so the read is bounded too.
    #[cfg(unix)]
    #[test]
    fn version_probe_gives_up_when_a_grandchild_holds_the_pipe() {
        let dir = tempfile::tempdir().unwrap();
        // Bounded on purpose: the grandchild only has to outlive the probe's
        // read grace, and a short sleep cleans itself up instead of needing a
        // `pkill` this test cannot guarantee exists.
        let bin = fake_binary(dir.path(), "forker", "sleep 30 &\nexit 0");

        let start = Instant::now();
        let outcome = probe_version(&bin, &["--version"]);
        assert_eq!(outcome, VersionProbe::Unknown);
        assert!(
            start.elapsed() < PROBE_TIMEOUT,
            "a held-open pipe must not extend the probe, took {:?}",
            start.elapsed()
        );
    }

    /// The happy path still parses, and a binary that answers is never
    /// misreported as timed out.
    #[cfg(unix)]
    #[test]
    fn version_probe_parses_a_prompt_answer() {
        let dir = tempfile::tempdir().unwrap();
        let ok = fake_binary(dir.path(), "quick", "exec echo GitHub Copilot CLI 1.0.21.");
        assert_eq!(
            probe_version(&ok, &["--version"]),
            VersionProbe::Version("1.0.21".to_string())
        );

        // Non-zero exit is "ran, said nothing useful" — not a timeout.
        let bad = fake_binary(dir.path(), "broken", "exec false");
        assert_eq!(probe_version(&bad, &["--version"]), VersionProbe::Unknown);
    }
}

#[cfg(test)]
mod wsl_tool_report_tests {
    use super::*;

    fn tool(name: &str, path: &str) -> ToolInfo {
        ToolInfo {
            name: name.to_string(),
            path: PathBuf::from(path),
        }
    }

    /// The doctor line itself, not the predicate: a Windows-side `npm` must be
    /// graded red and must fail the critical checks (#271).
    #[test]
    fn windows_side_critical_tool_is_reported_red_and_fails_critical() {
        let tools = vec![tool("npm", "/mnt/c/Users/N129069/AppData/Roaming/npm/npm")];
        let (lines, ok) = tool_lines(&tools, true);
        assert!(!ok, "a Windows-side npm must fail the critical checks");
        assert!(
            lines[0].contains('\u{2717}') && !lines[0].contains('\u{2713}'),
            "expected a red cross, got: {}",
            lines[0]
        );
        assert!(
            lines[0].contains("/mnt/c/Users/N129069/AppData/Roaming/npm/npm"),
            "the line must name the offending path, got: {}",
            lines[0]
        );
    }

    /// A non-critical tool is only warned about — it is not a broken install.
    #[test]
    fn windows_side_build_tool_is_warned_not_failed() {
        let tools = vec![tool(
            "gradle",
            "/mnt/c/apps/Gradle/gradle-8.10.2/bin/gradle",
        )];
        let (lines, ok) = tool_lines(&tools, true);
        assert!(
            ok,
            "a Windows-side gradle is a warning, not a critical failure"
        );
        assert!(
            lines[0].contains('\u{26a0}'),
            "expected a warning sign, got: {}",
            lines[0]
        );
    }

    /// Off WSL, `/mnt/c` is an ordinary mount and the tool is fine.
    #[test]
    fn mnt_path_outside_wsl_stays_green() {
        let tools = vec![tool("npm", "/mnt/c/npm")];
        let (lines, ok) = tool_lines(&tools, false);
        assert!(ok);
        assert!(lines[0].contains('\u{2713}'), "got: {}", lines[0]);
    }

    /// npm is the tool the reporter actually tripped over, so it has to be
    /// probed at all (#271).
    #[test]
    fn npm_is_checked() {
        assert!(TOOLS_TO_CHECK.contains(&"npm"));
    }
}
