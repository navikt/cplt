//! PATH shims: one script per installed agent in `~/.local/share/cplt/bin`,
//! each running that agent under cplt (#514, steps 1 to 3).
//!
//! Opt-in and off by default. Nothing here writes a file until
//! `cplt --shell-install --shims` has created the shim directory. Every other
//! entry point (the sync that `--shell-setup`, each launch and `cplt doctor`
//! run) checks for the directory first and does nothing without it.
//! `cplt --shell-uninstall` removes what the install added.
//!
//! A shim is a script, not a symlink: it has to pin `--agent`, for the reason
//! #513's alias does, and a symlink cannot carry an argument.

use crate::agent::Agent;
use std::path::{Path, PathBuf};

/// The shim directory, relative to `$HOME`. `CPLT_CONFIG` does not move it:
/// the static PATH lines in the rc files name it, and they never run cplt.
pub const SHIM_DIR: &str = ".local/share/cplt/bin";

/// Second line of every shim, followed by the agent it pins. What makes a file
/// in the shim directory ours to rewrite or remove.
const SHIM_MARKER: &str = "# cplt-shim: ";

/// Managed rc block markers.
pub const BLOCK_BEGIN: &str = "# >>> cplt >>>";
pub const BLOCK_END: &str = "# <<< cplt <<<";

/// Suffix of the copy taken of an rc file before cplt first edits it.
pub const BACKUP_SUFFIX: &str = ".cplt-backup";

/// The PATH line for the POSIX rc files. Static on purpose: `.zshenv` runs for
/// every zsh process on the machine, and an rc line that runs a binary is the
/// cost that makes an IDE's environment resolution give up (#514).
pub const POSIX_PATH_LINE: &str = "export PATH=\"$HOME/.local/share/cplt/bin:$PATH\"";

/// The fish equivalent. `--global --path` changes `$PATH` for this shell
/// only; the default (universal `fish_user_paths`) would persist past an
/// uninstall.
pub const FISH_PATH_LINE: &str = "fish_add_path --global --path --move $HOME/.local/share/cplt/bin";

#[must_use]
pub fn dir(home: &Path) -> PathBuf {
    home.join(SHIM_DIR)
}

/// Whether the user has opted in. The shim directory is the switch: only
/// `--shell-install --shims` creates it, and only `--shell-uninstall` removes it.
#[must_use]
pub fn installed(home: &Path) -> bool {
    dir(home).is_dir()
}

/// Every agent that gets a shim: all of them but `shell`, which has no binary.
pub fn shimmable() -> impl Iterator<Item = Agent> {
    Agent::ALL.iter().copied().filter(|a| *a != Agent::Shell)
}

fn home_from_env() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .filter(|h| !h.is_empty())
        .map(PathBuf::from)
}

/// Whether the PATH entry `entry` is the shim directory, spelled directly or
/// through a symlink.
#[must_use]
pub fn is_shim_dir(home: &Path, entry: &Path) -> bool {
    let d = dir(home);
    if entry == d {
        return true;
    }
    match (std::fs::canonicalize(entry), std::fs::canonicalize(&d)) {
        (Ok(a), Ok(b)) => a == b,
        _ => false,
    }
}

/// Whether an agent-binary candidate found on PATH is one of our shims, so the
/// resolver must skip it.
///
/// Without this, cplt would find its own shim as "the agent", launch it inside
/// the sandbox, and hit the `__CPLT_WRAPPED` recursion guard. The check covers
/// the candidate's directory and, through `canonicalize`, a symlink elsewhere on
/// PATH that points into the shim directory.
#[must_use]
pub fn skip_candidate(candidate: &Path) -> bool {
    let Some(home) = home_from_env() else {
        return false;
    };
    let in_dir = |p: &Path| p.parent().is_some_and(|parent| is_shim_dir(&home, parent));
    in_dir(candidate) || std::fs::canonicalize(candidate).is_ok_and(|c| in_dir(&c))
}

/// `path` (a `PATH` value) with the shim directory taken out, or `None` when it
/// was not there. Inside the sandbox the agent's own name must resolve to the
/// real binary: a shim there would only start a nested cplt, which is refused.
#[must_use]
pub fn path_without_shims(home: &Path, path: &str) -> Option<String> {
    let kept: Vec<&str> = path
        .split(':')
        .filter(|e| e.is_empty() || !is_shim_dir(home, Path::new(e)))
        .collect();
    let joined = kept.join(":");
    (joined != path).then_some(joined)
}

/// The first executable `name` on `path_var` that is not a shim and not cplt
/// itself. This is the real agent a shim stands in for.
#[must_use]
pub fn real_binary_in(path_var: &str, home: &Path, name: &str) -> Option<PathBuf> {
    let self_exe = std::env::current_exe()
        .ok()
        .and_then(|p| std::fs::canonicalize(p).ok());
    path_var
        .split(':')
        .filter(|d| !d.is_empty() && !is_shim_dir(home, Path::new(d)))
        .map(|d| Path::new(d).join(name))
        .filter(|c| crate::git::is_executable_file(c))
        .find(|c| {
            let resolved = std::fs::canonicalize(c).ok();
            // A symlink into the shim dir is a shim under another name.
            resolved.as_ref().is_none_or(|r| {
                self_exe.as_ref() != Some(r) && !r.parent().is_some_and(|p| is_shim_dir(home, p))
            })
        })
}

/// [`real_binary_in`] against this process's `PATH` and `$HOME`.
#[must_use]
pub fn real_binary(name: &str) -> Option<PathBuf> {
    let home = home_from_env()?;
    real_binary_in(&std::env::var("PATH").unwrap_or_default(), &home, name)
}

/// The shim script for `agent`.
///
/// - `__CPLT_WRAPPED` set means we are already inside a cplt sandbox. The
///   sandbox's PATH drops the shim directory, so reaching a shim there means
///   something ran it by path; exec'ing cplt again would only be refused, so
///   say why here instead.
/// - A missing `cplt` fails with 127 and names the fix. The shim never falls
///   through to the real agent: it does not know where that is, and looking
///   for it would make the shim fail open.
/// - Arguments pass after `--`, so none of them is read as a cplt flag.
#[must_use]
pub fn script(agent: Agent) -> String {
    let flag = agent.binary_name();
    format!(
        "#!/bin/sh\n\
         {SHIM_MARKER}{flag}\n\
         # Runs {name} inside the cplt sandbox. Written by `cplt --shell-install --shims`;\n\
         # `cplt --shell-uninstall` removes it. Edits are overwritten.\n\
         if [ -n \"${{__CPLT_WRAPPED:-}}\" ]; then\n  \
           echo \"cplt: $0 is a cplt shim and this is already a cplt sandbox; refusing to start cplt inside itself.\" >&2\n  \
           exit 126\n\
         fi\n\
         if ! command -v cplt >/dev/null 2>&1; then\n  \
           echo \"cplt is not installed; run 'cplt --shell-uninstall' before removing it, or delete ~/{SHIM_DIR}\" >&2\n  \
           exit 127\n\
         fi\n\
         exec cplt --agent {flag} -- \"$@\"\n",
        name = agent.display_name(),
    )
}

fn is_ours(path: &Path) -> bool {
    std::fs::read_to_string(path)
        .is_ok_and(|c| c.lines().nth(1).is_some_and(|l| l.starts_with(SHIM_MARKER)))
}

/// Whether `--version` output is the agent cplt knows by that name.
///
/// Only `goose` and `pi` are checked: `goose` is also pressly/goose, the Go
/// migration tool, and `pi` is taken by unrelated packages. The shapes were
/// read from each project's source, not remembered:
///
/// - Block's goose is a clap `#[command(name = "goose", version, display_name = "")]`,
///   printing `goose 1.15.0` or ` 1.15.0`. pressly/goose prints
///   `goose version: v3.x` (`cmd/goose/main.go`).
/// - Pi's release smoke test (`scripts/coding-agent-consumer.mjs`) requires
///   `pi --version` to print exactly the package version.
///
/// A heuristic, not a guarantee; `shell.skip` is the escape hatch.
#[must_use]
pub fn version_matches(agent: Agent, output: &str) -> bool {
    let t = output.trim();
    let starts_digit = |s: &str| s.chars().next().is_some_and(|c| c.is_ascii_digit());
    match agent {
        Agent::Goose => starts_digit(t.strip_prefix("goose").unwrap_or(t).trim_start()),
        Agent::Pi => {
            starts_digit(t) && !t.contains(char::is_whitespace) && t.split('.').count() >= 3
        }
        _ => true,
    }
}

fn confirmed(agent: Agent, bin: &Path) -> bool {
    match agent {
        Agent::Goose | Agent::Pi => crate::discover::probe_output(bin, &["--version"])
            .is_some_and(|out| version_matches(agent, &out)),
        _ => true,
    }
}

/// Whether `skip` (the `shell.skip` list) names `agent`, by its `--agent`
/// name or any of its command names.
fn skipped(agent: Agent, skip: &[String]) -> bool {
    skip.iter()
        .any(|s| s == agent.binary_name() || agent.binary_names().contains(&s.as_str()))
}

/// Bring the shim directory in line with the agents on `path_var`.
///
/// A PATH walk plus a directory diff: it writes nothing when nothing changed,
/// never touches the network, and runs a version probe only for a `goose` or
/// `pi` that has no shim yet. One `done` line per change, one `refused` line
/// per file it could not bring in line; a failure on one agent does not stop
/// the others. Does nothing, and creates nothing, unless the shim directory
/// already exists.
#[must_use]
pub fn sync_in(home: &Path, path_var: &str, skip: &[String]) -> Report {
    let mut report = Report::default();
    let d = dir(home);
    if !d.is_dir() {
        return report;
    }
    for agent in shimmable() {
        let names = agent.binary_names();
        let want = script(agent);
        let is_current = |n: &str| std::fs::read_to_string(d.join(n)).is_ok_and(|c| c == want);
        let current = names.iter().all(|n| is_current(n));
        let installed = !skipped(agent, skip)
            && names
                .iter()
                .find_map(|n| real_binary_in(path_var, home, n))
                .is_some_and(|bin| current || confirmed(agent, &bin));
        for name in names {
            let shim = d.join(name);
            let result = if installed && !is_current(name) {
                write_shim(&shim, &want).map(|()| format!("wrote {}", shim.display()))
            } else if !installed && is_ours(&shim) {
                std::fs::remove_file(&shim)
                    .map(|()| format!("removed {}", shim.display()))
                    .map_err(|e| format!("cannot remove {}: {e}", shim.display()))
            } else {
                continue;
            };
            match result {
                Ok(line) => report.done.push(line),
                Err(e) => report.refused.push(e),
            }
        }
    }
    report
}

/// [`sync_in`] against this process's `PATH`.
#[must_use]
pub fn sync(home: &Path, skip: &[String]) -> Report {
    sync_in(home, &std::env::var("PATH").unwrap_or_default(), skip)
}

/// Write one shim: to a temporary name first, then renamed over, so a shell
/// never execs a half-written file. A file of that name we did not write is
/// left alone.
fn write_shim(path: &Path, contents: &str) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    if path.exists() && !is_ours(path) {
        return Err(format!(
            "{} exists and was not written by cplt; move it out of the shim directory",
            path.display()
        ));
    }
    let name = path.file_name().unwrap_or_default().to_string_lossy();
    let tmp = path.with_file_name(format!(".{name}.cplt-tmp"));
    std::fs::write(&tmp, contents)
        .and_then(|()| std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o755)))
        .and_then(|()| std::fs::rename(&tmp, path))
        .map_err(|e| {
            let _ = std::fs::remove_file(&tmp);
            format!("cannot write {}: {e}", path.display())
        })
}

// ── Managed rc block ─────────────────────────────────────────────

/// The alias definitions that make an agent's own command run sandboxed.
///
/// Each alias pins `--agent`. Without the pin, the aliased command runs plain
/// `cplt`, which falls back to auto-detection and launches whichever agent it
/// finds first — copilot, ahead of the one whose name you typed (#509). An
/// alias that sandboxes a different agent than the command promises is worse
/// than no alias, because nothing tells you.
#[must_use]
pub fn alias_lines(agent: Agent, fish: bool) -> Vec<String> {
    let flag = agent.binary_name();
    agent
        .binary_names()
        .iter()
        .map(|name| {
            if fish {
                format!("alias {name} 'cplt --agent {flag}'")
            } else {
                format!("alias {name}='cplt --agent {flag}'")
            }
        })
        .collect()
}

/// The `.zshrc`/`.bashrc` block line for `agent`: aliases plus the shim sync.
/// Guarded, so removing cplt without `--shell-uninstall` does not print
/// "command not found" at every shell start.
#[must_use]
pub fn eval_line(agent: Agent) -> String {
    format!(
        "command -v cplt >/dev/null 2>&1 && eval \"$(cplt --shell-setup --agent {})\"",
        agent.binary_name()
    )
}

/// Every line cplt may have written inside a block. A line outside this set
/// is someone else's, and the block is then left alone.
fn known_line(line: &str) -> bool {
    line == POSIX_PATH_LINE
        || line == FISH_PATH_LINE
        || shimmable()
            .any(|a| line == eval_line(a) || alias_lines(a, true).iter().any(|l| l == line))
}

/// Where the block is, as `(begin line index, end line index)`.
fn find_block(lines: &[&str]) -> Result<Option<(usize, usize)>, String> {
    let begins: Vec<usize> = (0..lines.len())
        .filter(|&i| lines[i].trim_end() == BLOCK_BEGIN)
        .collect();
    let ends: Vec<usize> = (0..lines.len())
        .filter(|&i| lines[i].trim_end() == BLOCK_END)
        .collect();
    match (begins.as_slice(), ends.as_slice()) {
        ([], []) => Ok(None),
        ([b], [e]) if b < e => Ok(Some((*b, *e))),
        _ => Err("its cplt block markers are unbalanced or repeated".to_string()),
    }
}

fn check_foreign(body: &[&str]) -> Result<(), String> {
    match body
        .iter()
        .find(|l| !known_line(l.trim_end_matches(['\n', '\r'])))
    {
        Some(l) => Err(format!(
            "the cplt block has a line cplt did not write ({}); edit it out, then run this again",
            l.trim_end()
        )),
        None => Ok(()),
    }
}

/// `contents` with the block holding `body` plus whatever cplt lines it
/// already held, or `None` when nothing changes.
///
/// # Errors
/// Unbalanced markers, or a line inside the block cplt did not write. Neither
/// is ever overwritten.
pub fn upsert_block(contents: &str, body: &[String]) -> Result<Option<String>, String> {
    let lines: Vec<&str> = contents.split_inclusive('\n').collect();
    match find_block(&lines)? {
        None => {
            let mut out = contents.to_string();
            if !out.is_empty() && !out.ends_with('\n') {
                out.push('\n');
            }
            out.push_str(&render_block(body));
            Ok(Some(out))
        }
        Some((b, e)) => {
            let existing = &lines[b + 1..e];
            check_foreign(existing)?;
            let mut merged: Vec<String> = existing
                .iter()
                .map(|l| l.trim_end_matches(['\n', '\r']).to_string())
                .collect();
            for line in body {
                if !merged.contains(line) {
                    merged.push(line.clone());
                }
            }
            let block = render_block(&merged);
            let old: String = lines[b..=e].concat();
            // The END line may lack its newline at EOF; compare the content.
            if old.trim_end() == block.trim_end() {
                return Ok(None);
            }
            Ok(Some(format!(
                "{}{block}{}",
                lines[..b].concat(),
                lines[e + 1..].concat()
            )))
        }
    }
}

/// `contents` without the block, or `None` when it has none.
///
/// # Errors
/// As [`upsert_block`].
pub fn remove_block(contents: &str) -> Result<Option<String>, String> {
    let lines: Vec<&str> = contents.split_inclusive('\n').collect();
    let Some((b, e)) = find_block(&lines)? else {
        return Ok(None);
    };
    check_foreign(&lines[b + 1..e])?;
    Ok(Some(format!(
        "{}{}",
        lines[..b].concat(),
        lines[e + 1..].concat()
    )))
}

fn render_block(body: &[String]) -> String {
    let mut out = format!("{BLOCK_BEGIN}\n");
    for line in body {
        out.push_str(line);
        out.push('\n');
    }
    out.push_str(BLOCK_END);
    out.push('\n');
    out
}

/// One rc file cplt manages, and what goes in its block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RcFile {
    pub path: PathBuf,
    pub body: Vec<String>,
}

/// The rc files an install writes, per the PRD's placement table.
///
/// `.zshenv`, `.zprofile` and `.profile` are created when missing; they carry
/// only the static PATH line. `.zshrc` is written when it exists or zsh is the
/// login shell, `.bashrc` only when it exists (creating bash files changes
/// whether `.profile` is read, which is Volta's rule too), and fish's
/// `conf.d/cplt.fish` when fish is the shell or is configured.
#[must_use]
pub fn rc_files(home: &Path, shell: &str, agent: Agent) -> Vec<RcFile> {
    let path_body = vec![POSIX_PATH_LINE.to_string()];
    let mut files = vec![
        RcFile {
            path: home.join(".zshenv"),
            body: path_body.clone(),
        },
        RcFile {
            path: home.join(".zprofile"),
            body: path_body.clone(),
        },
        RcFile {
            path: home.join(".profile"),
            body: path_body,
        },
    ];
    let zshrc = home.join(".zshrc");
    if zshrc.exists() || shell.ends_with("/zsh") {
        files.push(RcFile {
            path: zshrc,
            body: vec![eval_line(agent)],
        });
    }
    let bashrc = home.join(".bashrc");
    if bashrc.exists() {
        files.push(RcFile {
            path: bashrc,
            body: vec![eval_line(agent)],
        });
    }
    let fish_dir = home.join(".config/fish");
    if fish_dir.is_dir() || shell.ends_with("/fish") {
        let mut body = vec![FISH_PATH_LINE.to_string()];
        body.extend(alias_lines(agent, true));
        files.push(RcFile {
            path: fish_dir.join("conf.d/cplt.fish"),
            body,
        });
    }
    files
}

/// Every file an uninstall looks at, whether or not this machine's install
/// wrote to it.
fn all_rc_paths(home: &Path) -> Vec<PathBuf> {
    [
        ".zshenv",
        ".zprofile",
        ".profile",
        ".zshrc",
        ".bashrc",
        ".config/fish/conf.d/cplt.fish",
    ]
    .iter()
    .map(|f| home.join(f))
    .collect()
}

fn backup_path(path: &Path) -> PathBuf {
    let mut s = path.as_os_str().to_owned();
    s.push(BACKUP_SUFFIX);
    PathBuf::from(s)
}

/// What an install or uninstall did, one line per path.
#[derive(Debug, Default)]
pub struct Report {
    pub done: Vec<String>,
    /// Files left alone, and why. Non-empty makes the command exit non-zero.
    pub refused: Vec<String>,
}

/// Opt in: create the shim directory, sync it, and write the managed blocks.
///
/// An existing rc file gets a one-time copy at `<file>.cplt-backup` before its
/// first edit. Idempotent: a second run changes nothing.
#[must_use]
pub fn install(home: &Path, shell: &str, agent: Agent, skip: &[String]) -> Report {
    let mut report = Report::default();
    let d = dir(home);
    if !d.is_dir() {
        if let Err(e) = std::fs::create_dir_all(&d) {
            report
                .refused
                .push(format!("cannot create {}: {e}", d.display()));
            return report;
        }
        report.done.push(format!("created {}", d.display()));
    }
    let synced = sync(home, skip);
    report.done.extend(synced.done);
    report.refused.extend(synced.refused);
    for rc in rc_files(home, shell, agent) {
        match write_rc(&rc) {
            Ok(Some(line)) => report.done.push(line),
            Ok(None) => {}
            Err(e) => report.refused.push(e),
        }
    }
    report
}

fn write_rc(rc: &RcFile) -> Result<Option<String>, String> {
    let shown = rc.path.display();
    let existing = match std::fs::read_to_string(&rc.path) {
        Ok(c) => Some(c),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => return Err(format!("{shown}: cannot read: {e}")),
    };
    let current = existing.clone().unwrap_or_default();
    let Some(updated) = upsert_block(&current, &rc.body).map_err(|e| format!("{shown}: {e}"))?
    else {
        return Ok(None);
    };
    let backup = backup_path(&rc.path);
    // Once per file, before cplt's first edit. A file that already has a
    // block was either backed up then or created by the install, and an
    // uninstall tells those apart by whether the backup exists.
    let first_edit = !current.lines().any(|l| l.trim_end() == BLOCK_BEGIN);
    if existing.is_some() && first_edit && !backup.exists() {
        std::fs::copy(&rc.path, &backup)
            .map_err(|e| format!("{shown}: cannot back up to {}: {e}", backup.display()))?;
    }
    if let Some(parent) = rc.path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("{shown}: {e}"))?;
    }
    std::fs::write(&rc.path, updated).map_err(|e| format!("{shown}: cannot write: {e}"))?;
    Ok(Some(if existing.is_some() {
        format!("updated {shown} (backup: {})", backup.display())
    } else {
        format!("created {shown}")
    }))
}

/// Opt out: remove every block, the backups, the files the install created,
/// and the shims. Leaves anything cplt did not write, and says so.
#[must_use]
pub fn uninstall(home: &Path) -> Report {
    let mut report = Report::default();
    for path in all_rc_paths(home) {
        let shown = path.display();
        let Ok(contents) = std::fs::read_to_string(&path) else {
            continue;
        };
        let stripped = match remove_block(&contents) {
            Ok(Some(s)) => s,
            Ok(None) => continue,
            Err(e) => {
                report.refused.push(format!("{shown}: {e}"));
                continue;
            }
        };
        let backup = backup_path(&path);
        // No backup means the install created the file. Once the block is
        // gone and nothing else was added, the file goes too.
        let result = if !backup.exists() && stripped.trim().is_empty() {
            std::fs::remove_file(&path).map(|()| format!("removed {shown}"))
        } else {
            std::fs::write(&path, &stripped)
                .map(|()| format!("removed the cplt block from {shown}"))
        };
        match result {
            Ok(line) => report.done.push(line),
            Err(e) => {
                report.refused.push(format!("{shown}: {e}"));
                continue;
            }
        }
        if backup.exists() {
            match std::fs::remove_file(&backup) {
                Ok(()) => report.done.push(format!("removed {}", backup.display())),
                Err(e) => report.refused.push(format!("{}: {e}", backup.display())),
            }
        }
    }
    let d = dir(home);
    if let Ok(entries) = std::fs::read_dir(&d) {
        for entry in entries.flatten() {
            let p = entry.path();
            if is_ours(&p) {
                match std::fs::remove_file(&p) {
                    Ok(()) => report.done.push(format!("removed {}", p.display())),
                    Err(e) => report.refused.push(format!("{}: {e}", p.display())),
                }
            }
        }
        // `remove_dir` refuses a non-empty directory, which is the point:
        // anything left in it is not ours.
        match std::fs::remove_dir(&d) {
            Ok(()) => {
                report.done.push(format!("removed {}", d.display()));
                // The install's `create_dir_all` may have made these too.
                // Only empty ones go, so anything else in them keeps them.
                for parent in d.ancestors().skip(1).take_while(|p| *p != home) {
                    if std::fs::remove_dir(parent).is_err() {
                        break;
                    }
                    report.done.push(format!("removed {}", parent.display()));
                }
            }
            Err(e) => report.refused.push(format!(
                "{}: {e}; it holds files cplt did not write",
                d.display()
            )),
        }
    }
    report
}

/// Where the first `name` on `path_var` lives, with no shim skipping: the
/// command the user's shell would run.
#[must_use]
pub fn first_on_path(path_var: &str, name: &str) -> Option<PathBuf> {
    path_var
        .split(':')
        .filter(|d| !d.is_empty())
        .map(|d| Path::new(d).join(name))
        .find(|c| crate::git::is_executable_file(c))
}

/// How a shim fares against the PATH `cplt doctor` was started with: Volta's
/// `check_shim_reachable`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reach {
    /// The shim is what the name resolves to.
    First,
    /// Something else comes first.
    Shadowed(PathBuf),
}

/// Reachability of each shim in the directory, or `None` when the directory
/// is not on `path_var` at all (no rc file cplt wrote is being read).
#[must_use]
pub fn reach(home: &Path, path_var: &str) -> Option<Vec<(String, Reach)>> {
    if !path_var
        .split(':')
        .any(|e| !e.is_empty() && is_shim_dir(home, Path::new(e)))
    {
        return None;
    }
    let d = dir(home);
    let mut names: Vec<String> = std::fs::read_dir(&d)
        .map(|rd| {
            rd.flatten()
                .filter(|e| is_ours(&e.path()))
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .collect()
        })
        .unwrap_or_default();
    names.sort();
    Some(
        names
            .into_iter()
            .map(|n| {
                let r = match first_on_path(path_var, &n) {
                    Some(p) if p.parent().is_some_and(|dir| is_shim_dir(home, dir)) => Reach::First,
                    Some(p) => Reach::Shadowed(p),
                    None => Reach::First,
                };
                (n, r)
            })
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn exe(dir: &Path, name: &str, body: &str) -> PathBuf {
        std::fs::create_dir_all(dir).unwrap();
        let p = dir.join(name);
        std::fs::write(&p, body).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        p
    }

    fn join(dirs: &[&Path]) -> String {
        dirs.iter()
            .map(|d| d.to_string_lossy().into_owned())
            .collect::<Vec<_>>()
            .join(":")
    }

    #[test]
    fn real_binary_skips_the_shim_dir() {
        let home = tempfile::tempdir().unwrap();
        let shims = dir(home.path());
        let bin = home.path().join("bin");
        exe(&shims, "copilot", &script(Agent::Copilot));
        let real = exe(&bin, "copilot", "#!/bin/sh\n");
        let path = join(&[&shims, &bin]);
        assert_eq!(real_binary_in(&path, home.path(), "copilot"), Some(real));
        // Only the shim on PATH: nothing real to find.
        assert_eq!(
            real_binary_in(&join(&[&shims]), home.path(), "copilot"),
            None
        );
    }

    #[test]
    fn real_binary_skips_a_symlink_into_the_shim_dir() {
        let home = tempfile::tempdir().unwrap();
        let shims = dir(home.path());
        let shim = exe(&shims, "copilot", &script(Agent::Copilot));
        let other = home.path().join("other");
        std::fs::create_dir_all(&other).unwrap();
        std::os::unix::fs::symlink(&shim, other.join("copilot")).unwrap();
        let bin = home.path().join("bin");
        let real = exe(&bin, "copilot", "#!/bin/sh\n");
        assert_eq!(
            real_binary_in(&join(&[&other, &bin]), home.path(), "copilot"),
            Some(real)
        );
    }

    #[test]
    fn sync_does_nothing_until_opted_in() {
        let home = tempfile::tempdir().unwrap();
        let bin = home.path().join("bin");
        exe(&bin, "copilot", "#!/bin/sh\n");
        let changes = sync_in(home.path(), &join(&[&bin]), &[]);
        assert!(changes.done.is_empty() && changes.refused.is_empty());
        assert!(!dir(home.path()).exists(), "sync must never create the dir");
    }

    #[test]
    fn sync_writes_removes_and_is_idempotent() {
        let home = tempfile::tempdir().unwrap();
        let shims = dir(home.path());
        std::fs::create_dir_all(&shims).unwrap();
        let bin = home.path().join("bin");
        exe(&bin, "copilot", "#!/bin/sh\n");
        exe(&bin, "agy", "#!/bin/sh\n");
        let path = join(&[&shims, &bin]);
        let first = sync_in(home.path(), &path, &[]).done;
        assert_eq!(first.len(), 3, "copilot + antigravity + agy: {first:?}");
        assert_eq!(
            std::fs::read_to_string(shims.join("agy")).unwrap(),
            script(Agent::Antigravity)
        );
        let mode = std::fs::metadata(shims.join("copilot"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o755);
        assert!(sync_in(home.path(), &path, &[]).done.is_empty());
        // Skipped: its shims go.
        let skip = vec!["antigravity".to_string()];
        let removed = sync_in(home.path(), &path, &skip).done;
        assert_eq!(removed.len(), 2, "{removed:?}");
        assert!(!shims.join("agy").exists());
        // A file we did not write is never touched.
        exe(&shims, "claude", "#!/bin/sh\necho mine\n");
        assert!(sync_in(home.path(), &path, &skip).done.is_empty());
        assert!(shims.join("claude").exists());
        // Not even when claude turns up: the sync refuses rather than clobbers.
        exe(&bin, "claude", "#!/bin/sh\n");
        let clash = sync_in(home.path(), &path, &skip);
        assert_eq!(clash.refused.len(), 1, "{:?}", clash.refused);
        assert!(clash.done.is_empty());
        assert_eq!(
            std::fs::read_to_string(shims.join("claude")).unwrap(),
            "#!/bin/sh\necho mine\n"
        );
    }

    #[test]
    fn version_probe_tells_the_goose_binaries_apart() {
        assert!(version_matches(Agent::Goose, "goose 1.15.0\n"));
        assert!(version_matches(Agent::Goose, " 1.15.0\n"));
        assert!(!version_matches(Agent::Goose, "goose version: v3.26.0\n"));
        assert!(version_matches(Agent::Pi, "0.87.1\n"));
        assert!(!version_matches(Agent::Pi, "pi 3.14\n"));
    }

    #[test]
    fn script_pins_the_agent_passes_args_and_guards() {
        let s = script(Agent::Antigravity);
        assert!(s.starts_with("#!/bin/sh\n# cplt-shim: antigravity\n"));
        assert!(s.ends_with("exec cplt --agent antigravity -- \"$@\"\n"));
        assert!(s.contains("__CPLT_WRAPPED"));
        assert!(s.contains("exit 127"));
    }

    #[test]
    fn path_without_shims_drops_only_the_shim_dir() {
        let home = Path::new("/h");
        assert_eq!(
            path_without_shims(home, "/h/.local/share/cplt/bin:/usr/bin"),
            Some("/usr/bin".to_string())
        );
        assert_eq!(path_without_shims(home, "/usr/bin:/bin"), None);
    }

    #[test]
    fn block_round_trips_and_refuses_foreign_lines() {
        let original = "export FOO=1\n";
        let body = vec![POSIX_PATH_LINE.to_string()];
        let with = upsert_block(original, &body).unwrap().unwrap();
        assert!(with.starts_with(original));
        assert!(with.contains(POSIX_PATH_LINE));
        assert_eq!(upsert_block(&with, &body).unwrap(), None, "idempotent");
        assert_eq!(remove_block(&with).unwrap().as_deref(), Some(original));
        assert_eq!(remove_block(original).unwrap(), None);

        let foreign = with.replace(POSIX_PATH_LINE, "rm -rf ~");
        assert!(upsert_block(&foreign, &body).is_err());
        assert!(remove_block(&foreign).is_err());
        let unbalanced = format!("{original}{BLOCK_BEGIN}\n");
        assert!(upsert_block(&unbalanced, &body).is_err());
    }

    #[test]
    fn block_accumulates_agents() {
        let a = upsert_block("", &[eval_line(Agent::Copilot)])
            .unwrap()
            .unwrap();
        let b = upsert_block(&a, &[eval_line(Agent::Claude)])
            .unwrap()
            .unwrap();
        assert!(b.contains(&eval_line(Agent::Copilot)) && b.contains(&eval_line(Agent::Claude)));
        assert_eq!(b.matches(BLOCK_BEGIN).count(), 1);
    }

    #[test]
    fn reach_reports_first_shadowed_and_absent() {
        let home = tempfile::tempdir().unwrap();
        let shims = dir(home.path());
        exe(&shims, "copilot", &script(Agent::Copilot));
        exe(&shims, "claude", &script(Agent::Claude));
        let bin = home.path().join("bin");
        let early = exe(&bin, "claude", "#!/bin/sh\n");
        let path = join(&[&bin, &shims]);
        let r = reach(home.path(), &path).unwrap();
        assert_eq!(
            r,
            vec![
                ("claude".to_string(), Reach::Shadowed(early)),
                ("copilot".to_string(), Reach::First)
            ]
        );
        assert_eq!(reach(home.path(), &join(&[&bin])), None);
    }
}
