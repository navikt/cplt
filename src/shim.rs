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
///
/// Guarded by `__CPLT_WRAPPED`: `.zshenv` also runs for every `zsh -c` the
/// sandboxed agent spawns, and putting the shim directory back first there
/// would make any tool call that runs an agent by name hit the shim's loop
/// guard (exit 126). An `if`, not `&&`, so a sandboxed shell does not start
/// with `$?` set to 1.
pub const POSIX_PATH_LINE: &str =
    "if [ -z \"${__CPLT_WRAPPED:-}\" ]; then export PATH=\"$HOME/.local/share/cplt/bin:$PATH\"; fi";

/// The fish equivalent, guarded the same way (`conf.d` runs for `fish -c`
/// too). `--global --path` changes `$PATH` for this shell only; the default
/// (universal `fish_user_paths`) would persist past an uninstall.
pub const FISH_PATH_LINE: &str = "if not set -q __CPLT_WRAPPED; fish_add_path --global --path --move $HOME/.local/share/cplt/bin; end";

/// The `.zshrc`/`.bashrc` block line: one `eval` for every shimmed agent's
/// alias, guarded so neither a sandboxed shell nor a machine without cplt runs
/// it.
pub const EVAL_LINE: &str = "if [ -z \"${__CPLT_WRAPPED:-}\" ] && command -v cplt >/dev/null 2>&1; then eval \"$(cplt --shell-setup --shims)\"; fi";

/// What install records in the shim directory (#514 review): the rc files it
/// created, the backups it took, the directories it made, the #513 lines it
/// moved into a block, and binaries whose version probe said "not this
/// agent". Uninstall undoes exactly what is listed. Hidden and without the
/// shim marker, so nothing treats it as a shim.
const MANIFEST: &str = ".manifest";

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

/// Only `goose` and `pi` share their names with unrelated tools.
fn needs_probe(agent: Agent) -> bool {
    matches!(agent, Agent::Goose | Agent::Pi)
}

/// The manifest line that says `bin` failed its version probe: its canonical
/// path, size and mtime, so a replaced binary is probed again.
fn rejected_entry(bin: &Path) -> Option<String> {
    let canon = std::fs::canonicalize(bin).ok()?;
    let meta = std::fs::metadata(&canon).ok()?;
    let mtime = meta
        .modified()
        .ok()?
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_nanos();
    Some(format!(
        "rejected\t{}\t{}:{mtime}",
        canon.display(),
        meta.len()
    ))
}

/// Run `bin --version`, unsandboxed, so only from an explicit command, and
/// remember a "not this agent" answer so the same binary is not run again.
fn confirmed(home: &Path, agent: Agent, bin: &Path) -> bool {
    let rejected = rejected_entry(bin);
    if rejected
        .as_ref()
        .is_some_and(|r| read_manifest(home).contains(r))
    {
        return false;
    }
    let ok = crate::discover::probe_output(bin, &["--version"])
        .is_some_and(|out| version_matches(agent, &out));
    if !ok && let Some(r) = rejected {
        let _ = append_manifest(home, &r);
    }
    ok
}

/// Whether `skip` (the `shell.skip` list) names `agent`, by its `--agent`
/// name or any of its command names.
fn skipped(agent: Agent, skip: &[String]) -> bool {
    skip.iter()
        .any(|s| s == agent.binary_name() || agent.binary_names().contains(&s.as_str()))
}

/// Who is syncing, which sets what the sync may do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncMode {
    /// A launch or `--shell-setup`: add only, and never run a binary. These run
    /// with whatever PATH the caller had (an IDE, cron, `env -i`, a mise
    /// project), so an agent missing from it is no evidence it was
    /// uninstalled, and removing its shim would let the agent run
    /// unsandboxed. A probe here would run an unvetted binary on the host at
    /// every shell start.
    Background,
    /// `cplt doctor`: may probe `goose` and `pi`, still never removes.
    Doctor,
    /// `--shell-install --shims`: probes, and removes the shims of agents not
    /// on PATH. The user ran it from the shell whose PATH they mean.
    Install,
}

/// Bring the shim directory in line with the agents on `path_var`.
///
/// A PATH walk plus a directory diff: it writes nothing when nothing changed
/// and never touches the network. A `shell.skip` entry removes that agent's
/// shims in every mode; the rest is up to `mode`. One `done` line per change,
/// one `refused` line per file it could not bring in line; a failure on one
/// agent does not stop the others. Does nothing, and creates nothing, unless
/// the shim directory already exists.
#[must_use]
pub fn sync_in(home: &Path, path_var: &str, skip: &[String], mode: SyncMode) -> Report {
    let mut report = Report::default();
    let d = dir(home);
    if !d.is_dir() {
        return report;
    }
    for agent in shimmable() {
        let names = agent.binary_names();
        let want = script(agent);
        let is_current = |n: &str| std::fs::read_to_string(d.join(n)).is_ok_and(|c| c == want);
        // A shim of ours already there was vetted when it was first written.
        let vetted = names.iter().any(|n| is_ours(&d.join(n)));
        let is_skipped = skipped(agent, skip);
        let installed = !is_skipped
            && names
                .iter()
                .find_map(|n| real_binary_in(path_var, home, n))
                .is_some_and(|bin| {
                    vetted
                        || !needs_probe(agent)
                        || (mode != SyncMode::Background && confirmed(home, agent, &bin))
                });
        let may_remove = is_skipped || mode == SyncMode::Install;
        for name in names {
            let shim = d.join(name);
            let result = if installed && !is_current(name) {
                write_shim(&shim, &want).map(|()| format!("wrote {}", shim.display()))
            } else if !installed && may_remove && is_ours(&shim) {
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
pub fn sync(home: &Path, skip: &[String], mode: SyncMode) -> Report {
    sync_in(home, &std::env::var("PATH").unwrap_or_default(), skip, mode)
}

/// What `--shell-setup --shims` prints: the aliases of every agent that has a
/// shim. In an interactive shell they survive an rc line that reorders PATH
/// after `.zshenv`.
#[must_use]
pub fn shimmed_aliases(home: &Path) -> Vec<String> {
    let d = dir(home);
    shimmable()
        .filter(|a| a.binary_names().iter().any(|n| is_ours(&d.join(n))))
        .flat_map(|a| alias_lines(a, false))
        .collect()
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

/// Replace an rc file's contents: a temporary file beside the file's real
/// location, renamed over it. A symlinked dotfile stays a symlink and its
/// target gets the new contents; the target's permissions carry over.
fn write_atomic(path: &Path, contents: &str) -> std::io::Result<()> {
    let target = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    if let Some(parent) = target.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let name = target.file_name().unwrap_or_default().to_string_lossy();
    let tmp = target.with_file_name(format!(".{name}.cplt-tmp"));
    let perms = std::fs::metadata(&target).ok().map(|m| m.permissions());
    let result = std::fs::write(&tmp, contents)
        .and_then(|()| perms.map_or(Ok(()), |p| std::fs::set_permissions(&tmp, p)))
        .and_then(|()| std::fs::rename(&tmp, &target));
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result
}

// ── Manifest ─────────────────────────────────────────────────────

fn manifest_path(home: &Path) -> PathBuf {
    dir(home).join(MANIFEST)
}

/// The manifest's lines, each `<kind>\t<path>[\t<detail>]`; empty when absent.
fn read_manifest(home: &Path) -> Vec<String> {
    std::fs::read_to_string(manifest_path(home))
        .map(|c| c.lines().map(str::to_string).collect())
        .unwrap_or_default()
}

fn append_manifest(home: &Path, line: &str) -> std::io::Result<()> {
    use std::io::Write;
    if read_manifest(home).iter().any(|l| l == line) {
        return Ok(());
    }
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(manifest_path(home))?;
    writeln!(f, "{line}")
}

fn entry(kind: &str, path: &Path) -> String {
    format!("{kind}\t{}", path.display())
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

/// The fish block's alias lines for `agent`, guarded like [`FISH_PATH_LINE`]:
/// `conf.d` runs for `fish -c` inside the sandbox too, where the alias would
/// only start a nested cplt.
#[must_use]
pub fn fish_block_aliases(agent: Agent) -> Vec<String> {
    alias_lines(agent, true)
        .into_iter()
        .map(|l| format!("if not set -q __CPLT_WRAPPED; {l}; end"))
        .collect()
}

/// A line this version writes inside a block.
fn current_line(line: &str) -> bool {
    line == POSIX_PATH_LINE
        || line == FISH_PATH_LINE
        || line == EVAL_LINE
        || shimmable().any(|a| fish_block_aliases(a).iter().any(|l| l == line))
}

/// A line an earlier version wrote inside a block. Still cplt's, so uninstall
/// removes it; the next install replaces it with the current form. When a
/// block line changes, its old form goes here.
fn historical_line(line: &str) -> bool {
    line == "export PATH=\"$HOME/.local/share/cplt/bin:$PATH\""
        || line == "fish_add_path --global --path --move $HOME/.local/share/cplt/bin"
        || shimmable().any(|a| {
            line == format!(
                "command -v cplt >/dev/null 2>&1 && eval \"$(cplt --shell-setup --agent {})\"",
                a.binary_name()
            ) || alias_lines(a, true).iter().any(|l| l == line)
        })
}

/// Every line cplt may have written inside a block. A line outside this set
/// is someone else's, and the block is then left alone.
fn known_line(line: &str) -> bool {
    current_line(line) || historical_line(line)
}

/// A line #513's plain `--shell-install` wrote outside any block, and the
/// agent it aliases. The block's own line covers it once shims are installed,
/// so an install moves it into the block rather than leave both to run.
fn legacy_alias_line(line: &str) -> Option<Agent> {
    if line == "eval \"$(cplt --shell-setup)\"" || line == "alias copilot cplt" {
        return Some(Agent::Copilot);
    }
    shimmable().find(|a| {
        line == format!("eval \"$(cplt --shell-setup --agent {})\"", a.binary_name())
            || alias_lines(*a, true).iter().any(|l| l == line)
    })
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

/// `contents` with the block holding `body` plus the current cplt lines it
/// already held, or `None` when nothing changes. Lines an earlier version
/// wrote are dropped: `body` carries their replacement.
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
                .filter(|l| current_line(l))
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

/// `contents` with the block replaced by `replacement` (usually empty), or
/// `None` when it has none.
///
/// # Errors
/// As [`upsert_block`].
pub fn replace_block(contents: &str, replacement: &str) -> Result<Option<String>, String> {
    let lines: Vec<&str> = contents.split_inclusive('\n').collect();
    let Some((b, e)) = find_block(&lines)? else {
        return Ok(None);
    };
    check_foreign(&lines[b + 1..e])?;
    Ok(Some(format!(
        "{}{replacement}{}",
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
    /// Whether #513's alias lines in this file move into the block.
    pub migrate: bool,
}

/// The rc files an install writes, per the PRD's placement table.
///
/// `.zshenv`, `.zprofile` and `.profile` are created when missing; they carry
/// only the static PATH line, as do `.bash_profile` and `.bash_login` when
/// they exist (a login bash reads the first of those two and `.profile`, so
/// `.profile` alone would miss it). `.zshrc` is written when it exists or zsh
/// is the login shell, `.bashrc` only when it exists (creating bash files
/// changes whether `.profile` is read, which is Volta's rule too), and fish's
/// `conf.d/cplt.fish` when fish is the shell or is configured.
#[must_use]
pub fn rc_files(home: &Path, shell: &str, agent: Agent) -> Vec<RcFile> {
    let path_rc = |name: &str| RcFile {
        path: home.join(name),
        body: vec![POSIX_PATH_LINE.to_string()],
        migrate: false,
    };
    let mut files = vec![
        path_rc(".zshenv"),
        path_rc(".zprofile"),
        path_rc(".profile"),
    ];
    for name in [".bash_profile", ".bash_login"] {
        if home.join(name).exists() {
            files.push(path_rc(name));
        }
    }
    let alias_rc = |path: PathBuf| RcFile {
        path,
        body: vec![EVAL_LINE.to_string()],
        migrate: true,
    };
    let zshrc = home.join(".zshrc");
    if zshrc.exists() || shell.ends_with("/zsh") {
        files.push(alias_rc(zshrc));
    }
    let bashrc = home.join(".bashrc");
    if bashrc.exists() {
        files.push(alias_rc(bashrc));
    }
    let fish_dir = home.join(".config/fish");
    if fish_dir.is_dir() || shell.ends_with("/fish") {
        let mut body = vec![FISH_PATH_LINE.to_string()];
        body.extend(fish_block_aliases(agent));
        files.push(RcFile {
            path: fish_dir.join("conf.d/cplt.fish"),
            body,
            migrate: true,
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
        ".bash_profile",
        ".bash_login",
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
/// An existing rc file gets a copy at `<file>.cplt-backup` before cplt's first
/// edit, replacing any stale copy. Everything created, backed up or migrated
/// is listed in the manifest for the uninstall. Idempotent: a second run
/// changes nothing.
#[must_use]
pub fn install(home: &Path, path_var: &str, shell: &str, agent: Agent, skip: &[String]) -> Report {
    let mut report = Report::default();
    let d = dir(home);
    if !d.is_dir() {
        let made: Vec<PathBuf> = d
            .ancestors()
            .skip(1)
            .take_while(|p| !p.exists())
            .map(Path::to_path_buf)
            .collect();
        if let Err(e) = std::fs::create_dir_all(&d) {
            report
                .refused
                .push(format!("cannot create {}: {e}", d.display()));
            return report;
        }
        report.done.push(format!("created {}", d.display()));
        for p in made {
            if let Err(e) = append_manifest(home, &entry("dir", &p)) {
                report
                    .refused
                    .push(format!("cannot record {}: {e}", p.display()));
            }
        }
    }
    let synced = sync_in(home, path_var, skip, SyncMode::Install);
    report.done.extend(synced.done);
    report.refused.extend(synced.refused);
    for rc in rc_files(home, shell, agent) {
        match write_rc(home, &rc) {
            Ok(Some(line)) => report.done.push(line),
            Ok(None) => {}
            Err(e) => report.refused.push(e),
        }
    }
    report
}

fn write_rc(home: &Path, rc: &RcFile) -> Result<Option<String>, String> {
    let shown = rc.path.display();
    let record = |line: String| {
        append_manifest(home, &line).map_err(|e| format!("{shown}: cannot record in manifest: {e}"))
    };
    let existing = match std::fs::read_to_string(&rc.path) {
        Ok(c) => Some(c),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => return Err(format!("{shown}: cannot read: {e}")),
    };
    let current = existing.clone().unwrap_or_default();

    // #513's lines outside the block: take them out, and let the block cover
    // their agents.
    let mut body = rc.body.clone();
    let mut migrated = Vec::new();
    let mut kept = String::new();
    let mut inside = false;
    for l in current.split_inclusive('\n') {
        let t = l.trim_end();
        inside |= t == BLOCK_BEGIN;
        let legacy = (rc.migrate && !inside)
            .then(|| legacy_alias_line(t.trim()))
            .flatten();
        inside &= t != BLOCK_END;
        match legacy {
            Some(agent) => {
                migrated.push(t.to_string());
                if t.trim().starts_with("alias ") {
                    body.extend(fish_block_aliases(agent));
                }
            }
            None => kept.push_str(l),
        }
    }

    let upserted = upsert_block(&kept, &body).map_err(|e| format!("{shown}: {e}"))?;
    let Some(updated) = upserted.or_else(|| (kept != current).then(|| kept.clone())) else {
        return Ok(None);
    };
    let backup = backup_path(&rc.path);
    // Before cplt's first edit: a file with a block was backed up then or
    // created by the install. A backup left from an earlier install is stale
    // by now, so it is replaced rather than reused.
    let first_edit = !current.lines().any(|l| l.trim_end() == BLOCK_BEGIN);
    let backed_up = existing.is_some() && first_edit;
    if backed_up {
        std::fs::copy(&rc.path, &backup)
            .map_err(|e| format!("{shown}: cannot back up to {}: {e}", backup.display()))?;
        record(entry("backup", &rc.path))?;
    }
    if existing.is_none() {
        record(entry("created", &rc.path))?;
    }
    write_atomic(&rc.path, &updated).map_err(|e| format!("{shown}: cannot write: {e}"))?;
    for line in &migrated {
        record(format!("legacy\t{}\t{line}", rc.path.display()))?;
    }
    Ok(Some(match (existing.is_some(), backed_up) {
        (false, _) => format!("created {shown}"),
        (true, true) => format!("updated {shown} (backup: {})", backup.display()),
        (true, false) => format!("updated {shown}"),
    }))
}

/// Opt out: remove every block, put back the #513 lines the install moved
/// into one, remove the backups and files the install made, then the shims,
/// the manifest and the directories the install created. Leaves anything
/// cplt did not write, and says so.
///
/// Without a manifest (an install from before it existed), a file with no
/// backup counts as created, and no directory above the shim directory is
/// removed.
#[must_use]
pub fn uninstall(home: &Path) -> Report {
    let mut report = Report::default();
    let manifest = read_manifest(home);
    let has_manifest = manifest_path(home).exists();
    let listed = |kind: &str, p: &Path| manifest.contains(&entry(kind, p));
    for path in all_rc_paths(home) {
        let shown = path.display();
        let Ok(contents) = std::fs::read_to_string(&path) else {
            continue;
        };
        let prefix = format!("{}\t", entry("legacy", &path));
        let restore: String = manifest
            .iter()
            .filter_map(|l| l.strip_prefix(&prefix))
            .map(|l| format!("{l}\n"))
            .collect();
        let stripped = match replace_block(&contents, &restore) {
            Ok(Some(s)) => s,
            Ok(None) => continue,
            Err(e) => {
                report.refused.push(format!("{shown}: {e}"));
                continue;
            }
        };
        let backup = backup_path(&path);
        let (created, backup_ours) = if has_manifest {
            (listed("created", &path), listed("backup", &path))
        } else {
            (!backup.exists(), backup.exists())
        };
        // Once the block is gone and nothing else was added, a file the
        // install created goes too.
        let result = if created && stripped.trim().is_empty() {
            std::fs::remove_file(&path).map(|()| format!("removed {shown}"))
        } else {
            write_atomic(&path, &stripped).map(|()| format!("removed the cplt block from {shown}"))
        };
        match result {
            Ok(line) => report.done.push(line),
            Err(e) => {
                report.refused.push(format!("{shown}: {e}"));
                continue;
            }
        }
        if backup_ours && backup.exists() {
            match std::fs::remove_file(&backup) {
                Ok(()) => report.done.push(format!("removed {}", backup.display())),
                Err(e) => report.refused.push(format!("{}: {e}", backup.display())),
            }
        }
    }
    let d = dir(home);
    let Ok(entries) = std::fs::read_dir(&d) else {
        return report;
    };
    for entry in entries.flatten() {
        let p = entry.path();
        if is_ours(&p) {
            match std::fs::remove_file(&p) {
                Ok(()) => report.done.push(format!("removed {}", p.display())),
                Err(e) => report.refused.push(format!("{}: {e}", p.display())),
            }
        }
    }
    // The manifest goes last, and only with the directory, so an uninstall
    // that stops here can be run again.
    let foreign = std::fs::read_dir(&d)
        .map(|rd| rd.flatten().any(|e| e.file_name() != MANIFEST))
        .unwrap_or(true);
    if foreign {
        report.refused.push(format!(
            "{}: it holds files cplt did not write; move them out, then run this again",
            d.display()
        ));
        return report;
    }
    let removed = std::fs::remove_file(manifest_path(home))
        .or_else(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                Ok(())
            } else {
                Err(e)
            }
        })
        .and_then(|()| std::fs::remove_dir(&d));
    if let Err(e) = removed {
        report.refused.push(format!("{}: {e}", d.display()));
        return report;
    }
    report.done.push(format!("removed {}", d.display()));
    // Only the directories the install made, deepest first. `remove_dir`
    // refuses a non-empty one, so anything else in them keeps them.
    for parent in manifest.iter().filter_map(|l| l.strip_prefix("dir\t")) {
        if std::fs::remove_dir(parent).is_err() {
            break;
        }
        report.done.push(format!("removed {parent}"));
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
        for mode in [SyncMode::Background, SyncMode::Doctor, SyncMode::Install] {
            let changes = sync_in(home.path(), &join(&[&bin]), &[], mode);
            assert!(changes.done.is_empty() && changes.refused.is_empty());
        }
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
        let first = sync_in(home.path(), &path, &[], SyncMode::Background).done;
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
        assert!(
            sync_in(home.path(), &path, &[], SyncMode::Background)
                .done
                .is_empty()
        );
        // Skipped: its shims go, whoever syncs.
        let skip = vec!["antigravity".to_string()];
        let removed = sync_in(home.path(), &path, &skip, SyncMode::Background).done;
        assert_eq!(removed.len(), 2, "{removed:?}");
        assert!(!shims.join("agy").exists());
        // A file we did not write is never touched.
        exe(&shims, "claude", "#!/bin/sh\necho mine\n");
        assert!(
            sync_in(home.path(), &path, &skip, SyncMode::Install)
                .done
                .is_empty()
        );
        assert!(shims.join("claude").exists());
        // Not even when claude turns up: the sync refuses rather than clobbers.
        exe(&bin, "claude", "#!/bin/sh\n");
        let clash = sync_in(home.path(), &path, &skip, SyncMode::Background);
        assert_eq!(clash.refused.len(), 1, "{:?}", clash.refused);
        assert!(clash.done.is_empty());
        assert_eq!(
            std::fs::read_to_string(shims.join("claude")).unwrap(),
            "#!/bin/sh\necho mine\n"
        );
    }

    /// #514 review: a launch or shell start with a thin PATH (an IDE, cron,
    /// `env -i`) must not take shims away, or the agent runs unsandboxed from
    /// every other shell. Only the explicit install removes.
    #[test]
    fn only_the_install_removes_a_shim_for_a_missing_agent() {
        let home = tempfile::tempdir().unwrap();
        let shims = dir(home.path());
        exe(&shims, "copilot", &script(Agent::Copilot));
        for path in ["", "/nonexistent"] {
            for mode in [SyncMode::Background, SyncMode::Doctor] {
                let r = sync_in(home.path(), path, &[], mode);
                assert!(r.done.is_empty() && r.refused.is_empty(), "{mode:?}: {r:?}");
                assert!(shims.join("copilot").exists(), "{mode:?} removed a shim");
            }
        }
        let r = sync_in(home.path(), "", &[], SyncMode::Install);
        assert_eq!(r.done.len(), 1, "{r:?}");
        assert!(!shims.join("copilot").exists());
    }

    /// #514 review: `goose --version` runs unsandboxed, so a launch or shell
    /// start must never run it: a `goose` an agent planted in a writable PATH
    /// directory would run on the host. `cplt doctor` and the install may, and
    /// a rejected binary is remembered rather than run again.
    #[test]
    fn only_explicit_commands_probe_and_a_rejection_is_cached() {
        let home = tempfile::tempdir().unwrap();
        let shims = dir(home.path());
        std::fs::create_dir_all(&shims).unwrap();
        let ran = home.path().join("probe-ran");
        let bin = home.path().join("bin");
        exe(
            &bin,
            "goose",
            &format!(
                "#!/bin/sh\necho x >> '{}'\necho 'goose version: v3.26.0'\n",
                ran.display()
            ),
        );
        let path = join(&[&bin]);
        let r = sync_in(home.path(), &path, &[], SyncMode::Background);
        assert!(r.done.is_empty(), "{r:?}");
        assert!(!ran.exists(), "a background sync ran the probe");

        let r = sync_in(home.path(), &path, &[], SyncMode::Doctor);
        assert!(r.done.is_empty(), "pressly/goose is not shimmed: {r:?}");
        assert_eq!(std::fs::read_to_string(&ran).unwrap().lines().count(), 1);
        let _ = sync_in(home.path(), &path, &[], SyncMode::Install);
        assert_eq!(
            std::fs::read_to_string(&ran).unwrap().lines().count(),
            1,
            "a rejected binary is not probed again"
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
        assert_eq!(replace_block(&with, "").unwrap().as_deref(), Some(original));
        assert_eq!(replace_block(original, "").unwrap(), None);

        let foreign = with.replace(POSIX_PATH_LINE, "rm -rf ~");
        assert!(upsert_block(&foreign, &body).is_err());
        assert!(replace_block(&foreign, "").is_err());
        let unbalanced = format!("{original}{BLOCK_BEGIN}\n");
        assert!(upsert_block(&unbalanced, &body).is_err());
    }

    /// #514 review: a block an earlier version wrote is still cplt's. The
    /// uninstall removes it, and the install swaps the old line for the new.
    #[test]
    fn historical_block_lines_are_recognized_and_replaced() {
        let old = format!(
            "x\n{BLOCK_BEGIN}\nexport PATH=\"$HOME/.local/share/cplt/bin:$PATH\"\n\
             command -v cplt >/dev/null 2>&1 && eval \"$(cplt --shell-setup --agent claude)\"\n{BLOCK_END}\n"
        );
        assert_eq!(replace_block(&old, "").unwrap().as_deref(), Some("x\n"));
        let new = upsert_block(&old, &[POSIX_PATH_LINE.to_string()])
            .unwrap()
            .unwrap();
        assert_eq!(
            new,
            format!("x\n{}", render_block(&[POSIX_PATH_LINE.to_string()]))
        );
    }

    #[test]
    fn block_accumulates_agents() {
        let a = upsert_block("", &fish_block_aliases(Agent::Copilot))
            .unwrap()
            .unwrap();
        let b = upsert_block(&a, &fish_block_aliases(Agent::Claude))
            .unwrap()
            .unwrap();
        for agent in [Agent::Copilot, Agent::Claude] {
            assert!(b.contains(&fish_block_aliases(agent)[0]), "{b}");
        }
        assert_eq!(b.matches(BLOCK_BEGIN).count(), 1);
    }

    /// #513's unguarded eval moves into the block, so it does not run next to
    /// the block's own; uninstall puts it back.
    #[test]
    fn install_migrates_the_513_eval_and_uninstall_restores_it() {
        let home = tempfile::tempdir().unwrap();
        let zshrc = home.path().join(".zshrc");
        let before = "export A=1\neval \"$(cplt --shell-setup --agent claude)\"\n";
        std::fs::write(&zshrc, before).unwrap();
        let r = install(home.path(), "", "/bin/zsh", Agent::Copilot, &[]);
        assert!(r.refused.is_empty(), "{r:?}");
        let after = std::fs::read_to_string(&zshrc).unwrap();
        assert_eq!(
            after,
            format!("export A=1\n{}", render_block(&[EVAL_LINE.to_string()]))
        );
        let r = uninstall(home.path());
        assert!(r.refused.is_empty(), "{r:?}");
        assert_eq!(std::fs::read_to_string(&zshrc).unwrap(), before);
    }

    /// A stale backup from an earlier install is replaced at the next first
    /// edit, and uninstall removes only what its manifest lists, leaving a
    /// `~/.local/share` that was already there.
    #[test]
    fn install_refreshes_stale_backups_and_uninstall_follows_the_manifest() {
        let home = tempfile::tempdir().unwrap();
        let share = home.path().join(".local/share");
        std::fs::create_dir_all(&share).unwrap();
        let profile = home.path().join(".profile");
        let bash_profile = home.path().join(".bash_profile");
        std::fs::write(&profile, "new\n").unwrap();
        std::fs::write(&bash_profile, "bp\n").unwrap();
        std::fs::write(backup_path(&profile), "stale\n").unwrap();
        let r = install(home.path(), "", "/bin/bash", Agent::Copilot, &[]);
        assert!(r.refused.is_empty(), "{r:?}");
        assert_eq!(
            std::fs::read_to_string(backup_path(&profile)).unwrap(),
            "new\n"
        );
        assert!(
            std::fs::read_to_string(&bash_profile)
                .unwrap()
                .contains(POSIX_PATH_LINE),
            "a login bash reads .bash_profile, not .profile"
        );
        let r = uninstall(home.path());
        assert!(r.refused.is_empty(), "{r:?}");
        assert_eq!(std::fs::read_to_string(&profile).unwrap(), "new\n");
        assert_eq!(std::fs::read_to_string(&bash_profile).unwrap(), "bp\n");
        assert!(!backup_path(&profile).exists());
        assert!(!home.path().join(".zshenv").exists());
        assert!(!home.path().join(".local/share/cplt").exists());
        assert!(share.is_dir(), "a directory the install did not make stays");
    }

    /// A symlinked dotfile stays a symlink; its target gets the block.
    #[test]
    fn rc_rewrite_keeps_a_symlinked_dotfile() {
        let home = tempfile::tempdir().unwrap();
        let real = home.path().join("dotfiles/zshenv");
        std::fs::create_dir_all(real.parent().unwrap()).unwrap();
        std::fs::write(&real, "a\n").unwrap();
        let link = home.path().join(".zshenv");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let r = install(home.path(), "", "/bin/sh", Agent::Copilot, &[]);
        assert!(r.refused.is_empty(), "{r:?}");
        assert!(link.symlink_metadata().unwrap().file_type().is_symlink());
        assert!(
            std::fs::read_to_string(&real)
                .unwrap()
                .contains(POSIX_PATH_LINE)
        );
        let _ = uninstall(home.path());
        assert!(link.symlink_metadata().unwrap().file_type().is_symlink());
        assert_eq!(std::fs::read_to_string(&real).unwrap(), "a\n");
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
