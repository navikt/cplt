//! `cplt doctor`: findings, not inventory.
//!
//! The question doctor answers is "will cplt work on this host for this
//! agent, and if the agent just failed, which enforcement decision caused
//! it?" — offline, without building a sandbox, so it still answers when a
//! launch cannot. The output is written to be pasted into a public issue:
//! paths are `~/…`, token *names* only, and the software inventory stays
//! behind `--verbose`.
//!
//! The rules here are pure functions over what the launch already resolved
//! (`Resolved`, the generated `LandlockPolicy`, the agent), so they cannot
//! answer from fewer inputs than the launch uses (#447). `main.rs` gathers
//! those inputs and prints; this module decides.

use crate::agent::{Agent, PACKAGE_REGISTRY_DOMAINS};
use crate::proxy::NetPolicy;
use crate::sandbox::LandlockPolicy;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    /// The agent will not start, or cplt will not launch.
    Blocking,
    /// Something will fail mid-session, or a protection is silently off.
    Warning,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub level: Level,
    pub message: String,
    pub fix: Option<String>,
}

impl Finding {
    #[must_use]
    pub fn blocking(message: impl Into<String>, fix: impl Into<String>) -> Self {
        Self {
            level: Level::Blocking,
            message: message.into(),
            fix: Some(fix.into()),
        }
    }

    #[must_use]
    pub fn warning(message: impl Into<String>, fix: Option<String>) -> Self {
        Self {
            level: Level::Warning,
            message: message.into(),
            fix,
        }
    }
}

/// `~/…` for anything under `home`, so a pasted report does not carry the
/// username. A Windows profile reached through WSL,
/// `/mnt/<drive>/Users/<name>/…`, carries the Windows username instead, and
/// is shown as `/mnt/<drive>/Users/~/…`.
#[must_use]
pub fn tilde(path: &Path, home: &Path) -> String {
    match path.strip_prefix(home) {
        Ok(rest) if rest.as_os_str().is_empty() => "~".to_string(),
        Ok(rest) => format!("~/{}", rest.display()),
        Err(_) => hide_windows_user(path).display().to_string(),
    }
}

/// `/mnt/<drive>/Users/<name>/…` → `/mnt/<drive>/Users/~/…`; anything else
/// unchanged. Not gated on WSL: the name is private either way.
fn hide_windows_user(path: &Path) -> PathBuf {
    let parts: Vec<_> = path.components().collect();
    let is_profile = crate::agent::is_windows_interop_path(path)
        && parts.len() > 4
        && parts[3].as_os_str().eq_ignore_ascii_case("users");
    if !is_profile {
        return path.to_path_buf();
    }
    let mut out: PathBuf = parts[..4].iter().collect();
    out.push("~");
    out.extend(&parts[5..]);
    out
}

/// The same, for free-form text that may quote a path.
///
/// `tilde` needs a `Path`; an error string built elsewhere — `cplt refuses to
/// sandbox '/Users/hans'`, a WSL tool at `/mnt/c/Users/<name>/…` — carries the
/// username in the middle of a sentence. The default view is meant to be
/// pasted into a public issue, so the substitution has to reach those too.
#[must_use]
pub fn tilde_in_text(text: &str, home: &Path) -> String {
    let home = home.to_string_lossy();
    let home = home.trim_end_matches('/');
    let text = if home.is_empty() {
        text.to_string()
    } else {
        replace_home(text, home)
    };
    hide_windows_user_in_text(&text)
}

/// Replaces `home` only where it stands as a whole path: not inside
/// `/newroot/home/u` and not as the prefix of `/home/anna`.
fn replace_home(text: &str, home: &str) -> String {
    let word = |c: char| c.is_alphanumeric() || matches!(c, '_' | '-');
    let mut out = String::with_capacity(text.len());
    let mut last = 0;
    for (i, _) in text.match_indices(home) {
        if i < last {
            continue;
        }
        let before = text[..i].chars().next_back();
        let mut after = text[i + home.len()..].chars();
        let starts = before.is_none_or(|c| !(word(c) || matches!(c, '/' | '.' | '~')));
        // A `.` ends a sentence unless a name continues after it.
        let ends = match after.next() {
            None | Some('/') => true,
            Some('.') => after.next().is_none_or(|c| !word(c)),
            Some(c) => !word(c),
        };
        if starts && ends {
            out.push_str(&text[last..i]);
            out.push('~');
            last = i + home.len();
        }
    }
    out.push_str(&text[last..]);
    out
}

/// `hide_windows_user` for a path quoted inside a sentence: the component
/// after `/mnt/<drive>/Users/` becomes `~`. The name ends where prose would
/// end a path (see `profile_name_len`), so the rest of the sentence survives.
fn hide_windows_user_in_text(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(i) = rest.find("/mnt/") {
        let (head, tail) = rest.split_at(i + "/mnt/".len());
        out.push_str(head);
        let b = tail.as_bytes();
        let profile = b.len() > 8
            && b[0].is_ascii_alphabetic()
            && b[1] == b'/'
            && tail
                .get(2..8)
                .is_some_and(|u| u.eq_ignore_ascii_case("users/"));
        let name_len = if profile {
            profile_name_len(&tail[8..])
        } else {
            0
        };
        if name_len == 0 {
            rest = tail;
            continue;
        }
        out.push_str(&tail[..8]);
        out.push('~');
        rest = &tail[8 + name_len..];
    }
    out.push_str(rest);
    out
}

/// Length of the profile name at the start of `s`. It stops at whitespace or
/// punctuation that ends a path in prose. A name with spaces (`Kari
/// Nordmann`) is taken whole only when its words run straight on to a `/` or
/// a closing quote; otherwise `kari and /mnt/…` would swallow the sentence.
fn profile_name_len(s: &str) -> usize {
    let word = |s: &str| {
        s.find(|c: char| {
            c.is_whitespace()
                || matches!(
                    c,
                    '/' | ':' | ',' | ')' | ']' | ';' | '\'' | '"' | '`' | '\x1b'
                )
        })
        .unwrap_or(s.len())
    };
    let first = word(s);
    let mut end = first;
    while let Some(rest) = s[end..].strip_prefix(' ') {
        match word(rest) {
            0 => break,
            w => end += 1 + w,
        }
    }
    if matches!(s[end..].chars().next(), Some('/' | '\'' | '"' | '`')) {
        end
    } else {
        first
    }
}

// ── Rule: tracked secrets vs. the .env deny ────────────────────

/// A tracked secret under the `.env` deny breaks every git command that hashes
/// the index (`add`, `diff`, `stash`, `commit -a`) with `cannot hash`. The
/// file list comes from `cplt check`'s `tracked_sensitive_files` (#451).
///
/// `extension_only` says a file is on the list only because of
/// `sandbox.deny_key_files_by_extension` (`server.pem`, not `.pem`), so
/// turning that key off is a narrower fix than `allow_env_files`.
#[must_use]
pub fn tracked_env_finding(
    files: &[String],
    allow_env_files: bool,
    extension_only: bool,
) -> Option<Finding> {
    if allow_env_files || files.is_empty() {
        return None;
    }
    let list = files.join(", ");
    let first = &files[0];
    Some(Finding::warning(
        format!(
            "{list} {} tracked in git and allow_env_files is off: git add/diff/stash/commit -a \
             will fail with `cannot hash`.",
            if files.len() == 1 { "is" } else { "are" }
        ),
        Some(format!(
            // `--` and quoting: a tracked path can contain spaces, and one
            // beginning with a dash would be read as a flag. The fix line is
            // meant to be pasted.
            "git rm --cached -- '{first}' && echo '{first}' >> .gitignore  \
             (or sandbox.allow_env_files = true{})",
            if extension_only {
                ", or for the key files matched by extension only, \
                 sandbox.deny_key_files_by_extension = false"
            } else {
                ""
            }
        )),
    ))
}

// ── Rule: Pi's trust lock vs. the read-only agent root ─────────

/// Whether the resolved policy grants `dir` itself read-only.
/// Read-only *and* unable to create entries.
///
/// `!write` alone is not the question any more. A create-only grant is
/// `write: false` with named entries it may `mkdir`, which is exactly what
/// lets Pi take its lock — so keying on `write` would report "Pi will not
/// start" on a host where it now starts fine. Adding a dimension to the access
/// model makes every existing `!write` check potentially incomplete; this is
/// one of them.
fn dir_is_read_only(policy: &LandlockPolicy, dir: &Path) -> bool {
    policy
        .fs_rules
        .iter()
        .find(|r| r.path == dir)
        .is_some_and(|r| !r.access.write && !r.access.create_dirs)
}

/// Pi creates a lock *directory* in `~/.pi/agent` to read `trust.json`
/// (`withTrustFileLock` in `dist/core/trust-manager.js`, present in the
/// released 0.85.1), and that root is granted read-only in every regime —
/// Landlock rule and, when bubblewrap is active, the mount too. So no Pi
/// version and no bubblewrap state changes the answer (#449).
#[must_use]
pub fn pi_lock_finding(agent: Agent, policy: &LandlockPolicy, home: &Path) -> Option<Finding> {
    if agent != Agent::Pi || !dir_is_read_only(policy, &home.join(".pi/agent")) {
        return None;
    }
    Some(Finding::blocking(
        "Pi will not start: ~/.pi/agent is read-only in this run, and Pi takes a write lock \
         there (trust.json.lock) before a session exists.",
        "run pi outside cplt for now; a cplt fix that grants the lock is in progress (#449)",
    ))
}

// ── Rule: shims resolving outside a granted root ───────────────

/// A `(name, path-as-found-on-PATH)` pair; the path must be the PATH entry,
/// not its canonical target, or there is no shim left to inspect.
pub type ToolOnPath<'a> = (&'a str, &'a Path);

/// One warning per tool whose symlink target the policy does not grant
/// execute on. Same predicate the launch warns with (#390).
#[must_use]
pub fn shim_findings(
    policy: &LandlockPolicy,
    tools: &[ToolOnPath<'_>],
    home: &Path,
) -> Vec<Finding> {
    tools
        .iter()
        .filter_map(|(name, path)| {
            let target = crate::check::shim_target_without_exec(policy, path)?;
            let dir = target.parent().unwrap_or(&target).to_path_buf();
            Some(Finding::warning(
                format!(
                    "{name} is a shim resolving to {}, which this run does not grant execute on: \
                     running it fails with exit 126 and no message.",
                    tilde(&target, home)
                ),
                Some(format!(
                    "--allow-exec {} (or [sandbox] allow.exec)",
                    tilde(&dir, home)
                )),
            ))
        })
        .collect()
}

// ── Bubblewrap: three states, not a PATH lookup ────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Bubblewrap {
    /// Present and able to create the namespaces the launch needs.
    Usable(PathBuf),
    /// On disk, but the probe the launch runs fails (no user namespaces, a
    /// hardened kernel, some WSL configs). Auto-detect falls back silently.
    Unusable { path: PathBuf, reason: String },
    /// Not in any trusted directory.
    NotInstalled,
    /// `use_bubblewrap = false` / `--no-bubblewrap`.
    Disabled,
    /// Not a Linux host.
    NotApplicable,
}

impl Bubblewrap {
    #[must_use]
    pub fn active(&self) -> bool {
        matches!(self, Self::Usable(_))
    }

    /// The `bubblewrap:` fragment of the enforcement line.
    #[must_use]
    pub fn describe(&self) -> String {
        match self {
            Self::Usable(_) => "bubblewrap: active".to_string(),
            Self::Unusable { reason, .. } => format!("bubblewrap: installed, {reason}"),
            Self::NotInstalled => "bubblewrap: not installed".to_string(),
            Self::Disabled => "bubblewrap: disabled by config".to_string(),
            Self::NotApplicable => String::new(),
        }
    }
}

/// What the launch's own `bubblewrap::resolve` would conclude for `config`:
/// the same trusted-directory lookup, and the same wrapper — the launch's
/// rules, overlays and deny masks — probed with `bwrap … /bin/true`. A probe
/// with an empty rule set can pass where the launch's fails and falls back to
/// Landlock only, and every finding keyed on `active()` would then be wrong.
///
/// `scratch` is `Resolved::scratch_dir`. When it is on and `config` has no
/// scratch dir (doctor's does not), the probe makes a session scratch dir of
/// its own the way the launch does, so the scratch bind and the file deny
/// masks, whose placeholder lives there, are probed. It and any ancestor it
/// had to create are removed before this returns.
///
/// Still not probed: the pnpm shadow dir (the launch copies pnpm into a fresh
/// directory under `~/.cplt-pnpm-shadow` and grants it read+execute; doctor
/// will not copy files for a diagnosis), and, if the scratch dir cannot be
/// created here, the scratch bind and file masks.
#[cfg(target_os = "linux")]
#[must_use]
pub fn bubblewrap_state(
    use_bubblewrap: Option<bool>,
    scratch: bool,
    config: &crate::sandbox::SandboxConfig,
) -> Bubblewrap {
    use crate::sandbox::bubblewrap_probe;
    if use_bubblewrap == Some(false) {
        return Bubblewrap::Disabled;
    }
    let Some(path) = bubblewrap_probe::check_availability() else {
        return Bubblewrap::NotInstalled;
    };
    let probe_scratch =
        (scratch && config.scratch_dir.is_none()).then(|| ProbeScratch::create(config.home_dir));
    let probed = crate::sandbox::SandboxConfig {
        scratch_dir: config
            .scratch_dir
            .or_else(|| probe_scratch.as_ref().and_then(ProbeScratch::path)),
        ..config.clone()
    };
    match bubblewrap_probe::test_launch(&probed) {
        Ok(()) => Bubblewrap::Usable(path),
        Err(reason) => Bubblewrap::Unusable {
            path,
            reason: probe_reason(&reason, config.home_dir),
        },
    }
}

/// A session scratch dir for one probe. Dropping it removes the dir and then
/// every ancestor `ScratchDir::create` had to make, so doctor leaves nothing
/// behind on a host that never launched.
#[cfg(target_os = "linux")]
struct ProbeScratch {
    dir: Option<crate::scratch::ScratchDir>,
    /// Deepest first, the order they must be removed in.
    created: Vec<PathBuf>,
}

#[cfg(target_os = "linux")]
impl ProbeScratch {
    fn create(home_dir: &Path) -> Self {
        let base = crate::scratch::ScratchDir::base(home_dir);
        let created = base
            .ancestors()
            .take_while(|p| p.symlink_metadata().is_err())
            .map(Path::to_path_buf)
            .collect();
        Self {
            dir: crate::scratch::ScratchDir::create(home_dir).ok(),
            created,
        }
    }

    fn path(&self) -> Option<&Path> {
        self.dir.as_ref().map(crate::scratch::ScratchDir::path)
    }
}

#[cfg(target_os = "linux")]
impl Drop for ProbeScratch {
    fn drop(&mut self) {
        drop(self.dir.take());
        for dir in &self.created {
            let _ = std::fs::remove_dir(dir);
        }
    }
}

#[cfg(not(target_os = "linux"))]
#[must_use]
pub fn bubblewrap_state(
    _use_bubblewrap: Option<bool>,
    _scratch: bool,
    _config: &crate::sandbox::SandboxConfig,
) -> Bubblewrap {
    Bubblewrap::NotApplicable
}

/// The first line of a probe error, without the `bwrap test failed: ` that
/// `test_functionality` puts in front of bwrap's own `bwrap: …`. bwrap names
/// the mount it failed on, often under home, so the username is hidden here:
/// the reason is printed on the enforcement line as well as in a finding.
#[cfg(any(target_os = "linux", test))]
fn probe_reason(raw: &str, home: &Path) -> String {
    let line = raw
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty())
        .unwrap_or("probe failed");
    tilde_in_text(
        line.strip_prefix("bwrap test failed: ").unwrap_or(line),
        home,
    )
}

/// Auto-detect (`use_bubblewrap` unset) found no usable bubblewrap, so the
/// launch runs Landlock + seccomp only and says so in one line nobody reads.
/// `use_bubblewrap = true` has its own blocking finding; `false` was a choice.
#[must_use]
pub fn bubblewrap_finding(state: &Bubblewrap, use_bubblewrap: Option<bool>) -> Option<Finding> {
    if use_bubblewrap.is_some() {
        return None;
    }
    match state {
        Bubblewrap::NotInstalled => Some(Finding::warning(
            "bubblewrap is not installed: the launch runs Landlock + seccomp only, without the \
             mount-level protections listed above.",
            Some(
                "sudo apt install bubblewrap (or your distro's package; it must land in a trusted \
                 system directory such as /usr/bin or /usr/local/bin)"
                    .to_string(),
            ),
        )),
        Bubblewrap::Unusable { reason, .. } => {
            let lower = reason.to_ascii_lowercase();
            // bwrap says "No permissions to create new namespace" or fails
            // "setting up uid map" when unprivileged user namespaces are off.
            let userns = lower.contains("namespace") || lower.contains("uid map");
            Some(Finding::warning(
                format!(
                    "bubblewrap is installed but its probe fails ({reason}): the launch falls \
                     back to Landlock + seccomp only."
                ),
                userns.then(|| {
                    "enable user namespaces (sysctl kernel.unprivileged_userns_clone=1; on \
                     Ubuntu 23.10+ kernel.apparmor_restrict_unprivileged_userns blocks them)"
                        .to_string()
                }),
            ))
        }
        _ => None,
    }
}

// ── Rule: a project on a Windows drive under WSL ───────────────

/// A project under `/mnt/<drive>/` is served over 9p (or virtiofs), where
/// nobody has verified Landlock's behaviour and every file access crosses the
/// VM boundary. Same path test as the Windows-interop agent check, gated on
/// the same WSL signal: on plain Linux `/mnt/c` is an ordinary mount.
#[must_use]
pub fn wsl_drive_project_finding(project_dir: &Path, wsl: bool) -> Option<Finding> {
    // The joined component makes the bare drive root, `/mnt/c` itself, count.
    if !crate::agent::is_wsl_interop_binary(&project_dir.join("x"), wsl) {
        return None;
    }
    // Only the drive: the rest is usually /mnt/c/Users/<name>/….
    let drive = project_dir
        .components()
        .nth(2)?
        .as_os_str()
        .to_string_lossy();
    Some(Finding::warning(
        format!(
            "The project is on the Windows drive /mnt/{drive}: Landlock enforcement on that \
             mount is unverified, and every file access crosses the VM boundary (9p or \
             virtiofs), which is slow."
        ),
        Some("move the project into the distro (e.g. ~/src) and run cplt there".to_string()),
    ))
}

// ── Rule: the network policy blocks the agent's own hosts ──────

/// The agent's own infrastructure hosts and, under an active allowlist, the
/// package registries, run through the proxy's gate the way `cplt check net`
/// does (`explain_domain`, port 443, no network). One warning naming what is
/// blocked, so a policy too strict for the agent cannot pass doctor (#604).
///
/// Registries count only under an allowlist: without one, a registry is
/// blocked only by a blocklist the user wrote on purpose.
#[must_use]
pub fn agent_hosts_finding(agent: Agent, policy: &NetPolicy) -> Option<Finding> {
    let hosts = agent.default_allowed_domains();
    let blocked: Vec<(&str, crate::check::NetExplain)> = hosts
        .iter()
        .filter(|h| policy.allowlist_active || !PACKAGE_REGISTRY_DOMAINS.contains(h))
        .map(|h| {
            (
                *h,
                crate::check::explain_domain(policy, h, 443, true, false),
            )
        })
        .filter(|(_, e)| e.decision != crate::check::Decision::Allowed)
        .collect();
    if blocked.is_empty() {
        return None;
    }
    // One fix per distinct cause, so a mix (an agent host on the blocklist, a
    // registry off the allowlist) names every remedy it needs. Every active
    // allowlist carries the agent's own hosts (#605), so BLOCKED-ALLOWLIST is
    // only ever a registry, which one key merges; an agent host is blocked by
    // a blocklist, and its explain fix points there.
    let mut fixes: Vec<String> = Vec::new();
    for (_, e) in &blocked {
        let fix = if e.status == "BLOCKED-ALLOWLIST" {
            Some(
                "set proxy.default_allowlist = true (or pass --default-allowlist) to merge the \
                 package registries into your allowed_domains, or add them to that file"
                    .to_string(),
            )
        } else {
            e.fix.clone()
        };
        if let Some(fix) = fix.filter(|f| !fixes.contains(f)) {
            fixes.push(fix);
        }
    }
    let mut named: Vec<String> = blocked
        .iter()
        .take(3)
        .map(|(h, e)| format!("{h} ({})", e.status))
        .collect();
    if blocked.len() > 3 {
        named.push(format!("{} more", blocked.len() - 3));
    }
    Some(Finding::warning(
        format!(
            "The network policy blocks host(s) {} needs: {}. The agent cannot reach \
             them.",
            agent.display_name(),
            named.join(", ")
        ),
        (!fixes.is_empty()).then(|| fixes.join("; ")),
    ))
}

// ── Rule: a /dev grant without bubblewrap ──────────────────────

/// A grant on `/dev` (or `/`, or `/dev/pts` itself) covers every numbered
/// terminal of the user's other windows, which the default policy withholds
/// (GHSA-q3p2-6x2x-8w8w). Under bubblewrap `--dev /dev` gives the session its
/// own devpts and the grant only reaches that; without it, the host's.
///
/// Honest about what is left: on Linux seccomp still denies `TIOCSTI` /
/// `TIOCLINUX`, so it is reading input and forging output, not injection.
#[must_use]
pub fn pts_grant_finding(
    policy: &LandlockPolicy,
    bubblewrap_active: bool,
    linux: bool,
) -> Option<Finding> {
    if bubblewrap_active {
        return None;
    }
    let pts = Path::new("/dev/pts");
    // The widest covering grant: `--allow-read / --allow-write /dev` must be
    // reported as the write it is, not the read rule that comes first.
    // A grant below it, `/dev/pts/3`, reaches that one terminal only; a
    // covering grant outranks it.
    let matching = || {
        policy
            .fs_rules
            .iter()
            .filter(|r| r.access.read || r.access.write)
            .filter(|r| pts.starts_with(&r.path) || r.path.starts_with(pts))
    };
    let rule =
        matching().max_by_key(|r| (pts.starts_with(&r.path), r.access.write, r.access.execute))?;
    // Never under-warn: a covering read grant must not hide a write grant on
    // one terminal below it.
    let other_write = matching()
        .find(|r| r.access.write && !rule.access.write)
        .map(|w| format!(", and write into {} (allow.write)", w.path.display()))
        .unwrap_or_default();
    let covers = pts.starts_with(&rule.path);
    let them = if covers { "them" } else { "it" };
    // The rule carries access, not the config key it came from; an
    // `allow.exec` grant is read + execute.
    let (kind, reach) = if rule.access.write {
        (
            "allow.write",
            format!("read what you type in {them} and write into {them}"),
        )
    } else if rule.access.execute {
        (
            "allow.exec",
            format!("read what you type in {them}{other_write}"),
        )
    } else {
        (
            "allow.read",
            format!("read what you type in {them}{other_write}"),
        )
    };
    let (devices, fix) = if linux {
        (
            "/dev/pts/N",
            "let bubblewrap wrap the launch (sudo apt install bubblewrap; its private /dev/pts \
             holds only the session's own terminals), or drop the grant and run PTY-hungry \
             commands outside cplt",
        )
    } else {
        (
            "/dev/ttysNNN",
            "drop the grant and run PTY-hungry commands outside cplt; if you need it, pass \
             --allow-write /dev for a single run rather than keeping it in config",
        )
    };
    let seccomp = if linux {
        " seccomp still blocks TIOCSTI keystroke injection."
    } else {
        ""
    };
    let target = if covers {
        format!("every {devices}, the terminals of your other windows")
    } else {
        "a terminal that may belong to another window".to_string()
    };
    Some(Finding::warning(
        format!(
            "{kind} {} reaches {target}: the agent can {reach}.{seccomp}",
            rule.path.display()
        ),
        Some(fix.to_string()),
    ))
}

// ── Rendering ──────────────────────────────────────────────────

/// The findings block plus the summary line. `ok` is the one-line "what is
/// fine" roll-up; `header` is printed by the caller, which owns the inputs.
///
/// The whole block goes through `tilde_in_text` on the way out: a finding's
/// text is often an error built elsewhere that quotes a path, and this block
/// is what gets pasted into a public issue.
#[must_use]
pub fn render(findings: &[Finding], ok: &[String], verbose_hint: bool, home: &Path) -> String {
    use crate::ui::{GREEN, RED, RESET, YELLOW, stdout_color};
    use std::fmt::Write as _;
    let mut out = String::new();
    let blocking = findings
        .iter()
        .filter(|f| f.level == Level::Blocking)
        .count();
    let warnings = findings.len() - blocking;

    for f in findings {
        let (sym, color) = match f.level {
            Level::Blocking => ("✗", RED),
            Level::Warning => ("⚠", YELLOW),
        };
        let _ = writeln!(
            out,
            "{}{sym}{} {}",
            stdout_color(color),
            stdout_color(RESET),
            f.message
        );
        if let Some(fix) = &f.fix {
            let _ = writeln!(out, "  fix: {fix}");
        }
    }
    if !ok.is_empty() {
        let joined = ok
            .iter()
            .map(|s| format!("{}✓{} {s}", stdout_color(GREEN), stdout_color(RESET)))
            .collect::<Vec<_>>()
            .join(" · ");
        let _ = writeln!(out, "{joined}");
    }
    let _ = writeln!(out);
    let verdict = if blocking > 0 {
        format!(
            "{}{blocking} blocking, {warnings} warning{}.{}",
            stdout_color(RED),
            if warnings == 1 { "" } else { "s" },
            stdout_color(RESET)
        )
    } else if warnings > 0 {
        format!(
            "{}0 blocking, {warnings} warning{}.{}",
            stdout_color(YELLOW),
            if warnings == 1 { "" } else { "s" },
            stdout_color(RESET)
        )
    } else {
        format!(
            "{}No problems found.{}",
            stdout_color(GREEN),
            stdout_color(RESET)
        )
    };
    let hint = if verbose_hint {
        " `cplt doctor --verbose` for the inventory, `cplt check` to probe enforcement."
    } else {
        " `cplt check` to probe enforcement."
    };
    let _ = writeln!(out, "{verdict}{hint}");
    tilde_in_text(&out, home)
}

/// Exit non-zero iff something is blocking — the contract the old doctor had
/// for its "critical" checks.
#[must_use]
pub fn exit_nonzero(findings: &[Finding]) -> bool {
    findings.iter().any(|f| f.level == Level::Blocking)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sandbox::{FsAccess, FsRule};

    fn policy(rules: Vec<(&str, bool, bool)>) -> LandlockPolicy {
        LandlockPolicy {
            fs_rules: rules
                .into_iter()
                .map(|(p, write, execute)| FsRule {
                    nofollow: false,
                    path: PathBuf::from(p),
                    access: FsAccess {
                        read: true,
                        write,
                        execute,
                        ioctl: false,
                        create_dirs: false,
                    },
                })
                .collect(),
            net_rules: vec![],
            restrict_net_connect: false,
            proxy_forced: false,
            home_dir: PathBuf::from("/home/u"),
            precreate_dirs: vec![],
            plain_file: None,
        }
    }

    #[test]
    fn tilde_hides_the_username() {
        let home = Path::new("/Users/hans");
        assert_eq!(
            tilde(Path::new("/Users/hans/.pi/agent"), home),
            "~/.pi/agent"
        );
        assert_eq!(tilde(home, home), "~");
        assert_eq!(tilde(Path::new("/usr/bin/git"), home), "/usr/bin/git");
    }

    /// Under WSL a Windows-side tool carries the Windows username.
    #[test]
    fn tilde_hides_the_windows_username() {
        let home = Path::new("/home/u");
        assert_eq!(
            tilde(
                Path::new("/mnt/c/Users/Kari Nordmann/AppData/Roaming/npm/npm"),
                home
            ),
            "/mnt/c/Users/~/AppData/Roaming/npm/npm"
        );
        assert_eq!(
            tilde(Path::new("/mnt/d/users/kari"), home),
            "/mnt/d/users/~"
        );
        // Nothing to hide, or not a drive.
        assert_eq!(tilde(Path::new("/mnt/c/Users"), home), "/mnt/c/Users");
        assert_eq!(tilde(Path::new("/mnt/c/apps/x"), home), "/mnt/c/apps/x");
        assert_eq!(
            tilde(Path::new("/mnt/data/Users/kari"), home),
            "/mnt/data/Users/kari"
        );
    }

    /// Error text from elsewhere quotes paths mid-sentence.
    #[test]
    fn tilde_in_text_hides_both_usernames() {
        let home = Path::new("/home/u");
        assert_eq!(
            tilde_in_text(
                "copilot resolves to a Windows install:\n  /mnt/c/Users/Kari Nordmann/AppData/npm/copilot\n",
                home
            ),
            "copilot resolves to a Windows install:\n  /mnt/c/Users/~/AppData/npm/copilot\n"
        );
        assert_eq!(
            tilde_in_text("can't bind '/mnt/d/users/kari' and /home/u/x", home),
            "can't bind '/mnt/d/users/~' and ~/x"
        );
        for same in [
            "/mnt/c/Users/",
            "/mnt/data/Users/kari",
            "/mnt/c/apps/x",
            "/mnt/",
        ] {
            assert_eq!(tilde_in_text(same, home), same);
        }
    }

    /// The profile name ends where prose ends a path.
    #[test]
    fn tilde_in_text_keeps_the_sentence_after_a_windows_name() {
        let home = Path::new("/home/u");
        for (text, want) in [
            (
                "/mnt/c/Users/kari: permission denied (os error 13)",
                "/mnt/c/Users/~: permission denied (os error 13)",
            ),
            (
                "/mnt/c/Users/kari and /mnt/c/Users/ola ok",
                "/mnt/c/Users/~ and /mnt/c/Users/~ ok",
            ),
            (
                "in /mnt/c/Users/kari, then more",
                "in /mnt/c/Users/~, then more",
            ),
            ("(/mnt/c/Users/kari)", "(/mnt/c/Users/~)"),
            ("[/mnt/c/Users/kari]", "[/mnt/c/Users/~]"),
            ("/mnt/c/Users/kari; x", "/mnt/c/Users/~; x"),
            (
                "\x1b[1m/mnt/c/Users/kari\x1b[0m",
                "\x1b[1m/mnt/c/Users/~\x1b[0m",
            ),
            ("'/mnt/c/Users/Kari Nordmann' x", "'/mnt/c/Users/~' x"),
        ] {
            assert_eq!(tilde_in_text(text, home), want, "{text:?}");
        }
    }

    /// `$HOME` is replaced only as a whole path.
    #[test]
    fn tilde_in_text_matches_home_at_a_boundary() {
        let slash = Path::new("/home/ann/");
        assert_eq!(
            tilde_in_text("refuses to sandbox '/home/ann'", slash),
            "refuses to sandbox '~'"
        );
        assert_eq!(
            tilde_in_text("HOME=/home/ann is /home/ann.", slash),
            "HOME=~ is ~."
        );
        let home = Path::new("/home/ann");
        assert_eq!(tilde_in_text("/home/anna/x", home), "/home/anna/x");
        assert_eq!(tilde_in_text("/home/ann.bak/x", home), "/home/ann.bak/x");
        assert_eq!(
            tilde_in_text("/newroot/home/ann/.cache", home),
            "/newroot/home/ann/.cache"
        );
        assert_eq!(tilde_in_text("'/home/ann/x'", home), "'~/x'");
        assert_eq!(tilde_in_text("/home/ann", Path::new("/")), "/home/ann");
    }

    #[test]
    fn probe_reason_drops_the_wrapper_prefix() {
        let home = Path::new("/home/u");
        assert_eq!(
            probe_reason("bwrap test failed: bwrap: Can't mount proc\nmore", home),
            "bwrap: Can't mount proc"
        );
        assert_eq!(probe_reason("\n  other  \n", home), "other");
        assert_eq!(probe_reason("", home), "probe failed");
        // bwrap names the mount it failed on; the reason is printed as is.
        assert_eq!(
            probe_reason(
                "bwrap test failed: bwrap: Can't bind mount /home/u/.cache on /newroot/home/u/.cache",
                home
            ),
            "bwrap: Can't bind mount ~/.cache on /newroot/home/u/.cache"
        );
        assert_eq!(
            probe_reason("bwrap: Can't find source path /mnt/c/Users/kari/x", home),
            "bwrap: Can't find source path /mnt/c/Users/~/x"
        );
    }

    #[test]
    fn tracked_env_finding_needs_a_tracked_file_and_the_deny() {
        let files = vec!["config/.env.local".to_string()];
        assert!(
            tracked_env_finding(&files, true, false).is_none(),
            "deny off: nothing to say"
        );
        assert!(
            tracked_env_finding(&[], false, false).is_none(),
            "nothing tracked: nothing to say"
        );
        let f = tracked_env_finding(&files, false, false).expect("finding");
        assert_eq!(f.level, Level::Warning);
        assert!(f.message.contains("cannot hash"));
        let fix = f.fix.as_deref().unwrap();
        assert!(fix.contains("git rm --cached -- 'config/.env.local'"));
        assert!(
            !fix.contains("deny_key_files_by_extension"),
            "an exact-name match has nothing to do with the extension key: {fix}"
        );
        let f = tracked_env_finding(&["certs/server.pem".to_string()], false, true).unwrap();
        let fix = f.fix.as_deref().unwrap();
        assert!(
            fix.contains("sandbox.allow_env_files = true")
                && fix.contains("sandbox.deny_key_files_by_extension = false"),
            "an extension-only match names the narrower key too: {fix}"
        );
    }

    #[test]
    fn pi_lock_rule_fires_for_any_pi_on_a_read_only_root() {
        let home = Path::new("/home/u");
        let ro_root = policy(vec![("/home/u/.pi/agent", false, false)]);
        assert!(pi_lock_finding(Agent::Copilot, &ro_root, home).is_none());
        let blocking = pi_lock_finding(Agent::Pi, &ro_root, home).unwrap();
        assert_eq!(blocking.level, Level::Blocking);
        assert!(blocking.message.contains("trust.json.lock"));
        assert!(!blocking.fix.as_deref().unwrap().contains("0.85.1"));
        // A policy that grants the root writable has nothing to warn about.
        let rw_root = policy(vec![("/home/u/.pi/agent", true, false)]);
        assert!(pi_lock_finding(Agent::Pi, &rw_root, home).is_none());
    }

    #[test]
    fn shim_findings_use_the_launch_predicate() {
        // A real symlink whose target is outside every exec grant.
        let tmp =
            tempfile::env::temp_dir().join(format!("cplt-doctor-shim-{}", std::process::id()));
        let granted = tmp.join("granted");
        let outside = tmp.join("outside");
        std::fs::create_dir_all(&granted).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        let target = outside.join("real");
        std::fs::write(&target, "").unwrap();
        // The shim is named by its canonical directory, as a PATH entry the
        // launch canonicalized would be; the predicate compares paths textually.
        let granted_c = std::fs::canonicalize(&granted).unwrap();
        let shim = granted_c.join("node");
        std::os::unix::fs::symlink(&target, &shim).unwrap();
        let p = policy(vec![(granted_c.to_str().unwrap(), false, true)]);

        let found = shim_findings(&p, &[("node", shim.as_path())], &tmp);
        assert_eq!(found.len(), 1);
        assert!(found[0].message.starts_with("node is a shim"));
        assert!(found[0].fix.as_deref().unwrap().contains("--allow-exec"));

        // The target granted too: not a shim problem.
        let outside_c = std::fs::canonicalize(&outside).unwrap();
        let p2 = policy(vec![
            (granted_c.to_str().unwrap(), false, true),
            (outside_c.to_str().unwrap(), false, true),
        ]);
        assert!(shim_findings(&p2, &[("node", shim.as_path())], &tmp).is_empty());
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn bubblewrap_finding_only_on_auto_detect_without_a_usable_bwrap() {
        let missing = Bubblewrap::NotInstalled;
        let f = bubblewrap_finding(&missing, None).expect("not installed warns");
        assert_eq!(f.level, Level::Warning);
        let fix = f.fix.unwrap();
        assert!(fix.contains("apt install bubblewrap"));
        assert!(fix.contains("/usr/local/bin"), "not only /usr/bin: {fix}");
        // `true` has its own blocking finding; `false` was a choice.
        assert!(bubblewrap_finding(&missing, Some(true)).is_none());
        assert!(bubblewrap_finding(&missing, Some(false)).is_none());
        assert!(bubblewrap_finding(&Bubblewrap::Usable("/usr/bin/bwrap".into()), None).is_none());
        assert!(bubblewrap_finding(&Bubblewrap::NotApplicable, None).is_none());

        let userns = Bubblewrap::Unusable {
            path: "/usr/bin/bwrap".into(),
            reason: "bwrap: setting up uid map: Permission denied".into(),
        };
        let f = bubblewrap_finding(&userns, None).expect("unusable warns");
        assert!(f.message.contains("uid map"));
        assert!(f.fix.unwrap().contains("unprivileged_userns_clone"));
        let other = Bubblewrap::Unusable {
            path: "/usr/bin/bwrap".into(),
            reason: "bwrap: Can't mount proc".into(),
        };
        assert!(bubblewrap_finding(&other, None).unwrap().fix.is_none());
    }

    #[test]
    fn wsl_drive_project_names_the_drive_but_not_the_user() {
        let p = Path::new("/mnt/c/Users/hans/src/app");
        let f = wsl_drive_project_finding(p, true).expect("finding");
        assert!(f.message.contains("/mnt/c:"));
        assert!(f.message.contains("9p or virtiofs"), "{}", f.message);
        assert!(!f.message.contains("hans"));
        assert!(f.fix.unwrap().contains("~/src"));
        // Not WSL: /mnt/c is an ordinary mount.
        assert!(wsl_drive_project_finding(p, false).is_none());
        // WSL's own mounts and the Linux filesystem are fine.
        assert!(wsl_drive_project_finding(Path::new("/mnt/wsl/x"), true).is_none());
        assert!(wsl_drive_project_finding(Path::new("/home/u/src/app"), true).is_none());
        // The bare drive root is on the drive too.
        for root in ["/mnt/c", "/mnt/c/"] {
            let f = wsl_drive_project_finding(Path::new(root), true).expect(root);
            assert!(f.message.contains("/mnt/c:"), "{root}: {}", f.message);
        }
        assert!(wsl_drive_project_finding(Path::new("/mnt"), true).is_none());
    }

    /// `--allow-read / --allow-write /dev`: the read rule comes first, the
    /// write is what reaches the terminals.
    #[test]
    fn pts_grant_finding_reports_the_widest_covering_grant() {
        let both = policy(vec![("/", false, false), ("/dev", true, false)]);
        let f = pts_grant_finding(&both, false, true).expect("finding");
        assert!(f.message.starts_with("allow.write /dev "), "{}", f.message);
        let exec = policy(vec![("/", false, false), ("/dev", false, true)]);
        let f = pts_grant_finding(&exec, false, true).expect("finding");
        assert!(f.message.starts_with("allow.exec /dev "), "{}", f.message);
    }

    #[test]
    fn pts_grant_finding_fires_on_a_covering_grant_without_bubblewrap() {
        let dev_rw = policy(vec![("/dev/null", true, false), ("/dev", true, false)]);
        let f = pts_grant_finding(&dev_rw, false, true).expect("finding");
        assert!(
            f.message
                .starts_with("allow.write /dev reaches every /dev/pts/N")
        );
        assert!(f.message.contains("TIOCSTI"), "honest about seccomp");
        assert!(f.fix.unwrap().contains("bubblewrap"));
        // bubblewrap gives the session its own devpts.
        assert!(pts_grant_finding(&dev_rw, true, true).is_none());
        // macOS: no seccomp claim, no bubblewrap fix.
        let mac = pts_grant_finding(&dev_rw, false, false).unwrap();
        assert!(mac.message.contains("/dev/ttysNNN"));
        assert!(!mac.message.contains("TIOCSTI"));
        assert!(!mac.fix.unwrap().contains("bubblewrap"));
        // Read-only covering grant still leaks input, but not output.
        let pts_ro = policy(vec![("/dev/pts", false, false)]);
        let f = pts_grant_finding(&pts_ro, false, true).unwrap();
        assert!(f.message.starts_with("allow.read /dev/pts reaches every"));
        assert!(!f.message.contains("write into"));
        // One terminal below it reaches that terminal, not every one; a
        // covering grant elsewhere in the policy still wins.
        let one = policy(vec![("/dev/pts/3", true, false)]);
        let f = pts_grant_finding(&one, false, true).unwrap();
        assert!(
            f.message
                .starts_with("allow.write /dev/pts/3 reaches a terminal that"),
            "{}",
            f.message
        );
        assert!(f.message.contains("write into it."), "{}", f.message);
        let both = policy(vec![("/dev/pts/3", true, false), ("/dev", false, false)]);
        let f = pts_grant_finding(&both, false, true).unwrap();
        assert!(
            f.message.starts_with("allow.read /dev reaches every"),
            "{}",
            f.message
        );
        // ... but the write on the one terminal is still reported.
        assert!(
            f.message
                .contains(", and write into /dev/pts/3 (allow.write)."),
            "{}",
            f.message
        );
        // The default device grants do not cover /dev/pts.
        let defaults = policy(vec![
            ("/dev/null", true, false),
            ("/dev/tty", true, false),
            ("/dev/ptmx", true, false),
            ("/dev/shm", true, false),
        ]);
        assert!(pts_grant_finding(&defaults, false, true).is_none());
    }

    #[test]
    fn render_puts_the_verdict_last_and_counts_levels() {
        let findings = vec![
            Finding::blocking("Pi will not start", "run outside"),
            Finding::warning("x is tracked", None),
        ];
        let out = render(
            &findings,
            &["auth: gh CLI".to_string()],
            true,
            Path::new("/home/u"),
        );
        let lines: Vec<&str> = out.lines().collect();
        assert!(lines[0].contains("Pi will not start"));
        assert_eq!(lines[1].trim(), "fix: run outside");
        assert!(lines[2].contains("x is tracked"));
        assert!(lines[3].contains("auth: gh CLI"));
        assert!(lines.last().unwrap().starts_with("1 blocking, 1 warning."));
        assert!(lines.last().unwrap().contains("--verbose"));
        assert!(exit_nonzero(&findings));
        assert!(!exit_nonzero(&findings[1..]));
        assert!(render(&[], &[], false, Path::new("/home/u")).contains("No problems found."));
    }

    /// A finding built from an error elsewhere — `resolve_binary` naming a
    /// Windows-side agent under WSL — is hidden on the way out, whatever rule
    /// produced it.
    #[test]
    fn render_hides_usernames_in_every_finding() {
        let findings = vec![Finding::blocking(
            "copilot resolves to a Windows install reached through WSL interop:\n  \
             /mnt/c/Users/kari/AppData/Roaming/npm/copilot",
            "--allow-exec /home/u/bin",
        )];
        let out = render(
            &findings,
            &["x /home/u/y".to_string()],
            false,
            Path::new("/home/u"),
        );
        assert!(!out.contains("kari"), "{out}");
        assert!(!out.contains("/home/u"), "{out}");
        assert!(out.contains("/mnt/c/Users/~/AppData"), "{out}");
        assert!(out.contains("fix: --allow-exec ~/bin"), "{out}");
    }

    fn net(allowed: &[&str], active: bool, blocked: &[&str]) -> NetPolicy {
        NetPolicy {
            allowed_ports: vec![443],
            allowed_domains: allowed.iter().map(|s| (*s).to_string()).collect(),
            allowlist_active: active,
            blocked_domains: blocked.iter().map(|s| (*s).to_string()).collect(),
            ..NetPolicy::default()
        }
    }

    #[test]
    fn agent_hosts_pass_without_an_allowlist_or_under_the_agent_defaults() {
        for agent in Agent::ALL {
            assert_eq!(
                agent_hosts_finding(*agent, &net(&[], false, &[])),
                None,
                "{agent:?}"
            );
            let defaults = agent.default_allowed_domains();
            assert_eq!(
                agent_hosts_finding(*agent, &net(&defaults, true, &[])),
                None,
                "{agent:?}"
            );
        }
    }

    /// The #604 setup after #605: a user allowlist gets the agent's own hosts
    /// but not the registries, and the fix is the key that merges them.
    #[test]
    fn an_allowlist_without_the_registries_warns() {
        let mut allowed = Agent::Copilot.infra_domains();
        allowed.push("example.com");
        let f = agent_hosts_finding(Agent::Copilot, &net(&allowed, true, &[]))
            .expect("registries are blocked");
        assert_eq!(f.level, Level::Warning);
        assert!(f.message.contains("(BLOCKED-ALLOWLIST)"), "{}", f.message);
        assert!(f.message.contains(" more."), "{}", f.message);
        let fix = f.fix.unwrap();
        assert!(fix.contains("default_allowlist = true"), "{fix}");
        assert!(fix.contains("package registries"), "{fix}");
    }

    /// Only a blocklist can block an agent host now, so that is where the fix
    /// points, not at an allowlist key.
    #[test]
    fn a_blocklisted_agent_host_points_at_the_blocklist() {
        let defaults = Agent::Copilot.default_allowed_domains();
        let f = agent_hosts_finding(
            Agent::Copilot,
            &net(&defaults, true, &["githubcopilot.com"]),
        )
        .expect("blocked agent host");
        assert!(
            f.message.contains("githubcopilot.com (BLOCKED)"),
            "{}",
            f.message
        );
        assert!(f.fix.unwrap().contains("remove it from that file"));

        // Mixed causes name both remedies.
        let mut allowed = Agent::Copilot.infra_domains();
        allowed.push("example.com");
        let f = agent_hosts_finding(Agent::Copilot, &net(&allowed, true, &["githubcopilot.com"]))
            .expect("mixed");
        let fix = f.fix.unwrap();
        assert!(fix.contains("remove it from that file"), "{fix}");
        assert!(fix.contains("default_allowlist = true"), "{fix}");
    }

    #[test]
    fn a_blocklisted_registry_counts_only_under_an_allowlist() {
        let blocked = ["pypi.org"];
        assert_eq!(
            agent_hosts_finding(Agent::Shell, &net(&[], false, &blocked)),
            None
        );
        let defaults = Agent::Shell.default_allowed_domains();
        let f = agent_hosts_finding(Agent::Shell, &net(&defaults, true, &blocked))
            .expect("blocked registry under an allowlist");
        assert!(f.message.contains("pypi.org (BLOCKED)"), "{}", f.message);
    }
}
