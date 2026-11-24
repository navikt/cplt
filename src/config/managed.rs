//! Managed config layer (#1095): org-level defaults a wrapper such as
//! nav-pilot supplies through `CPLT_MANAGED_CONFIG`, without editing the
//! user's own config.
//!
//! Trust boundary. The env var can come from an agent-writable source (a
//! project `.envrc`, mise `[env]`), and so can `HOME`, `XDG_*` and the agent
//! config dirs, so nothing derived from the environment decides trust. The
//! rule is positive: the canonical path (every symlink hop resolved) must lie
//! under [`TRUSTED_DIR`] in the account's home directory, taken from the
//! passwd entry. That is inside cplt's own state tree (`.config/cplt`), which
//! every agent profile denies on macOS and Linux, both as spelled from `$HOME`
//! and in the passwd home. Refused there: any grant (`allow.*`, env-relocated
//! tool dirs) inside the tree. A writable tree above it (`~/.config`, `$HOME`)
//! only warns: macOS keeps the tree denied, and on Linux the session ignores
//! this layer and [`ManagedSnapshot`] quarantines what it changed. The file is
//! opened by walking from `/` one component at a time with `O_NOFOLLOW`,
//! so the file read is the one trust was decided on. The denies are spelled
//! from `$HOME`, so the file is also refused when `$HOME` does not resolve to
//! the passwd home. As extra refusals, the file is refused when it
//! or any hop lies in a tree this session can write; when the last component
//! is a symlink or not a regular file; when it has more than one hard link;
//! when the current user does not own it; or when the header, a key or an
//! entry is wrong. A refusal is one line, with every agent-controlled part
//! escaped, and the launch continues without the layer.
//!
//! The layer can only add entries to `proxy.allow_private_domains`: never
//! anything that widens file access or weakens the sandbox.

use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::io::Read as _;
use std::path::{Path, PathBuf};

/// The env var naming the managed file. Absolute paths only.
pub const MANAGED_CONFIG_ENV: &str = "CPLT_MANAGED_CONFIG";

/// The only schema this cplt understands.
const SCHEMA: i64 = 1;

/// Size cap: a managed file holds a handful of domain lists.
const LIMIT: u64 = 64 * 1024;

/// The directory, relative to the passwd home, a managed file must live under.
/// It is inside cplt's own state tree: grants inside it, and writable trees
/// that contain it, are refused (see the module docs), so no agent can write it.
pub const TRUSTED_DIR: &str = ".config/cplt/managed.d";

/// Open `rel` beneath the directory `dir`, one component at a time with
/// `O_NOFOLLOW`, so the file opened is under `dir` whatever happens to the
/// tree meanwhile. Non-blocking, so a FIFO cannot hang the launch.
/// Directories at index `check_from` and deeper must be owned by the user or
/// root and not group/world-writable, checked by `fstat` on the held fd, so
/// nobody else can swap an entry below them.
fn open_beneath(dir: &Path, rel: &Path, check_from: usize) -> std::io::Result<std::fs::File> {
    use std::os::fd::{FromRawFd as _, OwnedFd};
    use std::os::unix::ffi::OsStrExt as _;
    let open = |at: libc::c_int, name: &OsStr, flags: libc::c_int| {
        let c = std::ffi::CString::new(name.as_bytes())?;
        // SAFETY: `c` is NUL-terminated; `at` is AT_FDCWD or an open fd.
        let fd =
            unsafe { libc::openat(at, c.as_ptr(), flags | libc::O_NOFOLLOW | libc::O_CLOEXEC) };
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: openat returned a fresh fd we now own.
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    };
    use std::os::fd::AsRawFd as _;
    let mut cur = open(
        libc::AT_FDCWD,
        dir.as_os_str(),
        libc::O_RDONLY | libc::O_DIRECTORY,
    )?;
    let parts: Vec<_> = rel.components().collect();
    let mut walked = dir.to_path_buf();
    for (i, c) in parts.iter().enumerate() {
        let std::path::Component::Normal(name) = c else {
            return Err(std::io::Error::from_raw_os_error(libc::EINVAL));
        };
        let flags = if i + 1 == parts.len() {
            libc::O_RDONLY | libc::O_NONBLOCK
        } else {
            libc::O_RDONLY | libc::O_DIRECTORY
        };
        cur = open(cur.as_raw_fd(), name, flags)?;
        walked.push(name);
        if i + 1 < parts.len() && i >= check_from {
            // SAFETY: zeroed stat is a valid out-parameter; `cur` is an open fd.
            let mut st: libc::stat = unsafe { std::mem::zeroed() };
            if unsafe { libc::fstat(cur.as_raw_fd(), &raw mut st) } != 0 {
                return Err(std::io::Error::last_os_error());
            }
            // SAFETY: geteuid has no preconditions and cannot fail.
            let euid = unsafe { libc::geteuid() };
            let foreign = st.st_uid != euid && st.st_uid != 0;
            if foreign || st.st_mode & 0o022 != 0 {
                return Err(std::io::Error::other(OpenDir(walked.clone(), foreign)));
            }
        }
    }
    Ok(std::fs::File::from(cur))
}

/// Open `rel` under the canonical `trusted` dir by walking from `/`, so no
/// component of the chain (home, `.config`, `cplt`, `managed.d`) can be
/// swapped for a symlink between the canonicalize check and the open.
fn open_managed(trusted: &Path, rel: &Path) -> std::io::Result<std::fs::File> {
    let chain = trusted
        .strip_prefix("/")
        .map_err(|_| std::io::Error::from_raw_os_error(libc::EINVAL))?;
    // From the home dir down: `trusted` is `<home>/.config/cplt/managed.d`.
    let home_idx = chain.components().count().saturating_sub(4);
    open_beneath(Path::new("/"), &chain.join(rel), home_idx)
}

/// A managed file that passed every check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedConfig {
    pub path: PathBuf,
    /// The header's `managed_by`, shown as the `managed:<name>` source tag.
    /// Restricted to `[A-Za-z0-9._-]`, so it prints as is.
    pub managed_by: String,
    /// Normalized, validated DNS names, sorted, deduplicated.
    pub allow_private_domains: Vec<String>,
}

impl ManagedConfig {
    /// The source tag `config show` and `doctor` print next to its values.
    pub fn tag(&self) -> String {
        format!("managed:{}", self.managed_by)
    }

    /// The path, escaped for a terminal.
    pub fn display_path(&self) -> String {
        esc(&self.path.to_string_lossy())
    }
}

fn esc(s: &str) -> String {
    crate::audit::escape_path(s)
}

/// The account's home directory from the passwd entry, never `$HOME`.
pub fn account_home() -> Option<PathBuf> {
    // Test-only seam so e2e can trust a scratch home; absent from release builds.
    #[cfg(debug_assertions)]
    if let Some(h) = std::env::var_os("CPLT_TEST_ACCOUNT_HOME").filter(|v| !v.is_empty()) {
        return Some(PathBuf::from(h));
    }
    use std::ffi::CStr;
    use std::os::unix::ffi::OsStrExt as _;
    let mut buf = vec![0u8; 16 * 1024];
    // SAFETY: zeroed passwd is a valid out-parameter for getpwuid_r.
    let mut pw: libc::passwd = unsafe { std::mem::zeroed() };
    let mut out: *mut libc::passwd = std::ptr::null_mut();
    // SAFETY: every pointer is valid for the call; `buf` outlives the reads below.
    let rc = unsafe {
        libc::getpwuid_r(
            libc::geteuid(),
            &raw mut pw,
            buf.as_mut_ptr().cast(),
            buf.len(),
            &raw mut out,
        )
    };
    if rc != 0 || out.is_null() || pw.pw_dir.is_null() {
        return None;
    }
    // SAFETY: getpwuid_r succeeded, so pw_dir is a NUL-terminated string in `buf`.
    let dir = unsafe { CStr::from_ptr(pw.pw_dir) };
    let dir = PathBuf::from(OsStr::from_bytes(dir.to_bytes()));
    dir.is_absolute().then_some(dir)
}

/// Read the managed file named by `CPLT_MANAGED_CONFIG`. `None` when the
/// variable is unset or empty; `Some(Err(line))` when the file is refused.
/// `writable` is every tree this session can write (an extra refusal only).
pub fn load_managed(
    writable: impl FnOnce() -> Vec<PathBuf>,
) -> Option<Result<ManagedConfig, String>> {
    let value = std::env::var_os(MANAGED_CONFIG_ENV).filter(|v| !v.is_empty())?;
    let env_home = std::env::var_os("HOME").map(PathBuf::from);
    Some(load_managed_from(
        &value,
        account_home().as_deref(),
        env_home.as_deref(),
        &writable(),
    ))
}

/// `s` as a shell word that names the same bytes and is safe to print.
/// Each component is quoted on its own, so a plain prefix such as the home
/// directory stays bare and doctor can still turn it into an expanding `~`.
fn q(s: &Path) -> String {
    use std::os::unix::ffi::OsStrExt as _;
    let b = s.as_os_str().as_bytes();
    if b.is_empty() {
        return "''".to_string();
    }
    b.split(|&c| c == b'/')
        .map(q_part)
        .collect::<Vec<_>>()
        .join("/")
}

/// One path component: bare when plain, single-quoted when printable ASCII,
/// else `$'..'` with every other byte as `\xHH` (bash and zsh), so no
/// terminal escaping changes which file the command names.
fn q_part(b: &[u8]) -> String {
    if b.iter()
        .all(|c| c.is_ascii_alphanumeric() || b"._-+@%:,=".contains(c))
    {
        String::from_utf8_lossy(b).into_owned()
    } else if b.iter().all(|c| (0x20..0x7f).contains(c)) {
        format!("'{}'", String::from_utf8_lossy(b).replace('\'', r"'\''"))
    } else {
        let mut out = String::from("$'");
        for &c in b {
            match c {
                b'\\' | b'\'' => out.extend(['\\', char::from(c)]),
                0x20..0x7f => out.push(char::from(c)),
                _ => {
                    let _ = std::fmt::Write::write_fmt(&mut out, format_args!("\\x{c:02x}"));
                }
            }
        }
        out.push('\'');
        out
    }
}

/// A directory on the walk that is not owned by the user or root (`.1` is
/// true), or is group/world-writable. Carries the path for the remedy.
#[derive(Debug)]
struct OpenDir(PathBuf, bool);

impl std::fmt::Display for OpenDir {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let why = if self.1 {
            "is not owned by you or root"
        } else {
            "is group/world-writable"
        };
        write!(f, "the directory {} {why}", esc(&self.0.to_string_lossy()))
    }
}

impl std::error::Error for OpenDir {}

/// [`load_managed`] with every input explicit, for tests.
///
/// Every refusal names its cause and one specific remedy, for someone who
/// never set `CPLT_MANAGED_CONFIG` (a wrapper such as nav-pilot did). Unsetting
/// the variable comes last, as the way to run without the layer.
pub fn load_managed_from(
    value: &OsStr,
    account_home: Option<&Path>,
    env_home: Option<&Path>,
    writable: &[PathBuf],
) -> Result<ManagedConfig, String> {
    let path = Path::new(value);
    let refuse = |why: &str, fix: &str| {
        format!(
            "{MANAGED_CONFIG_ENV}={} ignored: {why}. {fix} To run without the managed layer, unset {MANAGED_CONFIG_ENV}. Continuing without the managed config.",
            esc(&path.to_string_lossy())
        )
    };
    let dir_hint = format!("Have the wrapper that set it write the file under ~/{TRUSTED_DIR}.");
    if !path.is_absolute() {
        return Err(refuse(
            "the path must be absolute",
            "The wrapper that set it must pass an absolute path.",
        ));
    }
    let home = account_home
        .and_then(|h| std::fs::canonicalize(h).ok())
        .ok_or_else(|| {
            refuse(
                "cannot find the account's home directory",
                "cplt reads it from the passwd entry; check that your account has an existing home directory.",
            )
        })?;
    // The sandbox denies the trusted dir as spelled from `$HOME`.
    let canon_env_home = env_home.and_then(|h| std::fs::canonicalize(h).ok());
    if canon_env_home.as_ref() != Some(&home) {
        let shown = env_home.map_or_else(|| "unset".to_string(), |h| esc(&h.to_string_lossy()));
        let tmp = [env_home, canon_env_home.as_deref()]
            .into_iter()
            .flatten()
            .any(|h| h.starts_with("/tmp") || h.starts_with("/private/tmp"));
        return Err(refuse(
            &format!(
                "HOME is not the account's home directory (HOME is {shown}, your account home is {}), so the sandbox would not deny the managed directory{}",
                esc(&home.to_string_lossy()),
                if tmp {
                    "; /tmp and /private/tmp are agent-writable by design"
                } else {
                    ""
                }
            ),
            &format!("Launch with HOME set to {}.", q(&home)),
        ));
    }
    let under = || refuse(&format!("it must lie under ~/{TRUSTED_DIR}"), &dir_hint);
    let trusted = std::fs::canonicalize(home.join(TRUSTED_DIR)).map_err(|_| under())?;
    // A linked `.config/cplt` or `managed.d` points trust at a tree an
    // earlier session may have written.
    if trusted != home.join(TRUSTED_DIR) {
        return Err(refuse(
            &format!("~/{TRUSTED_DIR} or a parent is a symlink"),
            &format!(
                "Replace the link with a real directory ({} resolves to {}), then have the wrapper rewrite the file.",
                q(&home.join(TRUSTED_DIR)),
                q(&trusted)
            ),
        ));
    }
    let canonical = std::fs::canonicalize(path).map_err(|e| {
        refuse(
            &format!("cannot resolve it ({})", esc(&e.to_string())),
            "Check that the file exists; the wrapper that set it must recreate it.",
        )
    })?;
    let rel = canonical.strip_prefix(&trusted).map_err(|_| under())?;
    if rel.iter().any(|c| {
        c.as_encoded_bytes()
            .starts_with(QUARANTINE_PREFIX.as_bytes())
    }) {
        return Err(refuse(
            "it was quarantined after a session that could write it",
            "Review the quarantined file, then have the wrapper rewrite it under its original name.",
        ));
    }
    crate::sandbox::resolve_unwritable(path, writable).map_err(|()| {
        let tree = writable
            .iter()
            .find(|w| canonical.starts_with(w) || path.starts_with(w) || trusted.starts_with(w));
        let which = tree.map_or_else(
            || "a writable root".to_string(),
            |w| format!("the writable tree {}", q(w)),
        );
        refuse(
            &format!("it lies in or passes through a tree this session can write ({which})"),
            "Remove the grant that makes it writable: an `allow.write` entry, a project, repo or HOME that contains it, or an env-set tool dir such as PNPM_HOME or CARGO_HOME. Check with `cplt config show`.",
        )
    })?;
    // The name itself must not be a link: whoever can re-point it chooses the file.
    let as_file = "The wrapper that wrote it must rewrite it as a regular file";
    let wrapper_fix = |m: &str| format!("{as_file} ({m}).");
    if std::fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_symlink()) {
        return Err(refuse("it is a symlink", &wrapper_fix(&q(path))));
    }
    // Open what is read relative to the trusted dir, never following a link,
    // so a hop flipped after the canonicalize above cannot swap the file.
    let file = open_managed(&trusted, rel).map_err(|e| {
        if let Some(d) = e.get_ref().and_then(|r| r.downcast_ref::<OpenDir>()) {
            let fix = if d.1 {
                format!(
                    "Recreate {} as your own directory (or have root `chown` it to you), then have the wrapper rewrite the file.",
                    q(&d.0)
                )
            } else {
                format!("Run: chmod go-w {}", q(&d.0))
            };
            refuse(&d.to_string(), &fix)
        } else if e.raw_os_error() == Some(libc::ELOOP) || e.raw_os_error() == Some(libc::ENOTDIR) {
            refuse(
                "a component changed into a symlink while it was opened",
                &format!(
                    "Replace any link under {} with a real directory and rerun.",
                    q(&home.join(".config/cplt"))
                ),
            )
        } else {
            refuse(
                &format!("cannot open it ({})", esc(&e.to_string())),
                &format!("Check that {} exists and is readable by you.", q(path)),
            )
        }
    })?;
    // fstat the open descriptor so nothing can swap the file between check and read.
    let meta = file.metadata().map_err(|e| {
        refuse(
            &format!("cannot stat it ({})", esc(&e.to_string())),
            &format!("Check that {} is readable by you.", q(path)),
        )
    })?;
    {
        use std::os::unix::fs::MetadataExt;
        if meta.nlink() > 1 {
            return Err(refuse(
                "it has more than one hard link",
                &wrapper_fix(&q(path)),
            ));
        }
        // SAFETY: geteuid has no preconditions and cannot fail.
        if meta.uid() != unsafe { libc::geteuid() } {
            return Err(refuse(
                "it is not owned by the current user",
                &wrapper_fix(&q(path)),
            ));
        }
        if meta.mode() & 0o022 != 0 {
            return Err(refuse(
                "it is group- or world-writable",
                &format!("Run: chmod 644 {}", q(path)),
            ));
        }
    }
    if !meta.is_file() {
        return Err(refuse("it is not a regular file", &wrapper_fix(&q(path))));
    }
    let invalid = |why: &str, raw: &str| {
        let by = wrote_by(raw);
        refuse(
            why,
            &format!("{by} wrote an invalid file; update or reinstall it."),
        )
    };
    if meta.len() > LIMIT {
        return Err(invalid(&format!("it is larger than {LIMIT} bytes"), ""));
    }
    let mut raw = String::new();
    // One byte past the cap: a file that grew after the fstat is refused, not truncated.
    file.take(LIMIT + 1)
        .read_to_string(&mut raw)
        .map_err(|e| invalid(&format!("cannot read it ({})", esc(&e.to_string())), ""))?;
    if raw.len() as u64 > LIMIT {
        return Err(invalid(&format!("it is larger than {LIMIT} bytes"), ""));
    }
    let (managed_by, allow_private_domains) = parse(&raw).map_err(|e| invalid(&e, &raw))?;
    Ok(ManagedConfig {
        path: path.to_path_buf(),
        managed_by,
        allow_private_domains,
    })
}

/// Who wrote a file that failed to parse: its `managed_by` when that is a
/// plain name, otherwise "the wrapper".
fn wrote_by(raw: &str) -> String {
    toml::from_str::<toml::Table>(raw)
        .ok()
        .and_then(|t| match t.get("managed_by") {
            Some(toml::Value::String(s))
                if !s.is_empty()
                    && s.len() <= 64
                    && s.bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b)) =>
            {
                Some(s.clone())
            }
            _ => None,
        })
        .unwrap_or_else(|| "the wrapper".to_string())
}

/// Parse and check the header and keys. Errors name the offending key,
/// escaped. Walks the tables by hand rather than flattening them, so a quoted
/// dotted key (`"proxy.allow_private_domains" = [...]`) and an empty unknown
/// table are refused too.
fn parse(raw: &str) -> Result<(String, Vec<String>), String> {
    let table: toml::Table = toml::from_str(raw)
        .map_err(|e: toml::de::Error| format!("not valid TOML ({})", esc(e.message().trim())))?;
    let managed_by = match table.get("managed_by") {
        Some(toml::Value::String(s))
            if !s.is_empty()
                && s.len() <= 64
                && s.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b)) =>
        {
            s.clone()
        }
        Some(_) => {
            return Err(
                "`managed_by` must be 1-64 characters of A-Z, a-z, 0-9, '.', '_' or '-'".into(),
            );
        }
        None => return Err("the `managed_by` header is missing".into()),
    };
    match table.get("schema") {
        Some(toml::Value::Integer(SCHEMA)) => {}
        Some(v) => {
            return Err(format!(
                "unknown schema {}, this cplt supports {SCHEMA}",
                esc(&v.to_string())
            ));
        }
        None => return Err("the `schema` header is missing".into()),
    }
    let mut domains = Vec::new();
    for (key, value) in &table {
        match (key.as_str(), value) {
            ("managed_by" | "schema", _) => {}
            ("proxy", toml::Value::Table(proxy)) => {
                for (k, v) in proxy {
                    if k != "allow_private_domains" {
                        return Err(format!(
                            "key `proxy.{}` is not allowed in a managed config",
                            esc(k)
                        ));
                    }
                    let list = v
                        .as_array()
                        .filter(|a| a.iter().all(toml::Value::is_str))
                        .ok_or("`proxy.allow_private_domains` must be a list of strings")?;
                    for d in list {
                        let raw = d.as_str().unwrap_or_default();
                        let d = crate::proxy::normalize_hostname(raw);
                        if !is_dns_name(&d) {
                            return Err(format!(
                                "`proxy.allow_private_domains` entry \"{}\" is not a DNS name with at least one dot",
                                esc(raw)
                            ));
                        }
                        domains.push(d);
                    }
                }
            }
            _ => {
                return Err(format!(
                    "key `{}` is not allowed in a managed config",
                    esc(key)
                ));
            }
        }
    }
    domains.sort_unstable();
    domains.dedup();
    Ok((managed_by, domains))
}

/// A lowercase DNS name with at least two labels: labels of 1-63 `[a-z0-9-]`
/// without a leading or trailing '-', at most 253 bytes, and a top label that
/// is not all digits, which refuses IPv4 literals. IPv6 fails on ':'.
fn is_dns_name(d: &str) -> bool {
    let labels: Vec<&str> = d.split('.').collect();
    d.len() <= 253
        && labels.len() >= 2
        && labels.iter().all(|l| {
            (1..=63).contains(&l.len())
                && l.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
                && !l.starts_with('-')
                && !l.ends_with('-')
        })
        && !labels[labels.len() - 1].bytes().all(|b| b.is_ascii_digit())
}

impl super::types::Resolved {
    /// Union the managed layer into the resolved config. The precedence is
    /// built-in < managed < user < CLI; every managed key is a list, and a
    /// list only grows, so a union is that order. To drop the managed entries,
    /// unset `CPLT_MANAGED_CONFIG`.
    pub fn apply_managed(&mut self, managed: &ManagedConfig) {
        for d in &managed.allow_private_domains {
            if !self.allow_private_domains.contains(d) {
                self.allow_private_domains.push(d.clone());
            }
        }
        self.allow_private_domains.sort_unstable();
        self.allow_private_domains.dedup();
        self.managed = Some(managed.clone());
    }

    /// `managed:<name>` when `domain` came only from the managed layer.
    pub fn managed_tag(&self, domain: &str, user_domains: &[String]) -> Option<String> {
        self.managed.as_ref().and_then(|m| {
            (m.allow_private_domains.iter().any(|d| d == domain)
                && !user_domains.iter().any(|d| d == domain))
            .then(|| m.tag())
        })
    }
}

/// Name prefix of an entry moved aside by [`ManagedSnapshot::finish`]. The
/// loader refuses any path with a component carrying it.
pub const QUARANTINE_PREFIX: &str = ".quarantine-";

/// One `managed.d` entry as the parent saw it: inode, size, mtime in ns,
/// link count, ctime in ns, and a SHA-256 of the content for a regular file.
/// ctime catches a hardlink or chmod that leaves content and mtime alone.
type Entry = (u64, u64, i64, u64, i64, Option<[u8; 32]>);

/// The held dir, its (dev, ino), and its entries (`None`: too many to compare).
type Before = (std::fs::File, (u64, u64), Option<BTreeMap<PathBuf, Entry>>);

/// Entries scanned before the whole dir counts as changed: a session must not
/// be able to stall the parent's check with a million files.
const MAX_ENTRIES: usize = 4096;

/// `managed.d` as it was before a Linux session that can write it (a grant at
/// or above cplt's state dir, warned instead of refused). Landlock cannot deny
/// below a granted tree, so the parent keeps this in memory, where the agent
/// cannot reach it, and after the session moves aside every entry that is new
/// or changed. The residual (parent SIGKILLed before the check, or a process
/// the session left behind writing after it) is in SECURITY.md.
pub struct ManagedSnapshot {
    path: PathBuf,
    before: Option<Before>,
}

impl ManagedSnapshot {
    /// Snapshot `<home>/.config/cplt/managed.d`.
    #[must_use]
    pub fn take(home: &Path) -> Self {
        // Canonical, as the loader takes it: `open_dir` refuses any symlink hop.
        let path = std::fs::canonicalize(home)
            .unwrap_or_else(|_| home.to_path_buf())
            .join(TRUSTED_DIR);
        let before = open_dir(&path).map(|(f, id)| {
            let entries = scan(&f);
            (f, id, entries)
        });
        Self { path, before }
    }

    /// Re-scan and quarantine what changed. Returns one warning line, or
    /// `None` when nothing did.
    #[must_use]
    pub fn finish(self) -> Option<String> {
        let now = open_dir(&self.path);
        let moved = match (self.before, now) {
            // Gone, or replaced by (or reached through) a symlink: the loader
            // refuses that layout, so nothing loads from it. Say so.
            (before, None) => {
                return (before.is_some() || std::fs::symlink_metadata(&self.path).is_ok()).then(
                    || {
                        format!(
                            "The session could write cplt's state directory, and {} is no \
                             longer a plain directory (moved, removed or replaced by a symlink). \
                             The managed config is refused until it is restored. Review it, and \
                             remove the grant that covers ~/.config/cplt.",
                            esc(&self.path.to_string_lossy())
                        )
                    },
                );
            }
            (Some((_, id, Some(old))), Some((f, now_id))) if id == now_id => {
                let Some(new) = scan(&f) else {
                    return quarantine_dir(&self.path);
                };
                let mut names: Vec<&OsStr> = new
                    .iter()
                    // A second hard link to a file is a way back in for a later session.
                    .filter(|(rel, e)| old.get(*rel) != Some(e) || (e.5.is_some() && e.3 > 1))
                    .filter_map(|(rel, _)| rel.iter().next())
                    .collect();
                names.dedup();
                let mut moved = Vec::new();
                for n in names {
                    match quarantine_at(&f, n) {
                        Some(m) => moved.push(m),
                        // Nothing that changed may stay where it loads: the
                        // whole dir goes, or the user is told how.
                        None => return quarantine_dir(&self.path),
                    }
                }
                moved
            }
            // Created, replaced, or too big to compare: the whole dir goes.
            _ => return quarantine_dir(&self.path),
        };
        (!moved.is_empty()).then(|| quarantine_line(&self.path, &moved.join(", ")))
    }
}

fn quarantine_line(dir: &Path, what: &str) -> String {
    format!(
        "The session could write cplt's state directory, and changed {} in {}. \
         Moved aside as {QUARANTINE_PREFIX}*, so the managed config ignores it. \
         Review it, and remove the grant that covers ~/.config/cplt.",
        esc(what),
        esc(&dir.to_string_lossy())
    )
}

fn stamp() -> String {
    let t = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    format!("{QUARANTINE_PREFIX}{}{:09}-", t.as_secs(), t.subsec_nanos())
}

/// Move the whole dir aside, next to itself, through its parent's descriptor.
/// When even that fails, the line says how to do it by hand: a failure is
/// never silent, since what changed would load at the next launch.
fn quarantine_dir(path: &Path) -> Option<String> {
    let name = path.file_name()?;
    let moved = path
        .parent()
        .and_then(open_dir)
        .and_then(|(parent, _)| quarantine_at(&parent, name));
    if moved.is_some() {
        return Some(quarantine_line(path, &name.to_string_lossy()));
    }
    let p = esc(&path.to_string_lossy());
    Some(format!(
        "The session could write cplt's state directory and changed {p}, and cplt could \
         not move it aside. The managed config there may now be the session's. Before the \
         next launch, run: chmod -R u+w '{p}' && mv '{p}' '{p}.quarantined' — then review \
         it, and remove the grant that covers ~/.config/cplt."
    ))
}

/// Rename `name` inside the held dir, never through a path an agent may have
/// re-pointed.
fn quarantine_at(dir: &std::fs::File, name: &OsStr) -> Option<String> {
    use std::os::fd::AsRawFd as _;
    use std::os::unix::ffi::OsStrExt as _;
    let mut to = std::ffi::OsString::from(stamp());
    to.push(name);
    let from = std::ffi::CString::new(name.as_bytes()).ok()?;
    let to = std::ffi::CString::new(to.as_bytes()).ok()?;
    let fd = dir.as_raw_fd();
    // SAFETY: both names are NUL-terminated; `fd` is an open directory.
    let rename = || unsafe { libc::renameat(fd, from.as_ptr(), fd, to.as_ptr()) } == 0;
    // The session may have dropped write permission on the dir (`chmod 555`):
    // restore owner write through the held descriptor and try once more.
    let ok = rename()
        || dir.metadata().is_ok_and(|m| {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = (m.permissions().mode() | 0o700) & 0o7777;
            // SAFETY: `fd` is an open directory; fchmod has no other preconditions.
            let rc = unsafe { libc::fchmod(fd, mode as libc::mode_t) };
            rc == 0
        }) && rename();
    ok.then(|| name.to_string_lossy().into_owned())
}

/// Open `path` as a directory when it, and every parent, is no symlink.
fn open_dir(path: &Path) -> Option<(std::fs::File, (u64, u64))> {
    use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
    if std::fs::canonicalize(path).ok()? != path {
        return None;
    }
    let f = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(path)
        .ok()?;
    let m = f.metadata().ok()?;
    Some((f, (m.dev(), m.ino())))
}

/// Every entry below `dir`, `None` past [`MAX_ENTRIES`] or on a read error.
fn scan(dir: &std::fs::File) -> Option<BTreeMap<PathBuf, Entry>> {
    let mut out = BTreeMap::new();
    scan_into(dir, Path::new(""), &mut out, 0)?;
    Some(out)
}

fn scan_into(
    dir: &std::fs::File,
    prefix: &Path,
    out: &mut BTreeMap<PathBuf, Entry>,
    depth: usize,
) -> Option<()> {
    use std::os::fd::{AsRawFd as _, FromRawFd as _};
    use std::os::unix::ffi::OsStrExt as _;
    // SAFETY: dup of an open fd; fdopendir takes ownership of the copy.
    let dp = unsafe { libc::fdopendir(libc::dup(dir.as_raw_fd())) };
    if dp.is_null() {
        return None;
    }
    let mut names = Vec::new();
    loop {
        // SAFETY: `dp` is a valid DIR*; the entry is copied before the next call.
        let ent = unsafe { libc::readdir(dp) };
        if ent.is_null() {
            break;
        }
        // SAFETY: d_name is NUL-terminated.
        let name = unsafe { std::ffi::CStr::from_ptr((*ent).d_name.as_ptr()) };
        if name.to_bytes() != b"." && name.to_bytes() != b".." {
            names.push(name.to_owned());
        }
    }
    // SAFETY: `dp` came from fdopendir and is closed once.
    unsafe { libc::closedir(dp) };
    for name in names {
        if out.len() >= MAX_ENTRIES || depth > 8 {
            return None;
        }
        let rel = prefix.join(OsStr::from_bytes(name.to_bytes()));
        // SAFETY: `name` is NUL-terminated; `fd` is an open directory.
        let fd = unsafe {
            libc::openat(
                dir.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            // A symlink (ELOOP) or a socket: record by lstat, content-free.
            let mut st: libc::stat = unsafe { std::mem::zeroed() };
            // SAFETY: as above; `st` is a valid out pointer.
            if unsafe {
                libc::fstatat(
                    dir.as_raw_fd(),
                    name.as_ptr(),
                    &raw mut st,
                    libc::AT_SYMLINK_NOFOLLOW,
                )
            } != 0
            {
                return None;
            }
            out.insert(rel, stat_entry(&st, None));
            continue;
        }
        // SAFETY: `fd` was just opened and is owned here.
        let f = unsafe { std::fs::File::from_raw_fd(fd) };
        let m = f.metadata().ok()?;
        let entry = {
            use std::os::unix::fs::MetadataExt as _;
            let hash = if m.is_file() {
                use sha2::Digest as _;
                let mut buf = Vec::new();
                (&f).take(LIMIT + 1).read_to_end(&mut buf).ok()?;
                Some(sha2::Sha256::digest(&buf).into())
            } else {
                None
            };
            (
                m.ino(),
                m.size(),
                m.mtime() * 1_000_000_000 + m.mtime_nsec(),
                m.nlink(),
                m.ctime() * 1_000_000_000 + m.ctime_nsec(),
                hash,
            )
        };
        out.insert(rel.clone(), entry);
        if m.is_dir() {
            scan_into(&f, &rel, out, depth + 1)?;
        }
    }
    Some(())
}

#[allow(clippy::cast_sign_loss, clippy::unnecessary_cast)]
fn stat_entry(st: &libc::stat, hash: Option<[u8; 32]>) -> Entry {
    (
        st.st_ino as u64,
        st.st_size as u64,
        st.st_mtime as i64 * 1_000_000_000 + st.st_mtime_nsec as i64,
        u64::from(st.st_nlink),
        st.st_ctime as i64 * 1_000_000_000 + st.st_ctime_nsec as i64,
        hash,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt as _;

    const GOOD: &str = "managed_by = \"nav-pilot\"\nschema = 1\n\n[proxy]\nallow_private_domains = [\"Intern.NAV.no.\", \"b.nav.no\"]\n";

    fn write(dir: &Path, name: &str, body: &str) -> PathBuf {
        let p = dir.join(name);
        std::fs::write(&p, body).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
        p
    }

    /// A fake account home with the trusted dir; it stands for the passwd home.
    /// A parent of `managed.d` swapped for a symlink after the path checks
    /// (Copilot PRRT_kwDOR-ZXjs67IKT9): the open must refuse it.
    #[test]
    fn open_managed_refuses_symlinked_parent() {
        use std::os::unix::fs::symlink;
        for swap in [".config", ".config/cplt", ".config/cplt/managed.d"] {
            let d = tempfile::tempdir().unwrap();
            let root = std::fs::canonicalize(d.path()).unwrap();
            let home = root.join("home");
            let evil = root.join("evil");
            std::fs::create_dir_all(home.join(TRUSTED_DIR)).unwrap();
            std::fs::write(home.join(TRUSTED_DIR).join("x.toml"), "ok").unwrap();
            assert!(open_managed(&home.join(TRUSTED_DIR), Path::new("x.toml")).is_ok());
            // Attacker tree mirroring what lies below the swapped component.
            let below = Path::new(TRUSTED_DIR).strip_prefix(swap).unwrap();
            std::fs::create_dir_all(evil.join(below)).unwrap();
            std::fs::write(evil.join(below).join("x.toml"), "evil").unwrap();
            std::fs::rename(home.join(swap), root.join("old")).unwrap();
            symlink(&evil, home.join(swap)).unwrap();
            let e = open_managed(&home.join(TRUSTED_DIR), Path::new("x.toml")).expect_err(swap);
            assert!(
                matches!(e.raw_os_error(), Some(libc::ELOOP) | Some(libc::ENOTDIR)),
                "{swap}: {e}"
            );
        }
    }

    struct Home(tempfile::TempDir);

    impl Home {
        fn new() -> Self {
            let d = tempfile::tempdir().unwrap();
            std::fs::create_dir_all(d.path().join(TRUSTED_DIR)).unwrap();
            Self(d)
        }
        fn path(&self) -> &Path {
            self.0.path()
        }
        fn managed_d(&self) -> PathBuf {
            self.path().join(TRUSTED_DIR)
        }
        fn load(&self, value: &OsStr, writable: &[PathBuf]) -> Result<ManagedConfig, String> {
            load_managed_from(value, Some(self.path()), Some(self.path()), writable)
        }
        fn refused(&self, value: &OsStr, writable: &[PathBuf], why: &str) -> String {
            let e = self.load(value, writable).unwrap_err();
            assert!(e.contains(why), "expected {why:?} in {e:?}");
            assert_one_line(&e);
            e
        }
    }

    fn assert_one_line(e: &str) {
        assert!(
            !e.chars().any(char::is_control),
            "refusal must be one escaped line: {e:?}"
        );
    }

    #[test]
    fn accepts_a_good_file_in_the_trusted_dir_and_normalizes() {
        let h = Home::new();
        let p = write(&h.managed_d(), "nav-pilot.toml", GOOD);
        let m = h.load(p.as_os_str(), &[]).unwrap();
        assert_eq!(m.managed_by, "nav-pilot");
        assert_eq!(m.allow_private_domains, ["b.nav.no", "intern.nav.no"]);
        assert_eq!(m.tag(), "managed:nav-pilot");
    }

    #[test]
    fn refuses_group_or_world_writable_file_or_parent() {
        use std::os::unix::fs::PermissionsExt as _;
        let set = |p: &Path, m: u32| {
            std::fs::set_permissions(p, std::fs::Permissions::from_mode(m)).unwrap();
        };
        let h = Home::new();
        let p = write(&h.managed_d(), "nav-pilot.toml", GOOD);
        set(&p, 0o664);
        h.refused(p.as_os_str(), &[], "group- or world-writable");
        set(&p, 0o644);
        let cplt = h.path().join(".config/cplt");
        set(&cplt, 0o777);
        h.refused(p.as_os_str(), &[], "group/world-writable");
        set(&cplt, 0o755);
        assert!(h.load(p.as_os_str(), &[]).is_ok());
    }

    /// #1131 review: the shell word names the original bytes.
    #[test]
    fn shell_word_preserves_the_path_bytes() {
        use std::os::unix::ffi::OsStrExt as _;
        assert_eq!(
            q(Path::new("/a/b.toml")),
            "/a/b.toml",
            "plain path stays bare"
        );
        assert_eq!(
            q(Path::new(r"/a/x\ y")),
            r"/a/'x\ y'",
            "one backslash stays one"
        );
        assert_eq!(
            q(Path::new("/a/x'y")),
            r"/a/'x'\''y'",
            "quote is closed and escaped"
        );
        assert_eq!(
            q(Path::new(std::ffi::OsStr::from_bytes(b"/a/\\\n\xff'"))),
            r"/a/$'\\\x0a\xff\''",
            "control and non-UTF-8 bytes become \\xHH"
        );
        // Doctor abbreviates the home; the tilde must stay outside any quote.
        assert_eq!(
            crate::doctor::tilde_in_text(
                &format!("Run: chmod 644 {}", q(Path::new("/home/u/m d/a b.toml"))),
                Path::new("/home/u"),
            ),
            "Run: chmod 644 ~/'m d'/'a b.toml'",
            "doctor keeps the operand expandable"
        );
    }

    /// #1131 review: a foreign-owned directory is not fixed by chmod.
    #[test]
    fn open_dir_names_its_own_cause() {
        let d = OpenDir(PathBuf::from("/x"), true).to_string();
        assert!(
            d.contains("not owned by you or root"),
            "ownership cause: {d}"
        );
        assert!(!d.contains("writable"), "no mode cause: {d}");
        let d = OpenDir(PathBuf::from("/x"), false).to_string();
        assert!(d.contains("group/world-writable"), "mode cause: {d}");
    }

    /// #1129: each refusal ends with a fix for its own cause, and the
    /// last-resort unset comes after it.
    #[test]
    fn every_refusal_carries_its_own_remedy() {
        use std::os::unix::fs::PermissionsExt as _;
        let set = |p: &Path, m: u32| {
            std::fs::set_permissions(p, std::fs::Permissions::from_mode(m)).unwrap();
        };
        let fix = |e: &str, want: &str| {
            let at = e.find(want).unwrap_or_else(|| panic!("no {want:?} in {e}"));
            let unset = e.find("unset CPLT_MANAGED_CONFIG").expect(e);
            assert!(at < unset, "remedy must precede the unset hint: {e}");
        };
        let h = Home::new();
        let p = write(&h.managed_d(), "nav-pilot.toml", GOOD);
        let ps = p.to_string_lossy().to_string();
        set(&p, 0o664);
        fix(
            &h.refused(p.as_os_str(), &[], "group- or world-writable"),
            &format!("chmod 644 {ps}"),
        );
        set(&p, 0o600);
        let cplt = h.path().join(".config/cplt");
        set(&cplt, 0o777);
        fix(
            &h.refused(p.as_os_str(), &[], "group/world-writable"),
            &format!(
                "chmod go-w {}",
                std::fs::canonicalize(&cplt).unwrap().display()
            ),
        );
        set(&cplt, 0o755);
        // Not a tempdir: on Linux that sits under /tmp and adds the tmp note.
        let other = Path::new("/nonexistent/cplt-other-home");
        let e = load_managed_from(p.as_os_str(), Some(h.path()), Some(other), &[]).unwrap_err();
        let home = std::fs::canonicalize(h.path()).unwrap();
        fix(&e, &format!("Launch with HOME set to {}", home.display()));
        assert!(
            e.contains(&format!("your account home is {}", home.display())),
            "{e}"
        );
        assert!(
            !e.contains("agent-writable by design"),
            "tmp note only for a HOME under /tmp: {e}"
        );
        let e = load_managed_from(
            p.as_os_str(),
            Some(h.path()),
            Some(Path::new("/tmp/x")),
            &[],
        )
        .unwrap_err();
        assert!(e.contains("agent-writable by design"), "{e}");
        let out = write(h.path(), "x.toml", GOOD);
        fix(
            &h.refused(out.as_os_str(), &[], "must lie under"),
            "Have the wrapper that set it write the file under ~/.config/cplt/managed.d",
        );
        let link = h.managed_d().join("l.toml");
        std::os::unix::fs::symlink(&p, &link).unwrap();
        fix(
            &h.refused(link.as_os_str(), &[], "it is a symlink"),
            "must rewrite it as a regular file",
        );
        std::fs::hard_link(&p, h.managed_d().join("other")).unwrap();
        fix(
            &h.refused(p.as_os_str(), &[], "hard link"),
            "must rewrite it as a regular file",
        );
        std::fs::remove_file(h.managed_d().join("other")).unwrap();
        let e = h.refused(p.as_os_str(), &[h.managed_d()], "can write");
        assert!(e.contains(&format!("{}", h.managed_d().display())), "{e}");
        fix(&e, "Remove the grant");
        fix(
            &refused_body(
                "managed_by = \"nav-pilot\"\nschema = 2\n",
                "unknown schema 2",
            ),
            "nav-pilot wrote an invalid file; update or reinstall it",
        );
        fix(
            &refused_body("not toml [", "not valid TOML"),
            "the wrapper wrote an invalid file; update or reinstall it",
        );
    }

    #[test]
    fn refuses_nav_pilot_state_dir() {
        // `~/.nav-pilot` can be granted write (an env-relocated tool dir, a
        // per-file allow.write), so it is not trusted.
        let h = Home::new();
        let dir = h.path().join(".nav-pilot");
        std::fs::create_dir_all(&dir).unwrap();
        let p = write(&dir, "managed.toml", GOOD);
        h.refused(p.as_os_str(), &[], "must lie under");
    }

    #[test]
    fn no_grant_can_make_the_trusted_dir_writable() {
        // What keeps agents out on both platforms: every grant into cplt's
        // state tree is refused, whether `allow.write` or an env-relocated
        // tool dir such as GOCACHE.
        let h = Home::new();
        let home = h.path();
        for target in [h.managed_d(), h.managed_d().join("nav-pilot.toml")] {
            assert!(crate::sandbox::validate_grant_path("allow.write", &target, home).is_err());
            assert!(
                crate::sandbox::grant_is_refused(home, &target),
                "{target:?}"
            );
        }
        let env = vec![("GOCACHE".to_string(), h.managed_d().display().to_string())];
        for o in crate::sandbox::tool_path_env_overrides(&env, home) {
            assert!(crate::sandbox::grant_is_refused(home, &o.path), "{o:?}");
        }
    }

    #[test]
    fn refuses_relative_path() {
        Home::new().refused(OsStr::new("managed.toml"), &[], "must be absolute");
    }

    #[test]
    fn refuses_a_file_outside_the_trusted_dirs_even_when_not_writable() {
        let h = Home::new();
        let p = write(h.path(), "managed.toml", GOOD);
        h.refused(p.as_os_str(), &[], "must lie under");
        // A sibling whose name starts like a trusted dir is outside it too.
        let sib = h.path().join(".config/cplt/managed.d-x");
        std::fs::create_dir_all(&sib).unwrap();
        let p = write(&sib, "managed.toml", GOOD);
        h.refused(p.as_os_str(), &[], "must lie under");
    }

    #[test]
    fn relocated_home_cannot_move_the_trusted_dir() {
        // `.envrc` sets HOME (or CLAUDE_CONFIG_DIR/XDG) into the project and
        // plants `<fake>/.config/cplt/managed.d/m.toml`. Trust comes from the
        // passwd home, so the planted file is outside it; and with HOME
        // relocated even a file in the real managed.d is refused, since the
        // sandbox denies spell from `$HOME`.
        let real = Home::new();
        let fake = Home::new();
        let planted = write(&fake.managed_d(), "m.toml", GOOD);
        let e = load_managed_from(
            planted.as_os_str(),
            Some(real.path()),
            Some(fake.path()),
            &[],
        )
        .unwrap_err();
        assert!(e.contains("HOME is not the account's home"), "{e}");
        let e = load_managed_from(
            planted.as_os_str(),
            Some(real.path()),
            Some(real.path()),
            &[],
        )
        .unwrap_err();
        assert!(e.contains("must lie under"), "{e}");
        let good = write(&real.managed_d(), "m.toml", GOOD);
        let e = load_managed_from(good.as_os_str(), Some(real.path()), Some(fake.path()), &[])
            .unwrap_err();
        assert!(e.contains("HOME is not the account's home"), "{e}");
        assert!(load_managed_from(good.as_os_str(), None, Some(real.path()), &[]).is_err());
    }

    #[test]
    fn refuses_a_symlink_hop_out_of_the_trusted_dir() {
        let h = Home::new();
        let elsewhere = tempfile::tempdir().unwrap();
        write(elsewhere.path(), "managed.toml", GOOD);
        let link = h.managed_d().join("dir");
        std::os::unix::fs::symlink(elsewhere.path(), &link).unwrap();
        h.refused(link.join("managed.toml").as_os_str(), &[], "must lie under");
    }

    #[test]
    fn still_refuses_a_trusted_file_inside_a_writable_tree() {
        // Defense in depth: the grant is refused at launch anyway.
        let h = Home::new();
        let p = write(&h.managed_d(), "managed.toml", GOOD);
        h.refused(p.as_os_str(), &[h.managed_d()], "can write");
        h.refused(p.as_os_str(), std::slice::from_ref(&p), "can write");
    }

    #[test]
    fn a_symlink_flipped_during_the_load_never_gets_its_target_read() {
        // `dir` flips between a link into managed.d and a link out of it. The
        // canonicalize may see the inside target; the open must not follow
        // the link that is there by then.
        let h = Home::new();
        let inside = h.managed_d().join("real");
        std::fs::create_dir(&inside).unwrap();
        write(&inside, "m.toml", GOOD);
        let evil = tempfile::tempdir().unwrap();
        write(
            evil.path(),
            "m.toml",
            &GOOD.replace("\"nav-pilot\"", "\"evil\""),
        );
        let dir = h.managed_d().join("dir");
        let tmp = h.managed_d().join("dir.tmp");
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let flipper = {
            let (stop, dir, tmp) = (stop.clone(), dir.clone(), tmp.clone());
            let targets = [inside.clone(), evil.path().to_path_buf()];
            std::thread::spawn(move || {
                let mut i = 0;
                while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                    let _ = std::fs::remove_file(&tmp);
                    std::os::unix::fs::symlink(&targets[i % 2], &tmp).unwrap();
                    std::fs::rename(&tmp, &dir).unwrap();
                    i += 1;
                }
            })
        };
        let value = dir.join("m.toml");
        for _ in 0..3000 {
            if let Ok(m) = h.load(value.as_os_str(), &[]) {
                assert_eq!(m.managed_by, "nav-pilot", "read the file outside managed.d");
            }
        }
        stop.store(true, std::sync::atomic::Ordering::Relaxed);
        flipper.join().unwrap();
    }

    #[test]
    fn refuses_a_symlinked_trusted_dir() {
        let h = Home::new();
        let old = tempfile::tempdir().unwrap();
        write(old.path(), "m.toml", GOOD);
        std::fs::remove_dir(h.managed_d()).unwrap();
        std::os::unix::fs::symlink(old.path(), h.managed_d()).unwrap();
        h.refused(
            h.managed_d().join("m.toml").as_os_str(),
            &[],
            "is a symlink",
        );
    }

    #[test]
    fn refuses_a_symlink_as_the_file() {
        let h = Home::new();
        let real = write(&h.managed_d(), "real.toml", GOOD);
        let link = h.managed_d().join("managed.toml");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        h.refused(link.as_os_str(), &[], "symlink");
    }

    #[test]
    fn refuses_a_fifo() {
        let h = Home::new();
        let p = h.managed_d().join("managed.toml");
        let c = std::ffi::CString::new(p.as_os_str().as_encoded_bytes()).unwrap();
        // SAFETY: `c` is a valid NUL-terminated path.
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
        h.refused(p.as_os_str(), &[], "not a regular file");
    }

    #[test]
    fn refuses_a_hard_linked_file() {
        let h = Home::new();
        let p = write(&h.managed_d(), "managed.toml", GOOD);
        std::fs::hard_link(&p, h.managed_d().join("other")).unwrap();
        h.refused(p.as_os_str(), &[], "hard link");
    }

    fn refused_body(body: &str, why: &str) -> String {
        let h = Home::new();
        let p = write(&h.managed_d(), "m.toml", body);
        h.refused(p.as_os_str(), &[], why)
    }

    #[test]
    fn refuses_missing_or_unknown_header() {
        for (body, why) in [
            ("schema = 1\n", "`managed_by` header is missing"),
            ("managed_by = \"x\"\n", "`schema` header is missing"),
            ("managed_by = \"x\"\nschema = 2\n", "unknown schema 2"),
            ("managed_by = \"\"\nschema = 1\n", "`managed_by` must be"),
            ("managed_by = \"a b\"\nschema = 1\n", "`managed_by` must be"),
            ("not toml [", "not valid TOML"),
        ] {
            refused_body(body, why);
        }
    }

    #[test]
    fn refuses_disallowed_keys_by_name() {
        for (body, key) in [
            ("[allow]\nwrite = [\"/\"]\n", "allow"),
            ("[sandbox]\npreset = \"open\"\n", "sandbox"),
            (
                "[proxy]\nallowed_domains = \"/x\"\n",
                "proxy.allowed_domains",
            ),
            // Empty unknown table: nothing to flatten, still refused.
            ("[future]\n", "future"),
            // Quoted dotted key at top level is not the `[proxy]` table.
            (
                "\"proxy.allow_private_domains\" = [\"a.nav.no\"]\n",
                "proxy.allow_private_domains",
            ),
        ] {
            refused_body(
                &format!("managed_by = \"x\"\nschema = 1\n{body}"),
                &format!("key `{key}` is not allowed"),
            );
        }
    }

    #[test]
    fn refuses_entries_that_are_not_dns_names() {
        for bad in [
            "no",
            "internal",
            "10.0.0.1",
            "::1",
            "[::1]",
            "*.nav.no",
            "-a.nav.no",
            "a-.nav.no",
            "a_b.nav.no",
            "a..no",
            "",
            ".",
            "nav.no:443",
        ] {
            refused_body(
                &format!(
                    "managed_by = \"x\"\nschema = 1\n[proxy]\nallow_private_domains = [\"ok.nav.no\", \"{bad}\"]\n"
                ),
                "is not a DNS name",
            );
        }
        let long = format!("{}.no", "a".repeat(64));
        refused_body(
            &format!(
                "managed_by = \"x\"\nschema = 1\n[proxy]\nallow_private_domains = [\"{long}\"]\n"
            ),
            "is not a DNS name",
        );
    }

    #[test]
    fn escapes_control_characters_in_every_refusal() {
        let h = Home::new();
        let dir = h.managed_d().join("a\x1b[2Jb\rc\nd");
        std::fs::create_dir(&dir).unwrap();
        let p = write(&dir, "m.toml", "managed_by = \"x\"\nschema = 1\n[future]\n");
        let e = h.refused(p.as_os_str(), &[], "not allowed");
        assert!(e.contains("\\u{1b}[2Jb\\rc\\nd"), "{e}");
        // Outside the trusted dirs: the env value itself is escaped.
        let e = h.refused(OsStr::new("/x\x1b]0;pwn\x07\r\n"), &[], "ignored");
        assert!(e.contains("\\u{1b}]0;pwn\\u{7}\\r\\n"), "{e}");
        for body in [
            "managed_by = \"x\"\nschema = 1\n\"k\\u001b[31m\" = 1\n",
            "managed_by = \"x\"\nschema = 1\n[proxy]\n\"a\\r\\n\" = 1\n",
            "managed_by = \"x\"\nschema = 1\n[proxy]\nallow_private_domains = [\"a\\u001b.no\\r\\n\"]\n",
            "managed_by = \"x\\u001b\\n\"\nschema = 1\n",
            "managed_by = \"x\"\nschema = \"\\u001b\\n\"\n",
            "\u{1b}\r\n[",
        ] {
            let p = write(&h.managed_d(), "m.toml", body);
            let e = h.load(p.as_os_str(), &[]).unwrap_err();
            assert_one_line(&e);
        }
    }

    #[test]
    fn apply_unions_and_tags_only_managed_only_values() {
        let user = crate::config::Config::parse(
            "[proxy]\nallow_private_domains = [\"b.nav.no\", \"user.nav.no\"]\n",
        )
        .unwrap();
        let mut r = user
            .merge_with_no_proxy_env(crate::config::CliFlags::default(), None)
            .unwrap();
        let user_domains = r.allow_private_domains.clone();
        let m = ManagedConfig {
            path: PathBuf::from("/m"),
            managed_by: "nav-pilot".into(),
            allow_private_domains: vec!["b.nav.no".into(), "intern.nav.no".into()],
        };
        r.apply_managed(&m);
        assert_eq!(
            r.allow_private_domains,
            ["b.nav.no", "intern.nav.no", "user.nav.no"]
        );
        assert_eq!(
            r.managed_tag("intern.nav.no", &user_domains).as_deref(),
            Some("managed:nav-pilot")
        );
        assert_eq!(r.managed_tag("b.nav.no", &user_domains), None);
        assert_eq!(r.managed_tag("user.nav.no", &user_domains), None);
    }

    fn names(dir: &Path) -> Vec<String> {
        let mut v: Vec<String> = std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        v.sort();
        v
    }

    /// Linux warn mode: a session that could write `managed.d` leaves files,
    /// links, FIFOs and in-place edits. The parent's in-memory snapshot moves
    /// each new or changed entry aside, keeps the untouched one, and the
    /// loader then refuses the quarantined name.
    #[test]
    fn snapshot_quarantines_what_a_session_adds_or_changes() {
        let h = Home::new();
        let d = h.managed_d();
        write(&d, "keep.toml", GOOD);
        let edit = write(&d, "edit.toml", GOOD);
        std::fs::create_dir(d.join("sub")).unwrap();
        let nested = write(&d.join("sub"), "n.toml", GOOD);
        let snap = ManagedSnapshot::take(h.path());
        assert!(
            ManagedSnapshot::take(h.path()).finish().is_none(),
            "no change, no line"
        );

        // The session.
        write(&d, "planted.toml", GOOD);
        std::fs::write(&edit, GOOD.replace("b.nav.no", "x.nav.no")).unwrap();
        std::fs::write(&nested, GOOD.replace("b.nav.no", "y.nav.no")).unwrap();
        std::os::unix::fs::symlink("/etc/hosts", d.join("link.toml")).unwrap();
        let fifo = std::ffi::CString::new(d.join("fifo").as_os_str().as_encoded_bytes()).unwrap();
        // SAFETY: NUL-terminated path.
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);

        let line = snap.finish().expect("changes are reported");
        assert_one_line(&line);
        let left = names(&d);
        assert!(left.contains(&"keep.toml".to_string()), "{left:?}");
        for gone in ["planted.toml", "edit.toml", "sub", "link.toml", "fifo"] {
            assert!(!left.contains(&gone.to_string()), "{gone} left in {left:?}");
            assert!(
                left.iter()
                    .any(|n| n.starts_with(QUARANTINE_PREFIX) && n.ends_with(gone)),
                "{gone} not quarantined: {left:?}"
            );
        }
        let q = left.iter().find(|n| n.ends_with("planted.toml")).unwrap();
        h.refused(d.join(q).as_os_str(), &[], "quarantined");
        assert!(h.load(d.join("keep.toml").as_os_str(), &[]).is_ok());
    }

    /// Fable on #1126: a session that drops write permission on `managed.d`
    /// must not keep its edit loadable. The parent restores owner write and
    /// moves the entry aside.
    #[test]
    fn snapshot_quarantines_despite_a_read_only_dir() {
        use std::os::unix::fs::PermissionsExt as _;
        let h = Home::new();
        let d = h.managed_d();
        let f = write(&d, "nav-pilot.toml", GOOD);
        let snap = ManagedSnapshot::take(h.path());
        std::fs::write(&f, GOOD.replace("b.nav.no", "x.nav.no")).unwrap();
        std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o555)).unwrap();
        let line = snap.finish().expect("reported");
        assert!(
            !d.join("nav-pilot.toml").exists(),
            "edit left loadable: {line}"
        );
    }

    /// When nothing can be moved (here: the parent and `managed.d` are both
    /// read-only to the rename, simulated by a dir the parent cannot open),
    /// the line gives the manual fix instead of staying silent.
    #[test]
    fn quarantine_dir_failure_is_loud() {
        let h = Home::new();
        let gone = h.path().join("no/such/managed.d");
        let line = quarantine_dir(&gone).expect("never silent");
        assert!(
            line.contains("could not move it aside") && line.contains("mv '"),
            "{line}"
        );
    }

    /// A hard link planted in `managed.d` changes no content or mtime, only
    /// nlink and ctime: it must still be quarantined, and the loader refuses it.
    #[test]
    fn snapshot_quarantines_a_planted_hard_link() {
        let h = Home::new();
        let d = h.managed_d();
        let f = write(&d, "nav-pilot.toml", GOOD);
        let snap = ManagedSnapshot::take(h.path());
        std::fs::hard_link(&f, h.path().join("outside.toml")).unwrap();
        h.refused(f.as_os_str(), &[], "more than one hard link");
        assert!(snap.finish().is_some());
        assert!(!d.join("nav-pilot.toml").exists());
    }

    /// The session replaces `managed.d` with a symlink: reported, not silent.
    #[test]
    fn snapshot_reports_a_symlinked_dir() {
        let h = Home::new();
        let d = h.managed_d();
        let snap = ManagedSnapshot::take(h.path());
        std::fs::rename(&d, h.path().join("elsewhere")).unwrap();
        std::os::unix::fs::symlink(h.path().join("elsewhere"), &d).unwrap();
        assert!(
            snap.finish()
                .unwrap()
                .contains("no longer a plain directory")
        );
    }

    /// `managed.d` created, or swapped for a fresh dir, during the session:
    /// the whole dir is moved aside.
    #[test]
    fn snapshot_quarantines_a_created_or_replaced_dir() {
        let h = Home::new();
        let d = h.managed_d();
        std::fs::remove_dir(&d).unwrap();
        let snap = ManagedSnapshot::take(h.path());
        std::fs::create_dir(&d).unwrap();
        write(&d, "planted.toml", GOOD);
        assert!(snap.finish().is_some());
        assert!(!d.exists());

        std::fs::create_dir(&d).unwrap();
        write(&d, "nav-pilot.toml", GOOD);
        let snap = ManagedSnapshot::take(h.path());
        let parent = d.parent().unwrap();
        std::fs::rename(&d, parent.join("old")).unwrap();
        std::fs::create_dir(&d).unwrap();
        write(&d, "nav-pilot.toml", GOOD);
        assert!(snap.finish().is_some());
        assert!(!d.exists(), "replaced dir must be moved aside");
    }
}
