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
//! every agent profile denies on macOS and Linux and where every grant,
//! `allow.write` and env-relocated tool dirs alike, is refused. The file is
//! opened beneath the trusted dir one component at a time with `O_NOFOLLOW`,
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
/// It is inside cplt's own state tree, where every grant (`allow.*`, and
/// env-relocated tool dirs such as `GOCACHE`) is refused, so no agent can
/// write it.
pub const TRUSTED_DIR: &str = ".config/cplt/managed.d";

/// Open `rel` beneath the directory `dir`, one component at a time with
/// `O_NOFOLLOW`, so the file opened is under `dir` whatever happens to the
/// tree meanwhile. Non-blocking, so a FIFO cannot hang the launch.
fn open_beneath(dir: &Path, rel: &Path) -> std::io::Result<std::fs::File> {
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
    }
    Ok(std::fs::File::from(cur))
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

/// [`load_managed`] with every input explicit, for tests.
pub fn load_managed_from(
    value: &OsStr,
    account_home: Option<&Path>,
    env_home: Option<&Path>,
    writable: &[PathBuf],
) -> Result<ManagedConfig, String> {
    let path = Path::new(value);
    let refuse = |why: &str| {
        format!(
            "{MANAGED_CONFIG_ENV}={} ignored: {why}. Continuing without the managed config.",
            esc(&path.to_string_lossy())
        )
    };
    if !path.is_absolute() {
        return Err(refuse("the path must be absolute"));
    }
    let home = account_home
        .and_then(|h| std::fs::canonicalize(h).ok())
        .ok_or_else(|| refuse("cannot find the account's home directory"))?;
    // The sandbox denies the trusted dir as spelled from `$HOME`.
    if env_home
        .and_then(|h| std::fs::canonicalize(h).ok())
        .as_ref()
        != Some(&home)
    {
        return Err(refuse(
            "HOME is not the account's home directory, so the sandbox would not deny the managed directory",
        ));
    }
    let under = || refuse(&format!("it must lie under ~/{TRUSTED_DIR}"));
    let trusted = std::fs::canonicalize(home.join(TRUSTED_DIR)).map_err(|_| under())?;
    // A linked `.config/cplt` or `managed.d` points trust at a tree an
    // earlier session may have written.
    if trusted != home.join(TRUSTED_DIR) {
        return Err(refuse(&format!("~/{TRUSTED_DIR} or a parent is a symlink")));
    }
    let canonical = std::fs::canonicalize(path)
        .map_err(|e| refuse(&format!("cannot resolve it ({})", esc(&e.to_string()))))?;
    let rel = canonical.strip_prefix(&trusted).map_err(|_| under())?;
    crate::sandbox::resolve_unwritable(path, writable)
        .map_err(|()| refuse("it lies in or passes through a tree this session can write"))?;
    // The name itself must not be a link: whoever can re-point it chooses the file.
    if std::fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_symlink()) {
        return Err(refuse("it is a symlink"));
    }
    // Open what is read relative to the trusted dir, never following a link,
    // so a hop flipped after the canonicalize above cannot swap the file.
    let file = open_beneath(&trusted, rel).map_err(|e| {
        if e.raw_os_error() == Some(libc::ELOOP) || e.raw_os_error() == Some(libc::ENOTDIR) {
            refuse("a component changed into a symlink while it was opened")
        } else {
            refuse(&format!("cannot open it ({})", esc(&e.to_string())))
        }
    })?;
    // fstat the open descriptor so nothing can swap the file between check and read.
    let meta = file
        .metadata()
        .map_err(|e| refuse(&format!("cannot stat it ({})", esc(&e.to_string()))))?;
    {
        use std::os::unix::fs::MetadataExt;
        if meta.nlink() > 1 {
            return Err(refuse("it has more than one hard link"));
        }
        // SAFETY: geteuid has no preconditions and cannot fail.
        if meta.uid() != unsafe { libc::geteuid() } {
            return Err(refuse("it is not owned by the current user"));
        }
    }
    if !meta.is_file() {
        return Err(refuse("it is not a regular file"));
    }
    if meta.len() > LIMIT {
        return Err(refuse(&format!("it is larger than {LIMIT} bytes")));
    }
    let mut raw = String::new();
    // One byte past the cap: a file that grew after the fstat is refused, not truncated.
    file.take(LIMIT + 1)
        .read_to_string(&mut raw)
        .map_err(|e| refuse(&format!("cannot read it ({})", esc(&e.to_string()))))?;
    if raw.len() as u64 > LIMIT {
        return Err(refuse(&format!("it is larger than {LIMIT} bytes")));
    }
    let (managed_by, allow_private_domains) = parse(&raw).map_err(|e| refuse(&e))?;
    Ok(ManagedConfig {
        path: path.to_path_buf(),
        managed_by,
        allow_private_domains,
    })
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
}
