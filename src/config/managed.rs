//! Managed config layer (#1095): org-level defaults a wrapper such as
//! nav-pilot supplies through `CPLT_MANAGED_CONFIG`, without editing the
//! user's own config.
//!
//! Trust boundary. The env var can come from an agent-writable source (a
//! project `.envrc`, mise `[env]`), so the path itself is untrusted. The file
//! is refused when the path is relative; when it, an ancestor or any symlink
//! hop lies in a tree this session can write (by identity, see
//! `sandbox::resolve_unwritable`); when the last component is a symlink or
//! not a regular file; when it has more than one hard link; when the current
//! user does not own it; or when the header is missing or names an unknown
//! schema. A refusal is one line and the launch continues without the layer.
//!
//! The layer can only add entries to the keys in [`MANAGED_KEYS`]: network
//! allowlists, never anything that widens file access or weakens the sandbox.

use std::ffi::OsStr;
use std::io::Read as _;
use std::path::{Path, PathBuf};

/// The env var naming the managed file. Absolute paths only.
pub const MANAGED_CONFIG_ENV: &str = "CPLT_MANAGED_CONFIG";

/// The only schema this cplt understands.
const SCHEMA: i64 = 1;

/// Size cap: a managed file holds a handful of domain lists.
const LIMIT: u64 = 64 * 1024;

/// Keys a managed file may set, besides the `managed_by`/`schema` header.
/// Every one is a list that is unioned into the user's value. Add
/// `proxy.allowed_domains` and MCP server specs here when they are wired up;
/// never `allow.*`, `sandbox.preset` or anything that loosens the sandbox.
const MANAGED_KEYS: &[&str] = &["proxy.allow_private_domains"];

/// A managed file that passed every check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedConfig {
    pub path: PathBuf,
    /// The header's `managed_by`, shown as the `managed:<name>` source tag.
    pub managed_by: String,
    /// Normalized, sorted, deduplicated.
    pub allow_private_domains: Vec<String>,
}

impl ManagedConfig {
    /// The source tag `config show` and `doctor` print next to its values.
    pub fn tag(&self) -> String {
        format!("managed:{}", self.managed_by)
    }
}

/// Read the managed file named by `CPLT_MANAGED_CONFIG`. `None` when the
/// variable is unset or empty; `Some(Err(line))` when the file is refused.
/// `writable` is every tree this session can write.
pub fn load_managed(writable: &[PathBuf]) -> Option<Result<ManagedConfig, String>> {
    let value = std::env::var_os(MANAGED_CONFIG_ENV).filter(|v| !v.is_empty())?;
    Some(load_managed_from(&value, writable))
}

/// [`load_managed`] for an explicit value, for tests.
pub fn load_managed_from(value: &OsStr, writable: &[PathBuf]) -> Result<ManagedConfig, String> {
    let path = Path::new(value);
    let refuse = |why: &str| {
        format!(
            "{MANAGED_CONFIG_ENV}={} ignored: {why}. Continuing without the managed config.",
            path.display()
        )
    };
    if !path.is_absolute() {
        return Err(refuse("the path must be absolute"));
    }
    let real = crate::sandbox::resolve_unwritable(path, writable)
        .map_err(|()| refuse("it lies in or passes through a tree this session can write"))?;
    // The name itself must not be a link: whoever can re-point it chooses the file.
    if std::fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_symlink()) {
        return Err(refuse("it is a symlink"));
    }
    let file = match crate::untrusted::open_untrusted(&real) {
        Ok(Some(f)) => f,
        Ok(None) => return Err(refuse("it is not a regular file")),
        Err(e) => return Err(refuse(&format!("cannot open it ({e})"))),
    };
    // fstat the open descriptor so nothing can swap the file between check and read.
    let meta = file
        .metadata()
        .map_err(|e| refuse(&format!("cannot stat it ({e})")))?;
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
    if meta.len() > LIMIT {
        return Err(refuse(&format!("it is larger than {LIMIT} bytes")));
    }
    let mut raw = String::new();
    file.take(LIMIT)
        .read_to_string(&mut raw)
        .map_err(|e| refuse(&format!("cannot read it ({e})")))?;
    let (managed_by, allow_private_domains) = parse(&raw).map_err(|e| refuse(&e))?;
    Ok(ManagedConfig {
        path: path.to_path_buf(),
        managed_by,
        allow_private_domains,
    })
}

/// Parse and check the header and keys. Errors name the offending key.
fn parse(raw: &str) -> Result<(String, Vec<String>), String> {
    let table: toml::Table = toml::from_str(raw)
        .map_err(|e: toml::de::Error| format!("not valid TOML ({})", e.message().trim()))?;
    let managed_by = match table.get("managed_by") {
        Some(toml::Value::String(s)) if !s.trim().is_empty() => s.trim().to_string(),
        Some(_) => return Err("`managed_by` must be a non-empty string".into()),
        None => return Err("the `managed_by` header is missing".into()),
    };
    match table.get("schema") {
        Some(toml::Value::Integer(SCHEMA)) => {}
        Some(v) => return Err(format!("unknown schema {v}, this cplt supports {SCHEMA}")),
        None => return Err("the `schema` header is missing".into()),
    }
    let mut keys = Vec::new();
    flatten("", &table, &mut keys);
    let mut domains = Vec::new();
    for (key, value) in keys {
        if key == "managed_by" || key == "schema" {
            continue;
        }
        if !MANAGED_KEYS.contains(&key.as_str()) {
            return Err(format!("key `{key}` is not allowed in a managed config"));
        }
        let list = value
            .as_array()
            .filter(|a| a.iter().all(toml::Value::is_str))
            .ok_or_else(|| format!("`{key}` must be a list of strings"))?;
        for d in list {
            let d = crate::proxy::normalize_hostname(d.as_str().unwrap_or_default());
            if d.is_empty() {
                return Err(format!("`{key}` has an empty entry"));
            }
            domains.push(d);
        }
    }
    domains.sort_unstable();
    domains.dedup();
    Ok((managed_by, domains))
}

/// Dotted leaf keys of `table`; a nested table recurses, anything else is a leaf.
fn flatten<'a>(prefix: &str, table: &'a toml::Table, out: &mut Vec<(String, &'a toml::Value)>) {
    for (k, v) in table {
        let key = if prefix.is_empty() {
            k.clone()
        } else {
            format!("{prefix}.{k}")
        };
        match v {
            toml::Value::Table(t) => flatten(&key, t, out),
            _ => out.push((key, v)),
        }
    }
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

    fn safe_dir() -> tempfile::TempDir {
        tempfile::tempdir().unwrap()
    }

    #[test]
    fn accepts_a_good_file_and_normalizes() {
        let d = safe_dir();
        let p = write(d.path(), "managed.toml", GOOD);
        let m = load_managed_from(p.as_os_str(), &[]).unwrap();
        assert_eq!(m.managed_by, "nav-pilot");
        assert_eq!(m.allow_private_domains, ["b.nav.no", "intern.nav.no"]);
        assert_eq!(m.tag(), "managed:nav-pilot");
    }

    fn refused(value: &OsStr, writable: &[PathBuf], why: &str) {
        let e = load_managed_from(value, writable).unwrap_err();
        assert!(e.contains(why), "expected {why:?} in {e:?}");
        assert!(!e.contains('\n'), "refusal must be one line: {e:?}");
    }

    #[test]
    fn refuses_relative_path() {
        refused(OsStr::new("managed.toml"), &[], "must be absolute");
    }

    #[test]
    fn refuses_file_inside_a_writable_tree() {
        // Covers workdir, scratch and allow.write alike: each is a root in `writable`.
        let d = safe_dir();
        let p = write(d.path(), "managed.toml", GOOD);
        refused(p.as_os_str(), &[d.path().to_path_buf()], "can write");
    }

    #[test]
    fn refuses_a_file_grant_on_the_managed_file_itself() {
        let d = safe_dir();
        let p = write(d.path(), "managed.toml", GOOD);
        refused(p.as_os_str(), std::slice::from_ref(&p), "can write");
    }

    #[test]
    fn refuses_case_variant_of_a_writable_root() {
        let d = safe_dir();
        let root = d.path().join("Proj");
        std::fs::create_dir(&root).unwrap();
        let p = write(&root, "managed.toml", GOOD);
        let variant = d.path().join("PROJ");
        if !variant.exists() {
            return; // case-sensitive filesystem: no variant to confuse
        }
        refused(p.as_os_str(), &[variant], "can write");
    }

    #[test]
    fn refuses_symlink_hop_into_a_writable_tree() {
        let safe = safe_dir();
        let w = safe_dir();
        write(w.path(), "managed.toml", GOOD);
        let link = safe.path().join("dir");
        std::os::unix::fs::symlink(w.path(), &link).unwrap();
        refused(
            link.join("managed.toml").as_os_str(),
            &[w.path().to_path_buf()],
            "can write",
        );
    }

    #[test]
    fn refuses_a_symlink_as_the_file() {
        let d = safe_dir();
        let real = write(d.path(), "real.toml", GOOD);
        let link = d.path().join("managed.toml");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        refused(link.as_os_str(), &[], "symlink");
    }

    #[test]
    fn refuses_a_fifo() {
        let d = safe_dir();
        let p = d.path().join("managed.toml");
        let c = std::ffi::CString::new(p.as_os_str().as_encoded_bytes()).unwrap();
        // SAFETY: `c` is a valid NUL-terminated path.
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
        refused(p.as_os_str(), &[], "not a regular file");
    }

    #[test]
    fn refuses_a_hard_linked_file() {
        let d = safe_dir();
        let p = write(d.path(), "managed.toml", GOOD);
        std::fs::hard_link(&p, d.path().join("other")).unwrap();
        refused(p.as_os_str(), &[], "hard link");
    }

    #[test]
    fn refuses_a_file_owned_by_someone_else() {
        // A root-owned regular file exists on every Unix; skip when running as root.
        // SAFETY: geteuid has no preconditions.
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        let p = Path::new("/etc/hosts");
        if std::fs::symlink_metadata(p).map_or(true, |m| !m.is_file()) {
            return;
        }
        let e = load_managed_from(p.as_os_str(), &[]).unwrap_err();
        assert!(
            e.contains("not owned") || e.contains("hard link"),
            "unexpected refusal: {e}"
        );
    }

    #[test]
    fn refuses_missing_or_unknown_header() {
        let d = safe_dir();
        for (body, why) in [
            ("schema = 1\n", "`managed_by` header is missing"),
            ("managed_by = \"x\"\n", "`schema` header is missing"),
            ("managed_by = \"x\"\nschema = 2\n", "unknown schema 2"),
            ("managed_by = \"\"\nschema = 1\n", "non-empty string"),
            ("not toml [", "not valid TOML"),
        ] {
            let p = write(d.path(), "m.toml", body);
            refused(p.as_os_str(), &[], why);
        }
    }

    #[test]
    fn refuses_disallowed_keys_by_name() {
        let d = safe_dir();
        for (body, key) in [
            ("[allow]\nwrite = [\"/\"]\n", "allow.write"),
            ("[sandbox]\npreset = \"open\"\n", "sandbox.preset"),
            (
                "[proxy]\nallowed_domains = \"/x\"\n",
                "proxy.allowed_domains",
            ),
        ] {
            let p = write(
                d.path(),
                "m.toml",
                &format!("managed_by = \"x\"\nschema = 1\n{body}"),
            );
            refused(p.as_os_str(), &[], &format!("key `{key}` is not allowed"));
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
