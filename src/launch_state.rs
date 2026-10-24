//! Per-project "did this change since the last launch?" memory.
//!
//! Backs the "Changed" tier of the output policy (CONTRIBUTING.md): a block
//! prints in full once when its content differs from the last launch in this
//! project, then stays quiet. Stored as one hash per (project, topic) in
//! cplt's state directory, which the sandbox denies, so the agent cannot
//! silence a change notice. Any read or write failure counts as changed:
//! showing too much is the safe failure.

use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

fn hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn path(home: &Path, project: &Path, topic: &str) -> PathBuf {
    let project = std::fs::canonicalize(project).unwrap_or_else(|_| project.to_path_buf());
    crate::sandbox::cplt_state_file(home, "launch").join(format!(
        "{}-{topic}",
        &hex(project.to_string_lossy().as_bytes())[..32]
    ))
}

/// Open `file` without following a symlink and without blocking on a FIFO,
/// and refuse anything but a regular file: a planted link or pipe must never
/// be read or written through.
fn open_regular(file: &Path, write: bool) -> Option<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    let f = std::fs::OpenOptions::new()
        .read(!write)
        .write(write)
        .create(write)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(file)
        .ok()?;
    f.metadata().ok()?.is_file().then_some(f)
}

fn read(file: &Path) -> Option<String> {
    let mut s = String::new();
    std::io::Read::read_to_string(&mut open_regular(file, false)?, &mut s).ok()?;
    Some(s)
}

/// True when `content` is what was last recorded for `topic` in this project.
pub fn matches(home: &Path, project: &Path, topic: &str, content: &str) -> bool {
    read(&path(home, project, topic))
        .is_some_and(|old| old.lines().next().map(str::trim) == Some(&hex(content.as_bytes())))
}

/// Record `content` for `topic` in this project.
pub fn record(home: &Path, project: &Path, topic: &str, content: &str) {
    record_fields(home, project, topic, content, &[]);
}

/// Short per-field fingerprints, one `name hash` line each: enough to name
/// what changed, nothing that reveals a value.
fn field_lines(fields: &[(String, String)]) -> String {
    fields
        .iter()
        .map(|(name, value)| format!("\n{name} {}", &hex(value.as_bytes())[..12]))
        .collect()
}

/// [`record`], plus the fingerprints of `fields` for [`changed_fields`].
pub fn record_fields(
    home: &Path,
    project: &Path,
    topic: &str,
    content: &str,
    fields: &[(String, String)],
) {
    let file = path(home, project, topic);
    if let Some(dir) = file.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    if let Some(mut f) = open_regular(&file, true) {
        let body = format!("{}{}", hex(content.as_bytes()), field_lines(fields));
        let _ = f
            .set_len(0)
            .and_then(|()| std::io::Write::write_all(&mut f, body.as_bytes()));
    }
}

/// The names in `fields` that differ from the last [`record_fields`] for
/// `topic`. Empty when nothing was recorded with fields.
pub fn changed_fields(
    home: &Path,
    project: &Path,
    topic: &str,
    fields: &[(String, String)],
) -> Vec<String> {
    let Some(old) = read(&path(home, project, topic)) else {
        return Vec::new();
    };
    let old: Vec<&str> = old.lines().skip(1).collect();
    if old.is_empty() {
        return Vec::new();
    }
    let new = field_lines(fields);
    let new: Vec<&str> = new.lines().skip(1).collect();
    let name = |l: &str| l.split_once(' ').map_or(l, |(n, _)| n).to_string();
    let mut names: Vec<String> = new
        .iter()
        .filter(|l| !old.contains(l))
        .chain(old.iter().filter(|l| !new.contains(l)))
        .map(|l| name(l))
        .collect();
    names.dedup();
    names
}

/// True when `content` differs from what was recorded for `topic` in this
/// project, recording the new value as it goes.
pub fn changed(home: &Path, project: &Path, topic: &str, content: &str) -> bool {
    if matches(home, project, topic, content) {
        return false;
    }
    record(home, project, topic, content);
    true
}

/// The launch profile the confirmation prompt is about (output policy, "Act
/// now"): a TTY launch skips the prompt only when this matches the profile the
/// user last said yes to. [`Confirmation::record`] runs only after a person saw
/// the table on a TTY and said yes, so a declined or scripted launch never counts.
pub struct Confirmation {
    topic: String,
    display_topic: String,
    content: String,
    fields: Vec<(String, String)>,
    /// The same profile was confirmed before (and a TTY is there to ask on).
    pub confirmed: bool,
    /// The full table was printed with a TTY present, so a person saw what
    /// they confirm. Only then may [`Confirmation::record`] run.
    pub shown: bool,
}

impl Confirmation {
    /// `tty` false means no prompt could be shown, so nothing is confirmed.
    pub fn new(home: &Path, project: &Path, agent: &str, content: String, tty: bool) -> Self {
        let topic = format!("confirmed-{agent}");
        let seen = matches(home, project, &topic, &content);
        Self {
            topic,
            display_topic: format!("summary-{agent}"),
            content,
            fields: Vec::new(),
            confirmed: tty && seen,
            shown: false,
        }
    }

    /// Per-field fingerprints stored with the hash, for "Changed since last
    /// launch".
    #[must_use]
    pub fn with_fields(mut self, fields: Vec<(String, String)>) -> Self {
        self.fields = fields;
        self
    }

    /// The table differs from the last accepted TTY launch.
    pub fn display_changed(&self, home: &Path, project: &Path) -> bool {
        !matches(home, project, &self.display_topic, &self.content)
    }

    /// Field names that changed since the last accepted launch.
    pub fn changed_fields(&self, home: &Path, project: &Path) -> Vec<String> {
        changed_fields(home, project, &self.display_topic, &self.fields)
    }

    pub fn record(&self, home: &Path, project: &Path) {
        record_fields(home, project, &self.topic, &self.content, &self.fields);
    }

    /// The launch went ahead (TTY or headless `--yes`): remember what was
    /// shown, so it is not shown in full again. Display only; a declined
    /// launch never gets here, so the old record stays.
    pub fn record_display(&self, home: &Path, project: &Path) {
        record_fields(
            home,
            project,
            &self.display_topic,
            &self.content,
            &self.fields,
        );
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn changed_once_then_quiet_per_project_and_topic() {
        crate::with_env_lock_no_xdg(inner);
    }

    fn inner() {
        let home = tempfile::tempdir().unwrap();
        let (a, b) = (home.path().join("a"), home.path().join("b"));
        assert!(super::changed(home.path(), &a, "t", "x"));
        assert!(!super::changed(home.path(), &a, "t", "x"));
        assert!(super::changed(home.path(), &b, "t", "x"));
        assert!(super::changed(home.path(), &a, "u", "x"));
        assert!(super::changed(home.path(), &a, "t", "y"));
        assert!(!super::changed(home.path(), &a, "t", "y"));
    }

    #[test]
    fn confirmed_only_after_record_and_with_a_tty() {
        crate::with_env_lock_no_xdg(confirm_inner);
    }

    fn confirm_inner() {
        use super::Confirmation;
        let home = tempfile::tempdir().unwrap();
        let p = home.path().join("p");
        let c = |content: &str, tty| Confirmation::new(home.path(), &p, "A", content.into(), tty);
        // First launch, and a declined one (never recorded): prompt again.
        assert!(!c("x", true).confirmed);
        assert!(!c("x", true).confirmed);
        c("x", true).record(home.path(), &p);
        assert!(c("x", true).confirmed);
        // No TTY: never treated as confirmed, so --yes stays required.
        assert!(!c("x", false).confirmed);
        // A changed profile prompts; another agent has its own record.
        assert!(!c("y", true).confirmed);
        assert!(!Confirmation::new(home.path(), &p, "B", "x".into(), true).confirmed);
        // The display topic does not count as a confirmation.
        assert!(super::changed(home.path(), &p, "summary-A", "z"));
        assert!(!c("z", true).confirmed);
    }

    #[test]
    fn display_records_only_accepted_tty_launches_and_names_changes() {
        crate::with_env_lock_no_xdg(display_inner);
    }

    fn display_inner() {
        use super::Confirmation;
        let home = tempfile::tempdir().unwrap();
        let (h, p) = (home.path(), home.path().join("p"));
        let f = |a: &str, b: &str| vec![("a".to_string(), a.to_string()), ("b".into(), b.into())];
        let c = |content: &str, fields, tty| {
            Confirmation::new(h, &p, "A", content.into(), tty).with_fields(fields)
        };
        // Accepted on a TTY: recorded, so the next launch is quiet.
        c("x", f("1", "2"), true).record_display(h, &p);
        assert!(!c("x", f("1", "2"), true).display_changed(h, &p));
        // A changed profile names the field; declining it records nothing,
        // so the old profile stays quiet afterwards.
        let changed = c("y", f("1", "3"), true);
        assert!(changed.display_changed(h, &p));
        assert_eq!(changed.changed_fields(h, &p), ["b"]);
        assert!(!c("x", f("1", "2"), true).display_changed(h, &p));
        // An accepted headless launch updates the display, never the confirmation.
        c("y", f("1", "3"), false).record_display(h, &p);
        assert!(!c("y", f("1", "3"), true).display_changed(h, &p));
        assert!(!c("y", f("1", "3"), true).confirmed);
    }

    #[test]
    fn planted_fifo_or_symlink_is_never_read_or_written() {
        crate::with_env_lock_no_xdg(planted_inner);
    }

    fn planted_inner() {
        let home = tempfile::tempdir().unwrap();
        let (h, p) = (home.path(), home.path().join("p"));
        let sentinel = h.join("sentinel");
        std::fs::write(&sentinel, "keep").unwrap();
        let file = super::path(h, &p, "t");
        std::fs::create_dir_all(file.parent().unwrap()).unwrap();
        std::os::unix::fs::symlink(&sentinel, &file).unwrap();
        assert!(super::changed(h, &p, "t", "x"));
        assert_eq!(std::fs::read_to_string(&sentinel).unwrap(), "keep");
        std::fs::remove_file(&file).unwrap();
        let c = std::ffi::CString::new(file.to_str().unwrap()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
        // Would block forever on a plain open.
        assert!(super::changed(h, &p, "t", "x"));
        assert!(!super::matches(h, &p, "t", "x"));
    }
}
