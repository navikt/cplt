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

/// True when `content` is what was last recorded for `topic` in this project.
pub fn matches(home: &Path, project: &Path, topic: &str, content: &str) -> bool {
    std::fs::read_to_string(path(home, project, topic))
        .is_ok_and(|old| old.trim() == hex(content.as_bytes()))
}

/// Record `content` for `topic` in this project.
pub fn record(home: &Path, project: &Path, topic: &str, content: &str) {
    let file = path(home, project, topic);
    if let Some(dir) = file.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    let _ = std::fs::write(&file, hex(content.as_bytes()));
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
    content: String,
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
        let confirmed = tty && matches(home, project, &topic, &content);
        Self {
            topic,
            content,
            confirmed,
            shown: false,
        }
    }

    pub fn record(&self, home: &Path, project: &Path) {
        record(home, project, &self.topic, &self.content);
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
}
