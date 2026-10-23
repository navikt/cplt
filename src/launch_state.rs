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
    crate::sandbox::cplt_state_dir_for(&crate::sandbox::process_env, home, "launch")
        .join("launch")
        .join(format!(
            "{}-{topic}",
            &hex(project.to_string_lossy().as_bytes())[..32]
        ))
}

/// True when `content` differs from what was recorded for `topic` in this
/// project, recording the new value as it goes.
pub fn changed(home: &Path, project: &Path, topic: &str, content: &str) -> bool {
    let file = path(home, project, topic);
    let now = hex(content.as_bytes());
    if std::fs::read_to_string(&file).is_ok_and(|old| old.trim() == now) {
        return false;
    }
    if let Some(dir) = file.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    let _ = std::fs::write(&file, now);
    true
}

#[cfg(test)]
mod tests {
    #[test]
    fn changed_once_then_quiet_per_project_and_topic() {
        // Unset so the state lands in the temp home, not the real XDG dir.
        temp_env::with_var_unset("XDG_CONFIG_HOME", || {
            let home = tempfile::tempdir().unwrap();
            let (a, b) = (home.path().join("a"), home.path().join("b"));
            assert!(super::changed(home.path(), &a, "t", "x"));
            assert!(!super::changed(home.path(), &a, "t", "x"));
            assert!(super::changed(home.path(), &b, "t", "x"));
            assert!(super::changed(home.path(), &a, "u", "x"));
            assert!(super::changed(home.path(), &a, "t", "y"));
            assert!(!super::changed(home.path(), &a, "t", "y"));
        });
    }
}
