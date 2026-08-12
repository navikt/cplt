//! Managed Gradle init script for sandboxed builds.
//!
//! cplt injects `-Djava.net.preferIPv4Stack=true` via `JAVA_TOOL_OPTIONS` so
//! JVM localhost connections match the sandbox's `localhost:*` rules (SBPL
//! cannot match IPv4-mapped `::ffff:127.0.0.1` addresses). But Gradle plugin
//! workers (WorkerExecutor process isolation, e.g. ktlint-gradle) fork JVMs
//! with explicit `forkOptions {}` and do not reliably propagate the
//! environment — the flag is lost and their daemon connections on ephemeral
//! localhost ports fail with `ConnectException`.
//!
//! cplt cannot reach into plugin-managed forks, so instead it installs a
//! Gradle init script at `~/.gradle/init.d/cplt-sandbox.gradle`. The script
//! is guarded by `__CPLT_WRAPPED` — it only activates inside the sandbox and
//! is inert in normal builds.
//!
//! Scope: the script covers the daemon itself plus `Test`/`JavaExec` forks.
//! `WorkerExecutor` process-isolation forks have no public configuration
//! hook — those still require the plugin to propagate the environment (see
//! JLLeitschuh/ktlint-gradle#1110).

use std::path::{Path, PathBuf};

/// Init script file name inside `~/.gradle/init.d/`.
const SCRIPT_NAME: &str = "cplt-sandbox.gradle";

/// Script content. Guarded by `__CPLT_WRAPPED` so it is inert outside the
/// sandbox. Groovy DSL for compatibility with older Gradle versions.
const SCRIPT_BODY: &str = "\
// Managed by cplt — do not edit. Re-generated on sandbox launch.
// Applies sandbox networking workarounds to Gradle builds running INSIDE
// cplt; inert outside (guarded by __CPLT_WRAPPED).
//
// Why: Gradle plugin workers (WorkerExecutor process isolation, e.g.
// ktlint-gradle) do not reliably propagate JAVA_TOOL_OPTIONS into forked
// JVMs, so cplt's -Djava.net.preferIPv4Stack=true is lost and their
// dual-stack sockets produce IPv4-mapped addresses (::ffff:127.0.0.1)
// that the macOS sandbox cannot match — daemon connections on ephemeral
// localhost ports then fail with ConnectException.
if (System.getenv(\"__CPLT_WRAPPED\") != null) {
    // Daemon-side: keep daemon sockets on pure IPv4.
    System.setProperty(\"java.net.preferIPv4Stack\", \"true\")

    allprojects {
        tasks.withType(JavaExec).configureEach {
            jvmArgs \"-Djava.net.preferIPv4Stack=true\"
        }
        tasks.withType(Test).configureEach {
            jvmArgs \"-Djava.net.preferIPv4Stack=true\"
        }
    }
}
";

/// Path to the managed init script for a given home directory.
pub fn script_path(home: &Path) -> PathBuf {
    home.join(".gradle/init.d").join(SCRIPT_NAME)
}

/// Install (or refresh) the init script. Idempotent: rewrites only when the
/// content differs. Creates `~/.gradle/init.d/` if `~/.gradle` exists.
/// No-op when the user has no `~/.gradle` (not a Gradle user).
pub fn ensure_init_script(home: &Path) -> std::io::Result<Option<PathBuf>> {
    let gradle_dir = home.join(".gradle");
    if !gradle_dir.is_dir() {
        return Ok(None);
    }
    let init_d = gradle_dir.join("init.d");
    std::fs::create_dir_all(&init_d)?;
    let path = init_d.join(SCRIPT_NAME);
    match std::fs::read_to_string(&path) {
        Ok(existing) if existing == SCRIPT_BODY => Ok(Some(path)),
        _ => {
            std::fs::write(&path, SCRIPT_BODY)?;
            Ok(Some(path))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn script_is_guarded_by_cplt_env_marker() {
        assert!(SCRIPT_BODY.contains("__CPLT_WRAPPED"));
        assert!(SCRIPT_BODY.contains("preferIPv4Stack"));
    }

    #[test]
    fn ensure_init_script_noop_without_gradle_dir() {
        let tmp = std::env::temp_dir().join(format!("cplt-gradle-noop-{}", std::process::id()));
        std::fs::create_dir_all(&tmp).unwrap();
        let result = ensure_init_script(&tmp).unwrap();
        assert!(result.is_none(), "no ~/.gradle → no script written");
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn ensure_init_script_writes_and_is_idempotent() {
        let tmp = std::env::temp_dir().join(format!("cplt-gradle-init-{}", std::process::id()));
        let gradle = tmp.join(".gradle");
        std::fs::create_dir_all(&gradle).unwrap();

        let first = ensure_init_script(&tmp).unwrap().expect("script written");
        assert!(first.exists());
        let content = std::fs::read_to_string(&first).unwrap();
        assert_eq!(content, SCRIPT_BODY);

        // Second call: no rewrite (mtime unchanged)
        let mtime1 = first.metadata().unwrap().modified().unwrap();
        let second = ensure_init_script(&tmp).unwrap().expect("script present");
        let mtime2 = second.metadata().unwrap().modified().unwrap();
        assert_eq!(
            mtime1, mtime2,
            "idempotent: no rewrite when content matches"
        );

        // Stale content gets refreshed
        std::fs::write(&first, "// old version").unwrap();
        ensure_init_script(&tmp).unwrap();
        assert_eq!(std::fs::read_to_string(&first).unwrap(), SCRIPT_BODY);

        let _ = std::fs::remove_dir_all(&tmp);
    }
}
