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
//! cplt cannot reach into plugin-managed forks, so instead it can install a
//! Gradle init script in the Gradle user home (`$GRADLE_USER_HOME/init.d/` or
//! `~/.gradle/init.d/cplt-sandbox.gradle`) — **opt-in**
//! via `sandbox.gradle_init = true` (cplt does not write tool config dirs by
//! default). The script is guarded by `__CPLT_WRAPPED` — it only activates
//! inside the sandbox and is inert in normal builds.
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
/// Respects `GRADLE_USER_HOME` (allowlisted env var) — otherwise a user with a
/// relocated Gradle home would never load the script.
pub fn script_path(home: &Path) -> PathBuf {
    gradle_user_home(home).join("init.d").join(SCRIPT_NAME)
}

/// Resolve the effective Gradle user home: `GRADLE_USER_HOME` if set and
/// non-empty, else `~/.gradle`.
fn gradle_user_home(home: &Path) -> PathBuf {
    std::env::var("GRADLE_USER_HOME")
        .ok()
        .filter(|s| !s.is_empty())
        .map_or_else(|| home.join(".gradle"), PathBuf::from)
}

/// Install (or refresh) the init script. Idempotent: rewrites only when the
/// content differs. Creates `~/.gradle/init.d/` if `~/.gradle` exists.
/// No-op when the user has no `~/.gradle` (not a Gradle user).
///
/// Writes are atomic (temp + rename): a crash mid-write must never leave a
/// truncated script — Gradle evaluates every file in init.d, and a partial
/// Groovy file would fail every build with a syntax error.
pub fn ensure_init_script(home: &Path) -> std::io::Result<Option<PathBuf>> {
    let gradle_dir = gradle_user_home(home);
    if !gradle_dir.is_dir() {
        return Ok(None);
    }
    let init_d = gradle_dir.join("init.d");
    std::fs::create_dir_all(&init_d)?;
    let path = init_d.join(SCRIPT_NAME);
    match std::fs::read_to_string(&path) {
        Ok(existing) if existing == SCRIPT_BODY => Ok(Some(path)),
        _ => {
            // Unique temp name avoids concurrent cplt processes clobbering
            // each other's temp file; the .tmp extension means Gradle never
            // evaluates a leftover temp after a crash.
            let tmp = init_d.join(format!(".{SCRIPT_NAME}.{}.tmp", std::process::id()));
            std::fs::write(&tmp, SCRIPT_BODY)?;
            std::fs::rename(&tmp, &path)?;
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
    fn script_path_respects_gradle_user_home() {
        // temp_env is used elsewhere in the repo for env-dependent tests
        temp_env::with_var("GRADLE_USER_HOME", Some("/custom/gradle-home"), || {
            let p = script_path(Path::new("/home/user"));
            assert_eq!(
                p,
                Path::new("/custom/gradle-home/init.d/cplt-sandbox.gradle")
            );
        });
        temp_env::with_var("GRADLE_USER_HOME", None::<&str>, || {
            let p = script_path(Path::new("/home/user"));
            assert_eq!(
                p,
                Path::new("/home/user/.gradle/init.d/cplt-sandbox.gradle")
            );
        });
    }

    #[test]
    fn ensure_init_script_noop_without_gradle_dir() {
        // Isolate from GRADLE_USER_HOME in the ambient env (set on CI
        // runners), which would otherwise redirect the install away from
        // the tempdir.
        temp_env::with_var("GRADLE_USER_HOME", None::<&str>, || {
            let tmp = tempfile::tempdir().unwrap();
            let result = ensure_init_script(tmp.path()).unwrap();
            assert!(result.is_none(), "no ~/.gradle → no script written");
        });
    }

    #[test]
    fn ensure_init_script_writes_and_is_idempotent() {
        temp_env::with_var("GRADLE_USER_HOME", None::<&str>, || {
            let tmp = tempfile::tempdir().unwrap();
            let gradle = tmp.path().join(".gradle");
            std::fs::create_dir_all(&gradle).unwrap();

            let first = ensure_init_script(tmp.path())
                .unwrap()
                .expect("script written");
            assert!(first.exists());
            let content = std::fs::read_to_string(&first).unwrap();
            assert_eq!(content, SCRIPT_BODY);
            // No temp files left behind after the atomic write.
            let leftovers: Vec<_> = std::fs::read_dir(gradle.join("init.d"))
                .unwrap()
                .flatten()
                .filter(|e| e.file_name().to_string_lossy().ends_with(".tmp"))
                .collect();
            assert!(leftovers.is_empty(), "no .tmp leftovers after install");

            // Second call: no rewrite (mtime unchanged)
            let mtime1 = first.metadata().unwrap().modified().unwrap();
            let second = ensure_init_script(tmp.path())
                .unwrap()
                .expect("script present");
            let mtime2 = second.metadata().unwrap().modified().unwrap();
            assert_eq!(
                mtime1, mtime2,
                "idempotent: no rewrite when content matches"
            );

            // Stale content gets refreshed
            std::fs::write(&first, "// old version").unwrap();
            ensure_init_script(tmp.path()).unwrap();
            assert_eq!(std::fs::read_to_string(&first).unwrap(), SCRIPT_BODY);
        });
    }
}
