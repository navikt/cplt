//! Copilot SEA runtime extraction preflight.
//!
//! Copilot CLI ships as a single-executable application that unpacks its runtime
//! into the platform cache on first run. The sandbox denies writes to that cache,
//! so `cplt` has to force the extraction before entering it (#166).

use cplt::ui;
use std::path::Path;
use std::path::PathBuf;

/// Copilot's SEA extraction directory for this platform, plus cplt's own cache
/// directory (which holds the `copilot-extracted` fast-path marker).
#[cfg(target_os = "macos")]
fn copilot_cache_dirs(home: &Path, arch: &str) -> (PathBuf, PathBuf) {
    (
        home.join("Library/Caches/copilot/pkg")
            .join(format!("darwin-{arch}")),
        home.join("Library/Caches/cplt"),
    )
}

/// Copilot's SEA extraction directory for this platform, plus cplt's own cache
/// directory (which holds the `copilot-extracted` fast-path marker).
#[cfg(target_os = "linux")]
fn copilot_cache_dirs(home: &Path, arch: &str) -> (PathBuf, PathBuf) {
    (
        home.join(".cache/copilot/pkg")
            .join(format!("linux-{arch}")),
        home.join(".cache/cplt"),
    )
}

/// Ensure Copilot's bundled package is extracted before entering the sandbox.
///
/// Copilot CLI (SEA binary) extracts its runtime into a per-version directory
/// under the platform cache — `~/Library/Caches/copilot/pkg/darwin-<arch>/` on
/// macOS, `~/.cache/copilot/pkg/linux-<arch>/` on Linux. Writes to that
/// directory are denied inside the sandbox to prevent write-then-exec attacks,
/// so the extraction must happen outside.
///
/// The fast-path cache key is the binary's identity (path + inode + size +
/// mtime). When that misses, we run `copilot --version` to trigger extraction
/// and detect the newly created directory by its `.extraction-complete` marker.
/// If no new directory appears, we accept a pre-existing extraction only when it
/// matches the version copilot reports (exact or `"{version}-"` prefix, since
/// pre-release builds may report `1.0.32` while extracting to `1.0.32-1-73748`).
/// A stale OLD-version directory is never accepted — otherwise the sandboxed
/// session would re-extract the current version and hit EPERM on the write-
/// denied cache.
///
/// When that leaves nothing usable, the leftover directories are removed and
/// extraction is retried once (see `purge_stale_extractions`). Without that
/// retry the failure is permanent: a partial directory makes Copilot skip
/// extraction, and a leftover directory of any kind — including one for a
/// version that now extracts somewhere else entirely — keeps the "this binary
/// does not SEA-extract here" escape hatch below from ever firing (#166).
///
/// Returns Ok(()) if extraction is confirmed or not needed, Err(message) if it
/// failed and entering the sandbox would cause EPERM on copilot/pkg writes.
#[cfg(any(target_os = "macos", target_os = "linux"))]
pub fn ensure_copilot_extracted(
    copilot_bin: &Path,
    home: &Path,
    project_dir: &Path,
) -> Result<(), String> {
    // Security guard: this preflight executes `copilot --version` outside the
    // sandbox. If PATH resolves to a project-local wrapper script, that script
    // would run unsandboxed with full user privileges before trust lock applies.
    let bin = copilot_bin
        .canonicalize()
        .map_err(|e| format!("Failed to resolve copilot binary path: {e}"))?;
    let project = project_dir
        .canonicalize()
        .map_err(|e| format!("Failed to resolve project directory path: {e}"))?;
    if bin.starts_with(&project) {
        return Ok(());
    }

    let arch = match std::env::consts::ARCH {
        "aarch64" => "arm64",
        "x86_64" => "x64",
        _ => return Ok(()),
    };

    let (pkg_base, cache_dir) = copilot_cache_dirs(home, arch);

    // Compute binary identity for the fast-path cache.
    // Works for any file type: Mach-O binary (Homebrew), node/shell wrapper (npm).
    // The identity is based on canonicalized path + inode + size + mtime — changes
    // whenever the copilot binary is updated/reinstalled.
    let binary_id = binary_identity(copilot_bin);

    // Fast path: check cplt-managed marker that records both the binary
    // identity and the actual extraction directory from the last successful run.
    let cache_file = cache_dir.join("copilot-extracted");
    if let Some(ref bid) = binary_id
        && let Ok(cached) = std::fs::read_to_string(&cache_file)
    {
        let mut lines = cached.lines();
        if let (Some(cached_id), Some(cached_dir)) = (lines.next(), lines.next())
            && cached_id == bid.as_str()
        {
            // Binary unchanged — verify the extracted dir still exists on disk
            let extracted_marker = pkg_base.join(cached_dir).join(".extraction-complete");
            if extracted_marker.exists() {
                return Ok(());
            }
        }
    }

    ui::info("Extracting Copilot runtime (first run after update)...");

    // Ensure pkg_base exists — Copilot extracts into it, and both preflight
    // spawns use it as their working directory. A failure here has to be
    // reported: `current_dir` on a missing directory makes `spawn` fail, and
    // the spawn-failure message tells the user to run `copilot --version`
    // themselves, which would work and leave them chasing the wrong thing.
    std::fs::create_dir_all(&pkg_base).map_err(|e| {
        format!(
            "Failed to create the Copilot extraction directory {}: {e}",
            pkg_base.display(),
        )
    })?;

    // Clean up stale .extracting-* temp dirs from previous failed attempts.
    // These can confuse the SEA loader into thinking extraction is in progress.
    clean_stale_extracting_dirs(&pkg_base);

    // Two passes at most: the second runs only after clearing leftover
    // directories, and only if there was something to clear.
    let mut reported_version: Option<String> = None;
    for pass in 0..2 {
        // Snapshot existing extraction dirs so we can detect the new one.
        let dirs_before = extraction_dirs(&pkg_base);
        let attempt = run_extraction_attempt(copilot_bin, &pkg_base, &project, &dirs_before)
            .map_err(|e| {
                format!(
                    "Failed to spawn copilot for extraction: {e}\n  \
                     Try running '{} --version' manually to trigger extraction",
                    copilot_bin.display(),
                )
            })?;
        let outcome = resolve_extraction(copilot_bin, &pkg_base, &project, &dirs_before, &attempt);
        if attempt.version.is_some() {
            reported_version = attempt.version;
        }

        match outcome {
            ExtractionOutcome::Extracted(dir_name) => {
                // Persist success: binary identity + extracted dir name.
                if let Some(ref bid) = binary_id {
                    let _ = std::fs::create_dir_all(&cache_dir);
                    let _ = std::fs::write(&cache_file, format!("{bid}\n{dir_name}"));
                }
                if !dirs_before.contains(&dir_name) {
                    ui::ok("Copilot runtime extracted");
                }
                return Ok(());
            }
            ExtractionOutcome::NotNeeded => return Ok(()),
            ExtractionOutcome::Unresolved => {}
        }

        // Self-heal, once. Only reached when every other path is exhausted, so
        // a working setup never gets here.
        if pass == 0 {
            let removed = purge_stale_extractions(&pkg_base);
            if removed.is_empty() {
                break;
            }
            ui::warn(&format!(
                "Removing unusable Copilot runtime {} ({}) and re-extracting",
                if removed.len() == 1 {
                    "directory"
                } else {
                    "directories"
                },
                removed.join(", "),
            ));
        }
    }

    Err(extraction_failure_message(
        copilot_bin,
        &pkg_base,
        reported_version.as_deref(),
    ))
}

/// What one `copilot --version` run told us about extraction.
#[cfg(any(target_os = "macos", target_os = "linux"))]
struct ExtractionAttempt {
    /// A directory that appeared during this run carrying `.extraction-complete`.
    dir: Option<String>,
    /// The version copilot printed, if it could be parsed.
    version: Option<String>,
    /// Whether the copilot process exited successfully.
    exit_ok: bool,
}

/// Environment variables the extraction preflight passes through to `copilot`.
///
/// Two things decide what belongs here.
///
/// The first is whether copilot can run at all: `HOME` for the SEA loader's
/// platform default, `PATH` so a wrapper script finds its `node`, `TMPDIR` so
/// Node's scratch space lands where the user's other tools put theirs.
///
/// The second is the rule that actually matters: **the preflight must resolve
/// the same extraction directory the sandboxed session will.** The SEA loader
/// picks its target as `$COPILOT_PKG_CACHE_HOME/pkg`, else
/// `$COPILOT_CACHE_HOME/pkg`, else the platform default — which on Linux is
/// `$XDG_CACHE_HOME/copilot`, falling back to `~/.cache/copilot` only when
/// `XDG_CACHE_HOME` is unset. It searches that same set plus `$COPILOT_HOME/pkg`
/// for an existing extraction. The sandbox passes every one of these to the
/// session (`XDG_CACHE_HOME` in `ENV_ALLOWLIST`, the rest via the `COPILOT_`
/// entry in `ENV_PREFIX_ALLOWLIST`), so withholding any of them here would have
/// the preflight extract to one directory and report success while the session
/// extracts to another — into a write-denied cache, which is the EPERM that
/// #166 exists to prevent. They are path overrides, not secrets.
///
/// Everything else stays out: tokens (`GH_TOKEN`, `COPILOT_GITHUB_TOKEN`),
/// cloud credentials and `NODE_OPTIONS` have no business in an agent process
/// running outside the sandbox.
///
/// Note that cplt's own `copilot_cache_dirs` does not yet honour this
/// precedence — it hardcodes `~/.cache`. Passing the variables through keeps
/// copilot self-consistent; making cplt agree with copilot is #374.
#[cfg(any(target_os = "macos", target_os = "linux"))]
const EXTRACTION_ENV_ALLOWLIST: &[&str] = &[
    "HOME",
    "PATH",
    "TMPDIR",
    // Extraction-target overrides, in the loader's own precedence order.
    "COPILOT_PKG_CACHE_HOME",
    "COPILOT_CACHE_HOME",
    "COPILOT_HOME",
    "XDG_CACHE_HOME",
];

/// Build a `copilot` command for the extraction preflight.
///
/// Both preflight spawns run OUTSIDE the sandbox, as the user, before
/// `sandbox::preflight` and before the launch confirmation. The `-p exit`
/// fallback is not a probe but a full agent session: it loads user config, MCP
/// servers, and any instruction file it finds under its working directory. An
/// inherited cwd is the untrusted project, and an inherited environment carries
/// every credential the sandbox exists to strip — so the command gets a cleared
/// environment rebuilt from `EXTRACTION_ENV_ALLOWLIST` and a cwd inside the
/// Copilot cache, which holds nothing but extracted runtimes.
///
/// The binary itself is already guarded: `ensure_copilot_extracted` refuses to
/// run a `copilot` that lives under the project directory.
/// `PATH` with everything the untrusted project could have put there removed.
///
/// SECURITY: an npm-installed `copilot` is a `#!/usr/bin/env node` wrapper, so
/// `PATH` decides which `node` actually executes — outside the sandbox, as the
/// user. direnv, asdf and mise routinely prepend repo-local tool directories,
/// and a `.envrc` is the project's to write, so passing `PATH` through verbatim
/// would hand the project back the influence that clearing the environment and
/// the working directory just took away. The binary guard above only checks
/// where `copilot` itself lives, not what it goes on to run.
///
/// Dropped: entries under the project, relative entries (a bare `.`, or
/// anything not absolute — both resolve against the cwd), and empty segments,
/// which POSIX reads as the current directory.
#[cfg(any(target_os = "macos", target_os = "linux"))]
fn sanitized_path(project: &Path) -> Option<std::ffi::OsString> {
    sanitize_path_value(&std::env::var_os("PATH")?, project)
}

/// The filtering half of [`sanitized_path`], split out so it can be tested
/// without mutating the process environment — `set_var` is global, and these
/// tests share a binary with others that need a real `PATH`.
#[cfg(any(target_os = "macos", target_os = "linux"))]
fn sanitize_path_value(raw: &std::ffi::OsStr, project: &Path) -> Option<std::ffi::OsString> {
    let kept: Vec<PathBuf> = std::env::split_paths(raw)
        .filter(|entry| {
            if entry.as_os_str().is_empty() || !entry.is_absolute() {
                return false;
            }
            // Compare canonically where possible: a symlink into the project is
            // still the project. An entry that cannot be resolved does not exist,
            // so it cannot supply a binary either way; keep it rather than let a
            // stat failure silently shorten PATH.
            match entry.canonicalize() {
                Ok(resolved) => !resolved.starts_with(project),
                Err(_) => true,
            }
        })
        .collect();
    std::env::join_paths(kept).ok()
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
#[allow(clippy::disallowed_methods)] // resolved agent binary path, and the only extraction spawn that sets cwd + env
fn extraction_command(
    copilot_bin: &Path,
    args: &[&str],
    pkg_base: &Path,
    project: &Path,
) -> std::process::Command {
    let mut cmd = std::process::Command::new(copilot_bin);
    cmd.args(args).env_clear().current_dir(pkg_base);
    for var in EXTRACTION_ENV_ALLOWLIST {
        if *var == "PATH" {
            if let Some(path) = sanitized_path(project) {
                cmd.env("PATH", path);
            }
            continue;
        }
        if let Some(value) = std::env::var_os(var) {
            cmd.env(var, value);
        }
    }
    cmd
}

/// Run `copilot --version` outside the sandbox and wait for SEA extraction.
///
/// The extraction happens during Node.js startup, before any CLI logic, so
/// `--version` triggers it and exits cleanly (more reliable than `-p ""`, which
/// may hang waiting for input in newer versions). stdout is piped so we can read
/// the reported version, used by the caller to verify the CURRENT version — not
/// a stale one — is what ended up on disk.
///
/// A spawn failure is returned as `Err`, never folded into a failed attempt: if
/// copilot never ran, the reported version is unknowable, and the caller's
/// version-less fallback would accept any stale directory as proof — then cache
/// that false positive against the binary's identity.
#[cfg(any(target_os = "macos", target_os = "linux"))]
fn run_extraction_attempt(
    copilot_bin: &Path,
    pkg_base: &Path,
    project: &Path,
    dirs_before: &std::collections::HashSet<String>,
) -> Result<ExtractionAttempt, std::io::Error> {
    let mut child = extraction_command(
        copilot_bin,
        &["--no-auto-update", "--version"],
        pkg_base,
        project,
    )
    .stdin(std::process::Stdio::null())
    .stdout(std::process::Stdio::piped())
    .stderr(std::process::Stdio::null())
    .spawn()?;
    let mut child_stdout = child.stdout.take();

    // Poll for extraction completion. We check for both:
    // 1. A new directory with `.extraction-complete` marker (normal success)
    // 2. An in-progress `.extracting-*` temp dir (extraction is happening)
    // Timeout: 60s (larger SEA payloads in newer versions need more time)
    let mut extracted_dir_name: Option<String> = None;
    let mut saw_extracting = false;
    let mut child_exit_ok = false;
    for i in 0..120 {
        if let Some(name) = find_new_extracted_dir(pkg_base, dirs_before) {
            extracted_dir_name = Some(name);
            break;
        }
        // Detect in-progress `.extracting-*` temp dirs — proves extraction started
        if !saw_extracting && has_extracting_dir(pkg_base) {
            saw_extracting = true;
        }
        if let Ok(Some(status)) = child.try_wait() {
            child_exit_ok = status.success();
            // Process exited — check one more time
            extracted_dir_name = find_new_extracted_dir(pkg_base, dirs_before);
            if extracted_dir_name.is_some() {
                break;
            }
            // If extraction started (saw temp dir) but process exited without
            // completion, wait a bit more — rename may be in flight
            if saw_extracting && i < 119 {
                std::thread::sleep(std::time::Duration::from_millis(500));
                extracted_dir_name = find_new_extracted_dir(pkg_base, dirs_before);
            }
            if extracted_dir_name.is_none() && !status.success() {
                // Process failed — try fallback with `-p exit`
                extracted_dir_name =
                    try_extraction_fallback(copilot_bin, pkg_base, project, dirs_before);
            }
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(500));
    }

    // If extraction is still in flight when the poll loop ends, give it time to
    // finish instead of killing it. Interrupting a legitimate extraction leaves
    // a partial (marker-less) dir, which forces the sandboxed session to
    // re-extract — and that write is denied inside the sandbox (EPERM).
    if extracted_dir_name.is_none() && has_extracting_dir(pkg_base) {
        for _ in 0..240 {
            if let Some(name) = find_new_extracted_dir(pkg_base, dirs_before) {
                extracted_dir_name = Some(name);
                break;
            }
            if !has_extracting_dir(pkg_base) {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(500));
        }
    }

    let _ = child.kill();
    let _ = child.wait();

    // Read the version copilot reported (printed during the same startup that
    // performs extraction).
    let version = child_stdout.take().and_then(|mut out| {
        use std::io::Read;
        let mut s = String::new();
        out.read_to_string(&mut s).ok()?;
        parse_copilot_version(&s)
    });

    // Final check after process exit
    if extracted_dir_name.is_none() {
        extracted_dir_name = find_new_extracted_dir(pkg_base, dirs_before);
    }

    Ok(ExtractionAttempt {
        dir: extracted_dir_name,
        version,
        exit_ok: child_exit_ok,
    })
}

/// The verdict on one extraction attempt.
#[cfg(any(target_os = "macos", target_os = "linux"))]
enum ExtractionOutcome {
    /// This directory under `pkg_base` holds the current runtime.
    Extracted(String),
    /// This copilot does not SEA-extract here; there is nothing to do.
    NotNeeded,
    /// Neither could be established.
    Unresolved,
}

/// Decide whether an attempt proved the current runtime is extracted.
#[cfg(any(target_os = "macos", target_os = "linux"))]
fn resolve_extraction(
    copilot_bin: &Path,
    pkg_base: &Path,
    project: &Path,
    dirs_before: &std::collections::HashSet<String>,
    attempt: &ExtractionAttempt,
) -> ExtractionOutcome {
    if let Some(ref name) = attempt.dir {
        return ExtractionOutcome::Extracted(name.clone());
    }

    // If --version didn't produce a new dir, check whether the CURRENT version
    // is already extracted on disk. This handles the migration case (first cplt
    // run on a system with a pre-existing extraction). When the version is
    // known we MUST match it — a stale old-version dir is not proof that the
    // current version is extracted (otherwise the sandboxed session re-extracts
    // and hits EPERM). Fall back to any-complete only when version is unknown.
    if let Some(name) = complete_dir_for(pkg_base, attempt.version.as_deref()) {
        return ExtractionOutcome::Extracted(name);
    }

    // If no extraction dir exists anywhere, this copilot doesn't use SEA
    // extraction here (dev builds, non-SEA wrappers, test fakes, or a version
    // that extracts under a different cache subdirectory).
    // Only skip if copilot exited cleanly — a crash isn't proof of "no SEA".
    if attempt.exit_ok && extraction_dirs(pkg_base).is_empty() {
        return ExtractionOutcome::NotNeeded;
    }

    // Last resort: if no complete dir exists, try `-p exit` which forces full
    // startup (and thus extraction) in case --version uses a lazy code path.
    if let Some(name) = try_extraction_fallback(copilot_bin, pkg_base, project, dirs_before) {
        return ExtractionOutcome::Extracted(name);
    }
    match complete_dir_for(pkg_base, attempt.version.as_deref()) {
        Some(name) => ExtractionOutcome::Extracted(name),
        None => ExtractionOutcome::Unresolved,
    }
}

/// A complete extraction dir for `version`, or — when the version could not be
/// parsed — any complete dir.
#[cfg(any(target_os = "macos", target_os = "linux"))]
fn complete_dir_for(pkg_base: &Path, version: Option<&str>) -> Option<String> {
    match version {
        Some(v) => find_complete_dir_for_version(pkg_base, v),
        None => find_any_complete_dir(pkg_base),
    }
}

/// Remove leftover Copilot extraction directories directly under `pkg_base`.
///
/// Called only when extraction could not be confirmed by any other means. At
/// that point nothing here is proof of anything: a directory for the current
/// version without the `.extraction-complete` marker is a partial extraction
/// that makes Copilot skip re-extracting, and a directory for any other version
/// is a leftover that blocks the "does not extract here" escape hatch. This is
/// the documented manual workaround (`rm -rf .../copilot/pkg`), applied
/// automatically so recovery does not require knowing the cache path.
///
/// Bounded on purpose: `pkg_base` must be a real directory (never a symlink),
/// only its immediate children are considered, and only children that are
/// themselves real directories are removed. `read_dir` and `DirEntry::file_type`
/// do not follow symlinks, so nothing outside this one directory is reachable.
/// Copilot's in-flight `.extracting-*` temp dirs are hidden, so `extraction_dirs`
/// skips them and a concurrent extraction is left alone.
///
/// Returns the names actually removed, sorted.
#[cfg(any(target_os = "macos", target_os = "linux"))]
fn purge_stale_extractions(pkg_base: &Path) -> Vec<String> {
    // Refuse to delete through a symlinked pkg_base — that could reach a
    // directory outside the cache.
    if !std::fs::symlink_metadata(pkg_base).is_ok_and(|m| m.is_dir()) {
        return Vec::new();
    }
    let mut removed: Vec<String> = extraction_dirs(pkg_base)
        .into_iter()
        .filter(|name| std::fs::remove_dir_all(pkg_base.join(name)).is_ok())
        .collect();
    removed.sort();
    removed
}

/// Build the give-up message: what we saw, and the exact command to fix it.
#[cfg(any(target_os = "macos", target_os = "linux"))]
fn extraction_failure_message(
    copilot_bin: &Path,
    pkg_base: &Path,
    reported_version: Option<&str>,
) -> String {
    let mut entries: Vec<String> = std::fs::read_dir(pkg_base)
        .into_iter()
        .flatten()
        .flatten()
        .map(|e| {
            let name = e.file_name().to_string_lossy().into_owned();
            let complete = pkg_base.join(&name).join(".extraction-complete").exists();
            format!(
                "{name} ({})",
                if complete { "complete" } else { "incomplete" }
            )
        })
        .collect();
    entries.sort();
    let listing = if entries.is_empty() {
        "empty".to_string()
    } else {
        entries.join(", ")
    };
    let pkg_root = pkg_base.parent().unwrap_or(pkg_base);
    format!(
        "Copilot runtime extraction failed. The sandbox blocks writes to the Copilot\n  \
         cache, so extraction must succeed before entering the sandbox.\n  \
         Binary: {}\n  \
         Version reported: {}\n  \
         Cache: {} ({})\n  \
         Fix: run '{} --version' manually and read its output. If it prints a version\n  \
         but cplt still fails here, clear the cache and retry:\n    \
         rm -rf {}",
        copilot_bin.display(),
        reported_version.unwrap_or("could not parse"),
        pkg_base.display(),
        listing,
        copilot_bin.display(),
        pkg_root.display(),
    )
}

/// Try a fallback extraction method using `-p exit` (works on older Copilot versions).
#[cfg(any(target_os = "macos", target_os = "linux"))]
fn try_extraction_fallback(
    copilot_bin: &Path,
    pkg_base: &Path,
    project: &Path,
    dirs_before: &std::collections::HashSet<String>,
) -> Option<String> {
    let child = extraction_command(
        copilot_bin,
        &["--no-auto-update", "-p", "exit"],
        pkg_base,
        project,
    )
    .stdin(std::process::Stdio::null())
    .stdout(std::process::Stdio::null())
    .stderr(std::process::Stdio::null())
    .spawn();

    let Ok(mut child) = child else {
        return None;
    };

    for _ in 0..60 {
        if let Some(name) = find_new_extracted_dir(pkg_base, dirs_before) {
            let _ = child.kill();
            let _ = child.wait();
            return Some(name);
        }
        if let Ok(Some(_)) = child.try_wait() {
            return find_new_extracted_dir(pkg_base, dirs_before);
        }
        std::thread::sleep(std::time::Duration::from_millis(500));
    }

    let _ = child.kill();
    let _ = child.wait();
    find_new_extracted_dir(pkg_base, dirs_before)
}

/// Compute a stable identity for a binary based on filesystem metadata.
/// Uses canonicalized path + inode + size + full mtime (seconds + nanoseconds).
/// Works for any file type: Mach-O binaries, shell scripts, symlinks (resolved).
#[cfg(any(target_os = "macos", target_os = "linux"))]
fn binary_identity(path: &Path) -> Option<String> {
    use std::os::unix::fs::MetadataExt;
    let canonical = path.canonicalize().ok()?;
    let meta = canonical.metadata().ok()?;
    Some(format!(
        "{}:{}:{}:{}.{}",
        canonical.display(),
        meta.ino(),
        meta.len(),
        meta.mtime(),
        meta.mtime_nsec(),
    ))
}

/// List non-hidden directory names under `pkg_base` (extraction version dirs).
#[cfg(any(target_os = "macos", target_os = "linux"))]
fn extraction_dirs(pkg_base: &Path) -> std::collections::HashSet<String> {
    std::fs::read_dir(pkg_base)
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| {
            let name = e.file_name().to_string_lossy().into_owned();
            if !name.starts_with('.') && e.file_type().ok()?.is_dir() {
                Some(name)
            } else {
                None
            }
        })
        .collect()
}

/// Check if there's an in-progress `.extracting-*` temp directory.
#[cfg(any(target_os = "macos", target_os = "linux"))]
fn has_extracting_dir(pkg_base: &Path) -> bool {
    std::fs::read_dir(pkg_base)
        .into_iter()
        .flatten()
        .flatten()
        .any(|e| {
            let name = e.file_name().to_string_lossy().into_owned();
            name.starts_with(".extracting-")
        })
}

/// Remove stale `.extracting-*` temp dirs left over from previous failed attempts.
/// These can prevent the SEA loader from starting a fresh extraction.
#[cfg(any(target_os = "macos", target_os = "linux"))]
fn clean_stale_extracting_dirs(pkg_base: &Path) {
    let Ok(entries) = std::fs::read_dir(pkg_base) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.starts_with(".extracting-") {
            let _ = std::fs::remove_dir_all(entry.path());
        }
    }
}

/// Find a newly created extraction dir (not in `before`) that has `.extraction-complete`.
#[cfg(any(target_os = "macos", target_os = "linux"))]
fn find_new_extracted_dir(
    pkg_base: &Path,
    before: &std::collections::HashSet<String>,
) -> Option<String> {
    let current = extraction_dirs(pkg_base);
    for name in current.difference(before) {
        if pkg_base.join(name).join(".extraction-complete").exists() {
            return Some(name.clone());
        }
    }
    None
}

/// Find any extraction dir that has `.extraction-complete` (most recent first).
#[cfg(any(target_os = "macos", target_os = "linux"))]
fn find_any_complete_dir(pkg_base: &Path) -> Option<String> {
    let mut dirs: Vec<_> = std::fs::read_dir(pkg_base)
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| {
            let name = e.file_name().to_string_lossy().into_owned();
            if name.starts_with('.') {
                return None;
            }
            let marker = pkg_base.join(&name).join(".extraction-complete");
            if marker.exists() {
                let mtime = e.metadata().ok()?.modified().ok()?;
                Some((name, mtime))
            } else {
                None
            }
        })
        .collect();
    // Most recently modified first
    dirs.sort_by_key(|b| std::cmp::Reverse(b.1));
    dirs.into_iter().next().map(|(name, _)| name)
}

/// Parse the semantic version from `copilot --version` output.
///
/// e.g. `"GitHub Copilot CLI 1.0.63."` -> `Some("1.0.63")`. Accepts an optional
/// pre-release suffix (`1.0.63-2`). Returns `None` if no version token is found.
#[cfg(any(target_os = "macos", target_os = "linux"))]
fn parse_copilot_version(output: &str) -> Option<String> {
    output.split_whitespace().find_map(|tok| {
        let v = tok.trim_end_matches('.');
        let mut parts = v.splitn(3, '.');
        let major = parts.next()?;
        let minor = parts.next()?;
        let patch = parts.next()?;
        let numeric = |s: &str| !s.is_empty() && s.chars().all(|c| c.is_ascii_digit());
        // major.minor must be fully numeric; patch must START numeric so that a
        // pre-release suffix like "63-2" is still accepted.
        if numeric(major)
            && numeric(minor)
            && patch.chars().next().is_some_and(|c| c.is_ascii_digit())
        {
            Some(v.to_string())
        } else {
            None
        }
    })
}

/// Find a *complete* extraction dir that matches `version`.
///
/// Matches the dir named exactly `version` or one prefixed `"{version}-"`
/// (pre-release builds may report a base version while extracting to a suffixed
/// directory, e.g. version `1.0.32` -> dir `1.0.32-1-73748`).
///
/// Security: this prevents a STALE old-version extraction (e.g. `1.0.62`) from
/// being accepted as proof that the CURRENT version is extracted. Accepting a
/// stale dir would let the preflight return success while the sandboxed session
/// re-extracts the current version and hits EPERM on the write-denied cache.
#[cfg(any(target_os = "macos", target_os = "linux"))]
fn find_complete_dir_for_version(pkg_base: &Path, version: &str) -> Option<String> {
    let prefix = format!("{version}-");
    std::fs::read_dir(pkg_base)
        .into_iter()
        .flatten()
        .flatten()
        .find_map(|e| {
            let name = e.file_name().to_string_lossy().into_owned();
            if name.starts_with('.') || (name != version && !name.starts_with(&prefix)) {
                return None;
            }
            if pkg_base.join(&name).join(".extraction-complete").exists() {
                Some(name)
            } else {
                None
            }
        })
}

/// Tests for the Copilot SEA extraction preflight (#166).
///
/// These drive the real `ensure_copilot_extracted` against a temp HOME and a
/// fake `copilot` shell script, so the whole poll/resolve/self-heal path runs.
/// Unix-only because SEA extraction only exists on macOS and Linux — the code
/// under test is `cfg(any(macos, linux))`, so there is nothing to skip on
/// Windows, and both macOS and Linux CI run every case here.
#[cfg(test)]
#[allow(clippy::disallowed_methods)] // test code: no unsandboxed parent to protect (#239)
#[cfg(any(target_os = "macos", target_os = "linux"))]
mod copilot_extraction_tests {
    use super::*;

    /// Mirror of `copilot_cache_dirs` for building the fixture HOME.
    fn pkg_base_of(home: &Path) -> PathBuf {
        let arch = match std::env::consts::ARCH {
            "aarch64" => "arm64",
            _ => "x64",
        };
        copilot_cache_dirs(home, arch).0
    }

    struct Fixture {
        root: PathBuf,
        home: PathBuf,
        project: PathBuf,
        pkg: PathBuf,
        bin: PathBuf,
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            // A test may have chmod 000'd a dir; make it removable again.
            let _ = std::process::Command::new("chmod")
                .args(["-R", "u+rwX"])
                .arg(&self.root)
                .status();
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    /// Build a temp HOME plus a fake copilot whose body can inspect `$PKG`
    /// (the platform extraction dir).
    fn fixture(name: &str, script: &str) -> Fixture {
        use std::os::unix::fs::PermissionsExt;
        let root = std::env::temp_dir().join(format!("cplt-extract-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let home = root.join("home");
        let project = root.join("project");
        let bindir = root.join("bin");
        let pkg = pkg_base_of(&home);
        std::fs::create_dir_all(&project).unwrap();
        std::fs::create_dir_all(&bindir).unwrap();
        std::fs::create_dir_all(&pkg).unwrap();
        let bin = bindir.join("copilot");
        // Write the script here, then have a *child process* copy it into
        // place. Writing it in-process and exec'ing it races every other test
        // thread: `Command::spawn` forks, and a fork that happens while this
        // file is open for writing inherits the writable descriptor, so our
        // exec comes back ETXTBSY. #285 tried to close that with a staged
        // write plus an atomic rename, but ETXTBSY is a property of the inode,
        // not of the name — renaming hands the exec the very inode that was
        // open for writing, so the race survived and recurred. Copying via
        // `cp` gives `bin` a fresh inode whose only writable descriptor lives
        // and dies inside the child, where no fork of ours can inherit it.
        let staging = root.join("copilot.staging");
        std::fs::write(
            &staging,
            format!(
                "#!/bin/sh\nPKG=\"{}\"\nCOUNT=\"{}\"\n{script}\n",
                pkg.to_string_lossy().replace('"', "\\\""),
                root.join("version-calls")
                    .to_string_lossy()
                    .replace('"', "\\\""),
            ),
        )
        .unwrap();
        let copied = std::process::Command::new("cp")
            .arg(&staging)
            .arg(&bin)
            .status()
            .unwrap();
        assert!(copied.success(), "cp of the fake copilot failed: {copied}");
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
        Fixture {
            root,
            home,
            project,
            pkg,
            bin,
        }
    }

    impl Fixture {
        fn run(&self) -> Result<(), String> {
            ensure_copilot_extracted(&self.bin, &self.home, &self.project)
        }

        fn complete_dir(&self, name: &str) {
            std::fs::create_dir_all(self.pkg.join(name)).unwrap();
            std::fs::write(self.pkg.join(name).join(".extraction-complete"), "").unwrap();
        }

        fn partial_dir(&self, name: &str) {
            std::fs::create_dir_all(self.pkg.join(name).join("node_modules")).unwrap();
        }

        /// How many times the fake copilot was invoked with `--version`.
        fn version_calls(&self) -> usize {
            std::fs::read_to_string(self.root.join("version-calls"))
                .map_or(0, |s| s.lines().count())
        }

        /// Path of cplt's fast-path marker for this fixture.
        fn cache_file(&self) -> PathBuf {
            let arch = match std::env::consts::ARCH {
                "aarch64" => "arm64",
                _ => "x64",
            };
            copilot_cache_dirs(&self.home, arch)
                .1
                .join("copilot-extracted")
        }

        fn entries(&self) -> Vec<String> {
            let mut v: Vec<String> = std::fs::read_dir(&self.pkg)
                .into_iter()
                .flatten()
                .flatten()
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .collect();
            v.sort();
            v
        }
    }

    /// Prints a version, never extracts anything. Stands in for a copilot whose
    /// runtime already lives elsewhere (e.g. `pkg/universal/`, #102) or that is
    /// not a SEA build at all.
    const NEVER_EXTRACTS: &str = "echo 'GitHub Copilot CLI 1.0.63.'";

    /// Extracts 1.0.63 only if that directory does not already exist — the real
    /// SEA loader's behaviour, and the reason a partial directory deadlocks.
    const EXTRACTS_UNLESS_DIR_EXISTS: &str = concat!(
        "if [ ! -d \"$PKG/1.0.63\" ]; then\n",
        "  mkdir -p \"$PKG/1.0.63\" && touch \"$PKG/1.0.63/.extraction-complete\"\n",
        "fi\n",
        "echo 'GitHub Copilot CLI 1.0.63.'"
    );

    #[test]
    fn accepts_a_complete_dir_for_the_reported_version() {
        let f = fixture("current", NEVER_EXTRACTS);
        f.complete_dir("1.0.63");
        assert!(f.run().is_ok());
        // A healthy cache must survive untouched — self-heal must not fire here.
        assert_eq!(f.entries(), vec!["1.0.63".to_string()]);
    }

    #[test]
    fn empty_cache_and_a_clean_exit_means_nothing_to_extract() {
        let f = fixture("empty", NEVER_EXTRACTS);
        assert!(f.run().is_ok());
    }

    /// #166 core case: after an update the old version's directory is still
    /// there while the current runtime lives somewhere this preflight does not
    /// watch. Before the fix this was a permanent startup failure.
    #[test]
    fn recovers_from_a_stale_old_version_dir() {
        let f = fixture("stale-old", NEVER_EXTRACTS);
        f.complete_dir("1.0.62");
        assert!(f.run().is_ok(), "stale old-version dir must not deadlock");
        assert!(f.entries().is_empty(), "stale dir should have been removed");
    }

    /// #166 core case: an interrupted extraction leaves a marker-less directory
    /// for the CURRENT version. Copilot then sees the directory and skips
    /// extraction forever, so the marker never appears.
    #[test]
    fn recovers_from_a_partial_current_version_dir() {
        let f = fixture("partial", EXTRACTS_UNLESS_DIR_EXISTS);
        f.partial_dir("1.0.63");
        assert!(
            f.run().is_ok(),
            "partial dir must be cleared and re-extracted"
        );
        assert!(
            f.pkg.join("1.0.63/.extraction-complete").exists(),
            "re-extraction should have completed: {:?}",
            f.entries()
        );
    }

    /// An empty directory named after the current version blocks extraction the
    /// same way a partial one does.
    #[test]
    fn recovers_from_an_empty_current_version_dir() {
        let f = fixture("empty-dir", EXTRACTS_UNLESS_DIR_EXISTS);
        std::fs::create_dir_all(f.pkg.join("1.0.63")).unwrap();
        // Carry the error. A bare `is_ok()` here cost a CI round-trip to
        // diagnose, because the failure said nothing about why. Run once and
        // report that result: a second run would see the state the first left
        // behind and could well succeed, describing a failure that never was.
        let result = f.run();
        assert!(result.is_ok(), "extraction failed: {result:?}");
        assert!(f.pkg.join("1.0.63/.extraction-complete").exists());
    }

    /// A directory carrying the right name and marker but no readable contents
    /// cannot be removed either, so self-heal fails. That is allowed — but the
    /// error must name the directory and the command that fixes it.
    #[test]
    fn unremovable_dir_fails_with_the_cache_path_and_a_fix_command() {
        use std::os::unix::fs::PermissionsExt;
        let f = fixture("unreadable", NEVER_EXTRACTS);
        f.partial_dir("1.0.63");
        std::fs::set_permissions(f.pkg.join("1.0.63"), std::fs::Permissions::from_mode(0o000))
            .unwrap();
        let err = f.run().unwrap_err();
        assert!(err.contains("1.0.63"), "{err}");
        assert!(err.contains("Version reported: 1.0.63"), "{err}");
        assert!(
            err.contains(&format!("rm -rf {}", f.pkg.parent().unwrap().display())),
            "{err}"
        );
    }

    /// Copilot itself failing is still an error — but the message has to carry
    /// the diagnostics, since there is no cache state to clean up.
    #[test]
    fn a_failing_copilot_reports_the_empty_cache() {
        let f = fixture("crash", "echo 'GitHub Copilot CLI 1.0.63.'; exit 1");
        let err = f.run().unwrap_err();
        assert!(err.contains("(empty)"), "{err}");
        assert!(err.contains("--version"), "{err}");
    }

    /// A copilot that cannot be spawned must be a hard error. It never ran, so
    /// its version is unknowable, and the version-less fallback would otherwise
    /// accept any stale directory as proof — and then cache that false positive
    /// against the binary's identity, skipping the preflight from then on.
    #[test]
    fn a_binary_that_cannot_be_spawned_is_an_error() {
        use std::os::unix::fs::PermissionsExt;
        let f = fixture("nospawn", NEVER_EXTRACTS);
        f.complete_dir("0.0.1");
        std::fs::set_permissions(&f.bin, std::fs::Permissions::from_mode(0o644)).unwrap();

        let err = f.run().unwrap_err();
        assert!(err.contains("Failed to spawn copilot"), "{err}");
        // The spawn error itself must survive — "Permission denied" is the answer.
        assert!(err.contains("ermission denied"), "{err}");
        // No false positive was cached against this binary.
        assert!(!f.cache_file().exists());
    }

    /// The second pass runs only when the purge actually removed something.
    /// That guard is what keeps the worst-case wall time bounded, so it needs a
    /// test of its own: with nothing to remove, copilot is run exactly once.
    #[test]
    fn no_retry_when_there_is_nothing_to_purge() {
        let f = fixture(
            "no-retry",
            "case \"$*\" in *--version*) echo x >> \"$COUNT\" ;; esac\necho 'GitHub Copilot CLI 1.0.63.'\nexit 1",
        );
        assert!(f.run().is_err());
        assert_eq!(f.version_calls(), 1, "empty purge must not trigger a retry");
    }

    #[test]
    fn purge_removes_only_real_child_dirs() {
        let f = fixture("purge-scope", NEVER_EXTRACTS);
        let outside = f.root.join("outside");
        std::fs::create_dir_all(outside.join("keep")).unwrap();
        f.complete_dir("1.0.62");
        std::fs::create_dir_all(f.pkg.join(".extracting-abc")).unwrap();
        std::fs::write(f.pkg.join("loose-file"), "x").unwrap();
        std::os::unix::fs::symlink(&outside, f.pkg.join("link")).unwrap();

        assert_eq!(purge_stale_extractions(&f.pkg), vec!["1.0.62".to_string()]);
        // The symlink target is untouched: purge never follows links out.
        assert!(outside.join("keep").exists());
        // An in-flight extraction (hidden temp dir) and plain files are left alone,
        // so a concurrently extracting copilot is not disturbed.
        assert!(f.pkg.join(".extracting-abc").exists());
        assert!(f.pkg.join("loose-file").exists());
        assert!(f.pkg.join("link").exists());
    }

    #[test]
    fn purge_refuses_a_symlinked_pkg_base() {
        let f = fixture("purge-symlink", NEVER_EXTRACTS);
        let real = f.root.join("real-cache");
        std::fs::create_dir_all(real.join("1.0.62")).unwrap();
        let link = f.root.join("linked-pkg");
        std::os::unix::fs::symlink(&real, &link).unwrap();

        assert!(purge_stale_extractions(&link).is_empty());
        assert!(real.join("1.0.62").exists());
    }

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[test]
    fn parse_copilot_version_extracts_from_banner() {
        assert_eq!(
            parse_copilot_version("GitHub Copilot CLI 1.0.63."),
            Some("1.0.63".to_string())
        );
        assert_eq!(
            parse_copilot_version("GitHub Copilot CLI 1.0.63.\nRun 'copilot update'"),
            Some("1.0.63".to_string())
        );
        // Pre-release suffix is preserved.
        assert_eq!(
            parse_copilot_version("Copilot 1.0.32-1"),
            Some("1.0.32-1".to_string())
        );
        assert_eq!(parse_copilot_version("no version here"), None);
        assert_eq!(parse_copilot_version(""), None);
    }

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[test]
    fn find_complete_dir_for_version_rejects_stale_old_version() {
        let tmp = std::env::temp_dir().join(format!("cplt-ver-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        // Old version is fully extracted, current version is NOT.
        std::fs::create_dir_all(tmp.join("1.0.62")).unwrap();
        std::fs::write(tmp.join("1.0.62/.extraction-complete"), "").unwrap();
        std::fs::create_dir_all(tmp.join("1.0.63")).unwrap(); // present but incomplete

        // Must NOT accept the stale 1.0.62 dir when asking for 1.0.63.
        assert_eq!(find_complete_dir_for_version(&tmp, "1.0.63"), None);
        // The old version itself still resolves when explicitly requested.
        assert_eq!(
            find_complete_dir_for_version(&tmp, "1.0.62"),
            Some("1.0.62".to_string())
        );

        // Once the current version completes, it is accepted.
        std::fs::write(tmp.join("1.0.63/.extraction-complete"), "").unwrap();
        assert_eq!(
            find_complete_dir_for_version(&tmp, "1.0.63"),
            Some("1.0.63".to_string())
        );
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[test]
    fn find_complete_dir_for_version_matches_prerelease_suffix() {
        let tmp = std::env::temp_dir().join(format!("cplt-ver-pre-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(tmp.join("1.0.32-1-73748")).unwrap();
        std::fs::write(tmp.join("1.0.32-1-73748/.extraction-complete"), "").unwrap();

        // Base version reported by --version matches the suffixed extraction dir.
        assert_eq!(
            find_complete_dir_for_version(&tmp, "1.0.32"),
            Some("1.0.32-1-73748".to_string())
        );
        // A shorter prefix must not spuriously match (1.0.3 != 1.0.32).
        assert_eq!(find_complete_dir_for_version(&tmp, "1.0.3"), None);
        let _ = std::fs::remove_dir_all(&tmp);
    }

    /// Records the working directory and environment of each preflight spawn,
    /// then fails the `--version` probe so the `-p exit` fallback runs too.
    const DUMPS_CWD_AND_ENV: &str = concat!(
        "D=\"$(dirname \"$COUNT\")\"\n",
        "if [ \"$2\" = \"-p\" ]; then T=fallback; else T=probe; fi\n",
        "pwd > \"$D/$T.cwd\"\n",
        "env > \"$D/$T.env\"\n",
        "if [ \"$T\" = probe ]; then exit 3; fi\n",
        "exit 0"
    );

    /// Assert the spawn recorded under `tag` ran in the Copilot cache with an
    /// environment rebuilt from `EXTRACTION_ENV_ALLOWLIST`, not the caller's
    /// project directory and inherited credentials (F05).
    fn assert_isolated(f: &Fixture, tag: &str) {
        use std::collections::BTreeSet;

        let cwd = std::fs::read_to_string(f.root.join(format!("{tag}.cwd")))
            .unwrap_or_else(|e| panic!("{tag}: the spawn never happened: {e}"));
        assert_eq!(
            std::fs::canonicalize(cwd.trim()).unwrap(),
            std::fs::canonicalize(&f.pkg).unwrap(),
            "{tag}: spawn inherited the caller's working directory",
        );

        let dump = std::fs::read_to_string(f.root.join(format!("{tag}.env"))).unwrap();
        let names: BTreeSet<&str> = dump
            .lines()
            .filter_map(|line| line.split_once('='))
            .map(|(name, _)| name)
            .collect();
        // `sh` exports these itself in the child; everything else must be ours.
        let allowed: BTreeSet<&str> = EXTRACTION_ENV_ALLOWLIST
            .iter()
            .copied()
            .chain(["PWD", "SHLVL", "_"])
            .collect();
        let leaked: Vec<&&str> = names.difference(&allowed).collect();
        assert!(
            leaked.is_empty(),
            "{tag}: the parent environment leaked into the spawn: {leaked:?}",
        );
        assert!(
            names.contains("HOME") && names.contains("PATH"),
            "{tag}: the allowlist did not reach the spawn, got {names:?}",
        );
        for var in EXTRACTION_ENV_ALLOWLIST {
            if std::env::var_os(var).is_some() {
                assert!(
                    names.contains(var),
                    "{tag}: allowlisted {var} is set here but did not reach the spawn",
                );
            }
        }
        // Guard against a false pass: the parent must hold something that the
        // child would have inherited had the environment not been cleared.
        assert!(
            std::env::vars().any(|(name, _)| !allowed.contains(name.as_str())),
            "the test process environment is too clean to prove anything",
        );
    }

    /// PATH decides which `node` an npm-installed `copilot` shebang wrapper
    /// runs, outside the sandbox. direnv and asdf routinely prepend repo-local
    /// tool dirs, and `.envrc` belongs to the project, so passing PATH through
    /// verbatim would hand back the influence that clearing cwd and env removed.
    #[test]
    fn sanitized_path_drops_everything_the_project_controls() {
        let tmp = std::env::temp_dir().join(format!(
            "cplt-path-sanitize-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        let project = tmp.join("project");
        let node_bin = project.join("node_modules/.bin");
        let safe = tmp.join("usr-bin");
        std::fs::create_dir_all(&node_bin).expect("node bin");
        std::fs::create_dir_all(&safe).expect("safe bin");
        let project = project.canonicalize().expect("canonical project");

        // A project dir, a relative entry, an empty segment, and one safe entry.
        let raw = std::env::join_paths([
            node_bin.as_path(),
            Path::new("."),
            Path::new(""),
            safe.as_path(),
        ])
        .expect("join");

        // SAFETY: single-threaded assertion on a value read once, immediately.
        let kept = sanitize_path_value(&raw, &project).expect("non-empty PATH");
        let entries: Vec<PathBuf> = std::env::split_paths(&kept).collect();

        // Compare canonically. On macOS the temp dir is reached through the
        // /var -> /private/var symlink, so a raw `starts_with` against the
        // canonicalized project is false for a surviving project entry and the
        // assertion would pass without testing anything (it did, until a
        // mutation that removed the filter failed to turn this test red).
        assert!(
            !entries
                .iter()
                .filter_map(|e| e.canonicalize().ok())
                .any(|e| e.starts_with(&project)),
            "a PATH entry under the project survived sanitizing: {entries:?}"
        );
        assert!(
            !entries.iter().any(|e| !e.is_absolute()),
            "a relative PATH entry survived sanitizing: {entries:?}"
        );
        assert!(
            entries.iter().any(|e| e == &safe),
            "the safe entry must survive, or copilot cannot find node: {entries:?}"
        );

        std::fs::remove_dir_all(&tmp).ok();
    }

    /// The SEA loader resolves its extraction directory from these, in this
    /// order, and `ENV_ALLOWLIST`/`ENV_PREFIX_ALLOWLIST` hand every one of them
    /// to the sandboxed session. Withhold one here and the preflight extracts
    /// to a directory the session never looks at; the session then extracts
    /// into the write-denied cache and hits the EPERM this whole module exists
    /// to prevent (#166).
    #[test]
    fn the_allowlist_carries_every_cache_path_the_loader_consults() {
        for var in [
            "COPILOT_PKG_CACHE_HOME",
            "COPILOT_CACHE_HOME",
            "COPILOT_HOME",
            "XDG_CACHE_HOME",
            "HOME",
        ] {
            assert!(
                EXTRACTION_ENV_ALLOWLIST.contains(&var),
                "{var} decides where copilot extracts, so the preflight must see it",
            );
        }
    }

    #[test]
    fn version_probe_spawn_is_isolated() {
        let f = fixture("probe-isolation", DUMPS_CWD_AND_ENV);
        let _ = f.run();
        assert_isolated(&f, "probe");
    }

    #[test]
    fn fallback_spawn_is_isolated() {
        let f = fixture("fallback-isolation", DUMPS_CWD_AND_ENV);
        let _ = f.run();
        assert_isolated(&f, "fallback");
    }
}
