//! The proxy's effective domain lists — *right now*.
//!
//! [`DomainPolicy`] owns the three lists the CONNECT gates consult (blocklist,
//! allowlist, private-domain waiver list) plus the frozen port policy. It is a
//! plain value: building one validates its inputs, and reading one answers
//! "what does policy say at instant *t*". No socket is involved, so the whole
//! surface is testable without binding a port.
//!
//! # Provenance
//!
//! Each list is a union of two halves with different lifetimes:
//!
//! - **Sticky** entries come from a source that is read exactly once per
//!   session — CLI argv, the trust-approved repo `.cplt.toml` (read from git
//!   HEAD), a startup-frozen blocklist subscription cache, the agent's built-in
//!   default allowlist. Nothing re-reads them, so they must survive every
//!   refresh. Parking them in the reloadable cache is what made the 5-second
//!   TTL wipe `--allow-private-domain` mid-session (#186).
//! - **Reloadable** entries come from a file that is re-read every
//!   [`RELOAD_TTL`], so editing that file adds *and revokes* entries live.
//!
//! The effective list is `sticky ∪ file`. With no sticky entries the file's
//! contents are returned verbatim, which is the unchanged behaviour for every
//! configuration that predates subscriptions (#144), the default allowlist
//! (#52) and repo-proposed private domains.
//!
//! # Clock seam
//!
//! TTL freshness is decided against a caller-supplied `now: Instant` rather
//! than an ambient `Instant::now()`, the same shape as
//! [`crate::subscriptions::update_all`]. Production passes `Instant::now()`;
//! tests pass `start + 6s` to make a cache stale without sleeping and without
//! reaching into a private field.

use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::proxy::normalize_hostname;

/// How often file-backed domain lists are re-read from disk.
/// Within the TTL window, cached values are returned without I/O.
pub const RELOAD_TTL: Duration = Duration::from_secs(5);

/// A file-backed list plus its TTL bookkeeping.
struct Cache {
    domains: Vec<String>,
    /// When the last reload attempt was made (success or failure).
    /// Used for TTL backoff on both success and error paths.
    last_attempt: Instant,
}

/// One effective domain list: session-frozen entries unioned with a
/// TTL-reloaded file. See the module docs for the provenance rules.
pub struct DomainList {
    /// Frozen for the session; always present in the effective list.
    sticky: Vec<String>,
    /// Reloadable source. `None` = no file half at all.
    file: Option<PathBuf>,
    /// Parser for `file`. Returns `None` on read/parse failure, which keeps the
    /// last-good list rather than emptying it.
    parser: fn(&Path) -> Option<Vec<String>>,
    cache: Mutex<Cache>,
}

impl DomainList {
    /// Build a list from already-validated pieces. `initial` seeds the cache so
    /// the first read does no I/O; `now` starts its TTL window.
    fn new(
        sticky: Vec<String>,
        file: Option<PathBuf>,
        parser: fn(&Path) -> Option<Vec<String>>,
        initial: Vec<String>,
        now: Instant,
    ) -> Self {
        Self {
            sticky,
            file,
            parser,
            cache: Mutex::new(Cache {
                domains: initial,
                last_attempt: now,
            }),
        }
    }

    /// The effective list at `now`, re-reading the file half if its TTL expired.
    ///
    /// On read failure the last-good file half is kept (fail-safe) and the TTL
    /// resets, so a transient error backs off instead of spinning on I/O.
    #[must_use]
    pub fn current(&self, now: Instant) -> Vec<String> {
        let file_domains = self.file_half(now);

        // No sticky half — the file is the sole source, returned verbatim.
        if self.sticky.is_empty() {
            return file_domains;
        }

        let mut merged = self.sticky.clone();
        merged.extend(file_domains);
        merged.sort_unstable();
        merged.dedup();
        merged
    }

    fn file_half(&self, now: Instant) -> Vec<String> {
        let mut guard = self
            .cache
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        if now.saturating_duration_since(guard.last_attempt) < RELOAD_TTL {
            return guard.domains.clone();
        }

        if let Some(path) = self.file.as_deref()
            && let Some(fresh) = (self.parser)(path)
        {
            guard.domains = fresh;
        }
        // On failure: keep last-good domains (fail-safe).
        guard.last_attempt = now;
        guard.domains.clone()
    }
}

/// Everything needed to build a [`DomainPolicy`], straight off the resolved
/// config. Every field is the same value `ProxyOptions` carries; `Default`
/// exists so a test can name only the one list it cares about.
#[derive(Default)]
pub struct PolicySpec {
    /// Blocklist file. Re-read every [`RELOAD_TTL`].
    pub blocked_file: PathBuf,
    /// Domains from cached blocklist subscriptions (#144), frozen at startup.
    /// UNIONed with `blocked_file`. Tighten-only: can only ever ADD blocks.
    pub subscription_blocklist: Vec<String>,
    /// User allowlist file. Re-read every [`RELOAD_TTL`].
    pub allowed_domains_file: Option<PathBuf>,
    /// Allowlist domains from CLI/config, used when the file does not exist yet
    /// (or when there is no file at all).
    pub allowed_domains_initial: Vec<String>,
    /// The agent's built-in fail-closed allowlist (#52), frozen at startup.
    /// Empty = feature off (unchanged allow-all).
    pub default_allowlist: Vec<String>,
    /// Private domains from `--allow-private-domain`. Read once from argv.
    pub cli_private_domains: Vec<String>,
    /// Private domains that came from `config_file`'s own
    /// `proxy.allow_private_domains` — the only reloadable provenance.
    pub config_private_domains: Vec<String>,
    /// Trust-approved `[propose.proxy] allow_private_domains` from the repo
    /// `.cplt.toml`. Read once from git HEAD + the trust store.
    pub repo_private_domains: Vec<String>,
    /// TOML config file backing `config_private_domains`.
    pub config_file: Option<PathBuf>,
    /// Remote ports CONNECT may reach, before 443 is added.
    pub allowed_ports: Vec<u16>,
    /// Localhost ports explicitly opened by `--allow-localhost`.
    pub allow_localhost_ports: Vec<u16>,
    /// Whether `--allow-localhost-any` opened all localhost ports.
    pub allow_localhost_any: bool,
}

/// The effective CONNECT policy: three domain lists plus the frozen port
/// policy. Built once at startup, read on every CONNECT.
pub struct DomainPolicy {
    blocked: DomainList,
    allowed: DomainList,
    private: DomainList,
    /// Remote ports CONNECT may reach. Always includes 443. Frozen at startup
    /// because the kernel Seatbelt profile is immutable.
    pub allowed_ports: Vec<u16>,
    /// Localhost ports the private-IP block is bypassed for.
    pub allow_localhost_ports: Vec<u16>,
    /// Whether every localhost port is open.
    pub allow_localhost_any: bool,
}

impl DomainPolicy {
    /// Validate `spec` and freeze it into a policy.
    ///
    /// Startup validation is fail-fast, never fail-open:
    /// - a blocklist file that exists but cannot be read is an error, so a
    ///   corrupt blocklist can never silently degrade to "block nothing";
    /// - an allowlist file that exists but cannot be read is an error, so a
    ///   fail-closed allowlist can never silently degrade to "allow all".
    ///
    /// A file that does not exist is not an error for either: the blocklist
    /// starts empty and the allowlist falls back to `allowed_domains_initial`,
    /// both of which are today's behaviour for a not-yet-written file.
    pub fn build(spec: PolicySpec, now: Instant) -> Result<Self, String> {
        let mut ports: Vec<u16> = vec![443];
        ports.extend_from_slice(&spec.allowed_ports);
        ports.sort_unstable();
        ports.dedup();

        let blocked_initial = if spec.blocked_file.exists() {
            parse_lines_file(&spec.blocked_file).ok_or_else(|| {
                format!(
                    "Cannot read blocked domains file {}",
                    spec.blocked_file.display()
                )
            })?
        } else {
            Vec::new()
        };

        let allowlist_initial = match spec.allowed_domains_file.as_deref() {
            Some(path) if path.exists() => parse_lines_file(path)
                .ok_or_else(|| format!("Cannot read allowed domains file {}", path.display()))?,
            // File not written yet — seed from config, which the file will
            // take over from at the first successful reload.
            Some(_) | None => spec.allowed_domains_initial,
        };

        // Private domains whose source is read exactly once — CLI flags and
        // trust-approved repo `.cplt.toml` proposals — are sticky. The
        // reloadable cache's only refresh source is the global config file, so
        // anything else parked in it is dropped by the first refresh, 5s into
        // the session (#186).
        let mut sticky_private: Vec<String> = spec
            .cli_private_domains
            .iter()
            .chain(spec.repo_private_domains.iter())
            .map(|d| normalize_hostname(d))
            .collect();
        sticky_private.sort_unstable();
        sticky_private.dedup();

        Ok(Self {
            blocked: DomainList::new(
                spec.subscription_blocklist,
                Some(spec.blocked_file),
                parse_lines_file,
                blocked_initial,
                now,
            ),
            allowed: DomainList::new(
                spec.default_allowlist,
                spec.allowed_domains_file,
                parse_lines_file,
                allowlist_initial,
                now,
            ),
            private: DomainList::new(
                sticky_private,
                spec.config_file,
                parse_private_domains_from_toml,
                spec.config_private_domains,
                now,
            ),
            allowed_ports: ports,
            allow_localhost_ports: spec.allow_localhost_ports,
            allow_localhost_any: spec.allow_localhost_any,
        })
    }

    /// Effective blocklist: the reloadable file UNION the frozen subscription
    /// lists. Empty = block nothing.
    #[must_use]
    pub fn blocked_domains(&self, now: Instant) -> Vec<String> {
        self.blocked.current(now)
    }

    /// Effective allowlist: the reloadable user file merged with the agent's
    /// built-in defaults. Empty = allow-all (the feature is off); non-empty
    /// means the CONNECT gate fail-closes on anything unlisted.
    #[must_use]
    pub fn allowed_domains(&self, now: Instant) -> Vec<String> {
        self.allowed.current(now)
    }

    /// Effective private-domain waiver list: sticky CLI/repo entries plus the
    /// reloadable config-file entries.
    #[must_use]
    pub fn private_domains(&self, now: Instant) -> Vec<String> {
        self.private.current(now)
    }
}

/// Parse a one-domain-per-line file (blocklist or allowlist format).
/// Returns None on read failure (caller keeps last-good).
///
/// This is the **single** parser the live proxy feeds into its allowlist and
/// blocklist lists. `cplt check` must build its policy snapshot through this
/// same function (not `parse_domain_file`, which extra-normalizes by stripping
/// scheme/path/port) so a non-canonical allowlist entry like `github.com:443`
/// is stored byte-identically in both — otherwise check would report ALLOWED
/// for a host the live `handle_connect` blocks with BLOCKED-ALLOWLIST.
pub fn parse_lines_file(path: &Path) -> Option<Vec<String>> {
    let contents = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(e)
            if e.kind() == std::io::ErrorKind::NotFound
                || e.kind() == std::io::ErrorKind::NotADirectory =>
        {
            // File doesn't exist or path component is not a directory — silent.
            return None;
        }
        Err(e) => {
            eprintln!(
                "{}[proxy]{} Warning: cannot read {}: {e}",
                crate::ui::color(crate::ui::YELLOW),
                crate::ui::color(crate::ui::RESET),
                path.display()
            );
            return None;
        }
    };
    Some(
        contents
            .lines()
            .map(|l| l.trim().to_lowercase().trim_end_matches('.').to_string())
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .collect(),
    )
}

/// Parse `proxy.allow_private_domains` from a TOML config file.
///
/// `Some(list)` means the file was read and parsed: an empty list is the real
/// answer "this file allows no private domains", which is what revokes an entry
/// removed from the config mid-session. `None` means the file could not be read
/// or parsed, and the caller keeps its last-good list.
///
/// Uses the `toml` crate rather than scanning lines: the config file is written
/// by `cplt init` (which emits multi-line arrays for more than one entry) and by
/// hand, so a line scanner silently mis-reads multi-line arrays, trailing
/// comments and dotted keys — all of which serde accepts elsewhere in cplt.
fn parse_private_domains_from_toml(path: &Path) -> Option<Vec<String>> {
    let contents = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!(
                "{}[proxy]{} Warning: cannot read config {}: {e}",
                crate::ui::color(crate::ui::YELLOW),
                crate::ui::color(crate::ui::RESET),
                path.display()
            );
            return None;
        }
    };

    let parsed: toml::Value = toml::from_str(&contents).ok()?;
    let Some(value) = parsed
        .get("proxy")
        .and_then(|proxy| proxy.get("allow_private_domains"))
    else {
        // Key absent — the file genuinely allows nothing.
        return Some(Vec::new());
    };
    // Wrong type: treat as unreadable (keep last-good) rather than as a
    // revocation. Startup validation rejects it anyway.
    let entries = value.as_array()?;
    Some(
        entries
            .iter()
            .filter_map(toml::Value::as_str)
            .map(normalize_hostname)
            .filter(|d| !d.is_empty())
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proxy::{is_blocked_in_list, is_domain_match};

    /// Create a unique temp directory for test isolation.
    fn test_dir(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("cplt-test-domains-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// A moment past the TTL — the clock seam that replaces sleeping or
    /// reaching into the cache's private `last_attempt`.
    fn stale(now: Instant) -> Instant {
        now.checked_add(RELOAD_TTL + Duration::from_millis(100))
            .unwrap()
    }

    fn policy(spec: PolicySpec, now: Instant) -> DomainPolicy {
        DomainPolicy::build(spec, now).expect("policy build failed")
    }

    // ── TTL refresh ─────────────────────────────────────────────────────

    #[test]
    fn domain_list_returns_cached_within_ttl() {
        let now = Instant::now();
        let list = DomainList::new(
            Vec::new(),
            None,
            |_| panic!("should not call parser"),
            vec!["example.com".to_string()],
            now,
        );
        assert_eq!(list.current(now), vec!["example.com"]);
    }

    #[test]
    fn domain_list_reloads_after_ttl() {
        let dir = test_dir("reload");
        let path = dir.join("domains.txt");
        std::fs::write(&path, "old.com\n").unwrap();

        let now = Instant::now();
        let list = DomainList::new(
            Vec::new(),
            Some(path.clone()),
            parse_lines_file,
            vec!["old.com".to_string()],
            now,
        );
        assert_eq!(list.current(now), vec!["old.com"], "fresh cache, no I/O");

        std::fs::write(&path, "new.com\n").unwrap();
        assert_eq!(
            list.current(now),
            vec!["old.com"],
            "edit is invisible until the TTL expires"
        );
        assert_eq!(list.current(stale(now)), vec!["new.com"]);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn domain_list_keeps_last_good_on_failure() {
        let now = Instant::now();
        let list = DomainList::new(
            Vec::new(),
            Some(PathBuf::from("/nonexistent-cplt-test-file-xyz.txt")),
            parse_lines_file,
            vec!["good.com".to_string()],
            now,
        );
        assert_eq!(
            list.current(stale(now)),
            vec!["good.com"],
            "should keep last-good list on failure"
        );
    }

    #[test]
    fn domain_list_resets_ttl_after_failure() {
        let now = Instant::now();
        let path = PathBuf::from("/nonexistent-cplt-test-file-xyz.txt");
        let list = DomainList::new(
            Vec::new(),
            Some(path),
            parse_lines_file,
            vec!["good.com".to_string()],
            now,
        );
        let failed_at = stale(now);
        let _ = list.current(failed_at);
        assert!(
            list.cache.lock().unwrap().last_attempt == failed_at,
            "TTL should be reset after failed reload, so the next read backs off"
        );
    }

    // ── Parsers ─────────────────────────────────────────────────────────

    #[test]
    fn parse_lines_file_skips_comments_and_empty() {
        let dir = test_dir("parse-lines");
        let path = dir.join("test.txt");
        std::fs::write(&path, "# comment\n\nexample.com\n  MIXED.Case.  \n").unwrap();

        let result = parse_lines_file(&path).unwrap();
        assert_eq!(result, vec!["example.com", "mixed.case"]);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn parse_private_domains_from_toml_extracts_correctly() {
        let dir = test_dir("toml-extract");
        let path = dir.join("config.toml");
        std::fs::write(
            &path,
            "[sandbox]\nquiet = true\n\n[proxy]\nallow_private_domains = [\"intern.nav.no\", \"dev.CORP.example.com\"]\nport = 8080\n\n[allow]\nports = [443]\n",
        )
        .unwrap();

        let result = parse_private_domains_from_toml(&path).unwrap();
        assert_eq!(result, vec!["intern.nav.no", "dev.corp.example.com"]);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn parse_private_domains_from_toml_empty_section() {
        let dir = test_dir("toml-empty");
        let path = dir.join("config.toml");
        std::fs::write(&path, "[proxy]\nport = 8080\n").unwrap();

        let result = parse_private_domains_from_toml(&path).unwrap();
        assert!(result.is_empty());

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// TOML shapes the previous line-scanning parser silently mis-read as "no
    /// domains" (or, for the typo key, as an unreadable file): a multi-line
    /// array — what `cplt init` writes for more than one entry — a trailing
    /// comment, a dotted key, and a key that merely starts with the real one.
    #[test]
    fn parse_private_domains_from_toml_handles_real_world_shapes() {
        let dir = test_dir("toml-shapes");
        let cases = [
            "[proxy]\nallow_private_domains = [\n  \"a.nav.no\",\n  \"b.nav.no\",\n]\n",
            "[proxy]\nallow_private_domains = [\"a.nav.no\", \"B.NAV.no.\"]  # trailing comment\n",
            "proxy.allow_private_domains = [\"a.nav.no\", \"b.nav.no\"]\n",
            "[proxy]\nallow_private_domains_typo = []\nallow_private_domains = [\"a.nav.no\", \"b.nav.no\"]\n",
        ];
        for (i, contents) in cases.iter().enumerate() {
            let path = dir.join(format!("config{i}.toml"));
            std::fs::write(&path, contents).unwrap();
            assert_eq!(
                parse_private_domains_from_toml(&path),
                Some(vec!["a.nav.no".to_string(), "b.nav.no".to_string()]),
                "case {i}: {contents}"
            );
        }

        // Unparseable TOML is "unreadable", not "allows nothing" — the caller
        // keeps its last-good list instead of dropping every waiver.
        let path = dir.join("broken.toml");
        std::fs::write(&path, "[proxy\n").unwrap();
        assert_eq!(parse_private_domains_from_toml(&path), None);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn parse_private_domains_from_toml_no_proxy_section() {
        let dir = test_dir("toml-noproxy");
        let path = dir.join("config.toml");
        std::fs::write(&path, "[sandbox]\nquiet = true\n").unwrap();

        let result = parse_private_domains_from_toml(&path).unwrap();
        assert!(result.is_empty());

        let _ = std::fs::remove_dir_all(&dir);
    }

    // ── Startup validation ──────────────────────────────────────────────

    #[test]
    fn build_accepts_a_readable_blocklist() {
        let dir = test_dir("build-valid");
        let blocked = dir.join("blocked.txt");
        std::fs::write(&blocked, "test.com\n").unwrap();

        let now = Instant::now();
        let policy = policy(
            PolicySpec {
                blocked_file: blocked,
                ..PolicySpec::default()
            },
            now,
        );
        assert_eq!(policy.blocked_domains(now), vec!["test.com"]);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn build_fails_on_unreadable_allowlist() {
        let dir = test_dir("build-fail");
        let blocked = dir.join("blocked.txt");
        std::fs::write(&blocked, "").unwrap();

        // A directory where a file is expected — unreadable as a file.
        let allowlist_path = dir.join("allowlist");
        std::fs::create_dir(&allowlist_path).unwrap();

        let result = DomainPolicy::build(
            PolicySpec {
                blocked_file: blocked,
                allowed_domains_file: Some(allowlist_path),
                ..PolicySpec::default()
            },
            Instant::now(),
        );
        assert!(
            result.is_err(),
            "a fail-closed allowlist must never degrade to allow-all"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn build_fails_on_unreadable_blocklist() {
        let dir = test_dir("build-fail-blocklist");
        let blocked = dir.join("blocked");
        std::fs::create_dir(&blocked).unwrap();

        let result = DomainPolicy::build(
            PolicySpec {
                blocked_file: blocked,
                ..PolicySpec::default()
            },
            Instant::now(),
        );
        assert!(
            result.is_err(),
            "an unreadable blocklist must never degrade to block-nothing"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn build_always_allows_443_and_dedupes_ports() {
        let policy = policy(
            PolicySpec {
                allowed_ports: vec![8080, 443, 8080],
                ..PolicySpec::default()
            },
            Instant::now(),
        );
        assert_eq!(policy.allowed_ports, vec![443, 8080]);
    }

    // ── Blocklist ───────────────────────────────────────────────────────

    #[test]
    fn blocklist_reads_the_file() {
        let dir = test_dir("blocked");
        let path = dir.join("blocked.txt");
        std::fs::write(&path, "evil.com\nbad.org\n").unwrap();

        let now = Instant::now();
        let policy = policy(
            PolicySpec {
                blocked_file: path,
                ..PolicySpec::default()
            },
            now,
        );
        assert_eq!(policy.blocked_domains(now), vec!["evil.com", "bad.org"]);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn subscription_blocklist_merges_into_effective_blocklist() {
        let dir = test_dir("subscription-merge");
        let path = dir.join("blocked.txt");
        std::fs::write(&path, "local.example\n").unwrap();

        let now = Instant::now();
        let policy = policy(
            PolicySpec {
                blocked_file: path,
                subscription_blocklist: vec!["sub.example".to_string()],
                ..PolicySpec::default()
            },
            now,
        );
        let eff = policy.blocked_domains(now);
        assert!(is_blocked_in_list("local.example", &eff), "local kept");
        assert!(
            is_blocked_in_list("sub.example", &eff),
            "subscription added"
        );
        // Exact-or-subdomain matcher still applies to subscription domains.
        assert!(is_blocked_in_list("host.sub.example", &eff));
        assert!(!is_blocked_in_list("allowed.example", &eff));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn empty_subscription_blocklist_is_noop() {
        // No-regression: empty subscription list → exactly the file domains,
        // byte-identical to today's behaviour.
        let dir = test_dir("subscription-noop");
        let path = dir.join("blocked.txt");
        std::fs::write(&path, "local.example\n").unwrap();

        let now = Instant::now();
        let policy = policy(
            PolicySpec {
                blocked_file: path,
                ..PolicySpec::default()
            },
            now,
        );
        assert_eq!(
            policy.blocked_domains(now),
            vec!["local.example".to_string()]
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    // ── Allowlist ───────────────────────────────────────────────────────

    #[test]
    fn allowlist_empty_when_nothing_is_configured() {
        // No file, no initial domains, no agent defaults => allow-all.
        let now = Instant::now();
        let policy = policy(PolicySpec::default(), now);
        assert!(policy.allowed_domains(now).is_empty());
    }

    #[test]
    fn allowlist_falls_back_to_initial_until_the_file_exists() {
        let dir = test_dir("allowlist-initial");
        let path = dir.join("not-written-yet.txt");

        let now = Instant::now();
        let policy = policy(
            PolicySpec {
                allowed_domains_file: Some(path.clone()),
                allowed_domains_initial: vec!["github.com".to_string()],
                ..PolicySpec::default()
            },
            now,
        );
        assert_eq!(policy.allowed_domains(now), vec!["github.com"]);

        // Once written, the file takes over at the next refresh.
        std::fs::write(&path, "internal.example.com\n").unwrap();
        assert_eq!(
            policy.allowed_domains(stale(now)),
            vec!["internal.example.com"]
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn allowlist_reloads_from_file() {
        let dir = test_dir("allowlist-reload");
        let path = dir.join("allowed.txt");
        std::fs::write(&path, "github.com\n").unwrap();

        let now = Instant::now();
        let policy = policy(
            PolicySpec {
                allowed_domains_file: Some(path.clone()),
                ..PolicySpec::default()
            },
            now,
        );
        assert_eq!(policy.allowed_domains(now), vec!["github.com"]);

        std::fs::write(&path, "github.com\nnpm.pkg.github.com\n").unwrap();
        assert!(
            policy
                .allowed_domains(stale(now))
                .contains(&"npm.pkg.github.com".to_string())
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn default_allowlist_merges_and_fails_closed() {
        let defaults: Vec<String> = crate::agent::Agent::Copilot
            .default_allowed_domains()
            .iter()
            .map(ToString::to_string)
            .collect();
        let now = Instant::now();
        let policy = policy(
            PolicySpec {
                default_allowlist: defaults,
                ..PolicySpec::default()
            },
            now,
        );
        let eff = policy.allowed_domains(now);
        // Non-empty => the BLOCKED-ALLOWLIST gate fail-closes on unknown domains.
        assert!(!eff.is_empty(), "default allowlist must be enforced");
        for d in ["github.com", "api.github.com", "registry.npmjs.org"] {
            assert!(is_domain_match(d, &eff), "{d} must be allowed");
        }
        // Bare `githubcopilot.com` covers the `*.githubcopilot.com` subdomain.
        assert!(is_domain_match("api.githubcopilot.com", &eff));
        // Everything else is blocked.
        assert!(!is_domain_match("evil.com", &eff));
    }

    #[test]
    fn default_allowlist_merges_user_configured_domain() {
        let dir = test_dir("default-allowlist-merge");
        let path = dir.join("allowed.txt");
        std::fs::write(&path, "internal.example.com\n").unwrap();

        let now = Instant::now();
        let policy = policy(
            PolicySpec {
                default_allowlist: vec!["github.com".to_string()],
                allowed_domains_file: Some(path),
                ..PolicySpec::default()
            },
            now,
        );
        let eff = policy.allowed_domains(now);
        assert!(is_domain_match("github.com", &eff), "agent default kept");
        assert!(
            is_domain_match("internal.example.com", &eff),
            "user-configured domain must be merged in"
        );
        assert!(!is_domain_match("evil.com", &eff));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn empty_default_allowlist_is_allow_all_no_regression() {
        // CRITICAL no-regression check: feature off (empty default_allowlist)
        // and no file => empty effective allowlist => allow-all, exactly as
        // before this change. `handle_connect` treats empty as "no allowlist".
        let now = Instant::now();
        let policy = policy(PolicySpec::default(), now);
        assert!(
            policy.allowed_domains(now).is_empty(),
            "default off must remain allow-all"
        );
    }

    // ── Private domains ─────────────────────────────────────────────────

    #[test]
    fn private_domains_merge_cli_and_config() {
        let now = Instant::now();
        let policy = policy(
            PolicySpec {
                cli_private_domains: vec!["cli.example.com".to_string()],
                config_private_domains: vec!["config.example.com".to_string()],
                ..PolicySpec::default()
            },
            now,
        );
        let domains = policy.private_domains(now);
        assert!(domains.contains(&"cli.example.com".to_string()));
        assert!(domains.contains(&"config.example.com".to_string()));
    }

    #[test]
    fn private_domains_deduplicate() {
        let now = Instant::now();
        let policy = policy(
            PolicySpec {
                cli_private_domains: vec!["shared.com".to_string()],
                config_private_domains: vec!["shared.com".to_string()],
                ..PolicySpec::default()
            },
            now,
        );
        assert_eq!(
            policy
                .private_domains(now)
                .iter()
                .filter(|d| *d == "shared.com")
                .count(),
            1,
            "duplicates should be removed"
        );
    }

    /// #186: private domains whose source is read once — CLI flags and
    /// trust-approved `[propose.proxy] allow_private_domains` from the repo
    /// `.cplt.toml` — must survive the global config file's 5-second reload,
    /// while domains that file actually supplies keep following it (including
    /// being revoked when removed).
    #[test]
    fn private_domain_sources_survive_or_follow_the_config_reload() {
        let dir = test_dir("private-domains-186");
        let config_path = dir.join("config.toml");
        // Multi-line array: the form `cplt init` writes for >1 entry
        // (`init::write_string_array`), and the form the docs show.
        std::fs::write(
            &config_path,
            "[allow]\nread = [\"~/.kube/config\"]\n\n[proxy]\nallow_private_domains = [\n  \"global-a.nav.no\",\n  \"global-b.nav.no\",\n]\n",
        )
        .unwrap();

        // Built the way main.rs builds it: the resolved set (CLI + config file +
        // trust-approved repo proposal) minus the two once-read sources, which
        // it passes as their own fields. Hand-writing the reloadable list would
        // test a shape the real wiring never produces.
        let cli_private_domains = vec!["cli.nav.no".to_string()];
        let repo_private_domains = vec!["mimir.nav.cloud.nais.io".to_string()];
        let resolved_private_domains = [
            "cli.nav.no",
            "global-a.nav.no",
            "global-b.nav.no",
            "mimir.nav.cloud.nais.io",
        ];
        let config_private_domains: Vec<String> = resolved_private_domains
            .iter()
            .map(|d| (*d).to_string())
            .filter(|d| {
                !cli_private_domains
                    .iter()
                    .any(|c| normalize_hostname(c) == *d)
                    && !repo_private_domains.contains(d)
            })
            .collect();
        assert_eq!(
            config_private_domains,
            vec!["global-a.nav.no", "global-b.nav.no"],
            "only the config file's own entries are reloadable"
        );

        let start = Instant::now();
        let policy = policy(
            PolicySpec {
                cli_private_domains,
                config_private_domains,
                repo_private_domains,
                config_file: Some(config_path.clone()),
                ..PolicySpec::default()
            },
            start,
        );

        // Each `expire()` advances the clock past another TTL window, which is
        // exactly the refresh a long-running session sees every 5 seconds.
        let mut clock = start;
        let mut expire = || {
            clock = stale(clock);
            clock
        };
        let has = |now: Instant, d: &str| policy.private_domains(now).iter().any(|x| x == d);

        for d in [
            "cli.nav.no",
            "global-a.nav.no",
            "global-b.nav.no",
            "mimir.nav.cloud.nais.io",
        ] {
            assert!(has(start, d), "{d} must be allowed at startup");
        }

        // The reload that fires 5 seconds into a real session.
        let t = expire();
        assert!(
            has(t, "mimir.nav.cloud.nais.io"),
            "trust-approved repo domain must survive the config reload"
        );
        assert!(has(t, "cli.nav.no"), "CLI domain must survive the reload");
        assert!(
            has(t, "global-a.nav.no") && has(t, "global-b.nav.no"),
            "multi-line config array must still be read on reload"
        );

        // Revoking one entry from the config file takes effect within the TTL.
        std::fs::write(
            &config_path,
            "[proxy]\nallow_private_domains = [\"global-a.nav.no\"]  # b revoked\n",
        )
        .unwrap();
        let t = expire();
        assert!(has(t, "global-a.nav.no"), "remaining config entry stays");
        assert!(
            !has(t, "global-b.nav.no"),
            "config-file domain must be revocable by editing the file"
        );
        assert!(has(t, "mimir.nav.cloud.nais.io") && has(t, "cli.nav.no"));

        // Dropping the section revokes the rest of the file's entries.
        std::fs::write(&config_path, "[allow]\nread = []\n").unwrap();
        let t = expire();
        assert!(
            !has(t, "global-a.nav.no"),
            "removing the section must revoke its domains"
        );
        assert!(
            has(t, "mimir.nav.cloud.nais.io") && has(t, "cli.nav.no"),
            "once-read sources are not revoked by a config edit"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }
}
