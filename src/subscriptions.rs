//! Subscribable blocklists (issue #144, Phase 1 — blocklist subscriptions only).
//!
//! A *blocklist subscription* keeps a local cache file fresh from a maintained
//! upstream URL (e.g. cplt's own `blocked-domains.txt`). The cached domains are
//! UNIONed into the effective blocklist alongside the local `blocked_domains`
//! file and the built-in `blocked-domains.txt` — they are purely additive.
//!
//! # Security model (why this is the low-risk tier)
//!
//! Blocklists are **tighten-only**: the worst case of a bad, stale, or failed
//! blocklist is that a domain *isn't* blocked — no worse than today. There is no
//! way for a blocklist subscription to *widen* egress. Therefore:
//!
//! - **Fail-open is acceptable.** On fetch failure we keep and use the last-good
//!   cache; if there is no cache we treat the subscription as empty (empty = no
//!   extra blocks = byte-identical to not having the subscription at all). The
//!   run is NEVER blocked on the network beyond a bounded timeout.
//! - **Integrity is encouraged, not required.** A subscription entry may pin a
//!   `sha256`. When pinned, a hash mismatch REJECTS the downloaded copy (keeping
//!   the last-good cache) and warns loudly about possible tampering — reusing the
//!   verification discipline of `update.rs`. Unpinned blocklists still load,
//!   because tighten-only means an unverified blocklist cannot open exfil.
//! - **Repo config can NOT add a subscription.** Subscriptions are GLOBAL-only
//!   (`~/.config/cplt/config.toml`); the repo config schema (`.cplt.toml`) has no
//!   `[proxy]` table at all, so a malicious repo cannot point cplt at an attacker
//!   list.
//! - **The cache lives outside the agent's writable set.** Caches are written to
//!   the cplt config directory (`~/.config/cplt/subscriptions/`) by the parent
//!   process BEFORE the sandbox is entered. The sandboxed agent cannot write
//!   there, so it cannot poison the cache mid-session.
//!
//! Allowlist subscriptions (which DEFINE what is permitted and are therefore
//! security-critical, fail-closed, verification-required) are explicitly **out of
//! scope** for this module — they are a separate future feature (#144 Phase 2).

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Bounded per-fetch timeout (seconds) for the explicit `cplt update-lists`
/// path. The run must never hang on the network.
const FETCH_TIMEOUT_SECS: u64 = 20;

/// Much shorter per-fetch timeout (seconds) for the *lazy* pre-run refresh path.
/// Startup must not stall on a black-holed host, so the lazy path uses a tight
/// budget and degrades to the last-good cache; only the explicit `update-lists`
/// path gets the full [`FETCH_TIMEOUT_SECS`] timeout.
const LAZY_FETCH_TIMEOUT_SECS: u64 = 5;

/// Hard ceiling on a fetched blocklist response (bytes). A 1M-domain blocklist
/// is ~20 MB, so 50 MB is a safe, generous cap. Enforced two ways: `curl` aborts
/// early via `--max-filesize` when the server sends a `Content-Length`, and we
/// additionally cap the bytes we actually read/buffer (for chunked or
/// unknown-length responses `--max-filesize` is skipped) so a malicious or
/// MITM'd host cannot stream multi-GB within the timeout and OOM-kill the parent
/// — nor slip an oversize body past a pinned-hash check by forcing us to buffer
/// the whole body before it is hashed.
const MAX_FETCH_BYTES: u64 = 50 * 1024 * 1024;

/// Warn about a cache that has not been refreshed in this long.
const STALE_WARN: Duration = Duration::from_secs(30 * 24 * 60 * 60);

/// How often lazily-refreshed subscriptions are re-fetched before a run.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RefreshInterval {
    /// Never auto-refresh; only `cplt update-lists` fetches (default).
    Manual,
    /// Refresh caches older than 24h before a run.
    Daily,
    /// Refresh caches older than 7 days before a run.
    Weekly,
}

impl RefreshInterval {
    /// Parse the `refresh` config value. Defaults to `Manual`.
    pub fn parse(s: &str) -> Result<Self, String> {
        match s.trim().to_ascii_lowercase().as_str() {
            "manual" => Ok(Self::Manual),
            "daily" => Ok(Self::Daily),
            "weekly" => Ok(Self::Weekly),
            other => Err(format!(
                "invalid refresh value {other:?}: expected \"manual\", \"daily\", or \"weekly\""
            )),
        }
    }

    /// Maximum cache age before a lazy refresh is due. `None` = never (manual).
    fn max_age(self) -> Option<Duration> {
        match self {
            Self::Manual => None,
            Self::Daily => Some(Duration::from_secs(24 * 60 * 60)),
            Self::Weekly => Some(Duration::from_secs(7 * 24 * 60 * 60)),
        }
    }
}

impl std::fmt::Display for RefreshInterval {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Manual => "manual",
            Self::Daily => "daily",
            Self::Weekly => "weekly",
        })
    }
}

/// A single blocklist subscription source.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlocklistSubscription {
    /// The URL the list is fetched from (https:// or, in tests, file://).
    pub url: String,
    /// Optional pinned SHA256 (lowercase hex). When set, a mismatch REJECTS the
    /// downloaded copy and keeps the last-good cache (tamper protection).
    pub sha256: Option<String>,
}

/// A resolved set of blocklist subscriptions plus the cache location.
#[derive(Clone, Debug)]
pub struct SubscriptionSet {
    pub refresh: RefreshInterval,
    pub blocklists: Vec<BlocklistSubscription>,
    /// Directory holding cache files + `state.json`. Lives OUTSIDE the sandbox's
    /// writable set (the cplt config dir), so the agent cannot poison it.
    pub cache_dir: PathBuf,
}

impl SubscriptionSet {
    /// True when no blocklist subscriptions are configured. When empty, cplt's
    /// networking behaviour is byte-identical to having no subscriptions at all.
    pub fn is_empty(&self) -> bool {
        self.blocklists.is_empty()
    }
}

/// The outcome of attempting to fetch/verify one subscription.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UpdateOutcome {
    /// Fetched and cached `domains` entries. `verified` = a pinned hash matched.
    Fetched {
        url: String,
        domains: usize,
        verified: bool,
    },
    /// Fetch failed but a last-good cache exists and is still used.
    CacheKept { url: String, reason: String },
    /// Pinned hash mismatch — download REJECTED, last-good cache kept.
    VerifyFailed {
        url: String,
        expected: String,
        actual: String,
    },
    /// Fetch failed and there is no cache — treated as empty (safe, tighten-only).
    EmptyNoCache { url: String, reason: String },
    /// Fetched OK but the cache could not be persisted (dir create / atomic write
    /// failed). The last-good cache (if any) is kept and the state timestamp is
    /// NOT advanced, so the next run retries instead of treating an unwritten
    /// cache as "fresh".
    WriteFailed { url: String, reason: String },
}

impl UpdateOutcome {
    /// The subscription URL this outcome refers to.
    pub fn url(&self) -> &str {
        match self {
            Self::Fetched { url, .. }
            | Self::CacheKept { url, .. }
            | Self::VerifyFailed { url, .. }
            | Self::EmptyNoCache { url, .. }
            | Self::WriteFailed { url, .. } => url,
        }
    }

    /// Whether this outcome indicates a verification (tamper) failure.
    pub fn is_verify_failure(&self) -> bool {
        matches!(self, Self::VerifyFailed { .. })
    }
}

/// A network fetcher: URL → bytes, or an error string. Injectable so the
/// verify/cache/merge/staleness logic is unit-testable WITHOUT real network.
pub type Fetcher<'a> = dyn Fn(&str) -> Result<Vec<u8>, String> + 'a;

/// Default fetcher: download `url` with `/usr/bin/curl` (absolute path, bounded
/// timeout, https-only redirects). Mirrors the download discipline of
/// `update.rs`. Runs in cplt's parent process, OUTSIDE the sandbox.
pub fn curl_fetch(url: &str) -> Result<Vec<u8>, String> {
    curl_fetch_inner(url, FETCH_TIMEOUT_SECS)
}

/// Lazy-path fetcher: same download discipline as [`curl_fetch`] but with the
/// tight [`LAZY_FETCH_TIMEOUT_SECS`] budget so a stale-cache refresh before a run
/// cannot stall startup on a slow or black-holed host.
pub fn curl_fetch_lazy(url: &str) -> Result<Vec<u8>, String> {
    curl_fetch_inner(url, LAZY_FETCH_TIMEOUT_SECS)
}

/// Build the `curl` argument vector for `url`. Only https:// is fetched in
/// production; file:// is permitted so operators can point at a locally-mirrored
/// list (and tests use it). The `--` end-of-options marker is placed immediately
/// before the URL so a value beginning with `-` (e.g. `-K/curlrc`, `--output x`)
/// is always treated as the positional URL, never parsed as a curl flag.
fn curl_args(url: &str, timeout_secs: u64) -> Vec<String> {
    vec![
        "--fail".into(),
        "--silent".into(),
        "--show-error".into(),
        "--location".into(),
        "--proto".into(),
        "=https,file".into(),
        "--proto-redir".into(),
        "=https".into(),
        "--max-time".into(),
        timeout_secs.to_string(),
        "--max-filesize".into(),
        MAX_FETCH_BYTES.to_string(),
        "--header".into(),
        format!("User-Agent: cplt/{}", env!("CARGO_PKG_VERSION")),
        "--".into(),
        url.to_string(),
    ]
}

/// Fetch with an explicit timeout. Streams `curl`'s stdout through a hard byte
/// ceiling ([`MAX_FETCH_BYTES`]): `--max-filesize` aborts early only when the
/// server sends a `Content-Length`, so we ALSO stop reading the moment the body
/// exceeds the cap and kill `curl`, guaranteeing the parent never buffers a
/// multi-GB size bomb (which would OOM-kill cplt and defeat a pinned-hash check
/// that must see the whole body first).
fn curl_fetch_inner(url: &str, timeout_secs: u64) -> Result<Vec<u8>, String> {
    let mut child = Command::new("/usr/bin/curl")
        .args(curl_args(url, timeout_secs))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("cannot run /usr/bin/curl: {e}"))?;

    // Read at most MAX_FETCH_BYTES + 1: if we get that many, the body is over the
    // cap. `--silent` keeps stderr tiny (only errors), so reading stdout to EOF
    // before draining stderr cannot deadlock on a full stderr pipe.
    let mut stdout = child.stdout.take().expect("stdout is piped");
    let mut buf = Vec::new();
    let read_res = stdout
        .by_ref()
        .take(MAX_FETCH_BYTES + 1)
        .read_to_end(&mut buf);

    if read_res.is_err() || buf.len() as u64 > MAX_FETCH_BYTES {
        let _ = child.kill();
        let _ = child.wait();
        return Err(format!(
            "response exceeds the {MAX_FETCH_BYTES}-byte limit, refusing it (possible size bomb)"
        ));
    }

    let status = child
        .wait()
        .map_err(|e| format!("curl did not exit cleanly: {e}"))?;

    if status.success() {
        Ok(buf)
    } else {
        let mut stderr = String::new();
        if let Some(mut err) = child.stderr.take() {
            let _ = err.read_to_string(&mut stderr);
        }
        Err(stderr.trim().to_string())
    }
}

/// Compute the lowercase-hex SHA256 of `bytes`.
fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Deterministic cache filename for a subscription URL. Uses a hash of the URL
/// so arbitrary URLs map to safe, collision-resistant filenames.
fn cache_filename(url: &str) -> String {
    let hash = sha256_hex(url.as_bytes());
    format!("{}.list", &hash[..16])
}

/// Absolute path of the cache file for `url` under `cache_dir`.
fn cache_path(cache_dir: &Path, url: &str) -> PathBuf {
    cache_dir.join(cache_filename(url))
}

/// Parse a one-domain-per-line blocklist into normalized bare domains.
///
/// Mirrors `proxy`'s blocklist normalization (trim, lowercase, strip a trailing
/// dot, skip blank and `#` comment lines) so subscription domains match exactly
/// like the local blocklist file and built-in list under the existing
/// exact-or-subdomain matcher.
pub fn parse_blocklist(contents: &str) -> Vec<String> {
    contents
        .lines()
        .map(|l| l.trim().to_lowercase().trim_end_matches('.').to_string())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect()
}

/// Load and UNION the cached domains from every configured blocklist
/// subscription. Missing caches are skipped (fail-open: empty = safe). This is
/// what the proxy merges into the effective blocklist at startup.
///
/// Returns an empty vec when no subscriptions are configured — so with nothing
/// configured the effective blocklist is unchanged from today.
pub fn load_cached_domains(set: &SubscriptionSet) -> Vec<String> {
    let mut domains: Vec<String> = Vec::new();
    for sub in &set.blocklists {
        let path = cache_path(&set.cache_dir, &sub.url);
        if let Ok(contents) = std::fs::read_to_string(&path) {
            domains.extend(parse_blocklist(&contents));
        }
    }
    domains.sort_unstable();
    domains.dedup();
    domains
}

// ── Persistent per-subscription metadata (last-fetch time) ───────────────────

#[derive(Serialize, Deserialize, Default)]
struct State {
    #[serde(default)]
    subscriptions: Vec<StateEntry>,
}

#[derive(Serialize, Deserialize, Clone)]
struct StateEntry {
    url: String,
    /// Unix seconds of the last successful fetch+cache.
    last_fetch_secs: u64,
    /// Number of domains in that cache.
    domains: usize,
}

impl State {
    fn path(cache_dir: &Path) -> PathBuf {
        cache_dir.join("state.json")
    }

    fn load(cache_dir: &Path) -> Self {
        std::fs::read_to_string(Self::path(cache_dir))
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default()
    }

    fn save(&self, cache_dir: &Path) {
        if std::fs::create_dir_all(cache_dir).is_err() {
            return;
        }
        if let Ok(json) = serde_json::to_string_pretty(self) {
            let _ = write_atomic(&Self::path(cache_dir), json.as_bytes());
        }
    }

    fn get(&self, url: &str) -> Option<&StateEntry> {
        self.subscriptions.iter().find(|e| e.url == url)
    }

    fn set(&mut self, url: &str, last_fetch_secs: u64, domains: usize) {
        if let Some(entry) = self.subscriptions.iter_mut().find(|e| e.url == url) {
            entry.last_fetch_secs = last_fetch_secs;
            entry.domains = domains;
        } else {
            self.subscriptions.push(StateEntry {
                url: url.to_string(),
                last_fetch_secs,
                domains,
            });
        }
    }
}

/// Write `bytes` to `path` atomically (write temp + rename) so a crash mid-write
/// never leaves a truncated cache that would be parsed as a partial blocklist.
fn write_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, bytes)?;
    std::fs::rename(&tmp, path)
}

fn unix_secs(now: SystemTime) -> u64 {
    now.duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

/// Fetch, verify, and cache a single subscription. On any failure the last-good
/// cache is preserved (never deleted). Returns a per-list outcome for reporting.
fn update_one(
    set: &SubscriptionSet,
    sub: &BlocklistSubscription,
    fetch: &Fetcher,
    now: SystemTime,
    state: &mut State,
) -> UpdateOutcome {
    let path = cache_path(&set.cache_dir, &sub.url);
    let cache_exists = path.exists();

    let bytes = match fetch(&sub.url) {
        Ok(b) => b,
        Err(reason) => {
            // Fail-open: keep last-good cache, or treat as empty if none.
            return if cache_exists {
                UpdateOutcome::CacheKept {
                    url: sub.url.clone(),
                    reason,
                }
            } else {
                UpdateOutcome::EmptyNoCache {
                    url: sub.url.clone(),
                    reason,
                }
            };
        }
    };

    // Hard size ceiling, enforced BEFORE hashing or caching. `curl_fetch` already
    // caps its streamed read, but re-check here so any fetcher (incl. a mirror or
    // test double) cannot slip an oversize body past the pinned-hash check or into
    // the cache. Oversize is rejected fail-open: the last-good cache is preserved.
    if bytes.len() as u64 > MAX_FETCH_BYTES {
        let reason = format!(
            "response is {} bytes, over the {MAX_FETCH_BYTES}-byte limit, so cplt rejected it",
            bytes.len()
        );
        return if cache_exists {
            UpdateOutcome::CacheKept {
                url: sub.url.clone(),
                reason,
            }
        } else {
            UpdateOutcome::EmptyNoCache {
                url: sub.url.clone(),
                reason,
            }
        };
    }

    // Optional integrity check. A mismatch REJECTS the update and keeps the
    // last-good cache — the tamper-refuse behaviour of update.rs.
    let mut verified = false;
    if let Some(expected) = &sub.sha256 {
        let expected = expected.trim().to_ascii_lowercase();
        let actual = sha256_hex(&bytes);
        if actual != expected {
            return UpdateOutcome::VerifyFailed {
                url: sub.url.clone(),
                expected,
                actual,
            };
        }
        verified = true;
    }

    let domains = parse_blocklist(&String::from_utf8_lossy(&bytes)).len();

    // Persist the cache atomically, and record the fetch timestamp ONLY after the
    // write is confirmed. If the dir create or atomic write fails we leave the
    // prior timestamp untouched so the next run retries, rather than advancing the
    // clock and skipping a re-fetch while serving a stale/absent cache.
    let write_ok =
        std::fs::create_dir_all(&set.cache_dir).is_ok() && write_atomic(&path, &bytes).is_ok();
    if !write_ok {
        return UpdateOutcome::WriteFailed {
            url: sub.url.clone(),
            reason: "could not write cache file, keeping prior state, next run retries".to_string(),
        };
    }

    state.set(&sub.url, unix_secs(now), domains);

    UpdateOutcome::Fetched {
        url: sub.url.clone(),
        domains,
        verified,
    }
}

/// Fetch + verify + cache ALL configured blocklist subscriptions (the explicit
/// `cplt update-lists` refresh path). Returns a per-list outcome.
pub fn update_all(set: &SubscriptionSet, fetch: &Fetcher, now: SystemTime) -> Vec<UpdateOutcome> {
    let mut state = State::load(&set.cache_dir);
    let outcomes: Vec<UpdateOutcome> = set
        .blocklists
        .iter()
        .map(|sub| update_one(set, sub, fetch, now, &mut state))
        .collect();
    state.save(&set.cache_dir);
    outcomes
}

/// Whether a subscription is due for a lazy refresh: no cache yet, or the cache
/// is older than the refresh interval. `Manual` is never due.
fn is_due(
    set: &SubscriptionSet,
    sub: &BlocklistSubscription,
    state: &State,
    now: SystemTime,
) -> bool {
    let Some(max_age) = set.refresh.max_age() else {
        return false;
    };
    if !cache_path(&set.cache_dir, &sub.url).exists() {
        return true;
    }
    match state.get(&sub.url) {
        Some(entry) => {
            let age = unix_secs(now).saturating_sub(entry.last_fetch_secs);
            age >= max_age.as_secs()
        }
        // Cache exists but no metadata — refresh to establish a timestamp.
        None => true,
    }
}

/// Lazy pre-run refresh: when `refresh != manual`, re-fetch AT MOST ONE stale
/// subscription before the run, using the short lazy timeout supplied by the
/// caller. Fails over to the cache — never blocks or fails the run.
///
/// # Startup-stall budget
///
/// A stale cache must not turn startup into an `N * timeout` stall: with N
/// black-holed hosts, refreshing them all sequentially before every run could
/// hang for minutes. So the lazy path spends a single small budget per run — it
/// refreshes only the FIRST due subscription and stops. Remaining stale lists are
/// picked up one-per-run on subsequent invocations, and every one degrades to the
/// last-good cache on failure. The explicit `cplt update-lists` path
/// ([`update_all`]) still refreshes every list with the full timeout.
///
/// Returns outcomes for the (at most one) refreshed entry, or empty when nothing
/// was due or refresh is manual.
pub fn refresh_if_stale(
    set: &SubscriptionSet,
    fetch: &Fetcher,
    now: SystemTime,
) -> Vec<UpdateOutcome> {
    if set.refresh == RefreshInterval::Manual {
        return Vec::new();
    }
    let mut state = State::load(&set.cache_dir);
    let mut outcomes = Vec::new();
    for sub in &set.blocklists {
        if is_due(set, sub, &state, now) {
            outcomes.push(update_one(set, sub, fetch, now, &mut state));
            // Spend the whole per-run lazy budget on this one list; the rest wait
            // for future runs so startup can never stall on many dead hosts.
            break;
        }
    }
    if !outcomes.is_empty() {
        state.save(&set.cache_dir);
    }
    outcomes
}

/// One-line warnings for caches that have never been fetched or are older than
/// the stale threshold. Purely advisory (tighten-only: stale = safe).
pub fn staleness_warnings(set: &SubscriptionSet, now: SystemTime) -> Vec<String> {
    let state = State::load(&set.cache_dir);
    let mut warnings = Vec::new();
    for sub in &set.blocklists {
        let cache_exists = cache_path(&set.cache_dir, &sub.url).exists();
        if !cache_exists {
            warnings.push(format!(
                "blocklist subscription {} has never been fetched. Run `cplt update-lists`",
                sub.url
            ));
            continue;
        }
        if let Some(entry) = state.get(&sub.url) {
            let age = unix_secs(now).saturating_sub(entry.last_fetch_secs);
            if age >= STALE_WARN.as_secs() {
                let days = age / (24 * 60 * 60);
                warnings.push(format!(
                    "blocklist subscription {} cache is {days} days old. Run `cplt update-lists`",
                    sub.url
                ));
            }
        }
    }
    warnings
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set_with(
        dir: &Path,
        refresh: RefreshInterval,
        subs: Vec<BlocklistSubscription>,
    ) -> SubscriptionSet {
        SubscriptionSet {
            refresh,
            blocklists: subs,
            cache_dir: dir.to_path_buf(),
        }
    }

    fn sub(url: &str, sha: Option<&str>) -> BlocklistSubscription {
        BlocklistSubscription {
            url: url.to_string(),
            sha256: sha.map(str::to_string),
        }
    }

    #[test]
    fn refresh_interval_parse() {
        assert_eq!(
            RefreshInterval::parse("manual").unwrap(),
            RefreshInterval::Manual
        );
        assert_eq!(
            RefreshInterval::parse("Daily").unwrap(),
            RefreshInterval::Daily
        );
        assert_eq!(
            RefreshInterval::parse(" weekly ").unwrap(),
            RefreshInterval::Weekly
        );
        assert!(RefreshInterval::parse("hourly").is_err());
    }

    #[test]
    fn parse_blocklist_normalizes() {
        let raw = "# comment\nEvil.COM\n\n  bad.example.  \nfoo.test\n";
        let got = parse_blocklist(raw);
        assert_eq!(got, vec!["evil.com", "bad.example", "foo.test"]);
    }

    #[test]
    fn sha256_matches_known_vector() {
        // echo -n "abc" | sha256sum
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn update_all_fetches_and_caches() {
        let dir = tempfile::tempdir().unwrap();
        let set = set_with(
            dir.path(),
            RefreshInterval::Manual,
            vec![sub("mem://a", None)],
        );
        let fetch = |_url: &str| Ok(b"evil.com\nbad.test\n".to_vec());
        let outcomes = update_all(&set, &fetch, SystemTime::now());
        assert_eq!(outcomes.len(), 1);
        assert!(matches!(
            outcomes[0],
            UpdateOutcome::Fetched {
                domains: 2,
                verified: false,
                ..
            }
        ));
        // Cached domains load and merge.
        let domains = load_cached_domains(&set);
        assert_eq!(domains, vec!["bad.test", "evil.com"]);
    }

    #[test]
    fn sha256_verify_success() {
        let dir = tempfile::tempdir().unwrap();
        let body = b"evil.com\n".to_vec();
        let hash = sha256_hex(&body);
        let set = set_with(
            dir.path(),
            RefreshInterval::Manual,
            vec![sub("mem://a", Some(&hash))],
        );
        let outcomes = update_all(&set, &|_| Ok(body.clone()), SystemTime::now());
        assert!(matches!(
            outcomes[0],
            UpdateOutcome::Fetched { verified: true, .. }
        ));
        assert_eq!(load_cached_domains(&set), vec!["evil.com"]);
    }

    #[test]
    fn sha256_mismatch_rejects_and_keeps_cache() {
        let dir = tempfile::tempdir().unwrap();
        // First: a good fetch establishes a last-good cache.
        let set_good = set_with(
            dir.path(),
            RefreshInterval::Manual,
            vec![sub("mem://a", None)],
        );
        update_all(
            &set_good,
            &|_| Ok(b"good.com\n".to_vec()),
            SystemTime::now(),
        );
        assert_eq!(load_cached_domains(&set_good), vec!["good.com"]);

        // Now: a pinned subscription whose fetched bytes don't match the hash.
        let set_pinned = set_with(
            dir.path(),
            RefreshInterval::Manual,
            vec![sub("mem://a", Some(&"0".repeat(64)))],
        );
        let outcomes = update_all(
            &set_pinned,
            &|_| Ok(b"tampered.com\n".to_vec()),
            SystemTime::now(),
        );
        assert!(outcomes[0].is_verify_failure());
        // Last-good cache is UNCHANGED — the tampered copy was rejected.
        assert_eq!(load_cached_domains(&set_pinned), vec!["good.com"]);
    }

    #[test]
    fn fetch_failure_keeps_last_good_cache() {
        let dir = tempfile::tempdir().unwrap();
        let set = set_with(
            dir.path(),
            RefreshInterval::Manual,
            vec![sub("mem://a", None)],
        );
        update_all(&set, &|_| Ok(b"good.com\n".to_vec()), SystemTime::now());

        let outcomes = update_all(&set, &|_| Err("offline".to_string()), SystemTime::now());
        assert!(matches!(outcomes[0], UpdateOutcome::CacheKept { .. }));
        assert_eq!(load_cached_domains(&set), vec!["good.com"]);
    }

    #[test]
    fn fetch_failure_no_cache_is_empty() {
        let dir = tempfile::tempdir().unwrap();
        let set = set_with(
            dir.path(),
            RefreshInterval::Manual,
            vec![sub("mem://a", None)],
        );
        let outcomes = update_all(&set, &|_| Err("offline".to_string()), SystemTime::now());
        assert!(matches!(outcomes[0], UpdateOutcome::EmptyNoCache { .. }));
        assert!(load_cached_domains(&set).is_empty());
    }

    #[test]
    fn no_subscriptions_is_empty_and_noop() {
        let dir = tempfile::tempdir().unwrap();
        let set = set_with(dir.path(), RefreshInterval::Manual, vec![]);
        assert!(set.is_empty());
        assert!(load_cached_domains(&set).is_empty());
        assert!(update_all(&set, &|_| Ok(vec![]), SystemTime::now()).is_empty());
        assert!(refresh_if_stale(&set, &|_| Ok(vec![]), SystemTime::now()).is_empty());
    }

    #[test]
    fn manual_refresh_never_lazy_fetches() {
        let dir = tempfile::tempdir().unwrap();
        let set = set_with(
            dir.path(),
            RefreshInterval::Manual,
            vec![sub("mem://a", None)],
        );
        // No cache, but manual → refresh_if_stale does nothing.
        let outcomes = refresh_if_stale(
            &set,
            &|_| panic!("must not fetch under manual"),
            SystemTime::now(),
        );
        assert!(outcomes.is_empty());
    }

    #[test]
    fn lazy_refresh_fetches_when_stale() {
        let dir = tempfile::tempdir().unwrap();
        let set = set_with(
            dir.path(),
            RefreshInterval::Daily,
            vec![sub("mem://a", None)],
        );
        let t0 = UNIX_EPOCH + Duration::from_secs(1_000_000);
        // First refresh: no cache → due.
        let o1 = refresh_if_stale(&set, &|_| Ok(b"a.com\n".to_vec()), t0);
        assert_eq!(o1.len(), 1);

        // Shortly after: cache is fresh → not due.
        let t1 = t0 + Duration::from_secs(60 * 60);
        let o2 = refresh_if_stale(&set, &|_| panic!("should not refetch a fresh cache"), t1);
        assert!(o2.is_empty());

        // Two days later: cache is stale → due again.
        let t2 = t0 + Duration::from_secs(2 * 24 * 60 * 60);
        let o3 = refresh_if_stale(&set, &|_| Ok(b"a.com\nb.com\n".to_vec()), t2);
        assert_eq!(o3.len(), 1);
        assert_eq!(load_cached_domains(&set), vec!["a.com", "b.com"]);
    }

    #[test]
    fn staleness_warning_for_never_fetched() {
        let dir = tempfile::tempdir().unwrap();
        let set = set_with(
            dir.path(),
            RefreshInterval::Manual,
            vec![sub("mem://a", None)],
        );
        let warns = staleness_warnings(&set, SystemTime::now());
        assert_eq!(warns.len(), 1);
        assert!(warns[0].contains("never been fetched"));
    }

    #[test]
    fn staleness_warning_for_old_cache() {
        let dir = tempfile::tempdir().unwrap();
        let set = set_with(
            dir.path(),
            RefreshInterval::Manual,
            vec![sub("mem://a", None)],
        );
        let t0 = UNIX_EPOCH + Duration::from_secs(1_000_000);
        update_all(&set, &|_| Ok(b"a.com\n".to_vec()), t0);
        // 40 days later.
        let later = t0 + Duration::from_secs(40 * 24 * 60 * 60);
        let warns = staleness_warnings(&set, later);
        assert_eq!(warns.len(), 1);
        assert!(warns[0].contains("days old"));
    }

    #[test]
    fn file_url_fetch_via_curl() {
        // Exercises the real curl fetcher against a local file:// URL — no network.
        let dir = tempfile::tempdir().unwrap();
        let list = dir.path().join("list.txt");
        std::fs::write(&list, "curl.example\n").unwrap();
        let url = format!("file://{}", list.display());
        if let Ok(bytes) = curl_fetch(&url) {
            assert_eq!(String::from_utf8_lossy(&bytes).trim(), "curl.example");
        }
        // curl may be unavailable in some CI images; a fetch error is tolerated.
    }

    // ── FIX 1: response size cap (DoS / pinning-bypass) ─────────────────────

    #[test]
    fn oversize_response_rejected_and_keeps_cache() {
        let dir = tempfile::tempdir().unwrap();
        let set = set_with(
            dir.path(),
            RefreshInterval::Manual,
            vec![sub("mem://a", None)],
        );
        // Establish a last-good cache with a normal fetch.
        update_all(&set, &|_| Ok(b"good.com\n".to_vec()), SystemTime::now());
        assert_eq!(load_cached_domains(&set), vec!["good.com"]);

        // Now the host streams a body one byte over the hard cap.
        let oversize = vec![b'a'; (MAX_FETCH_BYTES + 1) as usize];
        let outcomes = update_all(&set, &|_| Ok(oversize.clone()), SystemTime::now());
        assert!(
            matches!(outcomes[0], UpdateOutcome::CacheKept { .. }),
            "oversize response must be rejected: {:?}",
            outcomes[0]
        );
        // Last-good cache is preserved, NOT overwritten by the oversize body.
        assert_eq!(load_cached_domains(&set), vec!["good.com"]);
    }

    #[test]
    fn oversize_response_no_cache_is_empty() {
        let dir = tempfile::tempdir().unwrap();
        let set = set_with(
            dir.path(),
            RefreshInterval::Manual,
            vec![sub("mem://a", None)],
        );
        let oversize = vec![b'a'; (MAX_FETCH_BYTES + 1) as usize];
        let outcomes = update_all(&set, &|_| Ok(oversize.clone()), SystemTime::now());
        assert!(matches!(outcomes[0], UpdateOutcome::EmptyNoCache { .. }));
        assert!(load_cached_domains(&set).is_empty());
    }

    #[test]
    fn at_cap_response_is_accepted() {
        // Exactly at the cap is allowed; only strictly-over is rejected.
        let dir = tempfile::tempdir().unwrap();
        let set = set_with(
            dir.path(),
            RefreshInterval::Manual,
            vec![sub("mem://a", None)],
        );
        // A body at the cap that parses to one domain line.
        let mut body = b"cap.example\n".to_vec();
        body.resize(MAX_FETCH_BYTES as usize, b'#'); // pad with comment bytes
        let outcomes = update_all(&set, &|_| Ok(body.clone()), SystemTime::now());
        assert!(matches!(outcomes[0], UpdateOutcome::Fetched { .. }));
    }

    // ── FIX 2: curl `--` end-of-options guard ───────────────────────────────

    #[test]
    fn curl_args_place_double_dash_before_url() {
        // A flag-like URL must sit AFTER `--` so curl never parses it as an option.
        let args = curl_args("-K/tmp/evil-curlrc", FETCH_TIMEOUT_SECS);
        let url_idx = args.iter().position(|a| a == "-K/tmp/evil-curlrc").unwrap();
        assert_eq!(
            args[url_idx - 1],
            "--",
            "the URL must be immediately preceded by the `--` end-of-options marker"
        );
        assert_eq!(
            url_idx,
            args.len() - 1,
            "the URL must be the final argument"
        );
    }

    #[test]
    fn curl_args_carry_size_cap() {
        let args = curl_args("https://example.com/list.txt", FETCH_TIMEOUT_SECS);
        let idx = args.iter().position(|a| a == "--max-filesize").unwrap();
        assert_eq!(args[idx + 1], MAX_FETCH_BYTES.to_string());
    }

    // ── FIX 3: lazy-refresh startup budget (one stale list per run) ──────────

    #[test]
    fn lazy_refresh_updates_at_most_one_stale_list_per_run() {
        let dir = tempfile::tempdir().unwrap();
        let set = set_with(
            dir.path(),
            RefreshInterval::Daily,
            vec![
                sub("mem://a", None),
                sub("mem://b", None),
                sub("mem://c", None),
            ],
        );
        let t0 = UNIX_EPOCH + Duration::from_secs(1_000_000);
        // All three are due (no cache). One run refreshes exactly ONE of them.
        let o1 = refresh_if_stale(&set, &|_| Ok(b"x.com\n".to_vec()), t0);
        assert_eq!(o1.len(), 1, "at most one stale list refreshes per run");
        // Next run picks up another still-stale list — again exactly one.
        let o2 = refresh_if_stale(&set, &|_| Ok(b"x.com\n".to_vec()), t0);
        assert_eq!(o2.len(), 1);
    }

    // ── FIX 4: state timestamp only after a confirmed cache write ────────────

    #[test]
    fn write_failure_reports_and_leaves_state_unadvanced() {
        let dir = tempfile::tempdir().unwrap();
        // Make the cache_dir un-creatable: its parent is a regular file.
        let blocker = dir.path().join("not-a-dir");
        std::fs::write(&blocker, b"x").unwrap();
        let cache_dir = blocker.join("subscriptions");
        let set = SubscriptionSet {
            refresh: RefreshInterval::Manual,
            blocklists: vec![sub("mem://a", None)],
            cache_dir,
        };
        let outcomes = update_all(&set, &|_| Ok(b"a.com\n".to_vec()), SystemTime::now());
        assert!(
            matches!(outcomes[0], UpdateOutcome::WriteFailed { .. }),
            "a failed cache write must report WriteFailed: {:?}",
            outcomes[0]
        );
        // State was NOT persisted (dir un-creatable), so a later run still sees the
        // list as due rather than skipping it on a bogus "fresh" timestamp.
        let state = State::load(&set.cache_dir);
        assert!(state.get("mem://a").is_none());
    }
}
