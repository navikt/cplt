//! HTTP CONNECT proxy with domain filtering.
//!
//! Intercepts outbound HTTPS connections from the sandboxed agent,
//! enforcing blocked/allowed domain lists and private IP restrictions.

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::ui;

/// Controls how much the proxy logs to stderr.
/// The audit log file (if configured) always records everything regardless of this level.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum ProxyLogLevel {
    /// No proxy output to stderr (default).
    #[default]
    None,
    /// Only log errors (DNS failures, connect failures, internal errors).
    Error,
    /// Log errors and blocked connections.
    Blocked,
    /// Log everything including successful connections.
    All,
}

impl ProxyLogLevel {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Error => "error",
            Self::Blocked => "blocked",
            Self::All => "all",
        }
    }

    /// Whether this status should be logged at the given level.
    fn should_log(self, status: &str) -> bool {
        match self {
            Self::None => false,
            Self::Error => is_error_status(status),
            Self::Blocked => is_error_status(status) || is_blocked_status(status),
            Self::All => true,
        }
    }
}

impl std::str::FromStr for ProxyLogLevel {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "none" | "off" => Ok(Self::None),
            "error" | "errors" => Ok(Self::Error),
            "blocked" => Ok(Self::Blocked),
            "all" | "verbose" => Ok(Self::All),
            _ => Err(format!(
                "invalid proxy log level '{s}': expected none, error, blocked, or all"
            )),
        }
    }
}

fn is_error_status(status: &str) -> bool {
    status.starts_with("DNS-FAIL")
        || status.starts_with("CONNECT-FAIL")
        || status.starts_with("FAIL")
        || status == "LIMIT"
}

fn is_blocked_status(status: &str) -> bool {
    status.starts_with("BLOCKED")
}

const MAX_CONNECTIONS: usize = 64;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Idle ceiling for an established CONNECT tunnel.
///
/// `proxy.timeout` bounds the request/header phase, where a stalled peer is a
/// real failure. Inside a tunnel it is only a liveness poll: a tunnel is
/// legitimately idle for long stretches — a streaming API response with long
/// server think-time, a pooled keep-alive connection between requests — and
/// tearing it down at `proxy.timeout` drops live sessions (Claude Code shows
/// this as a request timeout). Only this ceiling closes an idle tunnel.
// ponytail: fixed ceiling, make it configurable if anyone needs longer.
const RELAY_IDLE_TIMEOUT: Duration = Duration::from_secs(3600);

/// Fallback read-poll interval when `proxy.timeout` is 0, which the OS rejects.
const DEFAULT_PROXY_TIMEOUT: Duration = Duration::from_secs(60);

/// How often file-backed domain lists are re-read from disk.
/// Within the TTL window, cached values are returned without I/O.
const RELOAD_TTL: Duration = Duration::from_secs(5);

/// Cached domain list with TTL-based refresh.
struct DomainCache {
    domains: Vec<String>,
    /// When the last reload attempt was made (success or failure).
    /// Used for TTL backoff on both success and error paths.
    last_attempt: Instant,
}

impl DomainCache {
    fn new(domains: Vec<String>) -> Self {
        Self {
            domains,
            last_attempt: Instant::now(),
        }
    }

    fn is_stale(&self) -> bool {
        self.last_attempt.elapsed() >= RELOAD_TTL
    }
}

/// DNS resolver override used in tests to inject fake DNS responses.
/// Receives (hostname, port) and returns a resolved `SocketAddr`, or `None`
/// to simulate a DNS failure. Never used in production builds.
#[cfg(test)]
pub type ResolverFn = Arc<dyn Fn(&str, u16) -> Option<std::net::SocketAddr> + Send + Sync>;

/// A parsed upstream (corporate) HTTP proxy that cplt forwards CONNECT tunnels
/// through instead of connecting to targets directly.
///
/// When configured, the CONNECT handler establishes the tunnel by connecting to
/// this proxy and issuing a nested `CONNECT host:port` for the real target — but
/// only *after* every one of cplt's hostname-based policy checks has passed. The
/// upstream proxy must never receive a request that cplt's policy would block.
#[derive(Clone, PartialEq, Eq)]
pub struct UpstreamProxy {
    /// Host of the upstream proxy (no scheme, no port).
    pub host: String,
    /// Port of the upstream proxy.
    pub port: u16,
    /// Pre-computed `Proxy-Authorization: Basic <base64>` credential, i.e. the
    /// base64 of `user:pass` taken from the URL userinfo. `None` when the URL
    /// carried no credentials. Held here so the secret is parsed once at
    /// startup rather than reconstructed per connection.
    pub proxy_authorization: Option<String>,
}

/// Manual `Debug` that never prints the credential.
///
/// SECURITY: `proxy_authorization` holds base64(`user:pass`). A derived `Debug`
/// would splice that secret into any `{:?}` log line or panic message, so it is
/// rendered only as a presence marker (`Some("<redacted>")` / `None`). Host and
/// port carry no secret and are printed to keep the value useful for
/// diagnostics.
impl std::fmt::Debug for UpstreamProxy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UpstreamProxy")
            .field("host", &self.host)
            .field("port", &self.port)
            .field(
                "proxy_authorization",
                &self.proxy_authorization.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

impl UpstreamProxy {
    /// Parse an upstream-proxy URL such as `http://host:8080` or
    /// `http://user:pass@host:8080`. Also accepts a bare `host:8080` (no
    /// scheme). Only the `http` scheme is supported — an `https` upstream would
    /// require TLS to the proxy itself, which cplt does not implement; such a
    /// URL is rejected rather than silently downgraded. A port is mandatory so
    /// the destination is never ambiguous.
    ///
    /// The security value of this feature depends on cplt filtering *before*
    /// forwarding, so parsing is strict: a malformed value fails config loading
    /// (fail-closed) instead of being ignored.
    pub fn parse(url: &str) -> Result<Self, String> {
        let raw = url.trim();
        if raw.is_empty() {
            return Err("upstream proxy URL must not be empty".to_string());
        }

        // Strip and validate the scheme. Bare host:port (no scheme) is allowed.
        let without_scheme = if let Some(rest) = raw.strip_prefix("http://") {
            rest
        } else if raw.contains("://") {
            let scheme = raw.split("://").next().unwrap_or("");
            return Err(format!(
                "unsupported upstream proxy scheme '{scheme}': only http:// (or a bare host:port) is supported"
            ));
        } else {
            raw
        };

        // A trailing path (e.g. `host:8080/foo`) is meaningless for a CONNECT
        // proxy — reject it so typos surface instead of being silently dropped.
        let authority = without_scheme.trim_end_matches('/');
        if authority.contains('/') {
            return Err(format!(
                "upstream proxy URL must be host:port with no path: '{url}'"
            ));
        }

        // Split optional userinfo (user:pass@) from the host:port authority.
        let (userinfo, hostport) = match authority.rsplit_once('@') {
            Some((u, hp)) => (Some(u), hp),
            None => (None, authority),
        };

        // Split host from port. IPv6 literals contain multiple ':' and so must
        // be bracketed (`[::1]:3128`) to be unambiguous — the brackets are
        // stripped from the stored host but restored when forming a socket
        // address (see `socket_addr`). An UNbracketed value with more than one
        // ':' is an ambiguous IPv6 literal (e.g. `::1:3128`): rather than
        // mis-splitting on the last ':' and silently connecting somewhere
        // unintended, reject it as a config error (fail-closed).
        let (host, port_str) = if let Some(rest) = hostport.strip_prefix('[') {
            let (h, after) = rest
                .split_once(']')
                .ok_or_else(|| format!("upstream proxy URL has an unclosed '[' in '{url}'"))?;
            let port_str = after.strip_prefix(':').ok_or_else(|| {
                format!(
                    "bracketed IPv6 upstream proxy must include a port, e.g. http://[::1]:3128: '{url}'"
                )
            })?;
            (h, port_str)
        } else if hostport.matches(':').count() > 1 {
            return Err(format!(
                "ambiguous IPv6 upstream proxy address '{hostport}' must be bracketed, e.g. http://[::1]:3128: '{url}'"
            ));
        } else {
            hostport.rsplit_once(':').ok_or_else(|| {
                format!("upstream proxy URL must include a port, e.g. http://host:8080: '{url}'")
            })?
        };
        if host.is_empty() {
            return Err(format!("upstream proxy URL is missing a host: '{url}'"));
        }
        let port: u16 = port_str
            .parse()
            .map_err(|_| format!("invalid upstream proxy port '{port_str}' in '{url}'"))?;
        if port == 0 {
            return Err(format!("upstream proxy port must not be 0 in '{url}'"));
        }

        let proxy_authorization = match userinfo {
            Some(ui) if !ui.is_empty() => Some(base64_encode(ui.as_bytes())),
            _ => None,
        };

        Ok(Self {
            host: host.to_string(),
            port,
            proxy_authorization,
        })
    }

    /// Build the CONNECT request cplt sends to the upstream proxy to open a
    /// tunnel to `host:port`. Includes a `Host` header and, when credentials
    /// were supplied, a `Proxy-Authorization: Basic` header.
    fn connect_request(&self, host: &str, port: u16) -> String {
        let mut req = format!("CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n");
        if let Some(ref auth) = self.proxy_authorization {
            req.push_str("Proxy-Authorization: Basic ");
            req.push_str(auth);
            req.push_str("\r\n");
        }
        req.push_str("\r\n");
        req
    }

    /// The `host:port` string used to open the TCP connection to the upstream
    /// proxy. An IPv6 literal host (stored without brackets) is wrapped back in
    /// brackets so the result is a valid socket address (`[::1]:3128`); names
    /// and IPv4 addresses are used verbatim.
    fn socket_addr(&self) -> String {
        if self.host.contains(':') {
            format!("[{}]:{}", self.host, self.port)
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }
}

/// Minimal standard base64 encoder (RFC 4648) for building the
/// `Proxy-Authorization: Basic` credential. Kept local to avoid adding a
/// dependency for this single, small use.
fn base64_encode(input: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b0 = u32::from(chunk[0]);
        let b1 = u32::from(*chunk.get(1).unwrap_or(&0));
        let b2 = u32::from(*chunk.get(2).unwrap_or(&0));
        let triple = (b0 << 16) | (b1 << 8) | b2;
        out.push(ALPHABET[((triple >> 18) & 0x3f) as usize] as char);
        out.push(ALPHABET[((triple >> 12) & 0x3f) as usize] as char);
        out.push(if chunk.len() > 1 {
            ALPHABET[((triple >> 6) & 0x3f) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            ALPHABET[(triple & 0x3f) as usize] as char
        } else {
            '='
        });
    }
    out
}

/// Redact the userinfo credentials from an upstream-proxy URL so it is safe to
/// print in `cplt config show`/`explain` or any log line.
///
/// - `http://user:pass@host:8080` → `http://user:***@host:8080` (username kept,
///   password hidden)
/// - `http://token@host:8080` → `http://***@host:8080` (a lone userinfo could
///   itself be a bearer-style secret, so it is hidden whole)
/// - `http://host:8080` and bare `host:8080` → returned unchanged (no secret)
///
/// SECURITY: this is display-only. The real `Proxy-Authorization: Basic` header
/// sent to the upstream is derived from the untouched URL in
/// [`UpstreamProxy::parse`] and is never affected by this function — only what
/// humans see is redacted, so credentials cannot leak into terminals, logs, or
/// CI artifacts while the tunnel still authenticates correctly.
pub fn redact_upstream_url(url: &str) -> String {
    // Only the authority is touched; preserve any `scheme://` prefix verbatim.
    let (scheme, rest) = match url.split_once("://") {
        Some((s, r)) => (Some(s), r),
        None => (None, url),
    };

    // Userinfo is everything before the last '@' in the authority, matching the
    // split UpstreamProxy::parse performs. No '@' means there is nothing secret.
    let redacted_rest = match rest.rsplit_once('@') {
        Some((userinfo, hostport)) => {
            let masked = match userinfo.split_once(':') {
                Some((user, _pass)) => format!("{user}:***"),
                None => "***".to_string(),
            };
            format!("{masked}@{hostport}")
        }
        None => rest.to_string(),
    };

    match scheme {
        Some(s) => format!("{s}://{redacted_rest}"),
        None => redacted_rest,
    }
}

/// Verdict recorded for an observed CONNECT target: whether cplt's policy
/// permitted the connection (`Allowed`) or refused it (`Blocked`). A DNS or
/// transport failure on an otherwise-permitted target still counts as
/// `Allowed` — the point of observation is what the agent was *allowed to
/// attempt*, not whether the far end happened to answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DomainVerdict {
    /// Policy permitted the CONNECT (CONNECTED, or an allowed attempt that then
    /// failed DNS/transport).
    Allowed,
    /// Policy refused the CONNECT (any `BLOCKED*` status).
    Blocked,
}

impl DomainVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Allowed => "allowed",
            Self::Blocked => "blocked",
        }
    }
}

/// One host the proxy observed a CONNECT for, with its verdict and how many
/// CONNECTs targeted it. Returned (sorted by host) from
/// [`ProxyHandle::observed_domains`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObservedDomain {
    /// Normalized host (lowercase, trailing dot stripped).
    pub host: String,
    /// Whether the connection was allowed or blocked by policy.
    pub verdict: DomainVerdict,
    /// Number of CONNECTs seen for this host this session.
    pub count: u64,
}

/// Internal per-host accumulator behind the collector's `BTreeMap`.
struct DomainObservation {
    verdict: DomainVerdict,
    count: u64,
}

/// Thread-safe map of normalized host → observation, keyed for stable sorted
/// output. Held behind an `Arc` so the connection threads and the
/// [`ProxyHandle`] share one collector and results can be read after the
/// session ends.
///
/// This is the generic capture substrate for BOTH `--observe-domains` and audit
/// Phase 2 network reporting — it records EVERY CONNECT verdict regardless of
/// the stderr log level or whether a `--proxy-log` file is configured. A lock
/// per connection is intentionally acceptable: at cplt's scale (`MAX_CONNECTIONS`
/// = 64) the CONNECT path is not hot.
type DomainCollector = Mutex<BTreeMap<String, DomainObservation>>;

/// Shared proxy state holding cached domain lists and config paths.
/// Wrapped in `Arc` and shared across connection threads.
pub struct ProxyState {
    // Blocklist: file of domains to block
    blocked_file: PathBuf,
    blocked_cache: Mutex<DomainCache>,

    // Blocklist subscriptions (issue #144, Phase 1): domains from cached,
    // fetched-and-verified subscription lists, frozen at startup. Empty = no
    // subscriptions configured (behaviour identical to today). When non-empty
    // these are UNIONed with the reloadable `blocked_file` to form the effective
    // blocklist — tighten-only, so this can only ever ADD blocks. See
    // `crate::subscriptions` for the fetch/verify/cache + fail-open model.
    subscription_blocklist: Vec<String>,

    // Allowlist: optional file of permitted domains (fail-closed when configured)
    allowed_domains_file: Option<PathBuf>,
    allowlist_cache: Mutex<DomainCache>,

    // Agent default allowlist (issue #52): the agent's built-in fail-closed
    // domain set, frozen at startup. Empty = the feature is off (unchanged
    // allow-all behaviour). When non-empty it is MERGED with the reloadable
    // `allowed_domains_file` to form the effective allowlist — so the built-in
    // base and the user's additions both apply without re-listing either.
    default_allowlist: Vec<String>,

    // Private domains: merged from a sticky set + the dynamic TOML config.
    //
    // `sticky_private_domains` holds every startup-resolved private domain that
    // `config_file` does NOT supply: `--allow-private-domain` flags and
    // trust-approved `[propose.proxy] allow_private_domains` from the repo
    // `.cplt.toml`. They are frozen for the session because nothing re-reads
    // their source — the repo config is read once from git HEAD, the CLI once
    // from argv — so leaving them in the reloadable cache made the TTL refresh
    // wipe them 5s into the session (#186).
    sticky_private_domains: Vec<String>,
    config_file: Option<PathBuf>,
    private_domains_cache: Mutex<DomainCache>,

    // Ports: frozen at startup (kernel Seatbelt profile is immutable)
    allowed_ports: Vec<u16>,

    // Localhost: ports (or all) explicitly opened via --allow-localhost[/-any].
    // The proxy bypasses its private-IP block for CONNECT to these.
    allow_localhost_ports: Vec<u16>,
    allow_localhost_any: bool,

    // Audit log
    log_file: Option<PathBuf>,
    // Verbosity level for stderr output
    log_level: ProxyLogLevel,
    // Timeout for connection reads/writes
    timeout: std::time::Duration,

    // Optional upstream (corporate) proxy. When set, CONNECT tunnels are
    // forwarded through it instead of connecting to targets directly — but only
    // after all policy checks pass. When None, behavior is a direct connect.
    upstream: Option<UpstreamProxy>,

    // Hosts that BYPASS `upstream` and are connected to directly (NO_PROXY).
    // Normalized (lowercase, no leading/trailing dots) at config-merge time.
    // A no-op when `upstream` is None: the list is only consulted inside the
    // upstream-forward branch of handle_connect. Consulted with `is_domain_match`
    // (exact + subdomain), like the other domain lists.
    upstream_no_proxy: Vec<String>,

    // Observed-domains collector: records every CONNECT target host and whether
    // policy allowed or blocked it. Shared (Arc) with the ProxyHandle so the set
    // can be read after the session. Always present (cheap at cplt's scale);
    // `--observe-domains` merely reads it and forces allow-all so the full set
    // is captured. Foundation for audit Phase 2 network reporting.
    domain_collector: Arc<DomainCollector>,

    // Test-only: injectable DNS resolver to simulate fake DNS responses.
    #[cfg(test)]
    resolver: Option<ResolverFn>,
}

impl ProxyState {
    /// Record a CONNECT verdict for `host` in the observation collector.
    ///
    /// The host is normalized (lowercase, trailing dot stripped) before keying
    /// so `API.Example.com`, `api.example.com`, and `api.example.com.` collapse
    /// to a single entry. `Blocked` is sticky: once a host is seen blocked it
    /// stays blocked even if a later attempt is allowed, so the observed list
    /// always surfaces anything policy refused.
    fn record_observation(&self, host: &str, verdict: DomainVerdict) {
        let key = normalize_hostname(host);
        if key.is_empty() {
            return;
        }
        let mut map = self
            .domain_collector
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let entry = map
            .entry(key)
            .or_insert(DomainObservation { verdict, count: 0 });
        entry.count = entry.count.saturating_add(1);
        if verdict == DomainVerdict::Blocked {
            entry.verdict = DomainVerdict::Blocked;
        }
    }

    /// Get the current blocklist, re-reading from disk if TTL expired.
    /// On read failure, keeps last-good list and resets TTL for retry.
    fn get_blocked_domains(&self) -> Vec<String> {
        let file_domains = get_cached_domains(
            &self.blocked_cache,
            Some(&self.blocked_file),
            parse_lines_file,
        );

        // No subscriptions configured — preserve today's exact behaviour
        // (the reloadable file + built-ins are the sole source).
        if self.subscription_blocklist.is_empty() {
            return file_domains;
        }

        // UNION the cached subscription blocklist(s) with the local/built-in
        // blocklist. Tighten-only: this can only ADD blocks. Deduplicated so the
        // effective list matches what the existing matcher expects.
        let mut merged = file_domains;
        merged.extend(self.subscription_blocklist.iter().cloned());
        merged.sort_unstable();
        merged.dedup();
        merged
    }

    /// Get the effective allowlist, re-reading the user file from disk if the
    /// TTL expired and merging in the agent's built-in default allowlist.
    ///
    /// Resolution (issue #52):
    /// - `default_allowlist` empty (feature off / `--allow-all-domains`):
    ///   behaviour is UNCHANGED — the reloadable file is the sole source, and an
    ///   empty result means allow-all.
    /// - `default_allowlist` non-empty (`proxy.default_allowlist` on): the
    ///   effective allowlist is the agent defaults MERGED with any
    ///   user-configured file domains, deduplicated. The result is always
    ///   non-empty, so `handle_connect` fail-closes on unknown domains.
    ///
    /// Either way the returned list is fed to the same `is_domain_match` /
    /// BLOCKED-ALLOWLIST enforcement — no matching logic is duplicated.
    fn get_allowed_domains(&self) -> Vec<String> {
        let file_domains = match self.allowed_domains_file.as_deref() {
            Some(path) => get_cached_domains(&self.allowlist_cache, Some(path), parse_lines_file),
            None => Vec::new(),
        };

        if self.default_allowlist.is_empty() {
            // Feature off — preserve today's exact behaviour.
            return file_domains;
        }

        let mut merged = self.default_allowlist.clone();
        merged.extend(file_domains);
        merged.sort_unstable();
        merged.dedup();
        merged
    }

    /// Get private domains: union of the sticky entries + dynamic config entries.
    fn get_private_domains(&self) -> Vec<String> {
        let config_domains = get_cached_domains(
            &self.private_domains_cache,
            self.config_file.as_deref(),
            parse_private_domains_from_toml,
        );

        if self.sticky_private_domains.is_empty() {
            return config_domains;
        }
        if config_domains.is_empty() {
            return self.sticky_private_domains.clone();
        }

        // Merge sticky + config, deduplicate
        let mut merged = self.sticky_private_domains.clone();
        merged.extend(config_domains);
        merged.sort_unstable();
        merged.dedup();
        merged
    }

    /// Snapshot the effective CONNECT policy for static classification.
    ///
    /// Reads the current (cache-refreshed) allowlist and blocklist so
    /// [`classify_connect`] sees exactly what the live gates would see.
    fn net_policy(&self) -> NetPolicy {
        NetPolicy {
            allowed_ports: self.allowed_ports.clone(),
            allowed_domains: self.get_allowed_domains(),
            blocked_domains: self.get_blocked_domains(),
            allow_localhost_ports: self.allow_localhost_ports.clone(),
            allow_localhost_any: self.allow_localhost_any,
            private_domains: self.get_private_domains(),
        }
    }
}

/// Read cached domains, refreshing from disk if TTL has expired.
/// On read failure: keeps the last-good list, resets TTL for backoff retry.
fn get_cached_domains(
    cache: &Mutex<DomainCache>,
    path: Option<&Path>,
    parser: fn(&Path) -> Option<Vec<String>>,
) -> Vec<String> {
    let mut guard = cache
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);

    if !guard.is_stale() {
        return guard.domains.clone();
    }

    // TTL expired — attempt reload
    if let Some(path) = path
        && let Some(new_domains) = parser(path)
    {
        guard.domains = new_domains;
    }
    // On failure: keep last-good domains (fail-safe)
    guard.last_attempt = Instant::now();
    guard.domains.clone()
}

/// Parse a one-domain-per-line file (blocklist or allowlist format).
/// Returns None on read failure (caller keeps last-good).
///
/// This is the **single** parser the live proxy feeds into its allowlist and
/// blocklist caches ([`get_cached_domains`]). `cplt check` must build its policy
/// snapshot through this same function (not [`parse_domain_file`], which extra-
/// normalizes by stripping scheme/path/port) so a non-canonical allowlist entry
/// like `github.com:443` is stored byte-identically in both — otherwise check
/// would report ALLOWED for a host the live `handle_connect` blocks with
/// BLOCKED-ALLOWLIST.
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
                ui::color(ui::YELLOW),
                ui::color(ui::RESET),
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
                ui::color(ui::YELLOW),
                ui::color(ui::RESET),
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

pub struct ProxyHandle {
    shutdown_flag: Arc<std::sync::atomic::AtomicBool>,
    /// Actual port the proxy is listening on. With a configured port of 0,
    /// the OS assigns an ephemeral port; this field reflects the real value.
    pub port: u16,
    /// Shared observation collector (see [`ProxyState::domain_collector`]).
    /// Cloned from the state so the observed set can be read after the session
    /// via [`ProxyHandle::observed_domains`].
    domain_collector: Arc<DomainCollector>,
    /// Test-only view of the live state, so reload behaviour can be asserted
    /// against the real `start()` wiring instead of a hand-built `ProxyState`.
    #[cfg(test)]
    state: Option<Arc<ProxyState>>,
}

impl ProxyHandle {
    pub fn shutdown(&self) {
        self.shutdown_flag
            .store(true, std::sync::atomic::Ordering::SeqCst);
        // Accept loop is non-blocking with 50ms sleep, so it will notice
        // the flag within ~50ms without needing a wake-up connection.
    }

    /// Snapshot every host the proxy saw a CONNECT for this session, sorted by
    /// host, each with its verdict (`Allowed`/`Blocked`) and CONNECT count.
    ///
    /// Backs `--observe-domains` (and, later, audit Phase 2 network reporting).
    /// The `BTreeMap` yields hosts already sorted and deduplicated.
    pub fn observed_domains(&self) -> Vec<ObservedDomain> {
        let map = self
            .domain_collector
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        map.iter()
            .map(|(host, obs)| ObservedDomain {
                host: host.clone(),
                verdict: obs.verdict,
                count: obs.count,
            })
            .collect()
    }
}

/// Bundled proxy startup options.
pub struct ProxyOptions {
    pub port: u16,
    pub blocked_file: PathBuf,
    /// Domains from cached blocklist subscriptions (issue #144, Phase 1), frozen
    /// at startup. Empty = no subscriptions (unchanged behaviour). UNIONed with
    /// `blocked_file` to form the effective blocklist. Tighten-only.
    pub subscription_blocklist: Vec<String>,
    pub allowed_ports: Vec<u16>,
    /// Specific localhost ports explicitly opened by `--allow-localhost`.
    /// The proxy bypasses its private-IP block for CONNECT to these ports.
    pub allow_localhost_ports: Vec<u16>,
    /// Whether all localhost ports are open (`--allow-localhost-any`).
    pub allow_localhost_any: bool,
    /// Path to an allowlist file (one domain per line). When set, only
    /// matching domains pass. The file is re-read every RELOAD_TTL seconds.
    pub allowed_domains_file: Option<PathBuf>,
    /// Initial allowed domains from CLI/config (used for startup validation).
    /// After startup, the file is the source of truth for dynamic reload.
    pub allowed_domains_initial: Vec<String>,
    /// Agent built-in default allowlist (issue #52). Empty = feature off
    /// (unchanged allow-all). When set, it is merged with `allowed_domains_file`
    /// to form the effective, fail-closed allowlist. Frozen at startup.
    pub default_allowlist: Vec<String>,
    /// Domains allowed to resolve to private IPs — CLI portion (immutable).
    pub cli_private_domains: Vec<String>,
    /// Domains allowed to resolve to private IPs — the portion that came from
    /// `config_file`'s own `proxy.allow_private_domains`. Only these follow its
    /// 5-second reload, so editing that file still adds and revokes them.
    pub config_private_domains: Vec<String>,
    /// Domains allowed to resolve to private IPs — the trust-approved
    /// `[propose.proxy] allow_private_domains` entries from the repo
    /// `.cplt.toml` (`Resolved::repo_private_domains`). Frozen for the session
    /// like the CLI ones: their source is read once (git HEAD + trust store),
    /// so the config-file reload must not be able to drop them (#186).
    pub repo_private_domains: Vec<String>,
    /// Path to TOML config file for dynamic reload of private_domains.
    pub config_file: Option<PathBuf>,
    /// Path to append audit log lines. None = no file logging.
    pub log_file: Option<PathBuf>,
    /// Verbosity level for proxy stderr output.
    pub log_level: ProxyLogLevel,
    /// Timeout for proxy connections.
    pub timeout: std::time::Duration,
    /// Optional upstream (corporate) proxy to forward CONNECT tunnels through.
    /// When `None`, cplt connects to targets directly (unchanged behavior).
    pub upstream: Option<UpstreamProxy>,
    /// Normalized hosts that bypass `upstream` and are connected to directly
    /// (NO_PROXY semantics). No-op when `upstream` is `None`.
    pub upstream_no_proxy: Vec<String>,

    /// Test-only: injectable DNS resolver. Pass a closure to override DNS
    /// resolution in proxy tests (e.g. to simulate DNS rebinding).
    #[cfg(test)]
    pub resolver: Option<ResolverFn>,
}

/// Start the proxy on a background thread. Returns a handle for shutdown.
///
/// `allowed_ports` controls which remote ports CONNECT tunnels can reach.
/// Port 443 is always allowed. Additional ports come from `--allow-port`.
pub fn start(opts: ProxyOptions) -> Result<ProxyHandle, String> {
    let mut ports: Vec<u16> = vec![443];
    ports.extend_from_slice(&opts.allowed_ports);
    ports.sort_unstable();
    ports.dedup();

    let addr = format!("127.0.0.1:{}", opts.port);
    let listener = TcpListener::bind(&addr).map_err(|e| format!("Cannot bind to {addr}: {e}"))?;
    let actual_port = listener
        .local_addr()
        .map_err(|e| format!("Cannot get proxy listen address: {e}"))?
        .port();

    // Validate blocklist is readable at startup (fail-fast, not fail-open)
    let blocked_initial = if opts.blocked_file.exists() {
        parse_lines_file(&opts.blocked_file).ok_or_else(|| {
            format!(
                "Cannot read blocked domains file {}",
                opts.blocked_file.display()
            )
        })?
    } else {
        Vec::new()
    };

    // Validate allowlist at startup (fail-closed: abort if configured but unreadable)
    let allowlist_initial = if let Some(ref path) = opts.allowed_domains_file {
        if path.exists() {
            parse_lines_file(path)
                .ok_or_else(|| format!("Cannot read allowed domains file {}", path.display()))?
        } else if !opts.allowed_domains_initial.is_empty() {
            // File doesn't exist yet but we have initial domains from config
            opts.allowed_domains_initial.clone()
        } else {
            // No file and no initial domains — this is fine (no allowlist)
            Vec::new()
        }
    } else {
        opts.allowed_domains_initial.clone()
    };

    // Validate log file is writable at startup
    if let Some(ref log_path) = opts.log_file {
        std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(log_path)
            .map_err(|e| format!("Cannot open proxy log file {}: {e}", log_path.display()))?;
    }

    // Private domains whose source is read exactly once — CLI flags and
    // trust-approved repo `.cplt.toml` proposals — are held outside the
    // TTL cache. That cache's only refresh source is the global config file,
    // so anything else parked in it is silently dropped by the first refresh,
    // 5s into the session (#186).
    let mut sticky_private_domains: Vec<String> = opts
        .cli_private_domains
        .iter()
        .chain(opts.repo_private_domains.iter())
        .map(|d| normalize_hostname(d))
        .collect();
    sticky_private_domains.sort_unstable();
    sticky_private_domains.dedup();

    // Observation collector, shared between the connection threads (via state)
    // and the returned handle so observed domains can be read after shutdown.
    let domain_collector: Arc<DomainCollector> = Arc::new(Mutex::new(BTreeMap::new()));

    // Build shared state with initial caches
    let state = Arc::new(ProxyState {
        blocked_file: opts.blocked_file,
        blocked_cache: Mutex::new(DomainCache::new(blocked_initial)),
        subscription_blocklist: opts.subscription_blocklist,
        allowed_domains_file: opts.allowed_domains_file,
        allowlist_cache: Mutex::new(DomainCache::new(allowlist_initial)),
        default_allowlist: opts.default_allowlist,
        sticky_private_domains,
        config_file: opts.config_file,
        private_domains_cache: Mutex::new(DomainCache::new(opts.config_private_domains)),
        allowed_ports: ports,
        allow_localhost_ports: opts.allow_localhost_ports,
        allow_localhost_any: opts.allow_localhost_any,
        log_file: opts.log_file,
        log_level: opts.log_level,
        timeout: opts.timeout,
        upstream: opts.upstream,
        upstream_no_proxy: opts.upstream_no_proxy,
        domain_collector: domain_collector.clone(),
        #[cfg(test)]
        resolver: opts.resolver,
    });

    listener
        .set_nonblocking(false)
        .map_err(|e| format!("set_nonblocking: {e}"))?;

    #[cfg(test)]
    let state_for_tests = state.clone();

    let shutdown_flag = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let flag = shutdown_flag.clone();
    let active_count = Arc::new(std::sync::atomic::AtomicUsize::new(0));

    std::thread::Builder::new()
        .name("proxy-accept".into())
        .spawn(move || {
            accept_loop(listener, flag, state, active_count);
        })
        .map_err(|e| format!("spawn proxy thread: {e}"))?;

    std::thread::sleep(Duration::from_millis(50));

    Ok(ProxyHandle {
        shutdown_flag,
        port: actual_port,
        domain_collector,
        #[cfg(test)]
        state: Some(state_for_tests),
    })
}

fn accept_loop(
    listener: TcpListener,
    shutdown: Arc<std::sync::atomic::AtomicBool>,
    state: Arc<ProxyState>,
    active_count: Arc<std::sync::atomic::AtomicUsize>,
) {
    // Non-blocking accept with periodic shutdown check
    listener.set_nonblocking(true).ok();

    loop {
        if shutdown.load(std::sync::atomic::Ordering::SeqCst) {
            break;
        }

        let stream = match listener.accept() {
            Ok((s, _)) => s,
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(50));
                continue;
            }
            Err(_) => continue,
        };

        // Ensure accepted socket is blocking (listener is non-blocking for
        // shutdown checks, but connection handlers need blocking I/O).
        stream.set_nonblocking(false).ok();
        stream.set_nodelay(true).ok();

        // Connection limit
        let count = active_count.load(std::sync::atomic::Ordering::SeqCst);
        if count >= MAX_CONNECTIONS {
            log_connection(&state, "REJECT", "connection limit", "LIMIT");
            drop(stream);
            continue;
        }

        active_count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let conn_state = state.clone();
        let counter = active_count.clone();

        if let Err(e) = std::thread::Builder::new()
            .name("proxy-conn".into())
            .spawn(move || {
                handle_connection(stream, &conn_state);
                counter.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
            })
        {
            active_count.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
            log_connection(&state, "INTERNAL", "thread-spawn", &format!("FAIL:{e}"));
        }
    }
}

fn handle_connection(mut client: TcpStream, state: &ProxyState) {
    client.set_read_timeout(Some(state.timeout)).ok();
    client.set_write_timeout(Some(state.timeout)).ok();

    // Read the request line
    let mut buf = [0u8; 8192];
    let n = match client.read(&mut buf) {
        Ok(0) => return,
        Ok(n) => n,
        Err(_) => return,
    };

    let request = String::from_utf8_lossy(&buf[..n]);
    let first_line = request.lines().next().unwrap_or("");

    // Parse method and target
    let parts: Vec<&str> = first_line.split_whitespace().collect();
    if parts.len() < 2 {
        return;
    }

    let method = parts[0];
    let target = parts[1];

    if method.eq_ignore_ascii_case("CONNECT") {
        handle_connect(client, target, state);
    } else {
        // For non-CONNECT, send a simple error — the sandbox should force
        // CONNECT via proxy env vars for HTTPS traffic
        log_connection(state, method, target, "UNSUPPORTED");
        let _ = client.write_all(b"HTTP/1.1 405 Method Not Allowed\r\n\r\n");
    }
}

/// Resolve `host:port` to a socket address using the same local DNS path the
/// direct-connect flow uses, honoring the test-only injected resolver.
///
/// Returns `None` when the name does not resolve locally. Callers distinguish
/// two meanings of `None`: on the direct path it is a hard DNS failure (502);
/// on the upstream-forward path it means "this host is only resolvable by the
/// corporate proxy" (split-horizon DNS) and the tunnel is forwarded anyway.
/// Centralizing resolution here keeps the resolved-IP SSRF guard identical for
/// both paths.
#[cfg_attr(not(test), allow(unused_variables))] // `state` only used by the test resolver
fn resolve_locally(state: &ProxyState, host: &str, port: u16) -> Option<std::net::SocketAddr> {
    #[cfg(test)]
    {
        // In tests, an injected resolver can fake DNS responses (e.g. to
        // simulate DNS rebinding where evil.example.com → 169.254.169.254).
        if let Some(ref resolver) = state.resolver {
            return resolver(host, port);
        }
    }
    let _ = state;
    resolve_socket_addr(host, port)
}

/// Resolve `host:port` to a single socket address via the system resolver.
///
/// This is the real DNS path the live proxy uses ([`resolve_locally`], modulo
/// the test-injected resolver) and the exact resolver `cplt check net` reuses so
/// the diagnostic's post-DNS SSRF guard sees the same address the live proxy
/// would resolve — never duplicating resolution logic.
#[must_use]
pub fn resolve_socket_addr(host: &str, port: u16) -> Option<std::net::SocketAddr> {
    let addr_str = format!("{host}:{port}");
    addr_str.to_socket_addrs().ok().and_then(|mut a| a.next())
}

/// The verdict of the proxy's pre-DNS CONNECT policy gates.
///
/// This is the static portion of the CONNECT decision — the checks that depend
/// only on the target host/port and the configured policy, not on DNS
/// resolution. It is the single source of truth shared by the live proxy
/// ([`handle_connect`]) and the `cplt check net` diagnostic ([`classify_connect`]).
///
/// [`NetVerdict::Allowed`] means "no static gate blocks this" — the live path
/// then proceeds to DNS resolution and the resolved-IP SSRF guard, which can
/// still block a name that resolves to a private address. The diagnostic treats
/// `Allowed` as "cplt is not blocking this by policy".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetVerdict {
    /// No static policy gate blocks the target (would proceed to DNS/connect).
    Allowed,
    /// The target port is not in the allowed-ports set.
    BlockedPort,
    /// A fail-closed allowlist is active and the host is not in it.
    BlockedAllowlist,
    /// The host matches the blocklist.
    Blocked,
    /// The host is a known-private/loopback/link-local target (SSRF guard).
    BlockedPrivate,
}

impl NetVerdict {
    /// The `BLOCKED-*` status string used in the proxy audit log for this verdict.
    /// `Allowed` maps to `ALLOWED` (the target would be permitted by policy).
    #[must_use]
    pub fn status(self) -> &'static str {
        match self {
            NetVerdict::Allowed => "ALLOWED",
            NetVerdict::BlockedPort => "BLOCKED-PORT",
            NetVerdict::BlockedAllowlist => "BLOCKED-ALLOWLIST",
            NetVerdict::Blocked => "BLOCKED",
            NetVerdict::BlockedPrivate => "BLOCKED-PRIVATE",
        }
    }

    /// Whether this verdict permits the connection (no static gate blocked it).
    #[must_use]
    pub fn is_allowed(self) -> bool {
        matches!(self, NetVerdict::Allowed)
    }
}

/// A snapshot of the proxy's effective CONNECT policy for static classification.
///
/// Built either from a live [`ProxyState`] (via [`ProxyState::net_policy`]) or
/// directly from resolved config by the `cplt check` command. The field values
/// mean exactly what they mean inside [`handle_connect`]: `allowed_ports`
/// already includes 443, `allowed_domains` is the *effective* (merged) allowlist
/// where empty means allow-all.
#[derive(Debug, Clone, Default)]
pub struct NetPolicy {
    pub allowed_ports: Vec<u16>,
    pub allowed_domains: Vec<String>,
    pub blocked_domains: Vec<String>,
    pub allow_localhost_ports: Vec<u16>,
    pub allow_localhost_any: bool,
    /// Hosts explicitly trusted to resolve to private IPs
    /// (`allow_private_domains`). Consulted by the post-DNS resolved-IP guard
    /// (`resolved_ip_is_blocked`), not by the pre-DNS [`classify_connect`] gates.
    /// Mirrors `ProxyState::get_private_domains` so `cplt check net` applies the
    /// same waiver the live proxy does.
    pub private_domains: Vec<String>,
}

/// Classify a CONNECT target against the static (pre-DNS) proxy policy gates.
///
/// This is the exact gate order [`handle_connect`] enforces before it resolves
/// DNS — port policy, fail-closed allowlist, blocklist, then the
/// private-hostname SSRF guard — reusing the same matchers ([`is_domain_match`],
/// [`is_blocked_in_list`], [`is_private_hostname`]). Factoring it here keeps the
/// live path and the diagnostic from drifting apart.
#[must_use]
pub fn classify_connect(policy: &NetPolicy, host: &str, port: u16) -> NetVerdict {
    let host = normalize_hostname(host);

    let localhost_opt_in =
        policy.allow_localhost_any || policy.allow_localhost_ports.contains(&port);
    let localhost_connect_allowed = {
        let h = host.trim_start_matches('[').trim_end_matches(']');
        let is_loopback = h == "localhost"
            || h.ends_with(".localhost")
            || h.parse::<std::net::IpAddr>()
                .is_ok_and(|ip| ip.is_loopback());
        is_loopback && localhost_opt_in
    };

    if !localhost_connect_allowed && !policy.allowed_ports.contains(&port) {
        return NetVerdict::BlockedPort;
    }
    if !localhost_connect_allowed
        && !policy.allowed_domains.is_empty()
        && !is_domain_match(&host, &policy.allowed_domains)
    {
        return NetVerdict::BlockedAllowlist;
    }
    if is_blocked_in_list(&host, &policy.blocked_domains) {
        return NetVerdict::Blocked;
    }
    if !localhost_connect_allowed && is_private_hostname(&host) {
        return NetVerdict::BlockedPrivate;
    }
    NetVerdict::Allowed
}

/// Apply the resolved-IP SSRF / DNS-rebinding guard.
///
/// Returns `true` when the target must be BLOCKED: it resolves to a
/// private/link-local IP that is neither loopback nor covered by an
/// `allow_private_domains` entry. This is the exact policy the direct-connect
/// path enforces inline; the upstream-forward path reuses it so both modes
/// treat a resolvable host identically.
fn handle_connect(mut client: TcpStream, target: &str, state: &ProxyState) {
    // Parse host:port
    let (host, port) = match target.rsplit_once(':') {
        Some((h, p)) => (h.to_string(), p.parse::<u16>().unwrap_or(443)),
        None => (target.to_string(), 443),
    };

    // Normalize hostname: lowercase, strip trailing dot (valid DNS but
    // would bypass exact-match rules otherwise).
    let host = normalize_hostname(&host);

    // Compute localhost bypass before the port check: --allow-localhost <PORT> must
    // also exempt that port from the general port policy (which only lists remote ports
    // like 443/80). Without this, allow_localhost_ports would be silently ignored —
    // the port check would fire first and return 403 before the localhost logic ran.
    // Config-level localhost opt-in for this connection, independent of how the
    // hostname is spelled: the user either allowed all localhost ports
    // (`--allow-localhost-any`) or explicitly allow-listed this port
    // (`--allow-localhost <PORT>`). This is the sole gate for a target that
    // *resolves* to loopback — see the `resolved_ip_is_blocked` call below.
    let localhost_opt_in = state.allow_localhost_any || state.allow_localhost_ports.contains(&port);

    let localhost_connect_allowed = {
        let h = host.trim_start_matches('[').trim_end_matches(']');
        let is_loopback = h == "localhost"
            || h.ends_with(".localhost")
            || h.parse::<std::net::IpAddr>()
                .is_ok_and(|ip| ip.is_loopback());
        is_loopback && localhost_opt_in
    };

    // Apply the static (pre-DNS) policy gates — port policy, fail-closed
    // allowlist, blocklist, then the private-hostname SSRF guard — in that
    // order. The decision logic lives in `classify_connect` so the live proxy
    // and the `cplt check net` diagnostic can never drift apart; here we map
    // each verdict to its audit-log status and 403 response. The `Blocked`
    // (blocklist) and `BlockedPrivate` cases additionally half-close the socket,
    // matching the original inline behaviour. `localhost_connect_allowed` is
    // recomputed identically inside `classify_connect`; it is retained here
    // because the post-DNS section below still consults it.
    //
    // Every arm routes through `log_connection(state, ...)`, which is the single
    // choke point that also records the observation into `domain_collector`
    // (issue #143). So the merged path yields the SAME verdict `classify_connect`
    // computes AND records every contacted host — a blocked verdict is logged and
    // recorded here, an `Allowed` verdict falls through to be recorded downstream
    // when the connection reaches CONNECTED / a post-DNS block.
    let snapshot = state.net_policy();
    match classify_connect(&snapshot, &host, port) {
        NetVerdict::BlockedPort => {
            log_connection(state, "CONNECT", target, "BLOCKED-PORT");
            let _ = client.write_all(b"HTTP/1.1 403 Forbidden\r\n\r\nPort not allowed\r\n");
            return;
        }
        NetVerdict::BlockedAllowlist => {
            log_connection(state, "CONNECT", target, "BLOCKED-ALLOWLIST");
            let _ = client.write_all(b"HTTP/1.1 403 Forbidden\r\n\r\nDomain not in allowlist\r\n");
            return;
        }
        NetVerdict::Blocked => {
            log_connection(state, "CONNECT", target, "BLOCKED");
            let _ = client.write_all(b"HTTP/1.1 403 Forbidden\r\n\r\nBlocked by cplt\r\n");
            let _ = client.shutdown(std::net::Shutdown::Both);
            return;
        }
        NetVerdict::BlockedPrivate => {
            log_connection(state, "CONNECT", target, "BLOCKED-PRIVATE");
            let _ = client.write_all(b"HTTP/1.1 403 Forbidden\r\n\r\nPrivate target blocked\r\n");
            let _ = client.shutdown(std::net::Shutdown::Both);
            return;
        }
        NetVerdict::Allowed => {}
    }

    // ── Upstream (corporate) proxy chaining ──────────────────────────────
    // If an upstream proxy is configured, forward the tunnel through it rather
    // than connecting to the target directly. This branch is deliberately placed
    // AFTER every hostname-based policy gate above — the port check, the
    // allowlist check, the blocklist check, and the private-hostname check — so
    // the upstream proxy can NEVER receive a CONNECT that cplt's policy would
    // block. A blocked/blocklisted/wrong-port target has already returned 403
    // above and never reaches this code.
    //
    // Loopback carve-out (--allow-localhost): a target permitted only because
    // it is loopback must connect DIRECTLY, never via the upstream. Forwarding
    // `127.0.0.1`/`localhost` to the corporate proxy is nonsensical — it would
    // resolve loopback on the UPSTREAM's side, reaching a service on the proxy
    // host rather than the user's machine. Skipping the branch here keeps every
    // localhost carve-out local, and the direct path's stricter resolved-IP
    // loopback check (below) still applies.
    //
    // No-proxy carve-out (upstream_no_proxy / NO_PROXY): a target whose host
    // matches the no-proxy list must ALSO skip this branch and fall through to
    // the direct-connect path below, exactly as NO_PROXY makes a host bypass a
    // corporate proxy. `host_matches_no_proxy` gates the branch. Security is
    // preserved for free: every hostname policy gate above already ran, and the
    // direct path re-applies the resolved-IP SSRF guard (`resolved_ip_is_blocked`
    // at ~line 1000), so a no-proxy host is still fully policy-checked — it is
    // just connected DIRECTLY by cplt (which runs OUTSIDE the sandbox) instead
    // of being forwarded. Because cplt makes that connection, this also works
    // under `proxy.forced`, where the agent itself cannot reach the network.
    if !localhost_connect_allowed
        && let Some(upstream) = state.upstream.as_ref()
        && !host_matches_no_proxy(&host, &state.upstream_no_proxy)
    {
        // SSRF / DNS-rebinding guard for the forwarded path. We apply the SAME
        // resolved-IP check the direct path applies below, so upstream and
        // direct mode treat a *resolvable* host identically: a public name
        // whose A record points at a private/link-local IP (e.g. an
        // attacker-registered domain aimed at 10.x or the 169.254.169.254 cloud
        // metadata endpoint) is BLOCKED, never forwarded. Hosts explicitly
        // trusted via `allow_private_domains` are forwarded exactly as they are
        // permitted in direct mode — that is how legitimate corporate-internal
        // targets that resolve to private IPs keep working.
        //
        // Residual, stated honestly: a name that ONLY the corporate proxy can
        // resolve (split-horizon DNS, not resolvable from this host) yields no
        // local IP to check, so it is forwarded without a resolved-IP check.
        // Reaching such names is the intended purpose of upstream mode; the
        // hostname allow/block/port gates above still constrain it.
        if let Some(socket_addr) = resolve_locally(state, &host, port)
            && resolved_ip_is_blocked(
                &socket_addr.ip(),
                is_domain_match(&host, &state.get_private_domains()),
                localhost_opt_in,
            )
        {
            log_connection(state, "CONNECT", target, "BLOCKED-PRIVATE-RESOLVED");
            let _ = client.write_all(b"HTTP/1.1 403 Forbidden\r\n\r\nResolved to private IP\r\n");
            let _ = client.shutdown(std::net::Shutdown::Both);
            return;
        }
        connect_via_upstream(client, &host, port, target, upstream, state);
        return;
    }

    // Resolve DNS FIRST, then check the resolved IP. A local resolution failure
    // on the direct path is a hard error — there is no upstream to defer to.
    let Some(socket_addr) = resolve_locally(state, &host, port) else {
        log_connection(state, "CONNECT", target, "DNS-FAIL");
        let _ = client.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n");
        return;
    };

    // Hard requirement for the localhost carve-out: a target that was only
    // permitted because of --allow-localhost(-any) MUST resolve to a loopback
    // address. `*.localhost` is supposed to map to 127.0.0.1/::1, but a hostile
    // resolver or /etc/hosts entry could point `evil.localhost` at a public or
    // private non-loopback IP. Without this check the carve-out (which already
    // bypassed the port policy and private-hostname block) would tunnel to an
    // arbitrary port on an arbitrary host — an SSRF / egress-widening vector.
    // The earlier is_private_ip guard below only catches *private* IPs; this also
    // closes the *public* non-loopback case.
    if localhost_connect_allowed && !socket_addr.ip().is_loopback() {
        log_connection(state, "CONNECT", target, "BLOCKED-PRIVATE-RESOLVED");
        let _ = client.write_all(b"HTTP/1.1 403 Forbidden\r\n\r\nResolved to non-loopback IP\r\n");
        let _ = client.shutdown(std::net::Shutdown::Both);
        return;
    }

    // Check the RESOLVED IP address (prevents DNS rebinding attacks).
    // Domains in allow_private_domains are explicitly trusted to resolve to private IPs
    // (e.g. corporate internal services). All other checks still apply.
    //
    // For --allow-localhost: we use the *resolved* IP to confirm loopback, not the
    // hostname. `*.localhost` in DNS is supposed to resolve to 127.0.0.1, but a
    // compromised DNS or /etc/hosts entry could make `evil.localhost` resolve to
    // 169.254.169.254 (cloud IMDS) or an internal host. Using the hostname pattern
    // alone would bypass this check entirely, enabling SSRF to cloud metadata.
    //
    // Crucially, a loopback-resolving target is exempted only when the user opted
    // into localhost access for this connection (`localhost_opt_in`) — NOT based on
    // whether the hostname literally spells "localhost". Once the target has
    // resolved to a loopback IP, the spelling of the name is irrelevant: a user who
    // opted in with `--allow-localhost-any` (or `--allow-localhost <PORT>`) may
    // legitimately reach loopback via a loopback-aliasing name (`lvh.me`,
    // `127.0.0.1.nip.io`). With no opt-in, loopback stays blocked regardless of the
    // name, preserving the no-localhost default. See `resolved_ip_is_blocked`.
    let private_domains = state.get_private_domains();
    if resolved_ip_is_blocked(
        &socket_addr.ip(),
        is_domain_match(&host, &private_domains),
        localhost_opt_in,
    ) {
        log_connection(state, "CONNECT", target, "BLOCKED-PRIVATE-RESOLVED");
        let _ = client.write_all(b"HTTP/1.1 403 Forbidden\r\n\r\nResolved to private IP\r\n");
        let _ = client.shutdown(std::net::Shutdown::Both);
        return;
    }

    // Connect to resolved address (not re-resolving)
    let remote = match TcpStream::connect_timeout(&socket_addr, CONNECT_TIMEOUT) {
        Ok(s) => {
            s.set_nodelay(true).ok();
            s
        }
        Err(e) => {
            log_connection(state, "CONNECT", target, &format!("CONNECT-FAIL:{e}"));
            let _ = client.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n");
            return;
        }
    };

    // Log after TCP connect succeeds — this is the audit-relevant event.
    log_connection(state, "CONNECT", target, "CONNECTED");

    // Send 200 to client
    if client
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .is_err()
    {
        return;
    }

    // Bidirectional relay
    relay(client, remote, state.timeout);
}

/// Forward a CONNECT tunnel through the configured upstream (corporate) proxy.
///
/// Precondition: every cplt policy check (port, allowlist, blocklist,
/// private-hostname) has already passed in `handle_connect`. This function must
/// only ever be reached for a target cplt's policy permits — it performs no
/// filtering of its own; it just relays the already-approved target to the
/// upstream and splices bytes.
fn connect_via_upstream(
    mut client: TcpStream,
    host: &str,
    port: u16,
    target: &str,
    upstream: &UpstreamProxy,
    state: &ProxyState,
) {
    // Connect to the upstream proxy itself (not the target).
    let upstream_addr = upstream.socket_addr();
    let Some(socket_addr) = upstream_addr
        .to_socket_addrs()
        .ok()
        .and_then(|mut a| a.next())
    else {
        log_connection(state, "CONNECT", target, "CONNECT-FAIL:upstream-dns");
        let _ = client.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n");
        return;
    };
    let mut remote = match TcpStream::connect_timeout(&socket_addr, CONNECT_TIMEOUT) {
        Ok(s) => {
            s.set_nodelay(true).ok();
            s
        }
        Err(e) => {
            log_connection(
                state,
                "CONNECT",
                target,
                &format!("CONNECT-FAIL:upstream:{e}"),
            );
            let _ = client.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n");
            return;
        }
    };
    remote.set_read_timeout(Some(state.timeout)).ok();
    remote.set_write_timeout(Some(state.timeout)).ok();

    // Ask the upstream to open a tunnel to the real target.
    let request = upstream.connect_request(host, port);
    if remote.write_all(request.as_bytes()).is_err() {
        log_connection(state, "CONNECT", target, "CONNECT-FAIL:upstream-write");
        let _ = client.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n");
        return;
    }

    // Read the upstream's CONNECT response. Anything other than 2xx means the
    // upstream refused — fail the client's CONNECT cleanly instead of splicing.
    match read_upstream_connect_status(&mut remote) {
        Ok(true) => {}
        Ok(false) => {
            log_connection(state, "CONNECT", target, "CONNECT-FAIL:upstream-refused");
            let _ = client.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n");
            return;
        }
        Err(_) => {
            log_connection(state, "CONNECT", target, "CONNECT-FAIL:upstream-read");
            let _ = client.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n");
            return;
        }
    }

    // Log as CONNECTED — identical audit/stats semantics to a direct connect,
    // so the allowed connection is recorded the same way whether or not an
    // upstream is in use.
    log_connection(state, "CONNECT", target, "CONNECTED");

    // Tell the client its tunnel is established, then splice bytes as usual.
    if client
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .is_err()
    {
        return;
    }

    relay(client, remote, state.timeout);
}

/// Read and interpret the upstream proxy's response to our CONNECT request.
///
/// Returns `Ok(true)` for a 2xx status (tunnel established), `Ok(false)` for any
/// other status (upstream refused), or `Err` on an I/O/protocol error. Reads
/// byte-by-byte only up to the end of the status line, so the tunnelled TLS
/// bytes that may follow the header block are not consumed here — the relay
/// loop reads them from the same socket afterward.
fn read_upstream_connect_status(remote: &mut TcpStream) -> std::io::Result<bool> {
    // Read the first line (HTTP status line), terminated by \n. Cap the length
    // to avoid an unbounded read from a hostile/broken upstream.
    let mut line = Vec::with_capacity(64);
    let mut byte = [0u8; 1];
    loop {
        if remote.read(&mut byte)? == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "upstream closed before sending a CONNECT response",
            ));
        }
        if byte[0] == b'\n' {
            break;
        }
        if byte[0] != b'\r' {
            line.push(byte[0]);
        }
        if line.len() > 8192 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "upstream CONNECT status line too long",
            ));
        }
    }

    let status_line = String::from_utf8_lossy(&line);
    // Expected form: "HTTP/1.1 200 Connection established".
    let code = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse::<u16>().ok());
    let ok = matches!(code, Some(c) if (200..300).contains(&c));

    if ok {
        // Consume the remaining response headers up to the blank line so the
        // relay starts cleanly at the tunnelled payload. A well-behaved proxy
        // sends CRLFCRLF right after the status line for a 200.
        consume_until_header_end(remote)?;
    }
    Ok(ok)
}

/// Consume bytes from `remote` until the end of the HTTP header block
/// (`\r\n\r\n`). Used after a successful upstream CONNECT so the relay begins at
/// the tunnelled data rather than mid-header.
fn consume_until_header_end(remote: &mut TcpStream) -> std::io::Result<()> {
    // We already consumed the status line's trailing \n, so we are sitting at a
    // line boundary — start the newline counter at 1. If the very next line is
    // empty (the common `200\r\n\r\n` case with no extra headers), the next \n
    // takes us to 2 and ends the block. Any header byte resets the counter.
    // `usize`, not `u8`: a hostile/broken upstream that streams a long run of
    // newline-ish bytes must never overflow this counter (panic in debug, wrap
    // in release). The `total` cap below independently bounds the loop so the
    // read can never be unbounded regardless of the byte pattern.
    let mut byte = [0u8; 1];
    let mut consecutive_newlines = 1usize;
    let mut total = 0usize;
    loop {
        if remote.read(&mut byte)? == 0 {
            return Ok(());
        }
        match byte[0] {
            b'\n' => {
                consecutive_newlines += 1;
                if consecutive_newlines >= 2 {
                    return Ok(());
                }
            }
            b'\r' => { /* ignore, wait for the \n */ }
            _ => consecutive_newlines = 0,
        }
        total += 1;
        if total > 65536 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "upstream CONNECT headers too long",
            ));
        }
    }
}

fn relay(client: TcpStream, remote: TcpStream, timeout: Duration) {
    relay_with_ceiling(client, remote, timeout, RELAY_IDLE_TIMEOUT);
}

fn relay_with_ceiling(client: TcpStream, remote: TcpStream, timeout: Duration, ceiling: Duration) {
    let Ok(client_read) = client.try_clone() else {
        return;
    };
    let Ok(remote_write) = remote.try_clone() else {
        return;
    };
    let remote_read = remote;
    let client_write = client;

    // Reads poll at `timeout`; idleness is bounded by `ceiling`. A zero
    // timeout is rejected by the OS, which would leave the socket fully
    // blocking and the ceiling never evaluated — substitute the default.
    let poll = if timeout.is_zero() {
        DEFAULT_PROXY_TIMEOUT
    } else {
        timeout
    };
    client_read.set_read_timeout(Some(poll)).ok();
    remote_read.set_read_timeout(Some(poll)).ok();
    // Writes poll at the same interval, so a peer that stops reading is bounded
    // by `ceiling` too — otherwise a pump parked in a write would never reach
    // the ceiling check and would pin its connection slot forever. `write_all`
    // cannot be used with a write timeout (it reports the error without saying
    // how much it wrote, silently truncating a TLS record); `write_bounded`
    // tracks the offset itself, so a timeout costs a retry, not a frame.
    client_write.set_write_timeout(Some(poll)).ok();
    remote_write.set_write_timeout(Some(poll)).ok();

    // One clock for the whole tunnel, not one per direction. A long download
    // or SSE stream leaves the request direction idle from its first byte;
    // per-direction clocks would half-close that pump mid-stream and send a
    // FIN into a live connection.
    let last_activity = Arc::new(Mutex::new(Instant::now()));
    let a = Arc::clone(&last_activity);

    let t1 = std::thread::spawn(move || pump(client_read, remote_write, &a, ceiling));
    let t2 = std::thread::spawn(move || pump(remote_read, client_write, &last_activity, ceiling));

    t1.join().ok();
    t2.join().ok();
}

/// Copy one direction of a tunnel until EOF, error, or RELAY_IDLE_TIMEOUT.
///
/// Read timeouts are not fatal — they only mark elapsed idle time. Uses Write
/// shutdown (TCP half-close) so the other direction can finish delivering
/// in-flight data; shutdown(Both) would kill the read half of the shared
/// socket, breaking the other relay thread.
fn pump(mut from: TcpStream, mut to: TcpStream, last_activity: &Mutex<Instant>, ceiling: Duration) {
    let mut buf = [0u8; 8192];
    loop {
        match from.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                touch(last_activity);
                if !write_bounded(&mut to, &buf[..n], last_activity, ceiling) {
                    break;
                }
            }
            Err(e) if is_timeout(&e) => {
                if idle_for(last_activity) >= ceiling {
                    break;
                }
            }
            Err(_) => break,
        }
    }
    to.shutdown(std::net::Shutdown::Write).ok();
}

/// Write every byte of `buf`, retrying on write timeouts until the tunnel has
/// been idle for `ceiling`. Returns false when the write cannot complete.
///
/// This exists instead of `write_all` because the tunnel sockets carry a write
/// timeout. `write_all` returns a timeout error without reporting how many
/// bytes it managed to write, so the caller cannot resume — the remainder is
/// dropped and the TLS record is truncated. Tracking the offset here makes a
/// timeout a retry rather than data loss. A partial `write` is reported as
/// `Ok(n)`, so no byte is lost on the boundary either.
///
/// The ceiling is measured against the tunnel-wide clock, not this
/// direction's, so a pump stalled in a write is not reaped while the opposite
/// direction keeps the tunnel busy — a peer that stops reading but keeps
/// sending holds its slot. That is the deliberate cost of the shared clock:
/// a per-direction clock reaps this case but half-closes any one-directional
/// stream mid-flight, which is the worse failure and the one this module was
/// changed to remove.
// ponytail: narrow enough to live with; needs a real watchdog to close, not a
// second clock.
fn write_bounded(
    to: &mut TcpStream,
    buf: &[u8],
    last_activity: &Mutex<Instant>,
    ceiling: Duration,
) -> bool {
    let mut off = 0;
    while off < buf.len() {
        match to.write(&buf[off..]) {
            Ok(0) => return false,
            Ok(n) => {
                off += n;
                touch(last_activity);
            }
            Err(e) if is_timeout(&e) => {
                if idle_for(last_activity) >= ceiling {
                    return false;
                }
            }
            Err(_) => return false,
        }
    }
    true
}

fn touch(last_activity: &Mutex<Instant>) {
    if let Ok(mut t) = last_activity.lock() {
        *t = Instant::now();
    }
}

fn idle_for(last_activity: &Mutex<Instant>) -> Duration {
    last_activity
        .lock()
        .map(|t| t.elapsed())
        .unwrap_or(Duration::ZERO)
}

/// Errors that mean "nothing to read right now", not "this tunnel is dead".
///
/// `WouldBlock` / `TimedOut` are the read-timeout expiring. `Interrupted`
/// (EINTR) is a signal arriving mid-read — std does not retry it for
/// `TcpStream::read`, and treating it as fatal would kill a live tunnel.
fn is_timeout(e: &std::io::Error) -> bool {
    matches!(
        e.kind(),
        std::io::ErrorKind::WouldBlock
            | std::io::ErrorKind::TimedOut
            | std::io::ErrorKind::Interrupted
    )
}

/// Check if a hostname matches any entry in a pre-parsed blocklist.
fn is_blocked_in_list(hostname: &str, blocked_domains: &[String]) -> bool {
    let host = normalize_hostname(hostname);
    for pattern in blocked_domains {
        if host == *pattern || host.ends_with(&format!(".{pattern}")) {
            return true;
        }
    }
    false
}

pub fn is_blocked(hostname: &str, blocked_file: &PathBuf) -> bool {
    if !blocked_file.exists() {
        return false;
    }
    let contents = match std::fs::read_to_string(blocked_file) {
        Ok(c) => c,
        Err(e) => {
            eprintln!(
                "{}[proxy]{} Warning: cannot read blocklist {}: {e}",
                ui::color(ui::YELLOW),
                ui::color(ui::RESET),
                blocked_file.display()
            );
            return false;
        }
    };
    is_blocked_in_content(hostname, &contents)
}

pub fn is_blocked_in_content(hostname: &str, contents: &str) -> bool {
    let host = normalize_hostname(hostname);
    for line in contents.lines() {
        let pattern = line.trim().to_lowercase();
        if pattern.is_empty() || pattern.starts_with('#') {
            continue;
        }
        let pattern = pattern.trim_end_matches('.');
        if host == pattern || host.ends_with(&format!(".{pattern}")) {
            return true;
        }
    }
    false
}

/// Normalize a hostname (or a domain *pattern*) for consistent matching:
/// trim, lowercase, strip trailing dot — the same rule `parse_lines_file`
/// applies to file-sourced lists. Patterns must be normalized at ingest,
/// because [`is_domain_match`] normalizes only the hostname side.
pub fn normalize_hostname(host: &str) -> String {
    host.trim().to_lowercase().trim_end_matches('.').to_string()
}

/// Check if a hostname matches any entry in a domain list.
/// Matching is exact or subdomain: `example.com` matches `example.com`
/// and `sub.example.com`. Case-insensitive, trailing dots stripped.
pub fn is_domain_match(hostname: &str, domains: &[String]) -> bool {
    let host = normalize_hostname(hostname);
    for pattern in domains {
        if host == *pattern || host.ends_with(&format!(".{pattern}")) {
            return true;
        }
    }
    false
}

/// Whether `host` must BYPASS the upstream (corporate) proxy and be connected
/// to DIRECTLY by cplt, i.e. it matches the `upstream_no_proxy` list.
///
/// SECURITY: matching here does NOT bypass any filtering. Every hostname policy
/// gate (allowlist, blocklist, port policy, private-hostname) has already run in
/// `handle_connect` before this is consulted, and the direct-connect path this
/// host falls through to re-applies the resolved-IP SSRF guard
/// (`resolved_ip_is_blocked`). A no-proxy host is therefore fully policy-checked;
/// it is merely connected directly by cplt (which runs outside the sandbox)
/// rather than forwarded to the corporate proxy — so it also works under
/// `proxy.forced`. Matching reuses `is_domain_match` for consistency with cplt's
/// other domain lists (exact host + subdomain suffix).
fn host_matches_no_proxy(host: &str, no_proxy: &[String]) -> bool {
    is_domain_match(host, no_proxy)
}

/// Normalize a single NO_PROXY-style entry so `is_domain_match` handles it
/// consistently with cplt's other domain lists: trim, lowercase, and strip
/// leading AND trailing dots (`.example.com.` → `example.com`).
///
/// The trailing dot matters: the CONNECT host is normalized via
/// `normalize_hostname`, which strips a trailing dot, so an FQDN entry like
/// `example.com.` would otherwise never match `example.com`. Stripping it here
/// mirrors `parse_domain_file` / `is_blocked_in_content` (`trim_end_matches('.')`).
///
/// Returns `None` for entries that must be ignored:
/// - empty (blank field from a trailing comma or stray whitespace), and
/// - a bare `*` — in NO_PROXY this means "bypass the proxy for everything". cplt
///   deliberately does NOT honor a blanket wildcard here: silently sending ALL
///   traffic direct would disable the corporate proxy wholesale (and any egress
///   policy tied to it), so the wildcard is dropped. List real hosts instead.
pub fn normalize_no_proxy_entry(raw: &str) -> Option<String> {
    let s = raw
        .trim()
        .trim_start_matches('.')
        .trim_end_matches('.')
        .trim()
        .to_ascii_lowercase();
    if s.is_empty() || s == "*" {
        None
    } else {
        Some(s)
    }
}

/// Parse a `NO_PROXY`/`no_proxy` environment value into normalized no-proxy
/// entries. The value is comma- and/or whitespace-separated (both conventions
/// appear in the wild). Entries are normalized via [`normalize_no_proxy_entry`];
/// empty entries and a bare `*` are dropped.
pub fn parse_no_proxy_list(raw: &str) -> Vec<String> {
    raw.split([',', ' ', '\t', '\n', '\r'])
        .filter_map(normalize_no_proxy_entry)
        .collect()
}

/// Parse a domain list file into normalized entries.
/// Returns an error if the file cannot be read (fail-closed for allowlists).
pub fn parse_domain_file(path: &std::path::Path) -> Result<Vec<String>, String> {
    let contents = std::fs::read_to_string(path)
        .map_err(|e| format!("Cannot read domain file {}: {e}", path.display()))?;
    Ok(contents
        .lines()
        .map(|l| {
            let mut s = l.trim().to_lowercase();
            // Strip scheme if user pasted a URL
            if let Some(rest) = s.strip_prefix("https://") {
                s = rest.to_string();
            } else if let Some(rest) = s.strip_prefix("http://") {
                s = rest.to_string();
            }
            // Strip path/query if present
            if let Some(idx) = s.find('/') {
                s.truncate(idx);
            }
            // Strip port if present (search from end to avoid breaking IPv6 like [::1]:8080)
            if let Some(idx) = s.rfind(':')
                && s[idx + 1..].chars().all(|c| c.is_ascii_digit())
                && (s.chars().filter(|&c| c == ':').count() == 1 || s[..idx].ends_with(']'))
            {
                s.truncate(idx);
            }
            s.trim_end_matches('.').to_string()
        })
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect())
}

/// Check if a resolved IP address is private/reserved (post-DNS resolution).
/// This is the primary defense against DNS rebinding attacks.
pub fn is_private_ip(ip: &std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => {
            v4.is_loopback()                // 127.0.0.0/8
                || v4.is_private()           // 10/8, 172.16/12, 192.168/16
                || v4.is_link_local()        // 169.254.0.0/16
                || v4.is_unspecified()       // 0.0.0.0
                || v4.is_broadcast()         // 255.255.255.255
                || is_cgnat(v4)              // 100.64.0.0/10 (Tailscale, VPN)
                || is_benchmarking(v4)       // 198.18.0.0/15
                || is_reserved_v4(v4)        // 240.0.0.0/4
                || is_protocol_assign(v4) // 192.0.0.0/24
        }
        std::net::IpAddr::V6(v6) => {
            v6.is_loopback()                 // ::1
                || v6.is_unspecified()       // ::
                || is_ula(v6)                // fc00::/7 (private v6)
                || is_link_local_v6(v6)      // fe80::/10
                || is_v4_mapped_private(v6) // ::ffff:127.0.0.1 etc.
        }
    }
}

/// Decide whether a target's *resolved* IP must be blocked as a private-network
/// SSRF risk, given whether the host is an approved private domain and whether
/// the user opted into localhost access for this connection.
///
/// Semantics:
/// - A non-loopback private/reserved IP (RFC1918, CGNAT, link-local, cloud IMDS,
///   ULA, ...) is ALWAYS blocked here unless the host is an approved private
///   domain (`allow_private_domains`). The localhost opt-in never opens these.
/// - A loopback IP is blocked UNLESS the user opted into localhost access for this
///   connection (`localhost_allowed`, i.e. `--allow-localhost-any` OR the target
///   port is in the allow-listed localhost ports). This is the *config-level*
///   opt-in — it does not depend on whether the hostname literally spells
///   "localhost".
///
/// Security: a hostname that resolves to loopback (`lvh.me`, `127.0.0.1.nip.io`,
/// or alternate encodings such as `2130706433`, `0x7f000001`, `127.1`) must NOT
/// be silently exempted just because the final IP is loopback. Reaching loopback
/// services is only permitted when localhost access was explicitly requested;
/// otherwise a crafted DNS name defeats the no-localhost default — and under
/// `--proxy-forced`, where this proxy is the sole egress gate, it would tunnel to
/// arbitrary loopback services. Conversely, keying the loopback waiver on the
/// config opt-in (rather than the literal hostname) honors an explicit opt-in
/// consistently for loopback-aliasing names, without ever loosening the block on
/// non-loopback private IPs. `is_private_hostname` only catches the literal
/// `localhost` pre-DNS, so this resolved-IP check is the real gate for the rest.
pub fn resolved_ip_is_blocked(
    ip: &std::net::IpAddr,
    host_is_private_domain: bool,
    localhost_allowed: bool,
) -> bool {
    if !is_private_ip(ip) {
        return false;
    }
    // Explicitly-approved corporate/internal domains may resolve to private IPs.
    if host_is_private_domain {
        return false;
    }
    // Loopback is reachable only when localhost access was explicitly allowed;
    // every other private/reserved IP is always blocked here.
    !(ip.is_loopback() && localhost_allowed)
}

/// Check hostname patterns that are known to be private (pre-DNS fast path).
pub fn is_private_hostname(host: &str) -> bool {
    let h = host.trim_start_matches('[').trim_end_matches(']');
    // Check if it's an IP literal first
    if let Ok(ip) = h.parse::<std::net::IpAddr>() {
        return is_private_ip(&ip);
    }
    h == "localhost" || h.ends_with(".localhost") || h.ends_with(".local")
}

// CGNAT range (RFC 6598) — used by Tailscale, WireGuard, carrier NAT
fn is_cgnat(ip: &std::net::Ipv4Addr) -> bool {
    let o = ip.octets();
    o[0] == 100 && (o[1] & 0xC0) == 64 // 100.64.0.0/10
}

// Benchmarking range (RFC 2544)
fn is_benchmarking(ip: &std::net::Ipv4Addr) -> bool {
    let o = ip.octets();
    o[0] == 198 && (o[1] & 0xFE) == 18 // 198.18.0.0/15
}

// Reserved/future use (RFC 1112)
fn is_reserved_v4(ip: &std::net::Ipv4Addr) -> bool {
    ip.octets()[0] >= 240 // 240.0.0.0/4
}

// IETF protocol assignments (RFC 6890)
fn is_protocol_assign(ip: &std::net::Ipv4Addr) -> bool {
    let o = ip.octets();
    o[0] == 192 && o[1] == 0 && o[2] == 0 // 192.0.0.0/24
}

// IPv6 Unique Local Address (RFC 4193)
fn is_ula(ip: &std::net::Ipv6Addr) -> bool {
    (ip.segments()[0] & 0xFE00) == 0xFC00 // fc00::/7
}

// IPv6 link-local (RFC 4291)
fn is_link_local_v6(ip: &std::net::Ipv6Addr) -> bool {
    (ip.segments()[0] & 0xFFC0) == 0xFE80 // fe80::/10
}

// IPv4-mapped IPv6 addresses with private IPv4
fn is_v4_mapped_private(ip: &std::net::Ipv6Addr) -> bool {
    if let Some(v4) = ip.to_ipv4_mapped() {
        v4.is_loopback()
            || v4.is_private()
            || v4.is_link_local()
            || v4.is_unspecified()
            || is_cgnat(&v4)
    } else {
        false
    }
}

fn log_connection(state: &ProxyState, method: &str, target: &str, status: &str) {
    let log_file = state.log_file.as_deref();
    let level = state.log_level;

    // SECURITY: `method` and `target` are agent-controlled. Both are sliced
    // straight out of the CONNECT request line in `handle_connection`, and this
    // function is the ONE sink they reach: the stderr verdict line below, the
    // `--proxy-log` audit file, and — via `record_observation` — the observed
    // host set that `--observe-domains-out` writes as a ready-to-paste
    // allowlist. Escaping here therefore covers all three.
    //
    // `lines()` + `split_whitespace()` upstream already make CR/LF (and every
    // other whitespace class, incl. VT/FF/NEL/U+2028) unforgeable, so the
    // space-delimited audit format cannot be forged. ESC (0x1b) is NOT
    // whitespace and survived untouched: a target of "\x1b[2K\r" let the agent
    // ERASE or overwrite the very BLOCKED lines the user is watching, and
    // landed raw in the audit file for `cat` to re-emit.
    //
    // Escape rather than strip: the audit log must show that something odd was
    // attempted, not silently swallow it. `escape_debug` leaves printable
    // Unicode alone (IDN hostnames, punycode and UTF-8 alike) while covering
    // C0/C1, DEL, bidi overrides and zero-width formatters — a wider net than
    // "strip C0 controls" for one stdlib call, and lossless.
    let (method, target, status) = (
        method.escape_debug().to_string(),
        target.escape_debug().to_string(),
        status.escape_debug().to_string(),
    );
    let (method, target, status) = (method.as_str(), target.as_str(), status.as_str());

    // Record the observation for every CONNECT verdict, regardless of the stderr
    // log level or whether a --proxy-log file is set. This is the single choke
    // point every verdict flows through, so the collector sees the FULL set of
    // hosts the agent contacted. Only CONNECT targets are hostnames; REJECT /
    // INTERNAL / non-CONNECT-method log lines carry no host and are skipped.
    if method.eq_ignore_ascii_case("CONNECT") {
        let host = target.rsplit_once(':').map_or(target, |(h, _)| h);
        let verdict = if status.starts_with("BLOCKED") {
            DomainVerdict::Blocked
        } else {
            DomainVerdict::Allowed
        };
        state.record_observation(host, verdict);
    }

    if level.should_log(status) {
        let color = match status {
            "BLOCKED" | "BLOCKED-PRIVATE" | "BLOCKED-PORT" | "BLOCKED-ALLOWLIST" | "LIMIT" => {
                ui::color(ui::RED)
            }
            "CONNECTED" => ui::color(ui::GREEN),
            _ => ui::color(ui::YELLOW),
        };
        let timestamp = chrono_now();
        eprintln!(
            "{color}[proxy]{} {timestamp} {method} {target} → {status}",
            ui::color(ui::RESET)
        );
    }

    // Append to audit log file (reopen per-write for rotation compatibility)
    if let Some(path) = log_file
        && let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
    {
        let iso = iso_now();
        let _ = writeln!(f, "{iso} {method} {target} {status}");
    }
}

fn chrono_now() -> String {
    use std::time::SystemTime;
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = now.as_secs();
    let hours = (secs % 86400) / 3600;
    let mins = (secs % 3600) / 60;
    let s = secs % 60;
    format!("{hours:02}:{mins:02}:{s:02}")
}

fn iso_now() -> String {
    use std::time::SystemTime;
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = now.as_secs();
    let days = secs / 86400;
    let rem = secs % 86400;
    // Approximate date calculation (sufficient for log timestamps)
    let (y, m, d) = days_to_ymd(days);
    let h = rem / 3600;
    let mi = (rem % 3600) / 60;
    let s = rem % 60;
    format!("{y:04}-{m:02}-{d:02}T{h:02}:{mi:02}:{s:02}Z")
}

fn days_to_ymd(days: u64) -> (u64, u64, u64) {
    // Civil calendar from day count (algorithm from Howard Hinnant)
    let z = days as i64 + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y } as u64;
    (y, m, d)
}

use std::net::ToSocketAddrs;

#[cfg(test)]
mod tests {
    use super::*;

    // ── classify_connect: the shared static gate order ──

    fn np(allowed: &[&str], blocked: &[&str], ports: &[u16]) -> NetPolicy {
        NetPolicy {
            allowed_ports: ports.to_vec(),
            allowed_domains: allowed.iter().map(|s| (*s).to_string()).collect(),
            blocked_domains: blocked.iter().map(|s| (*s).to_string()).collect(),
            allow_localhost_ports: Vec::new(),
            allow_localhost_any: false,
            ..Default::default()
        }
    }

    #[test]
    fn classify_gate_order_matches_live_proxy() {
        // Port is checked first.
        assert_eq!(
            classify_connect(&np(&[], &[], &[443]), "github.com", 22),
            NetVerdict::BlockedPort
        );
        // Then the fail-closed allowlist.
        assert_eq!(
            classify_connect(&np(&["github.com"], &[], &[443]), "evil.example", 443),
            NetVerdict::BlockedAllowlist
        );
        // Empty allowlist = allow-all.
        assert_eq!(
            classify_connect(&np(&[], &[], &[443]), "anything.example", 443),
            NetVerdict::Allowed
        );
        // Blocklist applies even when the allowlist would pass.
        assert_eq!(
            classify_connect(
                &np(&["evil.example"], &["evil.example"], &[443]),
                "evil.example",
                443
            ),
            NetVerdict::Blocked
        );
        // Private/link-local SSRF guard (cloud metadata).
        assert_eq!(
            classify_connect(&np(&[], &[], &[443]), "169.254.169.254", 443),
            NetVerdict::BlockedPrivate
        );
    }

    #[test]
    fn classify_localhost_opt_in_bypasses_gates() {
        let mut policy = np(&["github.com"], &[], &[443]);
        // Without opt-in, localhost:3000 fails the port gate.
        assert_eq!(
            classify_connect(&policy, "localhost", 3000),
            NetVerdict::BlockedPort
        );
        // Opting the port in exempts it from port, allowlist, and SSRF gates.
        policy.allow_localhost_ports = vec![3000];
        assert_eq!(
            classify_connect(&policy, "localhost", 3000),
            NetVerdict::Allowed
        );
    }

    #[test]
    fn check_allowlist_parser_matches_live_enforcement() {
        // FIX 1: `cplt check` must build its allowlist through the SAME parser the
        // live cache uses (`parse_lines_file`), not `parse_domain_file`. A
        // non-canonical entry like `github.com:443` is a divergence point:
        //   - `parse_lines_file` (live + check now)  → stores "github.com:443"
        //   - `parse_domain_file` (check, the bug)   → strips port to "github.com"
        // With the port-stripping parser, check reported ALLOWED for `github.com`
        // while the live proxy (matching the verbatim "github.com:443") returns
        // BLOCKED-ALLOWLIST — a dangerous false ALLOWED. Prove the two parsers
        // diverge and that the shared `parse_lines_file` path now agrees with live.
        let dir = test_dir("allowlist-parity");
        let path = dir.join("allowed_domains.txt");
        std::fs::write(&path, "github.com:443\n").unwrap();

        // The parser the live allowlist cache feeds (and now `build_net_policy`).
        let live_list = parse_lines_file(&path).unwrap();
        assert_eq!(live_list, vec!["github.com:443"]);
        // The over-normalizing parser the check path used to use.
        let stripped_list = parse_domain_file(&path).unwrap();
        assert_eq!(stripped_list, vec!["github.com"]);

        // Same host, same gate logic — the verdict now agrees with live: BLOCKED.
        let live_policy = np(&["github.com:443"], &[], &[443]);
        assert_eq!(
            classify_connect(&live_policy, "github.com", 443),
            NetVerdict::BlockedAllowlist,
            "the live/check-parity allowlist blocks a host it does not verbatim match"
        );
        // The old stripped list would have wrongly reported ALLOWED — the bug.
        let stripped_policy = np(&["github.com"], &[], &[443]);
        assert_eq!(
            classify_connect(&stripped_policy, "github.com", 443),
            NetVerdict::Allowed,
            "the over-normalized allowlist produced the false ALLOWED this fix removes"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn net_verdict_status_strings() {
        assert_eq!(NetVerdict::Allowed.status(), "ALLOWED");
        assert_eq!(NetVerdict::BlockedPort.status(), "BLOCKED-PORT");
        assert_eq!(NetVerdict::BlockedAllowlist.status(), "BLOCKED-ALLOWLIST");
        assert_eq!(NetVerdict::Blocked.status(), "BLOCKED");
        assert_eq!(NetVerdict::BlockedPrivate.status(), "BLOCKED-PRIVATE");
    }

    /// Create a unique temp directory for test isolation.
    fn test_dir(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("cplt-test-proxy-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn resolved_loopback_blocked_unless_localhost_allowed() {
        // A target that resolves to loopback (e.g. lvh.me, 127.0.0.1.nip.io,
        // 2130706433, 0x7f000001, 127.1) must be BLOCKED when localhost access
        // was not explicitly allowed, and ALLOWED when it was. No real DNS is
        // needed — the decision is a pure function of the resolved IP.
        let loopback: std::net::IpAddr = "127.0.0.1".parse().unwrap();

        // Not allowed, not a private domain → blocked.
        assert!(
            resolved_ip_is_blocked(&loopback, false, false),
            "loopback-resolving target must be blocked when localhost not allowed"
        );

        // Localhost explicitly allowed → permitted.
        assert!(
            !resolved_ip_is_blocked(&loopback, false, true),
            "loopback must be reachable when localhost access is allowed"
        );

        // Approved private domain → permitted even without localhost flag.
        assert!(
            !resolved_ip_is_blocked(&loopback, true, false),
            "approved private domain resolving to loopback is permitted"
        );

        // IPv6 loopback behaves the same.
        let loopback_v6: std::net::IpAddr = "::1".parse().unwrap();
        assert!(resolved_ip_is_blocked(&loopback_v6, false, false));
        assert!(!resolved_ip_is_blocked(&loopback_v6, false, true));
    }

    #[test]
    fn resolved_non_loopback_private_always_blocked() {
        // Non-loopback private/reserved IPs are blocked regardless of the
        // localhost flag — the carve-out is loopback-only.
        let imds: std::net::IpAddr = "169.254.169.254".parse().unwrap(); // cloud IMDS
        let rfc1918: std::net::IpAddr = "10.0.0.5".parse().unwrap();
        for allowed in [false, true] {
            assert!(
                resolved_ip_is_blocked(&imds, false, allowed),
                "link-local IMDS must be blocked even with localhost allowed"
            );
            assert!(
                resolved_ip_is_blocked(&rfc1918, false, allowed),
                "RFC1918 private IP must be blocked even with localhost allowed"
            );
        }
        // But an approved private domain may reach a private (non-loopback) IP.
        assert!(!resolved_ip_is_blocked(&rfc1918, true, false));

        // Public IPs are never blocked by this gate.
        let public: std::net::IpAddr = "93.184.216.34".parse().unwrap();
        assert!(!resolved_ip_is_blocked(&public, false, false));
    }

    #[test]
    fn domain_cache_returns_cached_within_ttl() {
        let cache = Mutex::new(DomainCache::new(vec!["example.com".to_string()]));
        let result = get_cached_domains(&cache, None, |_| panic!("should not call parser"));
        assert_eq!(result, vec!["example.com"]);
    }

    #[test]
    fn domain_cache_reloads_after_ttl() {
        let dir = test_dir("reload");
        let path = dir.join("domains.txt");
        std::fs::write(&path, "old.com\n").unwrap();

        let cache = Mutex::new(DomainCache {
            domains: vec!["old.com".to_string()],
            last_attempt: Instant::now()
                .checked_sub(RELOAD_TTL + Duration::from_millis(100))
                .unwrap(),
        });

        let result = get_cached_domains(&cache, Some(&path), parse_lines_file);
        assert_eq!(result, vec!["old.com"]);

        // Modify file and force stale
        std::fs::write(&path, "new.com\n").unwrap();
        cache.lock().unwrap().last_attempt = Instant::now()
            .checked_sub(RELOAD_TTL + Duration::from_millis(100))
            .unwrap();

        let result = get_cached_domains(&cache, Some(&path), parse_lines_file);
        assert_eq!(result, vec!["new.com"]);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn domain_cache_keeps_last_good_on_failure() {
        let cache = Mutex::new(DomainCache {
            domains: vec!["good.com".to_string()],
            last_attempt: Instant::now()
                .checked_sub(RELOAD_TTL + Duration::from_millis(100))
                .unwrap(),
        });

        let bad_path = Path::new("/tmp/nonexistent-cplt-test-file-xyz.txt");
        let result = get_cached_domains(&cache, Some(bad_path), parse_lines_file);
        assert_eq!(
            result,
            vec!["good.com"],
            "should keep last-good list on failure"
        );
    }

    #[test]
    fn domain_cache_resets_ttl_after_failure() {
        let cache = Mutex::new(DomainCache {
            domains: vec!["good.com".to_string()],
            last_attempt: Instant::now()
                .checked_sub(RELOAD_TTL + Duration::from_millis(100))
                .unwrap(),
        });

        let bad_path = Path::new("/tmp/nonexistent-cplt-test-file-xyz.txt");
        let _ = get_cached_domains(&cache, Some(bad_path), parse_lines_file);

        let guard = cache.lock().unwrap();
        assert!(!guard.is_stale(), "TTL should be reset after failed reload");
    }

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

    #[test]
    fn proxy_state_merges_cli_and_config_private_domains() {
        let state = ProxyState {
            blocked_file: PathBuf::from("/dev/null"),
            blocked_cache: Mutex::new(DomainCache::new(Vec::new())),
            allowed_domains_file: None,
            allowlist_cache: Mutex::new(DomainCache::new(Vec::new())),
            default_allowlist: Vec::new(),
            subscription_blocklist: Vec::new(),
            sticky_private_domains: vec!["cli.example.com".to_string()],
            config_file: None,
            private_domains_cache: Mutex::new(DomainCache::new(vec![
                "config.example.com".to_string(),
            ])),
            allowed_ports: vec![443],
            allow_localhost_ports: Vec::new(),
            allow_localhost_any: false,
            log_file: None,
            log_level: ProxyLogLevel::None,
            timeout: Duration::from_secs(60),
            upstream: None,
            upstream_no_proxy: Vec::new(),
            domain_collector: Arc::new(Mutex::new(BTreeMap::new())),
            resolver: None,
        };

        let domains = state.get_private_domains();
        assert!(domains.contains(&"cli.example.com".to_string()));
        assert!(domains.contains(&"config.example.com".to_string()));
    }

    #[test]
    fn proxy_state_private_domains_deduplicates() {
        let state = ProxyState {
            blocked_file: PathBuf::from("/dev/null"),
            blocked_cache: Mutex::new(DomainCache::new(Vec::new())),
            allowed_domains_file: None,
            allowlist_cache: Mutex::new(DomainCache::new(Vec::new())),
            default_allowlist: Vec::new(),
            subscription_blocklist: Vec::new(),
            sticky_private_domains: vec!["shared.com".to_string()],
            config_file: None,
            private_domains_cache: Mutex::new(DomainCache::new(vec!["shared.com".to_string()])),
            allowed_ports: vec![443],
            allow_localhost_ports: Vec::new(),
            allow_localhost_any: false,
            log_file: None,
            log_level: ProxyLogLevel::None,
            timeout: Duration::from_secs(60),
            upstream: None,
            upstream_no_proxy: Vec::new(),
            domain_collector: Arc::new(Mutex::new(BTreeMap::new())),
            resolver: None,
        };

        let domains = state.get_private_domains();
        assert_eq!(
            domains.iter().filter(|d| *d == "shared.com").count(),
            1,
            "duplicates should be removed"
        );
    }

    #[test]
    fn proxy_state_allowlist_empty_when_no_file() {
        let state = ProxyState {
            blocked_file: PathBuf::from("/dev/null"),
            blocked_cache: Mutex::new(DomainCache::new(Vec::new())),
            allowed_domains_file: None,
            allowlist_cache: Mutex::new(DomainCache::new(vec![
                "should-not-appear.com".to_string(),
            ])),
            default_allowlist: Vec::new(),
            subscription_blocklist: Vec::new(),
            sticky_private_domains: Vec::new(),
            config_file: None,
            private_domains_cache: Mutex::new(DomainCache::new(Vec::new())),
            allowed_ports: vec![443],
            allow_localhost_ports: Vec::new(),
            allow_localhost_any: false,
            log_file: None,
            log_level: ProxyLogLevel::None,
            timeout: Duration::from_secs(60),
            upstream: None,
            upstream_no_proxy: Vec::new(),
            domain_collector: Arc::new(Mutex::new(BTreeMap::new())),
            resolver: None,
        };

        let domains = state.get_allowed_domains();
        assert!(domains.is_empty(), "no file configured = no allowlist");
    }

    #[test]
    fn proxy_state_blocked_domains_from_file() {
        let dir = test_dir("blocked");
        let path = dir.join("blocked.txt");
        std::fs::write(&path, "evil.com\nbad.org\n").unwrap();

        let state = ProxyState {
            blocked_file: path,
            blocked_cache: Mutex::new(DomainCache {
                domains: Vec::new(),
                last_attempt: Instant::now()
                    .checked_sub(RELOAD_TTL + Duration::from_millis(100))
                    .unwrap(),
            }),
            allowed_domains_file: None,
            allowlist_cache: Mutex::new(DomainCache::new(Vec::new())),
            default_allowlist: Vec::new(),
            subscription_blocklist: Vec::new(),
            sticky_private_domains: Vec::new(),
            config_file: None,
            private_domains_cache: Mutex::new(DomainCache::new(Vec::new())),
            allowed_ports: vec![443],
            allow_localhost_ports: Vec::new(),
            allow_localhost_any: false,
            log_file: None,
            log_level: ProxyLogLevel::None,
            timeout: Duration::from_secs(60),
            upstream: None,
            upstream_no_proxy: Vec::new(),
            domain_collector: Arc::new(Mutex::new(BTreeMap::new())),
            resolver: None,
        };

        let blocked = state.get_blocked_domains();
        assert_eq!(blocked, vec!["evil.com", "bad.org"]);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn proxy_state_dynamic_reload_picks_up_changes() {
        let dir = test_dir("dynamic-reload");
        let config_path = dir.join("config.toml");
        std::fs::write(
            &config_path,
            "[proxy]\nallow_private_domains = [\"old.nav.no\"]\n",
        )
        .unwrap();

        let state = ProxyState {
            blocked_file: PathBuf::from("/dev/null"),
            blocked_cache: Mutex::new(DomainCache::new(Vec::new())),
            allowed_domains_file: None,
            allowlist_cache: Mutex::new(DomainCache::new(Vec::new())),
            default_allowlist: Vec::new(),
            subscription_blocklist: Vec::new(),
            sticky_private_domains: vec!["cli.nav.no".to_string()],
            config_file: Some(config_path.clone()),
            private_domains_cache: Mutex::new(DomainCache {
                domains: vec!["old.nav.no".to_string()],
                last_attempt: Instant::now()
                    .checked_sub(RELOAD_TTL + Duration::from_millis(100))
                    .unwrap(),
            }),
            allowed_ports: vec![443],
            allow_localhost_ports: Vec::new(),
            allow_localhost_any: false,
            log_file: None,
            log_level: ProxyLogLevel::None,
            timeout: Duration::from_secs(60),
            upstream: None,
            upstream_no_proxy: Vec::new(),
            domain_collector: Arc::new(Mutex::new(BTreeMap::new())),
            resolver: None,
        };

        // First read: picks up "old.nav.no" from cache reload + "cli.nav.no"
        let domains = state.get_private_domains();
        assert!(domains.contains(&"old.nav.no".to_string()));
        assert!(domains.contains(&"cli.nav.no".to_string()));

        // Simulate config edit mid-session
        std::fs::write(
            &config_path,
            "[proxy]\nallow_private_domains = [\"new.nav.no\"]\n",
        )
        .unwrap();

        // Force TTL expiry
        state.private_domains_cache.lock().unwrap().last_attempt = Instant::now()
            .checked_sub(RELOAD_TTL + Duration::from_millis(100))
            .unwrap();

        let domains = state.get_private_domains();
        assert!(domains.contains(&"new.nav.no".to_string()));
        assert!(domains.contains(&"cli.nav.no".to_string()));
        assert!(
            !domains.contains(&"old.nav.no".to_string()),
            "old config domain should be gone after reload"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// #186: private domains whose source is read once — CLI flags and
    /// trust-approved `[propose.proxy] allow_private_domains` from the repo
    /// `.cplt.toml` — must survive the global config file's 5-second reload,
    /// while domains that file actually supplies keep following it (including
    /// being revoked when removed).
    #[test]
    fn private_domain_sources_survive_or_follow_the_config_reload() {
        let dir = test_dir("private-domains-186");
        let blocked = dir.join("blocked.txt");
        std::fs::write(&blocked, "").unwrap();
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

        let handle = start(ProxyOptions {
            port: 0,
            blocked_file: blocked,
            allowed_ports: vec![],
            allow_localhost_ports: Vec::new(),
            allow_localhost_any: false,
            allowed_domains_file: None,
            allowed_domains_initial: Vec::new(),
            default_allowlist: Vec::new(),
            subscription_blocklist: Vec::new(),
            cli_private_domains,
            config_private_domains,
            repo_private_domains,
            config_file: Some(config_path.clone()),
            log_file: None,
            log_level: ProxyLogLevel::None,
            timeout: Duration::from_secs(60),
            upstream: None,
            upstream_no_proxy: Vec::new(),
            resolver: None,
        })
        .expect("proxy start failed");
        let state = handle.state.clone().expect("test state handle");

        let expire = || {
            state.private_domains_cache.lock().unwrap().last_attempt = Instant::now()
                .checked_sub(RELOAD_TTL + Duration::from_millis(100))
                .unwrap();
        };
        let has = |d: &str| state.get_private_domains().iter().any(|x| x == d);

        for d in [
            "cli.nav.no",
            "global-a.nav.no",
            "global-b.nav.no",
            "mimir.nav.cloud.nais.io",
        ] {
            assert!(has(d), "{d} must be allowed at startup");
        }

        // The reload that fires 5 seconds into a real session.
        expire();
        assert!(
            has("mimir.nav.cloud.nais.io"),
            "trust-approved repo domain must survive the config reload"
        );
        assert!(has("cli.nav.no"), "CLI domain must survive the reload");
        assert!(
            has("global-a.nav.no") && has("global-b.nav.no"),
            "multi-line config array must still be read on reload"
        );

        // Revoking one entry from the config file takes effect within the TTL.
        std::fs::write(
            &config_path,
            "[proxy]\nallow_private_domains = [\"global-a.nav.no\"]  # b revoked\n",
        )
        .unwrap();
        expire();
        assert!(has("global-a.nav.no"), "remaining config entry stays");
        assert!(
            !has("global-b.nav.no"),
            "config-file domain must be revocable by editing the file"
        );
        assert!(has("mimir.nav.cloud.nais.io") && has("cli.nav.no"));

        // Dropping the section revokes the rest of the file's entries.
        std::fs::write(&config_path, "[allow]\nread = []\n").unwrap();
        expire();
        assert!(
            !has("global-a.nav.no"),
            "removing the section must revoke its domains"
        );
        assert!(
            has("mimir.nav.cloud.nais.io") && has("cli.nav.no"),
            "once-read sources are not revoked by a config edit"
        );

        handle.shutdown();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn is_blocked_in_list_matches_exact_and_subdomain() {
        let blocked = vec!["evil.com".to_string(), "bad.org".to_string()];
        assert!(is_blocked_in_list("evil.com", &blocked));
        assert!(is_blocked_in_list("sub.evil.com", &blocked));
        assert!(!is_blocked_in_list("notevil.com", &blocked));
        assert!(!is_blocked_in_list("good.com", &blocked));
    }

    #[test]
    fn proxy_start_validates_blocklist_at_startup() {
        let dir = test_dir("start-valid");
        let blocked = dir.join("blocked.txt");
        std::fs::write(&blocked, "test.com\n").unwrap();

        let result = start(ProxyOptions {
            port: 0,
            blocked_file: blocked,
            allowed_ports: vec![],
            allow_localhost_ports: Vec::new(),
            allow_localhost_any: false,
            allowed_domains_file: None,
            allowed_domains_initial: Vec::new(),
            default_allowlist: Vec::new(),
            subscription_blocklist: Vec::new(),
            cli_private_domains: Vec::new(),
            config_private_domains: Vec::new(),
            repo_private_domains: Vec::new(),
            config_file: None,
            log_file: None,
            log_level: ProxyLogLevel::None,
            timeout: Duration::from_secs(60),
            upstream: None,
            upstream_no_proxy: Vec::new(),
            resolver: None,
        });
        assert!(result.is_ok());
        result.unwrap().shutdown();

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn proxy_start_fails_on_unreadable_allowlist() {
        let dir = test_dir("start-fail");
        let blocked = dir.join("blocked.txt");
        std::fs::write(&blocked, "").unwrap();

        // Create a directory where a file is expected (unreadable as file)
        let allowlist_path = dir.join("allowlist");
        std::fs::create_dir(&allowlist_path).unwrap();

        let result = start(ProxyOptions {
            port: 0,
            blocked_file: blocked,
            allowed_ports: vec![],
            allow_localhost_ports: Vec::new(),
            allow_localhost_any: false,
            allowed_domains_file: Some(allowlist_path),
            allowed_domains_initial: Vec::new(),
            default_allowlist: Vec::new(),
            subscription_blocklist: Vec::new(),
            cli_private_domains: Vec::new(),
            config_private_domains: Vec::new(),
            repo_private_domains: Vec::new(),
            config_file: None,
            log_file: None,
            log_level: ProxyLogLevel::None,
            timeout: Duration::from_secs(60),
            upstream: None,
            upstream_no_proxy: Vec::new(),
            resolver: None,
        });
        assert!(result.is_err(), "should fail when allowlist is unreadable");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn proxy_state_allowlist_reloads_from_file() {
        let dir = test_dir("allowlist-reload");
        let path = dir.join("allowed.txt");
        std::fs::write(&path, "github.com\n").unwrap();

        let state = ProxyState {
            blocked_file: PathBuf::from("/dev/null"),
            blocked_cache: Mutex::new(DomainCache::new(Vec::new())),
            allowed_domains_file: Some(path.clone()),
            allowlist_cache: Mutex::new(DomainCache {
                domains: vec!["github.com".to_string()],
                last_attempt: Instant::now()
                    .checked_sub(RELOAD_TTL + Duration::from_millis(100))
                    .unwrap(),
            }),
            default_allowlist: Vec::new(),
            subscription_blocklist: Vec::new(),
            sticky_private_domains: Vec::new(),
            config_file: None,
            private_domains_cache: Mutex::new(DomainCache::new(Vec::new())),
            allowed_ports: vec![443],
            allow_localhost_ports: Vec::new(),
            allow_localhost_any: false,
            log_file: None,
            log_level: ProxyLogLevel::None,
            timeout: Duration::from_secs(60),
            upstream: None,
            upstream_no_proxy: Vec::new(),
            domain_collector: Arc::new(Mutex::new(BTreeMap::new())),
            resolver: None,
        };

        // Initial read picks up github.com from stale cache (triggers reload)
        let domains = state.get_allowed_domains();
        assert_eq!(domains, vec!["github.com"]);

        // Edit file
        std::fs::write(&path, "github.com\nnpm.pkg.github.com\n").unwrap();
        state.allowlist_cache.lock().unwrap().last_attempt = Instant::now()
            .checked_sub(RELOAD_TTL + Duration::from_millis(100))
            .unwrap();

        let domains = state.get_allowed_domains();
        assert!(domains.contains(&"npm.pkg.github.com".to_string()));

        let _ = std::fs::remove_dir_all(&dir);
    }

    // ── Default allowlist (issue #52): effective-allowlist merge logic ──────

    /// Build a ProxyState wired for default-allowlist merge tests: a frozen
    /// agent `default_allowlist` plus an optional user `allowed_domains` file.
    fn state_for_allowlist(default_allowlist: Vec<String>, file: Option<PathBuf>) -> ProxyState {
        let initial = file
            .as_deref()
            .and_then(parse_lines_file)
            .unwrap_or_default();
        ProxyState {
            blocked_file: PathBuf::from("/dev/null"),
            blocked_cache: Mutex::new(DomainCache::new(Vec::new())),
            subscription_blocklist: Vec::new(),
            allowed_domains_file: file,
            allowlist_cache: Mutex::new(DomainCache::new(initial)),
            default_allowlist,
            sticky_private_domains: Vec::new(),
            config_file: None,
            private_domains_cache: Mutex::new(DomainCache::new(Vec::new())),
            allowed_ports: vec![443],
            allow_localhost_ports: Vec::new(),
            allow_localhost_any: false,
            log_file: None,
            log_level: ProxyLogLevel::None,
            timeout: Duration::from_secs(60),
            upstream: None,
            upstream_no_proxy: Vec::new(),
            domain_collector: Arc::new(Mutex::new(BTreeMap::new())),
            resolver: None,
        }
    }

    /// Build a ProxyState with an in-memory blocklist + subscription blocklist
    /// for issue #144 merge tests. `blocked_file` is `/dev/null` and the caches
    /// are seeded fresh, so `get_blocked_domains` reads the in-memory values.
    fn state_for_blocklist(file_domains: Vec<String>, subscription: Vec<String>) -> ProxyState {
        ProxyState {
            blocked_file: PathBuf::from("/dev/null"),
            blocked_cache: Mutex::new(DomainCache::new(file_domains)),
            subscription_blocklist: subscription,
            allowed_domains_file: None,
            allowlist_cache: Mutex::new(DomainCache::new(Vec::new())),
            default_allowlist: Vec::new(),
            sticky_private_domains: Vec::new(),
            config_file: None,
            private_domains_cache: Mutex::new(DomainCache::new(Vec::new())),
            allowed_ports: vec![443],
            allow_localhost_ports: Vec::new(),
            allow_localhost_any: false,
            log_file: None,
            log_level: ProxyLogLevel::None,
            timeout: Duration::from_secs(60),
            upstream: None,
            upstream_no_proxy: Vec::new(),
            resolver: None,
            domain_collector: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }

    #[test]
    fn subscription_blocklist_merges_into_effective_blocklist() {
        // Cached subscription domains UNION with the local/built-in blocklist.
        let state = state_for_blocklist(
            vec!["local.example".to_string()],
            vec!["sub.example".to_string()],
        );
        let eff = state.get_blocked_domains();
        assert!(is_blocked_in_list("local.example", &eff), "local kept");
        assert!(
            is_blocked_in_list("sub.example", &eff),
            "subscription added"
        );
        // Exact-or-subdomain matcher still applies to subscription domains.
        assert!(is_blocked_in_list("host.sub.example", &eff));
        assert!(!is_blocked_in_list("allowed.example", &eff));
    }

    #[test]
    fn empty_subscription_blocklist_is_noop() {
        // No-regression: empty subscription list → exactly the file domains,
        // byte-identical to today's behaviour.
        let with_empty = state_for_blocklist(vec!["local.example".to_string()], Vec::new());
        assert_eq!(
            with_empty.get_blocked_domains(),
            vec!["local.example".to_string()]
        );
    }

    #[test]
    fn default_allowlist_merges_and_fails_closed() {
        let defaults: Vec<String> = crate::agent::Agent::Copilot
            .default_allowed_domains()
            .iter()
            .map(ToString::to_string)
            .collect();
        let state = state_for_allowlist(defaults, None);
        let eff = state.get_allowed_domains();
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

        let state = state_for_allowlist(vec!["github.com".to_string()], Some(path));
        let eff = state.get_allowed_domains();
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
        let state = state_for_allowlist(Vec::new(), None);
        assert!(
            state.get_allowed_domains().is_empty(),
            "default off must remain allow-all"
        );
    }

    #[test]
    fn collector_records_verdicts_dedups_and_normalizes() {
        // The observation collector must record both allowed and blocked hosts
        // with the right verdict, collapse case/trailing-dot variants of the
        // same host into one entry, and count repeat CONNECTs.
        let state = state_for_allowlist(Vec::new(), None);
        state.record_observation("api.github.com", DomainVerdict::Allowed);
        // Same host, different spelling: uppercase + trailing dot must normalize
        // to the same key rather than creating a second entry.
        state.record_observation("API.GitHub.com.", DomainVerdict::Allowed);
        state.record_observation("evil.example", DomainVerdict::Blocked);

        let map = state
            .domain_collector
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        assert_eq!(
            map.len(),
            2,
            "case/trailing-dot variants must collapse to one host"
        );
        let gh = map.get("api.github.com").expect("host recorded normalized");
        assert_eq!(gh.verdict, DomainVerdict::Allowed);
        assert_eq!(gh.count, 2, "repeat CONNECTs must increment the count");
        assert_eq!(
            map.get("evil.example")
                .expect("blocked host recorded")
                .verdict,
            DomainVerdict::Blocked
        );
    }

    #[test]
    fn collector_blocked_verdict_is_sticky() {
        // A host seen blocked once must stay Blocked in the observed set even if
        // a later attempt is allowed, so the list always flags what policy
        // refused.
        let state = state_for_allowlist(Vec::new(), None);
        state.record_observation("x.example", DomainVerdict::Allowed);
        state.record_observation("x.example", DomainVerdict::Blocked);
        state.record_observation("x.example", DomainVerdict::Allowed);

        let map = state
            .domain_collector
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let entry = map.get("x.example").expect("host recorded");
        assert_eq!(
            entry.verdict,
            DomainVerdict::Blocked,
            "blocked verdict must be sticky"
        );
        assert_eq!(entry.count, 3);
    }

    #[test]
    fn observed_domains_sorted_and_unique() {
        // observed_domains() returns hosts sorted and deduplicated (the BTreeMap
        // key ordering) with verdict + count, ready for a paste-able allowlist.
        let collector: Arc<DomainCollector> = Arc::new(Mutex::new(BTreeMap::new()));
        {
            let mut map = collector.lock().unwrap();
            map.insert(
                "b.example".to_string(),
                DomainObservation {
                    verdict: DomainVerdict::Allowed,
                    count: 3,
                },
            );
            map.insert(
                "a.example".to_string(),
                DomainObservation {
                    verdict: DomainVerdict::Blocked,
                    count: 1,
                },
            );
        }
        let handle = ProxyHandle {
            shutdown_flag: Arc::new(std::sync::atomic::AtomicBool::new(true)),
            port: 0,
            domain_collector: collector,
            state: None,
        };
        let observed = handle.observed_domains();
        let hosts: Vec<&str> = observed.iter().map(|o| o.host.as_str()).collect();
        assert_eq!(hosts, vec!["a.example", "b.example"], "must be sorted");
        assert_eq!(observed[0].verdict, DomainVerdict::Blocked);
        assert_eq!(observed[1].count, 3);
    }

    /// Skip guard for tests that make real TCP connections.
    /// These tests require localhost TCP access, which is blocked inside the cplt sandbox.
    macro_rules! require_localhost_tcp {
        () => {
            if std::env::var("__CPLT_WRAPPED").is_ok() {
                eprintln!("SKIPPED: proxy CONNECT tests require localhost TCP (blocked inside cplt sandbox)");
                return;
            }
        };
    }

    /// Start a proxy with a default allowlist for end-to-end CONNECT tests.
    /// Traffic is forwarded to the (fake) `upstream`; a public-IP resolver is
    /// injected so the SSRF/resolved-IP guard passes deterministically for
    /// allowed domains without real DNS. Blocked domains never reach either.
    fn make_proxy_default_allowlist(
        default_allowlist: Vec<String>,
        allowed_domains_file: Option<PathBuf>,
        upstream: UpstreamProxy,
    ) -> ProxyHandle {
        let public_ip: std::net::IpAddr = "93.184.216.34".parse().unwrap();
        let resolver: ResolverFn =
            Arc::new(move |_h: &str, p: u16| Some(std::net::SocketAddr::new(public_ip, p)));
        start(ProxyOptions {
            port: 0,
            blocked_file: PathBuf::from("/dev/null"),
            allowed_ports: vec![443, 80],
            allow_localhost_ports: Vec::new(),
            allow_localhost_any: false,
            allowed_domains_file,
            allowed_domains_initial: Vec::new(),
            default_allowlist,
            subscription_blocklist: Vec::new(),
            cli_private_domains: Vec::new(),
            config_private_domains: Vec::new(),
            repo_private_domains: Vec::new(),
            config_file: None,
            log_file: None,
            log_level: ProxyLogLevel::None,
            timeout: Duration::from_secs(5),
            upstream: Some(upstream),
            upstream_no_proxy: Vec::new(),
            resolver: Some(resolver),
        })
        .expect("proxy start failed")
    }

    fn copilot_defaults() -> Vec<String> {
        crate::agent::Agent::Copilot
            .default_allowed_domains()
            .iter()
            .map(ToString::to_string)
            .collect()
    }

    /// Assert a CONNECT to an ALLOWED host completes with a 200 tunnel through
    /// the (already running) fake origin/upstream. A real policy block (`403
    /// Forbidden`) fails immediately; only transient transport closes (`403 EOF`
    /// / `403 ECONNRESET` from `proxy_connect`, which contain no "Forbidden")
    /// are retried, since the fake-server handshake can flake under heavy
    /// parallel test load. `host` is the CONNECT host (":443" is appended).
    fn assert_connect_allowed(proxy_port: u16, host: &str) {
        for _ in 0..8 {
            let status = proxy_connect(proxy_port, &format!("{host}:443"));
            assert!(
                !status.contains("Forbidden"),
                "{host} must NOT be blocked by policy; got {status}"
            );
            if status.contains("200") {
                return;
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        panic!("{host} must complete a 200 tunnel once allowed");
    }

    /// Block until `host` appears in the proxy's observed set, then return it.
    ///
    /// The connection thread records the host *after* the client's CONNECT has
    /// already returned, so snapshotting straight after `proxy_connect` races
    /// it. A fixed `sleep(50ms)` hid that race until a loaded CI runner ran
    /// past the window and failed the run for #158. Polling to a deadline is
    /// both faster in the common case and reliable under load — same reasoning
    /// as `assert_connect_allowed`'s retry loop above.
    fn await_observed(proxy: &ProxyHandle, host: &str) -> ObservedDomain {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if let Some(rec) = proxy
                .observed_domains()
                .into_iter()
                .find(|o| o.host == host)
            {
                return rec;
            }
            assert!(
                Instant::now() < deadline,
                "{host} was never recorded in the observed set"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    #[test]
    fn proxy_default_allowlist_blocks_unknown_domain() {
        require_localhost_tcp!();
        let up = spawn_fake_upstream();
        let upstream = UpstreamProxy::parse(&format!("http://127.0.0.1:{}", up.port)).unwrap();
        let proxy = make_proxy_default_allowlist(copilot_defaults(), None, upstream);

        let status = proxy_connect(proxy.port, "evil.com:443");
        proxy.shutdown();
        std::thread::sleep(Duration::from_millis(50));
        let contacted = up.contacted.load(std::sync::atomic::Ordering::SeqCst);
        up.shutdown.store(true, std::sync::atomic::Ordering::SeqCst);

        assert!(
            status.contains("403"),
            "evil.com must be blocked (BLOCKED-ALLOWLIST) under the default allowlist; got {status}"
        );
        assert!(
            !contacted,
            "upstream must NOT be contacted for a blocked domain"
        );
    }

    #[test]
    fn proxy_default_allowlist_allows_agent_and_registry_domains() {
        require_localhost_tcp!();
        // Copilot infra, its subdomain form, and a package registry all pass
        // the allowlist gate and get forwarded to the fake upstream (200). One
        // proxy + one upstream serves every host to keep resource use low.
        let up = spawn_fake_upstream();
        let upstream = UpstreamProxy::parse(&format!("http://127.0.0.1:{}", up.port)).unwrap();
        let proxy = make_proxy_default_allowlist(copilot_defaults(), None, upstream);
        for host in [
            "github.com",
            "api.github.com",
            "api.githubcopilot.com",
            "registry.npmjs.org",
        ] {
            assert_connect_allowed(proxy.port, host);
        }
        proxy.shutdown();
        up.shutdown.store(true, std::sync::atomic::Ordering::SeqCst);
    }

    #[test]
    fn proxy_default_allowlist_merges_user_domain_e2e() {
        require_localhost_tcp!();
        let dir = test_dir("default-allowlist-e2e-merge");
        let allowlist = dir.join("allowed.txt");
        std::fs::write(&allowlist, "extra.example.com\n").unwrap();

        // Small agent base + a user file: the user domain is merged and allowed.
        let up = spawn_fake_upstream();
        let upstream = UpstreamProxy::parse(&format!("http://127.0.0.1:{}", up.port)).unwrap();
        let proxy =
            make_proxy_default_allowlist(vec!["github.com".to_string()], Some(allowlist), upstream);
        assert_connect_allowed(proxy.port, "extra.example.com");
        proxy.shutdown();
        up.shutdown.store(true, std::sync::atomic::Ordering::SeqCst);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn proxy_allow_all_domains_disables_allowlist_e2e() {
        // `--allow-all-domains` => main.rs passes an empty default_allowlist and
        // no file. At the proxy that is allow-all: evil.com is permitted again.
        require_localhost_tcp!();
        let up = spawn_fake_upstream();
        let upstream = UpstreamProxy::parse(&format!("http://127.0.0.1:{}", up.port)).unwrap();
        let proxy = make_proxy_default_allowlist(Vec::new(), None, upstream);
        assert_connect_allowed(proxy.port, "evil.com");
        proxy.shutdown();
        up.shutdown.store(true, std::sync::atomic::Ordering::SeqCst);
    }

    #[test]
    fn observe_allow_all_records_domain_that_would_be_blocked() {
        // The `--observe-domains` override forces the proxy into allow-all mode
        // (main.rs passes an empty allowlist). A host that WOULD be blocked under
        // a configured allowlist must instead be permitted AND recorded here, so
        // the observed set is exhaustive rather than pre-filtered.
        require_localhost_tcp!();
        let up = spawn_fake_upstream();
        let upstream = UpstreamProxy::parse(&format!("http://127.0.0.1:{}", up.port)).unwrap();
        // Allow-all: empty default allowlist + no file — exactly what observe forces.
        let proxy = make_proxy_default_allowlist(Vec::new(), None, upstream);

        let status = proxy_connect(proxy.port, "would-be-blocked.example:443");
        let rec = await_observed(&proxy, "would-be-blocked.example");
        proxy.shutdown();
        up.shutdown.store(true, std::sync::atomic::Ordering::SeqCst);

        assert!(
            !status.contains("Forbidden"),
            "allow-all (observe) must NOT block would-be-blocked.example; got {status}"
        );
        assert_eq!(
            rec.verdict,
            DomainVerdict::Allowed,
            "in allow-all mode the host is recorded as Allowed"
        );
    }

    #[test]
    fn observe_records_blocked_verdict_under_allowlist() {
        // Complementary to the allow-all case: when a real allowlist IS in force,
        // a refused host is still recorded — with a Blocked verdict.
        require_localhost_tcp!();
        let up = spawn_fake_upstream();
        let upstream = UpstreamProxy::parse(&format!("http://127.0.0.1:{}", up.port)).unwrap();
        let proxy = make_proxy_default_allowlist(copilot_defaults(), None, upstream);

        let status = proxy_connect(proxy.port, "evil.com:443");
        let rec = await_observed(&proxy, "evil.com");
        proxy.shutdown();
        up.shutdown.store(true, std::sync::atomic::Ordering::SeqCst);

        assert!(
            status.contains("403"),
            "evil.com must be blocked under the allowlist; got {status}"
        );
        assert_eq!(rec.verdict, DomainVerdict::Blocked);
    }

    #[test]
    fn proxy_default_allowlist_allows_localhost_carveout_but_blocks_unknown() {
        // Combining fail-closed networking with a local dev-server carve-out
        // (`--default-allowlist --allow-localhost <PORT>`) must let the opted-in
        // localhost port through even though "localhost" is not in the agent
        // default allowlist, while a non-allowlisted public domain stays blocked.
        require_localhost_tcp!();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();

        // Accept the one localhost connection so the tunnel completes (200).
        let handle = std::thread::spawn(move || {
            listener.accept().ok();
        });

        // Pin resolution to IPv4 loopback so the tunnel reaches our listener and
        // the resolved-IP loopback check passes (localhost connects directly,
        // never via the upstream). evil.com never reaches resolution — it is
        // blocked at the allowlist gate first.
        let loopback_v4: std::net::IpAddr = "127.0.0.1".parse().unwrap();
        let resolver: ResolverFn =
            Arc::new(move |_host: &str, p: u16| Some(std::net::SocketAddr::new(loopback_v4, p)));
        let up = spawn_fake_upstream();
        let upstream = UpstreamProxy::parse(&format!("http://127.0.0.1:{}", up.port)).unwrap();
        let proxy = start(ProxyOptions {
            port: 0,
            blocked_file: PathBuf::from("/dev/null"),
            allowed_ports: vec![443, 80],
            allow_localhost_ports: vec![port],
            allow_localhost_any: false,
            allowed_domains_file: None,
            allowed_domains_initial: Vec::new(),
            default_allowlist: copilot_defaults(),
            subscription_blocklist: Vec::new(),
            cli_private_domains: Vec::new(),
            config_private_domains: Vec::new(),
            repo_private_domains: Vec::new(),
            config_file: None,
            log_file: None,
            log_level: ProxyLogLevel::None,
            timeout: Duration::from_secs(5),
            upstream: Some(upstream),
            upstream_no_proxy: Vec::new(),
            resolver: Some(resolver),
        })
        .expect("proxy start failed");

        let localhost_status = proxy_connect(proxy.port, &format!("localhost:{port}"));
        let evil_status = proxy_connect(proxy.port, "evil.com:443");

        proxy.shutdown();
        // Fallback connect so the accept thread unblocks if the proxy didn't reach it.
        let _ = std::net::TcpStream::connect(("127.0.0.1", port));
        handle.join().ok();
        up.shutdown.store(true, std::sync::atomic::Ordering::SeqCst);

        assert!(
            localhost_status.contains("200"),
            "CONNECT localhost:{port} must be ALLOWED under --default-allowlist \
             with --allow-localhost {port} (allowlist gate must not block the \
             localhost carve-out); got: {localhost_status}"
        );
        assert!(
            evil_status.contains("403"),
            "evil.com must stay BLOCKED (BLOCKED-ALLOWLIST) under the default \
             allowlist even when a localhost carve-out is active; got: {evil_status}"
        );
    }

    /// Helper: make a raw CONNECT request through the proxy and return the status line.
    fn proxy_connect(proxy_port: u16, target: &str) -> String {
        use std::io::{BufRead as _, BufReader, Write as _};
        let mut conn = std::net::TcpStream::connect(format!("127.0.0.1:{proxy_port}")).unwrap();
        let _ = write!(conn, "CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n");
        let mut reader = BufReader::new(conn);
        let mut line = String::new();
        match reader.read_line(&mut line) {
            Ok(0) => "403 EOF".to_string(),
            Ok(_) => line.trim().to_string(),
            Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => {
                "403 ECONNRESET".to_string()
            }
            Err(e) => format!("ERROR: {e}"),
        }
    }

    /// A control character in the agent's request line must never reach a log
    /// sink verbatim.
    ///
    /// Drives the REAL path — raw request lines over TCP into a live proxy —
    /// and inspects both sinks `log_connection` feeds: the `--proxy-log` audit
    /// file and the observed-host set behind `--observe-domains-out`. The
    /// stderr verdict line is formatted from the same two escaped locals, so
    /// the file assertion covers it too.
    ///
    /// Without the escaping, `\x1b[2K\r` in a CONNECT target reaches the
    /// user's terminal intact and erases the BLOCKED lines they are watching —
    /// including the one this very request produces.
    #[test]
    fn proxy_log_sinks_escape_control_characters() {
        require_localhost_tcp!();
        use std::io::Write as _;

        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("proxy.log");

        // Resolution always fails: the verdict is deterministic (still logged
        // AND recorded) and no lookup for a control-character host leaves the
        // machine.
        let resolver: ResolverFn = Arc::new(|_h: &str, _p: u16| None);
        let proxy = start(ProxyOptions {
            port: 0,
            blocked_file: PathBuf::from("/dev/null"),
            allowed_ports: vec![443, 80],
            allow_localhost_ports: Vec::new(),
            allow_localhost_any: false,
            allowed_domains_file: None,
            allowed_domains_initial: Vec::new(),
            default_allowlist: Vec::new(),
            subscription_blocklist: Vec::new(),
            cli_private_domains: Vec::new(),
            config_private_domains: Vec::new(),
            repo_private_domains: Vec::new(),
            config_file: None,
            log_file: Some(log.clone()),
            log_level: ProxyLogLevel::All,
            timeout: Duration::from_secs(5),
            upstream: None,
            upstream_no_proxy: Vec::new(),
            resolver: Some(resolver),
        })
        .expect("proxy start failed");

        // Raw request lines, exactly as a hostile agent would send them.
        let attacks = [
            // ESC and BEL inside the hostname — neither is whitespace, so both
            // survive `lines()` and `split_whitespace()` into `target`.
            "CONNECT evil\x1b[2K\x07.example:443 HTTP/1.1",
            // Line-erase payload: `split_whitespace()` leaves "\x1b[2K" as the
            // target and drops the rest of the line.
            "CONNECT \x1b[2K\rEVIL.example:443 HTTP/1.1",
            // The METHOD is agent-controlled too and is logged (UNSUPPORTED).
            "GE\x1bT http://evil.example/ HTTP/1.1",
        ];
        // Legitimate targets that must pass through the escaping VERBATIM. The
        // guard is only acceptable because it is lossless for real hostnames:
        // swapping `escape_debug` for `escape_default` would mangle the IDN
        // into "m\u{fc}nchen.de" in the terminal, in the audit file, and in
        // the --observe-domains-out allowlist, where it silently stops
        // matching anything. Punycode and the trailing dot are the other two
        // spellings a user can legitimately see.
        let legit = [
            "CONNECT münchen.de:443 HTTP/1.1",
            "CONNECT xn--mnchen-3ya.de:443 HTTP/1.1",
            "CONNECT example.com.:443 HTTP/1.1",
        ];
        for line in attacks.iter().chain(legit.iter()) {
            let mut conn =
                std::net::TcpStream::connect(format!("127.0.0.1:{}", proxy.port)).unwrap();
            let _ = write!(conn, "{line}\r\nHost: x\r\n\r\n");
            let mut drain = Vec::new();
            let _ = std::io::Read::read_to_end(&mut conn, &mut drain);
        }

        let observed = proxy.observed_domains();
        proxy.shutdown();

        let bytes = std::fs::read(&log).expect("audit log must exist");
        let text = String::from_utf8(bytes.clone()).expect("audit log must stay UTF-8");
        assert_eq!(
            text.lines().count(),
            attacks.len() + legit.len(),
            "one audit line per request: {text:?}"
        );
        let raw: Vec<u8> = bytes
            .iter()
            .copied()
            .filter(|b| (*b < 0x20 && *b != b'\n') || *b == 0x7f)
            .collect();
        assert!(
            raw.is_empty(),
            "control characters reached the --proxy-log audit file: {raw:?} in {text:?}"
        );
        assert!(
            text.contains("\\u{1b}"),
            "the escape attempt must survive in the log as evidence, \
             not be silently stripped: {text:?}"
        );

        for o in &observed {
            assert!(
                !o.host.chars().any(char::is_control),
                "control characters reached the observed-domain set that \
                 --observe-domains-out writes as an allowlist: {:?}",
                o.host
            );
        }
        assert!(
            observed.iter().any(|o| o.host.contains("\\u{1b}")),
            "the hostile targets must still be recorded, escaped: {observed:?}"
        );

        // Lossless for legitimate hostnames: UTF-8 IDN, punycode and the
        // trailing-dot form all survive both sinks byte-for-byte (the observed
        // set additionally lowercases and strips the trailing dot, which is
        // `normalize_hostname`'s long-standing job, not the escaping's).
        for host in [
            "münchen.de:443",
            "xn--mnchen-3ya.de:443",
            "example.com.:443",
        ] {
            assert!(
                text.contains(host),
                "escaping must not touch a legitimate hostname: {host:?} missing from {text:?}"
            );
        }
        for host in ["münchen.de", "xn--mnchen-3ya.de", "example.com"] {
            assert!(
                observed.iter().any(|o| o.host == host),
                "escaping must not mangle a legitimate hostname in the \
                 --observe-domains-out set: {host:?} missing from {observed:?}"
            );
        }
    }

    fn make_proxy(allow_localhost_ports: Vec<u16>, allow_localhost_any: bool) -> ProxyHandle {
        make_proxy_with_resolver(allow_localhost_ports, allow_localhost_any, None)
    }

    /// Start a proxy with an optional injected DNS resolver.
    /// Pass `Some(f)` to override DNS resolution in tests (e.g. to simulate
    /// DNS rebinding where `evil.localhost` resolves to `169.254.169.254`).
    fn make_proxy_with_resolver(
        allow_localhost_ports: Vec<u16>,
        allow_localhost_any: bool,
        resolver: Option<ResolverFn>,
    ) -> ProxyHandle {
        let blocked = PathBuf::from("/dev/null");
        start(ProxyOptions {
            port: 0,
            blocked_file: blocked,
            allowed_ports: vec![443, 80],
            allow_localhost_ports,
            allow_localhost_any,
            allowed_domains_file: None,
            allowed_domains_initial: Vec::new(),
            default_allowlist: Vec::new(),
            subscription_blocklist: Vec::new(),
            cli_private_domains: Vec::new(),
            config_private_domains: Vec::new(),
            repo_private_domains: Vec::new(),
            config_file: None,
            log_file: None,
            log_level: ProxyLogLevel::None,
            timeout: Duration::from_secs(60),
            upstream: None,
            upstream_no_proxy: Vec::new(),
            resolver,
        })
        .expect("proxy start failed")
    }

    #[test]
    fn proxy_connect_localhost_blocked_without_allow() {
        require_localhost_tcp!();
        // Start a real listener so the proxy can actually resolve the target.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();

        let proxy = make_proxy(vec![], false);
        let status = proxy_connect(proxy.port, &format!("localhost:{port}"));
        proxy.shutdown();
        drop(listener);

        assert!(
            status.contains("403"),
            "CONNECT to localhost should be blocked without --allow-localhost; got: {status}"
        );
    }

    #[test]
    fn proxy_connect_localhost_allowed_with_specific_port() {
        require_localhost_tcp!();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();

        // Accept the one connection so CONNECT doesn't hang waiting for TCP handshake.
        let handle = std::thread::spawn(move || {
            listener.accept().ok();
        });

        // Force IPv4 resolution: on macOS, `localhost` may resolve to ::1 first,
        // which fails to connect to our IPv4-only listener. The injected resolver
        // pins localhost → 127.0.0.1 so we test proxy allow-logic, not DNS order.
        let loopback_v4: std::net::IpAddr = "127.0.0.1".parse().unwrap();
        let resolver: ResolverFn =
            Arc::new(move |_host: &str, p: u16| Some(std::net::SocketAddr::new(loopback_v4, p)));
        let proxy = make_proxy_with_resolver(vec![port], false, Some(resolver));
        let status = proxy_connect(proxy.port, &format!("localhost:{port}"));
        proxy.shutdown();
        // Fallback connect so the accept thread unblocks if proxy didn't reach it.
        let _ = std::net::TcpStream::connect(("127.0.0.1", port));
        handle.join().ok();

        assert!(
            status.contains("200"),
            "CONNECT to localhost:{port} should succeed with --allow-localhost {port}; got: {status}"
        );
    }

    #[test]
    fn proxy_connect_localhost_other_port_still_blocked() {
        require_localhost_tcp!();
        let listener1 = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let allowed_port = listener1.local_addr().unwrap().port();
        let listener2 = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let blocked_port = listener2.local_addr().unwrap().port();

        let proxy = make_proxy(vec![allowed_port], false);
        let status = proxy_connect(proxy.port, &format!("localhost:{blocked_port}"));
        proxy.shutdown();
        drop(listener1);
        drop(listener2);

        assert!(
            status.contains("403"),
            "CONNECT to localhost:{blocked_port} should be blocked when only {allowed_port} is allowed; got: {status}"
        );
    }

    #[test]
    fn proxy_connect_localhost_any_opens_all_ports() {
        require_localhost_tcp!();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();

        let handle = std::thread::spawn(move || {
            listener.accept().ok();
        });

        // Force IPv4 resolution (same macOS ::1-first issue as the test above).
        let loopback_v4: std::net::IpAddr = "127.0.0.1".parse().unwrap();
        let resolver: ResolverFn =
            Arc::new(move |_host: &str, p: u16| Some(std::net::SocketAddr::new(loopback_v4, p)));
        let proxy = make_proxy_with_resolver(vec![], true, Some(resolver));
        let status = proxy_connect(proxy.port, &format!("localhost:{port}"));
        proxy.shutdown();
        let _ = std::net::TcpStream::connect(("127.0.0.1", port));
        handle.join().ok();

        assert!(
            status.contains("200"),
            "CONNECT to localhost:{port} should succeed with --allow-localhost-any; got: {status}"
        );
    }

    /// Regression guard for the DNS rebinding fix:
    /// The post-DNS private-IP check must use `socket_addr.ip().is_loopback()`, NOT
    /// `localhost_connect_allowed` (which is derived from the hostname pre-DNS).
    ///
    /// Attack: `CONNECT evil.localhost:PORT` where `evil.localhost` resolves to
    /// `169.254.169.254` (cloud IMDS) or `10.x.x.x` (internal).  The hostname
    /// `*.localhost` would set `localhost_connect_allowed = true`, bypassing the
    /// guard entirely with the old condition `&& !localhost_connect_allowed`.
    ///
    /// With the fix (`&& !socket_addr.ip().is_loopback()`), the resolved IP is
    /// always verified — a private non-loopback IP is blocked regardless of hostname.
    ///
    /// We can't fake DNS in a unit test, but we can assert the IP-level invariants
    /// that the fix relies on.
    ///
    /// With the injectable resolver (`make_proxy_with_resolver`), we CAN now simulate
    /// the full DNS rebinding path: the proxy receives `CONNECT evil.localhost:8080`,
    /// the injected resolver returns `169.254.169.254`, and we verify the proxy blocks it.
    #[test]
    fn post_dns_check_uses_is_loopback_not_hostname_pattern() {
        // cloud IMDS and internal IPs are private but NOT loopback
        let imds: std::net::IpAddr = "169.254.169.254".parse().unwrap();
        let internal: std::net::IpAddr = "10.0.0.1".parse().unwrap();
        let loopback: std::net::IpAddr = "127.0.0.1".parse().unwrap();
        let loopback6: std::net::IpAddr = "::1".parse().unwrap();

        // All four are caught by is_private_ip (the outer condition)
        assert!(is_private_ip(&imds), "IMDS must be private");
        assert!(is_private_ip(&internal), "RFC1918 must be private");
        assert!(is_private_ip(&loopback), "loopback must be private");
        assert!(is_private_ip(&loopback6), "IPv6 loopback must be private");

        // Only true loopback passes is_loopback() — the guard the fix uses
        assert!(!imds.is_loopback(), "IMDS must not be loopback");
        assert!(!internal.is_loopback(), "RFC1918 must not be loopback");
        assert!(loopback.is_loopback(), "127.0.0.1 must be loopback");
        assert!(loopback6.is_loopback(), "::1 must be loopback");
    }

    /// Full proxy-level DNS rebinding test using the injectable resolver.
    ///
    /// This test WOULD HAVE FAILED with the old `&& !localhost_connect_allowed`
    /// condition and PASSES with the fixed `&& !socket_addr.ip().is_loopback()`.
    ///
    /// Scenario: agent sends `CONNECT evil.localhost:8080` to the proxy.
    /// The hostname matches `*.localhost`, so `localhost_connect_allowed = true`.
    /// The injected resolver returns `169.254.169.254` (cloud IMDS).
    /// The proxy must block this despite `localhost_connect_allowed` being set,
    /// because the resolved IP is not loopback.
    #[test]
    fn proxy_blocks_dns_rebinding_evil_localhost_to_imds() {
        require_localhost_tcp!();

        let imds_addr: std::net::IpAddr = "169.254.169.254".parse().unwrap();

        // Inject a resolver that maps evil.localhost → 169.254.169.254 (cloud IMDS)
        let resolver: ResolverFn = Arc::new(move |host: &str, port: u16| {
            if host == "evil.localhost" {
                Some(std::net::SocketAddr::new(imds_addr, port))
            } else {
                // Fall back to real resolution for other hosts
                format!("{host}:{port}")
                    .to_socket_addrs()
                    .ok()
                    .and_then(|mut a| a.next())
            }
        });

        // Port 8080 is explicitly "opened" via allow_localhost_ports.
        // With the old code, this would cause the proxy to forward CONNECT to IMDS.
        let proxy = make_proxy_with_resolver(vec![8080], false, Some(resolver));
        let status = proxy_connect(proxy.port, "evil.localhost:8080");
        proxy.shutdown();

        assert!(
            status.contains("403"),
            "DNS rebinding: evil.localhost:8080 resolves to 169.254.169.254 — must block even though port 8080 is in allow_localhost_ports; got: {status}"
        );
    }

    // #126 Tier 2: the old `allow_private_domains_bypasses_private_ip_check`
    // unit test re-implemented the guard's boolean expression with constants and
    // never drove `handle_connect`, so deleting the real SSRF/private-IP guard
    // left it green. These two tests exercise the ACTUAL guard end-to-end through
    // the proxy with an injected resolver that maps a public-looking hostname onto
    // a private (RFC1918) IP — DNS rebinding — proving the resolved-IP block fires
    // and that `allow_private_domains` (and only it) is what lifts the block.

    /// A domain that resolves to a private IP and is NOT allow-listed must be
    /// blocked with 403 "Resolved to private IP". Deleting the `is_private_ip`
    /// guard makes the proxy forward the CONNECT instead → this turns red.
    #[test]
    fn proxy_blocks_private_ip_resolution_when_not_allowlisted() {
        require_localhost_tcp!();

        let private_addr: std::net::IpAddr = "10.0.0.1".parse().unwrap();
        // `corp.internal` is not an IP literal and not *.localhost/*.local, so it
        // passes the pre-DNS `is_private_hostname` fast path and reaches the
        // resolved-IP guard — the code under test.
        let resolver: ResolverFn = Arc::new(move |host: &str, port: u16| {
            if host == "corp.internal" {
                Some(std::net::SocketAddr::new(private_addr, port))
            } else {
                None
            }
        });

        let proxy = start(ProxyOptions {
            port: 0,
            blocked_file: PathBuf::from("/dev/null"),
            allowed_ports: vec![443, 80],
            allow_localhost_ports: vec![],
            allow_localhost_any: false,
            allowed_domains_file: None,
            allowed_domains_initial: Vec::new(),
            default_allowlist: Vec::new(),
            subscription_blocklist: Vec::new(),
            cli_private_domains: Vec::new(), // NOT allow-listed
            config_private_domains: Vec::new(),
            repo_private_domains: Vec::new(),
            config_file: None,
            log_file: None,
            log_level: ProxyLogLevel::None,
            timeout: Duration::from_secs(60),
            resolver: Some(resolver),
            upstream: None,
            upstream_no_proxy: Vec::new(),
        })
        .expect("proxy start failed");

        let status = proxy_connect(proxy.port, "corp.internal:443");
        proxy.shutdown();

        assert!(
            status.contains("403"),
            "corp.internal resolves to 10.0.0.1 (private) and is not allow-listed — \
             the resolved-IP guard must block it with 403; got: {status}"
        );
    }

    /// The same domain→private-IP mapping, but WITH the domain in
    /// `allow_private_domains`, must bypass the private-IP block. We resolve to a
    /// reserved/unroutable private IP so the (now-permitted) upstream connect
    /// fails fast with 502 rather than the 403 the guard would have produced —
    /// proving the allow-list, and only the allow-list, changed the decision.
    #[test]
    fn proxy_allowlist_bypasses_private_ip_block() {
        require_localhost_tcp!();

        // 0.0.0.0 is the unspecified address → is_private_ip() == true
        // (is_unspecified). We assert only that the block was LIFTED (no 403);
        // we deliberately do NOT assert the downstream connect outcome, because
        // it is environment-dependent: connect(0.0.0.0) is refused on macOS but
        // on Linux is treated as 127.0.0.1, which may connect successfully if a
        // loopback listener happens to be running (the linux CI job runs a
        // :443 listener for the proxy-forced enforcement test). The security
        // property under test — allow_private_domains flips the decision — is
        // proven by "not 403" here paired with the sibling test that returns 403
        // for the same IP without the allow-list.
        let private_addr: std::net::IpAddr = "0.0.0.0".parse().unwrap();
        let resolver: ResolverFn = Arc::new(move |host: &str, port: u16| {
            if host == "corp.internal" {
                Some(std::net::SocketAddr::new(private_addr, port))
            } else {
                None
            }
        });

        let proxy = start(ProxyOptions {
            port: 0,
            blocked_file: PathBuf::from("/dev/null"),
            allowed_ports: vec![443, 80],
            allow_localhost_ports: vec![],
            allow_localhost_any: false,
            allowed_domains_file: None,
            allowed_domains_initial: Vec::new(),
            default_allowlist: Vec::new(),
            subscription_blocklist: Vec::new(),
            cli_private_domains: vec!["corp.internal".to_string()], // allow-listed
            config_private_domains: Vec::new(),
            repo_private_domains: Vec::new(),
            config_file: None,
            log_file: None,
            log_level: ProxyLogLevel::None,
            timeout: Duration::from_secs(60),
            resolver: Some(resolver),
            upstream: None,
            upstream_no_proxy: Vec::new(),
        })
        .expect("proxy start failed");

        let status = proxy_connect(proxy.port, "corp.internal:443");
        proxy.shutdown();

        // The guard was bypassed: the proxy did NOT return the private-IP 403 and
        // proceeded past the block. (Sibling test proxy_blocks_private_ip_...
        // returns 403 for the same IP without the allow-list, so "not 403" is the
        // differential that proves the allow-list, and only the allow-list,
        // flipped the decision.)
        assert!(
            !status.contains("403"),
            "allow_private_domains must lift the private-IP block for corp.internal; got: {status}"
        );
    }

    /// Verify that legitimate localhost still works when --allow-localhost is set.
    /// This is the positive counterpart to proxy_blocks_dns_rebinding_evil_localhost_to_imds:
    /// real localhost resolves to 127.0.0.1, which is_loopback() = true → allowed.
    ///
    /// Uses an injected resolver to pin localhost → 127.0.0.1 so the test is stable
    /// on macOS where getaddrinfo("localhost") returns ::1 first.
    #[test]
    fn proxy_allows_real_localhost_with_allow_localhost() {
        require_localhost_tcp!();

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();

        let handle = std::thread::spawn(move || {
            listener.accept().ok();
        });

        let loopback_v4: std::net::IpAddr = "127.0.0.1".parse().unwrap();
        let resolver: ResolverFn =
            Arc::new(move |_host: &str, p: u16| Some(std::net::SocketAddr::new(loopback_v4, p)));
        let proxy = make_proxy_with_resolver(vec![port], false, Some(resolver));
        let status = proxy_connect(proxy.port, &format!("localhost:{port}"));
        proxy.shutdown();
        let _ = std::net::TcpStream::connect(("127.0.0.1", port));
        handle.join().ok();

        assert!(
            status.contains("200"),
            "localhost:{port} with allow_localhost must succeed (resolves to 127.0.0.1); got: {status}"
        );
    }

    /// Regression test for the *public-IP* DNS-rebinding variant of the localhost
    /// carve-out. The private-IP path is covered by the IMDS test above; this one
    /// pins `evil.localhost` to a public address (which `is_private_ip` does NOT
    /// catch) and asserts the loopback requirement still blocks it.
    #[test]
    fn proxy_blocks_localhost_carveout_to_public_ip() {
        require_localhost_tcp!();

        // 93.184.216.34 (example.com) — a routable public IP, not private/loopback.
        let public_addr: std::net::IpAddr = "93.184.216.34".parse().unwrap();
        let resolver: ResolverFn = Arc::new(move |host: &str, port: u16| {
            if host == "evil.localhost" {
                Some(std::net::SocketAddr::new(public_addr, port))
            } else {
                format!("{host}:{port}")
                    .to_socket_addrs()
                    .ok()
                    .and_then(|mut a| a.next())
            }
        });

        let proxy = make_proxy_with_resolver(vec![8080], false, Some(resolver));
        let status = proxy_connect(proxy.port, "evil.localhost:8080");
        proxy.shutdown();

        assert!(
            status.contains("403"),
            "carve-out: evil.localhost:8080 resolving to a public IP must be blocked (resolved IP is not loopback); got: {status}"
        );
    }

    /// Direct unit test of the `resolved_ip_is_blocked` contract after the
    /// localhost-opt-in change: the `localhost_allowed` argument is the
    /// config-level opt-in, and it waives ONLY loopback — never non-loopback
    /// private IPs like RFC1918.
    #[test]
    fn resolved_ip_is_blocked_waives_only_loopback_on_optin() {
        let loopback: std::net::IpAddr = "127.0.0.1".parse().unwrap();
        let loopback6: std::net::IpAddr = "::1".parse().unwrap();
        let rfc1918: std::net::IpAddr = "10.0.0.5".parse().unwrap();
        let public: std::net::IpAddr = "93.184.216.34".parse().unwrap();

        // No opt-in: loopback stays blocked (the SSRF-fix default).
        assert!(resolved_ip_is_blocked(&loopback, false, false));
        assert!(resolved_ip_is_blocked(&loopback6, false, false));

        // Opt-in: loopback is waived (v4 and v6).
        assert!(!resolved_ip_is_blocked(&loopback, false, true));
        assert!(!resolved_ip_is_blocked(&loopback6, false, true));

        // Opt-in must NOT open non-loopback private IPs (RFC1918).
        assert!(resolved_ip_is_blocked(&rfc1918, false, true));
        assert!(resolved_ip_is_blocked(&rfc1918, false, false));

        // Approved private domain lifts the block for the non-loopback private IP.
        assert!(!resolved_ip_is_blocked(&rfc1918, true, false));

        // Public IPs are never private → never blocked here regardless of flags.
        assert!(!resolved_ip_is_blocked(&public, false, false));
    }

    /// The localhost opt-in must be honored for a loopback-ALIASING DNS name
    /// (e.g. `lvh.me`) that does NOT literally spell "localhost". Before the fix,
    /// `resolved_ip_is_blocked` was gated on the hostname-literal flag, so such a
    /// name resolving to 127.0.0.1 was over-blocked even with `--allow-localhost-any`.
    ///
    /// CONNECT `lvh.me:443` (443 is in the general allowed_ports, so it clears the
    /// port policy), resolver pins `lvh.me` → the loopback listener. With the fix
    /// (`localhost_opt_in` passed to `resolved_ip_is_blocked`) this is ALLOWED.
    #[test]
    fn proxy_allows_loopback_aliasing_name_with_localhost_optin() {
        require_localhost_tcp!();

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let listen_port = listener.local_addr().unwrap().port();
        let handle = std::thread::spawn(move || {
            listener.accept().ok();
        });

        let loopback_addr = std::net::SocketAddr::new("127.0.0.1".parse().unwrap(), listen_port);
        let resolver: ResolverFn = Arc::new(move |host: &str, _port: u16| {
            if host == "lvh.me" {
                Some(loopback_addr)
            } else {
                None
            }
        });

        // allow_localhost_any = true (config-level opt-in), no hostname literal.
        let proxy = make_proxy_with_resolver(vec![], true, Some(resolver));
        let status = proxy_connect(proxy.port, "lvh.me:443");
        proxy.shutdown();
        let _ = std::net::TcpStream::connect(("127.0.0.1", listen_port));
        handle.join().ok();

        assert!(
            status.contains("200"),
            "lvh.me:443 resolving to loopback must be ALLOWED with --allow-localhost-any \
             even though the name isn't literally 'localhost'; got: {status}"
        );
    }

    /// The no-opt-in default stays fail-closed regardless of the hostname: a
    /// loopback-aliasing name resolving to 127.0.0.1 is BLOCKED when the user did
    /// not opt into localhost. Preserves the loopback SSRF fix.
    #[test]
    fn proxy_blocks_loopback_aliasing_name_without_optin() {
        require_localhost_tcp!();

        let loopback_addr = std::net::SocketAddr::new("127.0.0.1".parse().unwrap(), 443);
        let resolver: ResolverFn = Arc::new(move |host: &str, _port: u16| {
            if host == "lvh.me" {
                Some(loopback_addr)
            } else {
                None
            }
        });

        // No localhost opt-in at all.
        let proxy = make_proxy_with_resolver(vec![], false, Some(resolver));
        let status = proxy_connect(proxy.port, "lvh.me:443");
        proxy.shutdown();

        assert!(
            status.contains("403"),
            "lvh.me:443 resolving to loopback must be BLOCKED without any localhost opt-in; got: {status}"
        );
    }

    /// The localhost opt-in must NOT open non-loopback private IPs (RFC1918):
    /// `--allow-localhost-any` waives loopback only, never 10.0.0.0/8 etc.
    /// `corp.internal` (not allow-listed) resolving to 10.0.0.5 must stay BLOCKED
    /// even with `allow_localhost_any = true`.
    #[test]
    fn proxy_localhost_optin_does_not_open_rfc1918() {
        require_localhost_tcp!();

        let private_addr = std::net::SocketAddr::new("10.0.0.5".parse().unwrap(), 443);
        let resolver: ResolverFn = Arc::new(move |host: &str, _port: u16| {
            if host == "corp.internal" {
                Some(private_addr)
            } else {
                None
            }
        });

        // Opt into localhost broadly — must not affect the RFC1918 block.
        let proxy = make_proxy_with_resolver(vec![], true, Some(resolver));
        let status = proxy_connect(proxy.port, "corp.internal:443");
        proxy.shutdown();

        assert!(
            status.contains("403"),
            "corp.internal → 10.0.0.5 (RFC1918, not allow-listed) must stay BLOCKED even with \
             --allow-localhost-any; localhost opt-in must not open private networks; got: {status}"
        );
    }

    // ── Upstream proxy chaining ──────────────────────────────────────────

    #[test]
    fn base64_encode_known_vectors() {
        assert_eq!(base64_encode(b""), "");
        assert_eq!(base64_encode(b"a"), "YQ==");
        assert_eq!(base64_encode(b"ab"), "YWI=");
        assert_eq!(base64_encode(b"abc"), "YWJj");
        assert_eq!(base64_encode(b"user:pass"), "dXNlcjpwYXNz");
    }

    #[test]
    fn upstream_parse_host_and_port_with_scheme() {
        let up = UpstreamProxy::parse("http://corp-proxy.example.com:8080").unwrap();
        assert_eq!(up.host, "corp-proxy.example.com");
        assert_eq!(up.port, 8080);
        assert_eq!(up.proxy_authorization, None);
    }

    #[test]
    fn upstream_parse_host_and_port_without_scheme() {
        let up = UpstreamProxy::parse("corp-proxy.example.com:3128").unwrap();
        assert_eq!(up.host, "corp-proxy.example.com");
        assert_eq!(up.port, 3128);
        assert_eq!(up.proxy_authorization, None);
    }

    #[test]
    fn upstream_parse_with_userinfo_sets_basic_auth() {
        let up = UpstreamProxy::parse("http://user:pass@proxy.example.com:8080").unwrap();
        assert_eq!(up.host, "proxy.example.com");
        assert_eq!(up.port, 8080);
        // base64("user:pass") == "dXNlcjpwYXNz"
        assert_eq!(up.proxy_authorization.as_deref(), Some("dXNlcjpwYXNz"));
    }

    #[test]
    fn upstream_parse_rejects_https_scheme() {
        let err = UpstreamProxy::parse("https://proxy.example.com:8080").unwrap_err();
        assert!(err.contains("unsupported"), "got: {err}");
    }

    #[test]
    fn upstream_parse_rejects_missing_port() {
        assert!(UpstreamProxy::parse("http://proxy.example.com").is_err());
        assert!(UpstreamProxy::parse("proxy.example.com").is_err());
    }

    #[test]
    fn upstream_parse_rejects_path_and_empty_and_zero_port() {
        assert!(UpstreamProxy::parse("http://proxy.example.com:8080/foo").is_err());
        assert!(UpstreamProxy::parse("").is_err());
        assert!(UpstreamProxy::parse("http://proxy.example.com:0").is_err());
    }

    #[test]
    fn upstream_debug_redacts_credential() {
        let up = UpstreamProxy::parse("http://alice:s3cr3tpw@corp.example.com:8080").unwrap();
        let cred = up
            .proxy_authorization
            .clone()
            .expect("credential should be present");
        let shown = format!("{up:?}");
        // Neither the base64 credential nor the raw password may ever appear.
        assert!(
            !shown.contains(&cred),
            "Debug leaked the base64 credential: {shown}"
        );
        assert!(
            !shown.contains("s3cr3tpw"),
            "Debug leaked the raw password: {shown}"
        );
        // The host is safe and useful, and the secret is shown as a marker only.
        assert!(
            shown.contains("corp.example.com"),
            "Debug missing host: {shown}"
        );
        assert!(
            shown.contains("<redacted>"),
            "Debug should mark the secret: {shown}"
        );
        // With no credentials, the field is rendered as None.
        let noauth = UpstreamProxy::parse("http://corp.example.com:8080").unwrap();
        assert!(format!("{noauth:?}").contains("proxy_authorization: None"));
    }

    #[test]
    fn upstream_parse_bracketed_ipv6_strips_brackets_and_keeps_port() {
        let up = UpstreamProxy::parse("http://[::1]:3128").unwrap();
        assert_eq!(up.host, "::1");
        assert_eq!(up.port, 3128);
        // The upstream connect target must be a valid socket address, i.e. the
        // brackets are restored for the IPv6 literal.
        let addr = up.socket_addr();
        assert_eq!(addr, "[::1]:3128");
        assert!(
            addr.parse::<std::net::SocketAddr>().is_ok(),
            "connect target must be a valid socket addr: {addr}"
        );
    }

    #[test]
    fn upstream_parse_ipv4_host_and_port_unchanged() {
        let up = UpstreamProxy::parse("http://host:8080").unwrap();
        assert_eq!(up.host, "host");
        assert_eq!(up.port, 8080);
        assert_eq!(up.socket_addr(), "host:8080");
    }

    #[test]
    fn upstream_parse_rejects_unbracketed_ipv6() {
        // `::1:3128` is ambiguous (host vs. port) — must fail closed rather than
        // mis-split on the last ':'.
        assert!(UpstreamProxy::parse("http://::1:3128").is_err());
        assert!(UpstreamProxy::parse("::1:3128").is_err());
    }

    #[test]
    fn upstream_connect_request_has_correct_line_and_host() {
        let up = UpstreamProxy::parse("http://proxy.example.com:8080").unwrap();
        let req = up.connect_request("example.com", 443);
        assert_eq!(
            req,
            "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n"
        );
        // No credentials → no Proxy-Authorization header.
        assert!(!req.contains("Proxy-Authorization"));
    }

    #[test]
    fn upstream_connect_request_includes_proxy_authorization_when_userinfo() {
        let up = UpstreamProxy::parse("http://user:pass@proxy.example.com:8080").unwrap();
        let req = up.connect_request("example.com", 443);
        assert_eq!(
            req,
            "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\
             Proxy-Authorization: Basic dXNlcjpwYXNz\r\n\r\n"
        );
    }

    #[test]
    fn consume_until_header_end_handles_many_blank_lines_without_panic() {
        use std::io::Write as _;
        require_localhost_tcp!();
        // A hostile/broken upstream sends thousands of blank lines. This must
        // not overflow the newline counter or panic; the header block ends at
        // the first blank line and the call returns cleanly.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let writer = std::thread::spawn(move || {
            if let Ok((mut s, _)) = listener.accept() {
                let _ = s.write_all("\r\n".repeat(10_000).as_bytes());
                let _ = s.shutdown(std::net::Shutdown::Both);
            }
        });
        let mut client = std::net::TcpStream::connect(addr).unwrap();
        client.set_read_timeout(Some(Duration::from_secs(5))).ok();
        let res = consume_until_header_end(&mut client);
        assert!(res.is_ok(), "expected clean handling, got {res:?}");
        writer.join().ok();
    }

    #[test]
    fn consume_until_header_end_rejects_oversized_header_block() {
        use std::io::Write as _;
        require_localhost_tcp!();
        // An upstream that streams a header block with no terminating blank
        // line larger than the cap must be rejected (not read unbounded / hang).
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let writer = std::thread::spawn(move || {
            if let Ok((mut s, _)) = listener.accept() {
                let _ = s.write_all(&vec![b'A'; 70_000]);
                let _ = s.shutdown(std::net::Shutdown::Both);
            }
        });
        let mut client = std::net::TcpStream::connect(addr).unwrap();
        client.set_read_timeout(Some(Duration::from_secs(5))).ok();
        let err = consume_until_header_end(&mut client)
            .expect_err("oversized header block should be rejected");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        writer.join().ok();
    }

    #[test]
    fn redact_upstream_url_masks_password_keeps_username_and_host() {
        let shown = redact_upstream_url("http://alice:s3cret@corp.example.com:8080");
        assert_eq!(shown, "http://alice:***@corp.example.com:8080");
        // The secret must never survive redaction; the host:port must.
        assert!(!shown.contains("s3cret"));
        assert!(shown.contains("corp.example.com:8080"));
    }

    #[test]
    fn redact_upstream_url_without_userinfo_is_unchanged() {
        assert_eq!(
            redact_upstream_url("http://corp.example.com:8080"),
            "http://corp.example.com:8080"
        );
        // Bare host:port (no scheme, no userinfo) is likewise untouched.
        assert_eq!(
            redact_upstream_url("corp.example.com:3128"),
            "corp.example.com:3128"
        );
    }

    #[test]
    fn redact_upstream_url_hides_lone_userinfo_token() {
        // A userinfo with no ':' could itself be a bearer-style token, so the
        // whole thing is hidden rather than shown as a bare "username".
        assert_eq!(
            redact_upstream_url("http://tok3n@corp.example.com:8080"),
            "http://***@corp.example.com:8080"
        );
        // Also handled without a scheme.
        assert_eq!(
            redact_upstream_url("tok3n@corp.example.com:8080"),
            "***@corp.example.com:8080"
        );
    }

    /// Build a proxy that forwards through `upstream`, optionally with a
    /// blocklist file. Timeout kept short so the tests fail fast rather than
    /// hang if something is wrong.
    fn make_proxy_with_upstream(upstream: UpstreamProxy, blocked_file: PathBuf) -> ProxyHandle {
        start(ProxyOptions {
            port: 0,
            blocked_file,
            allowed_ports: vec![443, 80],
            allow_localhost_ports: Vec::new(),
            allow_localhost_any: false,
            allowed_domains_file: None,
            allowed_domains_initial: Vec::new(),
            default_allowlist: Vec::new(),
            subscription_blocklist: Vec::new(),
            cli_private_domains: Vec::new(),
            config_private_domains: Vec::new(),
            repo_private_domains: Vec::new(),
            config_file: None,
            log_file: None,
            log_level: ProxyLogLevel::None,
            timeout: Duration::from_secs(5),
            upstream: Some(upstream),
            upstream_no_proxy: Vec::new(),
            resolver: None,
        })
        .expect("proxy start failed")
    }

    /// A minimal fake upstream CONNECT proxy. Accepts connections, records the
    /// CONNECT request line it received, replies `200`, and then echoes any
    /// tunnelled bytes back. `contacted` flips true the moment a connection is
    /// accepted — used to prove cplt does NOT reach the upstream for a blocked
    /// target.
    struct FakeUpstream {
        port: u16,
        contacted: Arc<std::sync::atomic::AtomicBool>,
        last_connect_line: Arc<Mutex<Option<String>>>,
        shutdown: Arc<std::sync::atomic::AtomicBool>,
    }

    fn spawn_fake_upstream() -> FakeUpstream {
        use std::io::{BufRead as _, BufReader, Write as _};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).ok();
        let port = listener.local_addr().unwrap().port();
        let contacted = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let last_connect_line = Arc::new(Mutex::new(None));
        let shutdown = Arc::new(std::sync::atomic::AtomicBool::new(false));

        let c = contacted.clone();
        let l = last_connect_line.clone();
        let s = shutdown.clone();
        std::thread::spawn(move || {
            loop {
                if s.load(std::sync::atomic::Ordering::SeqCst) {
                    break;
                }
                let stream = match listener.accept() {
                    Ok((stream, _)) => stream,
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(10));
                        continue;
                    }
                    Err(_) => continue,
                };
                c.store(true, std::sync::atomic::Ordering::SeqCst);
                let l2 = l.clone();
                std::thread::spawn(move || {
                    stream.set_nonblocking(false).ok();
                    let mut writer = stream.try_clone().unwrap();
                    let mut reader = BufReader::new(stream);
                    // Read the request header block, capturing the first line.
                    let mut first_line = String::new();
                    reader.read_line(&mut first_line).ok();
                    *l2.lock().unwrap() = Some(first_line.trim_end().to_string());
                    // Drain the rest of the header block.
                    loop {
                        let mut line = String::new();
                        match reader.read_line(&mut line) {
                            Ok(0) => return,
                            Ok(_) if line == "\r\n" || line == "\n" => break,
                            Ok(_) => {}
                            Err(_) => return,
                        }
                    }
                    writer
                        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                        .ok();
                    // Echo tunnelled bytes back to the client.
                    let mut buf = [0u8; 1024];
                    loop {
                        match reader.get_mut().read(&mut buf) {
                            Ok(0) | Err(_) => break,
                            Ok(n) => {
                                if writer.write_all(&buf[..n]).is_err() {
                                    break;
                                }
                            }
                        }
                    }
                });
            }
        });

        FakeUpstream {
            port,
            contacted,
            last_connect_line,
            shutdown,
        }
    }

    /// End-to-end: cplt forwards an allowed CONNECT through the upstream proxy,
    /// the upstream sees the *real target* (not the upstream address), and the
    /// tunnel carries bytes both ways.
    #[test]
    fn proxy_forwards_allowed_connect_through_upstream() {
        use std::io::{BufRead as _, BufReader, Read as _, Write as _};
        require_localhost_tcp!();

        let upstream_srv = spawn_fake_upstream();
        let upstream =
            UpstreamProxy::parse(&format!("http://127.0.0.1:{}", upstream_srv.port)).unwrap();
        let proxy = make_proxy_with_upstream(upstream, PathBuf::from("/dev/null"));

        // Open a raw CONNECT to cplt for an allowed public target.
        let mut conn = std::net::TcpStream::connect(format!("127.0.0.1:{}", proxy.port)).unwrap();
        conn.set_read_timeout(Some(Duration::from_secs(5))).ok();
        write!(
            conn,
            "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n"
        )
        .unwrap();

        let mut reader = BufReader::new(conn.try_clone().unwrap());
        let mut status = String::new();
        reader.read_line(&mut status).unwrap();
        assert!(
            status.contains("200"),
            "cplt should return 200 once upstream tunnel is up; got: {status}"
        );
        // Consume cplt's response header terminator (blank line).
        let mut blank = String::new();
        reader.read_line(&mut blank).ok();

        // The tunnel is live: send bytes, expect the fake upstream to echo them.
        conn.write_all(b"ping").unwrap();
        let mut echo = [0u8; 4];
        reader.get_mut().read_exact(&mut echo).unwrap();
        assert_eq!(
            &echo, b"ping",
            "tunnelled bytes should round-trip via upstream"
        );

        // The upstream must have been asked to reach the REAL target.
        let line = upstream_srv.last_connect_line.lock().unwrap().clone();
        assert_eq!(line.as_deref(), Some("CONNECT example.com:443 HTTP/1.1"));

        proxy.shutdown();
        upstream_srv
            .shutdown
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }

    /// Security invariant: a blocklisted target is rejected by cplt BEFORE the
    /// upstream proxy is ever contacted. The upstream must never see a request
    /// cplt's policy would block.
    #[test]
    fn proxy_blocks_domain_before_contacting_upstream() {
        require_localhost_tcp!();

        let dir = test_dir("upstream-blocked");
        let blocked = dir.join("blocked.txt");
        std::fs::write(&blocked, "blocked.example.com\n").unwrap();

        let upstream_srv = spawn_fake_upstream();
        let upstream =
            UpstreamProxy::parse(&format!("http://127.0.0.1:{}", upstream_srv.port)).unwrap();
        let proxy = make_proxy_with_upstream(upstream, blocked);

        let status = proxy_connect(proxy.port, "blocked.example.com:443");
        assert!(
            status.contains("403"),
            "blocked domain must be rejected; got: {status}"
        );

        // Give any (erroneous) upstream connect a chance to land, then assert
        // the upstream was NEVER contacted for the blocked target.
        std::thread::sleep(Duration::from_millis(100));
        assert!(
            !upstream_srv
                .contacted
                .load(std::sync::atomic::Ordering::SeqCst),
            "upstream proxy must NOT be contacted for a blocked domain"
        );

        proxy.shutdown();
        upstream_srv
            .shutdown
            .store(true, std::sync::atomic::Ordering::SeqCst);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Flexible upstream-proxy builder for the policy-ordering tests: lets each
    /// test vary the allowed ports, allowlist file, private-domain allowlist,
    /// and injected resolver while forwarding through `upstream`.
    #[allow(clippy::too_many_arguments)]
    fn make_proxy_with_upstream_opts(
        upstream: UpstreamProxy,
        blocked_file: PathBuf,
        allowed_ports: Vec<u16>,
        allowed_domains_file: Option<PathBuf>,
        cli_private_domains: Vec<String>,
        resolver: Option<ResolverFn>,
    ) -> ProxyHandle {
        start(ProxyOptions {
            port: 0,
            blocked_file,
            allowed_ports,
            allow_localhost_ports: Vec::new(),
            allow_localhost_any: false,
            allowed_domains_file,
            allowed_domains_initial: Vec::new(),
            default_allowlist: Vec::new(),
            subscription_blocklist: Vec::new(),
            cli_private_domains,
            config_private_domains: Vec::new(),
            repo_private_domains: Vec::new(),
            config_file: None,
            log_file: None,
            log_level: ProxyLogLevel::None,
            timeout: Duration::from_secs(5),
            upstream: Some(upstream),
            upstream_no_proxy: Vec::new(),
            resolver,
        })
        .expect("proxy start failed")
    }

    /// How a broken fake upstream should misbehave after accepting a connection.
    #[derive(Clone, Copy)]
    enum BrokenUpstream {
        /// Reply with a non-2xx CONNECT status (upstream refuses the tunnel).
        Refuse403,
        /// Accept the connection then close immediately without any reply.
        CloseEarly,
    }

    /// Spawn a fake upstream that always fails the CONNECT — used to prove cplt
    /// surfaces a clean 502 (and does not hang) when the upstream refuses or
    /// disappears. Returns (port, shutdown flag).
    fn spawn_broken_upstream(mode: BrokenUpstream) -> (u16, Arc<std::sync::atomic::AtomicBool>) {
        use std::io::Write as _;
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).ok();
        let port = listener.local_addr().unwrap().port();
        let shutdown = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let s = shutdown.clone();
        std::thread::spawn(move || {
            loop {
                if s.load(std::sync::atomic::Ordering::SeqCst) {
                    break;
                }
                match listener.accept() {
                    Ok((mut stream, _)) => match mode {
                        BrokenUpstream::Refuse403 => {
                            stream.set_nonblocking(false).ok();
                            let _ = stream.write_all(b"HTTP/1.1 403 Forbidden\r\n\r\n");
                            // Drop the stream — tunnel never established.
                        }
                        BrokenUpstream::CloseEarly => {
                            // Drop immediately without replying.
                            drop(stream);
                        }
                    },
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(10));
                    }
                    Err(_) => {}
                }
            }
        });
        (port, shutdown)
    }

    /// Security invariant (Finding 3a): a fail-closed allowlist rejects a target
    /// BEFORE the upstream proxy is contacted. The allowlist gate must run ahead
    /// of forwarding, exactly as the blocklist gate does.
    #[test]
    fn proxy_allowlist_blocks_before_upstream() {
        require_localhost_tcp!();

        let dir = test_dir("upstream-allowlist");
        let allowlist = dir.join("allowed.txt");
        std::fs::write(&allowlist, "allowed.example.com\n").unwrap();

        let upstream_srv = spawn_fake_upstream();
        let upstream =
            UpstreamProxy::parse(&format!("http://127.0.0.1:{}", upstream_srv.port)).unwrap();
        let proxy = make_proxy_with_upstream_opts(
            upstream,
            PathBuf::from("/dev/null"),
            vec![443, 80],
            Some(allowlist),
            Vec::new(),
            None,
        );

        let status = proxy_connect(proxy.port, "notallowed.example.com:443");
        assert!(
            status.contains("403"),
            "domain not in allowlist must be rejected; got: {status}"
        );

        std::thread::sleep(Duration::from_millis(100));
        assert!(
            !upstream_srv
                .contacted
                .load(std::sync::atomic::Ordering::SeqCst),
            "upstream must NOT be contacted for a domain outside the allowlist"
        );

        proxy.shutdown();
        upstream_srv
            .shutdown
            .store(true, std::sync::atomic::Ordering::SeqCst);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Security invariant (Finding 3b): a disallowed port is rejected BEFORE the
    /// upstream proxy is contacted. The port gate must run ahead of forwarding.
    #[test]
    fn proxy_disallowed_port_blocks_before_upstream() {
        require_localhost_tcp!();

        let upstream_srv = spawn_fake_upstream();
        let upstream =
            UpstreamProxy::parse(&format!("http://127.0.0.1:{}", upstream_srv.port)).unwrap();
        // Only 443/80 allowed; 22 is not.
        let proxy = make_proxy_with_upstream_opts(
            upstream,
            PathBuf::from("/dev/null"),
            vec![443, 80],
            None,
            Vec::new(),
            None,
        );

        let status = proxy_connect(proxy.port, "example.com:22");
        assert!(
            status.contains("403"),
            "disallowed port must be rejected; got: {status}"
        );

        std::thread::sleep(Duration::from_millis(100));
        assert!(
            !upstream_srv
                .contacted
                .load(std::sync::atomic::Ordering::SeqCst),
            "upstream must NOT be contacted for a disallowed port"
        );

        proxy.shutdown();
        upstream_srv
            .shutdown
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }

    /// Robustness (Finding 3c): when the upstream refuses with a non-2xx status,
    /// cplt returns a clean 502 to the client instead of hanging or splicing.
    #[test]
    fn proxy_upstream_non_2xx_returns_502() {
        require_localhost_tcp!();

        let (up_port, up_shutdown) = spawn_broken_upstream(BrokenUpstream::Refuse403);
        let upstream = UpstreamProxy::parse(&format!("http://127.0.0.1:{up_port}")).unwrap();
        let proxy = make_proxy_with_upstream_opts(
            upstream,
            PathBuf::from("/dev/null"),
            vec![443, 80],
            None,
            Vec::new(),
            None,
        );

        let status = proxy_connect(proxy.port, "example.com:443");
        assert!(
            status.contains("502"),
            "upstream 403 refusal must surface as 502 to the client; got: {status}"
        );

        proxy.shutdown();
        up_shutdown.store(true, std::sync::atomic::Ordering::SeqCst);
    }

    /// Robustness (Finding 3c): when the upstream accepts then closes before
    /// replying, cplt returns a clean 502 instead of hanging.
    #[test]
    fn proxy_upstream_early_close_returns_502() {
        require_localhost_tcp!();

        let (up_port, up_shutdown) = spawn_broken_upstream(BrokenUpstream::CloseEarly);
        let upstream = UpstreamProxy::parse(&format!("http://127.0.0.1:{up_port}")).unwrap();
        let proxy = make_proxy_with_upstream_opts(
            upstream,
            PathBuf::from("/dev/null"),
            vec![443, 80],
            None,
            Vec::new(),
            None,
        );

        let status = proxy_connect(proxy.port, "example.com:443");
        assert!(
            status.contains("502"),
            "upstream closing early must surface as 502 to the client; got: {status}"
        );

        proxy.shutdown();
        up_shutdown.store(true, std::sync::atomic::Ordering::SeqCst);
    }

    /// Security invariant (Finding 3d / SSRF fix): a host that resolves locally
    /// to a private/link-local IP and is NOT in allow_private_domains is blocked
    /// BEFORE the upstream is contacted — the same resolved-IP guard the direct
    /// path applies. Simulates an attacker-registered public name whose A record
    /// points at the cloud metadata endpoint.
    #[test]
    fn proxy_private_resolved_ip_blocks_before_upstream() {
        require_localhost_tcp!();

        let imds_addr: std::net::IpAddr = "169.254.169.254".parse().unwrap();
        let resolver: ResolverFn = Arc::new(move |host: &str, port: u16| {
            if host == "evil.example.com" {
                Some(std::net::SocketAddr::new(imds_addr, port))
            } else {
                None
            }
        });

        let upstream_srv = spawn_fake_upstream();
        let upstream =
            UpstreamProxy::parse(&format!("http://127.0.0.1:{}", upstream_srv.port)).unwrap();
        let proxy = make_proxy_with_upstream_opts(
            upstream,
            PathBuf::from("/dev/null"),
            vec![443, 80],
            None,
            Vec::new(),
            Some(resolver),
        );

        let status = proxy_connect(proxy.port, "evil.example.com:443");
        assert!(
            status.contains("403"),
            "public name resolving to a private IP must be blocked; got: {status}"
        );

        std::thread::sleep(Duration::from_millis(100));
        assert!(
            !upstream_srv
                .contacted
                .load(std::sync::atomic::Ordering::SeqCst),
            "upstream must NOT be contacted for a host that resolves to a private IP"
        );

        proxy.shutdown();
        upstream_srv
            .shutdown
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }

    /// Positive counterpart to the SSRF fix: the legitimate corporate-internal
    /// case still works. A host that resolves to a private IP but IS listed in
    /// allow_private_domains is forwarded to the upstream, exactly as it would be
    /// permitted in direct mode.
    #[test]
    fn proxy_private_resolved_ip_forwarded_when_in_allow_private_domains() {
        require_localhost_tcp!();

        let internal_addr: std::net::IpAddr = "10.0.0.5".parse().unwrap();
        let resolver: ResolverFn = Arc::new(move |host: &str, port: u16| {
            if host == "intranet.corp.example" {
                Some(std::net::SocketAddr::new(internal_addr, port))
            } else {
                None
            }
        });

        let upstream_srv = spawn_fake_upstream();
        let upstream =
            UpstreamProxy::parse(&format!("http://127.0.0.1:{}", upstream_srv.port)).unwrap();
        let proxy = make_proxy_with_upstream_opts(
            upstream,
            PathBuf::from("/dev/null"),
            vec![443, 80],
            None,
            vec!["intranet.corp.example".to_string()],
            Some(resolver),
        );

        // Retry transport flakes: `assert_connect_allowed` still fails fast on a
        // real `403 Forbidden`, so the policy assertion keeps its teeth.
        assert_connect_allowed(proxy.port, "intranet.corp.example");

        std::thread::sleep(Duration::from_millis(100));
        assert!(
            upstream_srv
                .contacted
                .load(std::sync::atomic::Ordering::SeqCst),
            "upstream MUST be contacted for an allow_private_domains internal host"
        );
        let line = upstream_srv.last_connect_line.lock().unwrap().clone();
        assert_eq!(
            line.as_deref(),
            Some("CONNECT intranet.corp.example:443 HTTP/1.1")
        );

        proxy.shutdown();
        upstream_srv
            .shutdown
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }

    // ── upstream_no_proxy (NO_PROXY) carve-out ───────────────────────────

    /// `host_matches_no_proxy` reuses `is_domain_match`: an entry matches the
    /// exact host and all its subdomains, and an empty list matches nothing.
    #[test]
    fn no_proxy_matches_exact_and_subdomain() {
        let list = vec!["example.com".to_string()];
        assert!(host_matches_no_proxy("example.com", &list));
        assert!(host_matches_no_proxy("internal.example.com", &list));
        assert!(host_matches_no_proxy("a.b.example.com", &list));
        assert!(!host_matches_no_proxy("notexample.com", &list));
        assert!(!host_matches_no_proxy("example.com", &[]));
    }

    /// Entry normalization: trim, lowercase, strip leading AND trailing dots;
    /// empty and a bare `*` are dropped.
    #[test]
    fn no_proxy_entry_normalization() {
        assert_eq!(
            normalize_no_proxy_entry(".Example.COM"),
            Some("example.com".to_string())
        );
        assert_eq!(
            normalize_no_proxy_entry("  host.example  "),
            Some("host.example".to_string())
        );
        // FQDN with a trailing dot must normalize the same as without, so it
        // matches the CONNECT host (which normalize_hostname strips too).
        assert_eq!(
            normalize_no_proxy_entry("example.com."),
            Some("example.com".to_string())
        );
        assert_eq!(
            normalize_no_proxy_entry(".example.com."),
            Some("example.com".to_string())
        );
        assert_eq!(normalize_no_proxy_entry(""), None);
        assert_eq!(normalize_no_proxy_entry("   "), None);
        assert_eq!(normalize_no_proxy_entry("."), None);
        assert_eq!(normalize_no_proxy_entry("*"), None);
    }

    /// A trailing-dot FQDN entry (`example.com.`) matches the plain host
    /// `example.com`: the entry is normalized, then compared against the host
    /// which `is_domain_match` normalizes via `normalize_hostname`. Without the
    /// trailing-dot strip the corporate proxy would be used for a NO_PROXY host.
    #[test]
    fn no_proxy_trailing_dot_entry_matches_host() {
        let list = parse_no_proxy_list("example.com.");
        assert_eq!(list, vec!["example.com".to_string()]);
        assert!(host_matches_no_proxy("example.com", &list));
        assert!(host_matches_no_proxy("sub.example.com", &list));
    }

    /// A NO_PROXY env value is comma/whitespace-separated, normalized, with
    /// empties and the bare wildcard dropped.
    #[test]
    fn no_proxy_env_value_parsing() {
        let got = parse_no_proxy_list(".foo.com, bar.example\tBAZ.NET,,*");
        assert_eq!(
            got,
            vec![
                "foo.com".to_string(),
                "bar.example".to_string(),
                "baz.net".to_string(),
            ]
        );
    }

    /// A minimal fake DIRECT origin: a plain TCP listener that flips `contacted`
    /// on accept, proving cplt connected directly rather than via the upstream.
    struct FakeDirect {
        port: u16,
        contacted: Arc<std::sync::atomic::AtomicBool>,
        shutdown: Arc<std::sync::atomic::AtomicBool>,
    }

    fn spawn_fake_direct_target() -> FakeDirect {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).ok();
        let port = listener.local_addr().unwrap().port();
        let contacted = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let shutdown = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let c = contacted.clone();
        let s = shutdown.clone();
        std::thread::spawn(move || {
            loop {
                if s.load(std::sync::atomic::Ordering::SeqCst) {
                    break;
                }
                match listener.accept() {
                    Ok((stream, _)) => {
                        c.store(true, std::sync::atomic::Ordering::SeqCst);
                        // Hold the stream briefly so cplt's relay setup succeeds.
                        std::thread::spawn(move || {
                            std::thread::sleep(Duration::from_millis(50));
                            drop(stream);
                        });
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(10));
                    }
                    Err(_) => {}
                }
            }
        });
        FakeDirect {
            port,
            contacted,
            shutdown,
        }
    }

    /// Build an upstream-forwarding proxy that also honors an `upstream_no_proxy`
    /// bypass list. Used by the NO_PROXY carve-out tests.
    fn make_proxy_with_no_proxy(
        upstream: UpstreamProxy,
        upstream_no_proxy: Vec<String>,
        blocked_file: PathBuf,
        cli_private_domains: Vec<String>,
        resolver: Option<ResolverFn>,
    ) -> ProxyHandle {
        start(ProxyOptions {
            port: 0,
            blocked_file,
            allowed_ports: vec![443, 80],
            allow_localhost_ports: Vec::new(),
            allow_localhost_any: false,
            allowed_domains_file: None,
            allowed_domains_initial: Vec::new(),
            default_allowlist: Vec::new(),
            subscription_blocklist: Vec::new(),
            cli_private_domains,
            config_private_domains: Vec::new(),
            repo_private_domains: Vec::new(),
            config_file: None,
            log_file: None,
            log_level: ProxyLogLevel::None,
            timeout: Duration::from_secs(5),
            upstream: Some(upstream),
            upstream_no_proxy,
            resolver,
        })
        .expect("proxy start failed")
    }

    /// Core behavior: a host in `upstream_no_proxy` takes the DIRECT path and the
    /// upstream is NEVER contacted for it, while a host NOT in the list is still
    /// forwarded to the upstream. Proves the bypass is scoped to the list.
    #[test]
    fn proxy_no_proxy_host_takes_direct_path_not_upstream() {
        require_localhost_tcp!();

        let upstream_srv = spawn_fake_upstream();
        let upstream =
            UpstreamProxy::parse(&format!("http://127.0.0.1:{}", upstream_srv.port)).unwrap();
        let direct = spawn_fake_direct_target();

        let direct_ip: std::net::IpAddr = "127.0.0.1".parse().unwrap();
        let direct_port = direct.port;
        let resolver: ResolverFn = Arc::new(move |host: &str, _port: u16| match host {
            // The no-proxy host resolves to our local fake origin (stands in for
            // an internal/public IP we cannot bind in a unit test).
            "internal.corp.example" => Some(std::net::SocketAddr::new(direct_ip, direct_port)),
            // The forwarded host is only resolvable by the (fake) upstream, so
            // local resolution returns None and cplt forwards it as-is.
            _ => None,
        });

        let proxy = make_proxy_with_no_proxy(
            upstream,
            vec!["internal.corp.example".to_string()],
            PathBuf::from("/dev/null"),
            // Trust the no-proxy host to resolve to loopback so the direct path's
            // resolved-IP guard permits our local fake origin.
            vec!["internal.corp.example".to_string()],
            Some(resolver),
        );

        // 1. No-proxy host → DIRECT path: 200, direct origin reached, upstream not.
        assert_connect_allowed(proxy.port, "internal.corp.example");
        std::thread::sleep(Duration::from_millis(100));
        assert!(
            direct.contacted.load(std::sync::atomic::Ordering::SeqCst),
            "no-proxy host must reach the DIRECT origin"
        );
        assert!(
            !upstream_srv
                .contacted
                .load(std::sync::atomic::Ordering::SeqCst),
            "upstream must NOT be contacted for a no-proxy host"
        );

        // 2. A host NOT in the no-proxy list is still forwarded to the upstream.
        assert_connect_allowed(proxy.port, "external.example.net");
        std::thread::sleep(Duration::from_millis(100));
        assert!(
            upstream_srv
                .contacted
                .load(std::sync::atomic::Ordering::SeqCst),
            "upstream MUST be contacted for a host outside the no-proxy list"
        );

        proxy.shutdown();
        upstream_srv
            .shutdown
            .store(true, std::sync::atomic::Ordering::SeqCst);
        direct
            .shutdown
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }

    /// Filtering precedence preserved: a no-proxy host that is BLOCKED by the
    /// blocklist is still rejected with 403, and the upstream is never contacted.
    /// The NO_PROXY carve-out only chooses direct-vs-upstream; it does NOT skip
    /// the allow/block/port/SSRF gates that run first.
    #[test]
    fn proxy_no_proxy_host_still_blocked_by_policy() {
        require_localhost_tcp!();

        let dir = test_dir("no-proxy-blocked");
        let blocked = dir.join("blocked.txt");
        std::fs::write(&blocked, "blocked.example.com\n").unwrap();

        let upstream_srv = spawn_fake_upstream();
        let upstream =
            UpstreamProxy::parse(&format!("http://127.0.0.1:{}", upstream_srv.port)).unwrap();
        // The blocked host is ALSO in the no-proxy list — policy must still win.
        let proxy = make_proxy_with_no_proxy(
            upstream,
            vec!["blocked.example.com".to_string()],
            blocked,
            Vec::new(),
            None,
        );

        let status = proxy_connect(proxy.port, "blocked.example.com:443");
        assert!(
            status.contains("403"),
            "a blocklisted no-proxy host must still be 403; got: {status}"
        );

        std::thread::sleep(Duration::from_millis(100));
        assert!(
            !upstream_srv
                .contacted
                .load(std::sync::atomic::Ordering::SeqCst),
            "upstream must NOT be contacted for a blocked host"
        );

        proxy.shutdown();
        upstream_srv
            .shutdown
            .store(true, std::sync::atomic::Ordering::SeqCst);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Companion NEGATIVE test to `proxy_no_proxy_host_takes_direct_path_not_upstream`
    /// (which sets allow_private_domains): a no-proxy host that resolves to a
    /// PRIVATE IP but is NOT an allow_private_domains entry is BLOCKED with 403 by
    /// the direct path's resolved-IP SSRF guard, and the upstream is never used.
    ///
    /// This is the feature's central gotcha: NO_PROXY diverts an internal host to
    /// cplt's DIRECT path, which then applies the private-IP guard — so the same
    /// internal host must ALSO be in `proxy.allow_private_domains` to connect.
    #[test]
    fn proxy_no_proxy_host_private_ip_blocked_without_allow_private() {
        require_localhost_tcp!();

        let upstream_srv = spawn_fake_upstream();
        let upstream =
            UpstreamProxy::parse(&format!("http://127.0.0.1:{}", upstream_srv.port)).unwrap();

        // The no-proxy host resolves to an RFC1918 private IP.
        let private_ip: std::net::IpAddr = "10.1.2.3".parse().unwrap();
        let resolver: ResolverFn = Arc::new(move |host: &str, _port: u16| match host {
            "internal.corp.example" => Some(std::net::SocketAddr::new(private_ip, 443)),
            _ => None,
        });

        // NOTE: cli_private_domains is EMPTY — the host is NOT permitted to
        // resolve to a private IP.
        let proxy = make_proxy_with_no_proxy(
            upstream,
            vec!["internal.corp.example".to_string()],
            PathBuf::from("/dev/null"),
            Vec::new(),
            Some(resolver),
        );

        let status = proxy_connect(proxy.port, "internal.corp.example:443");
        assert!(
            status.contains("403"),
            "a no-proxy host resolving to a private IP without allow_private_domains \
             must be 403; got: {status}"
        );

        std::thread::sleep(Duration::from_millis(100));
        assert!(
            !upstream_srv
                .contacted
                .load(std::sync::atomic::Ordering::SeqCst),
            "upstream must NOT be contacted for a no-proxy host"
        );

        proxy.shutdown();
        upstream_srv
            .shutdown
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }

    /// A peer that completes CONNECT and then stops reading must not pin the
    /// tunnel forever. The pump parks in a write, not a read, so the ceiling
    /// has to be evaluated on the write path too — otherwise the connection
    /// slot (MAX_CONNECTIONS is 64) is never released.
    #[test]
    fn stalled_reader_is_bounded_by_the_ceiling() {
        fn pair() -> (TcpStream, TcpStream) {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let a = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
            let (b, _) = listener.accept().unwrap();
            (a, b)
        }
        let (client, proxy_client) = pair();
        let (proxy_remote, mut remote) = pair();

        let timeout = Duration::from_millis(20);
        let ceiling = Duration::from_millis(100);
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            relay_with_ceiling(proxy_client, proxy_remote, timeout, ceiling);
            tx.send(()).ok();
        });

        // Remote floods; the client never reads, so both socket buffers fill
        // and the remote->client pump blocks in write.
        std::thread::spawn(move || {
            let blob = vec![0u8; 1 << 20];
            for _ in 0..8 {
                if remote.write_all(&blob).is_err() {
                    break;
                }
            }
        });

        assert!(
            rx.recv_timeout(Duration::from_secs(30)).is_ok(),
            "relay never returned: a stalled reader pinned the connection slot"
        );
        drop(client);
    }

    /// A tunnel streaming in ONE direction is not idle. The request direction
    /// of a long download or SSE stream goes quiet after its first byte; a
    /// per-direction idle clock would half-close that pump mid-stream and send
    /// a FIN into a live connection. Regression guard for the shared clock.
    #[test]
    fn one_way_traffic_keeps_the_quiet_direction_alive() {
        fn pair() -> (TcpStream, TcpStream) {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let a = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
            let (b, _) = listener.accept().unwrap();
            (a, b)
        }
        let (mut client, proxy_client) = pair();
        let (proxy_remote, mut remote) = pair();

        let timeout = Duration::from_millis(20);
        // Margin matters here: the gap between ticks must stay far below the
        // ceiling even on a loaded runner, while the total stream outlasts it.
        let ceiling = Duration::from_millis(500);
        let gap = Duration::from_millis(25);
        let ticks = 40;
        std::thread::spawn(move || {
            relay_with_ceiling(proxy_client, proxy_remote, timeout, ceiling);
        });

        // Remote streams for well over the ceiling; the client never sends.
        let long = Some(Duration::from_secs(10));
        client.set_read_timeout(long).unwrap();
        remote.set_write_timeout(long).unwrap();
        let mut buf = [0u8; 4];
        for _ in 0..ticks {
            remote.write_all(b"tick").unwrap();
            client.read_exact(&mut buf).unwrap();
            assert_eq!(&buf, b"tick");
            std::thread::sleep(gap);
        }

        // The quiet direction must still carry a byte: it was never idle,
        // because the tunnel as a whole was not.
        remote.set_read_timeout(long).unwrap();
        client.write_all(b"ping").unwrap();
        remote.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"ping", "quiet direction was closed mid-stream");
    }

    /// A CONNECT tunnel that sits idle longer than `proxy.timeout` must stay
    /// open — read timeouts are a liveness poll, not a teardown. Regression
    /// guard for agent sessions dropped mid-stream on long server think-time.
    #[test]
    fn relay_survives_idle_longer_than_timeout() {
        fn pair() -> (TcpStream, TcpStream) {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let a = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
            let (b, _) = listener.accept().unwrap();
            (a, b)
        }
        let (mut client, proxy_client) = pair();
        let (proxy_remote, mut remote) = pair();

        let timeout = Duration::from_millis(50);
        std::thread::spawn(move || relay(proxy_client, proxy_remote, timeout));
        std::thread::sleep(timeout * 5);

        let long = Some(Duration::from_secs(5));
        client.set_read_timeout(long).unwrap();
        remote.set_read_timeout(long).unwrap();
        let mut buf = [0u8; 4];

        client.write_all(b"ping").unwrap();
        remote.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"ping", "tunnel must survive idle > proxy.timeout");

        remote.write_all(b"pong").unwrap();
        client.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"pong");
    }
}
