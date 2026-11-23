//! The remote HTTP leg of a brokered MCP server (#909): an endpoint at a
//! secret path on cplt's CONNECT proxy port that forwards each request through
//! the system `curl` to one pinned upstream, adding a bearer token and forced
//! headers that the client cannot set. Parameterised by the upstream URL, the
//! forced headers and the token source, so `github_mcp` (#797) is one user.
//!
//! cplt has no TLS stack, so the upstream leg runs through the system `curl`
//! (trusted dirs only), one process per request. The token and the request
//! reach curl on stdin as a config file, never in argv, and `-q` keeps the
//! user's `~/.curlrc` out.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::{Mutex, OnceLock};

use super::credential::{CredentialSource, GH_TOKEN};
use super::policy::{Action, Pending, on_client, on_server};
use super::spec::Spec;
use crate::agent::SecretToken;
use crate::proxy::{ProxyLogLevel, UpstreamProxy};

const MAX_BODY: usize = 4 * 1024 * 1024;
/// curl's limit on reaching the upstream (or the upstream proxy).
const CONNECT_TIMEOUT_SECS: &str = "10";
/// curl's default limit on one whole request, an event stream included, so a
/// stalled upstream cannot hold a proxy connection slot for ever (#1059). A
/// spec's `timeoutSecs` replaces it within `spec::REMOTE_TIMEOUT_SECS`.
pub(crate) const MAX_TIME_SECS: u64 = 600;

/// Running curl children as (owning proxy's shutdown-flag address, PID), so proxy shutdown can kill
/// them (#1059). A PID leaves the set before it is reaped, so it is never a
/// reused PID.
pub(crate) static CHILDREN: std::sync::Mutex<Vec<(usize, u32)>> = std::sync::Mutex::new(Vec::new());

/// Kill the running curl children of one proxy instance, when it shuts down.
/// `owner` is the address of that instance's shutdown flag: unique while the
/// proxy lives, unlike its port, which a new proxy may reuse during shutdown.
pub(crate) fn kill_children(owner: &std::sync::atomic::AtomicBool) {
    let owner = std::ptr::from_ref(owner) as usize;
    let pids = CHILDREN
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    for &(_, pid) in pids.iter().filter(|(o, _)| *o == owner) {
        if let Ok(pid) = libc::pid_t::try_from(pid) {
            // SAFETY: plain syscall; the PID is unreaped (see CHILDREN).
            unsafe { libc::kill(pid, libc::SIGKILL) };
        }
    }
}

/// Read exactly `buf.len()` bytes, all within `limit` in total: a per-read
/// timeout alone lets a client trickle a 4 MiB body one byte at a time (#1059).
fn read_body(client: &mut TcpStream, buf: &mut [u8], limit: std::time::Duration) -> bool {
    // `proxy.timeout` is any u64 of seconds: cap it so the sum cannot overflow.
    let deadline = std::time::Instant::now() + limit.min(std::time::Duration::from_secs(86_400));
    let mut done = 0;
    while done < buf.len() {
        let left = deadline.saturating_duration_since(std::time::Instant::now());
        if left.is_zero() || client.set_read_timeout(Some(left)).is_err() {
            return false;
        }
        match client.read(&mut buf[done..]) {
            Ok(0) | Err(_) => return false,
            Ok(n) => done += n,
        }
    }
    true
}

/// Where request lines go: the proxy's log level and `--proxy-log` file.
pub struct Log {
    pub level: ProxyLogLevel,
    pub file: Option<PathBuf>,
}

impl Log {
    /// A spec endpoint (`broker`) follows the broker's rule: DENIED and
    /// failures reach the terminal at every level. The built-in GitHub
    /// endpoint keeps the proxy's level.
    fn to_terminal(&self, broker: bool, status: &str) -> bool {
        self.level.should_log(status) || (broker && super::runtime::to_terminal(self.level, status))
    }

    /// `tag` and `upstream` are the endpoint's own, so a second endpoint
    /// never logs as GitHub's.
    fn line(&self, tag: &str, upstream: &str, broker: bool, method: &'static str, status: &str) {
        let status = status.escape_debug().to_string();
        let tag = tag.escape_debug().to_string();
        let upstream = upstream.escape_debug().to_string();
        if self.to_terminal(broker, &status) {
            eprintln!(
                "{}[{tag}]{} {} {method} {upstream} → {status}",
                crate::ui::color(crate::ui::YELLOW),
                crate::ui::color(crate::ui::RESET),
                crate::proxy::chrono_now()
            );
        }
        if let Some(path) = &self.file
            && let Ok(mut f) = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
        {
            let _ = writeln!(
                f,
                "{} {method} {upstream} {status}",
                crate::proxy::iso_now()
            );
        }
    }
}

/// What the proxy serves at the secret path.
pub struct Endpoint {
    /// The bearer token source: sent upstream, never to the client.
    pub(crate) token: SecretToken,
    pub(crate) path: String,
    pub(crate) curl: PathBuf,
    pub(crate) upstream: String,
    /// Header lines cplt always sends; the client's copies are dropped.
    pub(crate) forced: Vec<String>,
    /// The log tag: `github-mcp`, or the spec id.
    pub(crate) tag: String,
    /// curl `--max-time`, seconds.
    pub(crate) timeout_secs: u64,
    /// The spec whose `tools.allow` applies to every JSON-RPC message, each
    /// way; `None` for the built-in GitHub endpoint (#797), which forwards
    /// as before.
    pub(crate) policy: Option<Spec>,
    /// Requests in flight across every connection to this endpoint, so a
    /// cancel on one connection reaches a call running on another. Bounded
    /// by `MAX_IN_FLIGHT` in `on_client`; freed on response, cancel or
    /// timeout. Locked only around each message, never across a relay.
    pub(crate) pending: Mutex<Pending>,
}

/// The per-exchange view of an endpoint's policy: the audit lines of the
/// `tools/call`s this exchange answered are kept here, not in the shared
/// `Pending`, so concurrent connections never log each other's.
struct Filter<'a> {
    spec: &'a Spec,
    pending: &'a Mutex<Pending>,
    audit: Vec<String>,
    /// This exchange's `Mcp-Session-Id` ("" if none): ids are per session.
    session: String,
}

impl<'a> Filter<'a> {
    fn lock(&self) -> std::sync::MutexGuard<'a, Pending> {
        self.pending
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// Frees the exchange's own request id when the exchange ends, whether or
/// not a response for it came back (upstream error, curl failure): else
/// every such failure would hold an in-flight slot until the timeout.
/// The `Instant` makes sure a later request reusing the id is left alone.
/// A `tools/call` still unanswered here gets its audit line from here, so
/// every call is logged exactly once: by the response, a cancel, eviction,
/// or this.
struct OwnId<'a> {
    ep: &'a Endpoint,
    log: &'a Log,
    session: String,
    id: String,
    sent: std::time::Instant,
    /// The upstream status, or why there was none.
    outcome: String,
}

impl Drop for OwnId<'_> {
    fn drop(&mut self) {
        let freed = self
            .ep
            .pending
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&self.session, &self.id, self.sent);
        if let Some(tool) = freed {
            let ms = self.sent.elapsed().as_millis();
            // curl's --max-time is the timeout, so a call this old timed out.
            let outcome = if ms >= u128::from(self.ep.timeout_secs) * 1000 {
                "TIMEOUT".to_string()
            } else {
                format!("FAIL {}", self.outcome)
            };
            self.log.line(
                &self.ep.tag,
                &self.ep.upstream,
                true,
                "POST",
                &format!("tools/call {tool} → {outcome} {ms}ms"),
            );
        }
    }
}

/// The endpoint for one validated remote spec, or why it cannot start.
/// The token is read here, once, at launch.
pub(crate) fn for_spec(
    spec: &Spec,
    source: &dyn CredentialSource,
    curl: PathBuf,
    secret: &str,
) -> Result<Endpoint, String> {
    let upstream = spec.remote.clone().ok_or("not a remote spec")?;
    if spec.credential.name != GH_TOKEN.name {
        return Err(format!(
            "credential {} has no token source yet",
            spec.credential.name
        ));
    }
    let token = source.bearer().ok_or("no gh login: run `gh auth login`")?;
    Ok(Endpoint {
        token,
        path: format!("/{secret}"),
        curl,
        upstream,
        forced: spec.remote_headers.clone(),
        tag: spec.id.clone(),
        timeout_secs: spec.timeout_secs,
        policy: Some(spec.clone()),
        pending: Mutex::default(),
    })
}

/// Endpoints for every remote spec. With the remote gate off there are
/// none, and the credential source is never asked: gate-off launches stay
/// as they were.
#[cfg_attr(not(test), allow(dead_code))] // wired to clients in #909 PR3/PR4
pub(crate) fn remote_endpoints(
    specs: &[Spec],
    gate: bool,
    source: &dyn CredentialSource,
    curl: &std::path::Path,
    secret: impl Fn() -> Result<String, String>,
) -> Vec<Result<Endpoint, String>> {
    if !gate {
        return Vec::new();
    }
    specs
        .iter()
        .filter(|s| s.remote.is_some())
        .map(|s| for_spec(s, source, curl.to_path_buf(), &secret()?))
        .collect()
}

/// ponytail: one endpoint per process, which is one cplt session; a
/// per-proxy field would be needed to serve two.
static ENDPOINT: OnceLock<Endpoint> = OnceLock::new();

pub(crate) fn install_endpoint(ep: Endpoint) -> Result<(), String> {
    ENDPOINT
        .set(ep)
        .map_err(|_| "the GitHub MCP endpoint is already set".to_string())
}

/// The endpoint, when `target` is exactly its path. Constant-time, so the
/// secret cannot be guessed a byte at a time.
pub(crate) fn endpoint_for(target: &str) -> Option<&'static Endpoint> {
    let ep = ENDPOINT.get()?;
    let (a, b) = (target.as_bytes(), ep.path.as_bytes());
    // The length is public (a fixed-size secret); only the bytes are compared
    // in constant time.
    if a.len() != b.len() {
        return None;
    }
    let diff = a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y));
    (diff == 0).then_some(ep)
}

/// Client headers that never reach upstream: credentials, every header cplt
/// forces, and MCP mode switches are cplt's to set (`X-MCP-Toolsets` only
/// picks tool groups and passes unless forced); the rest are hop-by-hop or
/// curl's job. Under a tool policy the client cannot ask for a compressed
/// answer, which the policy could not read.
fn forwarded(name: &str, forced: &[String], policy: bool) -> bool {
    let n = name.to_ascii_lowercase();
    let is_forced = forced.iter().any(|h| {
        h.split(':')
            .next()
            .is_some_and(|f| f.trim().eq_ignore_ascii_case(&n))
    });
    if is_forced || (policy && n == "accept-encoding") {
        return false;
    }
    n == "x-mcp-toolsets"
        || !(n.starts_with("x-mcp-")
            || n.starts_with("proxy-")
            || matches!(
                n.as_str(),
                "authorization"
                    | "x-http-method-override"
                    | "x-http-method"
                    | "x-method-override"
                    | "cookie"
                    | "host"
                    | "content-length"
                    | "connection"
                    | "keep-alive"
                    | "transfer-encoding"
                    | "te"
                    | "trailer"
                    | "upgrade"
                    | "expect"
            ))
}

/// A header name or value that could break out of its line: any control
/// byte but HTAB, or DEL. Checked before anything is quoted for curl.
pub(crate) fn bad_header_byte(s: &str) -> bool {
    s.bytes().any(|b| (b < 0x20 && b != b'\t') || b == 0x7f)
}

/// A quoted curl config value. curl unescapes `\\r`, `\\n` and `\\t` again,
/// so the body round-trips exactly; headers never reach here with a control
/// byte (see [`bad_header_byte`]), and NUL is refused for both.
fn quote(out: &mut Vec<u8>, value: &[u8]) {
    out.push(b'"');
    for &b in value {
        match b {
            b'\\' => out.extend_from_slice(b"\\\\"),
            b'"' => out.extend_from_slice(b"\\\""),
            b'\n' => out.extend_from_slice(b"\\n"),
            b'\r' => out.extend_from_slice(b"\\r"),
            b'\t' => out.extend_from_slice(b"\\t"),
            _ => out.push(b),
        }
    }
    out.extend_from_slice(b"\"\n");
}

/// An RFC 9110 token (`tchar`), the only header name forwarded. curl reads a
/// `header` value starting with `@` as a file of headers, so anything else
/// could make the host curl read local files or add cplt's own mode headers.
/// The name always leads the value, so no value can start a curl special form.
fn header_name(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
}

/// The curl config for one request, or `None` for a header with a control
/// byte or a name that is not a token. Upstream, credential and MCP mode come from cplt alone; the client
/// supplies only the method, its other headers and the body.
#[allow(clippy::too_many_arguments)] // one request's inputs, each needed
fn curl_config(
    upstream: &str,
    via: Option<&UpstreamProxy>,
    method: &str,
    headers: &[(String, String)],
    body: &[u8],
    token: &str,
    forced: &[String],
    policy: bool,
) -> Option<Vec<u8>> {
    if headers
        .iter()
        .any(|(k, v)| !header_name(k) || bad_header_byte(v))
    {
        return None;
    }
    let mut c = Vec::new();
    let mut opt = |name: &str, value: &[u8]| {
        c.extend_from_slice(name.as_bytes());
        c.extend_from_slice(b" = ");
        quote(&mut c, value);
    };
    opt("url", upstream.as_bytes());
    // The route is set here, never left to curl's env: the token goes direct
    // or through the user's `proxy.upstream`, nowhere else.
    match via {
        Some(u) => {
            opt("proxy", format!("http://{}", u.socket_addr()).as_bytes());
            opt("noproxy", b"");
            if let Some(auth) = &u.proxy_authorization {
                opt(
                    "proxy-header",
                    format!("Proxy-Authorization: Basic {auth}").as_bytes(),
                );
            }
        }
        None => opt("noproxy", b"*"),
    }
    opt("request", method.as_bytes());
    for (k, v) in headers.iter().filter(|(k, _)| forwarded(k, forced, policy)) {
        opt("header", format!("{k}: {v}").as_bytes());
    }
    opt(
        "header",
        format!("Authorization: Bearer {token}").as_bytes(),
    );
    for h in forced {
        opt("header", h.as_bytes());
    }
    opt("header", b"Expect:");
    if via.is_some() {
        // A bare boolean: curl's config parser refuses a value here.
        c.extend_from_slice(b"proxytunnel\n");
    }
    if !body.is_empty() {
        c.extend_from_slice(b"data-raw = ");
        quote(&mut c, body);
    }
    Some(c)
}

/// curl's stderr for the log: the token replaced before truncation, so a cut
/// can never leave a token prefix behind.
fn redact_stderr(raw: &[u8], token: &str) -> String {
    let s = String::from_utf8_lossy(raw).replace(token, "<token>");
    let mut end = s.len().min(2048);
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    s[..end].to_string()
}

fn reply(stream: &mut TcpStream, status: &str) {
    let _ = write!(
        stream,
        "HTTP/1.1 {status}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    );
}

impl Endpoint {
    /// One request, whose head the proxy has read (its size cap, deadline and
    /// connection limit apply); the body is still in `client`. Runs curl and
    /// streams its answer back.
    /// Host and port of the pinned upstream, for the proxy's domain policy.
    pub(crate) fn authority(&self) -> (String, u16) {
        let (scheme, rest) = self.upstream.split_once("://").unwrap_or(("https", ""));
        let auth = rest.split('/').next().unwrap_or_default();
        match auth.rsplit_once(':') {
            Some((h, p)) if p.parse::<u16>().is_ok() => (h.to_string(), p.parse().unwrap_or(443)),
            _ => (auth.to_string(), if scheme == "http" { 80 } else { 443 }),
        }
    }

    /// The curl command line; the request itself goes in on stdin.
    fn command(&self) -> Command {
        #[allow(clippy::disallowed_methods)] // resolved trusted path, or a fixture in tests
        let mut cmd = Command::new(&self.curl);
        // -q first: no ~/.curlrc. No redirects; https only for the real upstream.
        cmd.args([
            "-q",
            "-sS",
            "-N",
            "-i",
            "--http1.1",
            "--suppress-connect-headers",
            "--max-redirs",
            "0",
            "--connect-timeout",
            CONNECT_TIMEOUT_SECS,
            "--max-time",
            &self.timeout_secs.to_string(),
            "-K",
            "-",
        ]);
        if self.upstream.starts_with("https://") {
            cmd.args(["--proto", "=https"]);
        }
        // A cleared env: HTTPS_PROXY, ALL_PROXY, NO_PROXY and CURL_* on the host
        // must not decide where the token goes. Only CA locations pass.
        cmd.env_clear();
        for var in ["SSL_CERT_FILE", "SSL_CERT_DIR", "CURL_CA_BUNDLE"] {
            if let Some(v) = std::env::var_os(var) {
                cmd.env(var, v);
            }
        }
        cmd
    }

    pub(crate) fn serve(
        &self,
        mut client: TcpStream,
        head: &[u8],
        log: &Log,
        via: Option<&UpstreamProxy>,
        body_limit: std::time::Duration,
        shutdown: &std::sync::atomic::AtomicBool,
    ) {
        let head = String::from_utf8_lossy(head);
        let mut lines = head.split('\n').map(|l| l.strip_suffix('\r').unwrap_or(l));
        // A static string from here on: no request byte reaches the log.
        let method: &'static str = match lines.next().and_then(|l| l.split(' ').next()) {
            Some("GET") => "GET",
            Some("POST") => "POST",
            Some("DELETE") => "DELETE",
            _ => {
                reply(&mut client, "405 Method Not Allowed");
                return log.line(
                    &self.tag,
                    &self.upstream,
                    self.policy.is_some(),
                    "<other>",
                    "BLOCKED-METHOD",
                );
            }
        };
        let headers: Vec<(String, String)> = lines
            .take_while(|l| !l.is_empty())
            .map(|l| match l.split_once(':') {
                Some((k, v)) => (k.trim().to_string(), v.trim().to_string()),
                // A line without a colon is malformed; make it fail the check.
                None => (String::new(), "\u{0}".into()),
            })
            .collect();
        let header = |name: &str| {
            headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case(name))
                .map(|(_, v)| v.as_str())
        };
        if header("transfer-encoding").is_some() {
            reply(&mut client, "411 Length Required");
            return log.line(
                &self.tag,
                &self.upstream,
                self.policy.is_some(),
                method,
                "FAIL chunked request",
            );
        }
        let len = match header("content-length").map(str::parse::<usize>) {
            None => 0,
            Some(Ok(n)) if n <= MAX_BODY => n,
            _ => {
                reply(&mut client, "413 Content Too Large");
                return log.line(
                    &self.tag,
                    &self.upstream,
                    self.policy.is_some(),
                    method,
                    "FAIL body length",
                );
            }
        };
        let mut body = vec![0; len];
        if !read_body(&mut client, &mut body, body_limit) || body.contains(&0) {
            reply(&mut client, "400 Bad Request");
            return log.line(
                &self.tag,
                &self.upstream,
                self.policy.is_some(),
                method,
                "FAIL bad body",
            );
        }
        // Ids are keyed by session, so the session must be unambiguous.
        let sessions = headers
            .iter()
            .filter(|(k, _)| k.eq_ignore_ascii_case("mcp-session-id"))
            .count();
        if self.policy.is_some() && sessions > 1 {
            reply(&mut client, "400 Bad Request");
            return log.line(
                &self.tag,
                &self.upstream,
                true,
                method,
                "FAIL more than one Mcp-Session-Id",
            );
        }
        // The spec's tool policy, as for a stdio server: one JSON-RPC
        // message per POST (batches refused), checked and re-serialised.
        let mut filter = self.policy.as_ref().map(|spec| Filter {
            spec,
            pending: &self.pending,
            audit: Vec::new(),
            session: header("mcp-session-id").unwrap_or_default().to_string(),
        });
        // A session-less `initialize` creates a session, so two of them
        // never share ids: each gets a namespace no header value can name.
        if let Some(f) = &mut filter
            && f.session.is_empty()
            && serde_json::from_slice::<serde_json::Value>(&body)
                .is_ok_and(|v| v.get("method").and_then(|m| m.as_str()) == Some("initialize"))
        {
            static INIT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            let n = INIT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            f.session = format!("\ninitialize {n}");
        }
        // Stream resume is not supported: every exchange frees its ids and
        // writes its audit lines when it ends, so nothing is left to resume.
        if self.policy.is_some() && header("last-event-id").is_some() {
            let msg = r#"{"jsonrpc":"2.0","id":null,"error":{"code":-32600,"message":"SSE stream resume (Last-Event-ID) is not supported by cplt's MCP broker"}}"#;
            let _ = write!(
                client,
                "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{msg}",
                msg.len()
            );
            return log.line(
                &self.tag,
                &self.upstream,
                true,
                method,
                "FAIL stream resume not supported",
            );
        }
        // Only a POST body is checked, so no other method may carry one.
        if self.policy.is_some() && method != "POST" && !body.is_empty() {
            reply(&mut client, "400 Bad Request");
            return log.line(
                &self.tag,
                &self.upstream,
                self.policy.is_some(),
                method,
                "FAIL body on non-POST",
            );
        }
        let mut own = None;
        if let Some(f) = &mut filter
            && method == "POST"
        {
            let (action, evicted) = {
                let mut p = f.lock();
                // curl gives up at the same deadline, so nothing is left to cancel.
                let evicted = p.evict(std::time::Duration::from_secs(self.timeout_secs));
                let action = on_client(&String::from_utf8_lossy(&body), f.spec, &f.session, &mut p);
                f.audit.extend(p.1.take());
                if let Action::Forward(line) = &action {
                    let v: serde_json::Value = serde_json::from_str(line).unwrap_or_default();
                    let id = v.get("id").filter(|_| v.get("method").is_some());
                    own = id.and_then(|id| {
                        let id = id.to_string();
                        let sent = p.sent(&f.session, &id)?;
                        Some(OwnId {
                            ep: self,
                            log,
                            session: f.session.clone(),
                            id,
                            sent,
                            outcome: "upstream not reached".into(),
                        })
                    });
                }
                (action, evicted)
            };
            for audit in evicted.into_iter().filter_map(|(_, _, a)| a) {
                log.line(&self.tag, &self.upstream, true, method, &audit);
            }
            match action {
                Action::Forward(line) => body = line.into_bytes(),
                Action::Reply(line, why) => {
                    json_reply(&mut client, &line);
                    let why = why.unwrap_or_else(|| "DENIED".into());
                    return log.line(
                        &self.tag,
                        &self.upstream,
                        self.policy.is_some(),
                        method,
                        &why,
                    );
                }
                Action::Drop => {
                    reply(&mut client, "202 Accepted");
                    return log.line(
                        &self.tag,
                        &self.upstream,
                        self.policy.is_some(),
                        method,
                        "DROPPED",
                    );
                }
            }
        }
        let Some(config) = curl_config(
            &self.upstream,
            via,
            method,
            &headers,
            &body,
            self.token.expose(),
            &self.forced,
            self.policy.is_some(),
        ) else {
            reply(&mut client, "400 Bad Request");
            return log.line(
                &self.tag,
                &self.upstream,
                self.policy.is_some(),
                method,
                "FAIL bad header",
            );
        };
        if shutdown.load(std::sync::atomic::Ordering::SeqCst) {
            reply(&mut client, "503 Service Unavailable");
            return log.line(
                &self.tag,
                &self.upstream,
                self.policy.is_some(),
                method,
                "FAIL proxy shutting down",
            );
        }
        let mut cmd = self.command();
        let Ok(mut child) = cmd
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
        else {
            reply(&mut client, "502 Bad Gateway");
            return log.line(
                &self.tag,
                &self.upstream,
                self.policy.is_some(),
                method,
                "FAIL curl did not start",
            );
        };
        CHILDREN
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push((std::ptr::from_ref(shutdown) as usize, child.id()));
        // Shutdown sets its flag before it kills: either it saw this PID, or
        // this load sees the flag.
        if shutdown.load(std::sync::atomic::Ordering::SeqCst) {
            let _ = child.kill();
        }
        // Bounded, and drained so curl never blocks on a full pipe.
        let stderr = child.stderr.take().map(|e| {
            std::thread::spawn(move || {
                let mut e = e;
                let mut buf = Vec::new();
                let _ = e.by_ref().take(64 * 1024).read_to_end(&mut buf);
                let _ = std::io::copy(&mut e, &mut std::io::sink());
                buf
            })
        });
        let wrote = child
            .stdin
            .take()
            .is_some_and(|mut s| s.write_all(&config).is_ok());
        let status = match child.stdout.take() {
            Some(out) if wrote => relay(out, &mut client, filter.as_mut()),
            _ => None,
        };
        CHILDREN
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .retain(|&(_, p)| p != child.id());
        let _ = child.kill();
        let _ = child.wait();
        if let Some(own) = &mut own {
            let code = status.as_ref().map(|(c, _)| c.as_str());
            own.outcome = code.unwrap_or("upstream").to_string();
        }
        for audit in filter.map(|f| f.audit).unwrap_or_default() {
            log.line(
                &self.tag,
                &self.upstream,
                self.policy.is_some(),
                method,
                &audit,
            );
        }
        if let Some((code, closed)) = status {
            // A GET answered 405 is the MCP spec's "no standalone SSE stream",
            // which GitHub returns on every session: not an error.
            let expected = method == "GET" && code == "405";
            let verdict = if (code.starts_with(['4', '5']) && !expected) || closed.is_some() {
                "FAIL"
            } else {
                "FORWARDED"
            };
            let note = closed.map(|c| format!(" ({c})")).unwrap_or_default();
            log.line(
                &self.tag,
                &self.upstream,
                self.policy.is_some(),
                method,
                &format!("{verdict} {code}{note}"),
            );
        } else {
            reply(&mut client, "502 Bad Gateway");
            let err = stderr
                .and_then(|t| t.join().ok())
                .map(|b| redact_stderr(&b, self.token.expose()))
                .unwrap_or_default();
            log.line(
                &self.tag,
                &self.upstream,
                self.policy.is_some(),
                method,
                &format!("FAIL upstream: {}", err.trim()),
            );
        }
    }
}

/// Copy curl's `-i` output to the client: the status line and headers, minus
/// hop-by-hop ones (curl has already de-chunked the body), then the body as it
/// arrives, unbuffered, so SSE streams through. Returns the status code once
/// the head is sent, with why the body was cut short under a tool policy;
/// `None` if curl produced no response.
///
/// With `filter`, every JSON-RPC message goes through the spec's policy:
/// a JSON body whole, an event stream one event at a time. Anything the
/// policy cannot read is not passed: an unparsable event closes the stream.
fn relay(
    out: impl Read,
    client: &mut TcpStream,
    filter: Option<&mut Filter>,
) -> Option<(String, Option<&'static str>)> {
    let mut out = BufReader::new(out);
    let mut status = String::new();
    out.read_line(&mut status).ok()?;
    let mut code = status.split_whitespace().nth(1)?.to_string();
    // curl -i prints interim 1xx blocks (100 Continue, 103 Early Hints)
    // before the final response: skip them. 101 would switch protocols,
    // which curl never asks for here.
    while code.starts_with('1') && code != "101" {
        loop {
            let mut line = String::new();
            if out.read_line(&mut line).ok()? == 0 {
                return None;
            }
            if line.trim_end_matches(['\r', '\n']).is_empty() {
                break;
            }
        }
        status.clear();
        out.read_line(&mut status).ok()?;
        code = status.split_whitespace().nth(1)?.to_string();
    }
    let mut head = status.trim_end().to_string() + "\r\n";
    let mut ctype = String::new();
    loop {
        let mut line = String::new();
        if out.read_line(&mut line).ok()? == 0 {
            return None;
        }
        let l = line.trim_end_matches(['\r', '\n']);
        if l.is_empty() {
            break;
        }
        let name = l.split(':').next().unwrap_or_default().to_ascii_lowercase();
        if name == "content-type" {
            ctype = l[l.find(':').map_or(l.len(), |i| i + 1)..]
                .split(';')
                .next()
                .unwrap_or_default()
                .trim()
                .to_ascii_lowercase();
        }
        // A filtered body changes length.
        let rewritten = filter.is_some() && name == "content-length";
        if !rewritten
            && !matches!(
                name.as_str(),
                "transfer-encoding" | "connection" | "keep-alive"
            )
        {
            head += l;
            head += "\r\n";
        }
    }
    head += "Connection: close\r\n";
    let mut closed = None;
    match filter {
        None => {
            head += "\r\n";
            if client.write_all(head.as_bytes()).is_ok() {
                // ponytail: a client that hangs up mid-stream is noticed on the next
                // upstream chunk, not at once; the session's exit reaps the rest.
                let _ = std::io::copy(&mut out, client);
            }
        }
        Some(f) if ctype == "text/event-stream" => {
            head += "\r\n";
            if client.write_all(head.as_bytes()).is_ok() {
                closed = filter_events(&mut out, client, f).err();
            }
        }
        Some(f) => {
            let mut body = Vec::new();
            let read = (&mut out)
                .take(MAX_BODY as u64 + 1)
                .read_to_end(&mut body)
                .is_ok();
            let filtered = if body.is_empty() {
                Ok(String::new())
            } else if !read || body.len() > MAX_BODY {
                Err("body too large")
            } else if ctype != "application/json" {
                Err("not JSON")
            } else {
                filter_message(&body, f)
            };
            let text = match filtered {
                Ok(t) => t,
                Err(why) => {
                    closed = Some(why);
                    String::new()
                }
            };
            let _ = write!(client, "{head}Content-Length: {}\r\n\r\n{text}", text.len());
        }
    }
    let _ = client.shutdown(std::net::Shutdown::Both);
    Some((code, closed))
}

/// One server message through the policy: the line to pass (empty when the
/// policy drops it), or an error when it is not JSON.
fn filter_message(data: &[u8], f: &mut Filter) -> Result<String, &'static str> {
    let text = std::str::from_utf8(data).map_err(|_| "unparsable message")?;
    serde_json::from_str::<serde_json::Value>(text).map_err(|_| "unparsable message")?;
    let action = {
        let mut p = f.lock();
        let action = on_server(text, f.spec, &f.session, &mut p);
        f.audit.extend(p.1.take());
        action
    };
    Ok(match action {
        Action::Forward(line) => line,
        // A server request is not delivered (D13); there is no channel back
        // to the server on this exchange, so it is dropped.
        Action::Reply(..) | Action::Drop => String::new(),
    })
}

/// An event stream, one event at a time: `data` lines joined and checked as
/// one message, other fields kept. Returns why the stream was closed early.
fn filter_events(
    out: &mut impl BufRead,
    client: &mut TcpStream,
    f: &mut Filter,
) -> Result<(), &'static str> {
    loop {
        let (mut fields, mut data, mut size) = (String::new(), Vec::<String>::new(), 0usize);
        loop {
            let mut raw = Vec::new();
            let n = out
                .by_ref()
                .take((MAX_BODY - size) as u64 + 1)
                .read_until(b'\n', &mut raw)
                .map_err(|_| "upstream read failed")?;
            if n == 0 {
                return Ok(()); // end of stream; a partial event is dropped
            }
            size += n;
            if size > MAX_BODY {
                return Err("event too large");
            }
            let line = String::from_utf8(raw).map_err(|_| "unparsable event")?;
            let line = line.strip_suffix('\n').unwrap_or(&line);
            let line = line.strip_suffix('\r').unwrap_or(line);
            // A lone CR ends a line for the client's parser but not this
            // one: refuse it rather than pass a line the client splits.
            if line.contains('\r') {
                return Err("unparsable event");
            }
            if line.is_empty() {
                break;
            }
            // Only known fields pass; a BOM or unknown field could hide a
            // `data:` line from this parser that the client still reads.
            if let Some(d) = line.strip_prefix("data:") {
                data.push(d.strip_prefix(' ').unwrap_or(d).to_string());
            } else if line.starts_with(':')
                || ["event:", "id:", "retry:"]
                    .iter()
                    .any(|f| line.starts_with(f))
            {
                fields += line;
                fields += "\n";
            } else {
                return Err("unknown event field");
            }
        }
        let event = if data.is_empty() {
            fields + "\n"
        } else if data.iter().all(String::is_empty) {
            // An empty-data event (an MCP priming event) carries no message.
            format!("{fields}data:\n\n")
        } else {
            let msg = filter_message(data.join("\n").as_bytes(), f)?;
            if msg.is_empty() {
                continue;
            }
            format!("{fields}data: {msg}\n\n")
        };
        if client.write_all(event.as_bytes()).is_err() {
            return Ok(());
        }
    }
}

/// A JSON-RPC answer from cplt itself (a denied request).
fn json_reply(stream: &mut TcpStream, line: &str) {
    let _ = write!(
        stream,
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{line}",
        line.len()
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::github_mcp::{FORCED_HEADERS, UPSTREAM};
    use std::path::Path;

    fn forced() -> Vec<String> {
        FORCED_HEADERS.iter().map(ToString::to_string).collect()
    }

    fn endpoint(curl: PathBuf) -> Endpoint {
        Endpoint {
            token: SecretToken::new("T".into()),
            path: "/x".into(),
            curl,
            upstream: UPSTREAM.into(),
            forced: forced(),
            tag: "github-mcp".into(),
            timeout_secs: MAX_TIME_SECS,
            policy: None,
            pending: Mutex::default(),
        }
    }

    fn hdrs(list: &[(&str, &str)]) -> Vec<(String, String)> {
        list.iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn config_pins_upstream_and_forces_headers() {
        let headers = hdrs(&[
            ("Authorization", "Bearer agent"),
            ("x-mcp-readonly", "false"),
            ("X-MCP-Lockdown", "false"),
            ("X-MCP-Toolsets", "repos"),
            ("Host", "evil"),
            ("Cookie", "c"),
            ("Mcp-Session-Id", "s\"1\\"),
        ]);
        let c = String::from_utf8(
            curl_config(
                UPSTREAM,
                None,
                "POST",
                &headers,
                b"{\"a\":\n1}",
                "T",
                &forced(),
                false,
            )
            .unwrap(),
        )
        .unwrap();
        let lines: Vec<&str> = c.lines().collect();
        assert_eq!(lines.iter().filter(|l| l.starts_with("url = ")).count(), 1);
        assert_eq!(lines[0], format!("url = \"{UPSTREAM}\""));
        assert!(!c.contains("agent") && !c.contains("Host:") && !c.contains("Cookie"));
        assert!(!c.to_lowercase().contains(": false"), "{c}");
        for h in [
            "Authorization: Bearer T",
            "X-MCP-Readonly: true",
            "X-MCP-Lockdown: true",
            "X-MCP-Toolsets: repos",
            r#"Mcp-Session-Id: s\"1\\"#,
        ] {
            assert!(c.contains(&format!("header = \"{h}\"")), "{h}: {c}");
        }
        assert!(c.contains(r#"data-raw = "{\"a\":\n1}""#));
        assert!(c.contains("noproxy = \"*\""), "{c}");
    }

    #[test]
    fn upstream_proxy_credential_and_tunnel_precede_the_body() {
        let via = UpstreamProxy::parse("http://u:p@127.0.0.1:3128").unwrap();
        let c = String::from_utf8(
            curl_config(
                UPSTREAM,
                Some(&via),
                "POST",
                &[],
                b"{}",
                "T",
                &forced(),
                false,
            )
            .unwrap(),
        )
        .unwrap();
        assert!(c.contains("proxy = \"http://127.0.0.1:3128\""), "{c}");
        assert!(c.contains("noproxy = \"\""), "{c}");
        assert!(
            c.contains("proxy-header = \"Proxy-Authorization: Basic dTpw\""),
            "{c}"
        );
        let tunnel = c.find("proxytunnel\n").expect("no proxytunnel");
        assert!(tunnel < c.find("data-raw").unwrap(), "{c}");
    }

    /// The host env must not reach curl: proxy variables would reroute the
    /// token, and SSLKEYLOGFILE would write its TLS keys to disk.
    #[test]
    fn curl_runs_with_a_cleared_env_and_bounded_times() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let fake = dir.path().join("curl");
        let out = dir.path().join("env");
        std::fs::write(&fake, format!("#!/bin/sh\nenv > '{}'\n", out.display())).unwrap();
        std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755)).unwrap();
        let ep = endpoint(fake);
        let vars = [
            ("SSLKEYLOGFILE", Some("/keys")),
            ("HTTPS_PROXY", Some("http://trap")),
            ("SSL_CERT_FILE", Some("/ca.pem")),
        ];
        let mut cmd = temp_env::with_vars(vars, || ep.command());
        let args: Vec<_> = cmd
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        let joined = args.join(" ");
        assert!(
            joined.contains(&format!("--connect-timeout {CONNECT_TIMEOUT_SECS}")),
            "{joined}"
        );
        assert!(
            joined.contains(&format!("--max-time {MAX_TIME_SECS}")),
            "{joined}"
        );
        let status = temp_env::with_vars(vars, || cmd.stdin(Stdio::null()).status().unwrap());
        assert!(status.success());
        let env = std::fs::read_to_string(&out).unwrap();
        assert!(
            !env.contains("SSLKEYLOGFILE") && !env.contains("HTTPS_PROXY"),
            "{env}"
        );
        assert!(env.contains("SSL_CERT_FILE=/ca.pem"), "{env}");
    }

    #[test]
    fn no_curl_starts_after_shutdown() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let fake = dir.path().join("curl");
        let ran = dir.path().join("ran");
        std::fs::write(&fake, format!("#!/bin/sh\ntouch '{}'\n", ran.display())).unwrap();
        std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755)).unwrap();
        let ep = endpoint(fake);
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let mut c = TcpStream::connect(l.local_addr().unwrap()).unwrap();
        let (server, _) = l.accept().unwrap();
        let log = Log {
            level: ProxyLogLevel::None,
            file: None,
        };
        let shut = std::sync::atomic::AtomicBool::new(true);
        ep.serve(
            server,
            b"GET /x HTTP/1.1\r\n\r\n",
            &log,
            None,
            std::time::Duration::from_secs(5),
            &shut,
        );
        let mut reply = String::new();
        c.read_to_string(&mut reply).unwrap();
        assert!(reply.starts_with("HTTP/1.1 503"), "expected 503");
        assert_eq!(
            reply.matches("HTTP/1.1").count(),
            1,
            "expected one response"
        );
        assert!(!ran.exists(), "curl ran after shutdown");
    }

    #[test]
    fn huge_body_limit_does_not_overflow() {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let mut c = TcpStream::connect(l.local_addr().unwrap()).unwrap();
        let (mut server, _) = l.accept().unwrap();
        c.write_all(b"x").unwrap();
        assert!(read_body(&mut server, &mut [0], std::time::Duration::MAX));
    }

    #[test]
    fn kill_children_kills_only_that_proxy() {
        let spawn = || {
            #[allow(clippy::disallowed_methods)] // absolute path
            Command::new("/bin/sleep").arg("30").spawn().unwrap()
        };
        // Two proxies that could share a port: ownership is the flag, not the port.
        let (a, b) = (
            std::sync::atomic::AtomicBool::new(true),
            std::sync::atomic::AtomicBool::new(false),
        );
        let key = |f: &std::sync::atomic::AtomicBool| std::ptr::from_ref(f) as usize;
        let (mut mine, mut other) = (spawn(), spawn());
        CHILDREN
            .lock()
            .unwrap()
            .extend([(key(&a), mine.id()), (key(&b), other.id())]);
        kill_children(&a);
        assert!(!mine.wait().unwrap().success(), "the curl child survived");
        assert!(
            other.try_wait().unwrap().is_none(),
            "another proxy's child died"
        );
        let _ = other.kill();
        let _ = other.wait();
        CHILDREN
            .lock()
            .unwrap()
            .retain(|&(o, _)| o != key(&a) && o != key(&b));
    }

    #[test]
    fn log_line_escapes_control_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("log");
        let log = Log {
            level: ProxyLogLevel::None,
            file: Some(path.clone()),
        };
        log.line("t\x1b", "u\r\n", false, "GET", "OK\n\x1b[2K forged");
        let text = std::fs::read_to_string(&path).unwrap();
        assert_eq!(text.lines().count(), 1);
        assert!(!text.contains('\x1b') && !text.contains('\r'));
    }

    #[test]
    fn control_bytes_in_headers_are_refused() {
        for (k, v) in [
            ("Mcp-Session-Id", "s\rurl = \"https://evil\""),
            ("Mcp-Session-Id", "s\nurl = \"https://evil\""),
            ("Mcp-Session-Id", "s\u{0}"),
            ("Mcp-Session-Id", "s\u{b}"),
            ("Mcp-Session-Id", "s\u{7f}"),
            ("X-A\r", "v"),
        ] {
            assert_eq!(
                curl_config(
                    UPSTREAM,
                    None,
                    "POST",
                    &hdrs(&[(k, v)]),
                    b"",
                    "T",
                    &forced(),
                    false
                ),
                None,
                "{k:?}: {v:?}"
            );
        }
        assert!(
            curl_config(
                UPSTREAM,
                None,
                "POST",
                &hdrs(&[("A", "x\ty")]),
                b"",
                "T",
                &forced(),
                false
            )
            .is_some()
        );
    }

    #[test]
    fn non_token_header_names_are_refused() {
        for k in [
            "@/etc/passwd",
            "@x",
            "",
            "X A",
            "X:A",
            "X;",
            "X\"A",
            "X(A)",
            "X\u{e9}",
        ] {
            assert_eq!(
                curl_config(
                    UPSTREAM,
                    None,
                    "POST",
                    &hdrs(&[(k, "v")]),
                    b"",
                    "T",
                    &forced(),
                    false
                ),
                None,
                "{k:?}"
            );
        }
        let c = curl_config(
            UPSTREAM,
            None,
            "POST",
            &hdrs(&[("X-a!#$%&'*+.^_`|~1", "@v")]),
            b"",
            "T",
            &forced(),
            false,
        );
        assert!(c.is_some());
    }

    #[test]
    fn stderr_is_redacted_before_truncation() {
        let token = "ghp_SECRETSECRETSECRET";
        let mut raw = vec![b'x'; 2040];
        raw.extend_from_slice(token.as_bytes());
        let out = redact_stderr(&raw, token);
        assert!(!out.contains("ghp_"), "{out}");
        assert!(out.len() <= 2048);
        assert!(redact_stderr(&[b'a'; 4000], token).len() == 2048);
    }

    fn gh_spec() -> Spec {
        let root = crate::mcp_broker::spec::tests::gh_root();
        crate::mcp_broker::spec::validate_gated(
            &root.to_string(),
            crate::mcp_broker::test_util::FILE,
            |_| None,
            true,
        )
        .unwrap()
    }

    struct Fixed(Option<&'static str>);
    impl CredentialSource for Fixed {
        fn bearer(&self) -> Option<SecretToken> {
            self.0.map(|t| SecretToken::new(t.into()))
        }
    }
    struct Never;
    impl CredentialSource for Never {
        fn bearer(&self) -> Option<SecretToken> {
            panic!("the credential source was asked with the gate off")
        }
    }

    #[test]
    fn gate_off_never_constructs_a_remote_endpoint() {
        let specs = [gh_spec()];
        let secret = || -> Result<String, String> { panic!("secret made with the gate off") };
        assert!(remote_endpoints(&specs, false, &Never, Path::new("/c"), secret).is_empty());
        let eps = remote_endpoints(&specs, true, &Fixed(Some("T")), Path::new("/c"), || {
            Ok("s".into())
        });
        let ep = eps[0].as_ref().unwrap();
        assert_eq!(ep.upstream, crate::mcp_broker::spec::GH_TOKEN_UPSTREAM);
        assert_eq!(ep.tag, "io.github.nais/nais-mcp");
        assert_eq!(ep.path, "/s");
        assert_eq!(ep.forced.len(), 3);
        assert!(ep.policy.is_some());
        let eps = remote_endpoints(&specs, true, &Fixed(None), Path::new("/c"), || {
            Ok("s".into())
        });
        assert!(eps[0].as_ref().err().unwrap().contains("gh auth login"));
    }

    #[test]
    fn spec_timeout_reaches_curl() {
        let mut spec = gh_spec();
        spec.timeout_secs = 900;
        let ep = for_spec(&spec, &Fixed(Some("T")), "/c".into(), "s").unwrap();
        let args: Vec<_> = ep
            .command()
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        assert!(args.join(" ").contains("--max-time 900"), "{args:?}");
    }

    #[test]
    fn client_copies_of_every_forced_header_are_dropped() {
        let forced = vec!["Foo-Mode: cplt".to_string()];
        let c = String::from_utf8(
            curl_config(
                UPSTREAM,
                None,
                "POST",
                &hdrs(&[("foo-mode", "agent"), ("Accept-Encoding", "gzip")]),
                b"",
                "T",
                &forced,
                true,
            )
            .unwrap(),
        )
        .unwrap();
        assert!(!c.contains("agent") && !c.contains("gzip"), "{c}");
        assert!(c.contains("header = \"Foo-Mode: cplt\""), "{c}");
    }

    /// A one-shot local upstream answering `answer`; sends back what it got.
    fn fake_upstream(answer: &'static [u8]) -> (String, std::sync::mpsc::Receiver<String>) {
        fake_upstreams(vec![answer])
    }

    /// One answer per connection, in order.
    fn fake_upstreams(answers: Vec<&'static [u8]>) -> (String, std::sync::mpsc::Receiver<String>) {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/mcp", l.local_addr().unwrap());
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            for answer in answers {
                let (mut s, _) = l.accept().unwrap();
                let mut got = Vec::new();
                let mut buf = [0; 4096];
                while let Ok(n) = s.read(&mut buf) {
                    got.extend_from_slice(&buf[..n]);
                    let text = String::from_utf8_lossy(&got);
                    if let Some(end) = text.find("\r\n\r\n") {
                        let len = text
                            .lines()
                            .find_map(|l| {
                                l.to_ascii_lowercase()
                                    .strip_prefix("content-length:")
                                    .map(|v| v.trim().parse::<usize>().unwrap())
                            })
                            .unwrap_or(0);
                        if got.len() >= end + 4 + len {
                            break;
                        }
                    }
                    if n == 0 {
                        break;
                    }
                }
                let _ = tx.send(String::from_utf8_lossy(&got).into_owned());
                let _ = s.write_all(answer);
            }
        });
        (url, rx)
    }

    /// One request through a policy endpoint for `upstream` with the real curl.
    fn through(upstream: String, curl: PathBuf, body: &str) -> (String, String) {
        through_as("POST", upstream, curl, body)
    }

    fn through_as(method: &str, upstream: String, curl: PathBuf, body: &str) -> (String, String) {
        let mut ep = for_spec(&gh_spec(), &Fixed(Some("T")), curl, "x").unwrap();
        ep.upstream = upstream;
        serve_on(&ep, method, body)
    }

    /// One request on a fresh connection to `ep`: the reply and the log.
    fn serve_on(ep: &Endpoint, method: &str, body: &str) -> (String, String) {
        serve_with(ep, method, body, "")
    }

    fn serve_with(ep: &Endpoint, method: &str, body: &str, extra: &str) -> (String, String) {
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("log");
        let log = Log {
            level: ProxyLogLevel::None,
            file: Some(log_path.clone()),
        };
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let mut c = TcpStream::connect(l.local_addr().unwrap()).unwrap();
        let (server, _) = l.accept().unwrap();
        let head = format!(
            "{method} /x HTTP/1.1\r\nContent-Type: application/json\r\nX-MCP-Lockdown: false\r\n{extra}Content-Length: {}\r\n\r\n",
            body.len()
        );
        c.write_all(body.as_bytes()).unwrap();
        let shut = std::sync::atomic::AtomicBool::new(false);
        ep.serve(
            server,
            head.as_bytes(),
            &log,
            None,
            std::time::Duration::from_secs(5),
            &shut,
        );
        let mut reply = String::new();
        c.read_to_string(&mut reply).unwrap();
        (
            reply,
            std::fs::read_to_string(&log_path).unwrap_or_default(),
        )
    }

    /// A cancel on a second connection reaches the upstream while the call
    /// it names is still running on the first, and frees the call's slot;
    /// a cancel for an id not in flight is dropped (stdio semantics).
    #[test]
    fn cross_connection_cancel_is_forwarded() {
        let Some(curl) = real_curl() else { return };
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/mcp", l.local_addr().unwrap());
        let (tx, rx) = std::sync::mpsc::channel();
        let (seen_tx, seen) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            // Hold the call's connection open until the cancel has come in;
            // the two curls may connect in either order.
            let mut held = Vec::new();
            for _ in 0..2 {
                let (mut c, _) = l.accept().unwrap();
                let (mut got, mut buf) = (Vec::new(), [0; 4096]);
                while !got.ends_with(b"}}") {
                    match c.read(&mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => got.extend_from_slice(&buf[..n]),
                    }
                }
                let got = String::from_utf8_lossy(&got).into_owned();
                if got.contains("notifications/cancelled") {
                    let _ = c.write_all(b"HTTP/1.1 202 Accepted\r\nContent-Length: 0\r\n\r\n");
                    let _ = tx.send(got);
                } else {
                    let _ = seen_tx.send(());
                    held.push(c);
                }
            }
            drop(held);
        });
        let mut ep = for_spec(&gh_spec(), &Fixed(Some("T")), curl, "x").unwrap();
        ep.upstream = url;
        let ep = std::sync::Arc::new(ep);
        let call = r#"{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"get_me","arguments":{}}}"#;
        let first = {
            let ep = ep.clone();
            std::thread::spawn(move || serve_on(&ep, "POST", call))
        };
        let in_flight = || ep.pending.lock().unwrap().in_flight();
        // The call has reached the upstream, so it is in flight.
        seen.recv_timeout(std::time::Duration::from_secs(10))
            .expect("call never reached the upstream");
        let unknown =
            r#"{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":99}}"#;
        let (reply, log) = serve_on(&ep, "POST", unknown);
        assert!(
            reply.starts_with("HTTP/1.1 202"),
            "unknown id not answered 202"
        );
        assert!(log.contains("DROPPED"), "unknown id not dropped");
        let cancel =
            r#"{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":7}}"#;
        let (_, log) = serve_on(&ep, "POST", cancel);
        let sent = rx.recv_timeout(std::time::Duration::from_secs(10)).unwrap();
        assert!(
            sent.contains("notifications/cancelled"),
            "cancel not forwarded"
        );
        assert!(
            log.contains("tools/call get_me → CANCELLED"),
            "no cancel audit"
        );
        assert_eq!(in_flight(), 0, "slot not freed");
        let _ = first.join();
    }

    #[test]
    fn failed_exchanges_free_their_ids() {
        let Some(curl) = real_curl() else { return };
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/mcp", l.local_addr().unwrap());
        std::thread::spawn(move || {
            for n in 0..9 {
                let (mut c, _) = l.accept().unwrap();
                let (mut got, mut buf) = (Vec::new(), [0; 4096]);
                while !got.ends_with(b"}") {
                    match c.read(&mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => got.extend_from_slice(&buf[..n]),
                    }
                }
                let reply: &[u8] = if n < 8 {
                    b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 3\r\n\r\nbad"
                } else {
                    let b = r#"{"jsonrpc":"2.0","id":1,"result":{"tools":[]}}"#;
                    &format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{b}", b.len()).into_bytes()
                };
                let _ = c.write_all(reply);
            }
        });
        let mut ep = for_spec(&gh_spec(), &Fixed(Some("T")), curl, "x").unwrap();
        ep.upstream = url;
        for id in 1..=8 {
            let list = format!(r#"{{"jsonrpc":"2.0","id":{id},"method":"tools/list"}}"#);
            let (reply, _) = serve_on(&ep, "POST", &list);
            assert!(reply.starts_with("HTTP/1.1 502"), "reply assertion");
        }
        assert_eq!(ep.pending.lock().unwrap().in_flight(), 0, "slots leaked");
        // Past the cap, and id 1 reused.
        let (reply, _) = serve_on(&ep, "POST", LIST);
        assert!(reply.contains(r#""result""#), "reply assertion");
    }

    const LIST: &str = r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#;

    #[test]
    fn denied_tools_call_never_reaches_upstream() {
        let dir = tempfile::tempdir().unwrap();
        let (_, ran) = fake_curl(dir.path());
        let call = r#"{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"delete_repo","arguments":{}}}"#;
        let (reply, log) = through(
            "https://up.example/mcp".into(),
            dir.path().join("curl"),
            call,
        );
        assert!(reply.starts_with("HTTP/1.1 200"));
        let body = reply.split("\r\n\r\n").nth(1).unwrap();
        let v: serde_json::Value = serde_json::from_str(body).unwrap();
        assert_eq!(v["id"], 7);
        assert_eq!(v["error"]["code"], super::super::DENIED);
        assert!(!ran.exists(), "curl ran for a denied call");
        // The endpoint's own upstream, never the built-in GitHub one.
        assert!(log.contains("https://up.example/mcp tools/call") && log.contains("DENIED"));
        assert!(!log.contains(UPSTREAM));
    }

    fn fake_curl(dir: &std::path::Path) -> (PathBuf, PathBuf) {
        use std::os::unix::fs::PermissionsExt;
        let fake = dir.join("curl");
        let ran = dir.join("ran");
        std::fs::write(&fake, format!("#!/bin/sh\ntouch '{}'\n", ran.display())).unwrap();
        std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755)).unwrap();
        (fake, ran)
    }

    fn real_curl() -> Option<PathBuf> {
        crate::git::trusted_binary("curl")
    }

    #[test]
    fn tools_list_json_is_filtered_and_headers_forced() {
        let Some(curl) = real_curl() else { return };
        let (url, got) = fake_upstream(
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 105\r\n\r\n{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"tools\":[{\"name\":\"get_me\"},{\"name\":\"delete_repo\"}]}}            ",
        );
        let (reply, log) = through(url.clone(), curl, LIST);
        let sent = got.recv().unwrap();
        assert!(sent.contains("Authorization: Bearer T"));
        assert!(sent.contains("X-MCP-Lockdown: true") && !sent.contains("false"));
        assert!(reply.contains("get_me") && !reply.contains("delete_repo"));
        let body = reply.split("\r\n\r\n").nth(1).unwrap();
        assert!(reply.contains(&format!("Content-Length: {}\r\n", body.len())));
        assert!(log.contains(&url) && log.contains("FORWARDED 200"));
    }

    #[test]
    fn sse_events_are_filtered_and_a_bad_event_closes_the_stream() {
        let Some(curl) = real_curl() else { return };
        let (url, _got) = fake_upstream(
            b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\r\n: ping\n\nevent: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\n\
data: \"result\":{\"tools\":[{\"name\":\"get_me\"},{\"name\":\"delete_repo\"}]}}\n\n\
data: not json\n\n\
data: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"tools\":[{\"name\":\"after_bad\"}]}}\n\n",
        );
        let (reply, log) = through(url, curl, LIST);
        assert!(reply.contains(": ping\n\n"));
        assert!(reply.contains("event: message\ndata: {"));
        assert!(reply.contains("get_me") && !reply.contains("delete_repo"));
        assert!(!reply.contains("not json") && !reply.contains("after_bad"));
        assert!(log.contains("FAIL 200 (unparsable message)"));
    }

    #[test]
    fn non_post_body_is_refused_under_a_policy() {
        let dir = tempfile::tempdir().unwrap();
        let (_, ran) = fake_curl(dir.path());
        let call = r#"{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"delete_repo","arguments":{}}}"#;
        for m in ["GET", "DELETE"] {
            let (reply, log) = through_as(
                m,
                "https://up.example/mcp".into(),
                dir.path().join("curl"),
                call,
            );
            assert!(reply.starts_with("HTTP/1.1 400"));
            assert!(log.contains("FAIL body on non-POST"));
        }
        assert!(!ran.exists(), "curl ran for a non-POST body");
    }

    #[test]
    fn method_override_headers_are_never_forwarded() {
        for h in [
            "X-HTTP-Method-Override",
            "x-http-method",
            "X-Method-Override",
        ] {
            assert!(!forwarded(h, &[], true) && !forwarded(h, &[], false), "{h}");
        }
    }

    #[test]
    fn allowed_tools_call_logs_the_audit_line() {
        let Some(curl) = real_curl() else { return };
        let (url, _got) = fake_upstream(
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 47\r\n\r\n{\"jsonrpc\":\"2.0\",\"id\":7,\"result\":{\"x\":1}}    ",
        );
        let call = r#"{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"get_me","arguments":{}}}"#;
        let (_, log) = through(url, curl, call);
        assert!(log.contains("tools/call get_me → ALLOWED "));
    }

    const CALL: &str = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_me","arguments":{}}}"#;

    /// A failed call is audited by name, once.
    #[test]
    fn failed_tools_call_logs_the_audit_line_once() {
        let Some(curl) = real_curl() else { return };
        let (url, _got) = fake_upstream(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n");
        let (_, log) = through(url, curl, CALL);
        assert_eq!(
            log.matches("tools/call get_me → FAIL 502 ").count(),
            1,
            "{log}"
        );
        assert_eq!(log.matches("tools/call").count(), 1, "{log}");
    }

    #[test]
    fn timed_out_tools_call_logs_the_audit_line_once() {
        let Some(curl) = real_curl() else { return };
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/mcp", l.local_addr().unwrap());
        // Accept and never answer.
        std::thread::spawn(move || {
            let held = l.accept();
            std::thread::sleep(std::time::Duration::from_secs(5));
            drop(held);
        });
        let mut ep = for_spec(&gh_spec(), &Fixed(Some("T")), curl, "x").unwrap();
        ep.upstream = url;
        ep.timeout_secs = 1;
        let (_, log) = serve_on(&ep, "POST", CALL);
        assert_eq!(
            log.matches("tools/call get_me → TIMEOUT ").count(),
            1,
            "{log}"
        );
        assert_eq!(log.matches("tools/call").count(), 1, "{log}");
        assert_eq!(ep.pending.lock().unwrap().in_flight(), 0);
    }

    /// A primed stream that closes before the response frees the id and is
    /// audited once, at exchange end: resume is not supported.
    #[test]
    fn a_primed_stream_is_audited_once_at_exchange_end() {
        let Some(curl) = real_curl() else { return };
        let (url, _got) = fake_upstream(
            b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\r\nid: 1\nretry: 10\ndata:\n\n",
        );
        let mut ep = for_spec(&gh_spec(), &Fixed(Some("T")), curl, "x").unwrap();
        ep.upstream = url;
        let (reply, log) = serve_on(&ep, "POST", CALL);
        assert!(reply.contains("id: 1\nretry: 10\ndata:\n\n"), "{reply}");
        assert_eq!(log.matches("tools/call").count(), 1, "{log}");
        assert!(log.contains("tools/call get_me → FAIL 200 "), "{log}");
        assert_eq!(ep.pending.lock().unwrap().in_flight(), 0);
    }

    /// An event with an `id:` whose message the policy drops pins nothing.
    #[test]
    fn a_dropped_event_with_an_id_pins_nothing() {
        let Some(curl) = real_curl() else { return };
        let (url, _got) = fake_upstream(
            b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\r\nid: 5\n\
data: {\"jsonrpc\":\"2.0\",\"id\":9,\"method\":\"sampling/createMessage\"}\n\n",
        );
        let mut ep = for_spec(&gh_spec(), &Fixed(Some("T")), curl, "x").unwrap();
        ep.upstream = url;
        let (_, log) = serve_on(&ep, "POST", CALL);
        assert_eq!(log.matches("tools/call").count(), 1, "{log}");
        assert_eq!(ep.pending.lock().unwrap().in_flight(), 0);
    }

    /// A session-less `initialize` on a primed stream never stays pinned.
    #[test]
    fn a_primed_initialize_is_not_pinned() {
        let Some(curl) = real_curl() else { return };
        let (url, _got) = fake_upstream(
            b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\r\nid: 1\ndata:\n\n",
        );
        let mut ep = for_spec(&gh_spec(), &Fixed(Some("T")), curl, "x").unwrap();
        ep.upstream = url;
        let init = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#;
        serve_on(&ep, "POST", init);
        assert_eq!(ep.pending.lock().unwrap().in_flight(), 0);
    }

    /// A GET with `Last-Event-ID` is refused without reaching upstream.
    #[test]
    fn a_last_event_id_get_is_refused() {
        let Some(curl) = real_curl() else { return };
        let (url, got) = fake_upstream(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
        let mut ep = for_spec(&gh_spec(), &Fixed(Some("T")), curl, "x").unwrap();
        ep.upstream = url;
        let (reply, log) = serve_with(&ep, "GET", "", "Last-Event-ID: 1\r\n");
        assert!(reply.starts_with("HTTP/1.1 400"), "{reply}");
        assert!(
            reply.contains("resume (Last-Event-ID) is not supported"),
            "{reply}"
        );
        assert!(log.contains("FAIL stream resume not supported"), "{log}");
        assert!(got.try_recv().is_err(), "upstream reached");
    }

    /// Two session-less `initialize` calls with the same id are separate
    /// sessions, not duplicates.
    #[test]
    fn concurrent_initializations_with_one_id_both_pass() {
        let Some(curl) = real_curl() else { return };
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/mcp", l.local_addr().unwrap());
        let (seen_tx, seen) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let mut held = Vec::new();
            for _ in 0..2 {
                let (mut c, _) = l.accept().unwrap();
                let (mut got, mut buf) = (Vec::new(), [0; 4096]);
                while !got.ends_with(b"}}") {
                    match c.read(&mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => got.extend_from_slice(&buf[..n]),
                    }
                }
                let _ = seen_tx.send(());
                held.push(c);
            }
            let b = r#"{"jsonrpc":"2.0","id":1,"result":{}}"#;
            for mut c in held {
                let _ = c.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{b}", b.len()).as_bytes());
            }
        });
        let mut ep = for_spec(&gh_spec(), &Fixed(Some("T")), curl, "x").unwrap();
        ep.upstream = url;
        let ep = std::sync::Arc::new(ep);
        let init = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}"#;
        let t = std::time::Duration::from_secs(10);
        let hs: Vec<_> = (0..2)
            .map(|_| {
                let ep = ep.clone();
                std::thread::spawn(move || serve_on(&ep, "POST", init))
            })
            .collect();
        seen.recv_timeout(t)
            .expect("first initialize not forwarded");
        seen.recv_timeout(t)
            .expect("second initialize refused as a duplicate");
        for h in hs {
            assert!(
                h.join().unwrap().0.contains(r#""result""#),
                "reply assertion"
            );
        }
        assert_eq!(ep.pending.lock().unwrap().in_flight(), 0);
    }

    #[test]
    fn two_session_headers_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        let (curl, ran) = fake_curl(dir.path());
        let ep = for_spec(&gh_spec(), &Fixed(Some("T")), curl, "x").unwrap();
        let (reply, log) = serve_with(
            &ep,
            "POST",
            LIST,
            "Mcp-Session-Id: A\r\nMcp-Session-Id: B\r\n",
        );
        assert!(reply.starts_with("HTTP/1.1 400"), "reply assertion");
        assert!(
            log.contains("more than one Mcp-Session-Id"),
            "log assertion"
        );
        assert!(!ran.exists(), "curl ran");
    }

    /// `filter_events` over `stream`: what the client got, and why it closed.
    fn sse(stream: &str) -> (String, Option<&'static str>) {
        let ep = for_spec(&gh_spec(), &Fixed(Some("T")), PathBuf::from("/c"), "x").unwrap();
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let mut c = TcpStream::connect(l.local_addr().unwrap()).unwrap();
        let (mut server, _) = l.accept().unwrap();
        let mut f = Filter {
            session: String::new(),
            spec: ep.policy.as_ref().unwrap(),
            pending: &ep.pending,
            audit: Vec::new(),
        };
        let mut input = std::io::Cursor::new(stream.as_bytes().to_vec());
        let why = filter_events(&mut input, &mut server, &mut f).err();
        drop(server);
        let mut got = String::new();
        c.read_to_string(&mut got).unwrap();
        (got, why)
    }

    #[test]
    fn sse_only_known_fields_pass() {
        let list = r#"{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"delete_repo"}]}}"#;
        let (got, why) = sse(&format!("\u{feff}data: {list}\n\n"));
        assert_eq!((got.as_str(), why), ("", Some("unknown event field")));
        let (got, why) = sse(&format!("foo: x\ndata: {list}\n\n"));
        assert_eq!((got.as_str(), why), ("", Some("unknown event field")));
        let (got, why) = sse("event: m\nid: 1\nretry: 5\n: c\n\n");
        assert_eq!(
            (got.as_str(), why),
            ("event: m\nid: 1\nretry: 5\n: c\n\n", None)
        );
        let big = format!("data: {}\n", "x".repeat(MAX_BODY));
        assert_eq!(sse(&big).1, Some("event too large"));
        // A server request and a batch are dropped, not delivered.
        let req = r#"{"jsonrpc":"2.0","id":9,"method":"sampling/createMessage","params":{}}"#;
        let batch = format!("[{list}]");
        let (got, why) = sse(&format!("data: {req}\n\ndata: {batch}\n\n"));
        assert_eq!((got.as_str(), why), ("", None));
    }

    #[test]
    fn sse_lone_cr_closes_the_stream() {
        let Some(curl) = real_curl() else { return };
        let (url, _got) = fake_upstream(
            b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\r\nid: 1\rdata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"tools\":[{\"name\":\"delete_repo\"}]}}\n\n",
        );
        let (reply, log) = through(url, curl, LIST);
        assert!(!reply.contains("delete_repo"));
        assert!(log.contains("FAIL 200"));
    }

    #[test]
    fn unknown_content_type_body_is_not_passed() {
        let Some(curl) = real_curl() else { return };
        let (url, _got) = fake_upstream(
            b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 11\r\n\r\ndelete_repo",
        );
        let (reply, log) = through(url, curl, LIST);
        assert!(!reply.contains("delete_repo"));
        assert!(log.contains("FAIL 200 (not JSON)"));
    }

    #[test]
    fn broker_denials_and_failures_reach_the_terminal_at_every_level() {
        let log = Log {
            level: ProxyLogLevel::None,
            file: None,
        };
        assert!(log.to_terminal(true, "tools/call delete_repo → DENIED"));
        assert!(log.to_terminal(true, "FAIL 200 (not JSON)"));
        assert!(!log.to_terminal(true, "FORWARDED 200"));
        // The built-in endpoint keeps the proxy's level.
        assert!(!log.to_terminal(false, "tools/call x → DENIED"));
    }

    fn relay_of(input: &str) -> (String, Option<(String, Option<&'static str>)>) {
        let ep = for_spec(&gh_spec(), &Fixed(Some("T")), PathBuf::from("/c"), "x").unwrap();
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let mut c = TcpStream::connect(l.local_addr().unwrap()).unwrap();
        let (mut server, _) = l.accept().unwrap();
        let mut f = Filter {
            session: String::new(),
            spec: ep.policy.as_ref().unwrap(),
            pending: &ep.pending,
            audit: Vec::new(),
        };
        // The response answers a request in flight.
        on_client(LIST, f.spec, "", &mut f.lock());
        let got = relay(input.as_bytes(), &mut server, Some(&mut f));
        drop(server);
        let mut reply = String::new();
        c.read_to_string(&mut reply).unwrap();
        (reply, got)
    }

    #[test]
    fn interim_responses_are_skipped() {
        let body = r#"{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"get_me"},{"name":"delete_repo"}]}}"#;
        for interim in [
            "HTTP/1.1 100 Continue\r\n\r\n",
            "HTTP/1.1 103 Early Hints\r\nLink: </x>; rel=preload\r\n\r\n",
        ] {
            let input = format!(
                "{interim}HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
                body.len()
            );
            let (reply, got) = relay_of(&input);
            assert_eq!(got, Some(("200".to_string(), None)), "{interim}");
            assert!(reply.starts_with("HTTP/1.1 200"), "reply assertion");
            assert!(reply.contains("get_me") && !reply.contains("delete_repo"));
        }
    }

    #[test]
    fn sse_priming_event_passes() {
        let Some(curl) = real_curl() else { return };
        let (url, _got) = fake_upstream(
            b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\r\nid: 1\ndata:\n\n\
data: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"tools\":[{\"name\":\"get_me\"},{\"name\":\"delete_repo\"}]}}\n\n",
        );
        let (reply, log) = through(url, curl, LIST);
        assert!(reply.contains("id: 1\ndata:\n\n"), "reply assertion");
        assert!(reply.contains("get_me") && !reply.contains("delete_repo"));
        assert!(log.contains("FORWARDED 200"), "log assertion");
    }

    /// Ids are keyed by `Mcp-Session-Id`: the same id in a second session
    /// goes through while the first is in flight; in the same session it
    /// is a duplicate.
    #[test]
    fn session_id_header_keys_in_flight_ids() {
        let Some(curl) = real_curl() else { return };
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/mcp", l.local_addr().unwrap());
        let (seen_tx, seen) = std::sync::mpsc::channel();
        let (go_tx, go) = std::sync::mpsc::channel::<()>();
        std::thread::spawn(move || {
            let mut held = Vec::new();
            for _ in 0..2 {
                let (mut c, _) = l.accept().unwrap();
                let (mut got, mut buf) = (Vec::new(), [0; 4096]);
                while !got.ends_with(b"}}") {
                    match c.read(&mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => got.extend_from_slice(&buf[..n]),
                    }
                }
                let _ = seen_tx.send(String::from_utf8_lossy(&got).into_owned());
                held.push(c);
            }
            let _ = go.recv();
            let b = r#"{"jsonrpc":"2.0","id":7,"result":{}}"#;
            for mut c in held {
                let _ = c.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{b}", b.len()).as_bytes());
            }
        });
        let mut ep = for_spec(&gh_spec(), &Fixed(Some("T")), curl, "x").unwrap();
        ep.upstream = url;
        let ep = std::sync::Arc::new(ep);
        let call = r#"{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"get_me","arguments":{}}}"#;
        let t = std::time::Duration::from_secs(10);
        let in_session = |s: &'static str| {
            let ep = ep.clone();
            std::thread::spawn(move || {
                serve_with(&ep, "POST", call, &format!("Mcp-Session-Id: {s}\r\n"))
            })
        };
        let a = in_session("A");
        seen.recv_timeout(t)
            .expect("session A never reached upstream");
        let b = in_session("B");
        let got = seen.recv_timeout(t).expect("session B id 7 not forwarded");
        assert!(got.contains("Mcp-Session-Id: B"), "got assertion");
        let (reply, log) = serve_with(&ep, "POST", call, "Mcp-Session-Id: A\r\n");
        assert!(reply.contains("already in flight"), "reply assertion");
        assert!(log.contains("DENIED duplicate id"), "log assertion");
        go_tx.send(()).unwrap();
        for h in [a, b] {
            assert!(h.join().unwrap().0.starts_with("HTTP/1.1 200"));
        }
    }
}
