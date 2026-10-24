//! Proxy-side GitHub token injection (#820), opt-in with
//! `proxy.inject_github_token` / `--inject-github-token`.
//!
//! The sandbox gets a placeholder in place of each GitHub token cplt hands
//! it. The placeholder has the real token's prefix and length, because
//! Copilot checks the prefix before it sends anything. For CONNECTs to
//! `api.github.com`, `github.com` and `*.githubcopilot.com` on 443, the proxy
//! terminates TLS with a leaf signed by a CA that exists only in this
//! process's memory, puts the real token back in the `Authorization` header
//! and opens its own TLS connection upstream. Every other host keeps the
//! plain tunnel. A long-lived token read out of the sandbox is then worth
//! nothing outside it.
//!
//! The CA key never touches disk. Only its certificate goes into the scratch
//! dir, inside the bundles the sandboxed clients are pointed at. Those files
//! are agent-writable; editing them changes only what the agent trusts,
//! never what the proxy trusts, which is held in memory.
//!
//! Any setup failure refuses the launch with a message saying what to fix:
//! never a silent fallback to the real token.

use std::collections::HashMap;
use std::io::{ErrorKind, Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use rustls::pki_types::pem::PemObject as _;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::{ClientConfig, ClientConnection, RootCertStore, ServerConfig, ServerConnection};

use crate::agent::SecretToken;

/// GitHub token prefixes. Longest first: `github_pat_` must win over `gh?_`.
const PREFIXES: &[&str] = &["github_pat_", "gho_", "ghp_", "ghu_", "ghs_", "ghr_"];

/// Variables that carry a whole GitHub token into the child.
const TOKEN_VARS: &[&str] = &["GH_TOKEN", "GITHUB_TOKEN", "COPILOT_GITHUB_TOKEN"];

/// Variables whose value may embed a GitHub token among other text.
const EMBEDDING_VARS: &[&str] = &["OPENCODE_AUTH_CONTENT"];

/// User CA files already in the environment. Concatenated into cplt's
/// bundles, never replaced: a corporate TLS-inspecting proxy breaks
/// otherwise.
pub const USER_CA_VARS: &[&str] = &["SSL_CERT_FILE", "NODE_EXTRA_CA_CERTS", "GIT_SSL_CAINFO"];

/// System root bundles, first hit wins: macOS / Alpine / Arch, Debian /
/// Ubuntu, Fedora / RHEL, openSUSE.
const SYSTEM_BUNDLES: &[&str] = &[
    "/etc/ssl/cert.pem",
    "/etc/ssl/certs/ca-certificates.crt",
    "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
    "/etc/pki/tls/certs/ca-bundle.crt",
    "/etc/ssl/ca-bundle.pem",
];

const CA_FILE_LIMIT: u64 = 8 * 1024 * 1024;
const MAX_HEAD: usize = 64 * 1024;

/// The variables that point the agent at the session bundles.
pub const CA_VARS: &[&str] = &["SSL_CERT_FILE", "GIT_SSL_CAINFO", "NODE_EXTRA_CA_CERTS"];

/// The first CA variable `deny_env` names. Injection cannot honour such a
/// denial and still have the agent trust the proxy, so it falls back.
pub fn denied_ca_var(deny_env: &[String]) -> Option<&'static str> {
    CA_VARS
        .iter()
        .copied()
        .find(|v| deny_env.iter().any(|d| d == v))
}

pub const FULL_BUNDLE: &str = "cplt-ca-bundle.pem";
pub const NODE_BUNDLE: &str = "cplt-node-ca.pem";

/// Placeholder → real token, for every token masked this session.
static TOKENS: Mutex<Vec<(String, SecretToken)>> = Mutex::new(Vec::new());

/// ponytail: one injector per process, which is one cplt session.
static INJECTOR: OnceLock<Injector> = OnceLock::new();

struct Injector {
    ca: rcgen::Issuer<'static, rcgen::KeyPair>,
    ca_der: CertificateDer<'static>,
    client: Arc<ClientConfig>,
    leaves: Mutex<HashMap<String, Arc<ServerConfig>>>,
    full_bundle: PathBuf,
    node_bundle: PathBuf,
}

/// Is injection active for this session?
pub fn active() -> bool {
    INJECTOR.get().is_some()
}

/// Set injection up for this session: CA, bundles in `scratch`, upstream
/// roots. On `Err` nothing is active and the caller says so in one line.
pub fn setup(scratch: &Path) -> Result<(), String> {
    let system = SYSTEM_BUNDLES
        .iter()
        .find_map(|p| read_ca_file(Path::new(p)))
        .ok_or("no system CA bundle found")?;
    // A CA the user set but cplt cannot load would be missing from the
    // bundles and break every client behind a corporate proxy: refuse.
    let mut user = String::new();
    for var in USER_CA_VARS {
        let Some(path) = std::env::var_os(var).filter(|p| !p.is_empty()) else {
            continue;
        };
        user.push_str(
            &read_ca_file(Path::new(&path))
                .ok_or_else(|| format!("cannot load the CA file in {var}"))?,
        );
    }
    let injector = build(&system, &user, scratch)?;
    INJECTOR
        .set(injector)
        .map_err(|_| "token injection is already set up".to_string())
}

/// Read a PEM file the user named, which may sit somewhere the agent can
/// write: no symlinks, no FIFOs, capped. `None` when it holds no cert.
fn read_ca_file(path: &Path) -> Option<String> {
    let text = crate::untrusted::read_untrusted(path, CA_FILE_LIMIT).ok()??;
    let pem = certs_only(&text);
    (!pem.is_empty()).then_some(pem)
}

/// Only the CERTIFICATE blocks of `text`, re-encoded. The bundles are
/// agent-readable, and a combined cert-and-key file must not carry its key
/// into them.
fn certs_only(text: &str) -> String {
    CertificateDer::pem_slice_iter(text.as_bytes())
        .flatten()
        .map(|der| {
            let b64 = B64.encode(der.as_ref());
            let lines: Vec<&str> = b64
                .as_bytes()
                .chunks(64)
                .map(|c| std::str::from_utf8(c).unwrap_or_default())
                .collect();
            format!(
                "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
                lines.join("\n")
            )
        })
        .collect()
}

fn build(system: &str, user: &str, scratch: &Path) -> Result<Injector, String> {
    let mut roots = RootCertStore::empty();
    for der in CertificateDer::pem_slice_iter(format!("{system}{user}").as_bytes()).flatten() {
        // A cert rustls cannot parse is skipped, as every TLS client does.
        let _ = roots.add(der);
    }
    if roots.is_empty() {
        return Err("no usable CA certificates".into());
    }

    let (ca, ca_der, ca_pem) = new_ca().map_err(|e| format!("cannot create the CA: {e}"))?;
    let full_bundle = scratch.join(FULL_BUNDLE);
    let node_bundle = scratch.join(NODE_BUNDLE);
    write_new(&full_bundle, &format!("{system}{user}{ca_pem}"))?;
    write_new(&node_bundle, &format!("{user}{ca_pem}"))?;

    let mut client = ClientConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .map_err(|e| e.to_string())?
        .with_root_certificates(roots)
        .with_no_client_auth();
    client.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Injector {
        ca,
        ca_der,
        client: Arc::new(client),
        leaves: Mutex::new(HashMap::new()),
        full_bundle,
        node_bundle,
    })
}

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// Validity for session certs: an hour back for clock skew, a week ahead.
/// Short, because Apple's verifier refuses long-lived TLS leaves.
fn validity(params: &mut rcgen::CertificateParams) {
    let now = time::OffsetDateTime::now_utc();
    params.not_before = now - time::Duration::hours(1);
    params.not_after = now + time::Duration::days(7);
}

type Ca = (
    rcgen::Issuer<'static, rcgen::KeyPair>,
    CertificateDer<'static>,
    String,
);

fn new_ca() -> Result<Ca, rcgen::Error> {
    let key = rcgen::KeyPair::generate()?;
    let mut params = rcgen::CertificateParams::default();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "cplt session CA");
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Constrained(0));
    params.key_usages = vec![
        rcgen::KeyUsagePurpose::KeyCertSign,
        rcgen::KeyUsagePurpose::DigitalSignature,
    ];
    // Bounded to the injected hosts: even a leaked CA cannot vouch for
    // anything else, for verifiers that honour name constraints.
    params.name_constraints = Some(rcgen::NameConstraints {
        permitted_subtrees: vec![
            rcgen::GeneralSubtree::DnsName("github.com".into()),
            rcgen::GeneralSubtree::DnsName("githubcopilot.com".into()),
        ],
        excluded_subtrees: Vec::new(),
    });
    validity(&mut params);
    let cert = params.self_signed(&key)?;
    let pem = cert.pem();
    let der = cert.der().clone();
    Ok((rcgen::Issuer::new(params, key), der, pem))
}

/// Create `path` 0600, refusing anything already there.
fn write_new(path: &Path, contents: &str) -> Result<(), String> {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .and_then(|mut f| f.write_all(contents.as_bytes()))
        .map_err(|e| format!("cannot write {}: {e}", path.display()))
}

// ── Placeholders ─────────────────────────────────────────────────────────

/// A placeholder for `real`: same prefix, same length, same separator
/// positions, random alphanumerics elsewhere. `None` for a value that is
/// not a GitHub token.
pub fn placeholder_for(real: &str) -> Option<String> {
    let prefix = PREFIXES.iter().find(|p| real.starts_with(**p))?;
    let rest = &real[prefix.len()..];
    if rest.is_empty() || !rest.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
        return None;
    }
    let mut random = vec![0u8; rest.len()];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut random))
        .ok()?;
    const ALNUM: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let body: String = rest
        .bytes()
        .zip(random)
        .map(|(b, r)| {
            if b == b'_' {
                '_'
            } else {
                // 256 % 62 bias is irrelevant: the value is not a secret.
                ALNUM[r as usize % ALNUM.len()] as char
            }
        })
        .collect();
    Some(format!("{prefix}{body}"))
}

/// The placeholder for `real`, made and remembered on first use. `real`
/// unchanged when injection is off or it is not a GitHub token.
pub fn mask(real: &str) -> String {
    if active() {
        remember(real)
    } else {
        real.to_string()
    }
}

fn remember(real: &str) -> String {
    let mut tokens = TOKENS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some((p, _)) = tokens.iter().find(|(_, r)| r.expose() == real) {
        return p.clone();
    }
    let Some(p) = placeholder_for(real) else {
        return real.to_string();
    };
    tokens.push((p.clone(), SecretToken::new(real.to_string())));
    p
}

/// Substrings of `value` shaped like a GitHub token: a known prefix at a
/// word start, then `[A-Za-z0-9_]`.
fn embedded_tokens(value: &str) -> Vec<&str> {
    let word = |b: u8| b.is_ascii_alphanumeric() || b == b'_';
    let bytes = value.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        let at_start = i == 0 || !word(bytes[i - 1]);
        if at_start
            && PREFIXES
                .iter()
                .any(|p| bytes[i..].starts_with(p.as_bytes()))
        {
            let end = bytes[i..]
                .iter()
                .position(|&b| !word(b))
                .map_or(bytes.len(), |n| i + n);
            out.push(&value[i..end]);
            i = end;
        } else {
            i += 1;
        }
    }
    out
}

/// Every known real token in `value` replaced by its placeholder.
fn mask_within(value: &str) -> String {
    let tokens = TOKENS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    tokens.iter().fold(value.to_string(), |v, (p, r)| {
        if r.expose().is_empty() {
            v
        } else {
            v.replace(r.expose(), p)
        }
    })
}

fn real_for(placeholder: &str) -> Option<SecretToken> {
    let tokens = TOKENS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    tokens
        .iter()
        .find(|(p, _)| p == placeholder)
        .map(|(_, r)| r.clone())
}

/// Point the child at the session bundles and replace every GitHub token in
/// its environment with a placeholder. Runs after every other env step, so
/// nothing set later can bring a real token back. A no-op when injection is
/// off.
///
/// `inherit_env` says whether the child inherits the parent environment.
/// Without it the child gets only what was set on `cmd`, and this must never
/// add a variable the allowlist kept out.
pub fn apply_to_child(cmd: &mut Command, inherit_env: bool) {
    let Some(inj) = INJECTOR.get() else {
        return;
    };
    mask_child_env(cmd, inherit_env);
    cmd.env("SSL_CERT_FILE", &inj.full_bundle);
    cmd.env("GIT_SSL_CAINFO", &inj.full_bundle);
    cmd.env("NODE_EXTRA_CA_CERTS", &inj.node_bundle);
}

fn mask_child_env(cmd: &mut Command, inherit_env: bool) {
    // The env the child actually gets: explicit entries, over inherited ones
    // only in inherit mode. Masking only ever rewrites a value in it.
    let mut env: HashMap<String, Option<String>> = if inherit_env {
        std::env::vars().map(|(k, v)| (k, Some(v))).collect()
    } else {
        HashMap::new()
    };
    for (k, v) in cmd.get_envs() {
        env.insert(
            k.to_string_lossy().into_owned(),
            v.map(|v| v.to_string_lossy().into_owned()),
        );
    }
    // Whole-token vars first, so the substring pass below knows the token.
    for name in TOKEN_VARS {
        if let Some(Some(v)) = env.get(*name) {
            let masked = remember(v.trim());
            if masked != v.trim() {
                cmd.env(name, masked);
            }
        }
    }
    // Values that embed a token, such as OpenCode's auth JSON, even one no
    // other channel registered.
    for name in EMBEDDING_VARS {
        if let Some(Some(v)) = env.get(*name) {
            for candidate in embedded_tokens(v) {
                remember(candidate);
            }
        }
    }
    for (k, v) in &env {
        if let Some(v) = v {
            let masked = mask_within(v);
            if &masked != v {
                cmd.env(k, masked);
            }
        }
    }
}

// ── Rules ────────────────────────────────────────────────────────────────

/// Does a CONNECT to `host:port` get TLS termination?
pub fn intercepts(host: &str, port: u16) -> bool {
    port == 443 && (host == "api.github.com" || host == "github.com" || is_copilot_host(host))
}

fn is_copilot_host(host: &str) -> bool {
    host.strip_suffix(".githubcopilot.com")
        .is_some_and(|sub| !sub.is_empty())
}

/// May a request with this `method` and `target` on `host` carry the real
/// token?
///
/// - TRACE echoes the request back, header included: never.
/// - The GitHub MCP paths on the Copilot hosts belong to `github_mcp`, which
///   pins them read-only; a write-capable token must not reach them here. A
///   first path segment with `%` or `.` could be an encoded or dotted
///   spelling of `/mcp`, so it is refused too.
pub fn may_inject(host: &str, method: &str, target: &str) -> bool {
    if method.eq_ignore_ascii_case("TRACE") || method.eq_ignore_ascii_case("CONNECT") {
        return false;
    }
    if !is_copilot_host(host) {
        return true;
    }
    // Absolute-form targets carry scheme and authority first.
    // Absolute form only when the target starts with a scheme: a `://` in
    // the query of an origin-form target must not move the path check.
    let lower = target.to_ascii_lowercase();
    let path = match ["https://", "http://"]
        .iter()
        .find(|s| lower.starts_with(**s))
    {
        Some(scheme) => {
            let rest = &target[scheme.len()..];
            rest.find(['/', '?', '#']).map_or("", |i| &rest[i..])
        }
        None => target,
    };
    let first = path
        .trim_start_matches('/')
        .split(['/', '?', '#'])
        .next()
        .unwrap_or("")
        .to_ascii_lowercase();
    !(first.starts_with("mcp") || first.contains(['%', '.']))
}

/// The real-token form of an `Authorization` value, if it carries a known
/// placeholder: `Bearer`/`token` (any case), or `Basic` whose decoded
/// password is the placeholder. `None` leaves the header as sent.
pub fn swap_authorization(value: &str) -> Option<String> {
    let (scheme, cred) = value.trim().split_once(' ')?;
    let cred = cred.trim();
    match scheme.to_ascii_lowercase().as_str() {
        "bearer" | "token" => real_for(cred).map(|r| format!("{scheme} {}", r.expose())),
        "basic" => {
            let decoded = String::from_utf8(B64.decode(cred).ok()?).ok()?;
            let (user, pass) = decoded.split_once(':')?;
            let real = real_for(pass)?;
            Some(format!(
                "{scheme} {}",
                B64.encode(format!("{user}:{}", real.expose()))
            ))
        }
        _ => None,
    }
}

/// The request head as forwarded: `Authorization` swapped when the rules
/// allow, and `Connection: close` unless it is an upgrade, so this is the
/// only request on the connection and every later byte can pass through
/// unparsed.
fn rewrite_head(host: &str, head: &str) -> String {
    let mut lines = head.split("\r\n");
    let request_line = lines.next().unwrap_or("");
    // Anything but exactly `METHOD TARGET VERSION` gets no token.
    let parts: Vec<&str> = request_line.split_whitespace().collect();
    let inject = matches!(parts[..], [method, target, _] if may_inject(host, method, target));
    let headers: Vec<&str> = lines.filter(|l| !l.is_empty()).collect();
    let upgrade = headers.iter().any(|l| {
        l.split_once(':')
            .is_some_and(|(n, _)| n.trim().eq_ignore_ascii_case("upgrade"))
    });
    let mut out = vec![request_line.to_string()];
    for line in headers {
        match line.split_once(':') {
            Some((n, value)) if inject && n.trim().eq_ignore_ascii_case("authorization") => {
                out.push(
                    swap_authorization(value)
                        .map_or_else(|| line.to_string(), |v| format!("{}: {v}", n.trim())),
                );
            }
            Some((n, _))
                if !upgrade
                    && (n.trim().eq_ignore_ascii_case("connection")
                        || n.trim().eq_ignore_ascii_case("keep-alive")) => {}
            _ => out.push(line.to_string()),
        }
    }
    if !upgrade {
        out.push("Connection: close".into());
    }
    out.join("\r\n") + "\r\n\r\n"
}

// ── The intercepted tunnel ───────────────────────────────────────────────

/// Serve one intercepted CONNECT: `client` has had its 200, `remote` is a raw
/// TCP path to `host:443` (direct or through the upstream proxy). Any
/// failure closes the connection; the client sees a TLS or HTTP error.
pub fn serve(client: TcpStream, remote: TcpStream, host: &str, timeout: Duration) {
    let Some(inj) = INJECTOR.get() else {
        return;
    };
    let _ = serve_inner(inj, client, remote, host, timeout);
}

fn serve_inner(
    inj: &Injector,
    client: TcpStream,
    remote: TcpStream,
    host: &str,
    timeout: Duration,
) -> Result<(), String> {
    let server_cfg = inj.leaf(host)?;
    let name = ServerName::try_from(host.to_string()).map_err(|e| e.to_string())?;
    let mut down = rustls::StreamOwned::new(
        ServerConnection::new(server_cfg).map_err(|e| e.to_string())?,
        client,
    );
    let mut up = rustls::StreamOwned::new(
        ClientConnection::new(Arc::clone(&inj.client), name).map_err(|e| e.to_string())?,
        remote,
    );
    for s in [&down.sock, &up.sock] {
        s.set_read_timeout(Some(timeout)).ok();
        s.set_write_timeout(Some(timeout)).ok();
    }
    // Handshake both sides, then read the first request head.
    while down.conn.is_handshaking() {
        down.conn
            .complete_io(&mut down.sock)
            .map_err(|e| e.to_string())?;
    }
    let (head, rest) = read_head(&mut down, timeout)?;
    up.write_all(rewrite_head(host, &head).as_bytes())
        .and_then(|()| up.write_all(&rest))
        .and_then(|()| up.flush())
        .map_err(|e| e.to_string())?;
    duplex(
        Side {
            conn: down.conn.into(),
            sock: down.sock,
        },
        Side {
            conn: up.conn.into(),
            sock: up.sock,
        },
        timeout,
    );
    Ok(())
}

impl Injector {
    fn leaf(&self, host: &str) -> Result<Arc<ServerConfig>, String> {
        let mut leaves = self
            .leaves
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(cfg) = leaves.get(host) {
            return Ok(Arc::clone(cfg));
        }
        let key = rcgen::KeyPair::generate().map_err(|e| e.to_string())?;
        let mut params =
            rcgen::CertificateParams::new(vec![host.to_string()]).map_err(|e| e.to_string())?;
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, host);
        params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
        params.use_authority_key_identifier_extension = true;
        validity(&mut params);
        let cert = params
            .signed_by(&key, &self.ca)
            .map_err(|e| e.to_string())?;
        let mut cfg = ServerConfig::builder_with_provider(provider())
            .with_safe_default_protocol_versions()
            .map_err(|e| e.to_string())?
            .with_no_client_auth()
            .with_single_cert(
                vec![cert.der().clone(), self.ca_der.clone()],
                PrivateKeyDer::Pkcs8(key.serialize_der().into()),
            )
            .map_err(|e| e.to_string())?;
        // HTTP/1.1 only: the rewrite parses one HTTP/1 head.
        cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
        let cfg = Arc::new(cfg);
        leaves.insert(host.to_string(), Arc::clone(&cfg));
        Ok(cfg)
    }
}

/// Read up to the end of the request head; returns the head (without the
/// final blank line) and any bytes read past it.
fn read_head<S: Read>(s: &mut S, timeout: Duration) -> Result<(String, Vec<u8>), String> {
    let deadline = Instant::now() + timeout;
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            let rest = buf.split_off(i + 4);
            buf.truncate(i);
            let head = String::from_utf8(buf).map_err(|_| "non-UTF-8 head")?;
            return Ok((head, rest));
        }
        if buf.len() > MAX_HEAD || Instant::now() > deadline {
            return Err("request head too large or too slow".into());
        }
        match s.read(&mut chunk) {
            Ok(0) => return Err("closed before the head".into()),
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
            Err(e) if is_wait(&e) => {}
            Err(e) => return Err(e.to_string()),
        }
    }
}

fn is_wait(e: &std::io::Error) -> bool {
    matches!(
        e.kind(),
        ErrorKind::WouldBlock | ErrorKind::TimedOut | ErrorKind::Interrupted
    )
}

/// One TLS side of an intercepted tunnel.
struct Side {
    conn: rustls::Connection,
    sock: TcpStream,
}

/// Pump both directions until either side closes, a write cannot finish, or
/// nothing moves for an hour (the plain relay's ceiling).
///
/// One thread, woken by `poll(2)` on both sockets rather than two pump
/// threads: a rustls connection is one state machine for both directions
/// and cannot be split across threads without a lock around every record.
/// Plaintext rustls already holds is drained before each wait, so nothing
/// sits behind a socket that shows no new bytes. Writes go through
/// `write_tls` on sockets with a write timeout; rustls keeps the unsent tail,
/// so a timeout is a retry, not a truncated record (the `write_bounded`
/// rule).
fn duplex(down: Side, up: Side, timeout: Duration) {
    use std::os::fd::AsRawFd as _;
    const CEILING: Duration = Duration::from_secs(3600);
    let mut sides = [down, up];
    for s in &sides {
        s.sock.set_write_timeout(Some(timeout)).ok();
    }
    let mut buf = vec![0u8; 64 * 1024];
    let mut last = Instant::now();
    'run: loop {
        {
            let [a, b] = &mut sides;
            if !forward(a, b, &mut buf, &mut last, CEILING)
                || !forward(b, a, &mut buf, &mut last, CEILING)
            {
                break;
            }
        }
        let mut fds = sides.each_ref().map(|s| libc::pollfd {
            fd: s.sock.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        });
        // SAFETY: `fds` is a live array of two initialised pollfds.
        let n = unsafe { libc::poll(fds.as_mut_ptr(), 2, 1000) };
        if n < 0 {
            if std::io::Error::last_os_error().kind() == ErrorKind::Interrupted {
                continue;
            }
            break;
        }
        for (side, fd) in sides.iter_mut().zip(fds) {
            if fd.revents == 0 {
                continue;
            }
            match side.conn.read_tls(&mut side.sock) {
                Ok(0) => break 'run,
                Ok(_) => {
                    last = Instant::now();
                    if side.conn.process_new_packets().is_err() {
                        break 'run;
                    }
                }
                Err(e) if is_wait(&e) => {}
                Err(_) => break 'run,
            }
        }
        if last.elapsed() >= CEILING {
            break;
        }
    }
    for side in &mut sides {
        side.conn.send_close_notify();
        let _ = flush_tls(side, &mut last, CEILING);
    }
}

/// Move all plaintext `src` holds to `dst`, and send what either owes its
/// socket. False when the tunnel should end.
fn forward(
    src: &mut Side,
    dst: &mut Side,
    buf: &mut [u8],
    last: &mut Instant,
    ceiling: Duration,
) -> bool {
    loop {
        match src.conn.reader().read(buf) {
            // Clean close_notify from this side.
            Ok(0) => return false,
            Ok(n) => {
                if dst.conn.writer().write_all(&buf[..n]).is_err() || !flush_tls(dst, last, ceiling)
                {
                    return false;
                }
            }
            Err(e) if e.kind() == ErrorKind::WouldBlock => break,
            Err(_) => return false,
        }
    }
    flush_tls(src, last, ceiling)
}

fn flush_tls(side: &mut Side, last: &mut Instant, ceiling: Duration) -> bool {
    while side.conn.wants_write() {
        match side.conn.write_tls(&mut side.sock) {
            Ok(0) => return false,
            Ok(_) => *last = Instant::now(),
            Err(e) if is_wait(&e) => {
                if last.elapsed() >= ceiling {
                    return false;
                }
            }
            Err(_) => return false,
        }
    }
    true
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    const REAL: &str = "gho_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789";

    /// Register `real` without an injector, for header tests.
    fn register(real: &str) -> String {
        let p = placeholder_for(real).unwrap();
        TOKENS
            .lock()
            .unwrap()
            .push((p.clone(), SecretToken::new(real.to_string())));
        p
    }

    #[test]
    fn placeholder_keeps_prefix_length_and_separators() {
        let p = placeholder_for(REAL).unwrap();
        assert!(p.starts_with("gho_"));
        assert_eq!(p.len(), REAL.len());
        assert_ne!(p, REAL);

        let pat = "github_pat_11ABCDEFG0123456789abc_ZyXwVuTsRqPoNmLkJiHgFeDcBa9876543210";
        let p = placeholder_for(pat).unwrap();
        assert!(p.starts_with("github_pat_") && !p.starts_with("github_pat_11ABCDEFG"));
        assert_eq!(p.len(), pat.len());
        assert_eq!(p.find('_'), pat.find('_'));
        assert_eq!(p.rfind('_'), pat.rfind('_'));

        assert_eq!(placeholder_for("not-a-token"), None);
        assert_eq!(placeholder_for("gho_"), None);
        assert_eq!(placeholder_for("gho_abc def"), None);
    }

    #[test]
    fn swaps_bearer_token_and_basic() {
        let p = register("ghu_SwapTest0123456789abcdefghijklmnopqr");
        let real = "ghu_SwapTest0123456789abcdefghijklmnopqr";
        assert_eq!(
            swap_authorization(&format!(" Bearer {p}")).as_deref(),
            Some(format!("Bearer {real}").as_str())
        );
        assert_eq!(
            swap_authorization(&format!("bearer {p}")).as_deref(),
            Some(format!("bearer {real}").as_str())
        );
        assert_eq!(
            swap_authorization(&format!("token {p}")).as_deref(),
            Some(format!("token {real}").as_str())
        );
        let basic = B64.encode(format!("x-access-token:{p}"));
        let swapped = swap_authorization(&format!("Basic {basic}")).unwrap();
        let decoded = B64.decode(swapped.strip_prefix("Basic ").unwrap()).unwrap();
        assert_eq!(decoded, format!("x-access-token:{real}").into_bytes());

        // Unknown values, the placeholder as a Basic user, other schemes.
        assert_eq!(swap_authorization("Bearer gho_unknown"), None);
        let user = B64.encode(format!("{p}:x"));
        assert_eq!(swap_authorization(&format!("Basic {user}")), None);
        assert_eq!(swap_authorization(&format!("Digest {p}")), None);
        assert_eq!(swap_authorization("Basic !!!"), None);
    }

    #[test]
    fn mcp_paths_and_trace_never_get_the_token() {
        let h = "api.githubcopilot.com";
        assert!(may_inject(h, "POST", "/responses"));
        assert!(may_inject(h, "GET", "/models"));
        for t in [
            "/mcp",
            "/mcp/readonly",
            "/MCP/",
            "//mcp",
            "/%6dcp",
            "/./mcp",
            "https://api.githubcopilot.com/mcp/x",
            "HTTPS://api.githubcopilot.com/mcp",
            "/mcp?next=https://x/responses",
            "/mcp#https://x/responses",
        ] {
            assert!(!may_inject(h, "POST", t), "{t}");
        }
        assert!(!may_inject(
            "api.business.githubcopilot.com",
            "GET",
            "/mcp/readonly"
        ));
        // github.com has no MCP endpoint; the rule is per host.
        assert!(may_inject("api.github.com", "GET", "/mcp"));
        assert!(!may_inject("api.github.com", "TRACE", "/user"));
    }

    #[test]
    fn rewrite_swaps_only_where_allowed_and_closes() {
        let real = "ghs_RewriteTest0123456789abcdefghijklmn";
        let p = register(real);
        let head = format!(
            "GET /user HTTP/1.1\r\nHost: api.github.com\r\nAuthorization: token {p}\r\nConnection: keep-alive"
        );
        let out = rewrite_head("api.github.com", &head);
        assert!(out.contains(&format!("Authorization: token {real}\r\n")));
        assert!(out.ends_with("Connection: close\r\n\r\n"));
        assert!(!out.contains("keep-alive"));

        let mcp = format!("POST /mcp HTTP/1.1\r\nAuthorization: Bearer {p}");
        let out = rewrite_head("api.githubcopilot.com", &mcp);
        assert!(!out.contains(real) && out.contains(&p));

        let ws = format!(
            "GET /responses HTTP/1.1\r\nAuthorization: Bearer {p}\r\nConnection: Upgrade\r\nUpgrade: websocket"
        );
        let out = rewrite_head("api.business.githubcopilot.com", &ws);
        assert!(out.contains(real) && out.contains("Connection: Upgrade"));
        assert!(!out.contains("Connection: close"));
    }

    #[test]
    fn child_env_gets_placeholders_everywhere() {
        let real = "gho_ChildEnv0123456789abcdefghijklmnopqr";
        #[allow(clippy::disallowed_methods)] // never spawned; only its env is read
        let mut cmd = Command::new("true");
        cmd.env("GH_TOKEN", real);
        cmd.env("OPENCODE_AUTH_CONTENT", format!(r#"{{"t":"{real}"}}"#));
        cmd.env("COPILOT_GITHUB_TOKEN", "not-a-github-token");
        // Inherit mode reads the process env, which other tests set through
        // temp_env: hold its lock.
        crate::with_env_lock_no_xdg(|| mask_child_env(&mut cmd, true));
        let env: HashMap<String, String> = cmd
            .get_envs()
            .filter_map(|(k, v)| Some((k.to_str()?.to_string(), v?.to_str()?.to_string())))
            .collect();
        let p = &env["GH_TOKEN"];
        assert!(p.starts_with("gho_") && p.len() == real.len() && p != real);
        assert_eq!(env["OPENCODE_AUTH_CONTENT"], format!(r#"{{"t":"{p}"}}"#));
        assert_eq!(env["COPILOT_GITHUB_TOKEN"], "not-a-github-token");
        assert_eq!(real_for(p).unwrap().expose(), real);
    }

    /// Clear mode (the default launch): a token only the parent holds must
    /// not be added to the child, masked or not.
    #[test]
    fn clear_mode_never_adds_parent_vars() {
        let real = "gho_ParentOnly0123456789abcdefghijklmnop";
        temp_env::with_vars(
            [
                ("GH_TOKEN", Some(real)),
                ("OPENCODE_AUTH_CONTENT", Some(real)),
            ],
            || {
                #[allow(clippy::disallowed_methods)] // never spawned; only its env is read
                let mut cmd = Command::new("true");
                cmd.env_clear();
                cmd.env("KEEP", "1");
                mask_child_env(&mut cmd, false);
                let names: Vec<_> = cmd.get_envs().map(|(k, _)| k.to_owned()).collect();
                assert_eq!(names, vec![std::ffi::OsString::from("KEEP")]);
            },
        );
    }

    #[test]
    fn explicit_auth_content_token_is_masked() {
        let real = "ghu_AuthContent0123456789abcdefghijklmn";
        #[allow(clippy::disallowed_methods)] // never spawned; only its env is read
        let mut cmd = Command::new("true");
        cmd.env_clear();
        let json = format!(r#"{{"github-copilot":{{"refresh":"{real}","x":"gho_"}}}}"#);
        cmd.env("OPENCODE_AUTH_CONTENT", &json);
        mask_child_env(&mut cmd, false);
        let got = cmd
            .get_envs()
            .find_map(|(_, v)| v.map(|v| v.to_string_lossy().into_owned()))
            .unwrap();
        assert!(!got.contains(real) && got.contains("\"x\":\"gho_\""));
        assert_eq!(got.len(), json.len());
        assert_eq!(
            embedded_tokens("xgho_abc gho_def_1 ëgho_g"),
            vec!["gho_def_1", "gho_g"] // and no panic on non-ASCII
        );
    }

    #[test]
    fn unloadable_user_ca_falls_back() {
        let dir = tempfile::tempdir().unwrap();
        let not_pem = dir.path().join("corp.pem");
        std::fs::write(&not_pem, "not a certificate").unwrap();
        // Other CA vars may be set by CI or a parallel test; pin them unset.
        let vars = [
            ("SSL_CERT_FILE", None),
            ("GIT_SSL_CAINFO", None),
            ("NODE_EXTRA_CA_CERTS", Some(not_pem.as_os_str())),
        ];
        temp_env::with_vars(vars, || {
            let err = setup(dir.path()).unwrap_err();
            assert!(err.contains("NODE_EXTRA_CA_CERTS"), "{err}");
        });
    }

    #[test]
    fn denied_ca_var_blocks_injection() {
        assert_eq!(denied_ca_var(&["FOO".into()]), None);
        let name = CA_VARS[1].to_string();
        assert_eq!(denied_ca_var(&[name]), Some(CA_VARS[1]));
    }

    #[test]
    fn bundles_carry_certificates_only() {
        let (_, _, cert) = new_ca().unwrap();
        let key = rcgen::KeyPair::generate().unwrap().serialize_pem();
        let out = certs_only(&format!("{key}{cert}"));
        assert_eq!(out.trim(), cert.trim().replace("\r\n", "\n"));
        assert!(!out.contains("PRIVATE KEY"));
        assert_eq!(certs_only(&key), "");
    }

    #[test]
    fn malformed_request_lines_get_no_token() {
        let real = "ghs_RequestLine0123456789abcdefghijklmn";
        let p = register(real);
        for line in [
            "POST\t/mcp HTTP/1.1",
            "POST  /mcp HTTP/1.1",
            "GET /user",
            "GET /user HTTP/1.1 extra",
        ] {
            let out = rewrite_head(
                "api.githubcopilot.com",
                &format!("{line}\r\nAuthorization: Bearer {p}"),
            );
            assert!(!out.contains(real), "{line}");
        }
        // Extra whitespace alone does not block a legitimate request.
        let out = rewrite_head(
            "api.github.com",
            &format!("GET  /user HTTP/1.1\r\nAuthorization: Bearer {p}"),
        );
        assert!(out.contains(real));
    }

    #[test]
    fn intercepts_only_github_hosts_on_443() {
        assert!(intercepts("api.github.com", 443));
        assert!(intercepts("github.com", 443));
        assert!(intercepts("api.individual.githubcopilot.com", 443));
        assert!(!intercepts("githubcopilot.com", 443));
        assert!(!intercepts("api.github.com", 80));
        assert!(!intercepts("evilgithub.com", 443));
        assert!(!intercepts("objects.githubusercontent.com", 443));
        assert!(!intercepts("x.githubcopilot.com.evil.net", 443));
    }

    #[test]
    fn bundles_concatenate_user_cas() {
        let dir = tempfile::tempdir().unwrap();
        let (_, _, sys) = new_ca().unwrap();
        let (_, _, corp) = new_ca().unwrap();
        let inj = build(&sys, &corp, dir.path()).unwrap();
        let full = std::fs::read_to_string(&inj.full_bundle).unwrap();
        let node = std::fs::read_to_string(&inj.node_bundle).unwrap();
        assert_eq!(full.matches("BEGIN CERTIFICATE").count(), 3);
        assert!(full.starts_with(&sys) && full.contains(&corp));
        assert_eq!(node.matches("BEGIN CERTIFICATE").count(), 2);
        assert!(node.starts_with(&corp) && !node.contains(&sys));
        // A second session in the same dir must not reuse the files.
        assert!(build(&sys, &corp, dir.path()).is_err());
    }

    /// End to end through a local TLS origin: the client trusts only the
    /// session CA and sends the placeholder; the origin sees the real token.
    #[test]
    fn tunnel_swaps_the_token_through_tls() {
        use std::net::TcpListener;
        const BIG: usize = 16 * 1024 * 1024;
        let real = "gho_Tunnel0123456789abcdefghijklmnopqrstu";
        let p = register(real);

        // Origin: a cert for api.github.com from its own CA.
        let (origin_ca, origin_ca_der, origin_ca_pem) = new_ca().unwrap();
        let okey = rcgen::KeyPair::generate().unwrap();
        let mut op = rcgen::CertificateParams::new(vec!["api.github.com".into()]).unwrap();
        validity(&mut op);
        let ocert = op.signed_by(&okey, &origin_ca).unwrap();
        let ocfg = Arc::new(
            ServerConfig::builder_with_provider(provider())
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_no_client_auth()
                .with_single_cert(
                    vec![ocert.der().clone(), origin_ca_der],
                    PrivateKeyDer::Pkcs8(okey.serialize_der().into()),
                )
                .unwrap(),
        );
        let origin = TcpListener::bind("127.0.0.1:0").unwrap();
        let oaddr = origin.local_addr().unwrap();
        let seen = std::thread::spawn(move || {
            let (s, _) = origin.accept().unwrap();
            let mut tls = rustls::StreamOwned::new(ServerConnection::new(ocfg).unwrap(), s);
            let (head, _) = read_head(&mut tls, Duration::from_secs(10)).unwrap();
            // A large body: the tunnel must not throttle (git clone).
            tls.write_all(
                format!("HTTP/1.1 200 OK\r\nContent-Length: {BIG}\r\nConnection: close\r\n\r\n")
                    .as_bytes(),
            )
            .unwrap();
            tls.write_all(&vec![b'x'; BIG - 2]).unwrap();
            tls.write_all(b"ok").unwrap();
            tls.conn.send_close_notify();
            let _ = tls.flush();
            head
        });

        let dir = tempfile::tempdir().unwrap();
        let inj = build(&origin_ca_pem, "", dir.path()).unwrap();
        let session_ca = std::fs::read(&inj.node_bundle).unwrap();

        // The proxy side: a socket pair standing in for the CONNECT client.
        let front = TcpListener::bind("127.0.0.1:0").unwrap();
        let faddr = front.local_addr().unwrap();
        let proxy = std::thread::spawn(move || {
            let (client, _) = front.accept().unwrap();
            let remote = TcpStream::connect(oaddr).unwrap();
            serve_inner(
                &inj,
                client,
                remote,
                "api.github.com",
                Duration::from_secs(10),
            )
            .unwrap();
        });

        let mut roots = RootCertStore::empty();
        for der in CertificateDer::pem_slice_iter(&session_ca).flatten() {
            roots.add(der).unwrap();
        }
        let ccfg = ClientConfig::builder_with_provider(provider())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let conn = ClientConnection::new(
            Arc::new(ccfg),
            ServerName::try_from("api.github.com").unwrap(),
        )
        .unwrap();
        let mut c = rustls::StreamOwned::new(conn, TcpStream::connect(faddr).unwrap());
        c.write_all(
            format!(
                "GET /user HTTP/1.1\r\nHost: api.github.com\r\nAuthorization: Bearer {p}\r\n\r\n"
            )
            .as_bytes(),
        )
        .unwrap();
        let started = Instant::now();
        let mut resp = Vec::new();
        let _ = c.read_to_end(&mut resp);
        assert!(resp.len() > BIG && resp.ends_with(b"ok"));
        // The old 10 ms poll managed about 1.5 MB/s: 16 MiB took over 10 s.
        // The bound is loose so a loaded runner passes; that regression
        // would still take minutes at git-clone sizes and shows up here.
        assert!(
            started.elapsed() < Duration::from_secs(60),
            "{:?}",
            started.elapsed()
        );

        let head = seen.join().unwrap();
        assert!(head.contains(&format!("Authorization: Bearer {real}")));
        assert!(!head.contains(&p));
        proxy.join().unwrap();
    }
}
