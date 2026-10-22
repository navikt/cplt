//! GitHub's remote MCP server for OpenCode v2, through a host-side proxy (#797).
//!
//! GitHub's OAuth has no dynamic client registration, so OpenCode cannot log
//! in to `api.githubcopilot.com/mcp` itself, and cplt strips `GH_TOKEN` for
//! it. When the user's own OpenCode config names that server, cplt serves an
//! endpoint at a random secret path on its existing CONNECT proxy port and
//! points the entry at it with `"oauth": false`. No new port is opened: on
//! Linux, Landlock port rules cannot be pinned to loopback, so a new port
//! would be open to every host.
//!
//! The endpoint adds the host's gh token and forwards every request to one
//! fixed upstream, the read-only endpoint, with `X-MCP-Readonly` and
//! `X-MCP-Lockdown` forced on. The token never enters the sandbox through
//! this path; the agent gets a read-only, lockdown view of GitHub.
//!
//! cplt has no TLS stack, so the upstream leg runs through the system `curl`
//! (trusted dirs only), one process per request. The token and the request
//! reach curl on stdin as a config file, never in argv, and `-q` keeps the
//! user's `~/.curlrc` out.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::OnceLock;

use crate::agent::SecretToken;

use serde_json::{Map, Value};

use crate::proxy::ProxyLogLevel;

/// The only place requests go, whatever URL the user's entry names.
pub const UPSTREAM: &str = "https://api.githubcopilot.com/mcp/readonly";
const MAX_BODY: usize = 4 * 1024 * 1024;
const CONFIG_LIMIT: u64 = 1024 * 1024;

/// Does `url` name GitHub's remote MCP server (full or read-only endpoint)?
pub fn is_github_mcp_url(url: &str) -> bool {
    let url = url.trim().to_ascii_lowercase();
    let Some(rest) = url.strip_prefix("https://") else {
        return false;
    };
    let rest = rest.split(['?', '#']).next().unwrap_or_default();
    let rest = rest.trim_end_matches('/');
    let rest = rest.replacen("api.githubcopilot.com:443/", "api.githubcopilot.com/", 1);
    rest == "api.githubcopilot.com/mcp" || rest == "api.githubcopilot.com/mcp/readonly"
}

/// An entry to route: (`true` for v2's `mcp.servers.<name>`, `false` for the
/// legacy `mcp.<name>` that v2 still reads; the name).
pub type Entry = (bool, String);

/// The entries in `config` that point at GitHub's MCP.
pub fn github_servers(config: &Value) -> Vec<Entry> {
    let is_github = |s: &Value| {
        s.get("url")
            .and_then(Value::as_str)
            .is_some_and(is_github_mcp_url)
    };
    let mut out = Vec::new();
    for (v2, map) in [
        (true, config.pointer("/mcp/servers")),
        (false, config.get("mcp")),
    ] {
        for (name, s) in map.and_then(Value::as_object).into_iter().flatten() {
            if is_github(s) {
                out.push((v2, name.clone()));
            }
        }
    }
    out
}

/// The `OPENCODE_CONFIG_CONTENT` value: `existing` with each entry pointed at
/// `proxy_url` and its OAuth off, in the shape it was found in. OpenCode
/// deep-merges this over the files, so the rest of each entry (`enabled`,
/// `timeout`) stays the user's. `None` when `existing` is not a JSON object:
/// cplt will not replace a value it cannot read.
pub fn overlay(existing: Option<&str>, entries: &[Entry], proxy_url: &str) -> Option<String> {
    let mut root = match existing.map(str::trim).filter(|s| !s.is_empty()) {
        None => Map::new(),
        Some(s) => match serde_json::from_str(s).ok()? {
            Value::Object(m) => m,
            _ => return None,
        },
    };
    for (v2, name) in entries {
        let mut parent = object_at(&mut root, "mcp")?;
        if *v2 {
            parent = object_at(parent, "servers")?;
        }
        let entry = object_at(parent, name)?;
        entry.insert("type".into(), "remote".into());
        entry.insert("url".into(), proxy_url.into());
        entry.insert("oauth".into(), false.into());
    }
    Some(Value::Object(root).to_string())
}

fn object_at<'a>(map: &'a mut Map<String, Value>, key: &str) -> Option<&'a mut Map<String, Value>> {
    map.entry(key)
        .or_insert_with(|| Value::Object(Map::new()))
        .as_object_mut()
}

/// The GitHub MCP entries in the config files the user controls: the config
/// dirs (`$XDG_CONFIG_HOME/opencode`, `OPENCODE_CONFIG_DIR`), `OPENCODE_CONFIG`
/// and `OPENCODE_CONFIG_CONTENT`. Project files are agent-writable and never
/// count: an agent must not be able to switch on spending the user's token.
/// `nav-pilot mcp enable --client opencode` writes the user config dir.
pub fn configured_servers(
    dirs: &[PathBuf],
    config_file: Option<&Path>,
    content: Option<&str>,
) -> Vec<Entry> {
    let mut files: Vec<PathBuf> = dirs
        .iter()
        .flat_map(|d| ["config.json", "opencode.json", "opencode.jsonc"].map(|f| d.join(f)))
        .collect();
    files.extend(config_file.map(Path::to_path_buf));
    let mut texts: Vec<String> = files
        .iter()
        .filter_map(|f| {
            crate::untrusted::read_untrusted(f, CONFIG_LIMIT)
                .ok()
                .flatten()
        })
        .collect();
    texts.extend(content.map(str::to_string));
    let mut names: Vec<Entry> = texts
        .iter()
        .filter_map(|t| serde_json::from_str(&crate::agent::strip_jsonc(t)).ok())
        .flat_map(|v: Value| github_servers(&v))
        .collect();
    names.sort();
    names.dedup();
    names
}

/// Where request lines go: the proxy's log level and `--proxy-log` file.
pub struct Log {
    pub level: ProxyLogLevel,
    pub file: Option<PathBuf>,
}

impl Log {
    fn line(&self, method: &str, status: &str) {
        let method = method.escape_debug().to_string();
        let status = status.escape_debug().to_string();
        if self.level.should_log(&status) {
            eprintln!(
                "{}[github-mcp]{} {} {method} {UPSTREAM} → {status}",
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
                "{} {method} {UPSTREAM} {status}",
                crate::proxy::iso_now()
            );
        }
    }
}

/// What the proxy serves at the secret path.
pub struct Endpoint {
    token: SecretToken,
    path: String,
    curl: PathBuf,
    upstream: String,
}

/// ponytail: one endpoint per process, which is one cplt session; a
/// per-proxy field would be needed to serve two.
static ENDPOINT: OnceLock<Endpoint> = OnceLock::new();

/// A fresh secret for the endpoint path.
pub fn new_secret() -> Result<String, String> {
    crate::scratch::generate_session_id()
}

/// Serve the endpoint at `/<secret>` on the running proxy.
pub fn install(token: SecretToken, secret: &str) -> Result<(), String> {
    let curl = crate::git::trusted_binary("curl").ok_or("no curl in the trusted dirs")?;
    install_endpoint(Endpoint {
        token,
        path: format!("/{secret}"),
        curl,
        upstream: UPSTREAM.into(),
    })
}

fn install_endpoint(ep: Endpoint) -> Result<(), String> {
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

/// Client headers that never reach upstream: credentials and MCP mode
/// switches are cplt's to set (`X-MCP-Toolsets` only picks tool groups and
/// passes); the rest are hop-by-hop or curl's job.
fn forwarded(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    n == "x-mcp-toolsets"
        || !(n.starts_with("x-mcp-")
            || n.starts_with("proxy-")
            || matches!(
                n.as_str(),
                "authorization"
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
fn bad_header_byte(s: &str) -> bool {
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

/// The curl config for one request, or `None` for a header with a control
/// byte. Upstream, credential and MCP mode come from cplt alone; the client
/// supplies only the method, its other headers and the body.
fn curl_config(
    upstream: &str,
    method: &str,
    headers: &[(String, String)],
    body: &[u8],
    token: &str,
) -> Option<Vec<u8>> {
    if headers
        .iter()
        .any(|(k, v)| bad_header_byte(k) || bad_header_byte(v))
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
    opt("request", method.as_bytes());
    for (k, v) in headers.iter().filter(|(k, _)| forwarded(k)) {
        opt("header", format!("{k}: {v}").as_bytes());
    }
    opt(
        "header",
        format!("Authorization: Bearer {token}").as_bytes(),
    );
    opt("header", b"X-MCP-Readonly: true");
    opt("header", b"X-MCP-Lockdown: true");
    opt("header", b"Expect:");
    if !body.is_empty() {
        opt("data-raw", body);
    }
    Some(c)
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
    pub(crate) fn serve(&self, mut client: TcpStream, head: &[u8], log: &Log) {
        let head = String::from_utf8_lossy(head);
        let mut lines = head.split('\n').map(|l| l.strip_suffix('\r').unwrap_or(l));
        let method = lines
            .next()
            .and_then(|l| l.split(' ').next())
            .unwrap_or_default()
            .to_string();
        if !matches!(method.as_str(), "GET" | "POST" | "DELETE") {
            reply(&mut client, "405 Method Not Allowed");
            return log.line(&method, "BLOCKED-METHOD");
        }
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
            return log.line(&method, "FAIL chunked request");
        }
        let len = match header("content-length").map(str::parse::<usize>) {
            None => 0,
            Some(Ok(n)) if n <= MAX_BODY => n,
            _ => {
                reply(&mut client, "413 Content Too Large");
                return log.line(&method, "FAIL body length");
            }
        };
        let mut body = vec![0; len];
        if client.read_exact(&mut body).is_err() || body.contains(&0) {
            reply(&mut client, "400 Bad Request");
            return log.line(&method, "FAIL bad body");
        }
        let Some(config) = curl_config(
            &self.upstream,
            &method,
            &headers,
            &body,
            self.token.expose(),
        ) else {
            reply(&mut client, "400 Bad Request");
            return log.line(&method, "FAIL bad header");
        };
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
            "-K",
            "-",
        ]);
        if self.upstream.starts_with("https://") {
            cmd.args(["--proto", "=https"]);
        }
        cmd.env_remove("SSLKEYLOGFILE");
        let Ok(mut child) = cmd
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
        else {
            reply(&mut client, "502 Bad Gateway");
            return log.line(&method, "FAIL curl did not start");
        };
        // Bounded, and drained so curl never blocks on a full pipe.
        let stderr = child.stderr.take().map(|e| {
            std::thread::spawn(move || {
                let mut e = e;
                let mut buf = Vec::new();
                let _ = e.by_ref().take(2048).read_to_end(&mut buf);
                let _ = std::io::copy(&mut e, &mut std::io::sink());
                buf
            })
        });
        let wrote = child
            .stdin
            .take()
            .is_some_and(|mut s| s.write_all(&config).is_ok());
        let status = match child.stdout.take() {
            Some(out) if wrote => relay(out, &mut client),
            _ => None,
        };
        let _ = child.kill();
        let _ = child.wait();
        if let Some(code) = status {
            // A GET answered 405 is the MCP spec's "no standalone SSE stream",
            // which GitHub returns on every session: not an error.
            let expected = method == "GET" && code == "405";
            let verdict = if code.starts_with(['4', '5']) && !expected {
                "FAIL"
            } else {
                "FORWARDED"
            };
            log.line(&method, &format!("{verdict} {code}"));
        } else {
            reply(&mut client, "502 Bad Gateway");
            let err = stderr
                .and_then(|t| t.join().ok())
                .map(|b| String::from_utf8_lossy(&b).replace(self.token.expose(), "<token>"))
                .unwrap_or_default();
            log.line(&method, &format!("FAIL upstream: {}", err.trim()));
        }
    }
}

/// Copy curl's `-i` output to the client: the status line and headers, minus
/// hop-by-hop ones (curl has already de-chunked the body), then the body as it
/// arrives, unbuffered, so SSE streams through. Returns the status code once
/// the head is sent; `None` if curl produced no response.
fn relay(out: impl Read, client: &mut TcpStream) -> Option<String> {
    let mut out = BufReader::new(out);
    let mut status = String::new();
    out.read_line(&mut status).ok()?;
    let code = status.split_whitespace().nth(1)?.to_string();
    let mut head = status.trim_end().to_string() + "\r\n";
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
        if !matches!(
            name.as_str(),
            "transfer-encoding" | "connection" | "keep-alive"
        ) {
            head += l;
            head += "\r\n";
        }
    }
    head += "Connection: close\r\n\r\n";
    if client.write_all(head.as_bytes()).is_ok() {
        // ponytail: a client that hangs up mid-stream is noticed on the next
        // upstream chunk, not at once; the session's exit reaps the rest.
        let _ = std::io::copy(&mut out, client);
    }
    let _ = client.shutdown(std::net::Shutdown::Both);
    Some(code)
}

/// Install a test endpoint with `upstream` (the real one is pinned).
#[cfg(test)]
pub(crate) fn install_for_test(upstream: &str, token: &str, secret: &str) -> Option<()> {
    let curl = crate::git::trusted_binary("curl")?;
    install_endpoint(Endpoint {
        token: SecretToken::new(token.into()),
        path: format!("/{secret}"),
        curl,
        upstream: upstream.into(),
    })
    .ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_detection() {
        for u in [
            "https://api.githubcopilot.com/mcp",
            "https://api.githubcopilot.com/mcp/",
            "https://API.githubcopilot.com/mcp/readonly",
            "https://api.githubcopilot.com:443/mcp/readonly?x=1",
        ] {
            assert!(is_github_mcp_url(u), "{u}");
        }
        for u in [
            "http://api.githubcopilot.com/mcp",
            "https://api.githubcopilot.com/mcp/x",
            "https://evil.example/api.githubcopilot.com/mcp",
            "https://api.githubcopilot.com.evil/mcp",
        ] {
            assert!(!is_github_mcp_url(u), "{u}");
        }
    }

    #[test]
    fn finds_entries_in_user_config_only() {
        let dir = tempfile::tempdir().unwrap();
        let oc = dir.path().join("oc");
        std::fs::create_dir(&oc).unwrap();
        std::fs::write(
            oc.join("opencode.jsonc"),
            r#"{ // c
              "mcp": {"servers": {"gh": {"type": "remote", "url": "https://api.githubcopilot.com/mcp/readonly"},
                                   "other": {"type": "remote", "url": "https://example.com/mcp"},}}}"#,
        )
        .unwrap();
        let file = dir.path().join("custom.json");
        std::fs::write(
            &file,
            r#"{"mcp":{"old":{"type":"remote","url":"https://api.githubcopilot.com/mcp/"}}}"#,
        )
        .unwrap();
        let content = r#"{"mcp":{"servers":{"gh2":{"url":"https://api.githubcopilot.com/mcp"}}}}"#;
        assert_eq!(
            configured_servers(&[oc], Some(&file), Some(content)),
            [
                (false, "old".to_string()),
                (true, "gh".to_string()),
                (true, "gh2".to_string())
            ]
        );
        // Nothing else is read: a project dir is not one of the inputs.
        assert_eq!(configured_servers(&[], None, None), []);
    }

    #[test]
    fn overlay_keeps_the_users_keys() {
        let existing = r#"{"model":"x","mcp":{"servers":{"gh":{"enabled":true,"headers":{"a":"b"}},"o":{"url":"u"}}}}"#;
        let gh = [(true, "gh".to_string())];
        let v: Value =
            serde_json::from_str(&overlay(Some(existing), &gh, "http://p").unwrap()).unwrap();
        assert_eq!(v["model"], "x");
        assert_eq!(v["mcp"]["servers"]["o"]["url"], "u");
        let e = &v["mcp"]["servers"]["gh"];
        assert_eq!(
            (
                e["url"].as_str(),
                e["oauth"].as_bool(),
                e["enabled"].as_bool()
            ),
            (Some("http://p"), Some(false), Some(true))
        );
        let fresh: Value = serde_json::from_str(&overlay(None, &gh, "http://p").unwrap()).unwrap();
        assert_eq!(fresh["mcp"]["servers"]["gh"]["type"], "remote");
        let old: Value =
            serde_json::from_str(&overlay(None, &[(false, "gh".into())], "http://p").unwrap())
                .unwrap();
        assert_eq!(
            (
                old["mcp"]["gh"]["oauth"].as_bool(),
                old["mcp"].get("servers")
            ),
            (Some(false), None)
        );
        assert_eq!(overlay(Some("[1]"), &gh, "http://p"), None);
        assert_eq!(overlay(Some("{\"mcp\":1}"), &gh, "http://p"), None);
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
            curl_config(UPSTREAM, "POST", &headers, b"{\"a\":\n1}", "T").unwrap(),
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
                curl_config(UPSTREAM, "POST", &hdrs(&[(k, v)]), b"", "T"),
                None,
                "{k:?}: {v:?}"
            );
        }
        assert!(curl_config(UPSTREAM, "POST", &hdrs(&[("A", "x\ty")]), b"", "T").is_some());
    }

    #[test]
    fn endpoint_path_must_match_exactly() {
        // Nothing installed in this process yet, or the seam test's endpoint.
        assert!(endpoint_for("/").is_none());
        assert!(endpoint_for("").is_none());
    }
}
