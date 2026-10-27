//! The child's own CONNECT proxy, allowing only its `egressHosts`.

use std::io::{Error, ErrorKind, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

use super::runtime::Log;

/// The egress decision for a CONNECT target: port 443 only, host equal to
/// or a subdomain of an `egressHosts` entry (the proxy's own matching rule).
/// Returns the host to dial.
pub fn egress_allowed(target: &str, hosts: &[String]) -> Result<String, String> {
    let (host, port) = target.rsplit_once(':').ok_or("no port")?;
    if port != "443" {
        return Err(format!("port {port}"));
    }
    let host = crate::proxy::normalize_hostname(host);
    if host.is_empty()
        || !host
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
    {
        return Err("not a hostname".into());
    }
    // An allowed parent never lets a blocked child through.
    if crate::proxy::is_blocked_in_list(&host, &crate::proxy::builtin_blocklist()) {
        return Err(format!("{host} is on cplt's blocked-domains list"));
    }
    if crate::proxy::is_domain_match(&host, hosts) {
        Ok(host)
    } else {
        Err(format!("{host} is not in egressHosts"))
    }
}

/// Head deadline, upstream connect timeout and relay poll interval.
const EGRESS_TIMEOUT: Duration = Duration::from_secs(10);

/// One child connection to its egress proxy: a CONNECT head (read with the
/// proxy's own reader, which leaves a pipelined ClientHello in the socket),
/// the policy check, then the proxy's relay. A refusal gets 403, a failed
/// dial 502 (504 on a timeout).
/// Addresses the proxy calls private (loopback, LAN, CGNAT, reserved) are
/// never dialled, so an allowed name cannot steer the child inward.
pub(crate) fn egress_tunnel(client: TcpStream, hosts: &[String], log: &Log, id: &str) {
    egress_tunnel_via(client, hosts, log, id, dial_public);
}

/// Resolve `host` and connect to its first reachable public address.
/// A host with no public address is refused (`PermissionDenied`); any other
/// error is a failed dial, of the kind of the last attempt.
fn dial_public(host: &str) -> Result<TcpStream, Error> {
    let addrs: Vec<_> = (host, 443)
        .to_socket_addrs()
        .map_err(|e| Error::new(e.kind(), format!("{host}: {e}")))?
        .filter(|a| !crate::proxy::is_private_ip(&a.ip()))
        .collect();
    let mut last = Error::new(ErrorKind::PermissionDenied, "no public address");
    for a in &addrs {
        match TcpStream::connect_timeout(a, EGRESS_TIMEOUT) {
            Ok(s) => return Ok(s),
            Err(e) => last = Error::new(e.kind(), format!("{a}: {e}")),
        }
    }
    Err(Error::new(last.kind(), format!("{host} ({last})")))
}

/// [`egress_tunnel`] with the upstream dial injected, so a test can reach an
/// allowed host without the network.
fn egress_tunnel_via(
    mut client: TcpStream,
    hosts: &[String],
    log: &Log,
    id: &str,
    dial: impl FnOnce(&str) -> Result<TcpStream, Error>,
) {
    let _ = client.set_nonblocking(false);
    let _ = client.set_read_timeout(Some(EGRESS_TIMEOUT));
    let Ok(head) = crate::proxy::read_request_head(&mut client, EGRESS_TIMEOUT) else {
        return;
    };
    let head = String::from_utf8_lossy(&head);
    let mut parts = head.lines().next().unwrap_or("").split(' ');
    let decision = match (parts.next(), parts.next()) {
        (Some("CONNECT"), Some(target)) => egress_allowed(target, hosts),
        _ => Err("only CONNECT is proxied".into()),
    };
    let deny = |mut client: TcpStream, why: String| {
        log.line(id, &format!("egress → DENIED {why}"));
        let _ = client.write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n");
    };
    let host = match decision {
        Ok(h) => h,
        Err(why) => return deny(client, why),
    };
    let upstream = match dial(&host) {
        Ok(u) => u,
        Err(e) if e.kind() == ErrorKind::PermissionDenied => {
            return deny(client, format!("{e}"));
        }
        Err(e) => {
            // A network failure, not a policy refusal (#858).
            log.line(id, &format!("egress → connect failed {e}"));
            let status = if e.kind() == ErrorKind::TimedOut {
                "504 Gateway Timeout"
            } else {
                "502 Bad Gateway"
            };
            let _ = write!(client, "HTTP/1.1 {status}\r\nContent-Length: 0\r\n\r\n");
            return;
        }
    };
    if client
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .is_err()
    {
        return;
    }
    crate::proxy::relay(client, upstream, EGRESS_TIMEOUT);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn egress_policy() {
        let hosts = vec!["console.nav.cloud.nais.io".to_string()];
        assert!(egress_allowed("console.nav.cloud.nais.io:443", &hosts).is_ok());
        assert!(egress_allowed("x.console.nav.cloud.nais.io:443", &hosts).is_ok());
        // Each refusal pinned to its reason: a bare `is_err` passes for any.
        assert_eq!(
            egress_allowed("console.nav.cloud.nais.io:80", &hosts),
            Err("port 80".into())
        );
        assert_eq!(
            egress_allowed("evilconsole.nav.cloud.nais.io:443", &hosts),
            Err("evilconsole.nav.cloud.nais.io is not in egressHosts".into())
        );
        assert_eq!(
            egress_allowed("ex ample.com:443", &hosts),
            Err("not a hostname".into())
        );
        // An allowed parent never lets a blocked child through.
        let parent = vec!["mozilla.org".to_string()];
        assert!(egress_allowed("www.mozilla.org:443", &parent).is_ok());
        assert_eq!(
            egress_allowed("paste.mozilla.org:443", &parent),
            Err("paste.mozilla.org is on cplt's blocked-domains list".into())
        );
    }

    /// One CONNECT for `target` through [`egress_tunnel_via`]: the response
    /// line, the client end positioned after the response head, and what the
    /// proxy logged.
    fn connect(
        target: &str,
        hosts: &[String],
        dial: impl FnOnce(&str) -> Result<TcpStream, Error> + Send + 'static,
    ) -> (String, TcpStream, String) {
        use std::io::{BufRead, BufReader};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let mut client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (server, _) = listener.accept().unwrap();
        let hosts = hosts.to_vec();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("log");
        let file = Some(path.clone());
        std::thread::spawn(move || {
            let log = Log {
                level: crate::proxy::ProxyLogLevel::None,
                file,
            };
            egress_tunnel_via(server, &hosts, &log, "t", dial);
        });
        write!(
            client,
            "CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n"
        )
        .unwrap();
        client.set_read_timeout(Some(EGRESS_TIMEOUT)).unwrap();
        let mut r = BufReader::new(client.try_clone().unwrap());
        let mut line = String::new();
        r.read_line(&mut line).unwrap();
        let mut blank = String::new();
        r.read_line(&mut blank).unwrap();
        // The proxy logs before it answers.
        let log = std::fs::read_to_string(&path).unwrap_or_default();
        (line.trim_end().to_string(), client, log)
    }

    /// Inside a cplt session localhost TCP is denied, as in the proxy tests.
    fn localhost_tcp_blocked() -> bool {
        let blocked = std::env::var("__CPLT_WRAPPED").is_ok();
        if blocked {
            eprintln!("SKIPPED: egress tests require localhost TCP (blocked inside cplt sandbox)");
        }
        blocked
    }

    #[test]
    fn an_allowed_connect_gets_200_and_relays() {
        if localhost_tcp_blocked() {
            return;
        }
        use std::io::Read;
        let upstream = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = upstream.local_addr().unwrap();
        let echo = std::thread::spawn(move || {
            let (mut s, _) = upstream.accept().unwrap();
            let mut buf = [0u8; 5];
            s.read_exact(&mut buf).unwrap();
            s.write_all(&buf).unwrap();
        });
        let hosts = vec!["example.org".to_string()];
        let (line, mut client, _) = connect("api.example.org:443", &hosts, move |host| {
            assert_eq!(host, "api.example.org");
            TcpStream::connect(addr)
        });
        assert_eq!(line, "HTTP/1.1 200 Connection Established");
        client.write_all(b"hello").unwrap();
        let mut back = [0u8; 5];
        client.read_exact(&mut back).unwrap();
        assert_eq!(&back, b"hello");
        echo.join().unwrap();
    }

    #[test]
    fn an_allowed_host_on_a_private_address_is_not_dialled() {
        if localhost_tcp_blocked() {
            return;
        }
        // `localhost` passes the name check and resolves only to loopback,
        // which the real dial drops before connecting.
        assert_eq!(
            dial_public("localhost").unwrap_err().to_string(),
            "localhost (no public address)"
        );
        let hosts = vec!["localhost".to_string()];
        let (line, _, _) = connect("localhost:443", &hosts, dial_public);
        assert_eq!(line, "HTTP/1.1 403 Forbidden");
    }

    #[test]
    fn a_failed_dial_is_a_gateway_error_not_a_denial() {
        if localhost_tcp_blocked() {
            return;
        }
        let hosts = vec!["example.org".to_string()];
        // A refused port: bind, note the address, close.
        let addr = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap();
        let (line, _, log) = connect("example.org:443", &hosts, move |_| TcpStream::connect(addr));
        assert_eq!(line, "HTTP/1.1 502 Bad Gateway");
        assert!(
            log.contains("connect failed") && !log.contains("DENIED"),
            "{log}"
        );
        let (line, _, log) = connect("example.org:443", &hosts, |_| {
            Err(Error::new(ErrorKind::TimedOut, "timed out"))
        });
        assert_eq!(line, "HTTP/1.1 504 Gateway Timeout");
        assert!(
            log.contains("connect failed timed out") && !log.contains("DENIED"),
            "{log}"
        );
        // A policy refusal never reaches the dial and keeps its 403.
        let (line, _, log) = connect("evil.example.com:443", &hosts, |_| unreachable!());
        assert_eq!(line, "HTTP/1.1 403 Forbidden");
        assert!(
            log.contains("egress → DENIED evil.example.com is not in egressHosts"),
            "{log}"
        );
    }
}
