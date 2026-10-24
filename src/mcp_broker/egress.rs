//! The child's own CONNECT proxy, allowing only its `egressHosts`.

use std::io::Write;
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
/// the policy check, then the proxy's relay. Anything else gets 403.
/// Addresses the proxy calls private (loopback, LAN, CGNAT, reserved) are
/// never dialled, so an allowed name cannot steer the child inward.
pub(crate) fn egress_tunnel(mut client: TcpStream, hosts: &[String], log: &Log, id: &str) {
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
    let upstream = decision.and_then(|host| {
        let addrs: Vec<_> = (host.as_str(), 443)
            .to_socket_addrs()
            .map_err(|e| format!("{host}: {e}"))?
            .filter(|a| !crate::proxy::is_private_ip(&a.ip()))
            .collect();
        let mut last = String::from("no public address");
        for a in &addrs {
            match TcpStream::connect_timeout(a, EGRESS_TIMEOUT) {
                Ok(s) => return Ok(s),
                Err(e) => last = format!("{a}: {e}"),
            }
        }
        Err(format!("CONNECT-FAIL {host} ({last})"))
    });
    let upstream = match upstream {
        Ok(u) => u,
        Err(why) => {
            log.line(id, &format!("egress → DENIED {why}"));
            let _ = client.write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n");
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
        assert!(egress_allowed("console.nav.cloud.nais.io:80", &hosts).is_err());
        assert!(egress_allowed("evilconsole.nav.cloud.nais.io:443", &hosts).is_err());
        assert!(egress_allowed("example.com:443", &hosts).is_err());
        let parent = vec!["mozilla.org".to_string()];
        assert!(egress_allowed("www.mozilla.org:443", &parent).is_ok());
        assert!(egress_allowed("paste.mozilla.org:443", &parent).is_err());
        assert!(crate::proxy::is_private_ip(&"127.0.0.1".parse().unwrap()));
        assert!(crate::proxy::is_private_ip(&"10.1.2.3".parse().unwrap()));
        assert!(crate::proxy::is_private_ip(
            &"::ffff:192.168.0.1".parse().unwrap()
        ));
        assert!(!crate::proxy::is_private_ip(&"1.1.1.1".parse().unwrap()));
    }
}
