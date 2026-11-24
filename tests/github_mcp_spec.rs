//! #909: a gh-token spec takes effect on OpenCode v2's GitHub MCP. Its own
//! test binary, so the process-wide endpoint slot is fresh.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::time::Duration;

use cplt::agent::SecretToken;
use cplt::mcp_broker::{self, Detected, META_KEY};
use cplt::proxy::{ProxyLogLevel, ProxyOptions, UpstreamProxy};

const ID: &str = "io.github.nais/nais-mcp";

fn write_spec(home: &Path) {
    let dir = mcp_broker::spec_dir(home);
    std::fs::create_dir_all(&dir).unwrap();
    let spec = serde_json::json!({
        "name": ID,
        "version": "7.0.1",
        "_meta": {META_KEY: {
            "v": 1,
            "credential": "gh-token",
            "egressHosts": ["api.githubcopilot.com"],
            "tools": {"allow": ["get_me"], "classes": {}},
        }},
        "remotes": [{"type": "streamable-http", "url": "https://api.githubcopilot.com/mcp/readonly"}],
    });
    std::fs::write(dir.join("io.github.nais__nais-mcp.json"), spec.to_string()).unwrap();
}

fn post(port: u16, path: &str, body: &str) -> String {
    let mut c = TcpStream::connect(("127.0.0.1", port)).unwrap();
    c.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
    write!(
        c,
        "POST {path} HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nAccept: application/json, text/event-stream\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    )
    .unwrap();
    let mut out = String::new();
    let _ = c.read_to_string(&mut out);
    out
}

#[test]
fn gh_token_spec_filters_opencode_github_mcp() {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path().join("home");
    let config = home.join(".config");
    std::fs::create_dir_all(config.join("opencode")).unwrap();
    std::fs::write(
        config.join("opencode/opencode.json"),
        r#"{"mcp":{"gh":{"type":"remote","url":"https://api.githubcopilot.com/mcp/readonly"}}}"#,
    )
    .unwrap();
    // SAFETY: the only test in this binary; set before any thread starts.
    unsafe {
        std::env::set_var("CPLT_MCP_REMOTE", "1");
        std::env::set_var("XDG_CONFIG_HOME", &config);
        std::env::set_var("XDG_STATE_HOME", home.join(".local/state"));
        std::env::set_var("XDG_DATA_HOME", home.join(".local/share"));
        std::env::set_var("XDG_CACHE_HOME", home.join(".cache"));
        std::env::remove_var("OPENCODE_CONFIG_DIR");
    }
    write_spec(&home);
    let none = |_: &Path| None;

    // A spec that cannot serve falls back to the built-in endpoint with a
    // warning naming the spec, the reason and the unapplied restrictions
    // (#1115).
    let fallback = |e: String, why: &str| {
        assert!(e.starts_with(mcp_broker::FALLBACK_PREFIX), "{e}");
        assert!(e.contains("NOT applied") && e.contains(why), "{e}");
    };
    let off = mcp_broker::load(&mcp_broker::spec_dir(&home), &[], &[ID.into()]);
    fallback(
        mcp_broker::github_spec(&off, Path::new("/nohome"), none).unwrap_err(),
        "--no-mcp-broker",
    );
    let mut found = mcp_broker::load(&mcp_broker::spec_dir(&home), &[], &[]);
    assert_eq!(found.remotes.len(), 1, "{:?}", found.rejected);
    let mut toggled = Detected {
        remotes: found.remotes.clone(),
        ..Default::default()
    };
    toggled.disable_remotes();
    fallback(
        mcp_broker::github_spec(&toggled, Path::new("/nohome"), none).unwrap_err(),
        "proxy is off",
    );
    // A spec the final policy can write is refused: fallback.
    fallback(
        mcp_broker::github_spec(&found, Path::new("/nohome"), |_| Some(home.clone())).unwrap_err(),
        "writable",
    );
    // Two specs are ambiguous.
    found.remotes.push(found.remotes[0].clone());
    fallback(
        mcp_broker::github_spec(&found, Path::new("/nohome"), none).unwrap_err(),
        "ambiguous",
    );
    found.remotes.pop();
    let spec = mcp_broker::github_spec(&found, Path::new("/nohome"), none)
        .unwrap()
        .unwrap();

    // The upstream: a fake upstream proxy, so the pinned https URL stays.
    let up = TcpListener::bind("127.0.0.1:0").unwrap();
    let up_port = up.local_addr().unwrap().port();
    let proxy = cplt::proxy::start(ProxyOptions {
        port: 0,
        blocked_file: None,
        subscription_blocklist: Vec::new(),
        allowed_ports: vec![443],
        allow_localhost_ports: Vec::new(),
        allow_localhost_any: false,
        allowed_domains_file: None,
        allowed_domains_initial: Vec::new(),
        extra_allowed_domains: Vec::new(),
        default_allowlist: Vec::new(),
        cli_private_domains: Vec::new(),
        config_private_domains: Vec::new(),
        repo_private_domains: Vec::new(),
        config_file: None,
        log_file: None,
        log_level: ProxyLogLevel::None,
        timeout: Duration::from_secs(20),
        upstream: Some(UpstreamProxy {
            host: "127.0.0.1".into(),
            port: up_port,
            proxy_authorization: None,
        }),
        upstream_no_proxy: Vec::new(),
    })
    .unwrap();

    let scratch = tmp.path().join("scratch");
    std::fs::create_dir_all(&scratch).unwrap();
    let mut session = cplt::opencode_v2::prepare(&scratch, &home, tmp.path()).unwrap();
    assert!(cplt::opencode_v2::github_mcp(
        &mut session,
        &home,
        &[],
        |_| false,
        Some(proxy.port),
        || Some(SecretToken::new("TOKEN".into())),
        Some(&spec),
    ));
    let content = &session
        .env
        .iter()
        .find(|(k, _)| k == "OPENCODE_CONFIG_CONTENT")
        .unwrap()
        .1;
    let marker = format!("http://127.0.0.1:{}/", proxy.port);
    let at = content.find(&marker).unwrap() + marker.len() - 1;
    let path: String = content[at..].chars().take_while(|c| *c != '"').collect();

    // Denied by the spec's tools.allow: a JSON-RPC error, nothing upstream.
    let reply = post(
        proxy.port,
        &path,
        r#"{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"delete_repo","arguments":{}}}"#,
    );
    let body = reply.split("\r\n\r\n").nth(1).unwrap_or_default();
    let v: serde_json::Value = serde_json::from_str(body).expect("JSON-RPC body");
    assert_eq!(v["id"], 7);
    assert!(
        v["error"].is_object(),
        "denied call did not return a JSON-RPC error"
    );
    up.set_nonblocking(true).unwrap();
    assert!(up.accept().is_err(), "a denied call reached upstream");

    // Allowed: curl tunnels to the pinned upstream through the fake proxy.
    let call = std::thread::spawn(move || {
        post(
            proxy.port,
            &path,
            r#"{"jsonrpc":"2.0","id":8,"method":"tools/call","params":{"name":"get_me","arguments":{}}}"#,
        )
    });
    // Timed waits: a regression fails here instead of hanging CI.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    let s = loop {
        match up.accept() {
            Ok((s, _)) => break s,
            Err(_) if std::time::Instant::now() < deadline => {
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
            Err(e) => panic!("upstream never received the call: {e}"),
        }
    };
    s.set_nonblocking(false).unwrap();
    s.set_read_timeout(Some(std::time::Duration::from_secs(30)))
        .unwrap();
    let mut line = String::new();
    BufReader::new(s).read_line(&mut line).unwrap();
    assert!(
        line.starts_with("CONNECT api.githubcopilot.com:443 "),
        "upstream did not receive the pinned CONNECT"
    );
    let _ = call.join();
}
