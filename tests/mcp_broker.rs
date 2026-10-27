//! MCP host broker end to end (#824, #834), on macOS and on Linux under
//! Bubblewrap.

// Test-binary exemption from the #239 lint, as in `tests/e2e.rs`.
#![allow(clippy::disallowed_methods)]
mod common;

use std::process::Command;

use common::{binary_path, cplt_cmd, fake_agent, home_temp_dir, project_dir, sandbox_usable};

/// MCP host broker (#824), end to end through cplt: a broker spec for a
/// fake stdio server, a fake Copilot that drives `cplt mcp-stdio` from
/// inside the sandbox with the entry cplt added to its args. The server
/// offers two tools; only the allowed one is listed, and calling the other
/// is refused by the broker before it reaches the server.
#[test]
fn e2e_mcp_broker_filters_tools_and_refuses_calls() {
    if !sandbox_usable() {
        return;
    }
    let home = home_temp_dir("mcp-broker");
    let home_path = std::fs::canonicalize(home.path()).unwrap();
    let server = home_path.join("fake_mcp.py");
    std::fs::write(
        &server,
        r#"import sys, json, os, socket, errno
def probe(target):
    host, port = os.environ["HTTPS_PROXY"].rsplit(":", 1)
    s = socket.create_connection((host.split("//")[1], int(port)), timeout=5)
    s.sendall(("CONNECT " + target + " HTTP/1.1\r\nHost: " + target + "\r\n\r\n").encode())
    return s.recv(64).decode().split("\r\n")[0]
def direct():
    # Past the proxy, to an address (#849): Seatbelt refuses with EPERM; in
    # the Linux child's own network namespace there is no route.
    try:
        socket.create_connection(("1.1.1.1", 443), timeout=5).close()
        return "open"
    except PermissionError:
        return "blocked"
    except OSError as e:
        if e.errno == errno.ENETUNREACH and sys.platform.startswith("linux"):
            return "blocked"
        return "error " + str(e.errno)
for line in sys.stdin:
    m = json.loads(line)
    if "id" not in m:
        continue
    meth = m["method"]
    if meth == "initialize":
        r = {"protocolVersion": "2025-11-25", "capabilities": {"tools": {}}, "serverInfo": {"name": "fake", "version": "1"}}
    elif meth == "tools/list":
        r = {"tools": [{"name": "echo", "inputSchema": {}}, {"name": "delete_everything", "inputSchema": {}}]}
    elif meth == "tools/call" and m["params"]["name"] == "probe":
        r = {"content": [{"type": "text", "text": "PROBE:" + probe("example.com:443") + "|" + probe("example.org:80") + "|DIRECT:" + direct()}]}
    elif meth == "tools/call":
        r = {"content": [{"type": "text", "text": "SERVER-RAN:" + m["params"]["name"]}]}
    else:
        r = {}
    print(json.dumps({"jsonrpc": "2.0", "id": m["id"], "result": r}), flush=True)
"#,
    )
    .unwrap();
    let spec_dir = home_path.join(".config/cplt/mcp");
    std::fs::create_dir_all(&spec_dir).unwrap();
    let spec = serde_json::json!({
        "name": "io.example/fake-mcp",
        "version": "1.0.0",
        "_meta": {"io.github.navikt/broker": {
            "v": 1,
            "credential": "none",
            "command": ["python3", server.display().to_string()],
            "egressHosts": ["example.org"],
            "tools": {"allow": ["echo", "probe"]}
        }}
    });
    std::fs::write(spec_dir.join("io.example__fake-mcp.json"), spec.to_string()).unwrap();

    // A real session bus (CI runs this under `dbus-run-session`): reachable
    // here on the host, the control, and hidden from the agent below.
    let session_bus = std::env::var("DBUS_SESSION_BUS_ADDRESS")
        .ok()
        .and_then(|a| {
            a.split([';', ','])
                .find_map(|p| p.strip_prefix("unix:path=").map(str::to_string))
        });
    if let Some(bus) = &session_bus {
        std::os::unix::net::UnixStream::connect(bus).unwrap_or_else(|e| {
            panic!("control: the session bus {bus} is not reachable on the host: {e}")
        });
    }
    if std::env::var("CPLT_TEST_REQUIRE_SESSION_BUS").as_deref() == Ok("1") {
        assert!(
            session_bus.is_some(),
            "no unix:path= session bus in DBUS_SESSION_BUS_ADDRESS"
        );
    }
    let fake = fake_agent("copilot", "");
    let agent = fake.path().join("copilot");
    // The real interpreter, not the /usr/bin/python3 stub: the stub runs
    // xcodebuild, which fails inside the sandbox on CI runners.
    let python = Command::new("/usr/bin/python3")
        .args(["-c", "import sys; print(sys.executable)"])
        .output()
        .expect("python3 on the host");
    let python = String::from_utf8(python.stdout).unwrap().trim().to_string();
    std::fs::write(
        &agent,
        format!(
            r#"#!{python}
import sys, json, os, subprocess, signal
signal.alarm(60)  # a hang bound: fail with what was printed so far
a = sys.argv
cfg = json.loads(a[a.index("--additional-mcp-config") + 1])
name, e = next(iter(cfg["mcpServers"].items()))
print("ENTRY:" + name + ":" + e["command"] + " " + " ".join(e["args"]), flush=True)
env = dict(os.environ, **e["env"])
print("SOCKET:" + e["env"]["CPLT_MCP_SOCKET"], flush=True)
p = subprocess.Popen(["{cplt}"] + e["args"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, env=env, text=True)
msgs = [
    {{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {{"protocolVersion": "2025-11-25", "capabilities": {{}}, "clientInfo": {{"name": "t", "version": "1"}}}}}},
    {{"jsonrpc": "2.0", "id": 2, "method": "tools/list"}},
    {{"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {{"name": "delete_everything", "arguments": {{}}}}}},
    {{"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {{"name": "echo", "arguments": {{}}}}}},
    {{"jsonrpc": "2.0", "id": 5, "method": "tools/call", "params": {{"name": "probe", "arguments": {{}}}}}},
]
for m in msgs:
    p.stdin.write(json.dumps(m) + "\n")
    p.stdin.flush()
    print("RESP:" + p.stdout.readline().strip(), flush=True)
p.stdin.close()
p.wait()
# The spec's egress host must not have joined the agent's allowlist.
import socket
host, port = os.environ["HTTPS_PROXY"].rsplit(":", 1)
s = socket.create_connection((host.split("//")[1], int(port)), timeout=5)
s.sendall(b"CONNECT example.org:443 HTTP/1.1\r\nHost: example.org:443\r\n\r\n")
print("AGENT:" + s.recv(64).decode().split("\r\n")[0])
# What the agent can see of the host's buses (#834), on Linux.
if sys.platform.startswith("linux"):
    def reach(path):
        c = socket.socket(socket.AF_UNIX)
        c.settimeout(2)
        try:
            c.connect(path)
            return True
        except OSError:
            return False
    print("SYSBUS:" + str(reach("/run/dbus/system_bus_socket")), flush=True)
    rt = os.environ.get("XDG_RUNTIME_DIR")
    if rt:
        print("RTBUS:" + str(reach(rt + "/bus")), flush=True)
    print("TMP:" + ",".join(sorted(os.listdir("/tmp"))), flush=True)
    if "{session_bus}":
        print("SESSBUS:" + str(reach("{session_bus}")), flush=True)
"#,
            cplt = binary_path().display(),
            session_bus = session_bus.as_deref().unwrap_or("")
        ),
    )
    .unwrap();
    // A fake session bus in a runtime dir of our own: the broker must hide it.
    let fake_rt = home_path.join("runtime");
    std::fs::create_dir(&fake_rt).unwrap();
    let _bus = std::os::unix::net::UnixListener::bind(fake_rt.join("bus")).unwrap();
    for runtime in [None, Some(fake_rt.clone())] {
        let mut cmd = cplt_cmd();
        match &runtime {
            // No runtime dir, as on WSL2 without systemd.
            None => cmd.env_remove("XDG_RUNTIME_DIR"),
            Some(dir) => cmd.env("XDG_RUNTIME_DIR", dir),
        };
        let out = cmd
            .args([
                "--yes",
                "--no-validate",
                "--default-allowlist",
                "--agent",
                "copilot",
            ])
            .env("HOME", &home_path)
            .env_remove("XDG_CONFIG_HOME")
            .env(
                "PATH",
                format!("{}:/usr/bin:/bin:/usr/sbin:/sbin", fake.path().display()),
            )
            .current_dir(project_dir())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .expect("binary should run");
        // A hang bound: kill cplt and fail with what it printed.
        let pid = out.id();
        let (tx, rx) = std::sync::mpsc::channel::<()>();
        std::thread::spawn(move || {
            if rx.recv_timeout(std::time::Duration::from_secs(90)).is_err() {
                let _ = Command::new("kill").args(["-9", &pid.to_string()]).status();
            }
        });
        let out = out.wait_with_output().unwrap();
        drop(tx);
        let stdout = String::from_utf8_lossy(&out.stdout);
        let stderr = String::from_utf8_lossy(&out.stderr);
        let resp: Vec<serde_json::Value> = stdout
            .lines()
            .filter_map(|l| l.strip_prefix("RESP:"))
            .map(|l| serde_json::from_str(l).expect("a JSON-RPC line"))
            .collect();
        assert_eq!(resp.len(), 5, "stdout: {stdout}\nstderr: {stderr}");
        assert!(
            stdout.contains("ENTRY:io.example/fake-mcp:cplt mcp-stdio io.example/fake-mcp"),
            "{stdout}"
        );
        if cfg!(target_os = "linux") {
            assert!(
                stdout.contains("SOCKET:/tmp/cplt-mcp-"),
                "the socket must sit under the private /tmp: {stdout}"
            );
        }
        assert_eq!(resp[0]["result"]["serverInfo"]["name"], "fake");
        let tools: Vec<&str> = resp[1]["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t["name"].as_str().unwrap())
            .collect();
        assert_eq!(tools, ["echo"], "{stdout}");
        assert_eq!(resp[2]["error"]["code"], -32001, "{stdout}");
        assert!(resp[2].get("result").is_none(), "{stdout}");
        assert_eq!(
            resp[3]["result"]["content"][0]["text"], "SERVER-RAN:echo",
            "{stdout}"
        );
        assert!(!stdout.contains("SERVER-RAN:delete_everything"), "{stdout}");
        assert!(
            stderr.contains("DENIED"),
            "the refusal is mirrored: {stderr}"
        );
        if cfg!(target_os = "linux") {
            assert!(
                stdout.contains("SYSBUS:False"),
                "system bus reachable: {stdout}"
            );
            if session_bus.is_some() {
                assert!(
                    stdout.contains("SESSBUS:False"),
                    "the real session bus is reachable from the sandbox: {stdout}"
                );
            }
            if runtime.is_some() {
                assert!(
                    stdout.contains("RTBUS:False"),
                    "session bus reachable: {stdout}"
                );
            }
            let tmp = stdout
                .lines()
                .find_map(|l| l.strip_prefix("TMP:"))
                .unwrap_or("missing");
            assert!(
                tmp.split(',').all(|e| e.starts_with("cplt-mcp-")),
                "the private /tmp holds more than the broker socket: {tmp}"
            );
        }
        let probe = resp[4]["result"]["content"][0]["text"].as_str().unwrap();
        let (probe, direct) = probe.split_once("|DIRECT:").unwrap();
        assert_eq!(
            probe, "PROBE:HTTP/1.1 403 Forbidden|HTTP/1.1 403 Forbidden",
            "{stdout}"
        );
        // The child's own sandbox (#849): the 403s above came back through
        // the egress proxy (on Linux over the bound socket and the relay in
        // the child's namespace), and a connect past it fails.
        assert_eq!(direct, "blocked", "{stdout}");
        assert!(stderr.contains("egress → DENIED example.com"), "{stderr}");
        let agent = stdout
            .lines()
            .find_map(|l| l.strip_prefix("AGENT:"))
            .unwrap_or("");
        assert!(
            agent.starts_with("HTTP/1.1 403"),
            "agent reached a spec-only host: {agent}\n{stdout}"
        );
    }
}
