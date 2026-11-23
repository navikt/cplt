//! Policy on the JSON-RPC stream, one line at a time.

use std::collections::{BTreeSet, HashMap};
use std::time::{Duration, Instant};

use serde_json::{Value, json};

use super::graphql::graphql_read_only;
use super::spec::Spec;
use super::{CLIENT_NOTIFICATIONS, DENIED, MAX_IN_FLIGHT, PROTOCOL_VERSIONS};

/// What to do with one line.
#[derive(Debug, PartialEq)]
pub enum Action {
    /// Pass this (possibly rewritten) line on.
    Forward(String),
    /// Answer the sender with this line instead; log the second part.
    Reply(String, Option<String>),
    /// Swallow it.
    Drop,
}

/// Requests from the client awaiting a server response: id → (the id
/// itself, when it was sent, the tool for a `tools/call`). `done` holds the
/// audit line for the last `tools/call` answered (design 6.4), for the
/// caller to log: tool, outcome and duration, never arguments or results.
/// Keys are (session, id), the session being the remote `Mcp-Session-Id`
/// ("" for stdio), so two clients sharing an endpoint neither collide on
/// ids nor cancel each other's.
#[derive(Default)]
pub struct Pending(
    HashMap<(String, String), (Value, Instant, Option<String>)>,
    pub Option<String>,
);

impl Pending {
    #[cfg(test)]
    pub fn in_flight(&self) -> usize {
        self.0.len()
    }

    /// When the request `id` of `session` was sent, if it is in flight.
    pub fn sent(&self, session: &str, id: &str) -> Option<Instant> {
        self.0
            .get(&(session.to_string(), id.to_string()))
            .map(|e| e.1)
    }

    /// Forget a request that will get no response (its exchange ended),
    /// unless the id has since been reused by a request sent at another time.
    /// Returns its tool, for a `tools/call` still in flight.
    pub fn remove(&mut self, session: &str, id: &str, sent: Instant) -> Option<String> {
        let key = (session.to_string(), id.to_string());
        if self.0.get(&key).is_some_and(|e| e.1 == sent) {
            return self.0.remove(&key).and_then(|e| e.2);
        }
        None
    }

    /// Drop requests older than `deadline` (design 5.6). For each, a timeout
    /// error for the client, a cancel for the server and, for a `tools/call`,
    /// an audit line; a late response is then dropped as unsolicited.
    pub fn evict(&mut self, deadline: Duration) -> Vec<(String, String, Option<String>)> {
        let mut out = Vec::new();
        self.0.retain(|_, (id, sent, tool)| {
            if sent.elapsed() < deadline {
                return true;
            }
            out.push((
                error_line(id, -32603, "cplt: request timed out"),
                json!({"jsonrpc": "2.0", "method": "notifications/cancelled",
                       "params": {"requestId": id, "reason": "cplt: timed out"}})
                .to_string(),
                tool.as_ref()
                    .map(|t| format!("tools/call {t} → TIMEOUT {}ms", sent.elapsed().as_millis())),
            ));
            false
        });
        out
    }
}

/// A client-supplied name as it may appear in a log line: itself when it
/// matches `^[A-Za-z0-9_.-]{1,128}$`, else `<invalid>`, so no agent byte
/// can forge or break a log line.
pub(crate) fn log_name(s: &str) -> &str {
    log_token(s, b"_.-")
}

/// A JSON-RPC method for a log line: as `log_name`, plus `/`.
fn log_method(s: &str) -> &str {
    log_token(s, b"_.-/")
}

fn log_token<'a>(s: &'a str, extra: &[u8]) -> &'a str {
    let ok = (1..=128).contains(&s.len())
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || extra.contains(&b));
    if ok { s } else { "<invalid>" }
}

const MAX_ID_LEN: usize = 256;

pub(crate) fn error_line(id: &Value, code: i64, message: &str) -> String {
    json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message}}).to_string()
}

/// A message from the client, on its way to the server.
pub fn on_client(line: &str, spec: &Spec, session: &str, pending: &mut Pending) -> Action {
    let msg: Value = match serde_json::from_str(line) {
        Ok(v) => v,
        Err(_) => return Action::Reply(error_line(&Value::Null, -32700, "parse error"), None),
    };
    if msg.is_array() {
        return Action::Reply(
            error_line(
                &Value::Null,
                -32600,
                "cplt: JSON-RPC batches are not supported",
            ),
            Some("batch → DENIED".into()),
        );
    }
    let Some(obj) = msg.as_object() else {
        return Action::Reply(error_line(&Value::Null, -32600, "invalid request"), None);
    };
    if let Err(key) = unambiguous(&msg) {
        return Action::Reply(
            error_line(
                obj.get("id").unwrap_or(&Value::Null),
                -32600,
                "cplt: ambiguous field name",
            ),
            Some(format!("→ DENIED ambiguous key {:?}", log_name(&key))),
        );
    }
    let Some(method) = obj.get("method").and_then(Value::as_str) else {
        // A response to a server request; those are not delivered (D13), so
        // there is nothing for it to answer.
        return Action::Drop;
    };
    let Some(id) = obj.get("id") else {
        // Notifications: only the ones a client sends, never a method that
        // policy checks (a server may answer an id-less call anyway).
        // A cancel frees its slot; the late response is then dropped. One
        // for an id not in flight has nothing to cancel.
        if method == "notifications/cancelled" {
            let req = msg.pointer("/params/requestId").map(Value::to_string);
            let key = req.map(|r| (session.to_string(), r));
            let Some((_, sent, tool)) = key.and_then(|k| pending.0.remove(&k)) else {
                return Action::Drop;
            };
            if let Some(tool) = tool {
                pending.1 = Some(format!(
                    "tools/call {tool} → CANCELLED {}ms",
                    sent.elapsed().as_millis()
                ));
            }
        }
        return if CLIENT_NOTIFICATIONS.contains(&method) {
            Action::Forward(msg.to_string())
        } else {
            Action::Drop
        };
    };
    // Only what JSON-RPC allows as an id, and short: it keys `Pending`.
    if !(id.is_number() || id.as_str().is_some_and(|s| s.len() <= MAX_ID_LEN)) {
        return Action::Reply(
            error_line(&Value::Null, -32600, "cplt: invalid request id"),
            Some(format!("{} → DENIED invalid id", log_method(method))),
        );
    }
    let key = (session.to_string(), id.to_string());
    if pending.0.contains_key(&key) {
        return Action::Reply(
            error_line(id, DENIED, "cplt: request id already in flight"),
            Some(format!("{} → DENIED duplicate id", log_method(method))),
        );
    }
    let deny = |why: String, logged: String| {
        Action::Reply(
            error_line(id, DENIED, &format!("cplt: {why}")),
            Some(format!("{} → DENIED {logged}", log_method(method))),
        )
    };
    match method {
        "initialize" => {
            let v = msg
                .pointer("/params/protocolVersion")
                .and_then(Value::as_str);
            if !v.is_some_and(|v| PROTOCOL_VERSIONS.contains(&v)) {
                let why = |v: &str| {
                    format!("MCP protocol {v} is not supported; use one of {PROTOCOL_VERSIONS:?}")
                };
                let v = v.unwrap_or("(none)");
                return deny(why(v), why(log_name(v)));
            }
        }
        "tools/call" => {
            let tool = msg
                .pointer("/params/name")
                .and_then(Value::as_str)
                .unwrap_or("");
            if !spec.allow.contains(tool) {
                let why = |t: &str| {
                    format!(
                        "tool {t:?} is not allowed for {}. Fix: nav-pilot mcp enable {}",
                        spec.id, spec.id
                    )
                };
                return deny(why(tool), why(log_name(tool)));
            }
            if spec.graphql.contains(tool) {
                // A server that folds case would see another key as `query`.
                let shadow = msg
                    .pointer("/params/arguments")
                    .and_then(Value::as_object)
                    .is_some_and(|a| {
                        a.keys()
                            .any(|k| k != "query" && k.eq_ignore_ascii_case("query"))
                    });
                if shadow {
                    let why = |t: &str| format!("{t}: an argument key folds to query");
                    return deny(why(tool), why(log_name(tool)));
                }
                let query = msg
                    .pointer("/params/arguments/query")
                    .and_then(Value::as_str);
                if let Err(e) = query
                    .ok_or("no query argument".to_string())
                    .and_then(graphql_read_only)
                {
                    // The parser's message quotes the query: not logged.
                    return deny(
                        format!("{tool}: {e}"),
                        format!("{}: read-only check failed", log_name(tool)),
                    );
                }
            }
        }
        _ => {}
    }
    if pending.0.len() >= MAX_IN_FLIGHT {
        return Action::Reply(
            error_line(id, DENIED, "cplt: too many requests in flight; retry"),
            Some(format!("{} → DENIED in-flight cap", log_method(method))),
        );
    }
    let tool = (method == "tools/call")
        .then(|| msg.pointer("/params/name").and_then(Value::as_str))
        .flatten()
        .map(|t| log_name(t).to_string());
    pending.0.insert(key, (id.clone(), Instant::now(), tool));
    // Re-serialized: the server parses exactly what was checked, whatever
    // its JSON parser does with duplicate keys or odd escapes.
    Action::Forward(msg.to_string())
}

/// Go's `encoding/json` (nais) matches struct fields case-insensitively,
/// with Unicode folding, so `"Name"` or `"nameſ"`-style keys would be read as
/// a field this broker checked under its exact spelling. In the envelope,
/// `params` and `params.arguments`, refuse two keys that fold together, and
/// any key that folds to a checked field without being spelt exactly so.
pub(crate) fn unambiguous(msg: &Value) -> Result<(), String> {
    const CHECKED: &[&str] = &[
        "jsonrpc",
        "id",
        "method",
        "params",
        "name",
        "arguments",
        "query",
        "protocolVersion",
    ];
    let fold = |k: &str| -> String {
        k.chars()
            .flat_map(char::to_lowercase)
            .map(|c| if c == '\u{17f}' { 's' } else { c })
            .collect()
    };
    let objects = [
        msg.as_object(),
        msg.get("params").and_then(Value::as_object),
        msg.pointer("/params/arguments").and_then(Value::as_object),
    ];
    for m in objects.into_iter().flatten() {
        let mut seen = BTreeSet::new();
        for k in m.keys() {
            let f = fold(k);
            if !seen.insert(f.clone()) || CHECKED.iter().any(|c| fold(c) == f && c != k) {
                return Err(k.clone());
            }
        }
    }
    Ok(())
}

/// A message from the server, on its way to the client.
pub fn on_server(line: &str, spec: &Spec, session: &str, pending: &mut Pending) -> Action {
    let Ok(Value::Object(mut obj)) = serde_json::from_str::<Value>(line) else {
        return Action::Drop;
    };
    if let Some(method) = obj.get("method").and_then(Value::as_str) {
        // Server-initiated: not delivered (D13). A request gets an error so
        // the server does not wait on it.
        return match obj.get("id") {
            Some(id) => Action::Reply(
                error_line(id, -32601, &format!("cplt: {method} is not delivered")),
                None,
            ),
            None => Action::Drop,
        };
    }
    let Some((_, sent, tool)) = obj
        .get("id")
        .and_then(|id| pending.0.remove(&(session.to_string(), id.to_string())))
    else {
        return Action::Drop;
    };
    if let Some(tool) = tool {
        // Only an integer code reaches the log: the value is the server's.
        let outcome = if let Some(e) = obj.get("error") {
            match e.get("code").and_then(Value::as_i64) {
                Some(code) => format!("FAIL {code}"),
                None => "FAIL invalid error code".into(),
            }
        } else if obj.get("result").and_then(|r| r.get("isError")) == Some(&Value::Bool(true)) {
            "FAIL tool error".into()
        } else {
            "ALLOWED".into()
        };
        pending.1 = Some(format!(
            "tools/call {tool} → {outcome} {}ms",
            sent.elapsed().as_millis()
        ));
    }
    // Filtered whatever the request was: an id cannot smuggle a tool list.
    if let Some(Value::Array(tools)) = obj.get_mut("result").and_then(|r| r.get_mut("tools")) {
        tools.retain(|t| {
            t.get("name")
                .and_then(Value::as_str)
                .is_some_and(|n| spec.allow.contains(n))
        });
    }
    Action::Forward(Value::Object(obj).to_string())
}

/// An auth failure in a server response, for mirroring to cplt's output.
/// Only the error fields count: a JSON-RPC `error`, or the text of a tool
/// result flagged `isError`. A successful result that merely mentions
/// "not logged in" (a doc page, a log line) is not one.
pub(crate) fn auth_error(line: &str) -> bool {
    let Ok(msg) = serde_json::from_str::<Value>(line) else {
        return false;
    };
    let mut texts: Vec<String> = Vec::new();
    if let Some(e) = msg.get("error") {
        texts.push(e.to_string());
    }
    if msg.pointer("/result/isError") == Some(&Value::Bool(true)) {
        let content = msg.pointer("/result/content").and_then(Value::as_array);
        texts.extend(
            content
                .into_iter()
                .flatten()
                .filter_map(|c| c.get("text").and_then(Value::as_str))
                .map(str::to_string),
        );
    }
    texts.iter().any(|t| {
        let l = t.to_ascii_lowercase();
        l.contains("unauthenticated") || l.contains("not logged in") || l.contains("please log in")
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mcp_broker::test_util::*;

    use serde_json::{Value, json};

    #[test]
    fn invariant_5_policy_only_from_the_spec() {
        let s = check(base()).unwrap();
        let mut p = Pending::default();
        let call = |t: &str| {
            json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":t,"arguments":{}}})
                .to_string()
        };
        assert!(matches!(
            on_client(&call("delete_app"), &s, "", &mut p),
            Action::Reply(..)
        ));
        assert!(matches!(
            on_client(&call("get_nais_context"), &s, "", &mut p),
            Action::Forward(_)
        ));
        assert!(check(with(base(), "/argChecks", json!({"x": "regex"}))).is_err());
    }

    #[test]
    fn graphql_arg_check_on_tools_call() {
        let s = check(base()).unwrap();
        let mut p = Pending::default();
        let call = |q: Value| {
            json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"execute_graphql","arguments":{"query":q}}}).to_string()
        };
        assert!(matches!(
            on_client(&call(json!("mutation { x }")), &s, "", &mut p),
            Action::Reply(..)
        ));
        assert!(matches!(
            on_client(&call(json!(1)), &s, "", &mut p),
            Action::Reply(..)
        ));
        assert!(matches!(
            on_client(&call(json!("{ me { id } }")), &s, "", &mut p),
            Action::Forward(_)
        ));
    }

    #[test]
    fn batch_and_protocol_rejected() {
        let s = check(base()).unwrap();
        let mut p = Pending::default();
        assert!(matches!(
            on_client(
                r#"[{"jsonrpc":"2.0","id":1,"method":"ping"}]"#,
                &s,
                "",
                &mut p
            ),
            Action::Reply(..)
        ));
        let init = |v: &str| {
            json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":v}})
                .to_string()
        };
        assert!(matches!(
            on_client(&init("2025-03-26"), &s, "", &mut p),
            Action::Reply(..)
        ));
        assert!(matches!(
            on_client(&init("2025-11-25"), &s, "", &mut p),
            Action::Forward(_)
        ));
    }

    #[test]
    fn tools_list_is_filtered_and_unsolicited_dropped() {
        let s = check(base()).unwrap();
        let mut p = Pending::default();
        let list = r#"{"jsonrpc":"2.0","id":"a","method":"tools/list"}"#;
        assert!(matches!(
            on_client(list, &s, "", &mut p),
            Action::Forward(_)
        ));
        let resp = r#"{"jsonrpc":"2.0","id":"a","result":{"tools":[{"name":"get_nais_context"},{"name":"delete_app"}]}}"#;
        let Action::Forward(out) = on_server(resp, &s, "", &mut p) else {
            panic!()
        };
        let v: Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["result"]["tools"], json!([{"name": "get_nais_context"}]));
        // Same id again: no longer pending.
        assert_eq!(on_server(resp, &s, "", &mut p), Action::Drop);
        assert_eq!(
            on_server(
                r#"{"jsonrpc":"2.0","method":"notifications/tools/list_changed"}"#,
                &s,
                "",
                &mut p
            ),
            Action::Drop
        );
        assert!(matches!(
            on_server(
                r#"{"jsonrpc":"2.0","id":9,"method":"roots/list"}"#,
                &s,
                "",
                &mut p
            ),
            Action::Reply(..)
        ));
    }

    #[test]
    fn ids_are_per_session_and_a_cancel_stays_in_its_session() {
        let s = check(base()).unwrap();
        let mut p = Pending::default();
        let list = r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#;
        let cancel =
            r#"{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":1}}"#;
        assert!(matches!(
            on_client(list, &s, "A", &mut p),
            Action::Forward(_)
        ));
        assert!(matches!(
            on_client(list, &s, "B", &mut p),
            Action::Forward(_)
        ));
        assert_eq!(p.in_flight(), 2);
        // B cancels its own id 1, then has nothing left to cancel.
        assert!(matches!(
            on_client(cancel, &s, "B", &mut p),
            Action::Forward(_)
        ));
        assert_eq!(on_client(cancel, &s, "B", &mut p), Action::Drop);
        assert_eq!(p.in_flight(), 1, "B's cancel reached A's request");
        let resp = r#"{"jsonrpc":"2.0","id":1,"result":{"tools":[]}}"#;
        assert!(matches!(
            on_server(resp, &s, "A", &mut p),
            Action::Forward(_)
        ));
        assert_eq!(p.in_flight(), 0);
    }

    #[test]
    fn a_stale_remove_leaves_a_reused_id_alone() {
        let s = check(base()).unwrap();
        let mut p = Pending::default();
        let list = r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#;
        assert!(matches!(
            on_client(list, &s, "", &mut p),
            Action::Forward(_)
        ));
        let a = p.sent("", "1").unwrap();
        // A's response frees id 1; B reuses it at a later instant.
        let resp = r#"{"jsonrpc":"2.0","id":1,"result":{}}"#;
        assert!(matches!(
            on_server(resp, &s, "", &mut p),
            Action::Forward(_)
        ));
        std::thread::sleep(Duration::from_millis(2));
        assert!(matches!(
            on_client(list, &s, "", &mut p),
            Action::Forward(_)
        ));
        assert_ne!(p.sent("", "1"), Some(a));
        // A's exchange ends and frees what it thinks is its id.
        assert_eq!(p.remove("", "1", a), None);
        assert_eq!(p.in_flight(), 1, "A's stale remove freed B's request");
    }

    #[test]
    fn odd_request_ids_are_refused() {
        let s = check(base()).unwrap();
        let mut p = Pending::default();
        let long = format!("\"{}\"", "a".repeat(257));
        for id in ["null", "{}", "[1]", "true", long.as_str()] {
            let msg = format!(r#"{{"jsonrpc":"2.0","id":{id},"method":"tools/list"}}"#);
            assert!(
                matches!(on_client(&msg, &s, "", &mut p), Action::Reply(..)),
                "id {id} accepted"
            );
        }
        assert_eq!(p.in_flight(), 0);
        let ok = format!(
            r#"{{"jsonrpc":"2.0","id":"{}","method":"tools/list"}}"#,
            "a".repeat(256)
        );
        assert!(matches!(on_client(&ok, &s, "", &mut p), Action::Forward(_)));
    }

    #[test]
    fn in_flight_cap() {
        let s = check(base()).unwrap();
        let mut p = Pending::default();
        for i in 0..MAX_IN_FLIGHT {
            let l = json!({"jsonrpc":"2.0","id":i,"method":"ping"}).to_string();
            assert!(matches!(on_client(&l, &s, "", &mut p), Action::Forward(_)));
        }
        assert!(matches!(
            on_client(
                r#"{"jsonrpc":"2.0","id":99,"method":"ping"}"#,
                &s,
                "",
                &mut p
            ),
            Action::Reply(..)
        ));
    }

    #[test]
    fn cancelled_calls_free_their_slots() {
        let s = check(base()).unwrap();
        let mut p = Pending::default();
        let call = |i: usize| {
            json!({"jsonrpc":"2.0","id":i,"method":"tools/call","params":{"name":"get_nais_context","arguments":{}}}).to_string()
        };
        for i in 0..MAX_IN_FLIGHT {
            assert!(matches!(
                on_client(&call(i), &s, "", &mut p),
                Action::Forward(_)
            ));
        }
        assert!(matches!(
            on_client(&call(99), &s, "", &mut p),
            Action::Reply(..)
        ));
        for i in 0..MAX_IN_FLIGHT {
            let c = json!({"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":i}}).to_string();
            assert!(matches!(on_client(&c, &s, "", &mut p), Action::Forward(_)));
        }
        // A cancel for nothing in flight goes nowhere.
        let stray =
            r#"{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":0}}"#;
        assert_eq!(on_client(stray, &s, "", &mut p), Action::Drop);
        assert!(matches!(
            on_client(&call(99), &s, "", &mut p),
            Action::Forward(_)
        ));
        // The late response to a cancelled call is dropped.
        let late = r#"{"jsonrpc":"2.0","id":3,"result":{}}"#;
        assert_eq!(on_server(late, &s, "", &mut p), Action::Drop);
    }

    #[test]
    fn each_tools_call_leaves_one_audit_line_without_arguments() {
        let s = check(base()).unwrap();
        let mut p = Pending::default();
        let call = |i: u8, t: &str| {
            json!({"jsonrpc":"2.0","id":i,"method":"tools/call","params":{"name":t,"arguments":{"team":"s3cr3t-arg"}}}).to_string()
        };
        assert!(matches!(
            on_client(&call(1, "get_nais_context"), &s, "", &mut p),
            Action::Forward(_)
        ));
        on_server(
            r#"{"jsonrpc":"2.0","id":1,"result":{"content":[{"text":"s3cr3t-res"}]}}"#,
            &s,
            "",
            &mut p,
        );
        let allowed = p.1.take().unwrap();
        assert!(
            allowed.starts_with("tools/call get_nais_context → ALLOWED ")
                && allowed.ends_with("ms"),
            "{allowed}"
        );
        assert!(matches!(
            on_client(&call(2, "get_nais_context"), &s, "", &mut p),
            Action::Forward(_)
        ));
        on_server(
            r#"{"jsonrpc":"2.0","id":2,"error":{"code":-32603,"message":"s3cr3t-res"}}"#,
            &s,
            "",
            &mut p,
        );
        let failed = p.1.take().unwrap();
        assert!(
            failed.starts_with("tools/call get_nais_context → FAIL -32603 "),
            "{failed}"
        );
        let Action::Reply(_, Some(denied)) = on_client(&call(3, "delete_app"), &s, "", &mut p)
        else {
            panic!("not denied");
        };
        assert!(
            denied.starts_with("tools/call → DENIED tool \"delete_app\""),
            "{denied}"
        );
        // A non-integer code is the server's content: not copied.
        on_client(&call(4, "get_nais_context"), &s, "", &mut p);
        on_server(
            r#"{"jsonrpc":"2.0","id":4,"error":{"code":{"token":"s3cr3t-res"}}}"#,
            &s,
            "",
            &mut p,
        );
        let odd = p.1.take().unwrap();
        assert!(odd.contains("→ FAIL invalid error code "), "{odd}");
        // A cancelled call still leaves its line.
        on_client(&call(5, "get_nais_context"), &s, "", &mut p);
        on_client(
            r#"{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":5}}"#,
            &s,
            "",
            &mut p,
        );
        let cancelled = p.1.take().unwrap();
        assert!(
            cancelled.starts_with("tools/call get_nais_context → CANCELLED "),
            "{cancelled}"
        );
        for l in [&allowed, &failed, &denied, &odd, &cancelled] {
            assert!(!l.contains("s3cr3t"), "{l}");
        }
        // Other methods leave no audit line.
        on_client(
            r#"{"jsonrpc":"2.0","id":4,"method":"ping"}"#,
            &s,
            "",
            &mut p,
        );
        on_server(r#"{"jsonrpc":"2.0","id":4,"result":{}}"#, &s, "", &mut p);
        assert!(p.1.is_none());
    }

    #[test]
    fn old_requests_are_evicted_with_a_timeout() {
        let s = check(base()).unwrap();
        let mut p = Pending::default();
        let ping = r#"{"jsonrpc":"2.0","id":"x","method":"ping"}"#;
        assert!(matches!(
            on_client(ping, &s, "", &mut p),
            Action::Forward(_)
        ));
        assert!(p.evict(Duration::from_secs(120)).is_empty());
        let out = p.evict(Duration::ZERO);
        assert_eq!(out.len(), 1);
        let err: Value = serde_json::from_str(&out[0].0).unwrap();
        assert_eq!(err["id"], "x");
        assert!(
            err["error"]["message"]
                .as_str()
                .unwrap()
                .contains("timed out")
        );
        let cancel: Value = serde_json::from_str(&out[0].1).unwrap();
        assert_eq!(cancel["params"]["requestId"], "x");
        assert_eq!(
            on_server(r#"{"jsonrpc":"2.0","id":"x","result":{}}"#, &s, "", &mut p),
            Action::Drop
        );
        assert!(p.0.is_empty());
    }

    #[test]
    fn auth_errors_only_from_error_fields() {
        for l in [
            r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"Unauthenticated"}}"#,
            r#"{"jsonrpc":"2.0","id":1,"result":{"isError":true,"content":[{"type":"text","text":"not logged in, run nais login"}]}}"#,
        ] {
            assert!(auth_error(l), "{l}");
        }
        for l in [
            r#"{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"docs: if you are not logged in, run nais login"}]}}"#,
            r#"{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"x","description":"please log in first"}]}}"#,
            "not logged in",
        ] {
            assert!(!auth_error(l), "{l}");
        }
    }

    #[test]
    fn id_less_calls_never_pass() {
        let s = check(base()).unwrap();
        let mut p = Pending::default();
        for m in [
            r#"{"jsonrpc":"2.0","method":"tools/call","params":{"name":"delete_app"}}"#,
            r#"{"jsonrpc":"2.0","method":"initialize","params":{"protocolVersion":"1999"}}"#,
            r#"{"jsonrpc":"2.0","method":"tools/list"}"#,
        ] {
            assert_eq!(on_client(m, &s, "", &mut p), Action::Drop, "{m}");
        }
        let ok = r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#;
        assert!(matches!(on_client(ok, &s, "", &mut p), Action::Forward(_)));
    }

    #[test]
    fn forwards_what_it_checked() {
        let s = check(base()).unwrap();
        let mut p = Pending::default();
        // serde keeps the last duplicate; the server must see the same.
        let dup = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"delete_app","name":"get_nais_context"}}"#;
        let Action::Forward(out) = on_client(dup, &s, "", &mut p) else {
            panic!()
        };
        assert!(!out.contains("delete_app"), "{out}");
        let fold = json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"execute_graphql","arguments":{"query":"{ a }","Query":"mutation { x }"}}}).to_string();
        assert!(matches!(
            on_client(&fold, &s, "", &mut p),
            Action::Reply(..)
        ));
    }

    #[test]
    fn duplicate_ids_and_smuggled_tool_lists() {
        let s = check(base()).unwrap();
        let mut p = Pending::default();
        let ping = r#"{"jsonrpc":"2.0","id":7,"method":"ping"}"#;
        assert!(matches!(
            on_client(ping, &s, "", &mut p),
            Action::Forward(_)
        ));
        let list = r#"{"jsonrpc":"2.0","id":7,"method":"tools/list"}"#;
        assert!(matches!(on_client(list, &s, "", &mut p), Action::Reply(..)));
        let resp = r#"{"jsonrpc":"2.0","id":7,"result":{"tools":[{"name":"delete_app"}]}}"#;
        let Action::Forward(out) = on_server(resp, &s, "", &mut p) else {
            panic!()
        };
        assert!(!out.contains("delete_app"), "{out}");
    }

    #[test]
    fn ambiguous_keys_are_refused() {
        let s = check(base()).unwrap();
        let mut p = Pending::default();
        for m in [
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_nais_context","Name":"execute_graphql"}}"#,
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"NAME":"execute_graphql"}}"#,
            r#"{"jsonrpc":"2.0","ID":1,"method":"notifications/initialized"}"#,
            "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"execute_graphql\",\"arguments\":{\"query\":\"{ a }\",\"querſ\":1,\"Query\":\"mutation { x }\"}}}",
        ] {
            assert!(
                matches!(on_client(m, &s, "", &mut p), Action::Reply(..)),
                "{m}"
            );
        }
        let ok = r#"{"jsonrpc":"2.0","id":2,"method":"initialize","params":{"protocolVersion":"2025-11-25","clientInfo":{"Name":"x"}}}"#;
        assert!(matches!(on_client(ok, &s, "", &mut p), Action::Forward(_)));
    }
}
