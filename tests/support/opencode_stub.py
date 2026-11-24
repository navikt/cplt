"""Stub OpenAI-compatible model and MCP server for the OpenCode v2 smoke tests.

Listens on 127.0.0.1 on a free port, prints the port on stdout, and answers
- POST /v1/chat/completions: one streamed reply, "STUB-REPLY";
- GET /v1/models: one model, "stub";
- POST /mcp: MCP streamable HTTP with one tool, "stub_echo".
Every request path is appended to the log file named by argv[1].
"""

import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

LOG = sys.argv[1]


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def _log(self):
        with open(LOG, "a") as f:
            f.write(f"{self.command} {self.path}\n")

    def _send(self, code, body, ctype="application/json", extra=()):
        data = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        for k, v in extra:
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        self._log()
        if self.path.startswith("/v1/models"):
            self._send(200, json.dumps({"object": "list", "data": [{"id": "stub", "object": "model"}]}))
        else:
            self._send(405 if self.path.startswith("/mcp") else 404, "")

    def do_DELETE(self):
        self._log()
        self._send(200, "")

    def do_POST(self):
        self._log()
        n = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(n) if n else b"{}"
        try:
            req = json.loads(raw or b"{}")
        except ValueError:
            req = {}
        if self.path.startswith("/v1/chat/completions"):
            self._chat(req)
        elif self.path.startswith("/mcp"):
            self._mcp(req)
        else:
            self._send(404, "")

    def _chat(self, req):
        base = {"id": "c1", "object": "chat.completion.chunk", "created": 0, "model": "stub"}
        if not req.get("stream"):
            msg = {"role": "assistant", "content": "STUB-REPLY"}
            body = dict(base, object="chat.completion",
                        choices=[{"index": 0, "message": msg, "finish_reason": "stop"}],
                        usage={"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2})
            self._send(200, json.dumps(body))
            return
        chunks = [
            {"index": 0, "delta": {"role": "assistant", "content": "STUB-REPLY"}, "finish_reason": None},
            {"index": 0, "delta": {}, "finish_reason": "stop"},
        ]
        out = "".join(f"data: {json.dumps(dict(base, choices=[c]))}\n\n" for c in chunks)
        usage = dict(base, choices=[], usage={"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2})
        out += f"data: {json.dumps(usage)}\n\ndata: [DONE]\n\n"
        self._send(200, out, "text/event-stream")

    def _mcp(self, req):
        if "id" not in req:
            self._send(202, "")
            return
        method = req.get("method")
        if method == "initialize":
            result = {
                "protocolVersion": req.get("params", {}).get("protocolVersion", "2025-03-26"),
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "stub", "version": "1"},
            }
        elif method == "tools/list":
            result = {"tools": [{"name": "stub_echo", "description": "echo",
                                 "inputSchema": {"type": "object", "properties": {}}}]}
        elif method in ("prompts/list", "resources/list", "resources/templates/list"):
            key = method.split("/")[0] if method != "resources/templates/list" else "resourceTemplates"
            result = {key: []}
        else:
            result = {}
        body = json.dumps({"jsonrpc": "2.0", "id": req["id"], "result": result})
        self._send(200, body, extra=[("Mcp-Session-Id", "stub")])


srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
print(srv.server_address[1], flush=True)
srv.serve_forever()
